//! Streaming pipeline: TAR -> Zstd compress -> Chunked AEAD Encrypt
//! and Decrypt -> Decompress -> TAR extract.

use std::io::{Read, Write, Cursor};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, Duration};
use zstd::stream::{Encoder, Decoder};
use crate::{
    Result, QencError, EncryptOptions, DecryptOptions, ProgressEvent, ProgressStage,
    CompressionProfile, KeyMode, DEFAULT_CHUNK_SIZE, DEFAULT_ARGON2_DESKTOP, VERSION,
    NamedStreamInput, EncryptStats, ProgressCallback,
    format::{RawHeader, encode_header, read_full_header, compute_header_hash, build_chunk_aad, build_chunk_nonce, read_chunk_record, write_chunk_record},
    crypto::{derive_key_argon2id, derive_key_hybrid, recover_key_hybrid, encrypt_chunk, decrypt_chunk, generate_nonce_prefix, load_public_key, load_full_secret_key},
    archive::{create_tar_stream_counted, pack_named_entries_to_tar, extract_tar_stream, estimate_input_size},
};

const PROGRESS_THROTTLE_MS: u64 = 60; // ~16 updates/sec
const CHUNK_SIZE: usize = DEFAULT_CHUNK_SIZE as usize;

/// Completion percentage, clamped to `0.0..=100.0`, NaN-safe.
fn compute_percent(bytes: u64, total: Option<u64>) -> f64 {
    match total {
        Some(t) if t > 0 => ((bytes as f64 / t as f64) * 100.0).clamp(0.0, 100.0),
        _ => {
            if bytes == 0 { 0.0 } else { 100.0 }
        }
    }
}

/// MB/s given processed bytes and elapsed milliseconds, NaN-safe.
fn mb_per_sec(bytes: u64, elapsed_ms: u64) -> f64 {
    if elapsed_ms > 0 {
        (bytes as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
    } else {
        0.0
    }
}

/// Derives the master key + header `key_data` for the requested mode.
/// Shared by `encrypt_stream` and `encrypt_named_streams`.
fn derive_master_key(
    mode: KeyMode,
    passphrase: Option<&str>,
    recipient_pubkey_path: Option<&str>,
    original_size: u64,
    mobile_hint: bool,
) -> Result<([u8; 32], KeyMode, Vec<u8>)> {
    match mode {
        KeyMode::Passphrase => {
            let passphrase = passphrase
                .ok_or(QencError::InvalidArgument("Passphrase required for Passphrase mode".into()))?;
            let params = if original_size > 100_000_000 || mobile_hint {
                // Mobile params for large files or when running on mobile.
                crate::DEFAULT_ARGON2_MOBILE
            } else {
                DEFAULT_ARGON2_DESKTOP
            };
            let salt = rand::random::<[u8; 16]>();
            let master_key = derive_key_argon2id(passphrase, &salt, &params)?;

            // key_data: salt (16) || m_cost (4) || t_cost (4) || p_cost (4)
            let mut key_data = Vec::new();
            key_data.extend_from_slice(&salt);
            key_data.extend_from_slice(&params.m_cost_kib.to_le_bytes());
            key_data.extend_from_slice(&params.t_cost.to_le_bytes());
            key_data.extend_from_slice(&params.p_cost.to_le_bytes());

            Ok((master_key, KeyMode::Passphrase, key_data))
        }
        KeyMode::HybridPqc => {
            let pubkey_path = recipient_pubkey_path
                .ok_or(QencError::InvalidArgument("Recipient public key required for HybridPqc mode".into()))?;
            let recipient_pub = load_public_key(pubkey_path)?;
            let (master_key, ephemeral_pk, mlkem_ct) = derive_key_hybrid(&recipient_pub)?;

            // key_data: ephemeral_pk (32) || mlkem_ct (1568)
            let mut key_data = Vec::new();
            key_data.extend_from_slice(&ephemeral_pk);
            key_data.extend_from_slice(&mlkem_ct);

            Ok((master_key, KeyMode::HybridPqc, key_data))
        }
    }
}

/// Encrypts a stream of files/directories to a .qenc container.
pub fn encrypt_stream<P: AsRef<Path>, W: Write + Send>(
    inputs: &[P],
    mut writer: W,
    options: EncryptOptions,
) -> Result<()> {
    let start_time = Instant::now();
    let cancel = options.cancel.clone().unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let progress_cb = options.progress_cb;

    // Estimate original size for progress / total display bytes
    let original_size = options.original_size_hint.unwrap_or_else(|| estimate_input_size(inputs));

    // Emit an immediate KeyDerivation event so the UI shows the KDF stage at 0%.
    if let Some(cb) = &progress_cb {
        cb(ProgressEvent {
            stage: ProgressStage::KeyDerivation,
            bytes_processed: 0,
            total_bytes: Some(original_size),
            output_bytes: 0,
            elapsed_ms: 0,
            mb_per_sec: 0.0,
            percent: 0.0,
        });
    }

    // Generate nonce prefix
    let nonce_prefix = generate_nonce_prefix();

    // Determine key mode and derive master key
    let (master_key, key_mode, key_data) = derive_master_key(options.mode, options.passphrase.as_deref(), options.recipient_pubkey_path.as_deref(), original_size, options.argon2_mobile_hint.unwrap_or(false))?;

    // Create header
    let header = RawHeader {
        version: VERSION,
        key_mode: key_mode as u8,
        comp_profile: options.profile as u8,
        chunk_size: DEFAULT_CHUNK_SIZE,
        nonce_prefix,
        original_size,
        key_data,
    };

    // Write header and capture exact bytes for AAD
    let header_bytes = encode_header(&header);
    writer.write_all(&header_bytes)?;

    // Compute header hash for AAD binding
    let header_hash = compute_header_hash(&header_bytes);

    // Create Zstd encoder
    let zstd_level = options.profile.zstd_level();

    let output_bytes_base = header_bytes.len() as u64;

    // Pack into TAR while counting raw input bytes (live Archiving progress).
    let raw_counter = AtomicU64::new(0);
    let mut tar_buffer = Vec::new();
    {
        let mut last_emit = Instant::now();
        create_tar_stream_counted(inputs, &mut tar_buffer, &raw_counter, || {
            if let Some(cb) = &progress_cb {
                if last_emit.elapsed() >= Duration::from_millis(PROGRESS_THROTTLE_MS) {
                    let raw = raw_counter.load(Ordering::Relaxed);
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    let pct = (compute_percent(raw, Some(original_size)) * 0.7).clamp(0.0, 70.0);
                    cb(ProgressEvent {
                        stage: ProgressStage::Archiving,
                        bytes_processed: raw,
                        total_bytes: Some(original_size),
                        output_bytes: output_bytes_base,
                        elapsed_ms: elapsed,
                        mb_per_sec: mb_per_sec(raw, elapsed),
                        percent: pct,
                    });
                    last_emit = Instant::now();
                }
            }
        })?;
    }
    let raw_packed = raw_counter.load(Ordering::Relaxed);

    // Compress with Zstd
    let mut compressed = Vec::new();
    {
        let mut encoder = Encoder::new(&mut compressed, zstd_level)
            .map_err(|e| QencError::Compression(e.to_string()))?;
        encoder.multithread(std::thread::available_parallelism().map_or(1, std::num::NonZero::get) as u32)
            .map_err(|e| QencError::Compression(e.to_string()))?;
        encoder.write_all(&tar_buffer)?;
        encoder.finish()?;
    }

    // Emit a single Compressing event.
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        let pct = (compute_percent(raw_packed, Some(original_size)) * 0.7).clamp(0.0, 70.0);
        cb(ProgressEvent {
            stage: ProgressStage::Compressing,
            bytes_processed: raw_packed,
            total_bytes: Some(original_size),
            output_bytes: output_bytes_base,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(raw_packed, elapsed),
            percent: pct,
        });
    }

    // Now encrypt compressed data in chunks
    let total_compressed = compressed.len().max(1) as u64;
    let mut offset = 0usize;
    let mut chunk_index = 0u64;
    let mut output_bytes = output_bytes_base;
    let mut last_progress = Instant::now();

    while offset < compressed.len() {
        if cancel.load(Ordering::Relaxed) {
            return Err(QencError::Cancelled);
        }

        let remaining = compressed.len() - offset;
        let chunk_len = remaining.min(CHUNK_SIZE);
        let chunk = &compressed[offset..offset + chunk_len];
        let is_final = offset + chunk_len >= compressed.len();

        // Build nonce and AAD
        let nonce = build_chunk_nonce(&nonce_prefix, chunk_index);
        let aad = build_chunk_aad(&header_hash, chunk_index, is_final);

        // Encrypt chunk
        let ciphertext = encrypt_chunk(&master_key, &nonce, &aad, chunk)?;

        // Write chunk record
        write_chunk_record(&mut writer, is_final, &ciphertext)?;

        offset += chunk_len;
        chunk_index += 1;
        output_bytes += ciphertext.len() as u64 + 5; // +5 for flag + length

        // Progress callback (Encrypting phase maps 70%..100%)
        if let Some(cb) = &progress_cb {
            if last_progress.elapsed() >= Duration::from_millis(PROGRESS_THROTTLE_MS) {
                let elapsed = start_time.elapsed().as_millis() as u64;
                let enc_frac = offset as f64 / total_compressed as f64;
                let pct = 30.0_f64.mul_add(enc_frac, 70.0).clamp(70.0, 100.0);
                cb(ProgressEvent {
                    stage: ProgressStage::Encrypting,
                    bytes_processed: raw_packed,
                    total_bytes: Some(original_size),
                    output_bytes,
                    elapsed_ms: elapsed,
                    mb_per_sec: mb_per_sec(raw_packed, elapsed),
                    percent: pct,
                });
                last_progress = Instant::now();
            }
        }

        // Check for chunk index overflow
        if chunk_index >= (1u64 << 63) {
            return Err(QencError::ChunkIndexOverflow);
        }
    }

    writer.flush()?;

    // Guaranteed final 100% event (even for tiny/fast files).
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        cb(ProgressEvent {
            stage: ProgressStage::Finalizing,
            bytes_processed: raw_packed,
            total_bytes: Some(original_size),
            output_bytes,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(raw_packed, elapsed),
            percent: 100.0,
        });
    }

    Ok(())
}

/// Encrypts named byte streams (Android SAF `content://` readers) into `.qenc`.
///
/// Uses the same GNU TAR -> Zstd -> 1 MiB chunked XChaCha20-Poly1305 pipeline as
/// [`encrypt_stream`], without copying files to temp storage. Returns summary stats.
#[allow(clippy::needless_pass_by_value)]
pub fn encrypt_named_streams<W: Write + Send>(
    entries: Vec<NamedStreamInput>,
    mut writer: W,
    options: &EncryptOptions,
    progress_cb: Option<ProgressCallback>,
    cancel: Arc<AtomicBool>,
) -> Result<EncryptStats> {
    let start_time = Instant::now();

    // Total raw input size across all streams.
    let original_size: u64 = entries.iter().map(|e| e.size).sum();

    // Immediate KeyDerivation event at 0%.
    if let Some(cb) = &progress_cb {
        cb(ProgressEvent {
            stage: ProgressStage::KeyDerivation,
            bytes_processed: 0,
            total_bytes: Some(original_size),
            output_bytes: 0,
            elapsed_ms: 0,
            mb_per_sec: 0.0,
            percent: 0.0,
        });
    }

    // Derive master key + header key_data.
    let (master_key, key_mode, key_data) = derive_master_key(options.mode, options.passphrase.as_deref(), options.recipient_pubkey_path.as_deref(), original_size, options.argon2_mobile_hint.unwrap_or(false))?;

    // Header
    let nonce_prefix = generate_nonce_prefix();
    let header = RawHeader {
        version: VERSION,
        key_mode: key_mode as u8,
        comp_profile: options.profile as u8,
        chunk_size: DEFAULT_CHUNK_SIZE,
        nonce_prefix,
        original_size,
        key_data,
    };
    let header_bytes = encode_header(&header);
    writer.write_all(&header_bytes)?;
    let header_hash = compute_header_hash(&header_bytes);
    let output_bytes_base = header_bytes.len() as u64;
    let zstd_level = options.profile.zstd_level();

    // Pack named streams into TAR while counting raw input bytes (Archiving 0..70).
    let raw_counter = AtomicU64::new(0);
    let mut tar_buffer = Vec::new();
    {
        let mut last_emit = Instant::now();
        pack_named_entries_to_tar(entries, &mut tar_buffer, &raw_counter, || {
            if let Some(cb) = &progress_cb {
                if last_emit.elapsed() >= Duration::from_millis(PROGRESS_THROTTLE_MS) {
                    let raw = raw_counter.load(Ordering::Relaxed);
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    let pct = (compute_percent(raw, Some(original_size)) * 0.7).clamp(0.0, 70.0);
                    cb(ProgressEvent {
                        stage: ProgressStage::Archiving,
                        bytes_processed: raw,
                        total_bytes: Some(original_size),
                        output_bytes: output_bytes_base,
                        elapsed_ms: elapsed,
                        mb_per_sec: mb_per_sec(raw, elapsed),
                        percent: pct,
                    });
                    last_emit = Instant::now();
                }
            }
        })?;
    }
    let raw_packed = raw_counter.load(Ordering::Relaxed);

    // Compress with Zstd
    let mut compressed = Vec::new();
    {
        let mut encoder = Encoder::new(&mut compressed, zstd_level)
            .map_err(|e| QencError::Compression(e.to_string()))?;
        encoder.multithread(std::thread::available_parallelism().map_or(1, std::num::NonZero::get) as u32)
            .map_err(|e| QencError::Compression(e.to_string()))?;
        encoder.write_all(&tar_buffer)?;
        encoder.finish()?;
    }

    // Compressing event (70%).
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        let pct = (compute_percent(raw_packed, Some(original_size)) * 0.7).clamp(0.0, 70.0);
        cb(ProgressEvent {
            stage: ProgressStage::Compressing,
            bytes_processed: raw_packed,
            total_bytes: Some(original_size),
            output_bytes: output_bytes_base,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(raw_packed, elapsed),
            percent: pct,
        });
    }

    // Encrypt chunks (70..100%).
    let total_compressed = compressed.len().max(1) as u64;
    let mut offset = 0usize;
    let mut chunk_index = 0u64;
    let mut output_bytes = output_bytes_base;
    let mut last_progress = Instant::now();

    while offset < compressed.len() {
        if cancel.load(Ordering::Relaxed) {
            return Err(QencError::Cancelled);
        }

        let remaining = compressed.len() - offset;
        let chunk_len = remaining.min(CHUNK_SIZE);
        let chunk = &compressed[offset..offset + chunk_len];
        let is_final = offset + chunk_len >= compressed.len();
        let nonce = build_chunk_nonce(&nonce_prefix, chunk_index);
        let aad = build_chunk_aad(&header_hash, chunk_index, is_final);
        let ciphertext = encrypt_chunk(&master_key, &nonce, &aad, chunk)?;
        write_chunk_record(&mut writer, is_final, &ciphertext)?;

        offset += chunk_len;
        chunk_index += 1;
        output_bytes += ciphertext.len() as u64 + 5; // +5 for flag + length

        if let Some(cb) = &progress_cb {
            if last_progress.elapsed() >= Duration::from_millis(PROGRESS_THROTTLE_MS) {
                let elapsed = start_time.elapsed().as_millis() as u64;
                let enc_frac = offset as f64 / total_compressed as f64;
                let pct = 30.0_f64.mul_add(enc_frac, 70.0).clamp(70.0, 100.0);
                cb(ProgressEvent {
                    stage: ProgressStage::Encrypting,
                    bytes_processed: raw_packed,
                    total_bytes: Some(original_size),
                    output_bytes,
                    elapsed_ms: elapsed,
                    mb_per_sec: mb_per_sec(raw_packed, elapsed),
                    percent: pct,
                });
                last_progress = Instant::now();
            }
        }

        if chunk_index >= (1u64 << 63) {
            return Err(QencError::ChunkIndexOverflow);
        }
    }

    writer.flush()?;

    let elapsed_ms = start_time.elapsed().as_millis() as u64;
    // Guaranteed final 100% event.
    if let Some(cb) = &progress_cb {
        cb(ProgressEvent {
            stage: ProgressStage::Finalizing,
            bytes_processed: raw_packed,
            total_bytes: Some(original_size),
            output_bytes,
            elapsed_ms,
            mb_per_sec: mb_per_sec(raw_packed, elapsed_ms),
            percent: 100.0,
        });
    }

    let compression_ratio_percent = if original_size > 0 {
        output_bytes as f64 / original_size as f64 * 100.0
    } else {
        100.0
    };

    Ok(EncryptStats {
        original_size,
        output_size: output_bytes,
        elapsed_ms,
        avg_mb_per_sec: mb_per_sec(raw_packed, elapsed_ms),
        compression_ratio_percent,
    })
}

/// Decrypts a .qenc container stream to a directory.
pub fn decrypt_stream<R: Read + Send, P: AsRef<Path>>(
    mut reader: R,
    output_dir: P,
    options: DecryptOptions,
) -> Result<()> {
    let start_time = Instant::now();
    let cancel = options.cancel.clone().unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let progress_cb = options.progress_cb;
    let input_total: Option<u64> = options.input_size_hint;

    // Emit an immediate KeyDerivation event before header/key derivation.
    if let Some(cb) = &progress_cb {
        cb(ProgressEvent {
            stage: ProgressStage::KeyDerivation,
            bytes_processed: 0,
            total_bytes: input_total,
            output_bytes: 0,
            elapsed_ms: 0,
            mb_per_sec: 0.0,
            percent: 0.0,
        });
    }

    // Read and parse header
    let (header_bytes, raw_header) = read_full_header(&mut reader)?;
    let header_hash = compute_header_hash(&header_bytes);

    // Validate header
    if raw_header.version != VERSION {
        return Err(QencError::UnsupportedVersion(raw_header.version));
    }
    let key_mode = KeyMode::from_u8(raw_header.key_mode)
        .ok_or(QencError::UnsupportedKeyMode(raw_header.key_mode))?;
    let _comp_profile = CompressionProfile::from_u8(raw_header.comp_profile)
        .ok_or(QencError::UnsupportedCompressionProfile(raw_header.comp_profile))?;

    // Derive master key
    let master_key = match key_mode {
        KeyMode::Passphrase => {
            let passphrase = options.passphrase.ok_or(QencError::InvalidArgument("Passphrase required for Passphrase mode".into()))?;

            // Parse Argon2 params from key_data
            let params = crate::format::parse_argon2_params(&raw_header.key_data)?;
            let salt: [u8; 16] = raw_header.key_data[0..16].try_into().unwrap();

            derive_key_argon2id(&passphrase, &salt, &params)?
        }
        KeyMode::HybridPqc => {
            let secret_key_path = options.secret_key_path.ok_or(QencError::InvalidArgument("Secret key required for HybridPqc mode".into()))?;
            let secret_key = load_full_secret_key(secret_key_path, options.secret_key_passphrase.as_deref())?;

            // Parse ephemeral PK and ML-KEM ciphertext from key_data
            let (ephemeral_pk, mlkem_ct) = crate::format::parse_hybrid_key_data(&raw_header.key_data)?;

            recover_key_hybrid(&secret_key, &ephemeral_pk, &mlkem_ct)?
        }
    };

    // Decrypt chunks and decompress
    let mut chunk_index = 0u64;
    let mut compressed_data = Vec::new();
    let mut bytes_processed = header_bytes.len() as u64; // header is already consumed from the reader
    let mut output_bytes = 0u64;
    let mut last_progress = Instant::now();
    let mut final_chunk_found = false;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(QencError::Cancelled);
        }

        // Read chunk record
        let chunk_record = match read_chunk_record(&mut reader)? {
            Some(record) => record,
            None => break, // EOF
        };

        if final_chunk_found {
            return Err(QencError::TrailingData);
        }

        if chunk_record.is_final {
            final_chunk_found = true;
        }

        // Build nonce and AAD
        let nonce = build_chunk_nonce(&raw_header.nonce_prefix, chunk_index);
        let aad = build_chunk_aad(&header_hash, chunk_index, chunk_record.is_final);

        // Decrypt chunk
        let plaintext = decrypt_chunk(&master_key, &nonce, &aad, &chunk_record.ciphertext)?;

        compressed_data.extend_from_slice(&plaintext);

        chunk_index += 1;
        // Track actual reader bytes consumed: flag(1) + length(4) + ciphertext.
        bytes_processed += 5 + chunk_record.ciphertext.len() as u64;
        output_bytes += plaintext.len() as u64;

        // Progress callback (Decrypting phase -> linear 0..100% of the input file)
        if let Some(cb) = &progress_cb {
            if last_progress.elapsed() >= Duration::from_millis(PROGRESS_THROTTLE_MS) {
                let elapsed = start_time.elapsed().as_millis() as u64;
                cb(ProgressEvent {
                    stage: ProgressStage::Decrypting,
                    bytes_processed,
                    total_bytes: input_total,
                    output_bytes,
                    elapsed_ms: elapsed,
                    mb_per_sec: mb_per_sec(bytes_processed, elapsed),
                    percent: compute_percent(bytes_processed, input_total),
                });
                last_progress = Instant::now();
            }
        }

        // Check for chunk index overflow
        if chunk_index >= (1u64 << 63) {
            return Err(QencError::ChunkIndexOverflow);
        }
    }

    if !final_chunk_found {
        return Err(QencError::UnexpectedEof);
    }

    // Decompress
    let known_total = input_total.unwrap_or(bytes_processed);
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        cb(ProgressEvent {
            stage: ProgressStage::Decompressing,
            bytes_processed,
            total_bytes: Some(known_total),
            output_bytes,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(bytes_processed, elapsed),
            percent: compute_percent(bytes_processed, Some(known_total)),
        });
    }

    let mut decoder = Decoder::new(&compressed_data[..])
        .map_err(|e| QencError::Decompression(e.to_string()))?;
    let mut tar_data = Vec::new();
    std::io::copy(&mut decoder, &mut tar_data)
        .map_err(|e| QencError::Decompression(e.to_string()))?;

    // Extract TAR
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        cb(ProgressEvent {
            stage: ProgressStage::Extracting,
            bytes_processed,
            total_bytes: Some(known_total),
            output_bytes,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(bytes_processed, elapsed),
            percent: compute_percent(bytes_processed, Some(known_total)),
        });
    }

    extract_tar_stream(Cursor::new(tar_data), output_dir.as_ref())?;

    // Guaranteed final 100% event.
    if let Some(cb) = &progress_cb {
        let elapsed = start_time.elapsed().as_millis() as u64;
        cb(ProgressEvent {
            stage: ProgressStage::Finalizing,
            bytes_processed: known_total,
            total_bytes: Some(known_total),
            output_bytes,
            elapsed_ms: elapsed,
            mb_per_sec: mb_per_sec(bytes_processed, elapsed),
            percent: 100.0,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use std::fs;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_encrypt_decrypt_roundtrip_passphrase_turbo() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"Hello, QENC! This is a test file.").unwrap();

        let output = temp.path().join("test.qenc");
        let passphrase = "test passphrase 123";

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Turbo,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        let extracted = dest.path().join("test.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read(extracted).unwrap(), b"Hello, QENC! This is a test file.");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_passphrase_balanced() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"Hello, QENC! Balanced profile test.").unwrap();

        let output = temp.path().join("test.qenc");
        let passphrase = "test passphrase 123";

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        let extracted = dest.path().join("test.txt");
        assert_eq!(fs::read(extracted).unwrap(), b"Hello, QENC! Balanced profile test.");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_passphrase_ultra() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"Hello, QENC! Ultra profile test.").unwrap();

        let output = temp.path().join("test.qenc");
        let passphrase = "test passphrase 123";

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Ultra,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        let extracted = dest.path().join("test.txt");
        assert_eq!(fs::read(extracted).unwrap(), b"Hello, QENC! Ultra profile test.");
    }

    #[test]
    fn test_encrypt_decrypt_directory() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("mydir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file1.txt"), b"File 1 content").unwrap();
        fs::write(dir.join("file2.txt"), b"File 2 content").unwrap();

        let output = temp.path().join("dir.qenc");
        let passphrase = "directory test passphrase";

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        encrypt_stream(&[&dir], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        assert_eq!(fs::read(dest.path().join("mydir/file1.txt")).unwrap(), b"File 1 content");
        assert_eq!(fs::read(dest.path().join("mydir/file2.txt")).unwrap(), b"File 2 content");
    }

    #[test]
    fn test_encrypt_decrypt_hybrid_pqc() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"Hybrid PQC test content").unwrap();

        // Generate keypair
        let (public, secret) = crate::crypto::generate_full_hybrid_keypair().unwrap();
        let pub_path = temp.path().join("test.qenc.pub");
        let sec_path = temp.path().join("test.qenc.sec");
        crate::crypto::save_public_key(&pub_path, &public).unwrap();
        crate::crypto::save_full_secret_key(&sec_path, &secret, None).unwrap();

        let output = temp.path().join("test.qenc");

        let options = EncryptOptions {
            mode: KeyMode::HybridPqc,
            profile: CompressionProfile::Balanced,
            recipient_pubkey_path: Some(pub_path.to_string_lossy().into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            secret_key_path: Some(sec_path.to_string_lossy().into()),
            secret_key_passphrase: None,
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        let extracted = dest.path().join("test.txt");
        assert_eq!(fs::read(extracted).unwrap(), b"Hybrid PQC test content");
    }

    #[test]
    fn test_multi_chunk_streaming() {
        // Create a file larger than 2.5 MiB to exercise multiple 1 MiB chunks
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("large.bin");
        let data = vec![0xABu8; 3_000_000]; // ~3 MB
        fs::write(&input_file, &data).unwrap();

        let output = temp.path().join("large.qenc");
        let passphrase = "multi-chunk test";

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();

        let extracted = dest.path().join("large.bin");
        assert_eq!(fs::read(extracted).unwrap(), data);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("correct".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some("wrong".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_header_fails() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        // Tamper with header: flip a bit in the original_size field
        let mut data = fs::read(&output).unwrap();
        // Magic (4) + version (1) + key_mode (1) + comp_profile (1) + chunk_size (4) + nonce (16) = 27
        // original_size starts at offset 27, 8 bytes
        data[27] ^= 0xFF; // Flip bits in original_size

        fs::write(&output, &data).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        // Should fail due to AAD mismatch (header hash changed)
        assert!(matches!(result, Err(QencError::AuthenticationFailed | QencError::IntegrityCheckFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test content for tampering").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        // Tamper with ciphertext: flip a bit after the header
        let mut data = fs::read(&output).unwrap();
        // Find first chunk ciphertext (after header)
        // Header size varies, but we can flip a byte in the latter half
        if data.len() > 100 {
            data[100] ^= 0x01;
        }
        fs::write(&output, &data).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_truncated_file_fails() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test content").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        // Truncate the file before the final chunk
        let mut data = fs::read(&output).unwrap();
        data.truncate(data.len() - 20); // Remove some bytes from end
        fs::write(&output, &data).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        // Truncation causes Io UnexpectedEof during chunk reading
        assert!(matches!(result, Err(QencError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn test_trailing_garbage_fails() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        // Append garbage byte after final chunk
        let mut file = fs::OpenOptions::new().append(true).open(&output).unwrap();
        file.write_all(&[0xFF]).unwrap();

        let decrypt_options = DecryptOptions {
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        // Trailing garbage is detected as invalid chunk flag
        assert!(matches!(result, Err(QencError::InvalidHeader(_))));
    }

    #[test]
    fn test_chunk_swap_fails() {
        let temp = TempDir::new().unwrap();
        // Create a file with random data that won't compress well, producing multiple chunks
        let input_file = temp.path().join("large.bin");
        let mut data = vec![0u8; 3_500_000]; // 3.5 MB of random data
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut data);
        fs::write(&input_file, &data).unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        // Normal decrypt should work
        let decrypt_options = DecryptOptions {
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options).unwrap();
        let extracted = dest.path().join("large.bin");
        assert_eq!(fs::read(extracted).unwrap(), data);
    }

    #[test]
    fn test_malicious_tar_path_traversal() {
        let temp = TempDir::new().unwrap();
        
        // Create a raw tar entry with path traversal (bypasses tar crate validation)
        fn create_raw_tar_entry(path: &str, size: u64, data: &[u8]) -> Vec<u8> {
            let mut block = vec![0u8; 512];
            // Name (100 bytes)
            let path_bytes = path.as_bytes();
            block[0..path_bytes.len().min(100)].copy_from_slice(&path_bytes[..path_bytes.len().min(100)]);
            // Mode (8 bytes)
            block[100..108].copy_from_slice(b"0000644 ");
            // UID (8 bytes)
            block[108..116].copy_from_slice(b"0000000 ");
            // GID (8 bytes)
            block[116..124].copy_from_slice(b"0000000 ");
            // Size (12 bytes, octal) - 11 octal digits + null terminator
            let size_oct = format!("{size:011o}");
            block[124..135].copy_from_slice(size_oct.as_bytes());
            block[135] = 0; // null terminator
            // Mtime (12 bytes)
            block[136..147].copy_from_slice(b"00000000000");
            block[147] = 0;
            // Checksum (8 bytes) - placeholder
            block[148..156].copy_from_slice(b"        ");
            // Typeflag (1 byte)
            block[156] = b'0'; // regular file
            // Linkname (100 bytes) - empty
            // Magic (6 bytes)
            block[257..263].copy_from_slice(b"ustar ");
            // Version (2 bytes)
            block[263..265].copy_from_slice(b"00");
            // Uname (32 bytes)
            block[265..297].copy_from_slice(b"user                            ");
            // Gname (32 bytes)
            block[297..329].copy_from_slice(b"group                           ");
            
            // Calculate checksum (treat checksum bytes as spaces for calculation)
            let mut checksum = 0u32;
            for (i, &b) in block.iter().enumerate() {
                if (148..156).contains(&i) {
                    checksum += u32::from(b' '); // checksum field treated as spaces
                } else {
                    checksum += u32::from(b);
                }
            }
            let checksum_oct = format!("{checksum:06o}");
            block[148..154].copy_from_slice(checksum_oct.as_bytes());
            block[154] = b' ';
            block[155] = b'\0';
            
            let mut result = block;
            // Add data, padded to 512 bytes
            result.extend_from_slice(data);
            let padding = (512 - (data.len() % 512)) % 512;
            result.extend(vec![0u8; padding]);
            // Add two 512-byte zero blocks for end of archive
            result.extend(vec![0u8; 1024]);
            result
        }

        let tar_data = create_raw_tar_entry("../evil.txt", 10, b"malicious");

        let output = temp.path().join("evil.qenc");
        let passphrase = "pass";

        // Create a valid qenc with the malicious tar inside
        // We'll encrypt the malicious tar directly
        let _options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        // Compress and encrypt the malicious tar
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        // Now manually create qenc with this compressed data
        let nonce_prefix = crate::crypto::generate_nonce_prefix();
        let salt = crate::crypto::generate_salt();
        let master_key = crate::crypto::derive_key_argon2id(passphrase, &salt, &crate::DEFAULT_ARGON2_DESKTOP).unwrap();

        let mut key_data = Vec::new();
        key_data.extend_from_slice(&salt);
        key_data.extend_from_slice(&crate::DEFAULT_ARGON2_DESKTOP.m_cost_kib.to_le_bytes());
        key_data.extend_from_slice(&crate::DEFAULT_ARGON2_DESKTOP.t_cost.to_le_bytes());
        key_data.extend_from_slice(&crate::DEFAULT_ARGON2_DESKTOP.p_cost.to_le_bytes());

        let header = crate::format::RawHeader {
            version: crate::VERSION,
            key_mode: crate::KeyMode::Passphrase as u8,
            comp_profile: crate::CompressionProfile::Balanced as u8,
            chunk_size: crate::DEFAULT_CHUNK_SIZE,
            nonce_prefix,
            original_size: tar_data.len() as u64,
            key_data,
        };

        let header_bytes = crate::format::encode_header(&header);
        let header_hash = crate::format::compute_header_hash(&header_bytes);

        let mut output_file = fs::File::create(&output).unwrap();
        output_file.write_all(&header_bytes).unwrap();

        // Encrypt compressed data in chunks
        let mut offset = 0;
        let mut chunk_index = 0;
        while offset < compressed.len() {
            let remaining = compressed.len() - offset;
            let chunk_len = remaining.min(crate::DEFAULT_CHUNK_SIZE as usize);
            let chunk = &compressed[offset..offset + chunk_len];
            let is_final = offset + chunk_len >= compressed.len();

            let nonce = crate::format::build_chunk_nonce(&nonce_prefix, chunk_index);
            let aad = crate::format::build_chunk_aad(&header_hash, chunk_index, is_final);

            let ciphertext = crate::crypto::encrypt_chunk(&master_key, &nonce, &aad, chunk).unwrap();
            crate::format::write_chunk_record(&mut output_file, is_final, &ciphertext).unwrap();

            offset += chunk_len;
            chunk_index += 1;
        }

        // Now try to decrypt - should fail on path traversal during extraction
        let decrypt_options = DecryptOptions {
            passphrase: Some(passphrase.into()),
            ..Default::default()
        };

        let dest = TempDir::new().unwrap();
        let result = decrypt_stream(File::open(&output).unwrap(), dest.path(), decrypt_options);
        assert!(matches!(result, Err(QencError::PathTraversal(_))));
    }

    #[test]
    fn test_cancellation() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("large.bin");
        let data = vec![0xEFu8; 10_000_000]; // 10 MB
        fs::write(&input_file, &data).unwrap();

        let output = temp.path().join("test.qenc");
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();

        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            cancel: Some(cancel),
            ..Default::default()
        };

        let handle = std::thread::spawn(move || {
            encrypt_stream(&[&input_file], File::create(&output).unwrap(), options)
        });

        // Cancel after a short delay
        std::thread::sleep(Duration::from_millis(10));
        cancel_clone.store(true, Ordering::Relaxed);

        let result = handle.join().unwrap();
        assert!(matches!(result, Err(QencError::Cancelled)));

        // Partial output should exist but be incomplete
        // (In production, we'd delete it on cancellation)
    }

    #[test]
    fn test_inspect_header() {
        let temp = TempDir::new().unwrap();
        let input_file = temp.path().join("test.txt");
        fs::write(&input_file, b"test").unwrap();

        let output = temp.path().join("test.qenc");
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("pass".into()),
            ..Default::default()
        };

        encrypt_stream(&[&input_file], File::create(&output).unwrap(), options).unwrap();

        let metadata = crate::inspect_header(&mut File::open(&output).unwrap()).unwrap();

        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.key_mode, KeyMode::Passphrase);
        assert_eq!(metadata.compression_profile, CompressionProfile::Balanced);
        assert_eq!(metadata.chunk_size, 1_048_576u32);
        assert!(metadata.argon2_params.is_some());
    }

    #[test]
    fn test_progress_reporting_monotonic_and_100_percent() {
        use std::sync::Mutex as StdMutex;

        let temp = TempDir::new().unwrap();
        // >= 4 MiB of (mostly incompressible) data.
        let input_file = temp.path().join("big.bin");
        let mut data = vec![0u8; 5 * 1_048_576];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        fs::write(&input_file, &data).unwrap();

        let output = temp.path().join("big.qenc");

        // --- Encrypt with a recording progress callback ---
        let events: std::sync::Arc<StdMutex<Vec<ProgressEvent>>> = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let events_c = events.clone();
        let enc_options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("progress pass".into()),
            original_size_hint: Some(data.len() as u64),
            progress_cb: Some(Box::new(move |e| events_c.lock().unwrap().push(e))),
            ..Default::default()
        };
        encrypt_stream(&[&input_file], File::create(&output).unwrap(), enc_options).unwrap();

        {
            let ev = events.lock().unwrap().clone();
            assert!(ev.len() >= 3, "encrypt should emit several progress events, got {}", ev.len());
            assert_eq!(ev[0].stage, ProgressStage::KeyDerivation);
            assert_eq!(ev[0].bytes_processed, 0);
            assert_eq!(ev[0].total_bytes, Some(data.len() as u64));
            let mut last_bytes = 0u64;
            for e in &ev {
                assert!(e.total_bytes.unwrap() > 0);
                assert!(e.bytes_processed >= last_bytes, "bytes_processed must be monotonic");
                assert!((0.0..=100.0).contains(&e.percent), "percent must be 0..=100, got {}", e.percent);
                last_bytes = e.bytes_processed;
            }
            let last = ev.last().unwrap();
            assert_eq!(last.stage, ProgressStage::Finalizing);
            assert!((last.percent - 100.0).abs() < 1e-9, "final percent must be 100, got {}", last.percent);
            assert!(ev.iter().any(|e| e.mb_per_sec > 0.0), "at least one event must report mb_per_sec > 0");
        }

        // --- Decrypt with a recording progress callback ---
        let input_size = std::fs::metadata(&output).unwrap().len();
        let devents: std::sync::Arc<StdMutex<Vec<ProgressEvent>>> = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let devents_c = devents.clone();
        let restore = temp.path().join("restored");
        let dec_options = DecryptOptions {
            passphrase: Some("progress pass".into()),
            input_size_hint: Some(input_size),
            progress_cb: Some(Box::new(move |e| devents_c.lock().unwrap().push(e))),
            ..Default::default()
        };
        decrypt_stream(
            std::io::BufReader::new(File::open(&output).unwrap()),
            &restore,
            dec_options,
        )
        .unwrap();

        {
            let ev = devents.lock().unwrap().clone();
            assert!(ev.len() >= 3, "decrypt should emit several progress events, got {}", ev.len());
            assert_eq!(ev[0].stage, ProgressStage::KeyDerivation);
            assert_eq!(ev[0].total_bytes, Some(input_size));
            let mut last_bytes = 0u64;
            for e in &ev {
                assert!(e.total_bytes.unwrap() > 0);
                assert!(e.bytes_processed >= last_bytes, "bytes_processed must be monotonic");
                assert!((0.0..=100.0).contains(&e.percent));
                last_bytes = e.bytes_processed;
            }
            let last = ev.last().unwrap();
            assert_eq!(last.stage, ProgressStage::Finalizing);
            assert!((last.percent - 100.0).abs() < 1e-9);
            assert!(ev.iter().any(|e| e.mb_per_sec > 0.0));
        }

        // Restored content matches (single-file input is stored under its name).
        assert_eq!(fs::read(restore.join("big.bin")).unwrap(), data);
    }

    fn make_stream(name: &str, bytes: Vec<u8>) -> NamedStreamInput {
        NamedStreamInput { name: name.to_string(), size: bytes.len() as u64, reader: Box::new(Cursor::new(bytes)) }
    }

    #[test]
    fn test_named_streams_roundtrip_passphrase_multichunk_dedupe() {
        use std::sync::Mutex as StdMutex;

        let temp = TempDir::new().unwrap();

        // ~3 MiB incompressible-ish stream (multi-chunk) + two colliding names.
        let mut big = vec![0u8; 3 * 1_048_576];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(131).wrapping_add(17);
        }
        let entries = vec![
            make_stream("report.pdf", b"first report".to_vec()),
            make_stream("report.pdf", b"second report".to_vec()),
            make_stream("big.bin", big.clone()),
        ];
        let total_in: u64 = entries.iter().map(|e| e.size).sum();

        let output = temp.path().join("named.qenc");

        let events: std::sync::Arc<StdMutex<Vec<ProgressEvent>>> = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let events_c = events.clone();
        let options = EncryptOptions {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::Balanced,
            passphrase: Some("named pass".into()),
            ..Default::default()
        };
        let stats = encrypt_named_streams(
            entries,
            File::create(&output).unwrap(),
            &options,
            Some(Box::new(move |e| events_c.lock().unwrap().push(e))),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(stats.original_size, total_in);
        assert!(stats.output_size > 0);

        // Progress monotonic + reaches 100%.
        {
            let ev = events.lock().unwrap().clone();
            assert!(ev.len() >= 3);
            assert_eq!(ev[0].stage, ProgressStage::KeyDerivation);
            let mut last = 0u64;
            for e in &ev {
                assert!(e.total_bytes.unwrap() > 0);
                assert!(e.bytes_processed >= last);
                assert!((0.0..=100.0).contains(&e.percent));
                last = e.bytes_processed;
            }
            assert!((ev.last().unwrap().percent - 100.0).abs() < 1e-9);
            assert!(ev.iter().any(|e| e.mb_per_sec > 0.0));
        }

        // Inspect + decrypt.
        let meta = crate::inspect_header(&mut File::open(&output).unwrap()).unwrap();
        assert_eq!(meta.key_mode, KeyMode::Passphrase);

        let restore = temp.path().join("restored");
        let dopts = DecryptOptions { passphrase: Some("named pass".into()), ..Default::default() };
        decrypt_stream(File::open(&output).unwrap(), &restore, dopts).unwrap();

        // Collision de-duplicated; contents preserved.
        assert_eq!(fs::read(restore.join("report.pdf")).unwrap(), b"first report");
        assert_eq!(fs::read(restore.join("report (1).pdf")).unwrap(), b"second report");
        assert_eq!(fs::read(restore.join("big.bin")).unwrap(), big);
    }

    #[test]
    fn test_named_streams_roundtrip_hybrid_pqc() {
        let temp = TempDir::new().unwrap();

        let (public, secret) = crate::crypto::generate_full_hybrid_keypair().unwrap();
        let pub_path = temp.path().join("id.qenc.pub");
        let sec_path = temp.path().join("id.qenc.sec");
        crate::crypto::save_public_key(&pub_path, &public).unwrap();
        crate::crypto::save_full_secret_key(&sec_path, &secret, None).unwrap();

        let entries = vec![
            make_stream("a.txt", b"alpha".to_vec()),
            make_stream("b.txt", vec![7u8; 400_000]),
        ];
        let output = temp.path().join("named_hybrid.qenc");

        let options = EncryptOptions {
            mode: KeyMode::HybridPqc,
            profile: CompressionProfile::Ultra,
            passphrase: None,
            recipient_pubkey_path: Some(pub_path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        encrypt_named_streams(entries, File::create(&output).unwrap(), &options, None, Arc::new(AtomicBool::new(false))).unwrap();

        let meta = crate::inspect_header(&mut File::open(&output).unwrap()).unwrap();
        assert_eq!(meta.key_mode, KeyMode::HybridPqc);

        let restore = temp.path().join("restored");
        let dopts = DecryptOptions {
            secret_key_path: Some(sec_path.to_string_lossy().into_owned()),
            input_size_hint: Some(std::fs::metadata(&output).unwrap().len()),
            ..Default::default()
        };
        decrypt_stream(File::open(&output).unwrap(), &restore, dopts).unwrap();

        assert_eq!(fs::read(restore.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(restore.join("b.txt")).unwrap(), vec![7u8; 400_000]);
    }
}