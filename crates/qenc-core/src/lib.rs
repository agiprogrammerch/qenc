//! QENC Core - Post-Quantum Encrypted Container Engine
//!
//! This crate provides the core cryptographic, compression, and archive functionality
//! for the `.qenc` file format. It is designed to be a pure-Rust, zero-unsafe,
//! streaming engine with no panics on malformed inputs.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::or_fun_call,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::option_if_let_else,
    clippy::multiple_crate_versions,
)]

pub mod archive;
pub mod crypto;
pub mod format;
pub mod pipeline;

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use thiserror::Error;

/// Compression profile for the streaming Zstd encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum CompressionProfile {
    /// Zstd level 3 - maximum speed, lower compression ratio
    Turbo = 1,
    /// Zstd level 9 - balanced speed and compression (default)
    #[default]
    Balanced = 2,
    /// Zstd level 19 - maximum compression ratio, slower
    Ultra = 3,
}


impl CompressionProfile {
    /// Returns the Zstd compression level for this profile.
    #[must_use]
    pub const fn zstd_level(&self) -> i32 {
        match self {
            Self::Turbo => 3,
            Self::Balanced => 9,
            Self::Ultra => 19,
        }
    }

    /// Creates a `CompressionProfile` from a u8 value (for header parsing).
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Turbo),
            2 => Some(Self::Balanced),
            3 => Some(Self::Ultra),
            _ => None,
        }
    }
}

/// Authentication mode for key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum KeyMode {
    /// Passphrase-based using Argon2id
    Passphrase = 1,
    /// Hybrid X25519 + ML-KEM-1024
    HybridPqc = 2,
}

impl KeyMode {
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Passphrase),
            2 => Some(Self::HybridPqc),
            _ => None,
        }
    }
}

/// Configuration options for encryption operations.
pub struct EncryptOptions {
    /// Authentication mode
    pub mode: KeyMode,
    /// Compression profile
    pub profile: CompressionProfile,
    /// Passphrase for Passphrase mode (ignored in `HybridPqc` mode)
    pub passphrase: Option<String>,
    /// Recipient public key file path for `HybridPqc` mode
    pub recipient_pubkey_path: Option<String>,
    /// Optional progress callback (throttled to ~20 updates/sec)
    pub progress_cb: Option<Box<dyn Fn(ProgressEvent) + Send>>,
    /// Cancellation flag checked every chunk
    pub cancel: Option<Arc<AtomicBool>>,
    /// Estimated original size for progress reporting (if known)
    pub original_size_hint: Option<u64>,
    /// Force the low-memory ("mobile") Argon2id params. Safe cross-platform:
    /// params are recorded in the header, so desktop can still decrypt.
    pub argon2_mobile_hint: Option<bool>,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            mode: KeyMode::Passphrase,
            profile: CompressionProfile::default(),
            passphrase: None,
            recipient_pubkey_path: None,
            progress_cb: None,
            cancel: None,
            original_size_hint: None,
            argon2_mobile_hint: None,
        }
    }
}

/// Configuration options for decryption operations.
#[derive(Default)]
pub struct DecryptOptions {
    /// Passphrase for Passphrase mode
    pub passphrase: Option<String>,
    /// Secret key file path for `HybridPqc` mode
    pub secret_key_path: Option<String>,
    /// Optional passphrase to decrypt the secret key file
    pub secret_key_passphrase: Option<String>,
    /// Optional progress callback
    pub progress_cb: Option<Box<dyn Fn(ProgressEvent) + Send>>,
    /// Cancellation flag checked every chunk
    pub cancel: Option<Arc<AtomicBool>>,
    /// Size of the .qenc input in bytes (if known), for linear progress 0%->100%
    pub input_size_hint: Option<u64>,
}


/// Progress event for streaming operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProgressEvent {
    /// Current processing stage
    pub stage: ProgressStage,
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Total bytes expected (if known)
    pub total_bytes: Option<u64>,
    /// Output bytes written so far
    pub output_bytes: u64,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
    /// Throughput in MB/s
    pub mb_per_sec: f64,
    /// Completion percentage, clamped to `0.0..=100.0`
    pub percent: f64,
}

/// Processing stage for progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProgressStage {
    /// Deriving the master key (Argon2id or Hybrid PQC encapsulation)
    KeyDerivation,
    /// Reading and packing input files into TAR
    Archiving,
    /// Compressing the TAR stream
    Compressing,
    /// Encrypting compressed chunks
    Encrypting,
    /// Decrypting chunks
    Decrypting,
    /// Decompressing decrypted stream
    Decompressing,
    /// Extracting TAR entries
    Extracting,
    /// Finalizing (writing header, flushing)
    Finalizing,
}

/// Metadata parsed from a .qenc file header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QencMetadata {
    /// File format version (currently 1)
    pub version: u8,
    /// Key mode used
    pub key_mode: KeyMode,
    /// Compression profile used
    pub compression_profile: CompressionProfile,
    /// Chunk size in bytes
    pub chunk_size: u32,
    /// Original uncompressed size estimate
    pub original_size: u64,
    /// Argon2id parameters (if Passphrase mode)
    pub argon2_params: Option<Argon2Params>,
    /// Ephemeral X25519 public key (if `HybridPqc` mode)
    pub ephemeral_x25519_pk: Option<[u8; 32]>,
    /// ML-KEM-1024 ciphertext (if `HybridPqc` mode)
    pub mlkem_ciphertext: Option<Vec<u8>>,
}

/// Argon2id parameters stored in the header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub m_cost_kib: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

/// Errors that can occur during QENC operations.
#[derive(Debug, Error)]
pub enum QencError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid magic bytes: expected QENC")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported key mode: {0}")]
    UnsupportedKeyMode(u8),

    #[error("Unsupported compression profile: {0}")]
    UnsupportedCompressionProfile(u8),

    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(u32),

    #[error("Argon2 error: {0}")]
    Argon2(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Archive error: {0}")]
    Archive(String),

    #[error("Authentication failed: wrong passphrase or corrupted data")]
    AuthenticationFailed,

    #[error("Integrity check failed: data tampered or corrupted")]
    IntegrityCheckFailed,

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("ML-KEM error: {0}")]
    MlKem(String),

    #[error("X25519 error: {0}")]
    X25519(String),

    #[error("HKDF error: {0}")]
    Hkdf(String),

    #[error("Path traversal attempt detected: {0}")]
    PathTraversal(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Chunk index overflow")]
    ChunkIndexOverflow,

    #[error("Unexpected EOF")]
    UnexpectedEof,

    #[error("Trailing data after final chunk")]
    TrailingData,

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<argon2::Error> for QencError {
    fn from(e: argon2::Error) -> Self {
        Self::Argon2(e.to_string())
    }
}

/// Result type for QENC operations.
pub type Result<T> = std::result::Result<T, QencError>;

/// Boxed progress callback used by the streaming APIs.
pub type ProgressCallback = Box<dyn Fn(ProgressEvent) + Send>;

/// A named in-memory byte stream to be encrypted.
///
/// On Android, Storage Access Framework hands back readable file descriptors
/// (`content://` URIs) rather than raw filesystem paths. Instead of copying
/// large files to temp storage, callers wrap each handle in a `NamedStreamInput`
/// and hand it to [`encrypt_named_streams`].
pub struct NamedStreamInput {
    /// Display/archive name for this stream (will be sanitized + de-duplicated).
    pub name: String,
    /// Exact byte length of the stream, used for progress + the TAR header.
    pub size: u64,
    /// The readable byte source.
    pub reader: Box<dyn std::io::Read + Send>,
}

/// Summary statistics returned by [`encrypt_named_streams`].
#[derive(Debug, Clone, Default)]
pub struct EncryptStats {
    /// Total raw input bytes packed.
    pub original_size: u64,
    /// Final `.qenc` container size in bytes.
    pub output_size: u64,
    /// Wall-clock elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Average throughput in MB/s.
    pub avg_mb_per_sec: f64,
    /// Output size as a percentage of the input size (clamped, NaN-safe).
    pub compression_ratio_percent: f64,
}

/// Default Argon2id parameters for desktop (higher security).
pub const DEFAULT_ARGON2_DESKTOP: Argon2Params = Argon2Params {
    m_cost_kib: 131_072, // 128 MiB
    t_cost: 3,
    p_cost: 2,
};

/// Default Argon2id parameters for mobile (lower memory).
pub const DEFAULT_ARGON2_MOBILE: Argon2Params = Argon2Params {
    m_cost_kib: 65_536, // 64 MiB
    t_cost: 3,
    p_cost: 1,
};

/// Maximum allowed Argon2id memory cost (512 MiB) to prevent `DoS`.
pub const MAX_ARGON2_M_COST_KIB: u32 = 524_288;

/// Maximum allowed Argon2id time cost to prevent `DoS`.
pub const MAX_ARGON2_T_COST: u32 = 16;

/// Default chunk size: 1 MiB
pub const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

/// Header magic bytes
pub const MAGIC: &[u8; 4] = b"QENC";

/// Current format version
pub const VERSION: u8 = 1;

/// HKDF info string for hybrid key derivation
pub const HKDF_INFO: &[u8] = b"QENC-V1-HYBRID-MASTER-KEY";

/// Encrypt files/directories to a .qenc container using paths.
///
/// This is the high-level path-based API suitable for desktop CLI usage.
pub fn encrypt_paths<P: AsRef<Path>, Q: AsRef<Path>>(
    inputs: &[P],
    output: Q,
    options: EncryptOptions,
) -> Result<()> {
    let output_file = std::fs::File::create(output)?;
    let writer = std::io::BufWriter::new(output_file);
    encrypt_stream(inputs, writer, options)
}

/// Encrypt a stream of files/directories to a .qenc container.
///
/// This is the generic stream-based API suitable for Android Storage Access Framework
/// or any Read/Write implementation.
pub fn encrypt_stream<P: AsRef<Path>, W: Write + Send>(
    inputs: &[P],
    writer: W,
    options: EncryptOptions,
) -> Result<()> {
    pipeline::encrypt_stream(inputs, writer, options)
}

/// Encrypts named byte streams (Android SAF `content://` readers, in-memory
/// buffers, etc.) into a `.qenc` container without temp copies. Returns stats.
pub fn encrypt_named_streams<W: Write + Send>(
    entries: Vec<NamedStreamInput>,
    writer: W,
    options: &EncryptOptions,
    progress_cb: Option<ProgressCallback>,
    cancel: Arc<AtomicBool>,
) -> Result<EncryptStats> {
    pipeline::encrypt_named_streams(entries, writer, options, progress_cb, cancel)
}

/// Decrypt a .qenc container to a directory using paths.
pub fn decrypt_to_dir<P: AsRef<Path>, Q: AsRef<Path>>(
    input: P,
    output_dir: Q,
    options: DecryptOptions,
) -> Result<()> {
    let input_file = std::fs::File::open(input)?;
    let reader = std::io::BufReader::new(input_file);
    decrypt_stream(reader, output_dir, options)
}

/// Decrypt a .qenc container from a stream to a directory.
pub fn decrypt_stream<R: Read + Send, P: AsRef<Path>>(
    reader: R,
    output_dir: P,
    options: DecryptOptions,
) -> Result<()> {
    pipeline::decrypt_stream(reader, output_dir, options)
}

/// Inspect a .qenc file header without decrypting.
pub fn inspect_header<R: Read>(reader: &mut R) -> Result<QencMetadata> {
    format::inspect_header(reader)
}

/// Generate a new Hybrid PQC keypair.
///
/// Returns (`public_key_bytes`[1600], `secret_key_bytes`[64] - simplified format with seeds only).
pub fn generate_keypair() -> Result<([u8; 1600], [u8; 64])> {
    crypto::generate_hybrid_keypair()
}

/// Serialize a public key to a file.
pub fn save_public_key<P: AsRef<Path>>(path: P, public_key: &[u8; 1600]) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(public_key)?;
    Ok(())
}

/// Serialize a secret key to a file, optionally encrypted with a passphrase.
pub fn save_secret_key<P: AsRef<Path>>(
    path: P,
    secret_key: &[u8; 64],
    passphrase: Option<&str>,
) -> Result<()> {
    crypto::save_secret_key(path, secret_key, passphrase)
}

/// Load a public key from a file.
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<[u8; 1600]> {
    let mut file = std::fs::File::open(path)?;
    let mut key = [0u8; 1600];
    file.read_exact(&mut key)?;
    Ok(key)
}

/// Load a secret key from a file, optionally decrypting with a passphrase.
pub fn load_secret_key<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> Result<[u8; 64]> {
    crypto::load_secret_key(path, passphrase)
}

// Re-export core types for convenience
pub use crypto::{HybridPublicKey, HybridSecretKey};
// KeyMode and CompressionProfile are defined in this crate and publicly exported
// EncryptOptions, DecryptOptions, ProgressEvent, ProgressStage are defined in this crate