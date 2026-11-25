//! Binary header serialization, parsing, and validation for .qenc format.

use std::io::{Read, Write, Cursor};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Sha256, Digest};
use crate::{
    Result, QencError, QencMetadata, KeyMode, CompressionProfile, Argon2Params,
    MAGIC, VERSION,
};

/// Raw header structure for serialization.
#[derive(Debug, Clone)]
pub struct RawHeader {
    pub version: u8,
    pub key_mode: u8,
    pub comp_profile: u8,
    pub chunk_size: u32,
    pub nonce_prefix: [u8; 16],
    pub original_size: u64,
    pub key_data: Vec<u8>,
}

/// Encodes the header to bytes.
#[must_use]
pub fn encode_header(header: &RawHeader) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    let _ = buf.write_u8(header.version);
    let _ = buf.write_u8(header.key_mode);
    let _ = buf.write_u8(header.comp_profile);
    let _ = buf.write_u32::<LittleEndian>(header.chunk_size);
    buf.extend_from_slice(&header.nonce_prefix);
    let _ = buf.write_u64::<LittleEndian>(header.original_size);
    #[allow(clippy::cast_possible_truncation)]
    let _ = buf.write_u32::<LittleEndian>(header.key_data.len() as u32);
    buf.extend_from_slice(&header.key_data);
    buf
}

/// Decodes the header from bytes.
pub fn decode_header(bytes: &[u8]) -> Result<RawHeader> {
    let mut cursor = Cursor::new(bytes);

    // Check magic
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(QencError::InvalidMagic);
    }

    let version = cursor.read_u8()?;
    if version != VERSION {
        return Err(QencError::UnsupportedVersion(version));
    }

    let key_mode = cursor.read_u8()?;
    if KeyMode::from_u8(key_mode).is_none() {
        return Err(QencError::UnsupportedKeyMode(key_mode));
    }

    let comp_profile = cursor.read_u8()?;
    if CompressionProfile::from_u8(comp_profile).is_none() {
        return Err(QencError::UnsupportedCompressionProfile(comp_profile));
    }

    let chunk_size = cursor.read_u32::<LittleEndian>()?;
    if chunk_size == 0 || chunk_size > 16_777_216 {
        return Err(QencError::InvalidChunkSize(chunk_size));
    }

    let mut nonce_prefix = [0u8; 16];
    cursor.read_exact(&mut nonce_prefix)?;

    let original_size = cursor.read_u64::<LittleEndian>()?;

    let key_data_len = cursor.read_u32::<LittleEndian>()? as usize;
    let mut key_data = vec![0u8; key_data_len];
    cursor.read_exact(&mut key_data)?;

    // Validate key_data length based on mode
    match KeyMode::from_u8(key_mode) {
        Some(KeyMode::Passphrase) => {
            if key_data_len != 16 + 4 + 4 + 4 {
                return Err(QencError::InvalidHeader(
                    "Invalid key data length for Passphrase mode".into(),
                ));
            }
        }
        Some(KeyMode::HybridPqc) => {
            // 32 bytes ephemeral X25519 PK + 1568 bytes ML-KEM-1024 ciphertext
            if key_data_len != 32 + 1568 {
                return Err(QencError::InvalidHeader(
                    "Invalid key data length for HybridPqc mode".into(),
                ));
            }
        }
        None => return Err(QencError::UnsupportedKeyMode(key_mode)),
    }

    Ok(RawHeader {
        version,
        key_mode,
        comp_profile,
        chunk_size,
        nonce_prefix,
        original_size,
        key_data,
    })
}

/// Parses Argon2 parameters from `key_data` in Passphrase mode.
pub fn parse_argon2_params(key_data: &[u8]) -> Result<Argon2Params> {
    if key_data.len() != 16 + 4 + 4 + 4 {
        return Err(QencError::InvalidHeader("Invalid Argon2 params length".into()));
    }
    let mut cursor = Cursor::new(&key_data[16..]);
    let m_cost_kib = cursor.read_u32::<LittleEndian>()?;
    let t_cost = cursor.read_u32::<LittleEndian>()?;
    let p_cost = cursor.read_u32::<LittleEndian>()?;

    // DoS protection: reject excessive parameters
    if m_cost_kib > crate::MAX_ARGON2_M_COST_KIB {
        return Err(QencError::InvalidHeader(
            format!("Argon2 memory cost {} KiB exceeds maximum {}", m_cost_kib, crate::MAX_ARGON2_M_COST_KIB),
        ));
    }
    if t_cost > crate::MAX_ARGON2_T_COST {
        return Err(QencError::InvalidHeader(
            format!("Argon2 time cost {} exceeds maximum {}", t_cost, crate::MAX_ARGON2_T_COST),
        ));
    }
    if p_cost == 0 || p_cost > 16 {
        return Err(QencError::InvalidHeader(
            format!("Argon2 parallelism {p_cost} invalid"),
        ));
    }

    Ok(Argon2Params { m_cost_kib, t_cost, p_cost })
}

/// Parses Hybrid PQC key data.
pub fn parse_hybrid_key_data(key_data: &[u8]) -> Result<([u8; 32], [u8; 1568])> {
    if key_data.len() != 32 + 1568 {
        return Err(QencError::InvalidHeader("Invalid Hybrid PQC key data length".into()));
    }
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&key_data[0..32]);
    let mut ciphertext = [0u8; 1568];
    ciphertext.copy_from_slice(&key_data[32..]);
    Ok((ephemeral_pk, ciphertext))
}

/// Computes the SHA-256 hash of the exact raw header bytes.
#[must_use]
pub fn compute_header_hash(header_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(header_bytes);
    hasher.finalize().into()
}

/// Builds the AAD for a chunk: `header_hash` (32) || `chunk_index` (8) || `is_final` (1)
#[must_use]
pub fn build_chunk_aad(header_hash: &[u8; 32], chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 1);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(u8::from(is_final));
    aad
}

/// Builds the 24-byte nonce for a chunk: `nonce_prefix` (16) || `chunk_index` (8)
#[must_use]
pub fn build_chunk_nonce(nonce_prefix: &[u8; 16], chunk_index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..16].copy_from_slice(nonce_prefix);
    nonce[16..24].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

/// Inspects a .qenc file header without decrypting.
pub fn inspect_header<R: Read>(reader: &mut R) -> Result<QencMetadata> {
    // Read the fixed-size header portion first to get key_data_len
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(QencError::InvalidMagic);
    }

    let version = reader.read_u8()?;
    if version != VERSION {
        return Err(QencError::UnsupportedVersion(version));
    }

    let key_mode = reader.read_u8()?;
    let key_mode_enum = KeyMode::from_u8(key_mode).ok_or(QencError::UnsupportedKeyMode(key_mode))?;

    let comp_profile = reader.read_u8()?;
    let comp_profile_enum = CompressionProfile::from_u8(comp_profile).ok_or(QencError::UnsupportedCompressionProfile(comp_profile))?;

    let chunk_size = reader.read_u32::<LittleEndian>()?;
    if chunk_size == 0 || chunk_size > 16_777_216 {
        return Err(QencError::InvalidChunkSize(chunk_size));
    }

    let mut nonce_prefix = [0u8; 16];
    reader.read_exact(&mut nonce_prefix)?;

    let original_size = reader.read_u64::<LittleEndian>()?;

    let key_data_len = reader.read_u32::<LittleEndian>()? as usize;
    let mut key_data = vec![0u8; key_data_len];
    reader.read_exact(&mut key_data)?;

    let mut metadata = QencMetadata {
        version,
        key_mode: key_mode_enum,
        compression_profile: comp_profile_enum,
        chunk_size,
        original_size,
        argon2_params: None,
        ephemeral_x25519_pk: None,
        mlkem_ciphertext: None,
    };

    match key_mode_enum {
        KeyMode::Passphrase => {
            metadata.argon2_params = Some(parse_argon2_params(&key_data)?);
        }
        KeyMode::HybridPqc => {
            let (ephemeral_pk, ciphertext) = parse_hybrid_key_data(&key_data)?;
            metadata.ephemeral_x25519_pk = Some(ephemeral_pk);
            metadata.mlkem_ciphertext = Some(ciphertext.to_vec());
        }
    }

    Ok(metadata)
}

/// Reads the full header and returns the header bytes and parsed `RawHeader`.
pub fn read_full_header<R: Read>(reader: &mut R) -> Result<(Vec<u8>, RawHeader)> {
    // We need to read the header in a way that captures the exact bytes for hashing
    let mut header_bytes = Vec::new();

    // Read magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    header_bytes.extend_from_slice(&magic);

    let version = reader.read_u8()?;
    header_bytes.write_u8(version)?;

    let key_mode = reader.read_u8()?;
    header_bytes.write_u8(key_mode)?;

    let comp_profile = reader.read_u8()?;
    header_bytes.write_u8(comp_profile)?;

    let chunk_size = reader.read_u32::<LittleEndian>()?;
    header_bytes.write_u32::<LittleEndian>(chunk_size)?;

    let mut nonce_prefix = [0u8; 16];
    reader.read_exact(&mut nonce_prefix)?;
    header_bytes.extend_from_slice(&nonce_prefix);

    let original_size = reader.read_u64::<LittleEndian>()?;
    header_bytes.write_u64::<LittleEndian>(original_size)?;

    let key_data_len = reader.read_u32::<LittleEndian>()?;
    header_bytes.write_u32::<LittleEndian>(key_data_len)?;

    let mut key_data = vec![0u8; key_data_len as usize];
    reader.read_exact(&mut key_data)?;
    header_bytes.extend_from_slice(&key_data);

    // Now parse the header from the bytes we collected
    let raw_header = decode_header(&header_bytes)?;

    Ok((header_bytes, raw_header))
}

/// Writes a complete header to a writer.
pub fn write_header<W: Write>(writer: &mut W, header: &RawHeader) -> Result<()> {
    let encoded = encode_header(header);
    writer.write_all(&encoded)?;
    Ok(())
}

/// Chunk record for reading/writing encrypted chunks.
#[derive(Debug)]
pub struct ChunkRecord {
    pub is_final: bool,
    pub ciphertext: Vec<u8>,
}

/// Reads a chunk record from the stream.
pub fn read_chunk_record<R: Read>(reader: &mut R) -> Result<Option<ChunkRecord>> {
    let mut flag = [0u8; 1];
    match reader.read_exact(&mut flag) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let is_final = flag[0] == 1;
    if flag[0] > 1 {
        return Err(QencError::InvalidHeader(format!("Invalid chunk flag: {}", flag[0])));
    }

    let ciphertext_len = reader.read_u32::<LittleEndian>()? as usize;
    // Ciphertext includes 16-byte Poly1305 tag
    if ciphertext_len < 16 {
        return Err(QencError::InvalidHeader("Ciphertext too short for AEAD tag".into()));
    }

    let mut ciphertext = vec![0u8; ciphertext_len];
    reader.read_exact(&mut ciphertext)?;

    Ok(Some(ChunkRecord { is_final, ciphertext }))
}

/// Writes a chunk record to the stream.
pub fn write_chunk_record<W: Write>(writer: &mut W, is_final: bool, ciphertext: &[u8]) -> Result<()> {
    writer.write_u8(u8::from(is_final))?;
    writer.write_u32::<LittleEndian>(ciphertext.len() as u32)?;
    writer.write_all(ciphertext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_CHUNK_SIZE, DEFAULT_ARGON2_DESKTOP};

    #[test]
    fn test_header_roundtrip_passphrase() {
        let params = DEFAULT_ARGON2_DESKTOP;
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&[0u8; 16]); // salt placeholder
        key_data.write_u32::<LittleEndian>(params.m_cost_kib).unwrap();
        key_data.write_u32::<LittleEndian>(params.t_cost).unwrap();
        key_data.write_u32::<LittleEndian>(params.p_cost).unwrap();

        let header = RawHeader {
            version: VERSION,
            key_mode: KeyMode::Passphrase as u8,
            comp_profile: CompressionProfile::Balanced as u8,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [42u8; 16],
            original_size: 1024,
            key_data,
        };

        let encoded = encode_header(&header);
        let decoded = decode_header(&encoded).unwrap();

        assert_eq!(decoded.version, header.version);
        assert_eq!(decoded.key_mode, header.key_mode);
        assert_eq!(decoded.comp_profile, header.comp_profile);
        assert_eq!(decoded.chunk_size, header.chunk_size);
        assert_eq!(decoded.nonce_prefix, header.nonce_prefix);
        assert_eq!(decoded.original_size, header.original_size);
        assert_eq!(decoded.key_data, header.key_data);
    }

    #[test]
    fn test_header_roundtrip_hybrid() {
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&[1u8; 32]); // ephemeral pk
        key_data.extend_from_slice(&[2u8; 1568]); // mlkem ciphertext

        let header = RawHeader {
            version: VERSION,
            key_mode: KeyMode::HybridPqc as u8,
            comp_profile: CompressionProfile::Ultra as u8,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [99u8; 16],
            original_size: 2048,
            key_data,
        };

        let encoded = encode_header(&header);
        let decoded = decode_header(&encoded).unwrap();

        assert_eq!(decoded.version, header.version);
        assert_eq!(decoded.key_mode, header.key_mode);
        assert_eq!(decoded.comp_profile, header.comp_profile);
        assert_eq!(decoded.key_data, header.key_data);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bad_header = encode_header(&RawHeader {
            version: VERSION,
            key_mode: KeyMode::Passphrase as u8,
            comp_profile: CompressionProfile::Balanced as u8,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [0u8; 16],
            original_size: 0,
            key_data: vec![0u8; 28],
        });
        bad_header[0] = b'X'; // Corrupt magic
        assert!(matches!(decode_header(&bad_header), Err(QencError::InvalidMagic)));
    }

    #[test]
    fn test_invalid_version() {
        let bad_header = encode_header(&RawHeader {
            version: 99,
            key_mode: KeyMode::Passphrase as u8,
            comp_profile: CompressionProfile::Balanced as u8,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [0u8; 16],
            original_size: 0,
            key_data: vec![0u8; 28],
        });
        assert!(matches!(decode_header(&bad_header), Err(QencError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_invalid_key_mode() {
        let bad_header = encode_header(&RawHeader {
            version: VERSION,
            key_mode: 99,
            comp_profile: CompressionProfile::Balanced as u8,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [0u8; 16],
            original_size: 0,
            key_data: vec![0u8; 28],
        });
        assert!(matches!(decode_header(&bad_header), Err(QencError::UnsupportedKeyMode(99))));
    }

    #[test]
    fn test_invalid_compression_profile() {
        let bad_header = encode_header(&RawHeader {
            version: VERSION,
            key_mode: KeyMode::Passphrase as u8,
            comp_profile: 99,
            chunk_size: DEFAULT_CHUNK_SIZE,
            nonce_prefix: [0u8; 16],
            original_size: 0,
            key_data: vec![0u8; 28],
        });
        assert!(matches!(decode_header(&bad_header), Err(QencError::UnsupportedCompressionProfile(99))));
    }

    #[test]
    fn test_chunk_aad_nonce_building() {
        let header_hash = [1u8; 32];
        let nonce_prefix = [2u8; 16];

        let aad = build_chunk_aad(&header_hash, 0, false);
        assert_eq!(aad.len(), 41);
        assert_eq!(&aad[0..32], &header_hash);
        assert_eq!(&aad[32..40], &0u64.to_le_bytes());
        assert_eq!(aad[40], 0);

        let aad_final = build_chunk_aad(&header_hash, 5, true);
        assert_eq!(aad_final[40], 1);

        let nonce = build_chunk_nonce(&nonce_prefix, 0);
        assert_eq!(&nonce[0..16], &nonce_prefix);
        assert_eq!(&nonce[16..24], &0u64.to_le_bytes());

        let nonce5 = build_chunk_nonce(&nonce_prefix, 5);
        assert_eq!(&nonce5[16..24], &5u64.to_le_bytes());
    }

    #[test]
    fn test_argon2_params_validation() {
        // Valid desktop params
        let params = Argon2Params { m_cost_kib: 131_072, t_cost: 3, p_cost: 2 };
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&[0u8; 16]);
        key_data.write_u32::<LittleEndian>(params.m_cost_kib).unwrap();
        key_data.write_u32::<LittleEndian>(params.t_cost).unwrap();
        key_data.write_u32::<LittleEndian>(params.p_cost).unwrap();
        assert!(parse_argon2_params(&key_data).is_ok());

        // Excessive memory cost
        let mut bad_key_data = Vec::new();
        bad_key_data.extend_from_slice(&[0u8; 16]);
        bad_key_data.write_u32::<LittleEndian>(600_000).unwrap();
        bad_key_data.write_u32::<LittleEndian>(3).unwrap();
        bad_key_data.write_u32::<LittleEndian>(2).unwrap();
        assert!(matches!(parse_argon2_params(&bad_key_data), Err(QencError::InvalidHeader(_))));

        // Excessive time cost
        let mut bad_key_data = Vec::new();
        bad_key_data.extend_from_slice(&[0u8; 16]);
        bad_key_data.write_u32::<LittleEndian>(131_072).unwrap();
        bad_key_data.write_u32::<LittleEndian>(20).unwrap();
        bad_key_data.write_u32::<LittleEndian>(2).unwrap();
        assert!(matches!(parse_argon2_params(&bad_key_data), Err(QencError::InvalidHeader(_))));

        // Zero parallelism
        let mut bad_key_data = Vec::new();
        bad_key_data.extend_from_slice(&[0u8; 16]);
        bad_key_data.write_u32::<LittleEndian>(131_072).unwrap();
        bad_key_data.write_u32::<LittleEndian>(3).unwrap();
        bad_key_data.write_u32::<LittleEndian>(0).unwrap();
        assert!(matches!(parse_argon2_params(&bad_key_data), Err(QencError::InvalidHeader(_))));
    }
}