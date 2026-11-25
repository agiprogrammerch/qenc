//! Cryptographic operations: Argon2id, Hybrid X25519 + ML-KEM-1024, HKDF-SHA256, XChaCha20-Poly1305.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit as AeadKeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use x25519_dalek::{PublicKey as X25519PublicKey};
use curve25519_dalek::scalar::Scalar as Curve25519Scalar;
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac, digest::KeyInit as DigestKeyInit};
use sha2::{Sha256};
use fips203::ml_kem_1024::{EncapsKey as MlKemEncapsKey, DecapsKey as MlKemDecapsKey, CipherText as MlKemCipherText, KG as MlKemKG};
use fips203::traits::{SerDes, Encaps, Decaps, KeyGen};
use rand_core::{RngCore, OsRng as RandOsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use crate::{Result, QencError, HKDF_INFO, DEFAULT_ARGON2_DESKTOP};

/// Clamps a 32-byte scalar for X25519 (RFC 7748).
/// Clears bits 0,1,2; clears bit 255; sets bit 254.
const fn clamp_x25519_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 0b1111_1000;  // Clear bits 0,1,2
    scalar[31] &= 0b0111_1111; // Clear bit 255
    scalar[31] |= 0b0100_0000; // Set bit 254
}

/// Generates a random X25519 secret key (properly clamped).
fn random_x25519_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    RandOsRng.fill_bytes(&mut bytes);
    clamp_x25519_scalar(&mut bytes);
    bytes
}

/// Hybrid PQC Public Key: X25519 (32 bytes) || ML-KEM-1024 (1568 bytes)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub ml_kem: [u8; 1568],
}

impl HybridPublicKey {
    /// Serializes to bytes: X25519 (32) || ML-KEM (1568) = 1600 bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 1600] {
        let mut bytes = [0u8; 1600];
        bytes[0..32].copy_from_slice(&self.x25519);
        bytes[32..1600].copy_from_slice(&self.ml_kem);
        bytes
    }

    /// Deserializes from 1600 bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 1600]) -> Self {
        let mut x25519 = [0u8; 32];
        let mut ml_kem = [0u8; 1568];
        x25519.copy_from_slice(&bytes[0..32]);
        ml_kem.copy_from_slice(&bytes[32..1600]);
        Self { x25519, ml_kem }
    }

    /// Gets the X25519 public key as dalek type
    #[must_use]
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.x25519)
    }

    /// Gets the ML-KEM encaps key as fips203 type
    #[must_use]
    pub fn ml_kem_encaps_key(&self) -> MlKemEncapsKey {
        MlKemEncapsKey::try_from_bytes(self.ml_kem).expect("Valid ML-KEM encaps key")
    }
}

/// Hybrid PQC Secret Key: X25519 (32 bytes) || ML-KEM-1024 (3168 bytes)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub x25519: [u8; 32],
    pub ml_kem: [u8; 3168], // ML-KEM-1024 private key size
}

impl HybridSecretKey {
    /// Serializes to bytes: X25519 (32) || ML-KEM (3168) = 3200 bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 3200] {
        let mut bytes = [0u8; 3200];
        bytes[0..32].copy_from_slice(&self.x25519);
        bytes[32..3200].copy_from_slice(&self.ml_kem);
        bytes
    }

    /// Deserializes from 3200 bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 3200]) -> Self {
        let mut x25519 = [0u8; 32];
        let mut ml_kem = [0u8; 3168];
        x25519.copy_from_slice(&bytes[0..32]);
        ml_kem.copy_from_slice(&bytes[32..3200]);
        Self { x25519, ml_kem }
    }

    /// Computes X25519 shared secret with an ephemeral public key using curve25519-dalek
    /// Returns the raw 32-byte shared secret (u-coordinate)
    #[must_use]
    pub fn x25519_diffie_hellman(&self, ephemeral_pk: &X25519PublicKey) -> [u8; 32] {
        // Convert ephemeral public key to MontgomeryPoint
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(ephemeral_pk.as_bytes());
        let ephemeral_point = MontgomeryPoint(pk_bytes);
        
        // Compute shared secret using curve25519-dalek's mul_clamped
        // This computes static_secret * ephemeral_point
        // The secret is already clamped during key generation
        let shared_point = ephemeral_point.mul_clamped(self.x25519);
        
        // The shared secret is the u-coordinate of the resulting point
        let mut shared_bytes = [0u8; 32];
        shared_bytes.copy_from_slice(&shared_point.0);
        shared_bytes
    }

    /// Gets the ML-KEM decaps key as fips203 type
    #[must_use]
    pub fn ml_kem_decaps_key(&self) -> MlKemDecapsKey {
        MlKemDecapsKey::try_from_bytes(self.ml_kem).expect("Valid ML-KEM decaps key")
    }
}

/// Simple HKDF-SHA256 implementation using HMAC
fn hkdf_sha256(salt: Option<&[u8]>, info: &[u8], ikm: &[u8], output: &mut [u8]) -> Result<()> {
    // HKDF-Extract
    let mut prk = [0u8; 32];
    if let Some(salt) = salt {
        let mut mac = <Hmac<Sha256> as DigestKeyInit>::new_from_slice(salt)
            .map_err(|e| QencError::Hkdf(e.to_string()))?;
        mac.update(ikm);
        prk.copy_from_slice(&mac.finalize().into_bytes());
    } else {
        // Use zero salt
        let mut mac = <Hmac<Sha256> as DigestKeyInit>::new_from_slice(&[0u8; 32])
            .map_err(|e| QencError::Hkdf(e.to_string()))?;
        mac.update(ikm);
        prk.copy_from_slice(&mac.finalize().into_bytes());
    }

    // HKDF-Expand
    let mut t = Vec::new();
    let mut counter = 1u8;
    while t.len() < output.len() {
        let mut mac = <Hmac<Sha256> as DigestKeyInit>::new_from_slice(&prk)
            .map_err(|e| QencError::Hkdf(e.to_string()))?;
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        let result = mac.finalize().into_bytes();
        t.extend_from_slice(&result);
        counter = counter.wrapping_add(1);
        if counter == 0 {
            return Err(QencError::Hkdf("HKDF counter overflow".into()));
        }
    }
    output.copy_from_slice(&t[..output.len()]);
    Ok(())
}

/// Generates a new Hybrid PQC keypair.
/// Returns (`public_key_bytes`[1600], `secret_key_bytes`[64] - simplified format with seeds only)
pub fn generate_hybrid_keypair() -> Result<([u8; 1600], [u8; 64])> {
    // Generate X25519 keypair using curve25519-dalek (properly clamped)
    let x25519_secret_bytes = random_x25519_secret();
    let x25519_scalar = Curve25519Scalar::from_bytes_mod_order(x25519_secret_bytes);
    let x25519_public_point = MontgomeryPoint::mul_base(&x25519_scalar);
    let x25519_public = X25519PublicKey::from(x25519_public_point.0);

    // Generate ML-KEM-1024 keypair
    let (ml_kem_encaps_key, _ml_kem_decaps_key) = MlKemKG::try_keygen_with_rng(&mut RandOsRng)
        .map_err(|e| QencError::MlKem(e.to_string()))?;

    // Combine public keys (1600 bytes)
    let mut public_bytes = [0u8; 1600];
    public_bytes[0..32].copy_from_slice(x25519_public.as_bytes());
    public_bytes[32..1600].copy_from_slice(&ml_kem_encaps_key.into_bytes());

    // Combine secret keys (64 bytes - just seeds for CLI keygen)
    let mut secret_bytes = [0u8; 64];
    secret_bytes[0..32].copy_from_slice(&x25519_secret_bytes);
    RandOsRng.fill_bytes(&mut secret_bytes[32..64]);

    Ok((public_bytes, secret_bytes))
}

/// Generates a full `HybridSecretKey` with complete ML-KEM private key.
pub fn generate_full_hybrid_keypair() -> Result<(HybridPublicKey, HybridSecretKey)> {
    let x25519_secret_bytes = random_x25519_secret();
    let x25519_scalar = Curve25519Scalar::from_bytes_mod_order(x25519_secret_bytes);
    let x25519_public_point = MontgomeryPoint::mul_base(&x25519_scalar);
    let x25519_public = X25519PublicKey::from(x25519_public_point.0);

    let (ml_kem_encaps_key, ml_kem_decaps_key) = MlKemKG::try_keygen_with_rng(&mut RandOsRng)
        .map_err(|e| QencError::MlKem(e.to_string()))?;

    let public = HybridPublicKey {
        x25519: *x25519_public.as_bytes(),
        ml_kem: ml_kem_encaps_key.into_bytes(),
    };

    let secret = HybridSecretKey {
        x25519: x25519_secret_bytes,
        ml_kem: ml_kem_decaps_key.into_bytes(),
    };

    Ok((public, secret))
}

/// Derives master key from passphrase using Argon2id.
pub fn derive_key_argon2id(passphrase: &str, salt: &[u8; 16], params: &crate::Argon2Params) -> Result<[u8; 32]> {
    let argon2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(32),
    ).map_err(|e| QencError::Crypto(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| QencError::Argon2(e.to_string()))?;

    Ok(output)
}

/// Derives master key using Hybrid PQC (X25519 + ML-KEM-1024).
pub fn derive_key_hybrid(
    recipient_pub: &HybridPublicKey,
) -> Result<([u8; 32], [u8; 32], [u8; 1568])> {
    // Generate ephemeral X25519 keypair using curve25519-dalek (properly clamped)
    let ephemeral_secret_bytes = random_x25519_secret();
    let ephemeral_scalar = Curve25519Scalar::from_bytes_mod_order(ephemeral_secret_bytes);
    let ephemeral_public_point = MontgomeryPoint::mul_base(&ephemeral_scalar);
    let ephemeral_public = X25519PublicKey::from(ephemeral_public_point.0);

    // X25519 ECDH using curve25519-dalek
    let recipient_point = MontgomeryPoint(recipient_pub.x25519);
    let x25519_shared_point = recipient_point.mul_clamped(ephemeral_secret_bytes);
    let mut x25519_shared = [0u8; 32];
    x25519_shared.copy_from_slice(&x25519_shared_point.0);

    // ML-KEM-1024 encapsulation
    let ml_kem_encaps_key = recipient_pub.ml_kem_encaps_key();
    // Note: fips203 returns (shared_secret, ciphertext) for encaps
    let (ml_kem_shared, ciphertext) = ml_kem_encaps_key.try_encaps_with_rng(&mut RandOsRng)
        .map_err(|e| QencError::MlKem(e.to_string()))?;

    // Combine via HKDF-SHA256
    // salt = ephemeral X25519 public key, info = "QENC-V1-HYBRID-MASTER-KEY"
    let mut master_key = [0u8; 32];
    let mut ikm = Vec::with_capacity(32 + 32);
    ikm.extend_from_slice(&x25519_shared);
    ikm.extend_from_slice(ml_kem_shared.into_bytes().as_slice());
    hkdf_sha256(Some(ephemeral_public.as_bytes()), HKDF_INFO, &ikm, &mut master_key)?;

    let mut ciphertext_bytes = [0u8; 1568];
    ciphertext_bytes.copy_from_slice(&ciphertext.into_bytes());

    Ok((master_key, *ephemeral_public.as_bytes(), ciphertext_bytes))
}

/// Recovers master key using Hybrid PQC (decryption side).
pub fn recover_key_hybrid(
    recipient_sec: &HybridSecretKey,
    ephemeral_x25519_pk: &[u8; 32],
    mlkem_ciphertext: &[u8; 1568],
) -> Result<[u8; 32]> {
    // X25519 ECDH using curve25519-dalek
    let ephemeral_pk = X25519PublicKey::from(*ephemeral_x25519_pk);
    let x25519_shared = recipient_sec.x25519_diffie_hellman(&ephemeral_pk);

    // ML-KEM-1024 decapsulation
    let ml_kem_decaps_key = recipient_sec.ml_kem_decaps_key();
    let ciphertext = MlKemCipherText::try_from_bytes(*mlkem_ciphertext)
        .map_err(|_| QencError::MlKem("Invalid ML-KEM ciphertext".into()))?;
    let ml_kem_shared = ml_kem_decaps_key.try_decaps(&ciphertext)
        .map_err(|e| QencError::MlKem(e.to_string()))?;

    // Combine via HKDF-SHA256
    let mut master_key = [0u8; 32];
    let mut ikm = Vec::with_capacity(32 + 32);
    ikm.extend_from_slice(&x25519_shared);
    ikm.extend_from_slice(ml_kem_shared.into_bytes().as_slice());
    hkdf_sha256(Some(ephemeral_x25519_pk), HKDF_INFO, &ikm, &mut master_key)?;

    Ok(master_key)
}

/// Encrypts data with XChaCha20-Poly1305 using a 24-byte nonce and AAD.
pub fn encrypt_chunk(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| QencError::Crypto("Encryption failed".into()))?;
    Ok(ciphertext)
}

/// Decrypts data with XChaCha20-Poly1305 using a 24-byte nonce and AAD.
pub fn decrypt_chunk(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| QencError::AuthenticationFailed)?;
    Ok(plaintext)
}

/// Saves a secret key to a file, optionally encrypted with a passphrase.
pub fn save_secret_key<P: AsRef<Path>>(
    path: P,
    secret_key: &[u8; 64], // Simplified 64-byte format
    passphrase: Option<&str>,
) -> Result<()> {
    let mut file = File::create(path)?;

    if let Some(pass) = passphrase {
        // Encrypt with Argon2id + XChaCha20-Poly1305
        let salt = rand::random::<[u8; 16]>();
        let params = DEFAULT_ARGON2_DESKTOP;
        let key = derive_key_argon2id(pass, &salt, &params)?;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher.encrypt(&nonce, secret_key.as_ref())
            .map_err(|_| QencError::Crypto("Secret key encryption failed".into()))?;

        // Write: version(1) || salt(16) || nonce(24) || ciphertext_len(4) || ciphertext
        file.write_all(&[1u8])?; // version
        file.write_all(&salt)?;
        file.write_all(&nonce)?;
        file.write_u32::<LittleEndian>(ciphertext.len() as u32)?;
        file.write_all(&ciphertext)?;
    } else {
        // Plaintext storage (not recommended)
        file.write_all(&[0u8])?; // version 0 = unencrypted
        file.write_all(secret_key)?;
    }

    Ok(())
}

/// Loads a secret key from a file, optionally decrypting with a passphrase.
pub fn load_secret_key<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> Result<[u8; 64]> {
    let mut file = File::open(path)?;
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;

    if version[0] == 0 {
        // Unencrypted
        let mut key = [0u8; 64];
        file.read_exact(&mut key)?;
        Ok(key)
    } else if version[0] == 1 {
        // Encrypted
        let pass = passphrase.ok_or(QencError::InvalidSecretKey("Secret key is encrypted, passphrase required".into()))?;

        let mut salt = [0u8; 16];
        file.read_exact(&mut salt)?;

        let mut nonce = [0u8; 24];
        file.read_exact(&mut nonce)?;

        let ciphertext_len = file.read_u32::<LittleEndian>()? as usize;
        let mut ciphertext = vec![0u8; ciphertext_len];
        file.read_exact(&mut ciphertext)?;

        let params = DEFAULT_ARGON2_DESKTOP;
        let key = derive_key_argon2id(pass, &salt, &params)?;

        let cipher = XChaCha20Poly1305::new(&key.into());
        let plaintext = cipher.decrypt((&nonce).into(), ciphertext.as_ref())
            .map_err(|_| QencError::AuthenticationFailed)?;

        if plaintext.len() != 64 {
            return Err(QencError::InvalidSecretKey("Decrypted secret key has invalid length".into()));
        }

        let mut result = [0u8; 64];
        result.copy_from_slice(&plaintext);
        Ok(result)
    } else {
        Err(QencError::InvalidSecretKey(format!("Unknown secret key format version: {}", version[0])))
    }
}

/// Saves a full `HybridSecretKey` (3200 bytes) to a file, optionally encrypted.
pub fn save_full_secret_key<P: AsRef<Path>>(
    path: P,
    secret_key: &HybridSecretKey,
    passphrase: Option<&str>,
) -> Result<()> {
    let bytes = secret_key.to_bytes();
    let mut file = File::create(path)?;

    if let Some(pass) = passphrase {
        let salt = rand::random::<[u8; 16]>();
        let params = DEFAULT_ARGON2_DESKTOP;
        let key = derive_key_argon2id(pass, &salt, &params)?;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher.encrypt(&nonce, bytes.as_ref())
            .map_err(|_| QencError::Crypto("Secret key encryption failed".into()))?;

        file.write_all(&[1u8])?;
        file.write_all(&salt)?;
        file.write_all(&nonce)?;
        file.write_u32::<LittleEndian>(ciphertext.len() as u32)?;
        file.write_all(&ciphertext)?;
    } else {
        file.write_all(&[0u8])?;
        file.write_all(&bytes)?;
    }

    Ok(())
}

/// Loads a full `HybridSecretKey` (3200 bytes) from a file.
pub fn load_full_secret_key<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> Result<HybridSecretKey> {
    let mut file = File::open(path)?;
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;

    if version[0] == 0 {
        let mut bytes = [0u8; 3200];
        file.read_exact(&mut bytes)?;
        Ok(HybridSecretKey::from_bytes(&bytes))
    } else if version[0] == 1 {
        let pass = passphrase.ok_or(QencError::InvalidSecretKey("Secret key is encrypted, passphrase required".into()))?;

        let mut salt = [0u8; 16];
        file.read_exact(&mut salt)?;

        let mut nonce = [0u8; 24];
        file.read_exact(&mut nonce)?;

        let ciphertext_len = file.read_u32::<LittleEndian>()? as usize;
        let mut ciphertext = vec![0u8; ciphertext_len];
        file.read_exact(&mut ciphertext)?;

        let params = DEFAULT_ARGON2_DESKTOP;
        let key = derive_key_argon2id(pass, &salt, &params)?;

        let cipher = XChaCha20Poly1305::new(&key.into());
        let plaintext = cipher.decrypt((&nonce).into(), ciphertext.as_ref())
            .map_err(|_| QencError::AuthenticationFailed)?;

        if plaintext.len() != 3200 {
            return Err(QencError::InvalidSecretKey("Decrypted secret key has invalid length".into()));
        }

        let mut bytes = [0u8; 3200];
        bytes.copy_from_slice(&plaintext);
        Ok(HybridSecretKey::from_bytes(&bytes))
    } else {
        Err(QencError::InvalidSecretKey(format!("Unknown secret key format version: {}", version[0])))
    }
}

/// Saves a `HybridPublicKey` (1600 bytes) to a file.
pub fn save_public_key<P: AsRef<Path>>(path: P, public_key: &HybridPublicKey) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&public_key.to_bytes())?;
    Ok(())
}

/// Loads a `HybridPublicKey` (1600 bytes) from a file.
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<HybridPublicKey> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 1600];
    file.read_exact(&mut bytes)?;
    Ok(HybridPublicKey::from_bytes(&bytes))
}

/// Generates a random salt for Argon2id.
#[must_use]
pub fn generate_salt() -> [u8; 16] {
    rand::random()
}

/// Generates a random nonce prefix for chunked encryption.
#[must_use]
pub fn generate_nonce_prefix() -> [u8; 16] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_argon2id_derivation() {
        let passphrase = "test passphrase 123";
        let salt = generate_salt();
        let params = DEFAULT_ARGON2_DESKTOP;

        let key1 = derive_key_argon2id(passphrase, &salt, &params).unwrap();
        let key2 = derive_key_argon2id(passphrase, &salt, &params).unwrap();
        assert_eq!(key1, key2);

        // Different salt produces different key
        let salt2 = generate_salt();
        let key3 = derive_key_argon2id(passphrase, &salt2, &params).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_argon2id_mobile_params() {
        let passphrase = "mobile test";
        let salt = generate_salt();
        let key = derive_key_argon2id(passphrase, &salt, &crate::DEFAULT_ARGON2_MOBILE).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hybrid_keypair_generation() {
        let (pub_bytes, sec_bytes) = generate_hybrid_keypair().unwrap();
        assert_eq!(pub_bytes.len(), 1600);
        assert_eq!(sec_bytes.len(), 64);
    }

    #[test]
    fn test_full_hybrid_keypair_generation() {
        let (public, secret) = generate_full_hybrid_keypair().unwrap();
        assert_eq!(public.x25519.len(), 32);
        assert_eq!(public.ml_kem.len(), 1568);
        assert_eq!(secret.x25519.len(), 32);
        assert_eq!(secret.ml_kem.len(), 3168);
    }

    #[test]
    fn test_hybrid_key_derivation_recovery() {
        let (public, secret) = generate_full_hybrid_keypair().unwrap();

        // Encrypt side: derive master key
        let (master_key_enc, ephemeral_pk, mlkem_ct) = derive_key_hybrid(&public).unwrap();

        // Decrypt side: recover master key
        let master_key_dec = recover_key_hybrid(&secret, &ephemeral_pk, &mlkem_ct).unwrap();

        assert_eq!(master_key_enc, master_key_dec);
    }

    #[test]
    fn test_xchacha20poly1305_encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [1u8; 24];
        let aad = b"test aad";
        let plaintext = b"Hello, QENC! This is a test message for encryption.";

        let ciphertext = encrypt_chunk(&key, &nonce, aad, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // Includes 16-byte tag

        let decrypted = decrypt_chunk(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20poly1305_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = [1u8; 24];
        let aad = b"aad";
        let plaintext = b"test";

        let ciphertext = encrypt_chunk(&key1, &nonce, aad, plaintext).unwrap();
        let result = decrypt_chunk(&key2, &nonce, aad, &ciphertext);
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_xchacha20poly1305_wrong_aad_fails() {
        let key = [1u8; 32];
        let nonce = [1u8; 24];
        let plaintext = b"test";

        let ciphertext = encrypt_chunk(&key, &nonce, b"aad1", plaintext).unwrap();
        let result = decrypt_chunk(&key, &nonce, b"aad2", &ciphertext);
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_xchacha20poly1305_wrong_nonce_fails() {
        let key = [1u8; 32];
        let nonce1 = [1u8; 24];
        let nonce2 = [2u8; 24];
        let aad = b"aad";
        let plaintext = b"test";

        let ciphertext = encrypt_chunk(&key, &nonce1, aad, plaintext).unwrap();
        let result = decrypt_chunk(&key, &nonce2, aad, &ciphertext);
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_secret_key_save_load_unencrypted() {
        let temp = NamedTempFile::new().unwrap();
        let secret = [99u8; 64];

        save_secret_key(temp.path(), &secret, None).unwrap();
        let loaded = load_secret_key(temp.path(), None).unwrap();

        assert_eq!(secret, loaded);
    }

    #[test]
    fn test_secret_key_save_load_encrypted() {
        let temp = NamedTempFile::new().unwrap();
        let secret = [88u8; 64];
        let passphrase = "test passphrase";

        save_secret_key(temp.path(), &secret, Some(passphrase)).unwrap();
        let loaded = load_secret_key(temp.path(), Some(passphrase)).unwrap();

        assert_eq!(secret, loaded);
    }

    #[test]
    fn test_secret_key_wrong_passphrase_fails() {
        let temp = NamedTempFile::new().unwrap();
        let secret = [77u8; 64];

        save_secret_key(temp.path(), &secret, Some("correct")).unwrap();
        let result = load_secret_key(temp.path(), Some("wrong"));
        assert!(matches!(result, Err(QencError::AuthenticationFailed)));
    }

    #[test]
    fn test_full_secret_key_save_load() {
        let temp = NamedTempFile::new().unwrap();
        let (_public, secret) = generate_full_hybrid_keypair().unwrap();

        save_full_secret_key(temp.path(), &secret, Some("passphrase")).unwrap();
        let loaded = load_full_secret_key(temp.path(), Some("passphrase")).unwrap();

        assert_eq!(secret.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn test_public_key_save_load() {
        let temp = NamedTempFile::new().unwrap();
        let (public, _) = generate_full_hybrid_keypair().unwrap();

        save_public_key(temp.path(), &public).unwrap();
        let loaded = load_public_key(temp.path()).unwrap();

        assert_eq!(public.to_bytes(), loaded.to_bytes());
    }
}