# Security Policy

QENC is a **local, offline, zero-telemetry** encrypted container format (`.qenc`) written in pure Rust + Tauri 2.0. It never contacts the network, has no accounts, and transmits no telemetry of any kind.

> **Disclaimer:** QENC implements NIST FIPS 203 (ML-KEM-1024) and modern AEAD primitives using pure-Rust crates. It is an open-source engineering project and has **not** undergone a formal, independent, third-party cryptographic audit. Review the source and threat model below before relying on it for sensitive deployments.

## Threat Model

### What QENC protects against
- **Offline brute-force / dictionary attacks** on the container — master keys are stretched with **Argon2id** (128 MiB / t=3 / p=2 desktop, 64 MiB / t=3 / p=1 mobile, configurable and recorded in the header).
- **Harvest-now-decrypt-later (HNDL)** on the key exchange — a hybrid **X25519 + ML-KEM-1024** key agreement is combined via **HKDF-SHA256**, so breaking only the classical (X25519) *or* only the future quantum (ML-KEM) channel is insufficient.
- **Header / chunk tampering** — every chunk's AAD binds the SHA-256 of the exact header, the chunk counter, and the final-chunk flag, so modifications are rejected by the Poly1305 tag.
- **Chunk reordering / duplication / truncation** — chunk counter is authenticated and the final-chunk flag (`0x01`) is mandatory; trailing or missing data fails closed.
- **TAR path-traversal ("zip-slip")** — extraction rejects absolute paths, `..` components, symlinks/hardlinks escaping the destination root, and device nodes/FIFOs.
- **Symmetric credential exposure at rest** — optional passphrase protection of `.qenc.sec` keys (Argon2id + XChaCha20-Poly1305), and RAM hygiene via the `zeroize` crate.

### What QENC does **not** protect against
- A **compromised host OS / kernel / hypervisor**, or malware running with your privileges (keyloggers, memory scrapers).
- **Weak user passphrases** — Argon2id cannot save a short or common passphrase. Use a high-entropy passphrase or a Hybrid PQC keypair.
- **Metadata / file-size side channels** — output sizes and original sizes are recorded in the (unencrypted) header. A padding/fixed-blocking scheme is out of scope for `.qenc` v1.
- **Denial-of-service attacks** on decrypt of attacker-supplied containers — costs are bounded by chunk size limits and Argon2 parameter caps, but QENC is not a DoS-hardened parser.

## `qenc` v1 Header Layout
All integers little-endian. `key_data` length depends on `key_mode`.

| Offset | Field | Size (bytes) | Notes |
|-------:|------|-------------:|-------|
| 0  | Magic | 4 | ASCII `QENC` |
| 4  | Version | 1 | `0x01` |
| 5  | Key mode | 1 | `0x01` = Passphrase, `0x02` = Hybrid PQC |
| 6  | Compression profile | 1 | `0x01` Turbo(L3), `0x02` Balanced(L9), `0x03` Ultra(L19) |
| 7  | Chunk size | 4 | Must be 1..=16,777,216 |
| 11 | Nonce prefix | 16 | Per-file random |
| 27 | Original size | 8 | Total uncompressed payload bytes |
| 35 | Key data length | 4 | 28 (passphrase) or 1600 (hybrid) |
| 39 | Key data | 28 / 1600 | Passphrase = salt(16)+m_cost(4)+t_cost(4)+p_cost(4); Hybrid = ephemeral X25519 pk(32)+ML-KEM ct(1568) |

**Chunk record:** `final_flag (1, 0x00|0x01)` · `ciphertext_len (4)` · `ciphertext (len, incl. 16-byte Poly1305 tag)`. Each chunk uses a 24-byte XChaCha20 nonce = `nonce_prefix(16) || chunk_counter(8)`, AAD = `SHA256(header) || chunk_counter(8) || final_flag(1)`.

## Reporting a Vulnerability
Please use GitHub's private Vulnerability Reporting (Security Advisories). Do not open a public issue for undisclosed vulnerabilities. We ask for a 90-day coordinated-disclosure window.