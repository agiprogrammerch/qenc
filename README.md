# QENC — Post-Quantum Encrypted Container (`.qenc`)

**QENC** is a deterministic, **100% offline, zero-telemetry** encrypted archiver built in **pure Rust + Tauri 2.0** with a headless CLI, native Linux `.deb`, Windows `.exe`, and Android `.apk` from a single codebase. It packs files into a streaming container, compresses with Zstd, and seals them with post-quantum cryptography — with no network access, no accounts, and no AI dependencies.

> **Security & audit notice.** QENC implements NIST FIPS 203 (`ML-KEM-1024`) and modern AEAD primitives using pure-Rust crates. It has **not** undergone a formal, independent, third-party cryptographic audit and is provided as an open-source engineering project. See [`SECURITY.md`](./SECURITY.md).

---

## Architecture & Cryptographic Stack

QENC runs a fully **streaming** pipeline, so peak memory stays bounded to a single ~1 MiB chunk regardless of input size — suited to low-RAM machines.

```
 Inputs ──► GNU TAR ──► Zstd ──► 1 MiB Chunked SHA-256 ──► .qenc container
 (files/    (safe,       (Turbo L3 /   XChaCha20-Poly1305   (header + chunks)
  streams)   zip-slip-    Balanced     (AAD binds header hash,
              proof)        L9 /         chunk counter +
                          Ultra L19)    final flag)
```

| Layer | Primitive | Notes |
|------|-----------|-------|
| Archive | Streaming **GNU TAR** (LongName/LongLink) | Path-traversal-proof extraction; rejects absolute / `..` / escaping symlinks / devices · FIFOs; de-duplicates colliding stream names |
| Compression | **Zstd** | Profiles: Turbo L3 (fastest) · Balanced L9 (default) · Ultra L19 (max ratio) |
| Symmetric AEAD | **XChaCha20-Poly1305** | 1 MiB chunks; 24-byte nonce = nonce_prefix(16) ‖ counter(8); AAD = SHA256(header) ‖ counter(8) ‖ final flag |
| Key exchange (Hybrid mode) | **X25519 + NIST FIPS 203 ML-KEM-1024** | Combined via **HKDF-SHA256**; the `.qenc.pub` is 1600 bytes, the ephemeral public key + KEM ciphertext are stored in the header |
| KDF (Passphrase mode) | **Argon2id** | 128 MiB / t=3 / p=2 desktop, 64 MiB / t=3 / p=1 mobile; params recorded in the header for portability |
| Memory hygiene | `zeroize` | Keys are zeroized on drop |

Both modes are **fully cross-compatible** — an Android device can decrypt a container produced on desktop Linux and vice versa, because the Argon2id / KEM parameters travel inside the header.

### `.qenc` v1 header layout (little-endian)
| Offset | Field | Bytes | Notes |
|-------:|------|------:|-------|
| 0  | Magic | 4 | `QENC` |
| 4  | Version | 1 | `0x01` |
| 5  | Key mode | 1 | `0x01` passphrase · `0x02` hybrid PQC |
| 6  | Comp. profile | 1 | `0x01` Turbo · `0x02` Balanced · `0x03` Ultra |
| 7  | Chunk size | 4 | 1..=16,777,216 |
| 11 | Nonce prefix | 16 | random |
| 27 | Original size | 8 | bytes |
| 35 | Key data len | 4 | 28 / 1600 |
| 39 | Key data | 28 / 1600 | passphrase: salt+m+t+p · hybrid: ephemeral X25519 pk + ML-KEM ciphertext |

---

## Performance & Footprint (verified)

Reference hardware: **Intel Core i3-1115G4 · 8 GB DDR4 · 500 GB HDD · Kali Linux**.

| Metric | Result |
|-------|--------|
| Authenticated throughput (Turbo / Balanced) | **~58 MB/s** encrypt & decrypt, streaming |
| Real project folder compression | **407.7 MB → 60.8 MB (85.1% smaller)** at Balanced |
| Native Debian package | **2.80 MiB** `.deb` |
| Peak RSS (32 MB buffer, CLI) | **< 128 MB** (streaming; scales with chunk, not input) |
| Automated tests | **76** unit / security / IPC-contract tests |
| Idle desktop CPU | **~0%** — no continuous animation loops; GPU-composited transforms only |

---

## Installation

### Linux (`.deb` — Debian / Kali / Ubuntu)
```bash
sudo dpkg -i qenc-1.0.0-linux-amd64.deb
# Registers the .qenc file association + MIME handler automatically.
qenc-gui            # launch the desktop app
qenc /path/to/backup.qenc   # or open a .qenc directly into the Decrypt workflow
```

### Windows 10 / 11 (`-setup.exe`)
Run `qenc-1.0.0-windows-x64-setup.exe` (NSIS, per-user install — no UAC friction). Associates `.qenc` with the app.

### Android 7 — 16 (`.apk`)
```bash
adb install qenc-1.0.0-android-7-to-16-universal.apk   # arm64 + armv7
```
Uses Storage Access Framework (`content://`) with Scoped-Storage-safe output directories; no broad storage permissions.

### Headless CLI (`qenc`)
```bash
qenc keygen  -o keys/alice --passphrase "pass"   # X25519 + ML-KEM-1024 keypair
qenc encrypt ./folder -o archive.qenc --passphrase "pass" --profile balanced
qenc inspect archive.qenc                       # header + KDF params, no decryption
qenc decrypt archive.qenc -o ./restored --passphrase "pass"
qenc bench --size-mb 32 --iterations 3
```
Hybrid mode: `--mode pqc --pubkey keys/alice.qenc.pub` for encryption;
`--seckey keys/alice.qenc.sec --seckey-passphrase "pass"` for decryption.

---

## Repository Layout
```
crates/qenc-core   # Pure-Rust engine: crypto, format, archive, streaming pipeline
crates/qenc-cli    # Headless CLI (encrypt / decrypt / inspect / keygen / bench)
src-tauri          # Tauri 2.0 desktop + Android shell (IPC, Scoped Storage bridge)
ui/                # Vanilla TypeScript + modern CSS frontend (no frameworks)
scripts/           # CI Android Gradle/Manifest patch (SDK floors + signing)
.github/workflows/ # CI + cross-platform Release factory (.deb/.exe/.apk + SHA256SUMS)
```

## Workspace
```bash
npm install && npx tsc --noEmit && npm run build   # frontend
cargo test --workspace                             # 76 tests
cargo clippy --workspace --all-targets -- -D warnings
npm run tauri build -- --bundles deb               # native package
```

## License
[MIT](./LICENSE) © 2026 Arush Shakya.