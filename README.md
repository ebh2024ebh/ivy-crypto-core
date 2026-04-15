# Ivy Cryptographic Engine (`ivy-crypto-core`)

This repository contains the standalone, memory-safe Rust cryptographic core for the **Ivy Sovereign Communications Platform**.

It handles all post-quantum key encapsulation, payload ratcheting, identity derivation, zero-knowledge proofs, and Tor V3 orchestration. It contains **zero UI code, zero analytics, zero telemetry, zero platform-specific shims**.

---

## Cryptographic Architecture

| Layer | Primitive | Standard |
|---|---|---|
| Post-Quantum KEM | ML-KEM-768 | FIPS 203 |
| Classical ECDH | X25519 | RFC 7748 |
| Hybrid Handshake | PQXDH (X3DH + ML-KEM) | Signal Foundation draft |
| Symmetric AEAD | XChaCha20-Poly1305 | RFC 8439 / IETF draft |
| Signatures | Ed25519 | RFC 8032 |
| KDF | HKDF-SHA-512 | RFC 5869 |
| Password → Key | Argon2id | RFC 9106 |
| Seed Phrases | BIP-39 | Bitcoin BIP |
| Blind Tickets | Blind-RSA Privacy Pass | RFC 9474 |
| Zero-Knowledge | Groth16 on BN254 | IETF draft |
| Secret Sharing | Shamir over GF(256) | Shamir 1979 |
| Anonymity Network | Tor V3 Hidden Services (via Arti) | tor-spec.txt |

All secrets implement `Drop + Zeroize` for deterministic memory scrubbing on scope exit. The crate is `#![forbid(unsafe_code)]` wherever the underlying math libraries permit, and uses pure-Rust TLS (`rustls`) with no OpenSSL or C-side dependencies.

---

## Module Layout

```
src/
├── crypto/
│   ├── argon2.rs          — Argon2id password hashing (configurable params)
│   ├── encryption.rs      — XChaCha20-Poly1305 payload encryption
│   ├── erasure.rs         — Reed-Solomon erasure coding
│   ├── hkdf.rs            — HKDF-SHA-512 key derivation
│   ├── nonce.rs           — 24-byte random nonce generation
│   ├── pow.rs             — SHA-256 proof-of-work
│   ├── pqxdh.rs           — ML-KEM-768 + X25519 hybrid handshake
│   ├── safety_number.rs   — SHA-512 over Ed25519/X25519/ML-KEM bundle
│   ├── shamir.rs          — Shamir secret sharing over GF(256)
│   └── zkp.rs             — Groth16 zero-knowledge proofs (BN254)
├── identity/
│   ├── keygen.rs          — Ed25519 + X25519 + ML-KEM-768 keypair generation
│   └── seed.rs            — BIP-39 mnemonic + passphrase derivation
├── network/
│   └── tor_client.rs      — Arti (Tor V3) circuit orchestration
└── lib.rs                 — UniFFI-exported public API
```

The public API is defined in [`ivy_crypto_core.udl`](ivy_crypto_core.udl) and exposed to client platforms (Android, iOS, desktop) via UniFFI-generated Kotlin and Swift bindings.

---

## Security Auditing

We operate on a zero-trust model. This repository is maintained strictly for **public audit, deterministic build verification, and cryptographic review** by enterprise security teams and independent researchers.

### Scope of interest

- Correctness of the ML-KEM-768 + X25519 hybrid encapsulation in [`crypto/pqxdh.rs`](src/crypto/pqxdh.rs)
- Double-ratchet state machine invariants in [`crypto/encryption.rs`](src/crypto/encryption.rs)
- Memory zeroization via `#[derive(Zeroize, ZeroizeOnDrop)]` in [`identity/keygen.rs`](src/identity/keygen.rs)
- Constant-time operations in all verification paths
- Arti circuit lifecycle and TLS configuration in [`network/tor_client.rs`](src/network/tor_client.rs)

### Reporting

**Out-of-band PGP only.** Please contact `security@ivy.security`.

Public key fingerprint:

```
F19F 34E8 E9F1 3F6D F418  1F38 0F1C 6872 0016 85D0
```

Import the armored public key from [`ivy-security-pubkey.asc`](ivy-security-pubkey.asc) at the root of this repository:

```bash
gpg --import ivy-security-pubkey.asc
gpg --fingerprint security@ivy.security   # verify against the value above
```

The key is RSA-4096 (sign+cert primary, encrypt subkey), rotated annually.

Do not open public GitHub issues for suspected vulnerabilities. A 72-hour acknowledgement SLA applies.

---

## Deterministic Builds

The `release` profile in `Cargo.toml` is configured for reproducible output:

```
opt-level = "z"       # size
lto = true            # cross-crate inlining
strip = "symbols"     # no function names, panic strings, or DWARF
codegen-units = 1     # deterministic ordering
panic = "abort"       # no unwind tables (no stack layout leak)
```

To produce a deterministic build:

```bash
cargo build --release --locked
sha256sum target/release/libivy_crypto_core.so
```

Any two builders on the same Rust version will produce byte-identical binaries. Report discrepancies to `security@ivy.security`.

---

## License

This core is licensed under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). See [`LICENSE`](LICENSE).

Public audit, academic review, and non-commercial open-source integration are welcome and encouraged.

**Commercial deployment** of this core within proprietary infrastructure (server-side or client-side) requires an Enterprise License. Contact `enterprise@ivy.security`.

---

## Not in this repository

The following Ivy components are maintained in private repositories and are **intentionally out of scope** for public audit:

- Android UI, Compose navigation, and Kotlin lifecycle layer
- SQLCipher schema, Room DAOs, and local database lifecycle
- Android Keystore / StrongBox integration
- Firebase Cloud Messaging (FCM) handling
- WorkManager background workers
- Enterprise provisioning, MDM, and white-label build pipeline
- Server-side Mailbox, DHT, Ticket, PAKE, and Update service binaries

These layers orchestrate the crypto in this repository but do not themselves contain cryptographic primitives.
