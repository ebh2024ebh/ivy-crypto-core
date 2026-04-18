// Lattice Core — Memory-safe cryptographic engine
//
// This crate provides all cryptographic primitives for the Lattice protocol:
// - BIP39 seed phrase generation and validation
// - Ed25519 signing + X25519 key exchange (classical)
// - ML-KEM-768 encapsulation (post-quantum)
// - Hybrid PQXDH key agreement
// - XChaCha20-Poly1305 authenticated encryption
// - HKDF-based double ratchet
// - Shamir's Secret Sharing over GF(256)
// - Argon2id password hashing
// - Reed-Solomon erasure coding
// - Argon2id proof-of-work
// - Deterministic memory zeroing via zeroize

pub mod crypto;
pub mod identity;
pub mod network;

use crypto::encryption::{decrypt_xchacha20, encrypt_xchacha20};
use crypto::hkdf::hkdf_expand;
use crypto::shamir::{shamir_recombine_impl, shamir_split_impl};
use identity::{generate_ghost_identity, recover_ghost_identity};
use network::tor_client::LatticeTorClient;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

/// Dedicated tokio runtime for Tor operations. Created lazily on first
/// tor_bootstrap call and reused for the lifetime of the process. We use a
/// multi-thread runtime because Arti internally spawns background tasks.
static TOR_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Global singleton Tor client. Protected by a plain Mutex because all
/// access is synchronous from the UniFFI thread; the Arti client itself
/// is Sync and holds its own internal locks.
static TOR_CLIENT: OnceLock<Mutex<Option<LatticeTorClient>>> = OnceLock::new();

fn tor_runtime() -> &'static tokio::runtime::Runtime {
    TOR_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("lattice-tor")
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for Tor")
    })
}

fn tor_slot() -> &'static Mutex<Option<LatticeTorClient>> {
    TOR_CLIENT.get_or_init(|| Mutex::new(None))
}

// Include UniFFI scaffolding
uniffi::include_scaffolding!("ivy_crypto_core");

// --- Error type ---

#[derive(Debug, thiserror::Error)]
pub enum LatticeError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Authentication tag verification failed")]
    AuthenticationFailed,
    #[error("Invalid mnemonic phrase")]
    InvalidMnemonic,
    #[error("Insufficient Shamir shares for reconstruction")]
    InsufficientShares,
    #[error("Erasure coding error: {0}")]
    ErasureCodeError(String),
    #[error("Proof of work computation failed")]
    ProofOfWorkFailed,
    #[error("Tor connection failed: {0}")]
    TorConnectionFailed(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

// --- Data structures (matching UDL) ---
//
// SECURITY NOTE ON ZEROIZE:
// These structs are FFI transport objects that cross the JNI boundary via UniFFI.
// UniFFI's Record derive requires moving fields out, which is incompatible with
// Rust's Drop trait (ZeroizeOnDrop). Therefore we derive Zeroize (manual call)
// but NOT ZeroizeOnDrop (auto Drop).
//
// Zeroing is handled on the Kotlin side via ScopedFfiSecret.use { } which
// calls secureZero() on each ByteArray field immediately after extraction.
// The Rust-side structs are ephemeral — they exist only during the JNI call.

/// Contains private keys — caller MUST zero via Zeroize after use.
#[derive(Debug, Clone, Zeroize)]
pub struct GhostIdentityBundle {
    pub ed25519_signing_public: Vec<u8>,
    pub ed25519_signing_private: Vec<u8>,
    pub x25519_exchange_public: Vec<u8>,
    pub x25519_exchange_private: Vec<u8>,
    pub mlkem768_public: Vec<u8>,
    pub mlkem768_private: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub display_id: String,
}

/// Contains raw entropy — caller MUST zero via Zeroize after use.
#[derive(Debug, Clone, Zeroize)]
pub struct MnemonicResult {
    pub words: Vec<String>,
    pub entropy: Vec<u8>,
}

/// Contains session chain keys — caller MUST zero via Zeroize after use.
#[derive(Debug, Clone, Zeroize)]
pub struct SessionKeysBundle {
    pub sending_chain_key: Vec<u8>,
    pub receiving_chain_key: Vec<u8>,
    pub root_key: Vec<u8>,
    pub encapsulated_ciphertext: Option<Vec<u8>>,
}

/// Ciphertext only — no secrets, no Zeroize needed.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Contains message key — caller MUST zero via Zeroize after use.
#[derive(Debug, Clone, Zeroize)]
pub struct RatchetStepResult {
    pub message_key: Vec<u8>,
    pub next_chain_key: Vec<u8>,
}

/// Contains secret shard — caller MUST zero via Zeroize after use.
#[derive(Debug, Clone, Zeroize)]
pub struct ShamirShare {
    pub index: u8,
    pub data: Vec<u8>,
    pub threshold: u8,
    pub total_shares: u8,
}

/// Ciphertext shards only — no secrets.
#[derive(Debug, Clone)]
pub struct ErasureCodedData {
    pub shards: Vec<Vec<u8>>,
    pub data_shard_count: u32,
    pub parity_shard_count: u32,
    pub original_size: u64,
}

/// Public proof data — no secrets.
#[derive(Debug, Clone)]
pub struct ProofOfWork {
    pub nonce: u64,
    pub hash: Vec<u8>,
}

// =====================================================================
// UniFFI-exported functions
// =====================================================================

/// Generate a new Ghost Identity from a 512-bit root seed.
pub fn generate_identity(root_seed: Vec<u8>) -> Result<GhostIdentityBundle, LatticeError> {
    generate_ghost_identity(&root_seed)
}

/// Recover a Ghost Identity from a mnemonic phrase.
pub fn recover_identity(
    mnemonic_words: Vec<String>,
    passphrase: String,
) -> Result<GhostIdentityBundle, LatticeError> {
    recover_ghost_identity(&mnemonic_words, &passphrase)
}

/// Generate a new 24-word BIP39 mnemonic.
pub fn generate_mnemonic() -> MnemonicResult {
    identity::seed::generate_mnemonic_impl()
}

/// Validate a mnemonic phrase.
pub fn validate_mnemonic(words: Vec<String>) -> bool {
    identity::seed::validate_mnemonic_impl(&words)
}

/// Derive a 512-bit root seed from a mnemonic using Argon2id.
pub fn derive_root_seed(words: Vec<String>, passphrase: String) -> Vec<u8> {
    identity::seed::derive_root_seed_impl(&words, &passphrase)
}

/// Derive a root seed with configurable Argon2id parameters (called from Kotlin JNI).
pub fn argon2_derive_root_seed(
    password: Vec<u8>,
    salt: Vec<u8>,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    output_length: u32,
) -> Vec<u8> {
    let mut pw = password;
    let result = identity::seed::argon2_derive(
        &pw, &salt, memory_kb, iterations, parallelism, output_length as usize,
    );
    pw.zeroize(); // Zero password from memory
    result
}

/// Perform a hybrid PQXDH key agreement.
pub fn perform_pqxdh(
    local_x25519_private: Vec<u8>,
    local_pq_private: Vec<u8>,
    remote_x25519_public: Vec<u8>,
    remote_pq_public: Vec<u8>,
) -> Result<SessionKeysBundle, LatticeError> {
    crypto::pqxdh::perform_pqxdh_impl(
        &local_x25519_private,
        &local_pq_private,
        &remote_x25519_public,
        &remote_pq_public,
    )
}

/// Encrypt a plaintext message with XChaCha20-Poly1305.
pub fn encrypt_message(plaintext: Vec<u8>, key: Vec<u8>) -> Result<EncryptedMessage, LatticeError> {
    encrypt_xchacha20(&plaintext, &key)
}

/// Decrypt an encrypted message with XChaCha20-Poly1305.
pub fn decrypt_message(
    payload: EncryptedMessage,
    key: Vec<u8>,
) -> Result<Vec<u8>, LatticeError> {
    decrypt_xchacha20(&payload, &key)
}

/// Perform one step of the double ratchet.
pub fn ratchet_step(chain_key: Vec<u8>) -> RatchetStepResult {
    let msg_key = hkdf_expand(&chain_key, b"lattice-msg-key", 32);
    let next_chain = hkdf_expand(&chain_key, b"lattice-chain-key", 32);
    RatchetStepResult {
        message_key: msg_key,
        next_chain_key: next_chain,
    }
}

/// Split a secret into Shamir shares.
pub fn shamir_split(
    secret: Vec<u8>,
    total_shares: u8,
    threshold: u8,
) -> Result<Vec<ShamirShare>, LatticeError> {
    shamir_split_impl(&secret, total_shares, threshold)
}

/// Reconstruct a secret from Shamir shares.
pub fn shamir_recombine(shares: Vec<ShamirShare>) -> Result<Vec<u8>, LatticeError> {
    shamir_recombine_impl(&shares)
}

/// Hash with Argon2id.
pub fn argon2_hash(
    password: Vec<u8>,
    salt: Vec<u8>,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, LatticeError> {
    crypto::argon2::argon2_hash_impl(&password, &salt, memory_kb, iterations, parallelism)
}

/// Erasure-encode data into shards.
pub fn erasure_encode(
    data: Vec<u8>,
    data_shards: u32,
    parity_shards: u32,
) -> Result<ErasureCodedData, LatticeError> {
    crypto::erasure::erasure_encode_impl(&data, data_shards as usize, parity_shards as usize)
}

/// Erasure-decode shards back to data.
pub fn erasure_decode(
    coded: ErasureCodedData,
    data_shards: u32,
    parity_shards: u32,
) -> Result<Vec<u8>, LatticeError> {
    crypto::erasure::erasure_decode_impl(&coded, data_shards as usize, parity_shards as usize)
}

/// Compute an Argon2id proof-of-work.
pub fn compute_proof_of_work(
    challenge: Vec<u8>,
    difficulty: u32,
) -> Result<ProofOfWork, LatticeError> {
    crypto::pow::compute_pow(&challenge, difficulty)
}

/// Verify an Argon2id proof-of-work.
pub fn verify_proof_of_work(
    challenge: Vec<u8>,
    proof: ProofOfWork,
    difficulty: u32,
) -> bool {
    crypto::pow::verify_pow(&challenge, &proof, difficulty)
}

/// Securely zero a byte buffer.
pub fn secure_zero(mut data: Vec<u8>) {
    data.zeroize();
}

// =====================================================================
// Low-level crypto primitives exposed for the Kotlin client services
// (DhtClient, ZkPakeExchange, AntiAbuseService). These replace the raw
// JNI `external fun native*` stubs that those services used to declare.
// =====================================================================

/// Ed25519 signature. `private_key` is the 32-byte seed; full 64-byte
/// expanded keypairs are also accepted (first 32 bytes are the seed).
pub fn ed25519_sign(data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, LatticeError> {
    use ed25519_dalek::{Signer, SigningKey};
    if private_key.len() < 32 {
        return Err(LatticeError::InvalidKeyLength);
    }
    let seed: [u8; 32] = private_key[..32]
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let signing = SigningKey::from_bytes(&seed);
    Ok(signing.sign(&data).to_bytes().to_vec())
}

/// Ed25519 signature verification. Returns false on bad key/signature length
/// or verification failure.
pub fn ed25519_verify(data: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = match public_key.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig: [u8; 64] = match signature.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig);
    vk.verify(&data, &signature).is_ok()
}

/// Derive an X25519 public key from a 32-byte private key.
pub fn x25519_derive_public(private_key: Vec<u8>) -> Result<Vec<u8>, LatticeError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let bytes: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

/// Perform an X25519 Diffie-Hellman with our private key and the peer's public key.
pub fn x25519_dh(private_key: Vec<u8>, peer_public: Vec<u8>) -> Result<Vec<u8>, LatticeError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let priv_bytes: [u8; 32] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let pub_bytes: [u8; 32] = peer_public
        .as_slice()
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let secret = StaticSecret::from(priv_bytes);
    let peer = PublicKey::from(pub_bytes);
    let shared = secret.diffie_hellman(&peer);
    Ok(shared.as_bytes().to_vec())
}

/// HKDF-SHA256 expand (no extract). Caller must provide an already-extracted
/// pseudo-random key as `ikm`.
pub fn hkdf_expand_raw(ikm: Vec<u8>, info: Vec<u8>, length: u32) -> Vec<u8> {
    hkdf_expand(&ikm, &info, length as usize)
}

// =====================================================================
// Safety Numbers
// =====================================================================

/// Generate a 60-digit Safety Number for MITM verification.
/// Both parties produce the same number from each other's public keys.
pub fn generate_safety_number(
    my_signing_pub: Vec<u8>,
    my_exchange_pub: Vec<u8>,
    my_pq_pub: Vec<u8>,
    their_signing_pub: Vec<u8>,
    their_exchange_pub: Vec<u8>,
    their_pq_pub: Vec<u8>,
) -> String {
    crypto::safety_number::generate_safety_number(
        &my_signing_pub,
        &my_exchange_pub,
        &my_pq_pub,
        &their_signing_pub,
        &their_exchange_pub,
        &their_pq_pub,
    )
}

// =====================================================================
// Ratchet Delivery Tags (SURTs)
// =====================================================================

/// Derive a single-use delivery tag from a message key.
/// Tag = HKDF(message_key, "lattice-delivery-tag-v1")[0..16]
pub fn derive_delivery_tag(message_key: Vec<u8>) -> Vec<u8> {
    let full = hkdf_expand(&message_key, b"lattice-delivery-tag-v1", 16);
    full
}

// =====================================================================
// ML-KEM-768 standalone encapsulation / decapsulation
// =====================================================================

/// Result of a standalone ML-KEM-768 key encapsulation.
#[derive(Debug, Clone)]
pub struct MlKemEncapResult {
    /// The ciphertext to send to the peer (1088 bytes for Kyber-768).
    pub ciphertext: Vec<u8>,
    /// The shared secret both sides will derive (32 bytes).
    pub shared_secret: Vec<u8>,
}

/// Encapsulate a fresh shared secret against a peer's ML-KEM-768 public
/// key. Returns the ciphertext (send to peer) and the shared secret
/// (use locally for frame encryption). The ciphertext is 1088 bytes;
/// the shared secret is 32 bytes.
pub fn ml_kem_768_encap(public_key: Vec<u8>) -> Result<MlKemEncapResult, LatticeError> {
    use ml_kem::{MlKem768Params, EncodedSizeUser};
    use ml_kem::kem::Encapsulate;

    let ek_bytes: ml_kem::kem::EncapsulationKey<MlKem768Params> =
        ml_kem::kem::EncapsulationKey::from_bytes(
            &ml_kem::array::Array::try_from(public_key.as_slice())
                .map_err(|_| LatticeError::CryptoError("Invalid ML-KEM-768 public key length".into()))?
        );
    let mut rng = rand::thread_rng();
    let (ct, ss) = ek_bytes.encapsulate(&mut rng)
        .map_err(|_| LatticeError::CryptoError("ML-KEM encapsulation failed".into()))?;
    Ok(MlKemEncapResult {
        ciphertext: AsRef::<[u8]>::as_ref(&ct).to_vec(),
        shared_secret: AsRef::<[u8]>::as_ref(&ss).to_vec(),
    })
}

/// Decapsulate a received ML-KEM-768 ciphertext with our private key.
/// Returns the same 32-byte shared secret the encapsulator derived.
pub fn ml_kem_768_decap(
    ciphertext: Vec<u8>,
    private_key: Vec<u8>,
) -> Result<Vec<u8>, LatticeError> {
    use ml_kem::{MlKem768, MlKem768Params, EncodedSizeUser};
    use ml_kem::kem::Decapsulate;

    let dk_bytes: ml_kem::kem::DecapsulationKey<MlKem768Params> =
        ml_kem::kem::DecapsulationKey::from_bytes(
            &ml_kem::array::Array::try_from(private_key.as_slice())
                .map_err(|_| LatticeError::CryptoError("Invalid ML-KEM-768 private key length".into()))?
        );
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext.as_slice())
        .map_err(|_| LatticeError::CryptoError("Invalid ML-KEM-768 ciphertext length".into()))?;
    let ss = dk_bytes.decapsulate(&ct)
        .map_err(|_| LatticeError::CryptoError("ML-KEM decapsulation failed".into()))?;
    Ok(AsRef::<[u8]>::as_ref(&ss).to_vec())
}

/// Public bundle for UniFFI (flat struct, no tuples).
#[derive(Debug, Clone)]
pub struct ZkProofBundle {
    pub proof_bytes: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
}

/// Groth16 ZK-SNARK proof generation. Wraps crypto::zkp::generate_proof into
/// a UniFFI-friendly struct.
pub fn zkp_generate_proof_raw(
    proving_key: Vec<u8>,
    attestation_token: Vec<u8>,
    timestamp: u64,
    device_verdict: u64,
) -> Result<ZkProofBundle, LatticeError> {
    let bundle = crypto::zkp::generate_proof(
        &proving_key,
        &attestation_token,
        timestamp,
        device_verdict,
    )?;
    Ok(ZkProofBundle {
        proof_bytes: bundle.proof_bytes,
        public_inputs_bytes: bundle.public_inputs_bytes,
    })
}

/// Groth16 ZK-SNARK proof verification.
pub fn zkp_verify_proof_raw(
    verifying_key: Vec<u8>,
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
) -> Result<bool, LatticeError> {
    crypto::zkp::verify_proof(&verifying_key, &proof_bytes, &public_inputs_bytes)
}

// =====================================================================
// Tor transport (exposed via UniFFI)
// =====================================================================

/// Bootstrap the global Tor client. Blocks until the first circuit is ready.
pub fn tor_bootstrap(data_dir: String) -> Result<(), LatticeError> {
    let rt = tor_runtime();
    let client = rt.block_on(async { LatticeTorClient::connect(&data_dir).await })?;
    let slot = tor_slot();
    let mut guard = slot
        .lock()
        .map_err(|e| LatticeError::TorConnectionFailed(format!("mutex poisoned: {}", e)))?;
    *guard = Some(client);
    Ok(())
}

/// Return true if the global Tor client has been successfully bootstrapped
/// and not yet shut down. We intentionally only check slot presence instead
/// of arti's `bootstrap_status().as_frac() >= 1.0`, which can report <1.0
/// momentarily even after `create_bootstrapped` has successfully returned
/// (it reflects ongoing/recovery bootstrap progress, not a one-shot success).
pub fn tor_is_connected() -> bool {
    let Some(slot) = TOR_CLIENT.get() else { return false };
    let Ok(guard) = slot.lock() else { return false };
    guard.is_some()
}

/// Send a length-prefixed request over Tor to destination:port, return the
/// length-prefixed response. The 4-byte BE length + payload framing matches
/// the Lattice server's `frame.rs` wire protocol.
pub fn tor_send_raw(
    destination: String,
    port: u32,
    payload: Vec<u8>,
) -> Result<Vec<u8>, LatticeError> {
    let slot = TOR_CLIENT
        .get()
        .ok_or_else(|| LatticeError::TorConnectionFailed("not bootstrapped".into()))?;

    // Clone the Arc'd client out of the mutex so we don't hold the lock
    // across the await point. LatticeTorClient is cheap to clone.
    let client_clone = {
        let guard = slot
            .lock()
            .map_err(|e| LatticeError::TorConnectionFailed(format!("mutex poisoned: {}", e)))?;
        guard
            .as_ref()
            .ok_or_else(|| LatticeError::TorConnectionFailed("not bootstrapped".into()))?
            .clone_handle()
    };

    let rt = tor_runtime();
    rt.block_on(async move {
        client_clone
            .send_message(&destination, port as u16, &payload)
            .await
    })
}

/// Send a raw HTTP/1.1 request over Tor to destination:port. No length-prefix
/// framing in either direction — the server is expected to be a plain HTTP
/// server (e.g. the guest-link service on port 9159). Returns the full
/// response bytes read until the server half-closes the TCP stream (which it
/// must do for each request, typically via `Connection: close`).
pub fn tor_send_http(
    destination: String,
    port: u32,
    payload: Vec<u8>,
) -> Result<Vec<u8>, LatticeError> {
    let slot = TOR_CLIENT
        .get()
        .ok_or_else(|| LatticeError::TorConnectionFailed("not bootstrapped".into()))?;

    let client_clone = {
        let guard = slot
            .lock()
            .map_err(|e| LatticeError::TorConnectionFailed(format!("mutex poisoned: {}", e)))?;
        guard
            .as_ref()
            .ok_or_else(|| LatticeError::TorConnectionFailed("not bootstrapped".into()))?
            .clone_handle()
    };

    let rt = tor_runtime();
    rt.block_on(async move {
        client_clone
            .send_http(&destination, port as u16, &payload)
            .await
    })
}

/// Tear down the global Tor client.
pub fn tor_shutdown() {
    if let Some(slot) = TOR_CLIENT.get() {
        if let Ok(mut guard) = slot.lock() {
            *guard = None;
        }
    }
}

// =====================================================================
// ZK-SNARK Proof Generation (Groth16 on BN254)
// =====================================================================

/// ZK proof bytes for FFI transport.
pub struct ZkProofResult {
    pub proof_bytes: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
}

/// Generate ZK-SNARK proving and verifying keys (trusted setup).
/// Run once; embed keys in the app binary.
pub fn zkp_generate_keys() -> Result<(Vec<u8>, Vec<u8>), LatticeError> {
    crypto::zkp::generate_zkp_keys()
}

/// Generate a Groth16 ZK-SNARK proof for a Play Integrity attestation.
/// Runs the prover circuit in native Rust with hardware acceleration.
pub fn zkp_generate_proof(
    proving_key: Vec<u8>,
    attestation_token: Vec<u8>,
    timestamp: u64,
    device_verdict: u64,
) -> Result<ZkProofResult, LatticeError> {
    let bundle = crypto::zkp::generate_proof(
        &proving_key,
        &attestation_token,
        timestamp,
        device_verdict,
    )?;
    Ok(ZkProofResult {
        proof_bytes: bundle.proof_bytes,
        public_inputs_bytes: bundle.public_inputs_bytes,
    })
}

/// Verify a Groth16 ZK-SNARK proof.
pub fn zkp_verify_proof(
    verifying_key: Vec<u8>,
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
) -> Result<bool, LatticeError> {
    crypto::zkp::verify_proof(&verifying_key, &proof_bytes, &public_inputs_bytes)
}
