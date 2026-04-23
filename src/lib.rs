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

/// Active desktop-companion hidden services, keyed by the 16-byte pairing
/// id (as a hex string — keeps the map hashable across FFI boundaries).
/// Each entry owns an `HsHostHandle` that keeps its Arti onion service
/// alive until `desktop_hs_stop()` is called from Kotlin. Stopping is
/// idempotent; starting a second time for the same pairing replaces the
/// prior handle and shuts the old one down cleanly.
static HS_HANDLES: OnceLock<
    Mutex<std::collections::HashMap<String, network::hs_host::HsHostHandle>>,
> = OnceLock::new();

fn hs_handles() -> &'static Mutex<std::collections::HashMap<String, network::hs_host::HsHostHandle>>
{
    HS_HANDLES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

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

// =====================================================================
// ML-DSA-65 (FIPS 204 "Module-Lattice Digital Signature Algorithm")
// =====================================================================
//
// Post-quantum-secure digital signatures. Used as the lattice-side half
// of our hybrid signature scheme — every critical authentication (group
// call mint, identity commitments) is signed with BOTH Ed25519 and
// ML-DSA-65. An adversary would need to break BOTH primitives to forge.
//
// Key sizes (ML-DSA-65 parameter set):
//   public key:  1952 bytes
//   private key: 4032 bytes
//   signature:   3309 bytes
//
// Standard: NIST FIPS 204 (August 2024), parameter set ML-DSA-65.
// Derived from the CRYSTALS-Dilithium submission (Dilithium-3).

/// Output of `ml_dsa_65_keypair` — a fresh randomly-generated keypair.
/// The private key MUST be kept in secure storage (Android Keystore /
/// iOS Keychain / hardware-backed where available) and zeroized when
/// destroyed. Exposed via UniFFI — matching UDL dictionary in
/// `uniffi/ivy_crypto_core.udl`.
#[derive(Debug, Clone)]
pub struct MlDsa65Keypair {
    /// 1952-byte ML-DSA-65 public key (verification key).
    pub public_key: Vec<u8>,
    /// 4032-byte ML-DSA-65 private key (signing key).
    pub private_key: Vec<u8>,
}

/// Generate a fresh ML-DSA-65 keypair using the OS CSPRNG via getrandom.
/// Matches the convention of `generate_ghost_identity` — caller is
/// responsible for persisting the key material.
///
/// The key sizes below are fixed by the FIPS 204 parameter set:
///   public key  = 1952 bytes (encoded rho + t1)
///   private key = 4032 bytes (internal signing-key encoding)
///   signature   = 3309 bytes (c̃ + z + h)
pub fn ml_dsa_65_keypair() -> Result<MlDsa65Keypair, LatticeError> {
    use ml_dsa::{KeyGen, MlDsa65, signature::Keypair};
    use hybrid_array::Array;
    // Feed OS randomness into FIPS 204 KeyGen_internal via a 32-byte seed.
    // We do this rather than passing a generic CryptoRng because the
    // rand_core version exported by ml-dsa (via `signature` 3.0-rc) is
    // newer than the rand 0.8 CryptoRng that the rest of the crate uses.
    // Deriving from seed gives byte-identical FIPS-204 output and lets
    // us store the seed as the persistent private key (32 B vs 4 KB for
    // the expanded form).
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| LatticeError::CryptoError(format!("getrandom: {}", e)))?;
    let seed_arr: &Array<u8, _> = <&Array<u8, _>>::try_from(seed.as_slice())
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let kp = MlDsa65::from_seed(seed_arr);
    Ok(MlDsa65Keypair {
        public_key: kp.verifying_key().encode().to_vec(),
        private_key: seed.to_vec(),
    })
}

/// Sign `data` with an ML-DSA-65 private key (32-byte seed) using the
/// deterministic variant. Returns a 3309-byte signature.
pub fn ml_dsa_65_sign(data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, LatticeError> {
    use ml_dsa::{MlDsa65, KeyGen};
    use hybrid_array::Array;
    let seed: &Array<u8, _> = <&Array<u8, _>>::try_from(private_key.as_slice())
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    // from_seed returns a SigningKey; the deterministic signer is on
    // the ExpandedSigningKey that SigningKey.signing_key() exposes.
    let sk = MlDsa65::from_seed(seed);
    let esk = sk.signing_key();
    let sig = esk
        .sign_deterministic(&data, b"")
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    Ok(sig.encode().to_vec())
}

/// Verify an ML-DSA-65 signature. Returns `false` on any error
/// (malformed key, wrong signature length, verification failure).
pub fn ml_dsa_65_verify(
    data: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> bool {
    use ml_dsa::{MlDsa65, Signature, VerifyingKey};
    use hybrid_array::Array;
    let pk_arr: &Array<u8, _> = match <&Array<u8, _>>::try_from(public_key.as_slice()) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: &Array<u8, _> = match <&Array<u8, _>>::try_from(signature.as_slice()) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(pk_arr);
    let sig = match Signature::<MlDsa65>::decode(sig_arr) {
        Some(s) => s,
        None => return false,
    };
    vk.verify_with_context(&data, b"", &sig)
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
/// server (e.g. the `guest` service on port 9159). Returns the full response
/// bytes read until the server half-closes the TCP stream (which it must do
/// for each request, typically via `Connection: close`).
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

// =====================================================================
// Desktop Companion pairing (v0.1) — Kotlin-facing API
// =====================================================================
//
// Re-export the phone-side pairing primitives from `crypto::desktop_pair`
// so they show up in the UniFFI scaffold. The phone app feeds the scanned
// QR URL + its identity keys and gets back a ready-to-POST blob plus the
// 6-word SAS string to display.

pub use crypto::desktop_pair::{
    DesktopPairResponse as LatticeDesktopPairResponse,
    PhoneIdentity as LatticePhoneIdentity,
};

/// Build a desktop-pair response blob for the phone side. See the
/// `desktop_pair` module documentation for the full protocol spec.
pub fn build_desktop_pair_response(
    qr_url: String,
    ed25519_seed: Vec<u8>,
    ed25519_public: Vec<u8>,
    mldsa_seed: Vec<u8>,
    mldsa_public: Vec<u8>,
    phone_onion: String,
) -> Result<LatticeDesktopPairResponse, LatticeError> {
    crypto::desktop_pair::build_desktop_pair_response(
        qr_url,
        crypto::desktop_pair::PhoneIdentity {
            ed25519_seed,
            ed25519_public,
            mldsa_seed,
            mldsa_public,
        },
        phone_onion,
    )
}

/// Package a `DesktopPairResponse` into the JSON body the Android app
/// should POST to `https://ivy.vin/api/pair/push`. Convenience wrapper —
/// keeps the base64 + JSON construction on the Rust side so the Kotlin
/// caller doesn't have to re-encode pre-signed fields.
pub fn build_rendezvous_push_body(resp: LatticeDesktopPairResponse) -> String {
    crypto::desktop_pair::build_rendezvous_push_body(&resp)
}

// =====================================================================
// Desktop Companion — hidden-service hosting (v0.1 Phase 3)
// =====================================================================
//
// The phone hosts one dedicated v3 onion per paired desktop. The onion
// identity is derived deterministically from the pairing key so the
// hostname is stable across app restarts without the phone having to
// persist anything extra.
//
// Usage from Kotlin:
//   1. `torBootstrap(filesDir + "/tor")` — one-time (already done by app).
//   2. `desktopHsStart(pairingId, pairingKey, snapshotJson)` → returns the
//      real `.onion` hostname; pass it back into the pairing blob.
//   3. On revoke: `desktopHsStop(pairingId)`.
//
// Handles are owned by the global `HS_HANDLES` map — Kotlin doesn't have
// to manage lifetimes. Calling start twice for the same pairing stops the
// prior instance and launches a fresh one (idempotent re-start).

/// Launch a dedicated onion service for `pairing_id`, return the onion
/// hostname (e.g. `xyz....onion`). The service stays up until
/// `desktop_hs_stop` is called OR the process exits.
///
/// * `pairing_id`   — 16 B (first 16 B of the pairing transcript hash)
/// * `pairing_key`  — 32 B symmetric key derived by `build_desktop_pair_response`
/// * `snapshot_json` — the canned inbox snapshot that the phone will seal
///   and deliver as the first mirror frame when a desktop connects.
pub fn desktop_hs_start(
    pairing_id: Vec<u8>,
    pairing_key: Vec<u8>,
    snapshot_json: String,
) -> Result<String, LatticeError> {
    if pairing_id.len() != 16 {
        return Err(LatticeError::InvalidKeyLength);
    }
    if pairing_key.len() != 32 {
        return Err(LatticeError::InvalidKeyLength);
    }
    let mut pid = [0u8; 16];
    pid.copy_from_slice(&pairing_id);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pairing_key);

    // Grab a cheap clone of the Arti client from the global slot.
    let slot = TOR_CLIENT
        .get()
        .ok_or_else(|| LatticeError::TorConnectionFailed("tor not bootstrapped".into()))?;
    let tor = {
        let guard = slot
            .lock()
            .map_err(|e| LatticeError::TorConnectionFailed(format!("mutex poisoned: {}", e)))?;
        guard
            .as_ref()
            .ok_or_else(|| {
                LatticeError::TorConnectionFailed("tor client slot empty".into())
            })?
            .clone_handle()
    };

    let rt = tor_runtime();
    let handle = rt.block_on(async move {
        network::hs_host::hs_start(&tor, pid, pk, snapshot_json).await
    })?;

    let onion = handle.onion_hostname.clone();
    let key = hex::encode(pid);
    let map = hs_handles();
    let mut guard = map
        .lock()
        .map_err(|e| LatticeError::NetworkError(format!("hs map poisoned: {}", e)))?;
    // Re-start: drop the old handle (this stops its accept loop + releases
    // the onion service); then insert the new one. The old handle's
    // `Drop` won't tear down the service on its own, so we explicitly
    // `stop()` before replacing.
    if let Some(prev) = guard.remove(&key) {
        prev.stop();
    }
    guard.insert(key, handle);

    // Zeroize the local pairing_key copy — callers should also zero theirs.
    pk.zeroize();
    Ok(onion)
}

/// Stop the hidden service for a paired desktop and remove its handle
/// from the global map. Safe to call when no such pairing exists.
pub fn desktop_hs_stop(pairing_id: Vec<u8>) {
    if pairing_id.len() != 16 {
        return;
    }
    let key = hex::encode(&pairing_id);
    if let Some(slot) = HS_HANDLES.get() {
        if let Ok(mut guard) = slot.lock() {
            if let Some(h) = guard.remove(&key) {
                h.stop();
            }
        }
    }
}

/// Return the onion hostname currently serving `pairing_id`, or `None`.
/// Kotlin uses this after a crash-restart to verify whether a pairing's
/// HS is still alive (before re-invoking `desktop_hs_start`).
pub fn desktop_hs_onion(pairing_id: Vec<u8>) -> Option<String> {
    if pairing_id.len() != 16 {
        return None;
    }
    let key = hex::encode(&pairing_id);
    let slot = HS_HANDLES.get()?;
    let guard = slot.lock().ok()?;
    guard.get(&key).map(|h| h.onion_hostname.clone())
}

/// Block up to `timeout_ms` waiting for an inbound decrypted plaintext
/// frame from the desktop. Returns `None` on timeout (so Kotlin can
/// loop + re-check cancellation) or the frame bytes when one arrives.
/// Each call creates a fresh subscriber — frames delivered while no
/// one is polling are dropped (they're broadcast, not queued).
///
/// Kotlin dispatches by parsing the JSON `type` field. See the mirror
/// protocol spec in `ivy-desktop/src-tauri/src/ipc.rs`.
pub fn desktop_hs_poll_inbound(
    pairing_id: Vec<u8>,
    timeout_ms: u64,
) -> Result<Option<Vec<u8>>, LatticeError> {
    if pairing_id.len() != 16 {
        return Err(LatticeError::InvalidKeyLength);
    }
    let key = hex::encode(&pairing_id);
    let mut rx = {
        let slot = HS_HANDLES
            .get()
            .ok_or_else(|| LatticeError::NetworkError("no hs map".into()))?;
        let guard = slot
            .lock()
            .map_err(|e| LatticeError::NetworkError(format!("hs map poisoned: {}", e)))?;
        let h = guard
            .get(&key)
            .ok_or_else(|| LatticeError::NetworkError("no active pairing".into()))?;
        h.inbound_tx.subscribe()
    };
    let rt = tor_runtime();
    Ok(rt.block_on(async move {
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx.recv()).await {
            Ok(Ok(frame)) => Some(frame),
            Ok(Err(_)) => None, // channel closed or lagged
            Err(_) => None,     // timeout
        }
    }))
}

/// Push a plaintext frame to the paired desktop right now. Kotlin builds
/// the JSON (e.g. `{"type":"message",...}`), the Rust task seals it on
/// the P2D chain and writes it to the HS stream. Returns the number of
/// receivers the frame went out to (0 means no desktop is currently
/// connected — the caller can treat that as a no-op).
pub fn desktop_hs_push(pairing_id: Vec<u8>, plaintext: Vec<u8>) -> Result<u32, LatticeError> {
    if pairing_id.len() != 16 {
        return Err(LatticeError::InvalidKeyLength);
    }
    let key = hex::encode(&pairing_id);
    let slot = HS_HANDLES
        .get()
        .ok_or_else(|| LatticeError::NetworkError("no hs map".into()))?;
    let guard = slot
        .lock()
        .map_err(|e| LatticeError::NetworkError(format!("hs map poisoned: {}", e)))?;
    let handle = guard
        .get(&key)
        .ok_or_else(|| LatticeError::NetworkError("no active pairing".into()))?;
    Ok(handle.push_frame(plaintext) as u32)
}
