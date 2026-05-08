use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use ml_kem::{MlKem768, MlKem768Params, EncodedSizeUser};
use ml_kem::kem::{Encapsulate, Decapsulate};
use zeroize::Zeroize;

use crate::{LatticeError, SessionKeysBundle};
use super::hkdf::hkdf_expand;

/// Single opaque error string returned for every PQXDH input-validation
/// or decap-failure path. Per Bug 10.5 (decap oracle leaks), distinct
/// error messages on different failure modes are observable by an
/// attacker probing the API and constitute a CCA-relevant oracle.
/// Collapsing them here removes the distinguishability surface entirely.
const PQXDH_OPAQUE_ERR: &str = "pqxdh: invalid input";

/// Perform a hybrid PQXDH key agreement combining:
/// 1. Classical X25519 ECDH shared secret
/// 2. ML-KEM-768 encapsulated shared secret
///
/// The two secrets are combined via HKDF to produce session keys
/// with both classical and post-quantum security guarantees.
pub fn perform_pqxdh_impl(
    local_x25519_private: &[u8],
    _local_pq_private: &[u8],
    remote_x25519_public: &[u8],
    remote_pq_public: &[u8],
) -> Result<SessionKeysBundle, LatticeError> {
    // --- Step 1: Classical X25519 ECDH ---
    if local_x25519_private.len() != 32 || remote_x25519_public.len() != 32 {
        return Err(LatticeError::InvalidKeyLength);
    }

    let local_secret = {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(local_x25519_private);
        X25519Secret::from(key_bytes)
    };

    let remote_public = {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(remote_x25519_public);
        X25519Public::from(key_bytes)
    };

    let classical_shared = local_secret.diffie_hellman(&remote_public);
    // RFC 9180 §7.1.4 / hpke-ng audit (May 2026): a low-order or
    // identity remote pubkey forces ECDH to produce all-zeros.
    // Reject constant-time before we feed it into HKDF. The hybrid
    // still has ML-KEM entropy backing it, but defense-in-depth.
    {
        use subtle::ConstantTimeEq;
        let zero = [0u8; 32];
        if classical_shared.as_bytes().ct_eq(&zero).into() {
            return Err(LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()));
        }
    }
    let mut classical_secret = classical_shared.as_bytes().to_vec();

    // --- Step 2: Post-Quantum ML-KEM-768 encapsulation ---
    //
    // Bug 10.5 / Audit floor 7.1 (decap oracle leaks): every error path
    // below returns the SAME error variant with the SAME message string.
    // Distinguishing "wrong-length input" from "encapsulation failed" via
    // the response would let a probing attacker identify which step they
    // tripped, which is the shape of the oracle ML-KEM's CCA security is
    // designed to prevent. The safe default is "every input-validation
    // error looks identical from the outside."
    let pq_ek = ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(
        &ml_kem::array::Array::try_from(remote_pq_public)
            .map_err(|_| LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()))?
    );
    let mut rng = rand::thread_rng();
    let (encapsulated_ct, pq_shared_secret) = pq_ek.encapsulate(&mut rng)
        .map_err(|_| LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()))?;
    let mut pq_secret: Vec<u8> = AsRef::<[u8]>::as_ref(&pq_shared_secret).to_vec();
    let encapsulated_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&encapsulated_ct).to_vec();

    // --- Step 3: Hybrid combination via HKDF ---
    //
    // HKDF DOMAIN SEPARATION (Vector 2c):
    //
    // The `info` parameter includes a protocol version prefix AND
    // BOTH parties' public keys in CANONICAL (lexicographic) order.
    // Canonical ordering ensures both sides derive identical root keys
    // regardless of who initiated the handshake.
    //
    // For send/recv chain differentiation, the initiator (encapsulator)
    // appends "i" (initiator) and the responder appends "r".
    //
    let mut combined = Vec::with_capacity(classical_secret.len() + pq_secret.len());
    combined.extend_from_slice(&classical_secret);
    combined.extend_from_slice(&pq_secret);

    let local_pub = x25519_dalek::PublicKey::from(&local_secret);

    // Canonical key ordering: sort lexicographically
    let local_pub_bytes: &[u8] = local_pub.as_bytes().as_slice();
    let (first_key, second_key) = if local_pub_bytes < remote_x25519_public {
        (local_pub_bytes, remote_x25519_public)
    } else {
        (remote_x25519_public, local_pub_bytes)
    };

    let mut root_info = b"lattice-pqxdh-v1-root".to_vec();
    root_info.extend_from_slice(first_key);
    root_info.extend_from_slice(second_key);
    let root_key = hkdf_expand(&combined, &root_info, 32);

    // Initiator's send = responder's recv (use "i" suffix)
    let mut init_info = b"lattice-pqxdh-v1-chain-i".to_vec();
    init_info.extend_from_slice(first_key);
    init_info.extend_from_slice(second_key);
    let init_chain = hkdf_expand(&root_key, &init_info, 32);

    let mut resp_info = b"lattice-pqxdh-v1-chain-r".to_vec();
    resp_info.extend_from_slice(first_key);
    resp_info.extend_from_slice(second_key);
    let resp_chain = hkdf_expand(&root_key, &resp_info, 32);

    // Initiator (encapsulator) sends on init_chain, receives on resp_chain
    let send_chain = init_chain;
    let recv_chain = resp_chain;

    // --- Step 4: Zero ALL intermediate secrets ---
    classical_secret.zeroize();
    pq_secret.zeroize();
    combined.zeroize();
    root_info.zeroize();
    init_info.zeroize();
    resp_info.zeroize();

    Ok(SessionKeysBundle {
        sending_chain_key: send_chain,
        receiving_chain_key: recv_chain,
        root_key,
        encapsulated_ciphertext: Some(encapsulated_bytes),
    })
}

/// Decapsulate on the receiving side to derive the same session keys.
pub fn decapsulate_pqxdh(
    local_x25519_private: &[u8],
    local_pq_private: &[u8],
    remote_x25519_public: &[u8],
    encapsulated_ciphertext: &[u8],
) -> Result<SessionKeysBundle, LatticeError> {
    // Classical ECDH (same as encapsulation side)
    if local_x25519_private.len() != 32 || remote_x25519_public.len() != 32 {
        return Err(LatticeError::InvalidKeyLength);
    }

    let local_secret = {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(local_x25519_private);
        X25519Secret::from(key_bytes)
    };

    let remote_public = {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(remote_x25519_public);
        X25519Public::from(key_bytes)
    };

    let classical_shared = local_secret.diffie_hellman(&remote_public);
    // Same low-order-point defense as the encapsulation side.
    // RFC 9180 §7.1.4 — reject all-zero ECDH output before HKDF.
    {
        use subtle::ConstantTimeEq;
        let zero = [0u8; 32];
        if classical_shared.as_bytes().ct_eq(&zero).into() {
            return Err(LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()));
        }
    }
    let mut classical_secret = classical_shared.as_bytes().to_vec();

    // PQ decapsulation — same single-opaque-error pattern as the
    // encapsulation side. Bug 10.5 (decap oracle): if "wrong-length
    // private key", "wrong-length ciphertext", and "decap failed"
    // returned distinguishable strings, an attacker submitting
    // ciphertexts could tell which step they tripped. They all
    // collapse to PQXDH_OPAQUE_ERR.
    let pq_dk = ml_kem::kem::DecapsulationKey::<MlKem768Params>::from_bytes(
        &ml_kem::array::Array::try_from(local_pq_private)
            .map_err(|_| LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()))?
    );
    let pq_ct = ml_kem::Ciphertext::<MlKem768>::try_from(encapsulated_ciphertext)
        .map_err(|_| LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()))?;
    let pq_shared_secret = pq_dk.decapsulate(&pq_ct)
        .map_err(|_| LatticeError::CryptoError(PQXDH_OPAQUE_ERR.into()))?;
    let mut pq_secret: Vec<u8> = AsRef::<[u8]>::as_ref(&pq_shared_secret).to_vec();

    // Hybrid combination with canonical key ordering (matches encapsulate)
    let mut combined = Vec::with_capacity(classical_secret.len() + pq_secret.len());
    combined.extend_from_slice(&classical_secret);
    combined.extend_from_slice(&pq_secret);

    let local_pub = x25519_dalek::PublicKey::from(&local_secret);

    // Canonical ordering: same sort as encapsulate side
    let local_pub_bytes: &[u8] = local_pub.as_bytes().as_slice();
    let (first_key, second_key) = if local_pub_bytes < remote_x25519_public {
        (local_pub_bytes, remote_x25519_public)
    } else {
        (remote_x25519_public, local_pub_bytes)
    };

    let mut root_info = b"lattice-pqxdh-v1-root".to_vec();
    root_info.extend_from_slice(first_key);
    root_info.extend_from_slice(second_key);
    let root_key = hkdf_expand(&combined, &root_info, 32);

    let mut init_info = b"lattice-pqxdh-v1-chain-i".to_vec();
    init_info.extend_from_slice(first_key);
    init_info.extend_from_slice(second_key);
    let init_chain = hkdf_expand(&root_key, &init_info, 32);

    let mut resp_info = b"lattice-pqxdh-v1-chain-r".to_vec();
    resp_info.extend_from_slice(first_key);
    resp_info.extend_from_slice(second_key);
    let resp_chain = hkdf_expand(&root_key, &resp_info, 32);

    // Responder sends on resp_chain, receives on init_chain
    let send_chain = resp_chain;
    let recv_chain = init_chain;

    classical_secret.zeroize();
    pq_secret.zeroize();
    combined.zeroize();
    root_info.zeroize();
    init_info.zeroize();
    resp_info.zeroize();

    Ok(SessionKeysBundle {
        sending_chain_key: send_chain,
        receiving_chain_key: recv_chain,
        root_key,
        encapsulated_ciphertext: None,
    })
}
