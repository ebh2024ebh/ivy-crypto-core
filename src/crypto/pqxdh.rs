use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use ml_kem::{KemCore, MlKem768, EncodedSizeUser, Encapsulate, Decapsulate};
use zeroize::Zeroize;

use crate::{LatticeError, SessionKeysBundle};
use super::hkdf::hkdf_expand;

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
    let mut classical_secret = classical_shared.as_bytes().to_vec();

    // --- Step 2: Post-Quantum ML-KEM-768 encapsulation ---
    let pq_ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
        ml_kem::array::Array::try_from(remote_pq_public)
            .map_err(|_| LatticeError::CryptoError("Invalid ML-KEM public key".into()))?
    );
    let mut rng = rand::thread_rng();
    let (encapsulated_ct, pq_shared_secret) = pq_ek.encapsulate(&mut rng)
        .map_err(|_| LatticeError::CryptoError("ML-KEM encapsulation failed".into()))?;
    let mut pq_secret = pq_shared_secret.as_bytes().to_vec();
    let encapsulated_bytes = encapsulated_ct.as_bytes().to_vec();

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
    let mut classical_secret = classical_shared.as_bytes().to_vec();

    // PQ decapsulation
    let pq_dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
        ml_kem::array::Array::try_from(local_pq_private)
            .map_err(|_| LatticeError::CryptoError("Invalid ML-KEM private key".into()))?
    );
    let pq_ct = ml_kem::Ciphertext::<ml_kem::MlKem768Params>::try_from(encapsulated_ciphertext)
        .map_err(|_| LatticeError::CryptoError("Invalid ciphertext".into()))?;
    let pq_shared_secret = pq_dk.decapsulate(&pq_ct)
        .map_err(|_| LatticeError::CryptoError("ML-KEM decapsulation failed".into()))?;
    let mut pq_secret = pq_shared_secret.as_bytes().to_vec();

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
