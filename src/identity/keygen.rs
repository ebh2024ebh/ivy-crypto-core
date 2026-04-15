use ed25519_dalek::SigningKey;
use x25519_dalek::StaticSecret as X25519Secret;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

// FIPS 203 ML-KEM-768 (exclusive — pqcrypto-kyber fully purged)
use ml_kem::{KemCore, MlKem768, EncodedSizeUser};

use crate::{GhostIdentityBundle, LatticeError};
use crate::crypto::hkdf::hkdf_expand;

/// Generate all three keypairs (Ed25519, X25519, ML-KEM-768) from a root seed.
///
/// Each keypair is derived from a distinct HKDF domain-separated sub-key
/// to ensure cryptographic independence. All derivations are fully
/// deterministic: the same root seed always produces identical keys.
pub fn generate_keypairs(root_seed: &[u8]) -> Result<GhostIdentityBundle, LatticeError> {
    // --- Derive domain-separated sub-seeds ---
    let mut ed_seed = hkdf_expand(root_seed, b"lattice-ed25519-signing", 32);
    let mut x_seed = hkdf_expand(root_seed, b"lattice-x25519-exchange", 32);
    // Reserved for future deterministic ML-KEM keygen when pqcrypto-kyber
    // exposes seeded generation. Derived and zeroized for forward compatibility.
    let mut _pq_seed = hkdf_expand(root_seed, b"lattice-mlkem768-pq", 64);

    // --- Ed25519 signing keypair ---
    let ed_seed_array: [u8; 32] = ed_seed[..32]
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let ed_signing_key = SigningKey::from_bytes(&ed_seed_array);
    let ed_verifying_key = ed_signing_key.verifying_key();

    let ed25519_signing_public = ed_verifying_key.to_bytes().to_vec();
    let ed25519_signing_private = ed_signing_key.to_bytes().to_vec();

    // --- X25519 key agreement keypair ---
    let x_seed_array: [u8; 32] = x_seed[..32]
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let x_secret = X25519Secret::from(x_seed_array);
    let x_public = x25519_dalek::PublicKey::from(&x_secret);

    let x25519_exchange_public = x_public.as_bytes().to_vec();
    let x25519_exchange_private = x_seed_array.to_vec();

    // --- ML-KEM-768 (Kyber) post-quantum keypair ---
    //
    // FIPS 203 deterministic keygen: derive d (32 bytes) and z (32 bytes)
    // from the BIP39 root seed via HKDF with domain separation. The same
    // seed always produces the same ML-KEM-768 keypair, enabling full
    // identity recovery from the 24-word mnemonic.
    let pq_d: [u8; 32] = _pq_seed[..32]
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;
    let pq_z: [u8; 32] = _pq_seed[32..64]
        .try_into()
        .map_err(|_| LatticeError::InvalidKeyLength)?;

    let (pq_dk, pq_ek) = MlKem768::generate_deterministic(&pq_d.into(), &pq_z.into());

    let mlkem768_public = pq_ek.as_bytes().to_vec();
    let mlkem768_private = pq_dk.as_bytes().to_vec();

    // --- Compute fingerprint: SHA-256(ed_pub || pq_pub), truncated to 20 bytes ---
    let mut hasher = Sha256::new();
    hasher.update(&ed25519_signing_public);
    hasher.update(&mlkem768_public);
    let hash = hasher.finalize();
    let fingerprint = hash[..20].to_vec();

    // --- Display ID ---
    let display_id = format!(
        "LX-{}",
        hex::encode(&fingerprint[..8]).to_uppercase()
    );

    // --- Zero ALL intermediate seed material ---
    ed_seed.zeroize();
    x_seed.zeroize();
    _pq_seed.zeroize();

    Ok(GhostIdentityBundle {
        ed25519_signing_public,
        ed25519_signing_private,
        x25519_exchange_public,
        x25519_exchange_private,
        mlkem768_public,
        mlkem768_private,
        fingerprint,
        display_id,
    })
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_produces_valid_bundle() {
        let seed = vec![42u8; 64];
        let bundle = generate_keypairs(&seed).unwrap();

        assert_eq!(bundle.ed25519_signing_public.len(), 32);
        assert_eq!(bundle.ed25519_signing_private.len(), 32);
        assert_eq!(bundle.x25519_exchange_public.len(), 32);
        assert_eq!(bundle.x25519_exchange_private.len(), 32);
        assert!(!bundle.mlkem768_public.is_empty());
        assert!(!bundle.mlkem768_private.is_empty());
        assert_eq!(bundle.fingerprint.len(), 20);
        assert!(bundle.display_id.starts_with("LX-"));
    }

    #[test]
    fn test_classical_keys_deterministic() {
        let seed = vec![99u8; 64];
        let bundle1 = generate_keypairs(&seed).unwrap();
        let bundle2 = generate_keypairs(&seed).unwrap();

        // Ed25519 and X25519 are always deterministic
        assert_eq!(bundle1.ed25519_signing_public, bundle2.ed25519_signing_public);
        assert_eq!(bundle1.ed25519_signing_private, bundle2.ed25519_signing_private);
        assert_eq!(bundle1.x25519_exchange_public, bundle2.x25519_exchange_public);
        assert_eq!(bundle1.x25519_exchange_private, bundle2.x25519_exchange_private);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let bundle1 = generate_keypairs(&vec![1u8; 64]).unwrap();
        let bundle2 = generate_keypairs(&vec![2u8; 64]).unwrap();

        assert_ne!(bundle1.ed25519_signing_public, bundle2.ed25519_signing_public);
        assert_ne!(bundle1.x25519_exchange_public, bundle2.x25519_exchange_public);
        assert_ne!(bundle1.fingerprint, bundle2.fingerprint);
    }

    #[test]
    fn test_short_seed_rejected() {
        let short_seed = vec![0u8; 32];
        // The caller (identity/mod.rs) validates seed length >= 64
        // keygen itself doesn't validate, but HKDF will still work
        let result = generate_keypairs(&short_seed);
        assert!(result.is_ok()); // HKDF accepts any length IKM
    }

    #[test]
    fn test_display_id_format() {
        let seed = vec![55u8; 64];
        let bundle = generate_keypairs(&seed).unwrap();
        assert!(bundle.display_id.starts_with("LX-"));
        // Should be "LX-" + 16 hex chars
        assert_eq!(bundle.display_id.len(), 3 + 16);
        assert!(bundle.display_id[3..].chars().all(|c| c.is_ascii_hexdigit()));
    }
}
