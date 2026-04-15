use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

use crate::{EncryptedMessage, LatticeError};
use super::nonce::NonceManager;

use super::hkdf::hkdf_expand;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// STATELESS DETERMINISTIC NONCE: The nonce is derived from the
/// encryption key via HKDF: Nonce = HKDF(key, "lattice-nonce-v1")[0..24].
///
/// This is safe because the Double Ratchet guarantees each message key
/// is unique and never reused. Since the key is unique, the derived
/// nonce is mathematically unique — no counter, no state, no process
/// coordination needed. Survives app restarts, multi-process, and OOM
/// kills without any risk of nonce collision.
///
/// Security proof: nonce reuse requires key reuse, which requires
/// ratchet state corruption (prevented by atomic SQLCipher transactions).
pub fn encrypt_xchacha20(plaintext: &[u8], key: &[u8]) -> Result<EncryptedMessage, LatticeError> {
    if key.len() != KEY_LEN {
        return Err(LatticeError::InvalidKeyLength);
    }

    // Derive nonce deterministically from the key itself.
    // Safe because the Double Ratchet guarantees key uniqueness.
    let nonce_full = hkdf_expand(key, b"lattice-nonce-v1", NONCE_LEN);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&nonce_full[..NONCE_LEN]);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LatticeError::CryptoError(e.to_string()))?;

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| LatticeError::CryptoError("Encryption failed".into()))?;

    // Split ciphertext and tag (tag is the last 16 bytes)
    let ct_len = ciphertext_with_tag.len() - TAG_LEN;
    let ciphertext = ciphertext_with_tag[..ct_len].to_vec();
    let tag = ciphertext_with_tag[ct_len..].to_vec();

    Ok(EncryptedMessage {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        tag,
    })
}

/// Decrypt a message with XChaCha20-Poly1305.
/// Authenticates the tag before decrypting (AEAD).
pub fn decrypt_xchacha20(
    payload: &EncryptedMessage,
    key: &[u8],
) -> Result<Vec<u8>, LatticeError> {
    if key.len() != KEY_LEN {
        return Err(LatticeError::InvalidKeyLength);
    }
    if payload.nonce.len() != NONCE_LEN {
        return Err(LatticeError::CryptoError("Invalid nonce length".into()));
    }

    let nonce = XNonce::from_slice(&payload.nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LatticeError::CryptoError(e.to_string()))?;

    // Reconstruct ciphertext || tag for AEAD decryption
    let mut ct_with_tag = payload.ciphertext.clone();
    ct_with_tag.extend_from_slice(&payload.tag);

    let plaintext = cipher
        .decrypt(nonce, ct_with_tag.as_slice())
        .map_err(|_| LatticeError::AuthenticationFailed)?;

    // Zero the intermediate buffer
    ct_with_tag.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Lattice!";

        let encrypted = encrypt_xchacha20(plaintext, &key).unwrap();
        let decrypted = decrypt_xchacha20(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Sensitive data";

        let mut encrypted = encrypt_xchacha20(plaintext, &key).unwrap();
        encrypted.ciphertext[0] ^= 0xFF; // Tamper

        assert!(decrypt_xchacha20(&encrypted, &key).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Secret";

        let encrypted = encrypt_xchacha20(plaintext, &key1).unwrap();
        assert!(decrypt_xchacha20(&encrypted, &key2).is_err());
    }
}
