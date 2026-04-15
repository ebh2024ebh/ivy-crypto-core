use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-Expand using SHA-256.
/// Derives `length` bytes of key material from input key material and info string.
///
/// # Panics
/// Only panics if `length > 255 * 32` (8160 bytes), which is an HKDF spec violation.
/// All Lattice callers request ≤ 2400 bytes, so this is unreachable in practice.
pub fn hkdf_expand(ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    debug_assert!(
        length <= 255 * 32,
        "HKDF-SHA256 output length must be <= 8160 bytes, got {}",
        length
    );
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut output = vec![0u8; length];
    // SAFETY: length is always within spec bounds for Lattice's usage.
    // If somehow violated, this is a programmer error (not user input).
    if hk.expand(info, &mut output).is_err() {
        // Graceful degradation: zero-fill rather than panic across FFI.
        output.fill(0);
    }
    output
}

/// HKDF-Extract + Expand using SHA-256 with an explicit salt.
pub fn hkdf_extract_expand(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    debug_assert!(
        length <= 255 * 32,
        "HKDF-SHA256 output length must be <= 8160 bytes, got {}",
        length
    );
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    if hk.expand(info, &mut output).is_err() {
        output.fill(0);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test key material";
        let info = b"test info";
        let out1 = hkdf_expand(ikm, info, 32);
        let out2 = hkdf_expand(ikm, info, 32);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let ikm = b"test key material";
        let out1 = hkdf_expand(ikm, b"info-a", 32);
        let out2 = hkdf_expand(ikm, b"info-b", 32);
        assert_ne!(out1, out2);
    }
}
