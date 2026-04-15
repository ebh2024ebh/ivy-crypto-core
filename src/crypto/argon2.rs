use argon2::{Algorithm, Argon2, Params, Version};
use crate::LatticeError;

/// Hash a password/PIN with Argon2id using configurable parameters.
///
/// Default hardened parameters for Blind Vault:
/// - memory_kb: 65536 (64 MB)
/// - iterations: 3
/// - parallelism: 4
///
/// These parameters make brute-force attacks computationally ruinous
/// while remaining feasible on modern mobile hardware (~1-2 seconds).
pub fn argon2_hash_impl(
    password: &[u8],
    salt: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, LatticeError> {
    let params = Params::new(
        memory_kb,
        iterations,
        parallelism,
        Some(32), // Output length: 256 bits
    )
    .map_err(|e| LatticeError::CryptoError(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| LatticeError::CryptoError(format!("Argon2 hashing failed: {}", e)))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_deterministic() {
        let password = b"test_pin_12345678";
        let salt = b"random_salt_16by";

        let hash1 = argon2_hash_impl(password, salt, 1024, 1, 1).unwrap();
        let hash2 = argon2_hash_impl(password, salt, 1024, 1, 1).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_argon2_different_passwords() {
        let salt = b"random_salt_16by";
        let h1 = argon2_hash_impl(b"pin1", salt, 1024, 1, 1).unwrap();
        let h2 = argon2_hash_impl(b"pin2", salt, 1024, 1, 1).unwrap();
        assert_ne!(h1, h2);
    }
}
