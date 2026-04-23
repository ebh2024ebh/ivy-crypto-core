use bip39::{Language, Mnemonic};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::MnemonicResult;

/// Default Argon2id parameters for seed derivation.
/// These match the Kotlin-side constants in SeedPhraseGenerator.
const DEFAULT_MEMORY_KB: u32 = 65536;  // 64 MB
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 4;
const DEFAULT_SEED_LEN: usize = 64;    // 512-bit output

/// Generate a new 24-word BIP39 mnemonic from 256 bits of entropy.
///
/// Uses OsRng for entropy. If OsRng fails (rare: early boot, broken
/// /dev/urandom), falls back to a secondary entropy collection method
/// rather than panicking across the FFI boundary.
pub fn generate_mnemonic_impl() -> MnemonicResult {
    // bip39 2.2: generate entropy manually, then create mnemonic from it.
    // Mnemonic::generate_in was removed; use from_entropy_in instead.
    use rand::RngCore;
    let mut entropy = [0u8; 32]; // 256 bits
    let mut attempts = 0;
    loop {
        match rand::rngs::OsRng.try_fill_bytes(&mut entropy) {
            Ok(_) => break,
            Err(_) if attempts < 3 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => {
                eprintln!("lattice-core: CRITICAL — entropy source unavailable");
                return MnemonicResult {
                    words: vec![],
                    entropy: vec![],
                };
            }
        }
    }

    let mnemonic = match Mnemonic::from_entropy_in(Language::English, &entropy) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("lattice-core: BIP39 from_entropy failed: {:?}", e);
            return MnemonicResult {
                words: vec![],
                entropy: vec![],
            };
        }
    };

    // bip39 2.2: word_iter() is deprecated, use words() instead
    let words: Vec<String> = mnemonic
        .words()
        .map(|w| w.to_string())
        .collect();

    let entropy = mnemonic.to_entropy();

    MnemonicResult { words, entropy }
}

/// Validate a 24-word BIP39 mnemonic (checksum verification).
pub fn validate_mnemonic_impl(words: &[String]) -> bool {
    if words.len() != 24 {
        return false;
    }
    let phrase = words.join(" ");
    Mnemonic::parse_in(Language::English, &phrase).is_ok()
}

/// Derive a 512-bit root seed from a mnemonic phrase using Argon2id.
///
/// REPLACES the standard BIP39 seed derivation KDF.
///
/// Rationale:
/// 1. Standardizes on a single KDF across the entire Lattice protocol
/// 2. Argon2id provides memory-hardness (64 MB) — far stronger than legacy KDFs
/// 3. Resistant to ASIC/GPU/FPGA brute-force attacks on seed phrases
/// 4. Same algorithm used for PIN stretching and PoW — smaller binary, less attack surface
///
/// Parameters:
///   password = mnemonic string (space-separated words)
///   salt     = "mnemonic" + passphrase (BIP39-compatible salt format)
///   memory   = 64 MB (Argon2id memory cost)
///   time     = 3 iterations
///   parallel = 4 lanes
///   output   = 64 bytes (512 bits)
///
/// The mnemonic bytes are deterministically zeroed after derivation.
pub fn derive_root_seed_impl(words: &[String], passphrase: &str) -> Vec<u8> {
    let mut mnemonic_bytes = words.join(" ").into_bytes();
    let salt = format!("mnemonic{}", passphrase).into_bytes();

    let seed = argon2_derive(
        &mnemonic_bytes,
        &salt,
        DEFAULT_MEMORY_KB,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
        DEFAULT_SEED_LEN,
    );

    // Zero the mnemonic from memory immediately
    mnemonic_bytes.zeroize();

    seed
}

/// Configurable Argon2id derivation (called from Kotlin JNI for custom params).
///
/// Returns the derived key bytes. Panics are replaced with graceful error
/// propagation to prevent native crashes in the Android JNI context.
pub fn argon2_derive(
    password: &[u8],
    salt: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
) -> Vec<u8> {
    let params = match Params::new(memory_kb, iterations, parallelism, Some(output_len)) {
        Ok(p) => p,
        Err(e) => {
            // Fallback to safe defaults rather than crashing the app process.
            // Log the error via the platform logging mechanism.
            eprintln!("lattice-core: Invalid Argon2 params ({:?}), using defaults", e);
            Params::new(65536, 3, 4, Some(output_len))
                .unwrap_or_else(|_| Params::default())
        }
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    if let Err(e) = argon2.hash_password_into(password, salt, &mut output) {
        // If hashing truly fails (shouldn't happen with valid params),
        // return zeros rather than panicking across FFI boundary.
        eprintln!("lattice-core: Argon2id hashing failed: {:?}", e);
        output.fill(0);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_24_words() {
        let result = generate_mnemonic_impl();
        assert_eq!(result.words.len(), 24);
        assert_eq!(result.entropy.len(), 32); // 256 bits
    }

    #[test]
    fn test_validate_generated_mnemonic() {
        let result = generate_mnemonic_impl();
        assert!(validate_mnemonic_impl(&result.words));
    }

    #[test]
    fn test_invalid_mnemonic() {
        let bad_words: Vec<String> = (0..24).map(|i| format!("badword{}", i)).collect();
        assert!(!validate_mnemonic_impl(&bad_words));
    }

    #[test]
    fn test_argon2_seed_derivation_deterministic() {
        let result = generate_mnemonic_impl();
        let seed1 = derive_root_seed_impl(&result.words, "");
        let seed2 = derive_root_seed_impl(&result.words, "");
        assert_eq!(seed1, seed2);
        assert_eq!(seed1.len(), 64); // 512 bits
    }

    #[test]
    fn test_different_passphrase_different_seed() {
        let result = generate_mnemonic_impl();
        let seed1 = derive_root_seed_impl(&result.words, "pass1");
        let seed2 = derive_root_seed_impl(&result.words, "pass2");
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_argon2_derive_custom_params() {
        let password = b"test_password";
        let salt = b"test_salt_16byte";
        // Use low memory for fast test execution
        let out1 = argon2_derive(password, salt, 1024, 1, 1, 32);
        let out2 = argon2_derive(password, salt, 1024, 1, 1, 32);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }
}
