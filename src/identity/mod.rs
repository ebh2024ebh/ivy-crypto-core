pub mod seed;
pub mod keygen;

use crate::{GhostIdentityBundle, LatticeError};
use seed::{derive_root_seed_impl, validate_mnemonic_impl};
use keygen::generate_keypairs;

/// Generate a Ghost Identity from a raw 512-bit root seed.
pub fn generate_ghost_identity(root_seed: &[u8]) -> Result<GhostIdentityBundle, LatticeError> {
    if root_seed.len() < 64 {
        return Err(LatticeError::CryptoError(
            "Root seed must be at least 512 bits".into(),
        ));
    }
    generate_keypairs(root_seed)
}

/// Recover a Ghost Identity from mnemonic words + optional passphrase.
pub fn recover_ghost_identity(
    words: &[String],
    passphrase: &str,
) -> Result<GhostIdentityBundle, LatticeError> {
    if !validate_mnemonic_impl(words) {
        return Err(LatticeError::InvalidMnemonic);
    }
    let root_seed = derive_root_seed_impl(words, passphrase);

    // SECURITY: Detect Argon2id failure (all-zero output).
    // An all-zero seed would produce identical keys for every user
    // who hits this error path — catastrophic key reuse.
    if root_seed.iter().all(|&b| b == 0) {
        return Err(LatticeError::CryptoError(
            "Seed derivation produced all-zero output — Argon2id may have failed".into(),
        ));
    }

    generate_keypairs(&root_seed)
}
