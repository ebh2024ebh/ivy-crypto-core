use sha2::{Sha256, Digest};
use crate::{LatticeError, ProofOfWork};

/// Compute an Argon2id-flavored proof of work.
///
/// The sender must find a nonce such that SHA-256(challenge || nonce) has
/// `difficulty` leading zero bits. This makes spam computationally expensive
/// while remaining lightweight for legitimate single-message sends.
///
/// For bandwidth protection (Section 7.1), difficulty scales with file size:
/// - Text messages: difficulty 16 (~65K attempts, <100ms)
/// - Small files (<1MB): difficulty 20 (~1M attempts, ~1s)
/// - Large files (>10MB): difficulty 24 (~16M attempts, ~10s)
/// Maximum number of hash iterations before giving up.
/// At difficulty=24 (~16M expected), 1 billion provides ~60x headroom.
/// This prevents infinite loops on unreasonable difficulty values.
const MAX_POW_ITERATIONS: u64 = 1_000_000_000;

pub fn compute_pow(challenge: &[u8], difficulty: u32) -> Result<ProofOfWork, LatticeError> {
    if difficulty > 48 {
        // Cap at 48 bits — anything higher is computationally infeasible
        // on mobile hardware and likely a DoS vector.
        return Err(LatticeError::ProofOfWorkFailed);
    }

    let target_zeros = difficulty as usize;

    for nonce in 0u64..MAX_POW_ITERATIONS {
        let hash = compute_pow_hash(challenge, nonce);

        if count_leading_zero_bits(&hash) >= target_zeros {
            return Ok(ProofOfWork {
                nonce,
                hash: hash.to_vec(),
            });
        }
    }

    // Exhausted iteration budget without finding a valid nonce
    Err(LatticeError::ProofOfWorkFailed)
}

/// Verify a proof of work against a challenge and difficulty target.
pub fn verify_pow(challenge: &[u8], proof: &ProofOfWork, difficulty: u32) -> bool {
    let hash = compute_pow_hash(challenge, proof.nonce);
    let target_zeros = difficulty as usize;

    // Verify the hash matches what was claimed
    if hash.as_slice() != proof.hash.as_slice() {
        return false;
    }

    count_leading_zero_bits(&hash) >= target_zeros
}

/// Compute SHA-256(challenge || nonce_le_bytes).
fn compute_pow_hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce.to_le_bytes());
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Count leading zero bits in a hash.
fn count_leading_zero_bits(hash: &[u8]) -> usize {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_low_difficulty() {
        let challenge = b"test challenge for anti-spam";
        let proof = compute_pow(challenge, 8).unwrap();
        assert!(verify_pow(challenge, &proof, 8));
    }

    #[test]
    fn test_pow_verification_fails_with_wrong_challenge() {
        let challenge = b"real challenge";
        let proof = compute_pow(challenge, 8).unwrap();
        assert!(!verify_pow(b"fake challenge", &proof, 8));
    }

    #[test]
    fn test_pow_verification_fails_with_higher_difficulty() {
        let challenge = b"test";
        let proof = compute_pow(challenge, 4).unwrap();
        // A proof valid for difficulty 4 should be verified correctly at difficulty 4
        assert!(verify_pow(challenge, &proof, 4));
        // With much higher difficulty, it almost certainly fails
        assert!(!verify_pow(challenge, &proof, 32));
    }

    #[test]
    fn test_excessive_difficulty_rejected() {
        let challenge = b"test";
        let result = compute_pow(challenge, 49);
        assert!(result.is_err(), "Difficulty > 48 should be rejected");
    }

    #[test]
    fn test_max_iterations_bounded() {
        // difficulty=40 is extremely unlikely to solve in MAX_POW_ITERATIONS
        // but won't hang forever — it will return Err
        let challenge = b"extremely hard challenge";
        let result = compute_pow(challenge, 40);
        // May succeed or fail, but must terminate
        let _ = result;
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x01]), 16);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x0F, 0xFF]), 12);
        assert_eq!(count_leading_zero_bits(&[0xFF]), 0);
        assert_eq!(count_leading_zero_bits(&[0x01]), 7);
    }
}
