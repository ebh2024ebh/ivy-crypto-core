use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{LatticeError, ShamirShare};

/// GF(256) multiplication using the AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1B; // Reduction polynomial
        }
        b >>= 1;
    }
    result
}

/// GF(256) multiplicative inverse via Fermat's little theorem: a^254 = a^(-1)
#[inline]
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Compute a^254 by repeated squaring
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

/// Split a secret into `n` shares with threshold `k` using Shamir's Secret Sharing.
/// Each byte of the secret is treated as the constant term of a random polynomial
/// of degree `k-1` over GF(256). Shares are evaluations at points 1..n.
pub fn shamir_split_impl(
    secret: &[u8],
    total_shares: u8,
    threshold: u8,
) -> Result<Vec<ShamirShare>, LatticeError> {
    if threshold < 2 || threshold > total_shares || total_shares == 0 {
        return Err(LatticeError::CryptoError(
            "Invalid Shamir parameters: need 2 <= threshold <= total_shares".into(),
        ));
    }

    let mut rng = OsRng;
    let mut shares: Vec<ShamirShare> = (1..=total_shares)
        .map(|x| ShamirShare {
            index: x,
            data: vec![0u8; secret.len()],
            threshold,
            total_shares,
        })
        .collect();

    // For each byte of the secret, create a random polynomial and evaluate
    for byte_idx in 0..secret.len() {
        // Random coefficients for degree 1..k-1 (constant term is secret[byte_idx])
        let mut coefficients = vec![0u8; (threshold - 1) as usize];
        rng.fill_bytes(&mut coefficients);

        for share in shares.iter_mut() {
            let x = share.index;
            let mut y = secret[byte_idx];
            let mut x_pow: u8 = 1;

            for &coeff in &coefficients {
                x_pow = gf256_mul(x_pow, x);
                y ^= gf256_mul(coeff, x_pow);
            }

            share.data[byte_idx] = y;
        }

        coefficients.zeroize();
    }

    Ok(shares)
}

/// Reconstruct a secret from `k` or more Shamir shares using Lagrange interpolation.
pub fn shamir_recombine_impl(shares: &[ShamirShare]) -> Result<Vec<u8>, LatticeError> {
    if shares.is_empty() {
        return Err(LatticeError::InsufficientShares);
    }

    let threshold = shares[0].threshold as usize;
    let total_shares = shares[0].total_shares;
    let data_len = shares[0].data.len();

    if shares.len() < threshold {
        return Err(LatticeError::InsufficientShares);
    }

    // SECURITY: Validate metadata consistency across all shares.
    // Mixing shares from different SSS sessions would silently produce
    // corrupted output — detecting this prevents subtle recovery failures.
    for (i, share) in shares.iter().enumerate() {
        if share.threshold != shares[0].threshold {
            return Err(LatticeError::CryptoError(format!(
                "Share {} has threshold {} but expected {}",
                i, share.threshold, shares[0].threshold
            )));
        }
        if share.total_shares != total_shares {
            return Err(LatticeError::CryptoError(format!(
                "Share {} has total_shares {} but expected {}",
                i, share.total_shares, total_shares
            )));
        }
        if share.data.len() != data_len {
            return Err(LatticeError::CryptoError(format!(
                "Share {} has data length {} but expected {}",
                i, share.data.len(), data_len
            )));
        }
        // Validate share indices are unique (duplicate indices = wrong reconstruction)
        for j in (i + 1)..shares.len() {
            if share.index == shares[j].index {
                return Err(LatticeError::CryptoError(format!(
                    "Duplicate share index {} at positions {} and {}",
                    share.index, i, j
                )));
            }
        }
    }

    let active = &shares[..threshold];
    let secret_len = active[0].data.len();
    let mut secret = vec![0u8; secret_len];

    for byte_idx in 0..secret_len {
        let mut result: u8 = 0;

        for i in 0..threshold {
            let xi = active[i].index;
            let yi = active[i].data[byte_idx];

            // Compute Lagrange basis polynomial at x=0
            let mut lagrange: u8 = 1;
            for j in 0..threshold {
                if i == j {
                    continue;
                }
                let xj = active[j].index;
                // L_i(0) = product of (0 - x_j) / (x_i - x_j) = product of x_j / (x_i ^ x_j)
                let numerator = xj;
                let denominator = xi ^ xj;
                lagrange = gf256_mul(lagrange, gf256_mul(numerator, gf256_inv(denominator)));
            }

            result ^= gf256_mul(yi, lagrange);
        }

        secret[byte_idx] = result;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul_identity() {
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);
    }

    #[test]
    fn test_gf256_inv_roundtrip() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "Failed for a={}", a);
        }
    }

    #[test]
    fn test_shamir_roundtrip_3_of_5() {
        let secret = b"Lattice sovereign identity key!!"; // 32 bytes
        let shares = shamir_split_impl(secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold shares
        let recovered = shamir_recombine_impl(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with different subset
        let recovered2 = shamir_recombine_impl(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_shamir_insufficient_shares_fails() {
        let secret = b"test secret";
        let shares = shamir_split_impl(secret, 5, 3).unwrap();
        assert!(shamir_recombine_impl(&shares[0..2]).is_err());
    }
}
