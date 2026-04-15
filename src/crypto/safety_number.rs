use sha2::{Sha512, Digest};

/// Generate a 60-digit Safety Number from two parties' public keys.
///
/// PROTOCOL:
/// 1. Concatenate all public keys for each party:
///    party_blob = signing_pub || exchange_pub || pq_pub
/// 2. Sort the two blobs lexicographically (canonical ordering)
/// 3. Hash: SHA-512(sorted_first || sorted_second)
/// 4. Convert to decimal digits, take first 60
///
/// Both devices produce the same output because:
/// - Key ordering is canonical (lexicographic sort)
/// - SHA-512 is deterministic
///
/// The user reads the number aloud or compares screens.
/// A MITM attacker who substituted keys produces a different number.
pub fn generate_safety_number(
    my_signing_pub: &[u8],
    my_exchange_pub: &[u8],
    my_pq_pub: &[u8],
    their_signing_pub: &[u8],
    their_exchange_pub: &[u8],
    their_pq_pub: &[u8],
) -> String {
    // Build per-party blobs
    let mut my_blob = Vec::with_capacity(
        my_signing_pub.len() + my_exchange_pub.len() + my_pq_pub.len(),
    );
    my_blob.extend_from_slice(my_signing_pub);
    my_blob.extend_from_slice(my_exchange_pub);
    my_blob.extend_from_slice(my_pq_pub);

    let mut their_blob = Vec::with_capacity(
        their_signing_pub.len() + their_exchange_pub.len() + their_pq_pub.len(),
    );
    their_blob.extend_from_slice(their_signing_pub);
    their_blob.extend_from_slice(their_exchange_pub);
    their_blob.extend_from_slice(their_pq_pub);

    // Canonical ordering: lexicographic sort
    let (first, second) = if my_blob < their_blob {
        (&my_blob, &their_blob)
    } else {
        (&their_blob, &my_blob)
    };

    // SHA-512 hash
    let mut hasher = Sha512::new();
    hasher.update(b"lattice-safety-number-v1");
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Convert to 60 decimal digits (chunked into 12 groups of 5)
    // Each 5-digit group is derived from 2 bytes of the hash (mod 100000)
    let mut digits = String::with_capacity(71); // 60 digits + 11 dashes
    for i in 0..12 {
        if i > 0 {
            digits.push('-');
        }
        let val = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as u32;
        // Map 0-65535 to 0-99999 (slight bias, acceptable for display)
        let group = (val * 100000) / 65536;
        digits.push_str(&format!("{:05}", group));
    }

    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_deterministic() {
        let my_sign = [1u8; 32];
        let my_exch = [2u8; 32];
        let my_pq = [3u8; 32]; // Simplified for test
        let their_sign = [4u8; 32];
        let their_exch = [5u8; 32];
        let their_pq = [6u8; 32];

        let n1 = generate_safety_number(&my_sign, &my_exch, &my_pq, &their_sign, &their_exch, &their_pq);
        let n2 = generate_safety_number(&my_sign, &my_exch, &my_pq, &their_sign, &their_exch, &their_pq);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_safety_number_symmetric() {
        let my_sign = [1u8; 32];
        let my_exch = [2u8; 32];
        let my_pq = [3u8; 32];
        let their_sign = [4u8; 32];
        let their_exch = [5u8; 32];
        let their_pq = [6u8; 32];

        let n1 = generate_safety_number(&my_sign, &my_exch, &my_pq, &their_sign, &their_exch, &their_pq);
        let n2 = generate_safety_number(&their_sign, &their_exch, &their_pq, &my_sign, &my_exch, &my_pq);
        assert_eq!(n1, n2, "Safety numbers must be identical regardless of who computes them");
    }

    #[test]
    fn test_safety_number_format() {
        let n = generate_safety_number(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32]);
        assert_eq!(n.len(), 71); // 60 digits + 11 dashes
        assert_eq!(n.matches('-').count(), 11);
        assert!(n.chars().all(|c| c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn test_different_keys_different_numbers() {
        let n1 = generate_safety_number(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32]);
        let n2 = generate_safety_number(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[7u8; 32], &[8u8; 32], &[9u8; 32]);
        assert_ne!(n1, n2);
    }
}
