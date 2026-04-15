use reed_solomon_erasure::galois_8::ReedSolomon;
use crate::{ErasureCodedData, LatticeError};

/// Erasure-encode data into data + parity shards using Reed-Solomon.
///
/// Used by the Desktop Swarm (Route B) to split encrypted media files
/// into redundant shards that can be reconstructed from any `data_shards`
/// out of `data_shards + parity_shards` total.
pub fn erasure_encode_impl(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<ErasureCodedData, LatticeError> {
    if data_shards == 0 || parity_shards == 0 {
        return Err(LatticeError::ErasureCodeError("Shard counts must be > 0".into()));
    }

    if data.is_empty() {
        return Err(LatticeError::ErasureCodeError("Cannot erasure-encode empty data".into()));
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| LatticeError::ErasureCodeError(format!("RS init failed: {}", e)))?;

    let original_size = data.len() as u64;

    // Pad data to be evenly divisible by data_shards.
    // shard_size is always >= 1 because data.len() >= 1 (checked above).
    let shard_size = (data.len() + data_shards - 1) / data_shards;
    debug_assert!(shard_size > 0, "shard_size must be > 0 for chunks()");
    let mut padded = data.to_vec();
    padded.resize(shard_size * data_shards, 0);

    // Split into data shards
    let mut shards: Vec<Vec<u8>> = padded
        .chunks(shard_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // Add empty parity shards
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // Encode parity
    rs.encode(&mut shards)
        .map_err(|e| LatticeError::ErasureCodeError(format!("Encoding failed: {}", e)))?;

    Ok(ErasureCodedData {
        shards,
        data_shard_count: data_shards as u32,
        parity_shard_count: parity_shards as u32,
        original_size,
    })
}

/// Erasure-decode shards back to the original data.
///
/// Can recover from up to `parity_shards` missing shards.
/// Missing shards should be represented as empty Vec<u8>.
pub fn erasure_decode_impl(
    coded: &ErasureCodedData,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, LatticeError> {
    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| LatticeError::ErasureCodeError(format!("RS init failed: {}", e)))?;

    let shard_size = if coded.shards.is_empty() {
        return Err(LatticeError::ErasureCodeError("No shards provided".into()));
    } else {
        coded.shards.iter().find(|s| !s.is_empty()).map(|s| s.len()).unwrap_or(0)
    };

    if shard_size == 0 {
        return Err(LatticeError::ErasureCodeError("All shards are empty".into()));
    }

    // Convert to Option<Vec<u8>> for reconstruction (None = missing)
    let mut shard_opts: Vec<Option<Vec<u8>>> = coded
        .shards
        .iter()
        .map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        })
        .collect();

    // Count missing shards and validate against parity budget
    let missing_count = shard_opts.iter().filter(|s| s.is_none()).count();
    if missing_count > parity_shards {
        return Err(LatticeError::ErasureCodeError(format!(
            "Too many missing shards: {} missing, max recoverable: {}",
            missing_count, parity_shards
        )));
    }

    // Reconstruct missing shards
    rs.reconstruct(&mut shard_opts)
        .map_err(|e| LatticeError::ErasureCodeError(format!("Reconstruction failed: {}", e)))?;

    // SECURITY: Validate original_size against actual shard data to prevent
    // malicious payloads from causing excessive memory allocation.
    let max_possible_size = (data_shards * shard_size) as u64;
    if coded.original_size > max_possible_size {
        return Err(LatticeError::ErasureCodeError(format!(
            "Claimed original_size {} exceeds maximum possible {} from {} shards of {} bytes",
            coded.original_size, max_possible_size, data_shards, shard_size
        )));
    }
    if coded.original_size > 100 * 1024 * 1024 {
        return Err(LatticeError::ErasureCodeError(
            "original_size exceeds 100MB safety limit".into()
        ));
    }

    // Concatenate data shards and trim to original size
    let mut result = Vec::with_capacity(coded.original_size as usize);
    for shard in shard_opts.iter().take(data_shards) {
        if let Some(s) = shard {
            result.extend_from_slice(s);
        } else {
            return Err(LatticeError::ErasureCodeError("Failed to reconstruct shard".into()));
        }
    }

    result.truncate(coded.original_size as usize);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_roundtrip_no_loss() {
        let data = b"Hello, Desktop Swarm! This is a test of erasure coding for media sharding.";
        let coded = erasure_encode_impl(data, 4, 2).unwrap();

        assert_eq!(coded.shards.len(), 6); // 4 data + 2 parity
        assert_eq!(coded.original_size, data.len() as u64);

        let recovered = erasure_decode_impl(&coded, 4, 2).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_erasure_recover_with_missing_shards() {
        let data = b"Sensitive encrypted media content that needs fault tolerance";
        let mut coded = erasure_encode_impl(data, 4, 2).unwrap();

        // Simulate 2 lost shards (max recoverable with 2 parity)
        coded.shards[1] = vec![];
        coded.shards[3] = vec![];

        let recovered = erasure_decode_impl(&coded, 4, 2).unwrap();
        assert_eq!(recovered, data);
    }
}
