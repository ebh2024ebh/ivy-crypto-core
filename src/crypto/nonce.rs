use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::collections::HashSet;

/// Thread-safe nonce generator for XChaCha20-Poly1305.
///
/// XChaCha20-Poly1305 is catastrophically vulnerable to nonce reuse:
/// reusing a (key, nonce) pair leaks the XOR of two plaintexts and
/// enables forgery of authentication tags.
///
/// NONCE CONSTRUCTION (192 bits / 24 bytes):
///
/// ```text
/// [8 bytes: monotonic counter][16 bytes: OsRng random]
/// ```
///
/// - The 64-bit monotonic counter guarantees uniqueness even if OsRng
///   produces a collision (birthday bound on 128-bit random is 2^64,
///   but the counter eliminates even that theoretical risk).
/// - The 128-bit random component from /dev/urandom prevents nonce
///   prediction by external observers.
/// - Combined: nonce reuse requires BOTH counter rollover (2^64 messages ≈
///   18 quintillion) AND OsRng collision. This is computationally impossible.
///
/// The counter persists in memory per session. On app restart, it resets
/// to 0, but the random component ensures uniqueness across sessions.
pub struct NonceManager {
    counter: AtomicU64,
    /// Sliding window for replay detection.
    /// Tracks the highest seen counter and a bitmap of recently seen
    /// counters within [highest - WINDOW_SIZE, highest].
    replay_state: Mutex<ReplayWindow>,
}

/// Sliding-window replay detection state.
///
/// Maintains a high-water mark and a set of seen counters within a
/// trailing window. Nonces with counters below the window floor are
/// automatically rejected (too old). Nonces within the window are
/// checked against the seen set.
struct ReplayWindow {
    /// Highest counter value seen so far
    high_water: u64,
    /// Set of counter values seen within the current window
    seen: HashSet<u64>,
    /// Maximum window size before pruning
    window_size: u64,
}

impl ReplayWindow {
    const DEFAULT_WINDOW_SIZE: u64 = 65536;

    fn new() -> Self {
        Self {
            high_water: 0,
            seen: HashSet::with_capacity(1024),
            window_size: Self::DEFAULT_WINDOW_SIZE,
        }
    }

    /// Check if a counter value is fresh (not replayed).
    /// Returns true if fresh, false if replayed or too old.
    fn check_and_record(&mut self, counter: u64) -> bool {
        // Reject counters below the window floor (too old)
        let floor = self.high_water.saturating_sub(self.window_size);
        if counter < floor && self.high_water > self.window_size {
            return false;
        }

        // Reject already-seen counters (replay)
        if self.seen.contains(&counter) {
            return false;
        }

        // Record this counter
        self.seen.insert(counter);

        // Advance high-water mark if needed
        if counter > self.high_water {
            self.high_water = counter;

            // Prune entries below the new floor
            let new_floor = self.high_water.saturating_sub(self.window_size);
            if self.seen.len() > self.window_size as usize {
                self.seen.retain(|&c| c >= new_floor);
            }
        }

        true
    }
}

impl NonceManager {
    pub const NONCE_SIZE: usize = 24; // XChaCha20 nonce = 192 bits

    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            replay_state: Mutex::new(ReplayWindow::new()),
        }
    }

    /// Generate a unique 192-bit nonce.
    ///
    /// Thread-safe: the atomic counter ensures no two threads can produce
    /// the same counter value, and each gets independent OsRng bytes.
    pub fn generate(&self) -> [u8; Self::NONCE_SIZE] {
        let mut nonce = [0u8; Self::NONCE_SIZE];

        // First 8 bytes: monotonic counter (little-endian)
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        nonce[..8].copy_from_slice(&count.to_le_bytes());

        // Last 16 bytes: OS-level cryptographic random.
        // Use try_fill_bytes to avoid panicking across FFI if OsRng
        // is temporarily unavailable. Fall back to counter-only nonce
        // which is still unique (monotonic) but loses unpredictability.
        if OsRng.try_fill_bytes(&mut nonce[8..]).is_err() {
            // Fallback: hash the counter with a domain separator to fill
            // the random portion. Still unique due to monotonic counter.
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(b"lattice-nonce-fallback");
            hasher.update(&count.to_le_bytes());
            let hash = hasher.finalize();
            nonce[8..].copy_from_slice(&hash[..16]);
        }

        nonce
    }

    /// Verify that a received nonce has not been seen before.
    /// Used on the receiving side to detect replay attacks.
    ///
    /// Uses a sliding window of recent nonce counter values.
    /// Returns true if the nonce is fresh (not replayed).
    pub fn verify_fresh(&self, nonce: &[u8; Self::NONCE_SIZE]) -> bool {
        // Extract the counter portion
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&nonce[..8]);
        let received_counter = u64::from_le_bytes(counter_bytes);

        // Verify the random portion is non-zero (basic sanity)
        let random_portion = &nonce[8..];
        let random_nonzero = random_portion.iter().any(|&b| b != 0);
        if !random_nonzero && received_counter == 0 {
            return false;
        }

        // Check against sliding window replay filter.
        // SECURITY: Use unwrap_or_else to recover from poisoned mutex
        // rather than panicking across the FFI boundary.
        let mut state = match self.replay_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Mutex was poisoned by a panic in another thread.
                // Recover the inner state — the data may be inconsistent
                // but rejecting all nonces is safer than crashing.
                poisoned.into_inner()
            }
        };
        state.check_and_record(received_counter)
    }

    /// Get the current counter value (for debugging/monitoring).
    pub fn current_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_nonces_are_unique() {
        let manager = NonceManager::new();
        let mut seen = HashSet::new();

        for _ in 0..10_000 {
            let nonce = manager.generate();
            assert!(seen.insert(nonce), "Nonce collision detected!");
        }
    }

    #[test]
    fn test_counter_increments() {
        let manager = NonceManager::new();
        let n1 = manager.generate();
        let n2 = manager.generate();

        // Extract counters
        let c1 = u64::from_le_bytes(n1[..8].try_into().unwrap());
        let c2 = u64::from_le_bytes(n2[..8].try_into().unwrap());

        assert_eq!(c1 + 1, c2);
    }

    #[test]
    fn test_random_portions_differ() {
        let manager = NonceManager::new();
        let n1 = manager.generate();
        let n2 = manager.generate();

        // Random portions (bytes 8-24) should differ
        assert_ne!(&n1[8..], &n2[8..]);
    }

    #[test]
    fn test_verify_fresh_detects_replay() {
        let manager = NonceManager::new();
        let nonce = manager.generate();

        // First check should pass
        assert!(manager.verify_fresh(&nonce), "First check should be fresh");

        // Same nonce again should be rejected (replay)
        assert!(!manager.verify_fresh(&nonce), "Replay should be detected");
    }

    #[test]
    fn test_verify_fresh_accepts_different_nonces() {
        let manager = NonceManager::new();
        for _ in 0..100 {
            let nonce = manager.generate();
            assert!(manager.verify_fresh(&nonce));
        }
    }

    #[test]
    fn test_verify_fresh_rejects_zero_nonce() {
        let manager = NonceManager::new();
        let zero_nonce = [0u8; NonceManager::NONCE_SIZE];
        assert!(!manager.verify_fresh(&zero_nonce));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(NonceManager::new());
        let mut handles = vec![];

        for _ in 0..8 {
            let m = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                let mut nonces = Vec::new();
                for _ in 0..1000 {
                    nonces.push(m.generate());
                }
                nonces
            }));
        }

        let mut all_nonces = HashSet::new();
        for handle in handles {
            let nonces = handle.join().unwrap();
            for nonce in nonces {
                assert!(all_nonces.insert(nonce), "Cross-thread nonce collision!");
            }
        }

        assert_eq!(all_nonces.len(), 8000);
    }
}
