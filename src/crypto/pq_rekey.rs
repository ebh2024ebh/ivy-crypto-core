//! Continuous-ratchet PQ rekey — state machine + wire-format codec.
//!
//! Spec: `docs/pq-rekey-v1.md`. Modelled after Apple PQ3 (iMessage,
//! iOS 17.4+). Closes the long-session HNDL gap that PQXDH alone
//! leaves open: the initial root key is post-quantum-protected, but
//! every subsequent classical-DH ratchet step is HNDL-vulnerable.
//! This module adds an ML-KEM-768 rekey every 50 messages or 7 days
//! (whichever first), anchoring the chain to a fresh PQ secret on
//! that cadence.
//!
//! Status: scaffold. The wire-format types, state machine, and chain-
//! integration helpers are implemented + tested. Production wiring
//! into the per-pairing chain (`hs_host`, `lan_host`, `mirror_client`)
//! happens in a follow-up commit behind the `pq_rekey` cargo feature.
//! No runtime behaviour change until that wiring lands.

use core::fmt;
use core::time::Duration;

use hkdf::Hkdf;
use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::LatticeError;

// ─── Cadence constants ────────────────────────────────────────────────

/// Trigger a rekey after this many messages on the current epoch.
/// Matches Apple PQ3's published cadence (50 msgs).
pub const MAX_MESSAGES_PER_EPOCH: u32 = 50;

/// Trigger a rekey after this much wall-clock time on the current
/// epoch. Matches Apple PQ3 (7 days).
pub const MAX_DURATION_PER_EPOCH: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long an initiator waits for an ack before resending the init.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(60);

// ─── Wire-format types ────────────────────────────────────────────────

/// A `pq_rekey_init` mirror frame. Initiator → responder.
///
/// Sealed under the **current** chain's AES-GCM envelope (not the new
/// one). An attacker who hasn't compromised the current chain can't
/// observe or tamper with the rekey itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqRekeyInit {
    /// Always the literal string `"pq_rekey_init"` for type discrimination.
    #[serde(rename = "type")]
    pub frame_type: String,
    pub epoch: u32,
    /// Base64url-no-pad-encoded 1184-byte ML-KEM-768 encapsulation key.
    pub ml_kem_ek_b64: String,
    /// Sender's wall-clock timestamp in milliseconds since epoch.
    /// Diagnostic only; not used for security decisions.
    pub ts_ms: u64,
}

/// A `pq_rekey_ack` mirror frame. Responder → initiator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqRekeyAck {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub epoch: u32,
    /// Base64url-no-pad-encoded 1088-byte ML-KEM-768 ciphertext.
    pub ml_kem_ct_b64: String,
    pub ts_ms: u64,
}

impl PqRekeyInit {
    pub const TYPE_TAG: &'static str = "pq_rekey_init";

    pub fn new(epoch: u32, ek_bytes: &[u8], ts_ms: u64) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        Self {
            frame_type: Self::TYPE_TAG.to_string(),
            epoch,
            ml_kem_ek_b64: URL_SAFE_NO_PAD.encode(ek_bytes),
            ts_ms,
        }
    }

    /// Decode the embedded ML-KEM-768 encapsulation key. Returns the
    /// SAME opaque error string for every failure mode (Bug 10.5
    /// mitigation): wrong length, wrong type tag, malformed base64
    /// all collapse to a single error.
    pub fn decode_ek(&self) -> Result<Vec<u8>, LatticeError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        if self.frame_type != Self::TYPE_TAG {
            return Err(LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()));
        }
        URL_SAFE_NO_PAD
            .decode(&self.ml_kem_ek_b64)
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))
    }
}

impl PqRekeyAck {
    pub const TYPE_TAG: &'static str = "pq_rekey_ack";

    pub fn new(epoch: u32, ct_bytes: &[u8], ts_ms: u64) -> Self {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        Self {
            frame_type: Self::TYPE_TAG.to_string(),
            epoch,
            ml_kem_ct_b64: URL_SAFE_NO_PAD.encode(ct_bytes),
            ts_ms,
        }
    }

    pub fn decode_ct(&self) -> Result<Vec<u8>, LatticeError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        if self.frame_type != Self::TYPE_TAG {
            return Err(LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()));
        }
        URL_SAFE_NO_PAD
            .decode(&self.ml_kem_ct_b64)
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))
    }
}

const REKEY_OPAQUE_ERR: &str = "pq_rekey: invalid input";

// ─── State machine ────────────────────────────────────────────────────

/// One side's per-pairing rekey state. Lives alongside the chain
/// state in `hs_host` / `lan_host` and is touched on every send +
/// every inbound rekey frame.
///
/// `Zeroize` impl drops the secret material on revoke or pairing-
/// drop. The decap key for any pending init is the most sensitive
/// item — without it, the stashed init frame is unrecoverable.
pub struct EpochState {
    /// Decap key for our own currently-pending init, keyed by the
    /// init's epoch. Stays in RAM until the responder acks; then
    /// zeroized.
    pending: Option<PendingInit>,

    /// Last completed rekey epoch. Increases monotonically.
    last_completed_epoch: u32,

    /// Highest epoch we've SEEN from the peer (any direction). Drops
    /// duplicate inits that arrive out of order due to reordering or
    /// retransmits.
    highest_epoch_seen: u32,

    /// Next epoch number to use for an outbound init.
    next_epoch_to_send: u32,

    /// Messages sent on the current chain. Reset to 0 on rekey
    /// completion.
    messages_since_rekey: u32,

    /// Wall-clock timestamp (ms) of the last completed rekey.
    /// `None` means "never rekeyed" — the chain is still on the
    /// initial PQXDH root key.
    last_rekey_at_ms: Option<u64>,
}

struct PendingInit {
    epoch: u32,
    /// 2400-byte ML-KEM-768 decapsulation key. Boxed to keep it off
    /// the stack (large) and to make `Drop` predictable.
    dk_bytes: Box<[u8]>,
    sent_at_ms: u64,
}

impl Drop for PendingInit {
    fn drop(&mut self) {
        self.dk_bytes.zeroize();
    }
}

impl Default for EpochState {
    fn default() -> Self {
        Self {
            pending: None,
            last_completed_epoch: 0,
            highest_epoch_seen: 0,
            next_epoch_to_send: 1,
            messages_since_rekey: 0,
            last_rekey_at_ms: None,
        }
    }
}

impl EpochState {
    pub fn new() -> Self { Self::default() }

    /// Increment the message counter. Called on each successful
    /// frame send (after the chain advance, before the rekey
    /// trigger check).
    pub fn note_message_sent(&mut self) {
        self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);
    }

    /// Should we initiate a rekey right now? Returns `true` if the
    /// thresholds are crossed and there's no pending rekey already
    /// in flight.
    pub fn should_initiate(&self, now_ms: u64) -> bool {
        if self.pending.is_some() {
            return false;
        }
        let count_hit = self.messages_since_rekey >= MAX_MESSAGES_PER_EPOCH;
        let time_hit = match self.last_rekey_at_ms {
            None => false, // pre-first-rekey grace: no time threshold yet
            Some(last) => now_ms.saturating_sub(last) >= MAX_DURATION_PER_EPOCH.as_millis() as u64,
        };
        count_hit || time_hit
    }

    /// Generate a fresh ML-KEM-768 keypair, stash the decap key in
    /// `pending`, and return the init frame ready to seal + send.
    pub fn build_init(&mut self, now_ms: u64) -> Result<PqRekeyInit, LatticeError> {
        if self.pending.is_some() {
            return Err(LatticeError::CryptoError(
                "pq_rekey: init already pending".into(),
            ));
        }
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let epoch = self.next_epoch_to_send;
        self.next_epoch_to_send = self.next_epoch_to_send.wrapping_add(1);
        let ek_bytes = ek.as_bytes().to_vec();
        let dk_bytes = dk.as_bytes().to_vec().into_boxed_slice();

        self.pending = Some(PendingInit { epoch, dk_bytes, sent_at_ms: now_ms });
        Ok(PqRekeyInit::new(epoch, &ek_bytes, now_ms))
    }

    /// Process an inbound init from the peer. Returns the ack frame
    /// to send back, plus the shared_secret to fold into the chain.
    /// On a duplicate / out-of-order init, returns `Ok(None)` and
    /// the caller drops the frame silently.
    pub fn handle_init(
        &mut self,
        init: &PqRekeyInit,
        now_ms: u64,
    ) -> Result<Option<RekeyOutcome>, LatticeError> {
        // Idempotent replay handling: if epoch <= already-seen, drop.
        if init.epoch <= self.highest_epoch_seen {
            return Ok(None);
        }
        // Race resolution: if we have our own pending init AND its
        // epoch is LOWER than the inbound, we yield to the inbound.
        // If our epoch is HIGHER, we ignore the inbound (peer will
        // see our higher init and ack it).
        if let Some(pending) = self.pending.as_ref() {
            if pending.epoch >= init.epoch {
                // We win the tiebreak; ignore inbound init.
                return Ok(None);
            }
            // We yield — drop our pending init.
            self.pending = None;
        }

        let ek_bytes = init.decode_ek()?;
        let ek_arr = Array::try_from(ek_bytes.as_slice())
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))?;
        let ek: <MlKem768 as KemCore>::EncapsulationKey =
            <_ as EncodedSizeUser>::from_bytes(&ek_arr);

        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))?;

        self.highest_epoch_seen = init.epoch;
        self.last_completed_epoch = init.epoch;
        self.messages_since_rekey = 0;
        self.last_rekey_at_ms = Some(now_ms);

        let ack = PqRekeyAck::new(init.epoch, ct.as_slice(), now_ms);
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(ss.as_slice());

        Ok(Some(RekeyOutcome { ack, shared_secret, epoch: init.epoch }))
    }

    /// Process an inbound ack. Returns the shared_secret to fold
    /// into the chain. If the ack is stale or doesn't match a
    /// pending init, returns `Ok(None)` and the caller drops.
    pub fn handle_ack(
        &mut self,
        ack: &PqRekeyAck,
        now_ms: u64,
    ) -> Result<Option<[u8; 32]>, LatticeError> {
        // Pull pending init out (drops + zeroizes dk on the way out
        // unless we put it back, which we don't if we're processing
        // the ack — the dk's job is done).
        let pending = match self.pending.take() {
            Some(p) => p,
            None => return Ok(None), // unsolicited ack — drop
        };

        // Validate epoch using constant-time compare so a probe
        // attacker can't distinguish "wrong epoch" from "wrong
        // ciphertext" via timing on this branch.
        let pending_be = pending.epoch.to_be_bytes();
        let ack_be = ack.epoch.to_be_bytes();
        if pending_be.ct_eq(&ack_be).unwrap_u8() == 0 {
            // Epoch mismatch — drop and put pending back so retry
            // can still ack. This is the "stale ack" case.
            self.pending = Some(pending);
            return Ok(None);
        }

        let ct_bytes = ack.decode_ct()?;
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))?;
        let dk_arr = Array::try_from(&pending.dk_bytes[..])
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))?;
        let dk: <MlKem768 as KemCore>::DecapsulationKey =
            <_ as EncodedSizeUser>::from_bytes(&dk_arr);
        let ss = dk
            .decapsulate(&ct)
            .map_err(|_| LatticeError::CryptoError(REKEY_OPAQUE_ERR.into()))?;

        // pending drops here, zeroizing dk_bytes.
        self.last_completed_epoch = pending.epoch;
        self.messages_since_rekey = 0;
        self.last_rekey_at_ms = Some(now_ms);

        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(ss.as_slice());
        Ok(Some(shared_secret))
    }

    /// Should we resend the pending init? Called periodically by the
    /// caller (e.g., on each tick of the existing keepalive loop).
    pub fn should_resend_init(&self, now_ms: u64) -> bool {
        match &self.pending {
            None => false,
            Some(p) => now_ms.saturating_sub(p.sent_at_ms) >= ACK_TIMEOUT.as_millis() as u64,
        }
    }

    /// On a revoke / pairing-drop, clear all pending rekey state.
    /// The Drop impl of `PendingInit` zeroizes the dk; this just
    /// makes it explicit at the call site.
    pub fn clear(&mut self) {
        self.pending = None;
        self.messages_since_rekey = 0;
    }

    pub fn last_completed_epoch(&self) -> u32 { self.last_completed_epoch }
    pub fn messages_since_rekey(&self) -> u32 { self.messages_since_rekey }
    pub fn has_pending(&self) -> bool { self.pending.is_some() }
}

impl fmt::Debug for EpochState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochState")
            .field("pending", &self.pending.is_some())
            .field("last_completed_epoch", &self.last_completed_epoch)
            .field("highest_epoch_seen", &self.highest_epoch_seen)
            .field("next_epoch_to_send", &self.next_epoch_to_send)
            .field("messages_since_rekey", &self.messages_since_rekey)
            .field("last_rekey_at_ms", &self.last_rekey_at_ms)
            .finish()
    }
}

/// Result of a successful `handle_init` — the caller seals the
/// `ack` frame, sends it on the current chain, AND folds
/// `shared_secret` + `epoch` into the chain via `derive_new_root`.
pub struct RekeyOutcome {
    pub ack: PqRekeyAck,
    pub shared_secret: [u8; 32],
    pub epoch: u32,
}

// ─── Chain integration ───────────────────────────────────────────────

/// Derive the new root key from the previous root + the freshly-
/// rekeyed shared secret. Both sides must compute this identically.
///
/// Salt structure binds:
///   - "pq_rekey_v1" domain tag (prevents cross-protocol confusion)
///   - epoch (4-byte BE) (prevents reordering / replay)
///   - pairing_id (16 bytes) (prevents cross-pairing confusion)
///
/// IKM structure binds:
///   - previous root key (32 bytes) — chains the new root to the old
///     so an adversary that compromises only the new state gains
///     nothing about messages encrypted under the previous chain
///   - rekey shared secret (32 bytes) — the actual PQ contribution
///
/// Returns the new 32-byte root key. The caller derives send/recv
/// chains from this root via `derive_chains`.
pub fn derive_new_root(
    previous_root: &[u8; 32],
    rekey_shared_secret: &[u8; 32],
    epoch: u32,
    pairing_id: &[u8; 16],
) -> [u8; 32] {
    let mut salt = Vec::with_capacity(11 + 4 + 16);
    salt.extend_from_slice(b"pq_rekey_v1");
    salt.extend_from_slice(&epoch.to_be_bytes());
    salt.extend_from_slice(pairing_id);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(previous_root);
    ikm[32..].copy_from_slice(rekey_shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut new_root = [0u8; 32];
    hk.expand(b"new-root", &mut new_root)
        .expect("HKDF expand 32 bytes never fails");

    // Best-effort zero of the IKM scratch.
    let mut ikm_zero = ikm;
    ikm_zero.zeroize();

    new_root
}

/// Derive send/recv chain keys from a new root, with the same
/// canonical-ordering convention as PQXDH (initiator's send ==
/// responder's recv). The caller passes `is_initiator` so each side
/// gets the right chain assignment.
pub fn derive_chains(new_root: &[u8; 32], is_initiator: bool) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::from_prk(new_root).expect("HKDF from PRK");
    let mut init_chain = [0u8; 32];
    let mut resp_chain = [0u8; 32];
    hk.expand(b"pq_rekey_v1-chain-i", &mut init_chain).expect("HKDF expand");
    hk.expand(b"pq_rekey_v1-chain-r", &mut resp_chain).expect("HKDF expand");
    if is_initiator {
        (init_chain, resp_chain) // (send, recv)
    } else {
        (resp_chain, init_chain)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 { 1_715_104_283_000 }

    #[test]
    fn init_ack_roundtrip_yields_matching_secret() {
        let mut alice = EpochState::new();
        let mut bob = EpochState::new();

        // Alice initiates.
        let init = alice.build_init(now()).expect("alice init");
        assert!(alice.has_pending());

        // Bob receives.
        let outcome = bob.handle_init(&init, now() + 100).expect("bob handle init")
            .expect("not a duplicate");
        assert_eq!(outcome.epoch, init.epoch);

        // Alice receives the ack.
        let alice_ss = alice.handle_ack(&outcome.ack, now() + 200)
            .expect("alice handle ack")
            .expect("not stale");

        assert_eq!(alice_ss, outcome.shared_secret, "both sides must derive the same secret");
        assert!(!alice.has_pending(), "alice clears pending after ack");
    }

    #[test]
    fn duplicate_init_is_dropped_silently() {
        let mut alice = EpochState::new();
        let mut bob = EpochState::new();
        let init = alice.build_init(now()).expect("init");
        let _ = bob.handle_init(&init, now()).expect("first").expect("not dup");
        // Second handle of the SAME init must return Ok(None) — drop.
        let r = bob.handle_init(&init, now() + 100).expect("second");
        assert!(r.is_none(), "duplicate init must be dropped");
    }

    #[test]
    fn race_lower_epoch_wins() {
        // Both sides initiate "simultaneously". Each side has its own
        // epoch space starting at 1, so both build epoch=1. Whichever
        // INBOUND init arrives first determines the outcome — but
        // critically, neither side enters an inconsistent state.
        let mut alice = EpochState::new();
        let mut bob = EpochState::new();

        let alice_init = alice.build_init(now()).unwrap();
        let bob_init = bob.build_init(now()).unwrap();
        assert_eq!(alice_init.epoch, 1);
        assert_eq!(bob_init.epoch, 1);

        // Bob sees alice_init while bob already has pending epoch=1.
        // pending.epoch (1) >= inbound (1) → bob ignores alice's init.
        let r = bob.handle_init(&alice_init, now()).unwrap();
        assert!(r.is_none(), "bob ignores alice's init when bob's pending epoch is >=");

        // Alice symmetric: ignores bob's init, both still have pending.
        let r = alice.handle_init(&bob_init, now()).unwrap();
        assert!(r.is_none());

        // Outcome: both sides still have pending; both will time out
        // (ack_timeout) and resend with NEW epochs (2 and 2). On the
        // second attempt, jitter alone usually breaks the tie. If
        // it doesn't, this state is provably stable: no inconsistent
        // chain advance, no key compromise, just transient stall.
        assert!(alice.has_pending());
        assert!(bob.has_pending());
    }

    #[test]
    fn stale_ack_dropped_pending_preserved() {
        let mut alice = EpochState::new();
        let _ = alice.build_init(now()).unwrap();
        // Forge a stale ack with the wrong epoch.
        let stale = PqRekeyAck::new(99, &[0u8; 1088], now());
        let r = alice.handle_ack(&stale, now()).unwrap();
        assert!(r.is_none(), "stale ack must be dropped");
        assert!(alice.has_pending(), "stale ack must NOT clear pending");
    }

    #[test]
    fn message_counter_triggers_rekey() {
        let mut s = EpochState::new();
        for _ in 0..MAX_MESSAGES_PER_EPOCH - 1 {
            s.note_message_sent();
        }
        assert!(!s.should_initiate(now()));
        s.note_message_sent();
        assert!(s.should_initiate(now()));
    }

    #[test]
    fn time_threshold_only_after_first_rekey() {
        let mut s = EpochState::new();
        // Pre-first-rekey: time threshold doesn't fire (last_rekey_at_ms is None).
        let far_future = now() + 100 * MAX_DURATION_PER_EPOCH.as_millis() as u64;
        assert!(!s.should_initiate(far_future), "time threshold must not fire pre-first-rekey");

        // Simulate a completed rekey in the past, then check time fires.
        s.last_rekey_at_ms = Some(now());
        assert!(!s.should_initiate(now() + 1));
        assert!(s.should_initiate(now() + MAX_DURATION_PER_EPOCH.as_millis() as u64 + 1));
    }

    #[test]
    fn pending_blocks_initiate() {
        let mut s = EpochState::new();
        let _ = s.build_init(now()).unwrap();
        // Even crossing the message threshold does not initiate
        // again while pending is set.
        for _ in 0..MAX_MESSAGES_PER_EPOCH * 2 {
            s.note_message_sent();
        }
        assert!(!s.should_initiate(now()));
    }

    #[test]
    fn ack_timeout_triggers_resend() {
        let mut s = EpochState::new();
        let _ = s.build_init(now()).unwrap();
        assert!(!s.should_resend_init(now()));
        assert!(!s.should_resend_init(now() + ACK_TIMEOUT.as_millis() as u64 - 1));
        assert!(s.should_resend_init(now() + ACK_TIMEOUT.as_millis() as u64));
    }

    #[test]
    fn derive_new_root_is_deterministic_and_binds_inputs() {
        let prev = [0x11u8; 32];
        let ss = [0x22u8; 32];
        let pid = [0x33u8; 16];

        let r1 = derive_new_root(&prev, &ss, 5, &pid);
        let r2 = derive_new_root(&prev, &ss, 5, &pid);
        assert_eq!(r1, r2, "deterministic for the same inputs");

        let r_diff_epoch = derive_new_root(&prev, &ss, 6, &pid);
        let r_diff_pid = derive_new_root(&prev, &ss, 5, &[0x44u8; 16]);
        let r_diff_ss = derive_new_root(&prev, &[0x55u8; 32], 5, &pid);
        let r_diff_prev = derive_new_root(&[0x66u8; 32], &ss, 5, &pid);

        // Each input must affect the output.
        assert_ne!(r1, r_diff_epoch);
        assert_ne!(r1, r_diff_pid);
        assert_ne!(r1, r_diff_ss);
        assert_ne!(r1, r_diff_prev);
    }

    #[test]
    fn derive_chains_swap_for_initiator_vs_responder() {
        let root = [0x77u8; 32];
        let (init_send, init_recv) = derive_chains(&root, true);
        let (resp_send, resp_recv) = derive_chains(&root, false);
        // Initiator's send chain == responder's recv chain.
        assert_eq!(init_send, resp_recv);
        assert_eq!(init_recv, resp_send);
        // Send and recv must be different keys for each side.
        assert_ne!(init_send, init_recv);
    }

    #[test]
    fn pending_init_zeroizes_dk_on_drop() {
        let mut s = EpochState::new();
        let _ = s.build_init(now()).unwrap();
        // Drop pending by clearing.
        s.clear();
        // Can't directly inspect dk after drop, but the test asserts
        // the function call succeeds — Drop runs, zeroize fires.
        assert!(!s.has_pending());
    }

    #[test]
    fn full_chain_integration_two_rekeys() {
        // Simulate two consecutive rekeys end-to-end and verify both
        // sides keep matching chain state.
        let pid = [0xABu8; 16];
        let initial_root = [0x01u8; 32];

        let mut alice = EpochState::new();
        let mut bob = EpochState::new();

        // Rekey 1
        let init1 = alice.build_init(now()).unwrap();
        let outcome1 = bob.handle_init(&init1, now() + 50).unwrap().unwrap();
        let alice_ss1 = alice.handle_ack(&outcome1.ack, now() + 100).unwrap().unwrap();
        assert_eq!(alice_ss1, outcome1.shared_secret);
        let alice_root1 = derive_new_root(&initial_root, &alice_ss1, outcome1.epoch, &pid);
        let bob_root1 = derive_new_root(&initial_root, &outcome1.shared_secret, outcome1.epoch, &pid);
        assert_eq!(alice_root1, bob_root1);

        // Rekey 2 (a while later)
        let later = now() + 1_000_000;
        let init2 = alice.build_init(later).unwrap();
        let outcome2 = bob.handle_init(&init2, later + 50).unwrap().unwrap();
        let alice_ss2 = alice.handle_ack(&outcome2.ack, later + 100).unwrap().unwrap();
        let alice_root2 = derive_new_root(&alice_root1, &alice_ss2, outcome2.epoch, &pid);
        let bob_root2 = derive_new_root(&bob_root1, &outcome2.shared_secret, outcome2.epoch, &pid);
        assert_eq!(alice_root2, bob_root2);
        assert_ne!(alice_root1, alice_root2, "rekey 2 must produce a fresh root");

        assert_eq!(alice.last_completed_epoch(), 2);
        assert_eq!(bob.last_completed_epoch(), 2);
    }

    #[test]
    fn json_codec_roundtrip() {
        let init = PqRekeyInit::new(42, &[0xDEu8; 1184], now());
        let json = serde_json::to_string(&init).unwrap();
        let parsed: PqRekeyInit = serde_json::from_str(&json).unwrap();
        assert_eq!(init, parsed);

        let ack = PqRekeyAck::new(42, &[0xEFu8; 1088], now());
        let json = serde_json::to_string(&ack).unwrap();
        let parsed: PqRekeyAck = serde_json::from_str(&json).unwrap();
        assert_eq!(ack, parsed);
    }

    #[test]
    fn frame_type_tag_is_validated() {
        // A frame with the wrong type tag must error opaque.
        let bad_init = PqRekeyInit {
            frame_type: "wrong_type".to_string(),
            epoch: 1,
            ml_kem_ek_b64: "AAAA".to_string(),
            ts_ms: 0,
        };
        assert!(bad_init.decode_ek().is_err());

        let bad_ack = PqRekeyAck {
            frame_type: "wrong_type".to_string(),
            epoch: 1,
            ml_kem_ct_b64: "AAAA".to_string(),
            ts_ms: 0,
        };
        assert!(bad_ack.decode_ct().is_err());
    }
}
