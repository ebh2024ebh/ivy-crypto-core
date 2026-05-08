# Continuous-ratchet PQ rekey — protocol spec v1

**Status:** v1 draft, scaffold-only as of 2026-05-07. Wire format
frozen here; runtime integration is staged behind a feature flag.

**Modelled after:** Apple PQ3 (deployed in iMessage from iOS 17.4,
February 2024). Symbolic Software's post-quantum migration playbook
(Chapter 6.2.1, May 2026) cites PQ3 as the production reference for
continuous-ratchet PQ in 1:1 secure messaging.

## Problem

Today, Ivy's PQXDH protects only the **initial root key** for 1:1
sessions. The classical Double Ratchet that follows uses X25519 DH
exclusively. An adversary that records ciphertext today and obtains a
CRQC + the chain state at any future point can decrypt the entire
session past the initial handshake. This is the harshest HNDL model
the playbook flags for messaging, and the gap PQ3 was designed to
close.

## Design goals

1. **Forward secrecy against future quantum adversaries.** After a
   rekey completes, an adversary that compromises the new chain state
   gains nothing about messages encrypted under the previous chain.

2. **Minimal bandwidth overhead.** Per-message hybrid (every message
   carries an ML-KEM exchange) is rejected — too costly. PQ3's
   anchoring approach (every N messages) amortises the cost.

3. **Backward compatible.** Pre-rekey-aware peers must continue to
   work. Capability advertised in the existing pair handshake; rekey
   only engages when both sides support it.

4. **No new persistent state at the user level.** Pairing key, chain
   state, and rekey state all live in the same per-pairing record.

5. **Idempotent under message reordering / retransmits.** Rekey
   frames carry an explicit epoch; a duplicate rekey is a no-op.

## Cadence

The rekey threshold is the AND of the following:

- `MAX_MESSAGES_PER_EPOCH = 50`
- `MAX_DURATION_PER_EPOCH = 7 days` (604,800 seconds)

Either side may initiate when EITHER threshold is hit. If both sides
hit the threshold at the same time, the lower epoch number wins
(deterministic tiebreak, see "Race resolution" below).

## Wire format

Two new mirror frame types, both wrapped in the existing AES-GCM
envelope using the **current** chain (not the new one). This means
an attacker who hasn't compromised the current chain can't observe or
tamper with the rekey itself.

### Type `pq_rekey_init` (initiator → responder)

```json
{
  "type": "pq_rekey_init",
  "epoch": 1,
  "ml_kem_ek_b64": "<URL_SAFE_NO_PAD base64 of 1184-byte ML-KEM-768 encapsulation key>",
  "ts_ms": 1715104283000
}
```

- `epoch` is a monotonically increasing u32. Each side tracks the
  highest epoch it has seen and the highest it has sent.
- `ml_kem_ek_b64` is a fresh ML-KEM-768 encapsulation key generated
  for this rekey. The corresponding decap key stays in RAM until the
  responder's ack arrives, then is zeroized.
- `ts_ms` is the sender's wall-clock timestamp, used only for
  diagnostics (not for security decisions).

### Type `pq_rekey_ack` (responder → initiator)

```json
{
  "type": "pq_rekey_ack",
  "epoch": 1,
  "ml_kem_ct_b64": "<URL_SAFE_NO_PAD base64 of 1088-byte ML-KEM-768 ciphertext>",
  "ts_ms": 1715104285000
}
```

- `epoch` echoes the initiator's epoch.
- `ml_kem_ct_b64` is the encapsulation output the responder produced
  against the initiator's encapsulation key.

### Capability advertisement

Add to the pair handshake response blob (existing `desktop_pair`
flow):

```json
{
  "supports_pq_rekey": true
}
```

Both sides set their per-pairing `pq_rekey_negotiated` flag to true
**only if both advertise true**. If either side is on a pre-v1
build, the flag stays false and the rekey path is never engaged.

## Chain integration

When a rekey completes (init + ack exchanged), both sides compute:

```
shared_secret  = ML_KEM_DECAPS(dk, ct)        // both sides have this 32-byte value
new_root_key   = HKDF-Extract(
                   salt = "pq_rekey_v1" ‖ epoch_be ‖ pairing_id,
                   ikm  = current_root_key ‖ shared_secret,
                 )
new_send_chain = HKDF-Expand(new_root_key, "send-chain")
new_recv_chain = HKDF-Expand(new_root_key, "recv-chain")
```

- `epoch_be` is the rekey epoch as a 4-byte big-endian u32.
- `pairing_id` is the existing 16-byte pairing identifier.
- The KDF binds the epoch to prevent reordering attacks (an attacker
  who replays an old rekey gets a stale epoch in the binding, which
  doesn't match the chain state).
- `current_root_key` is the chain key just before the rekey took
  effect — chaining the new key to the previous one means an
  adversary who compromises the new state must ALSO have observed
  the previous state to recover anything.

## State machine

Per pairing, both sides track:

- `current_pq_keypair`: ML-KEM-768 (decap key, encap key) pair this
  side is currently the OWNER of, used when this side is the
  responder. Generated lazily on first rekey-init received.
- `pending_rekey_epoch: Option<u32>`: if Some, an init we sent is
  awaiting an ack. Cleared on ack receipt or revoke.
- `last_rekey_count: u32`: messages since the last successful rekey.
  Reset to 0 on rekey completion.
- `last_rekey_time_ms: u64`: wall clock of the last rekey. Updated
  on completion.
- `next_epoch_to_send: u32`: monotonically increasing counter for
  this side's outgoing inits.
- `highest_epoch_seen: u32`: monotonically increasing counter for
  the highest epoch we've successfully completed.

### Trigger

Either side checks on every outbound message:

```
if (last_rekey_count >= MAX_MESSAGES_PER_EPOCH OR
    now - last_rekey_time_ms >= MAX_DURATION_PER_EPOCH_MS) AND
   pending_rekey_epoch.is_none() AND
   pq_rekey_negotiated:
       initiate_rekey()
```

### Initiate (sender side)

1. Generate fresh ML-KEM-768 keypair → `(dk, ek)`.
2. Stash `dk` in memory keyed by `next_epoch_to_send`.
3. Build `pq_rekey_init` frame with `ek` and `next_epoch_to_send`.
4. Set `pending_rekey_epoch = Some(next_epoch_to_send)`.
5. Increment `next_epoch_to_send`.
6. Send the frame on the current chain.
7. Continue normal messaging — the rekey doesn't pause the chain.

### Receive init (responder side)

1. Validate the epoch:
   - If `epoch <= highest_epoch_seen`, treat as duplicate — emit a
     log line, do not re-ack, do not advance state. (Idempotent
     replay handling.)
   - If `epoch > next_epoch_to_send` and we have our own pending
     init, this is a race; defer and let the lower-numbered side win
     (see "Race resolution").
2. Decode the encapsulation key.
3. Encapsulate against it → `(ct, shared_secret)`.
4. Send `pq_rekey_ack` on the current chain.
5. Compute the new root + chains using `shared_secret` and the
   formula above.
6. Atomically:
   - Replace `current_root_key`, `send_chain`, `recv_chain`.
   - Reset `last_rekey_count = 0`.
   - Update `last_rekey_time_ms`.
   - Update `highest_epoch_seen = epoch`.
   - Zeroize the previous root key.
7. Continue normal messaging on the new chain.

### Receive ack (initiator side)

1. Validate the epoch:
   - If `epoch != pending_rekey_epoch`, ignore (stale or unsolicited
     ack — log and drop).
2. Look up the stashed `dk` for this epoch.
3. Decapsulate → `shared_secret`.
4. Compute the new root + chains.
5. Atomically:
   - Same swap as the responder side.
   - Zeroize the stashed `dk` and the previous root key.
   - Set `pending_rekey_epoch = None`.

### Race resolution

If both sides initiate within the same RTT:

- Each side has sent its own init with epoch `e_self`.
- Each side receives the other's init with epoch `e_other`.
- The side with `e_self > e_other` aborts its own init (zeroize
  stashed `dk`, clear `pending_rekey_epoch`) and acks the other.
- The side with `e_self < e_other` ignores the inbound init and
  waits for its own ack (the peer will ack it).
- Tie (e_self == e_other) is impossible because each side allocates
  its own epoch space — but if it ever happens, break by comparing
  pairing-side bytes (the `0`-side of the encap key sequence vs the
  `1`-side, deterministic via lexicographic ordering of the X25519
  public keys established at pair-time).

### Offline peer

If the peer is offline when we trigger a rekey, the init frame is
queued in the existing mirror queue. When the peer reconnects, the
frame is delivered and the rekey completes normally. The delay does
not block normal messaging — messages continue to send under the
current chain.

## Forward-secrecy invariant

After a rekey completes, both sides MUST `zeroize`:

- The previous `root_key`.
- The previous `send_chain`.
- The previous `recv_chain`.
- The decap key from the initiator side (after the ack succeeds).
- The encap key from the responder side (it's public; doesn't matter
  but no reason to keep it).

This is enforced via the `Drop` impl on the rekey state struct (see
`pq_rekey.rs::EpochState::drop`).

## Failure modes

| Failure | Detection | Response |
|---|---|---|
| Init frame lost | No ack within 2 × current backoff | Resend with same epoch (idempotent on responder side) |
| Ack frame lost | Initiator times out waiting for ack | Resend init with same epoch |
| Decap fails on responder | ML-KEM returns implicit-rejection secret deterministically | Both sides derive a different root → first message under new chain fails to decrypt → responder requests retry → eventually surfaces as "rekey failed, please reconnect" UI |
| Peer doesn't support v1 | `pq_rekey_negotiated` is false at pair-time | Rekey path never engages; classical ratchet only. UI may surface "post-quantum forward secrecy not available — peer is on an older version" |
| Peer revoked mid-rekey | Existing revoke path triggers; pending rekey state is dropped | Rekey state cleared as part of the existing revoke handler |

## Telemetry (must ship for v1 rollout)

Emit counters (no message content):

- `pq_rekey_initiated_total{transport=...}`
- `pq_rekey_completed_total{transport=...}`
- `pq_rekey_failed_total{transport=..., reason=...}` where reason
  is one of: `ack_timeout`, `epoch_mismatch`, `decap_panic`,
  `chain_desync`, `peer_unsupported`.
- `pq_rekey_latency_ms` histogram.

Without telemetry, we can't tell from a production rollout whether
rekey is succeeding silently or failing silently.

## Acceptance criteria

A rollout is considered green when, on a 7-day soak with 100 paired
devices:

- `pq_rekey_completed_total / pq_rekey_initiated_total > 99.9%`.
- p99 `pq_rekey_latency_ms` < 1000 across LAN; < 10000 across Tor.
- Zero `chain_desync` events.
- Conformance test battery (`crypto::conformance`) passes on every
  commit that touches the rekey code.
- ctgrind clean run on Linux CI.

## Out of scope for v1

- **Group messaging.** Ivy doesn't have group text yet. When it
  does, build on RFC 9420 MLS, not on a custom rekey.
- **Pair-HS mirror channel rekey.** Lower threat model (desktop is
  local). Defer to v2.
- **Per-message hybrid.** Bandwidth cost is too high; PQ3-style
  anchoring is the proven middle ground.
- **Multi-device sync.** Ivy has one device per identity in v1.
