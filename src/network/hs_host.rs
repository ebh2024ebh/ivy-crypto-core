//! Tor hidden-service hosting for the Desktop Companion mirror channel.
//!
//! Each paired desktop gets a **dedicated** v3 onion service hosted locally
//! by the phone. The onion's long-term identity key is derived
//! deterministically from the per-pairing symmetric key so:
//!
//!   * the onion hostname is **stable** across app restarts (desktop doesn't
//!     need to re-pair every time the phone reboots);
//!   * the hostname is a **direct cryptographic function** of the shared
//!     pairing secret, so no extra "onion-address" field needs to travel in
//!     the pairing blob (v0.2 simplification — for v0.1 the phone still
//!     echoes it back so desktop can double-check);
//!   * zero server has ever seen the onion — even 199/185.
//!
//! Key derivation:
//!   hs_seed_32 = HKDF-SHA256(pairing_key, info="lattice-desktop-hs-id-v1", 32)
//!   expanded = ed25519::ExpandedKeypair::from_secret_key_bytes(
//!                BLAKE3(hs_seed_32) 64 bytes  // deterministic expansion)
//!   hsid = HsIdKeypair::from(expanded)
//!
//! We could equivalently `SigningKey::from_bytes(hs_seed_32)` and expand, but
//! the BLAKE3 expansion makes the secret 64 B which matches
//! `from_secret_key_bytes`'s input contract.
//!
//! Framing protocol on the accepted stream:
//!   * Desktop sends: 1 byte `0x69` (hello)
//!   * Phone replies with: a stream of [len: u32 BE][frame] envelopes.
//!     Each frame is `envelope::seal(message_key_i, pairing_id, epoch, plaintext)`.
//!   * The plaintext is a JSON message from `mirror_protocol::Message`.
//!
//! For v0.1 the phone only sends ONE frame — the inbox snapshot — then
//! keeps the stream open but idle. Real-time push comes in v0.2 via the
//! `inbound_tx` mpsc passed through `HsHostHandle`.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::task::JoinHandle;
use tor_hsservice::{config::OnionServiceConfigBuilder, RendRequest, HsNickname};
use tor_hscrypto::pk::{HsId, HsIdKey, HsIdKeypair};

use crate::LatticeError;

/// Deterministic HS identity derivation — same pairing_key always yields
/// the same .onion hostname.
fn derive_hs_keypair(pairing_key: &[u8; 32]) -> HsIdKeypair {
    let hk = Hkdf::<Sha256>::from_prk(pairing_key).expect("hkdf from_prk");
    let mut seed = [0u8; 32];
    hk.expand(b"lattice-desktop-hs-id-v1", &mut seed).expect("hkdf expand");

    // Expand the 32-byte seed to 64 B via SHA-512 with a domain tag, then
    // clamp per RFC 8032 §5.1.5. `ExpandedKeypair::from_secret_key_bytes`
    // requires the input to already satisfy the clamp; doing it here
    // keeps the Tor crate happy.
    let exp_kp = tor_llcrypto::pk::ed25519::ExpandedKeypair::from_secret_key_bytes(make_64b(&seed))
        .expect("ed25519 expanded keypair derivation");
    HsIdKeypair::from(exp_kp)
}

/// Deterministic 64 B expansion of a 32 B seed. Uses SHA-512 with a domain
/// separation tag so the same seed in different Ivy subsystems never
/// produces the same key material.
fn make_64b(seed: &[u8; 32]) -> [u8; 64] {
    use sha2::Digest;
    let mut h = sha2::Sha512::new();
    h.update(b"lattice-ed25519-expand-v1");
    h.update(seed);
    let out = h.finalize();
    let mut a = [0u8; 64];
    a.copy_from_slice(&out);
    // RFC 8032 §5.1.5 clamping.
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    a
}

/// Opaque handle returned to Kotlin. Dropping it does NOT stop the HS —
/// callers must call `stop()` explicitly (or `hs_host_stop(pairing_id)`
/// over FFI) to tear down cleanly.
pub struct HsHostHandle {
    pub onion_hostname: String,
    shutdown:           Arc<AtomicBool>,
    task:               Option<JoinHandle<()>>,
    /// Broadcast channel for pushing new plaintext frames to every
    /// currently-connected serve_rend task. Kotlin calls
    /// `desktop_hs_push(pairing_id, plaintext)` which hits this channel
    /// via the global handle map; each live task seals + ships the
    /// frame on its own P2D chain.
    push_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Inbound-frame fan-out. Every successfully decrypted desktop→phone
    /// plaintext is broadcast here; Kotlin subscribes via the
    /// `desktop_hs_poll_inbound` FFI and dispatches by JSON type.
    pub inbound_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

impl HsHostHandle {
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }

    /// Push a plaintext frame to every currently-connected desktop for
    /// this pairing. Returns the number of receivers that got the frame.
    /// A return value of 0 means no desktop is currently connected.
    pub fn push_frame(&self, plaintext: Vec<u8>) -> usize {
        self.push_tx.send(plaintext).unwrap_or(0)
    }
}

/// Start a dedicated onion service for a paired desktop + spawn the accept
/// loop. The returned handle holds the onion hostname (e.g.
/// `xyz....onion`) which gets written into the pairing blob's phone_onion
/// field.
///
/// `snapshot_json` is the v0.1 canned inbox snapshot sent once per
/// connected desktop. In v0.2 this becomes a channel-fed stream.
pub async fn hs_start(
    tor: &crate::network::tor_client::LatticeTorClient,
    pairing_id: [u8; 16],
    pairing_key: [u8; 32],
    snapshot_json: String,
) -> Result<HsHostHandle, LatticeError> {
    let hsid_keypair = derive_hs_keypair(&pairing_key);
    let hsid: HsId = HsIdKey::from(&hsid_keypair).id();
    let onion = HsNickname::new(hex_short(&pairing_id))
        .map_err(|e| LatticeError::NetworkError(format!("hs nickname: {e}")))?;
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(onion)
        .build()
        .map_err(|e| LatticeError::NetworkError(format!("hs config: {e}")))?;

    let client = tor.inner_client_clone();
    let (service, mut rend_requests) = client
        .launch_onion_service_with_hsid(hs_config, hsid_keypair)
        .map_err(|e| LatticeError::NetworkError(format!("hs launch: {e}")))?;

    let onion_hostname = hsid.to_string();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_task = Arc::clone(&shutdown);
    let snapshot_bytes = snapshot_json.into_bytes();
    let (push_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(64);
    let push_tx_task = push_tx.clone();
    let (inbound_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(64);
    let inbound_tx_task = inbound_tx.clone();

    let task = tokio::spawn(async move {
        let _service = service; // keep alive for lifetime of task
        while !shutdown_task.load(Ordering::SeqCst) {
            let Some(rend_req) = rend_requests.next().await else {
                tracing::info!("hs_host: rend-request stream ended, task exiting");
                return;
            };
            let shutdown_inner = Arc::clone(&shutdown_task);
            let snap = snapshot_bytes.clone();
            let pid = pairing_id;
            let pk = pairing_key;
            let push_rx = push_tx_task.subscribe();
            let inbound_tx_for_task = inbound_tx_task.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_rend(
                    rend_req, pid, pk, snap, shutdown_inner, push_rx, inbound_tx_for_task,
                ).await {
                    tracing::warn!("hs_host: serve_rend error: {e}");
                }
            });
        }
    });

    Ok(HsHostHandle {
        onion_hostname,
        shutdown,
        task: Some(task),
        push_tx,
        inbound_tx,
    })
}

/// Serve a single RendRequest: accept the first stream, perform the
/// mirror-protocol hello, send the snapshot, then idle until the desktop
/// disconnects or shutdown is signaled.
async fn serve_rend(
    rend_req: RendRequest,
    pairing_id: [u8; 16],
    pairing_key: [u8; 32],
    snapshot_bytes: Vec<u8>,
    shutdown: Arc<AtomicBool>,
    mut push_rx: tokio::sync::broadcast::Receiver<Vec<u8>>,
    inbound_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) -> Result<(), String> {
    let mut stream_reqs = rend_req
        .accept()
        .await
        .map_err(|e| format!("rend accept: {e}"))?;
    let Some(sreq) = stream_reqs.next().await else {
        return Err("no stream requests".into());
    };
    let stream = sreq
        .accept(tor_cell::relaycell::msg::Connected::new_empty())
        .await
        .map_err(|e| format!("stream accept: {e}"))?;
    let (mut rd, mut wr) = stream.split();

    // Hello handshake: desktop must send 0x69.
    let mut hello = [0u8; 1];
    rd.read_exact(&mut hello)
        .await
        .map_err(|e| format!("hello read: {e}"))?;
    if hello[0] != 0x69 {
        return Err(format!("bad hello byte 0x{:02x}", hello[0]));
    }
    tracing::info!("hs_host: desktop hello ok — sending snapshot");

    // Per-direction chain keys. Must match ivy-desktop/src-tauri's
    // `derive_dir_chain` + `HKDF_INFO_P2D` / `HKDF_INFO_D2P`.
    let p2d_seed = dir_chain(&pairing_key, b"lattice-mirror-chain-p2d-v1");
    let d2p_seed = dir_chain(&pairing_key, b"lattice-mirror-chain-d2p-v1");
    let mut send_ck = p2d_seed;
    let mut recv_ck = d2p_seed;
    // AAD epoch stays at 0 for v0.1 (no ratchet root rotation yet). Both
    // sides must use identical constants in the envelope AAD or decrypt
    // fails — so keep the ChainState.epoch convention (== 0).
    const AAD_EPOCH: u32 = 0;

    // Seal + send the snapshot (first p2d frame).
    let (mk, next_ck) = advance_chain(&send_ck);
    send_ck = next_ck;
    let sealed = crate::crypto::envelope::seal(&mk, &pairing_id, AAD_EPOCH, &snapshot_bytes)
        .map_err(|e| format!("seal: {e}"))?;
    let mut frame = (sealed.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&sealed);
    wr.write_all(&frame).await.map_err(|e| format!("write: {e}"))?;
    wr.flush().await.map_err(|e| format!("flush: {e}"))?;

    // Merge-select across inbound arti frames + outbound push broadcasts +
    // shutdown. Inbound frames get decrypted and logged (and acked if
    // they carry a local_id). Pushed plaintexts get sealed on the P2D
    // chain and shipped immediately.
    loop {
        if shutdown.load(Ordering::SeqCst) { return Ok(()); }

        tokio::select! {
            // Pushed outbound frame (e.g. {"type":"message",...})
            maybe_plaintext = push_rx.recv() => {
                let pt = match maybe_plaintext {
                    Ok(p) => p,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("hs_host: push channel closed");
                        return Ok(());
                    }
                };
                let (mk, next) = advance_chain(&send_ck);
                send_ck = next;
                match crate::crypto::envelope::seal(&mk, &pairing_id, AAD_EPOCH, &pt) {
                    Ok(sealed) => {
                        let mut f = (sealed.len() as u32).to_be_bytes().to_vec();
                        f.extend_from_slice(&sealed);
                        if let Err(e) = wr.write_all(&f).await {
                            tracing::warn!("hs_host: push write: {e}");
                            return Ok(());
                        }
                        let _ = wr.flush().await;
                        tracing::info!("hs_host: pushed frame ({} B)", pt.len());
                    }
                    Err(e) => tracing::warn!("hs_host: push seal: {e}"),
                }
            }
            // Inbound frame from desktop (desktop→phone)
            read_res = read_inbound_frame(&mut rd) => {
                match read_res {
                    Ok(None) => {
                        tracing::info!("hs_host: desktop disconnected");
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                    Ok(Some(body)) => {
                        let (rmk, rnext) = advance_chain(&recv_ck);
                        recv_ck = rnext;
                        let plaintext = match crate::crypto::envelope::open(
                            &rmk, &pairing_id, AAD_EPOCH, &body,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!("hs_host: inbound decrypt failed: {e}");
                                continue;
                            }
                        };
                        let text = String::from_utf8_lossy(&plaintext).to_string();
                        tracing::info!("hs_host: inbound plaintext ({} B): {}", plaintext.len(),
                            if text.len() > 160 { format!("{}…", &text[..160]) } else { text.clone() });

                        // Broadcast the raw plaintext to any polling
                        // Kotlin consumers (desktop_hs_poll_inbound FFI).
                        // `.send()` returns the receiver count; zero just
                        // means no one is listening right now.
                        let _ = inbound_tx.send(plaintext.clone());

                        if let Some(local_id) = extract_local_id(&text) {
                            let ack = format!(r#"{{"type":"ack","local_id":"{}"}}"#, local_id);
                            let (amk, anext) = advance_chain(&send_ck);
                            send_ck = anext;
                            if let Ok(sealed_ack) = crate::crypto::envelope::seal(
                                &amk, &pairing_id, AAD_EPOCH, ack.as_bytes(),
                            ) {
                                let mut f = (sealed_ack.len() as u32).to_be_bytes().to_vec();
                                f.extend_from_slice(&sealed_ack);
                                if let Err(e) = wr.write_all(&f).await {
                                    tracing::warn!("hs_host: ack write: {e}");
                                } else {
                                    let _ = wr.flush().await;
                                    tracing::info!("hs_host: ack sent for local_id={}", local_id);
                                }
                            }
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                // periodic re-check of shutdown flag
            }
        }
    }
}

async fn read_inbound_frame<R>(rd: &mut R) -> Result<Option<Vec<u8>>, String>
where
    R: futures::AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    match rd.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(_) => return Ok(None), // desktop disconnected
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 2 * 1024 * 1024 {
        return Err(format!("inbound frame size out of range: {len}"));
    }
    let mut body = vec![0u8; len];
    rd.read_exact(&mut body).await.map_err(|e| format!("body: {e}"))?;
    Ok(Some(body))
}

fn dir_chain(pairing_key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(pairing_key).expect("hkdf from_prk");
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

/// Advance a symmetric ratchet chain: MK = HMAC(CK, 0x02); next CK = HMAC(CK, 0x01).
fn advance_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    let mk = {
        let mut m = Hmac::<Sha256>::new_from_slice(ck).expect("hmac");
        m.update(&[0x02]);
        let t = m.finalize().into_bytes();
        let mut o = [0u8; 32];
        o.copy_from_slice(&t);
        o
    };
    let next = {
        let mut m = Hmac::<Sha256>::new_from_slice(ck).expect("hmac");
        m.update(&[0x01]);
        let t = m.finalize().into_bytes();
        let mut o = [0u8; 32];
        o.copy_from_slice(&t);
        o
    };
    (mk, next)
}

/// Parse `"local_id":"..."` out of a JSON-ish string WITHOUT pulling in a
/// full parser. The field, if present, is always a short hex/uuid-ish
/// literal bracketed by `"` in our outbound wire format.
fn extract_local_id(s: &str) -> Option<String> {
    let key = r#""local_id":""#;
    let i = s.find(key)? + key.len();
    let rest = &s[i..];
    let j = rest.find('"')?;
    Some(rest[..j].to_string())
}

#[allow(dead_code)]
fn msg_key_from_chain(ck: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(ck).expect("hmac");
    mac.update(&[0x02]);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// HS service nickname — arti requires a human-readable string, 1-30 chars
/// of [a-zA-Z0-9_]. Short hex of the pairing_id meets that easily.
fn hex_short(pid: &[u8; 16]) -> String {
    format!("ivy{}", hex::encode(&pid[..6]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hs_hostname_from_key() {
        let a = derive_hs_keypair(&[0x11u8; 32]);
        let b = derive_hs_keypair(&[0x11u8; 32]);
        let ha = HsIdKey::from(&a).id();
        let hb = HsIdKey::from(&b).id();
        assert_eq!(ha.to_string(), hb.to_string());
    }
    #[test]
    fn different_keys_different_hostname() {
        let a = derive_hs_keypair(&[0x11u8; 32]);
        let b = derive_hs_keypair(&[0x22u8; 32]);
        let ha = HsIdKey::from(&a).id();
        let hb = HsIdKey::from(&b).id();
        assert_ne!(ha.to_string(), hb.to_string());
    }
}
