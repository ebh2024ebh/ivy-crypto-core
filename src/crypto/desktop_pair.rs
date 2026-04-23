//! Desktop-pairing handshake — phone side.
//!
//! This is the Kotlin-visible entry point for the Ivy Desktop Companion
//! v0.1 pairing protocol. Mirrors the reference implementation shipped
//! as `ivy-desktop/src-tauri/src/bin/phone_simulator.rs` byte-for-byte.
//!
//! **Single-call design** — Kotlin calls `build_desktop_pair_response`
//! exactly once after the user scans the QR code. The function:
//!   1. Parses the QR payload and extracts the desktop's ephemeral
//!      X25519 pubkey + ML-KEM-1024 encapsulation key.
//!   2. Generates a fresh X25519 + ML-KEM-1024 keypair for this session.
//!   3. Performs the hybrid KEM: X25519 ECDH + ML-KEM encapsulation.
//!   4. Derives `pairing_key` via HKDF-SHA-256 over the transcript hash.
//!   5. Derives the 6-word BIP-39 SAS + 8-byte HMAC-SHA-256 commit.
//!   6. Signs the session handshake with the phone's identity keys
//!      (Ed25519 + ML-DSA-65 hybrid).
//!   7. Returns a ready-to-POST JSON blob plus the SAS words and the
//!      raw pairing key (so Kotlin can persist it under Keystore).
//!
//! The wire layout of the QR payload and response blob is documented
//! verbatim in `ivy-desktop/src-tauri/src/crypto/pair_kex.rs`. Don't
//! diverge without updating both sides.

use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::{
    array::Array,
    kem::Encapsulate,
    EncodedSizeUser, KemCore, MlKem1024,
};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};

/// Must match the byte-for-byte HKDF `info` string used by the desktop.
const HKDF_INFO_PAIR: &[u8]  = b"lattice-desktop-pair-v1";
const HKDF_INFO_SAS:  &[u8]  = b"lattice-pair-sas-v1";
const HMAC_SAS_COMMIT: &[u8] = b"lattice-pair-sas-commit-v1";

/// Magic + version of the QR payload wire format.
const QR_MAGIC:   &[u8; 8]  = b"IVY-PAIR";
const QR_VERSION: u8        = 0x01;
const ML_KEM_PUB_LEN: usize = 1568;

/// Phone identity credentials passed into the pairing flow. The phone
/// app loads these from Android Keystore and forwards them here; we
/// never persist or copy them inside lattice-core.
#[derive(Debug, Clone)]
pub struct PhoneIdentity {
    /// 32-byte Ed25519 seed (classic signing key material).
    pub ed25519_seed: Vec<u8>,
    /// 32-byte Ed25519 public key.
    pub ed25519_public: Vec<u8>,
    /// 32-byte ML-DSA-65 seed.
    pub mldsa_seed: Vec<u8>,
    /// 1952-byte ML-DSA-65 public key.
    pub mldsa_public: Vec<u8>,
}

/// Successful handshake output.
#[derive(Debug, Clone)]
pub struct DesktopPairResponse {
    /// JSON body the Android app must POST to
    /// `https://ivy.vin/api/pair/push` inside a
    /// `{session_nonce, blob_b64}` envelope (see callsite docs).
    pub blob_json: String,
    /// 64-char hex session nonce, used as the rendezvous path segment.
    pub session_nonce_hex: String,
    /// 6 BIP-39 words the phone UI must display for user SAS compare.
    pub sas_words: Vec<String>,
    /// 32-byte pairing key — persist under Keystore, never send on wire.
    pub pairing_key: Vec<u8>,
    /// 16-byte pairing identifier = `sha256(transcript)[..16]`. Used as
    /// the envelope AAD on BOTH sides (phone seals with this, desktop
    /// opens with this). Must be bit-identical to what
    /// `ivy-desktop/src-tauri/src/ipc.rs::confirm_pairing` computes:
    /// `&secrets.transcript[..16]`.
    pub pairing_id: Vec<u8>,
    /// The desktop's advertised onion host (echoed back to storage layer
    /// so the phone can later connect via arti when hosting the mirror
    /// service).  For v0.1 the phone passes this in as `phone_onion`
    /// (caller-supplied); we just echo it for completeness.
    pub phone_onion: String,
}

/// Entry point — decodes QR, runs full handshake, builds POST body.
///
/// If `phone_onion` is empty (`""`), this function **derives the onion
/// deterministically from the computed pairing_key** using the same HS
/// key-derivation logic used by `hs_host::hs_start`. This lets Kotlin
/// get a valid, signed blob with the real onion in a single FFI call,
/// without needing to bootstrap the HS before signing.
///
/// If `phone_onion` is non-empty, the caller-provided value is used
/// verbatim (v0.1 behaviour; kept for the phone-simulator + tests).
pub fn build_desktop_pair_response(
    qr_url: String,
    phone: PhoneIdentity,
    phone_onion: String,
) -> Result<DesktopPairResponse, crate::LatticeError> {
    use crate::LatticeError;

    // 1. Decode QR
    let qr_bytes = decode_qr_url(&qr_url)
        .map_err(|e| LatticeError::CryptoError(format!("QR decode: {e}")))?;
    if qr_bytes.len() < 8 + 1 + 32 + 32 + ML_KEM_PUB_LEN {
        return Err(LatticeError::CryptoError("QR payload too short".into()));
    }
    if &qr_bytes[..8] != QR_MAGIC {
        return Err(LatticeError::CryptoError("QR magic mismatch".into()));
    }
    if qr_bytes[8] != QR_VERSION {
        return Err(LatticeError::CryptoError(format!("QR version unsupported: {}", qr_bytes[8])));
    }
    let mut session_nonce = [0u8; 32];
    session_nonce.copy_from_slice(&qr_bytes[9..41]);
    let mut desktop_x_pub = [0u8; 32];
    desktop_x_pub.copy_from_slice(&qr_bytes[41..73]);
    let desktop_kem_pub_bytes = qr_bytes[73..73 + ML_KEM_PUB_LEN].to_vec();

    // 2. Phone ephemeral keys
    let mut rng = rand::thread_rng();
    let mut x_priv_bytes = [0u8; 32];
    rng.fill_bytes(&mut x_priv_bytes);
    let phone_x_priv = XSec::from(x_priv_bytes);
    let phone_x_pub = XPub::from(&phone_x_priv);

    // 3. ML-KEM-1024 encapsulation against desktop's pubkey
    type EkType = <MlKem1024 as KemCore>::EncapsulationKey;
    let encoded_ek: ml_kem::Encoded<EkType> = Array::try_from(desktop_kem_pub_bytes.as_slice())
        .map_err(|_| LatticeError::CryptoError("ML-KEM-1024 pubkey length".into()))?;
    let ek = <EkType as EncodedSizeUser>::from_bytes(&encoded_ek);
    let (ct, ss_kem) = ek.encapsulate(&mut rng)
        .map_err(|_| LatticeError::CryptoError("ML-KEM encapsulation failed".into()))?;

    // 4. X25519 ECDH
    let ss_x = phone_x_priv.diffie_hellman(&XPub::from(desktop_x_pub));

    // 5. HKDF to pairing_key
    let transcript = transcript_hash(
        &session_nonce,
        &desktop_x_pub,
        &desktop_kem_pub_bytes,
        phone_x_pub.as_bytes(),
        &ct,
    );
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_x.as_bytes());
    ikm.extend_from_slice(ss_kem.as_slice());
    let hk = Hkdf::<Sha256>::new(Some(&transcript), &ikm);
    let mut pairing_key = [0u8; 32];
    hk.expand(HKDF_INFO_PAIR, &mut pairing_key)
        .map_err(|_| LatticeError::CryptoError("HKDF expand".into()))?;

    // 6. SAS words + commit
    let sas_words = derive_sas_words(&pairing_key)?;
    let sas_commit = derive_sas_commit(&pairing_key);

    // 6.5. If caller didn't supply an onion, derive one deterministically
    //      from pairing_key using the same HS-keygen logic as hs_host. This
    //      keeps blob signing + HS hosting in perfect sync — the desktop's
    //      mirror_client will eventually `connect((phone_onion, 9163))` to
    //      exactly the onion whose HSID is derived from pairing_key.
    let phone_onion = if phone_onion.is_empty() {
        derive_onion_from_pairing_key(&pairing_key)?
    } else {
        phone_onion
    };

    // 7. Identity signatures — phone signs the session handshake.
    //    Signed message = session_nonce || phone_x_pub || ct || phone_onion
    let mut signed_msg = Vec::with_capacity(32 + 32 + ct.as_slice().len() + phone_onion.len());
    signed_msg.extend_from_slice(&session_nonce);
    signed_msg.extend_from_slice(phone_x_pub.as_bytes());
    signed_msg.extend_from_slice(ct.as_slice());
    signed_msg.extend_from_slice(phone_onion.as_bytes());

    let ed_sig = crate::ed25519_sign(signed_msg.clone(), phone.ed25519_seed.clone())?;
    let mldsa_sig = crate::ml_dsa_65_sign(signed_msg, phone.mldsa_seed.clone())?;

    // 8. Compose the blob exactly how the desktop's `pairing::decode_blob`
    //    expects it. Both sides parse/produce the same string bytes.
    let blob_json = json!({
        "session_nonce":             hex::encode(session_nonce),
        "phone_x25519_pub":          URL_SAFE_NO_PAD.encode(phone_x_pub.as_bytes()),
        "ml_kem_ct":                 URL_SAFE_NO_PAD.encode(ct.as_slice()),
        "phone_onion":               phone_onion.clone(),
        "phone_identity_ed_pub":     hex::encode(&phone.ed25519_public),
        "phone_identity_mldsa_pub":  URL_SAFE_NO_PAD.encode(&phone.mldsa_public),
        "sig_ed25519":               hex::encode(&ed_sig),
        "sig_mldsa":                 URL_SAFE_NO_PAD.encode(&mldsa_sig),
        "sas_commit":                hex::encode(sas_commit),
    })
    .to_string();

    // pairing_id = first 16 B of the transcript hash — matches the
    // desktop's `confirm_pairing` convention (see ivy-desktop/ipc.rs).
    // Used as AAD in every subsequent envelope seal/open.
    let pairing_id: Vec<u8> = transcript[..16].to_vec();

    Ok(DesktopPairResponse {
        blob_json,
        session_nonce_hex: hex::encode(session_nonce),
        sas_words,
        pairing_key: pairing_key.to_vec(),
        pairing_id,
        phone_onion,
    })
}

/// Convenience: base64-encode the blob body the way lattice-server's
/// `/api/pair/push` expects it — `{session_nonce, blob_b64}` JSON.
/// Android callers can hand the returned body directly to their HTTP POST.
pub fn build_rendezvous_push_body(resp: &DesktopPairResponse) -> String {
    let blob_b64 = STANDARD.encode(resp.blob_json.as_bytes());
    json!({
        "session_nonce": resp.session_nonce_hex,
        "blob_b64":      blob_b64,
    }).to_string()
}

// ─── Internals ─────────────────────────────────────────────────────────

fn decode_qr_url(qr_url: &str) -> Result<Vec<u8>, String> {
    const PREFIX: &str = "ivy-pair-v1://";
    if !qr_url.starts_with(PREFIX) {
        return Err(format!("prefix not '{PREFIX}'"));
    }
    URL_SAFE_NO_PAD
        .decode(&qr_url[PREFIX.len()..])
        .map_err(|e| format!("b64url: {e}"))
}

/// Must match `ivy-desktop/src-tauri/src/crypto/pair_kex.rs::transcript_hash` exactly.
fn transcript_hash(
    session_nonce: &[u8; 32],
    desktop_x_pub: &[u8; 32],
    desktop_kem_pub: &[u8],
    phone_x_pub: &[u8; 32],
    phone_kem_ct: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(session_nonce);
    h.update(desktop_x_pub);
    h.update(desktop_kem_pub);
    h.update(phone_x_pub);
    h.update(phone_kem_ct);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Must match `ivy-desktop/src-tauri/src/crypto/sas.rs::derive_sas` — same
/// HKDF info, same 2048-word BIP-39 English list, same bit-packing.
fn derive_sas_words(pairing_key: &[u8; 32]) -> Result<Vec<String>, crate::LatticeError> {
    use crate::LatticeError;

    let mut bytes = [0u8; 9];
    Hkdf::<Sha256>::from_prk(pairing_key)
        .map_err(|_| LatticeError::CryptoError("HKDF from_prk".into()))?
        .expand(HKDF_INFO_SAS, &mut bytes)
        .map_err(|_| LatticeError::CryptoError("HKDF SAS expand".into()))?;

    use bip39::Language;
    let wl = Language::English.word_list();

    let mut words = Vec::with_capacity(6);
    let mut bit_off = 0usize;
    for _ in 0..6 {
        let mut acc: u16 = 0;
        for _ in 0..11 {
            let byte = bytes[bit_off / 8];
            let bit = (byte >> (7 - (bit_off % 8))) & 1;
            acc = (acc << 1) | bit as u16;
            bit_off += 1;
        }
        // `word_list()` on bip39 2.x returns &[&str] of length 2048.
        words.push(wl[acc as usize].to_string());
    }
    Ok(words)
}

/// Must match `ivy-desktop/src-tauri/src/crypto/sas.rs::sas_commit`.
fn derive_sas_commit(pairing_key: &[u8; 32]) -> [u8; 8] {
    let mut mac = Hmac::<Sha256>::new_from_slice(pairing_key).expect("hmac");
    mac.update(HMAC_SAS_COMMIT);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&tag[..8]);
    out
}

/// Derive the onion hostname for the desktop HS identity keypair
/// generated deterministically from `pairing_key`. Mirrors
/// `network::hs_host::derive_hs_keypair` bit-for-bit so the signed blob
/// matches the HS that actually launches.
fn derive_onion_from_pairing_key(
    pairing_key: &[u8; 32],
) -> Result<String, crate::LatticeError> {
    use crate::LatticeError;
    use hkdf::Hkdf;
    use sha2::{Digest, Sha512};
    use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};

    let hk = Hkdf::<Sha256>::from_prk(pairing_key)
        .map_err(|_| LatticeError::CryptoError("HKDF from_prk (hs)".into()))?;
    let mut seed = [0u8; 32];
    hk.expand(b"lattice-desktop-hs-id-v1", &mut seed)
        .map_err(|_| LatticeError::CryptoError("HKDF expand (hs)".into()))?;

    // 32 B seed → 64 B expanded via SHA-512 with a domain tag + RFC 8032 clamp.
    let mut h = Sha512::new();
    h.update(b"lattice-ed25519-expand-v1");
    h.update(seed);
    let mut exp = [0u8; 64];
    exp.copy_from_slice(&h.finalize());
    exp[0] &= 248;
    exp[31] &= 127;
    exp[31] |= 64;

    let exp_kp = tor_llcrypto::pk::ed25519::ExpandedKeypair::from_secret_key_bytes(exp)
        .ok_or_else(|| LatticeError::CryptoError("ed25519 expanded keypair".into()))?;
    let hsid_kp = HsIdKeypair::from(exp_kp);
    Ok(HsIdKey::from(&hsid_kp).id().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_prefix() {
        let r = build_desktop_pair_response(
            "https://evil/not-ivy".to_string(),
            PhoneIdentity {
                ed25519_seed: vec![0u8; 32],
                ed25519_public: vec![0u8; 32],
                mldsa_seed: vec![0u8; 32],
                mldsa_public: vec![0u8; 1952],
            },
            "foo.onion".to_string(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_truncated_qr() {
        let r = build_desktop_pair_response(
            "ivy-pair-v1://SVZZLVBBSVI".to_string(),  // "IVY-PAIR" only
            PhoneIdentity {
                ed25519_seed: vec![0u8; 32],
                ed25519_public: vec![0u8; 32],
                mldsa_seed: vec![0u8; 32],
                mldsa_public: vec![0u8; 1952],
            },
            "foo.onion".to_string(),
        );
        assert!(r.is_err());
    }
}
