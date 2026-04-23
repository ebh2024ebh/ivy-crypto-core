//! AES-256-GCM envelope with constant-size padding.
//!
//! Bit-for-bit compatible with
//! `ivy-desktop/src-tauri/src/crypto/envelope.rs`.
//!
//! Frame format:
//!   [nonce (12 B)] [AES-256-GCM ciphertext of padded plaintext] [GCM tag 16 B]
//! Padded plaintext: `[u16 BE real_len][plaintext][0x00 … 0x00]` rounded up
//! to a multiple of [`PAD_QUANTUM`] bytes.
//!
//! AAD (20 B, exactly):
//!   [pairing_id 16 B] [ratchet_epoch u32 BE]
//!
//! Any tamper — wire bytes, AAD fields, or padding non-zero after
//! declared length — yields a decrypt error.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand_core::{OsRng, RngCore};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PAD_QUANTUM: usize = 512;
pub const AAD_LEN: usize = 16 + 4;

pub fn seal(
    key: &[u8; 32],
    pairing_id: &[u8; 16],
    ratchet_epoch: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let padded = pad_plaintext(plaintext)?;
    let aad = build_aad(pairing_id, ratchet_epoch);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &padded, aad: &aad })
        .map_err(|_| "aes-gcm encrypt")?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(
    key: &[u8; 32],
    pairing_id: &[u8; 16],
    ratchet_epoch: u32,
    wire: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if wire.len() < NONCE_LEN + TAG_LEN {
        return Err("envelope too short");
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce, ct) = wire.split_at(NONCE_LEN);
    let aad = build_aad(pairing_id, ratchet_epoch);
    let padded = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| "aes-gcm decrypt")?;
    unpad_plaintext(&padded)
}

fn build_aad(pairing_id: &[u8; 16], ratchet_epoch: u32) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..16].copy_from_slice(pairing_id);
    aad[16..20].copy_from_slice(&ratchet_epoch.to_be_bytes());
    aad
}

fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if plaintext.len() > u16::MAX as usize {
        return Err("plaintext too large");
    }
    let raw = plaintext.len() + 2;
    let padded_len = raw.div_ceil(PAD_QUANTUM) * PAD_QUANTUM;
    let mut buf = vec![0u8; padded_len];
    let len_be = (plaintext.len() as u16).to_be_bytes();
    buf[0] = len_be[0];
    buf[1] = len_be[1];
    buf[2..2 + plaintext.len()].copy_from_slice(plaintext);
    Ok(buf)
}

fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if padded.len() < 2 {
        return Err("unpad: too short");
    }
    let declared = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if declared + 2 > padded.len() {
        return Err("unpad: declared len > padded len");
    }
    if padded[2 + declared..].iter().any(|&b| b != 0) {
        return Err("unpad: non-zero padding");
    }
    Ok(padded[2..2 + declared].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let k = [0x42u8; 32];
        let pid = [0x11u8; 16];
        let pt = b"hello ivy";
        let wire = seal(&k, &pid, 7, pt).unwrap();
        let got = open(&k, &pid, 7, &wire).unwrap();
        assert_eq!(got, pt);
    }
}
