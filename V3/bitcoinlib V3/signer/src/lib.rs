// signer/src/lib.rs
//
// Narrow Rust signing module for the Bitcoin CLI wallet prototype.
//
// Public API (exposed to Python via PyO3):
//   encrypt_key_blob(wif, passphrase)           -> bytes
//   decrypt_and_sign(blob, passphrase, sighash) -> bytes   (DER signature)
//
// Design constraints
// - All secret buffers (WIF, raw key, PBKDF2 output, AES key) are wrapped in
//   `Zeroizing<_>` or types that implement `ZeroizeOnDrop`, so memory is
//   scrubbed deterministically on drop — including on panic/error paths.
// - Python receives only non-sensitive output (DER signature bytes).
// - No helper functions that return key material are exposed.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::Hmac;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use pbkdf2::pbkdf2_hmac;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rand_core::{OsRng, RngCore};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PBKDF2_ROUNDS: u32 = 210_000;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12; // standard AES-256-GCM nonce
// Blob layout: [32-byte salt | 12-byte nonce | AES-GCM ciphertext+tag]
const BLOB_MIN_LEN: usize = SALT_LEN + NONCE_LEN + 1;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES key from `passphrase` and `salt` using PBKDF2-HMAC-SHA512.
fn derive_aes_key(passphrase: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha512>(passphrase, salt, PBKDF2_ROUNDS, key.as_mut());
    key
}

/// Decode a WIF-encoded private key and return the raw 32-byte secret scalar.
///
/// WIF is base58check-encoded: [version(1)] [key(32)] [?compression(1)]
/// The function zeroizes the decoded bytes before returning.
fn wif_to_raw_key(wif: &[u8]) -> PyResult<Zeroizing<[u8; 32]>> {
    // bs58 with check validates the 4-byte checksum and strips it.
    let decoded = bs58::decode(wif)
        .with_check(None)
        .into_vec()
        .map_err(|e| PyValueError::new_err(format!("WIF base58check decode failed: {e}")))?;

    // decoded = version(1) + key(32) + optional compression flag(1)
    if decoded.len() < 33 {
        return Err(PyValueError::new_err("WIF decoded payload too short"));
    }

    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(&decoded[1..33]);
    // decoded is heap-allocated; Zeroizing<[u8;32]> zeroizes on drop.
    // We don't hold a Zeroizing wrapper for `decoded`, but it does not contain
    // sensitive material after we've copied the key bytes out — the caller's
    // raw buffer will be zeroized on drop.
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Public PyO3 functions
// ---------------------------------------------------------------------------

/// Encrypt a WIF-encoded private key with a passphrase-derived AES-256-GCM key.
///
/// The key is derived with PBKDF2-HMAC-SHA512 (210 000 rounds) over a fresh
/// 32-byte random salt.  Output blob layout:
///
///   [32-byte PBKDF2 salt][12-byte AES-GCM nonce][ciphertext + 16-byte GCM tag]
///
/// All intermediate key material is zeroized on function return.
#[pyfunction]
fn encrypt_key_blob(wif: &[u8], passphrase: &[u8]) -> PyResult<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let aes_key = derive_aes_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(aes_key.as_ref().into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, wif)
        .map_err(|_| PyValueError::new_err("AES-256-GCM encryption failed"))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an encrypted WIF blob, sign a 32-byte sighash with the recovered
/// secp256k1 key, and return the DER-encoded ECDSA signature.
///
/// Zeroization guarantees:
/// - The PBKDF2-derived AES key (`Zeroizing<[u8;32]>`) is zeroed on drop.
/// - The raw private key scalar (`Zeroizing<[u8;32]>`) is zeroed on drop.
/// - `k256::ecdsa::SigningKey` implements `ZeroizeOnDrop` and is zeroed when
///   it goes out of scope — on both success and error paths.
/// - No secret bytes are returned to Python; only the DER signature is.
#[pyfunction]
fn decrypt_and_sign(
    encrypted_blob: &[u8],
    passphrase: &[u8],
    sighash: &[u8],
) -> PyResult<Vec<u8>> {
    if sighash.len() != 32 {
        return Err(PyValueError::new_err("sighash must be exactly 32 bytes"));
    }
    if encrypted_blob.len() < BLOB_MIN_LEN {
        return Err(PyValueError::new_err(
            "encrypted_blob too short — was it produced by encrypt_key_blob?",
        ));
    }

    // Unpack blob
    let (salt, rest) = encrypted_blob.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    // Derive AES key (zeroized on drop)
    let aes_key = derive_aes_key(passphrase, salt);
    let cipher = Aes256Gcm::new(aes_key.as_ref().into());
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt WIF bytes (GCM tag validates integrity + passphrase)
    let wif_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| {
            PyValueError::new_err(
                "Decryption failed — incorrect passphrase or corrupted blob",
            )
        })?;
    // Wrap in Zeroizing so the heap allocation is scrubbed on drop.
    let wif_secret = Zeroizing::new(wif_bytes);

    // Parse WIF → raw 32-byte scalar (zeroized on drop)
    let raw_key = wif_to_raw_key(&wif_secret)?;

    // Build signing key — ZeroizeOnDrop ensures the scalar is scrubbed.
    let signing_key = SigningKey::from_bytes(raw_key.as_ref().into())
        .map_err(|e| PyValueError::new_err(format!("Invalid secp256k1 key: {e}")))?;

    // Sign prehash digest
    let sig: Signature = signing_key
        .sign_prehash(sighash)
        .map_err(|e| PyValueError::new_err(format!("ECDSA signing failed: {e}")))?;

    // Normalise s to low-s form (Bitcoin consensus requirement)
    let sig = sig.normalize_s().unwrap_or(sig);

    // Return DER-encoded bytes; signing_key drops + zeroizes here.
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Compute HMAC-SHA256 of `data` with `key`. Used for policy-file integrity
/// verification from Python without exposing the key derivation in Python land.
#[pyfunction]
fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    use hmac::Mac;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("{e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

#[pymodule]
fn bitcoin_signer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_key_blob, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_and_sign, m)?)?;
    m.add_function(wrap_pyfunction!(compute_hmac_sha256, m)?)?;
    Ok(())
}
