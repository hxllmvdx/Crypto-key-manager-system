use crate::crypto::error::CryptoError;
use rand::{RngCore, thread_rng};
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

pub fn encrypt_aes128(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let unbound_key =
        UnboundKey::new(&AES_128_GCM, key).map_err(|_| CryptoError::InvalidKeyLengthError)?;

    let mut nonce_bytes = vec![0u8; AES_128_GCM.nonce_len()];
    thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| CryptoError::NonceValidationError)?;

    let less_safe_key = LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    let aad = Aad::empty();

    less_safe_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok((in_out, nonce_bytes))
}

pub fn decrypt_aes128(
    key: &[u8],
    ciphertext_with_tag: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key =
        UnboundKey::new(&AES_128_GCM, key).map_err(|_| CryptoError::InvalidKeyLengthError)?;

    let mut in_out = ciphertext_with_tag.to_vec();
    let aad = Aad::empty();

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| CryptoError::NonceValidationError)?;

    let plaintext = LessSafeKey::new(unbound_key)
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    Ok(plaintext.to_vec())
}

pub fn encrypt_aes256(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::InvalidKeyLengthError)?;

    let mut nonce_bytes = vec![0u8; AES_256_GCM.nonce_len()];
    thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| CryptoError::NonceValidationError)?;

    let less_safe_key = LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    let aad = Aad::empty();

    less_safe_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok((in_out, nonce_bytes))
}

pub fn decrypt_aes256(
    key: &[u8],
    ciphertext_with_tag: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::InvalidKeyLengthError)?;

    let mut in_out = ciphertext_with_tag.to_vec();
    let aad = Aad::empty();

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| CryptoError::NonceValidationError)?;

    let plaintext = LessSafeKey::new(unbound_key)
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    Ok(plaintext.to_vec())
}
