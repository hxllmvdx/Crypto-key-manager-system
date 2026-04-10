use crate::crypto::error::CryptoError;
use rand::thread_rng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts};
use sha2::Sha256;

pub fn encrypt_rsa2048(private_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key)
        .map_err(|e| CryptoError::Pkcs1ToPrivateKeyError(e.to_string()))?;

    if private_key.size() != 256 {
        return Err(CryptoError::InvalidKeyLengthError);
    }

    let public_key = RsaPublicKey::from(&private_key);

    let padding = Oaep::new::<Sha256>();
    let mut rng = thread_rng();

    let ciphertext = public_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok(ciphertext)
}

pub fn decrypt_rsa2048(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key)
        .map_err(|e| CryptoError::Pkcs1ToPrivateKeyError(e.to_string()))?;

    if private_key.size() != 256 {
        return Err(CryptoError::InvalidKeyLengthError);
    }

    let padding = Oaep::new::<Sha256>();

    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    Ok(plaintext)
}
