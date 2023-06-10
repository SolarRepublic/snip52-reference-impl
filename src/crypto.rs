use hkdf::hmac::Hmac;
use sha2::Sha256;
use chacha20poly1305::{
    aead::{Aead, KeyInit,},
    ChaCha20Poly1305,
};
use cosmwasm_std::{StdResult, StdError};
use generic_array::GenericArray;

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

pub fn cipher_data(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8], 
) -> StdResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e|
        StdError::generic_err(format!("{:?}", e))
    )?;
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(nonce), plaintext)
        .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
    Ok(ciphertext)
}