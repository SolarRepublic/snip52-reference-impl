use chacha20poly1305::{
    aead::{Aead, KeyInit,},
    ChaCha20Poly1305,
};
use cosmwasm_std::{StdResult, StdError};
use generic_array::GenericArray;

pub fn cipher_data(
    key: &[u8],
    nonce: &[u8],
    plaintext: &str, 
) -> StdResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e|
        StdError::generic_err(format!("{:?}", e))
    )?;
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(nonce), plaintext.as_bytes())
        .map_err(|e| StdError::generic_err(format!("{:?}", e)))?;
    Ok(ciphertext)
}