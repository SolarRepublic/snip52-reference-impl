use hkdf::hmac::Hmac;
use sha2::{Digest, Sha256};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit,},
    ChaCha20Poly1305,
};
use cosmwasm_std::{StdResult, StdError};
use generic_array::GenericArray;

pub const SHA256_HASH_SIZE: usize = 32;

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

pub fn cipher_data(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8], 
    aad: &[u8],
) -> StdResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e|
            StdError::generic_err(format!("{:?}", e)
        )
    )?;
    let mut buffer: Vec<u8> = plaintext.to_vec();
    cipher
        .encrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buffer)
        .map_err(|e| 
            StdError::generic_err(format!("{:?}", e))
        )?;
    Ok(buffer)
}

pub fn sha_256(data: &[u8]) -> [u8; SHA256_HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    result
}
