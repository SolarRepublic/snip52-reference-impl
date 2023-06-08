use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use secret_toolkit::{storage::{Keymap, Item}, crypto::ContractPrng};

use cosmwasm_std::{CanonicalAddr, Storage, StdResult, Env, StdError};

pub static INTERNAL_SECRET: Item<Vec<u8>> = Item::new(b"secret");
pub static COUNTERS: Keymap<CanonicalAddr,u64> = Keymap::new(b"counters");
pub static SEEDS: Keymap<CanonicalAddr,String> = Keymap::new(b"seeds");

/// increment counter for a given address
pub fn increment_count(
    storage: &mut dyn Storage,
    addr: &CanonicalAddr,
) -> StdResult<u64> {
    let count = COUNTERS.get(storage, addr).unwrap_or(0_u64);
    let new_count = count.wrapping_add(1_u64);
    COUNTERS.insert(storage, addr, &new_count)?;
    Ok(new_count)
}

/// get counter for a given address
#[inline]
pub fn get_count(
    storage: &dyn Storage,
    addr: &CanonicalAddr,
) -> u64 {
    COUNTERS.get(storage, addr).unwrap_or(0_u64)
}

/// update the seed for a given address
#[inline]
pub fn update_seed(
    storage: &mut dyn Storage,
    addr: &CanonicalAddr,
    seed: String,
) -> StdResult<()> {
    SEEDS.insert(storage, addr, &seed)
}

/// get the seed for a given address
/// fun getSeedFor(recipientAddr) {
///   // recipient has a shared secret with contract
///   let seed := sharedSecretsTable[recipientAddr]
/// 
///   // no explicit shared secret; derive seed using contract's internal secret
///   if NOT exists(seed):
///     seed := hkdf(ikm=contractInternalSecret, info=canonical(recipientAddr))
///
///   return seed
/// }

pub fn get_seed(
    storage: &dyn Storage,
    addr: &CanonicalAddr,
) -> StdResult<String> {
    let may_seed = SEEDS.get(storage, addr);

    if let Some(seed) = may_seed {
        Ok(seed)
    } else {
        let secret = INTERNAL_SECRET.load(storage)?;
        let ikm = secret.as_slice();
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = [0u8; 42];
        let seed = match hk.expand(&addr.as_slice(), &mut okm) {
            Ok(_) => { general_purpose::STANDARD.encode(okm) }
            Err(e) => { return Err(StdError::generic_err(format!("{:?}", e))); }
        };
        Ok(seed)
    }
}