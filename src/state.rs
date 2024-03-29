use base64::{engine::general_purpose, Engine};
use secret_toolkit_storage::{Keymap, Item};
use cosmwasm_std::{CanonicalAddr, Storage, StdResult, Binary, to_binary};
use crate::crypto::hkdf_sha_256;

pub static INTERNAL_SECRET: Item<Vec<u8>> = Item::new(b"secret");
pub static COUNTERS: Keymap<CanonicalAddr,u64> = Keymap::new(b"counters");
pub static SEEDS: Keymap<CanonicalAddr,Vec<u8>> = Keymap::new(b"seeds");

/// increment counter for a given address
pub fn increment_count(
    storage: &mut dyn Storage,
    channel: &String,
    addr: &CanonicalAddr,
) -> StdResult<u64> {
    let count = COUNTERS.add_suffix(channel.as_bytes()).get(storage, addr).unwrap_or(0_u64);
    let new_count = count.wrapping_add(1_u64);
    COUNTERS.add_suffix(channel.as_bytes()).insert(storage, addr, &new_count)?;
    Ok(new_count)
}

/// get counter for a given address
#[inline]
pub fn get_count(
    storage: &dyn Storage,
    channel: &String,
    addr: &CanonicalAddr,
) -> u64 {
    COUNTERS.add_suffix(channel.as_bytes()).get(storage, addr).unwrap_or(0_u64)
}

/// store the seed for a given address
#[inline]
pub fn store_seed(
    storage: &mut dyn Storage,
    addr: &CanonicalAddr,
    seed: Vec<u8>,
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
) -> StdResult<Binary> {
    let may_seed = SEEDS.get(storage, addr);
    if let Some(seed) = may_seed {
        Ok(Binary::from(seed))
    } else {
        let new_seed = hkdf_sha_256(
            &None, 
            INTERNAL_SECRET.load(storage)?.as_slice(), 
            addr.as_slice()
        )?;
        Binary::from_base64(&general_purpose::STANDARD.encode(new_seed))
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::instantiate;
    use crate::msg::InstantiateMsg;

    use super::*;
    use cosmwasm_std::{testing::*, Addr, CanonicalAddr, OwnedDeps, Api, Storage, MemoryStorage,};
    use cosmwasm_std::{from_binary, Coin, StdError, Uint128};

    #[test]
    fn test_get_seed() {
        let mut deps = mock_dependencies();

        let env = mock_env();
        let info = mock_info("instantiator", &[]);

        let _init = instantiate(
            deps.as_mut(), 
            env, 
            info, 
            InstantiateMsg {
                entropy: "entropy 12345".to_string(),
            });

        let alice = Addr::unchecked("alice".to_string());
        let alice_raw = deps.api.addr_canonicalize(alice.as_str()).unwrap();

        let seed = get_seed(&deps.storage, &alice_raw);
        println!("seed: {:?}", seed);
        println!("seed len: {:?}", seed.as_ref().unwrap().len());
    }
}