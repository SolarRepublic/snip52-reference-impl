use secret_toolkit::storage::{Keymap};

use cosmwasm_std::{CanonicalAddr, Storage, StdResult};

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
#[inline]
pub fn get_seed(
    storage: &dyn Storage,
    addr: &CanonicalAddr,
) -> Option<String> {
    SEEDS.get(storage, addr)
}