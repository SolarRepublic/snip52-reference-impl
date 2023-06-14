use cosmwasm_std::{Storage, StdResult, CanonicalAddr};
use secret_toolkit::storage::{Keyset, Keymap};
use serde::{Serialize, Deserialize};

pub static CHANNELS: Keyset<String> = Keyset::new(b"channel-ids");
pub static CHANNEL_SCHEMATA: Keymap<String,String> = Keymap::new(b"channel-schemata");

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Channel {
    pub id: String,
    pub schema: Option<String>,
}

impl Channel {
    pub fn store(self, storage: &mut dyn Storage) -> StdResult<()> {
        CHANNELS.insert(storage, &self.id)?;
        if let Some(schema) = self.schema {
            CHANNEL_SCHEMATA.insert(storage, &self.id, &schema)?;
        } else if CHANNEL_SCHEMATA.get(storage, &self.id).is_some() { 
            // double check it does not already have a schema stored, and if 
            //   it does remove it.
            CHANNEL_SCHEMATA.remove(storage, &self.id)?;
        }
        Ok(())
    }

    pub fn remove(self, storage: &mut dyn Storage) -> StdResult<()> {
        CHANNELS.remove(storage, &self.id)?;
        CHANNEL_SCHEMATA.remove(storage, &self.id)?;
        Ok(())
    }
}

/// Example data struct for tx channel 
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TxChannelData {
    pub sender: CanonicalAddr,
    pub counter: u64,
    pub message: String,
}

/// Example CDDL Schema for TxChannelData
pub static TX_CHANNEL_SCHEMA: &str = r#"tx = {
    sender: bstr,
    counter: uint,
    message: tstr,
  }"#;