use cosmwasm_std::{Storage, StdResult,};
use secret_toolkit_storage::{Keyset, Keymap};
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
}

/// id for the `message` channel
pub const MESSAGE_CHANNEL_ID: &str = "message";
/// CDDL Schema for MessageChannelData
pub const MESSAGE_CHANNEL_SCHEMA: &str = "message=[sender:bstr,message:tstr]";

/// id for the `reaction` channel
pub const REACTION_CHANNEL_ID: &str = "reaction";
/// CDDL Schema for ReactionChannelData
pub const REACTION_CHANNEL_SCHEMA: &str = "reaction=[sender:bstr,message_hash:bstr,reaction:tstr]";
