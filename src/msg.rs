use cosmwasm_std::{Uint64, Binary};
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};
use crate::signed_doc::{SignedDocument};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub entropy: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// transaction that emits event on the chain
    Tx { 
        /// channel to increment the counter on
        channel: String,
        /// optional message length padding
        padding: Option<String>
    },
    /// updates the seed with a new document signature
    UpdateSeed {
        /// signed doc
        signed_doc: SignedDocument,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set viewing key
    SetViewingKey {
        /// viewing key
        key: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// Revoke a permit
    RevokePermit {
        permit_name: String,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    Tx {
        response: ResponseStatus,
        counter: Uint64,
        plaintext: Binary,
        padded_plaintext: Binary,
        seed: Binary,
        nonce: Binary,
        aad: Binary,
        tag_ciphertext: Binary,
    },
    UpdateSeed {
        seed: Binary,
    },
    SetViewingKey {
        response: ResponseStatus,
    },
    RevokePermit {
        response: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Public query to list all notification channels
    ListChannels {},
    /// Authenticated query allows clients to obtain the seed, counter, and 
    ///   Notification ID of a future event, for a specific channel.
    ChannelInfo {
        channel: String,
        viewer: ViewerInfo,
    },
    /// Authenticated queries with permits
    WithPermit {
        permit: Permit,
        query: QueryWithPermit,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryWithPermit {
    ChannelInfo {
        channel: String,
    },
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    ListChannels {
        channels: Vec<String>,
    },
    ChannelInfo {
        /// same as query input
        channel: String,
        /// shared secret in base64
        seed: Binary,
        /// current counter value
        counter: Uint64,
        /// the next Notification ID
        next_id: Binary,
        /// scopes validity of this response
        as_of_block: Uint64,
        /// optional CDDL schema definition string for the CBOR-encoded notification data
        cddl: Option<String>,
    },
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct ViewerInfo {
    /// querying address
    pub address: String,
    /// authentication key string
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}