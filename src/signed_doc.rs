use cosmwasm_std::{Binary, Uint128, CanonicalAddr};
use schemars::JsonSchema;
use secret_toolkit::crypto::sha_256;
use serde::{Serialize, Deserialize};
use ripemd::{Digest, Ripemd160};

/// Document
/// Note: The order of fields in this struct is important for the document signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Document {
    /// account number
    pub account_number: Uint128,
    /// id of chain
    pub chain_id: String,
    /// fee
    pub fee: Fee,
    /// memo
    pub memo: String,
    /// messages
    /// the signed message
    #[serde(bound = "")]
    pub msgs: Vec<DocumentMsg>,
    /// sequence
    pub sequence: Uint128,
}

/// Message
/// Note: The order of fields in this struct is important for the document signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DocumentMsg {
    /// message type: "notification_seed"
    pub r#type: String,
    /// message value
    pub value: MsgValue,
}

/// Message value
/// Note: The order of fields in this struct is important for the document signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MsgValue {
    /// bech32 address of contract
    pub contract: String,
    /// base64-encoded value of previous seed
    pub previous_seed: Binary,
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: Uint128,
}

impl Fee {
    pub fn new() -> Self {
        Self {
            amount: vec![Coin::new()],
            gas: Uint128::new(1),
        }
    }
}

impl Default for Fee {
    fn default() -> Self {
        Self::new()
    }
}

// Note: The order of fields in this struct is important for the permit signature verification!
#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Coin {
    pub amount: Uint128,
    pub denom: String,
}

impl Coin {
    pub fn new() -> Self {
        Self {
            amount: Uint128::zero(),
            denom: "uscrt".to_string(),
        }
    }
}

impl Default for Coin {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Signature {
    pub pub_key: PubKey,
    pub signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PubKey {
    /// ignored, but must be "tendermint/PubKeySecp256k1" otherwise the verification will fail
    pub r#type: String,
    /// Secp256k1 PubKey
    pub value: Binary,
}

impl PubKey {
    pub fn canonical_address(&self) -> CanonicalAddr {
        pubkey_to_account(&self.value)
    }
}

/// Seed
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SignedDocument {
    #[serde(bound = "")]
    document: Document,
    signature: Signature,
}

pub fn pubkey_to_account(pubkey: &Binary) -> CanonicalAddr {
    let mut hasher = Ripemd160::new();
    hasher.update(sha_256(&pubkey.0));
    CanonicalAddr(Binary(hasher.finalize().to_vec()))
}