use bech32::{ToBase32,Variant};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr, StdError, Api, CanonicalAddr, Storage, Uint64,
};
use minicbor_ser as cbor;
use base64::{engine::general_purpose, Engine as _};
use hkdf::hmac::{Mac};
use crate::crypto::{HmacSha256, sha_256, cipher_data}; //cipher_data, sha_256};
use crate::channel::{Channel, TxChannelData, TX_CHANNEL_SCHEMA, CHANNEL_SCHEMATA, CHANNELS};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, QueryAnswer, ViewerInfo, ExecuteAnswer, ResponseStatus::Success};
use crate::rng::ContractPrng;
use crate::signed_doc::{SignedDocument, pubkey_to_account, Document};
use crate::state::{increment_count, INTERNAL_SECRET, get_seed, store_seed, get_count};
use crate::vk::{ViewingKey, ViewingKeyStore};

pub const DATA_LEN: usize = 256;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // use entropy and contract prng to create an internal secret for the contract
    let entropy = msg.entropy.as_bytes();
    let entropy_len = 16 + info.sender.to_string().len() + entropy.len();
    let mut rng_entropy = Vec::with_capacity(entropy_len);
    rng_entropy.extend_from_slice(&env.block.height.to_be_bytes());
    rng_entropy.extend_from_slice(&env.block.time.seconds().to_be_bytes());
    rng_entropy.extend_from_slice(info.sender.as_bytes());
    rng_entropy.extend_from_slice(entropy);
    let seed = env.block.random.as_ref().unwrap();
    let mut rng = ContractPrng::new(seed, &rng_entropy);
    let rand_slice = rng.rand_bytes();
    let key = sha_256(&rand_slice);
    INTERNAL_SECRET.save(deps.storage, &general_purpose::STANDARD.encode(key).as_bytes().to_vec())?;

    // Channels will generally be hard-coded in contracts
    let channels: Vec<Channel> = vec![
        Channel {
            id: "tx".to_string(),
            schema: Some(TX_CHANNEL_SCHEMA.to_string()),
        },
        // ...
    ];

    channels.into_iter().for_each(|channel| {
        channel.store(deps.storage).unwrap()
    });

    let prng_seed = sha_256(
        general_purpose::STANDARD
            .encode(rng.rand_bytes())
            .as_bytes(),
    );
    ViewingKey::set_seed(deps.storage, &prng_seed);

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Tx { channel, .. } => try_tx(
            deps, 
            &env, 
            &info.sender, 
            channel
        ),
        ExecuteMsg::UpdateSeed { signed_doc, .. } => try_update_seed(
            deps,
            env,
            &info.sender, 
            signed_doc
        ),
        ExecuteMsg::SetViewingKey { viewing_key, .. } => try_set_viewing_key(
            deps, 
            &info.sender, 
            viewing_key
        ),
    }
}

/// 
/// Execute Tx message
/// 
///   This sample transaction increments the sender's counter for a specified channel,
///   and issues a new encrypted notification that will be pushed to client applications.
/// 
fn try_tx(
    deps: DepsMut,
    env: &Env,
    sender: &Addr,
    channel: String,
) -> StdResult<Response> {
    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let count = increment_count(deps.storage, &channel, &sender_raw)?;

    // use CBOR to encode data
    let data = cbor::to_vec(
        &TxChannelData {
            sender: sender_raw.clone(),
            counter: count,
            message: format!("You have a new message on channel '{}'", channel)
        }
    ).map_err(|e| 
        StdError::generic_err(format!("{:?}", e))
    )?;

    let id = notification_id(deps.storage, &sender_raw, &channel)?;
 
    let encrypted_data = encrypt_notification_data(
        deps.storage,
        &env,
        &sender_raw,
        &channel,
        data
    )?;

    Ok(Response::new()
        .set_data(
            to_binary(&ExecuteAnswer::Tx { response: Success })?
        )
        .add_attribute_plaintext(
            format!("wasm.{}", id.to_base64()), 
            encrypted_data.to_base64()
        )
    )
}

/// 
/// Execute UpdateSeed message
/// 
///   Allows clients to set a new shared secret. In order to guarantee the provided 
///   secret has high entropy, clients must submit a signed document params and signature 
///   to be verified before the new shared secret (i.e., the signature) is accepted.
/// 
///   Updates the sender's seed with the signature of the `signed_doc`. The signed doc
///   is validated to make sure:
///   - the signature is verified, 
///   - that the sender was the signer of the doc, 
///   - the `contract` field matches the address of this contract
///   - the `previous_seed` field matches the previous seed stored in the contract
/// 
pub fn try_update_seed(
    deps: DepsMut,
    env: Env,
    sender: &Addr,
    signed_doc: SignedDocument,
) -> StdResult<Response> {
    let account = validate_signed_doc(deps.api, &signed_doc, None)?;

    if sender.as_str() != account {
        return Err(StdError::generic_err("Signed doc is not signed by sender"));
    }

    if signed_doc.params.contract != env.contract.address.as_str() {
        return Err(StdError::generic_err(
            "Signed doc is not for this contract",
        ));
    }

    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;

    let previous_seed = get_seed(deps.storage, &sender_raw)?;
    if previous_seed != signed_doc.params.previous_seed {
        return Err(StdError::generic_err("Previous seed does not match previous seed in signed doc"));
    }

    store_seed(deps.storage, &sender_raw, signed_doc.signature.signature.clone().0)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::UpdateSeed {
        seed: signed_doc.signature.signature,
    })?))
}

/// 
/// Execute SetViewingKey
/// 
///   Sets the viewing key for the sender
/// 
fn try_set_viewing_key(
    deps: DepsMut,
    sender: &Addr,
    viewing_key: String,
) -> StdResult<Response> {
    ViewingKey::set(deps.storage, sender.as_str(), &viewing_key);
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::SetViewingKey { response: Success })?))
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ListChannels{} => query_list_channels(deps),
        QueryMsg::ChannelInfo { channel, viewer } => query_channel_info(deps, env, channel, viewer),
    }
}

///
/// ListChannels query
/// 
///   Public query to list all notification channels.
/// 
fn query_list_channels(deps: Deps) -> StdResult<Binary> {
    let channels: Vec<String> = CHANNELS
        .iter(deps.storage)?
        .map(|channel| channel.unwrap())
        .collect();
    to_binary(&QueryAnswer::ListChannels { channels })
}

///
/// ChannelInfo query
/// 
///   Authenticated query allows clients to obtain the seed, counter, 
///   and Notification ID of a future event, for a specific channel.
/// 
fn query_channel_info(
    deps: Deps,
    env: Env,
    channel: String,
    viewer: ViewerInfo,
) -> StdResult<Binary> {
    // make sure the viewing key is valid
    ViewingKey::check(deps.storage, &viewer.address, &viewer.viewing_key)?;
    let sender_raw = deps.api.addr_canonicalize(viewer.address.as_str())?;

    let next_id = notification_id(deps.storage, &sender_raw, &channel)?;
    let counter = Uint64::from(get_count(deps.storage, &channel, &sender_raw));
    let schema = CHANNEL_SCHEMATA.get(deps.storage, &channel);

    to_binary(&QueryAnswer::ChannelInfo { 
        channel,
        seed: get_seed(deps.storage, &sender_raw)?, 
        counter, 
        next_id, 
        as_of_block: Uint64::from(env.block.height),
        cddl: schema,
    })
}

///
/// fn validate_signed_doc
/// 
///   Validates a signed doc to verify the signature is correct. Returns the account
///   derived from the public key.
/// 
fn validate_signed_doc(
    api: &dyn Api,
    signed_doc: &SignedDocument,
    hrp: Option<&str>,
) -> StdResult<String> {
    let account_hrp = hrp.unwrap_or("secret");

    // Derive account from pubkey
    let pubkey = &signed_doc.signature.pub_key.value;

    let base32_addr = pubkey_to_account(pubkey).0.as_slice().to_base32();
    let account: String = bech32::encode(account_hrp, base32_addr, Variant::Bech32).unwrap();

    let signed_bytes = to_binary(&Document::from_params(&signed_doc.params))?;
    let signed_bytes_hash = sha_256(signed_bytes.as_slice());

    let verified = api
        .secp256k1_verify(
            &signed_bytes_hash, 
            &signed_doc.signature.signature.0, 
            &pubkey.0
        ).map_err(|err| StdError::generic_err(err.to_string()))?;
    
    if !verified {
        return Err(StdError::generic_err(
            "Failed to verify signatures for the given signed doc",
        ));
    }

    Ok(account)
}

/// 
/// fn notification_id
/// 
///   Returns a notification id for the given address and channel id.
/// 
/// pseudocode:
/// 
/// fun notificationIDFor(contractOrRecipientAddr, channelId) {
///   // counter reflects the nth notification for the given contract/recipient in the given channel
///   let counter := getCounterFor(contractOrRecipientAddr, channelId)
///
///   // compute notification ID for this event
///   let seed := getSeedFor(contractOrRecipientAddr)
///   let material := concatStrings(channelId, ":", uintToDecimalString(counter))
///   let notificationID := hmac_sha256(key=seed, message=utf8ToBytes(material))
///
///   return notificationID
/// }
/// 
fn notification_id(
    storage: &dyn Storage,
    addr: &CanonicalAddr,
    channel: &String,
) -> StdResult<Binary> {
    let counter = get_count(storage, channel, addr);

    // compute notification ID for this event
    let seed = get_seed(storage, addr)?;
    let material = [
        channel.as_bytes(),
        ":".as_bytes(),
        counter.to_string().as_bytes()
    ].concat();

    let mut mac: HmacSha256 = HmacSha256::new_from_slice(seed.0.as_slice()).unwrap();
    mac.update(material.as_slice());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(Binary::from(code_bytes.as_slice()))
}

/// 
/// fn encrypt_notification_data
/// 
///   Returns encrypted bytes given plaintext bytes, address, and channel id.
/// 
/// pseudocode:
/// 
/// fun encryptNotificationData(recipientAddr, channelId, plaintext, env) {
///   // counter reflects the nth notification for the given recipient in the given channel
///   let counter := getCounterFor(recipientAddr, channelId)
///
///   let seed := getSeedFor(recipientAddr)
///
///   // ChaCha20 expects a 96-bit (12 bytes) nonce. encode uint64 counter using BE and left-pad with 4 bytes of 0x00
///   let nonce := concat(zeros(4), uint64BigEndian(counter))
///
///   // right-pad the plaintext with 0x00 bytes until it is of the desired length (keep in mind, payload adds 16 bytes for tag)
///   let message := concat(plaintext, zeros(DATA_LEN - len(plaintext)))
///
///   // construct the additional authenticated data
///   let aad := concatStrings(env.blockHeight, ":", env.txIndex)
///
///   // encrypt notification data for this event
///   let [ciphertext, tag] := chacha20poly1305_encrypt(key=seed, nonce=nonce, message=message, aad=aad)
///
///   // concatenate 16 bytes of tag with variable-width ciphertext
///   let payload := concat(tag, ciphertext)
///
///   return payload
/// }
/// 

fn encrypt_notification_data(
    storage: &dyn Storage,
    env: &Env,
    addr: &CanonicalAddr,
    channel: &String,
    plaintext: Vec<u8>,
) -> StdResult<Binary> {
    let counter = get_count(storage, channel, addr);
    let mut padded_plaintext = plaintext;
    zero_pad(&mut padded_plaintext, DATA_LEN);

    let seed = get_seed(storage, addr)?;
    let nonce = [&[0_u8, 0_u8, 0_u8, 0_u8], counter.to_be_bytes().as_slice()].concat();

    let tx_index: u32;
    if let Some(transaction) = &env.transaction {
        tx_index = transaction.index;
    } else {
        return Err(StdError::generic_err("Cannot encrypt notification data outside of a transaction"));
    }
    
    let aad = format!("{}:{}", env.block.height, tx_index);

    // encrypt notification data for this event
    let tag_ciphertext = cipher_data(
        seed.0.as_slice(),
        nonce.as_slice(),
        padded_plaintext.as_slice(),
        aad.as_bytes()
    )?;

    Ok(Binary::from(tag_ciphertext))
}


/// Take a Vec<u8> and pad it up to a multiple of `block_size`, using 0x00 at the end.
fn zero_pad(message: &mut Vec<u8>, block_size: usize) -> &mut Vec<u8> {
    let len = message.len();
    let surplus = len % block_size;
    if surplus == 0 {
        return message;
    }

    let missing = block_size - surplus;
    message.reserve(missing);
    message.extend(std::iter::repeat(0x00).take(missing));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{Coin, Uint128};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info(
            "creator",
            &[Coin {
                denom: "earth".to_string(),
                amount: Uint128::new(1000),
            }],
        );
        let init_msg = InstantiateMsg {
            entropy: "secret sauce".to_string(),
        };

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn test_notification_id() {
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

        let id = notification_id(&deps.storage, &alice_raw, &"channel1".to_string());
        println!("notification id: {:?}", id);
    }
}
