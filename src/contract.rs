use std::collections::HashSet;

use bech32::{ToBase32,Variant};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr, ContractInfo, StdError, Api, Uint64, CanonicalAddr,
};
use secret_toolkit::crypto::{ContractPrng, sha_256};
use base64::{engine::general_purpose, Engine as _};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, QueryAnswer, ViewerInfo, ExecuteAnswer};
use crate::signed_doc::{SignedDocument, pubkey_to_account, Document};
use crate::state::{increment_count, INTERNAL_SECRET, SEEDS, get_seed, CHANNELS, store_seed, COUNTERS, get_count};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
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

    if msg.channels.len() == 0 {
        return Err(StdError::generic_err("No channel ids"))
    }

    msg.channels
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .for_each(|channel| {
            CHANNELS.insert(deps.storage, &channel);
        });

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Tx { channel, .. } => try_tx(deps, &info.sender, channel),
        ExecuteMsg::UpdateSeed { signed_doc, .. } => try_update_seed(
            deps,
            env,
            &info.sender, 
            signed_doc
        ),
    }
}

pub fn try_tx(
    deps: DepsMut,
    sender: &Addr,
    channel: String,
) -> StdResult<Response> {
    increment_count(deps.storage, &channel, &deps.api.addr_canonicalize(sender.as_str())?)?;
    Ok(Response::default())
}

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

/// fun notificationIDFor(contractOrRecipientAddr, channelId) {
///    // counter reflects the nth notification for the given contract/recipient in the given channel
///    let counter := getCounterFor(contractOrRecipientAddr, channelId)
///
///    // compute notification ID for this event
///    let seed := getSeedFor(contractOrRecipientAddr)
///    let material := concat(channelId, ":", counter)
///    let notificationID := hmac_sha256(key=seed, message=material)
///
///    return notificationID
///  }
fn notification_id(
    addr: &CanonicalAddr,
    channel: &String,
) -> StdResult<Binary> {
    // todo
    Ok(Binary::from(vec![0_u8, 0_u8, 0_u8, 0_u8]))
}

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

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ListChannels{} => query_list_channels(deps),
        QueryMsg::ChannelInfo { channel, viewer } => query_channel_info(deps, channel, viewer),
    }
}

fn query_list_channels(deps: Deps) -> StdResult<Binary> {
    to_binary(&QueryAnswer::ListChannels { channels: vec![] })
}

fn query_channel_info(
    deps: Deps,
    channel: String,
    viewer: ViewerInfo,
) -> StdResult<Binary> {
    to_binary("data")
    /* 
    to_binary(&QueryAnswer::ChannelInfo { 
        channel: (), 
        seed: (), 
        counter: (), 
        next_id: (), 
        as_of_block: () 
    })
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, Coin, StdError, Uint128};

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
            channels: vec![
                "channel1".to_string(),
                "channel2".to_string(),
            ],
            entropy: "secret sauce".to_string(),
        };

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }
}
