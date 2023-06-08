use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr,
};
use secret_toolkit::crypto::{ContractPrng, sha_256};
use base64::{engine::general_purpose, Engine as _};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, QueryAnswer, ViewerInfo};
use crate::signed_doc::SignedDocument;
use crate::state::{increment_count, INTERNAL_SECRET};

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

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Tx { .. } => try_tx(deps, &info.sender),
        ExecuteMsg::UpdateSeed { channel, signed_doc, .. } => try_update_seed(
            deps, 
            &info.sender, 
            channel, 
            signed_doc
        ),
    }
}

pub fn try_tx(deps: DepsMut, sender: &Addr) -> StdResult<Response> {
    increment_count(deps.storage, &deps.api.addr_canonicalize(sender.as_str())?)?;
    Ok(Response::default())
}

pub fn try_update_seed(
    deps: DepsMut,
    sender: &Addr,
    channel: String,
    signed_doc: SignedDocument,
) -> StdResult<Response> {
    Ok(Response::default())
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
        let init_msg = InstantiateMsg { entropy: "secret sauce".to_string() };

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }
}
