use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, QueryAnswer, ViewerInfo};
use crate::signed_doc::SignedDocument;
use crate::state::{increment_count};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
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
        let init_msg = InstantiateMsg { };

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }
}
