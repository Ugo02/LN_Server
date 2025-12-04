use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use cln_rpc::{
    model::{requests::FundchannelRequest, responses::FundchannelResponse},
    primitives::{Amount, AmountOrAll, PublicKey, Sha256},
    ClnRpc, Request, Response,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

type SharedClient = Arc<Mutex<ClnRpc>>;

const REQUESTCHANNELTAG: &str = "channelRequest";
const PUB_KEY: &str =
    "02a999fa0b71be07050c8fd5a6a131754303ae9b448d50f4be8b0e62d6df6790e3";
const IP_ADDRESS: &str = "127.0.0.1:9735";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client = match ClnRpc::new("/home/ugo/.lightning/testnet4/lightning-rpc").await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to cln rpc: {}", e);
            return;
        }
    };

    let shared_client = Arc::new(Mutex::new(client));

    let app = Router::new()
        .route("/channel_request", get(channel_request))
        .route("/open_channel", get(open_channel))
        .with_state(shared_client);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn channel_request() -> (StatusCode, Json<ChannelRequestResponse>) {
    let crr = ChannelRequestResponse {
        uri: format!("{}@{}", PUB_KEY, IP_ADDRESS),
        callback: "https://example.com/open_channel".to_string(),
        k1: "dontknow".to_string(),
        tag: REQUESTCHANNELTAG,
    };

    (StatusCode::OK, Json(crr))
}

#[derive(Debug, Deserialize)]
struct OpenChannelParams {
    remoteid: String,
    k1: String,
    #[serde(default)]
    private: Option<u8>,
}

async fn open_channel(
    State(client): State<SharedClient>,
    Query(params): Query<OpenChannelParams>,
) -> (StatusCode, Json<ChannelOpenResponse>) {
    if params.k1 != "dontknow" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ChannelOpenResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
                mindepth: None,
                channel_id: None,
                outnum: None,
                tx: None,
                txid: None,
            }),
        );
    }

    let node_id: PublicKey = match params.remoteid.parse() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ChannelOpenResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid node id: {}", e)),
                    mindepth: None,
                    channel_id: None,
                    outnum: None,
                    tx: None,
                    txid: None,
                }),
            );
        }
    };

    let amount = AmountOrAll::Amount(Amount::from_sat(100_000));
    let announce = params.private != Some(1);

    let request = FundchannelRequest {
        id: node_id,
        amount,
        feerate: None,
        announce: Some(announce),
        minconf: None,
        mindepth: None,
        utxos: None,
        push_msat: None,
        close_to: None,
        request_amt: None,
        compact_lease: None,
        reserve: None,
        channel_type: None,
    };

    let mut client_guard = client.lock().await;
    match client_guard.call(Request::FundChannel(request)).await {
        Ok(Response::FundChannel(response)) => success_response(response),
        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ChannelOpenResponse {
                status: "ERROR".to_string(),
                reason: Some("Unexpected response type".to_string()),
                mindepth: None,
                channel_id: None,
                outnum: None,
                tx: None,
                txid: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ChannelOpenResponse {
                status: "ERROR".to_string(),
                reason: Some(format!("Failed to open channel: {}", e)),
                mindepth: None,
                channel_id: None,
                outnum: None,
                tx: None,
                txid: None,
            }),
        ),
    }
}

fn success_response(response: FundchannelResponse) -> (StatusCode, Json<ChannelOpenResponse>) {
    (
        StatusCode::OK,
        Json(ChannelOpenResponse {
            status: "OK".to_string(),
            reason: None,
            mindepth: response.mindepth,
            channel_id: Some(response.channel_id),
            outnum: Some(response.outnum),
            tx: Some(response.tx),
            txid: Some(response.txid),
        }),
    )
}


#[derive(Debug, Clone, Serialize)]
struct ChannelRequestResponse {
    uri: String,
    callback: String,
    k1: String,
    tag: &'static str,
}

#[derive(Serialize)]
struct ChannelOpenResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mindepth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_id: Option<Sha256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outnum: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
}