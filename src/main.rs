//! LNURL HTTP server for Lightning Network (Core Lightning).
//!
//! This server implements LNURL flows as specified in the LUD (LNURL Definitions) specs:
//! - **LNURL-channel**: `GET /request-channel` (optionally with `remoteid` for one-shot open),
//!   and `GET /open-channel` for the two-step flow.
//! - **LNURL-withdraw**: `GET /request-withdraw` (optionally with `pr` for one-shot pay),
//!   and `GET /withdraw` for the two-step flow.
//! - **LNURL-auth** (LUD-04): `GET /lnurl-auth` and `GET /lnurl-auth-callback` for
//!   challenge/response authentication.
//!
//! The server talks to a local Core Lightning node via its Unix socket RPC. Single-use
//! challenge tokens (k1) are stored in memory; configure `IP_ADDRESS` and `CALLBACK_URL`
//! for the address clients use to reach this server (e.g. WireGuard IP or VPS). The
//! RPC socket path can be overridden with the `CLN_RPC_SOCKET` environment variable.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use cln_rpc::{self, primitives::Sha256};
use cln_rpc::model::requests::{FundchannelRequest, PayRequest};
use cln_rpc::primitives::{Amount, AmountOrAll};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::io::ErrorKind;
use std::sync::{Arc, OnceLock};
use std::collections::HashSet;
use tokio::sync::Mutex;
use rand::RngCore;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use tracing::{error, info, warn};
use hex;

/// Shared Core Lightning RPC client (thread-safe).
type SharedClient = Arc<Mutex<cln_rpc::ClnRpc>>;
/// In-memory store of valid k1 challenge tokens (single-use).
type SharedK1Store = Arc<Mutex<HashSet<String>>>;

/// Application state injected into all LNURL handlers.
#[derive(Clone)]
struct AppState {
    client: SharedClient,
    k1_store: SharedK1Store,
}

// -----------------------------------------------------------------------------
// LNURL constants (LUD specs)
// -----------------------------------------------------------------------------
const REQUESTCHANNELTAG: &str = "channelRequest";
const WITHDRAWCHANNELTAG: &str = "withdrawRequest";
const DEFAULT_DESCRIPTION: &str = "Withdrawal from service";
const AUTHTAG: &str = "login";

/// Public address for this node (Lightning P2P). Must be reachable by clients (e.g. WireGuard IP or VPS).
const IP_ADDRESS: &str = "192.168.27.73:49735";
/// Base URL of this HTTP server; used in callback fields. Must be reachable by clients.
const CALLBACK_URL: &str = "http://192.168.27.73:3000/";

/// Node URI (pubkey@host:port) set at startup from Core Lightning getinfo.
static NODE_URI: OnceLock<String> = OnceLock::new();

/// Returns a short prefix of k1 for logging (avoids dumping full tokens).
fn k1_prefix(k1: &str) -> String {
    k1.chars().take(8).collect::<String>()
}

/// Health check: GET / or GET /health. Returns "OK" if the server is up.
async fn health() -> &'static str {
    "OK"
}

// -----------------------------------------------------------------------------
// LNURL-channel
// -----------------------------------------------------------------------------

/// LNURL-channel response: node URI, callback, k1, tag; optional funding result when `remoteid` is provided.
#[derive(Debug, Serialize)]
struct RequestChannelResponse {
    uri: &'static str,
    callback: String,
    k1: String,
    tag: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
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

/// Query params for request-channel; when remoteid is set, we open the channel immediately.
#[derive(Debug, Deserialize)]
struct RequestChannelParams {
    #[serde(default)]
    remoteid: Option<String>,
    #[serde(default)]
    private: Option<bool>,
}

/// GET /request-channel — returns LNURL channel response. If `remoteid` is provided,
/// opens the channel in one shot and includes funding result in the same response.
async fn request_channel(
    State(state): State<AppState>,
    Query(params): Query<RequestChannelParams>,
) -> (StatusCode, Json<RequestChannelResponse>) {
    let k1 = Uuid::new_v4().to_string();
    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }

    let mut response = RequestChannelResponse {
        uri: NODE_URI.get().expect("NODE_URI set at startup"),
        callback: format!("{}{}", CALLBACK_URL, "open-channel"),
        k1: k1.clone(),
        tag: REQUESTCHANNELTAG,
        status: None,
        reason: None,
        mindepth: None,
        channel_id: None,
        outnum: None,
        tx: None,
        txid: None,
    };

    if let Some(ref remoteid) = params.remoteid {
        info!(endpoint = "request-channel", remoteid = %remoteid, k1_prefix = %k1_prefix(&k1), "channel challenge + open-channel in one call");
        let node_id = match remoteid.parse() {
            Ok(id) => id,
            Err(e) => {
                warn!(endpoint = "request-channel", remoteid = %remoteid, error = %e, "invalid node id");
                response.status = Some("ERROR".to_string());
                response.reason = Some(format!("Invalid node id: {}", e));
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        };
        let request = FundchannelRequest {
            id: node_id,
            amount: AmountOrAll::Amount(Amount::from_sat(100_000)),
            announce: params.private,
            feerate: None,
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
        let mut client_guard = state.client.lock().await;
        match client_guard.call(cln_rpc::Request::FundChannel(request)).await {
            Ok(cln_rpc::Response::FundChannel(fund)) => {
                info!(endpoint = "request-channel", remoteid = %remoteid, txid = %fund.txid, "channel open initiated");
                response.status = Some("OK".to_string());
                response.mindepth = Some(fund.mindepth.unwrap());
                response.channel_id = Some(fund.channel_id);
                response.outnum = Some(fund.outnum);
                response.tx = Some(fund.tx);
                response.txid = Some(fund.txid);
            }
            Ok(_) => {
                error!(endpoint = "request-channel", remoteid = %remoteid, "unexpected RPC response type");
                response.status = Some("ERROR".to_string());
                response.reason = Some("Unexpected response type".to_string());
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
            }
            Err(e) => {
                error!(endpoint = "request-channel", remoteid = %remoteid, error = %e, "fundchannel failed");
                response.status = Some("ERROR".to_string());
                response.reason = Some(format!("Failed to open channel: {}", e));
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
            }
        };
    } else {
        info!(endpoint = "request-channel", k1_prefix = %k1_prefix(&k1), "channel challenge issued");
    }

    (StatusCode::OK, Json(response))
}

/// Query parameters for the open-channel callback (LNURL-channel).
#[derive(Debug, Deserialize)]
struct OpenChannelParams {
    remoteid: String,
    k1: String,
    #[serde(default)]
    private: Option<bool>,
}

/// LNURL-channel callback response: status and optional funding details.
#[derive(Serialize, Default)]
struct OpenChannelResponse {
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

/// GET /open-channel — validates k1 (single-use), then calls Core Lightning fundchannel.
/// Used by clients that follow the two-step LNURL-channel flow.
async fn open_channel(
    State(state): State<AppState>,
    Query(params): Query<OpenChannelParams>,
) -> (StatusCode, Json<OpenChannelResponse>) {
    info!(endpoint = "open-channel", remoteid = %params.remoteid, k1_prefix = %k1_prefix(&params.k1), "open-channel request received");

    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    if !k1_valid {
        warn!(endpoint = "open-channel", remoteid = %params.remoteid, "invalid k1");
        return (
            StatusCode::BAD_REQUEST,
            Json(OpenChannelResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
                ..Default::default()
            }),
        );
    }

    let node_id = match params.remoteid.parse() {
        Ok(id) => id,
        Err(e) => {
            warn!(endpoint = "open-channel", remoteid = %params.remoteid, error = %e, "invalid node id");
            return (
                StatusCode::BAD_REQUEST,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid node id: {}", e)),
                    ..Default::default()
                }),
            );
        }
    };

    let amount = AmountOrAll::Amount(Amount::from_sat(100_000));
    let request = FundchannelRequest {
        id: node_id,
        amount,
        announce: params.private,
        feerate: None,
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

    let mut client_guard = state.client.lock().await;
    match client_guard.call(cln_rpc::Request::FundChannel(request)).await {
        Ok(cln_rpc::Response::FundChannel(response)) => {
            info!(endpoint = "open-channel", remoteid = %params.remoteid, txid = %response.txid, "channel open initiated");
            (
                StatusCode::OK,
                Json(OpenChannelResponse {
                    status: "OK".to_string(),
                    reason: None,
                    mindepth: Some(response.mindepth.unwrap()),
                    channel_id: Some(response.channel_id),
                    outnum: Some(response.outnum),
                    tx: Some(response.tx),
                    txid: Some(response.txid),
                }),
            )
        }
        Ok(_) => {
            error!(endpoint = "open-channel", remoteid = %params.remoteid, "unexpected RPC response type");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some("Unexpected response type".to_string()),
                    ..Default::default()
                }),
            )
        }
        Err(e) => {
            error!(endpoint = "open-channel", remoteid = %params.remoteid, error = %e, "fundchannel failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpenChannelResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Failed to open channel: {}", e)),
                    ..Default::default()
                }),
            )
        }
    }
}

// -----------------------------------------------------------------------------
// LNURL-withdraw
// -----------------------------------------------------------------------------

/// LNURL-withdraw initial response: callback URL, k1, and min/max withdrawable (msat).
#[derive(Debug, Serialize)]
struct RequestWithdrawResponse {
    callback: String,
    k1: String,
    tag: &'static str,
    defaultDescription: &'static str,
    minWithdrawable: u64,
    maxWithdrawable: u64,
}

/// Query params for request-withdraw; when pr is set, we pay the invoice immediately.
#[derive(Debug, Deserialize)]
struct RequestWithdrawParams {
    #[serde(default)]
    pr: Option<String>,
}

/// Outcome of request-withdraw: either challenge (no pr) or withdraw result (pr provided).
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum RequestWithdrawOutcome {
    Challenge(RequestWithdrawResponse),
    Withdraw(WithdrawResponse),
}

/// GET /request-withdraw — returns challenge (callback, k1, limits) or, if `pr` is
/// provided, pays the BOLT11 invoice immediately and returns withdraw status.
async fn request_withdraw(
    State(state): State<AppState>,
    Query(params): Query<RequestWithdrawParams>,
) -> (StatusCode, Json<RequestWithdrawOutcome>) {
    let k1 = Uuid::new_v4().to_string();
    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }

    if let Some(pr) = params.pr {
        info!(endpoint = "request-withdraw", k1_prefix = %k1_prefix(&k1), "withdraw + pay in one call");
        {
            let mut k1_store = state.k1_store.lock().await;
            k1_store.remove(&k1);
        }
        // Pay the invoice via Core Lightning; k1 consumed for this one-shot flow
        let pay_request = PayRequest {
            bolt11: pr.clone(),
            amount_msat: None,
            description: None,
            exemptfee: None,
            label: None,
            localinvreqid: None,
            maxdelay: None,
            maxfee: None,
            maxfeepercent: None,
            partial_msat: None,
            retry_for: None,
            riskfactor: None,
            exclude: None,
        };
        let mut client_guard = state.client.lock().await;
        match client_guard.call(cln_rpc::Request::Pay(pay_request)).await {
            Ok(cln_rpc::Response::Pay(_)) => {
                info!(endpoint = "request-withdraw", k1_prefix = %k1_prefix(&k1), "invoice paid");
                return (
                    StatusCode::OK,
                    Json(RequestWithdrawOutcome::Withdraw(WithdrawResponse {
                        status: "OK".to_string(),
                        reason: None,
                    })),
                );
            }
            Ok(_) => {
                error!(endpoint = "request-withdraw", "unexpected RPC response type");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RequestWithdrawOutcome::Withdraw(WithdrawResponse {
                        status: "ERROR".to_string(),
                        reason: Some("Unexpected response type".to_string()),
                    })),
                );
            }
            Err(e) => {
                error!(endpoint = "request-withdraw", k1_prefix = %k1_prefix(&k1), error = %e, "pay failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RequestWithdrawOutcome::Withdraw(WithdrawResponse {
                        status: "ERROR".to_string(),
                        reason: Some(format!("Failed to pay invoice: {}", e)),
                    })),
                );
            }
        };
    }

    info!(endpoint = "request-withdraw", k1_prefix = %k1_prefix(&k1), "withdraw challenge issued");
    let response = RequestWithdrawResponse {
        callback: format!("{}{}", CALLBACK_URL, "withdraw"),
        k1,
        tag: WITHDRAWCHANNELTAG,
        defaultDescription: DEFAULT_DESCRIPTION,
        minWithdrawable: 1000,
        maxWithdrawable: 1_000_000,
    };
    (StatusCode::OK, Json(RequestWithdrawOutcome::Challenge(response)))
}


/// Query parameters for the withdraw callback: k1 and BOLT11 invoice (pr).
#[derive(Debug, Deserialize)]
struct WithdrawParams {
    k1: String,
    pr: String,
}

/// LNURL-withdraw callback response.
#[derive(Debug, Serialize, Default)]
struct WithdrawResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// LNURL-auth initial response: tag, 32-byte hex challenge (k1), and callback URL (LUD-04).
#[derive(Debug, Serialize)]
struct LnurlAuthResponse {
    tag: &'static str,
    k1: String,
    callback: String,
}

/// Query parameters for the auth callback: k1, ECDSA signature (hex), and linking pubkey (hex).
#[derive(Debug, Deserialize)]
struct LnurlAuthParams {
    k1: String,
    sig: String,
    key: String,
}

/// LNURL-auth callback response.
#[derive(Serialize, Default)]
struct LnurlAuthCallbackResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// GET /withdraw — validates k1 (single-use), consumes it, then pays the BOLT11 invoice.
/// Used by clients that follow the two-step LNURL-withdraw flow.
async fn withdraw(
    State(state): State<AppState>,
    Query(params): Query<WithdrawParams>,
) -> (StatusCode, Json<WithdrawResponse>) {
    info!(endpoint = "withdraw", k1_prefix = %k1_prefix(&params.k1), "withdraw callback received");

    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    if !k1_valid {
        warn!(endpoint = "withdraw", k1_prefix = %k1_prefix(&params.k1), "invalid k1");
        return (
            StatusCode::BAD_REQUEST,
            Json(WithdrawResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
            }),
        );
    }

    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.remove(&params.k1);
    }
    // k1 consumed (single-use); proceed to pay the invoice

    let pay_request = PayRequest {
        bolt11: params.pr,
        amount_msat: None,
        description: None,
        exemptfee: None,
        label: None,
        localinvreqid: None,
        maxdelay: None,
        maxfee: None,
        maxfeepercent: None,
        partial_msat: None,
        retry_for: None,
        riskfactor: None,
        exclude: None,
    };

    let mut client_guard = state.client.lock().await;
    match client_guard
        .call(cln_rpc::Request::Pay(pay_request))
        .await
    {
        Ok(cln_rpc::Response::Pay(_)) => {
            info!(endpoint = "withdraw", k1_prefix = %k1_prefix(&params.k1), "invoice paid");
            (
                StatusCode::OK,
                Json(WithdrawResponse {
                    status: "OK".to_string(),
                    reason: None,
                }),
            )
        }
        Ok(_) => {
            error!(endpoint = "withdraw", "unexpected RPC response type");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse {
                    status: "ERROR".to_string(),
                    reason: Some("Unexpected response type".to_string()),
                }),
            )
        }
        Err(e) => {
            error!(endpoint = "withdraw", k1_prefix = %k1_prefix(&params.k1), error = %e, "pay failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Failed to pay invoice: {}", e)),
                }),
            )
        }
    }
}

/// GET /lnurl-auth — returns a 32-byte hex challenge (k1) and callback URL (LUD-04).
async fn lnurl_auth_request(
    State(state): State<AppState>,
) -> (StatusCode, Json<LnurlAuthResponse>) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let k1 = hex::encode(bytes);
    // LUD-04: k1 is 32 random bytes encoded as 64 hex chars

    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.insert(k1.clone());
    }

    info!(endpoint = "lnurl-auth", k1_prefix = %k1_prefix(&k1), "auth challenge issued");
    let response = LnurlAuthResponse {
        tag: AUTHTAG,
        k1,
        callback: format!("{}{}", CALLBACK_URL, "lnurl-auth-callback"),
    };

    (StatusCode::OK, Json(response))
}

/// GET /lnurl-auth-callback — verifies ECDSA signature over k1 with the given pubkey
/// (linking key); returns OK on success (LUD-04). Expects compact 64-byte signature (hex).
async fn lnurl_auth_callback(
    State(state): State<AppState>,
    Query(params): Query<LnurlAuthParams>,
) -> (StatusCode, Json<LnurlAuthCallbackResponse>) {
    info!(endpoint = "lnurl-auth-callback", key = %params.key, k1_prefix = %k1_prefix(&params.k1), "auth callback received");

    let k1_valid = {
        let k1_store = state.k1_store.lock().await;
        k1_store.contains(&params.k1)
    };
    if !k1_valid {
        warn!(endpoint = "lnurl-auth-callback", key = %params.key, "invalid k1");
        return (
            StatusCode::BAD_REQUEST,
            Json(LnurlAuthCallbackResponse {
                status: "ERROR".to_string(),
                reason: Some("Invalid k1".to_string()),
            }),
        );
    }

    let k1_bytes_vec = match hex::decode(&params.k1) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(LnurlAuthCallbackResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid k1 encoding: {}", e)),
                }),
            );
        }
    };

    if k1_bytes_vec.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(LnurlAuthCallbackResponse {
                status: "ERROR".to_string(),
                reason: Some("k1 must be 32 bytes".to_string()),
            }),
        );
    }

    let mut k1_bytes = [0u8; 32];
    k1_bytes.copy_from_slice(&k1_bytes_vec);
    let msg = Message::from_digest(k1_bytes);
    // k1 is the signed message (32-byte digest per LUD-04)

    let pubkey_bytes = match hex::decode(&params.key) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(LnurlAuthCallbackResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid key encoding: {}", e)),
                }),
            );
        }
    };

    let pubkey = match PublicKey::from_slice(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(LnurlAuthCallbackResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid public key: {}", e)),
                }),
            );
        }
    };

    let sig_bytes = match hex::decode(&params.sig) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(LnurlAuthCallbackResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid sig encoding: {}", e)),
                }),
            );
        }
    };

    let sig = match Signature::from_compact(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(LnurlAuthCallbackResponse {
                    status: "ERROR".to_string(),
                    reason: Some(format!("Invalid signature: {}", e)),
                }),
            );
        }
    };

    let secp = Secp256k1::verification_only();
    if let Err(e) = secp.verify_ecdsa(&msg, &sig, &pubkey) {
        warn!(endpoint = "lnurl-auth-callback", key = %params.key, error = %e, "signature verification failed");
        return (
            StatusCode::BAD_REQUEST,
            Json(LnurlAuthCallbackResponse {
                status: "ERROR".to_string(),
                reason: Some(format!("Signature verification failed: {}", e)),
            }),
        );
    }

    {
        let mut k1_store = state.k1_store.lock().await;
        k1_store.remove(&params.k1);
    }
    // k1 consumed (single-use); client is authenticated as params.key

    info!(endpoint = "lnurl-auth-callback", key = %params.key, "auth success");
    (
        StatusCode::OK,
        Json(LnurlAuthCallbackResponse {
            status: "OK".to_string(),
            reason: None,
        }),
    )
}

// -----------------------------------------------------------------------------
// Server bootstrap
// -----------------------------------------------------------------------------

/// Default path to Core Lightning RPC socket (testnet4).
/// Override with env var: `CLN_RPC_SOCKET`.
const DEFAULT_CLN_RPC_SOCKET: &str = "/home/ugo/.lightning/testnet4/lightning-rpc";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cln_rpc_socket = std::env::var("CLN_RPC_SOCKET")
        .unwrap_or_else(|_| DEFAULT_CLN_RPC_SOCKET.to_string());
    info!(socket = %cln_rpc_socket, "connecting to Core Lightning");

    let client = match cln_rpc::ClnRpc::new(&cln_rpc_socket).await {
        Ok(c) => c,
        Err(e) => {
            error!(socket = %cln_rpc_socket, error = %e, "failed to connect to Core Lightning RPC");
            return;
        }
    };

    let shared_client = Arc::new(Mutex::new(client));
    let k1_store = Arc::new(Mutex::new(HashSet::new()));
    let app_state = AppState {
        client: shared_client.clone(),
        k1_store: k1_store.clone(),
    };

    let node_info = shared_client
        .lock()
        .await
        .call(cln_rpc::Request::Getinfo(cln_rpc::model::requests::GetinfoRequest {}))
        .await;
    match node_info {
        Ok(cln_rpc::model::Response::Getinfo(response)) => {
            let pubkey = response.id.to_string();
            NODE_URI
                .set(format!("{}@{}", pubkey, IP_ADDRESS))
                .expect("NODE_URI set once at startup");
            info!(pubkey = %pubkey, address = %IP_ADDRESS, socket = %cln_rpc_socket, "node URI initialized (same node as lightning-cli if same socket)");
        }
        Err(e) => {
            error!(error = %e, "failed to get node info from Core Lightning");
            return;
        }
        _ => {
            error!("unexpected RPC response type");
            return;
        }
    }

    // Register LNURL endpoints and shared state
    let app = Router::new()
        .route("/", get(health))
        .route("/health", get(health))
        .route("/request-channel", get(request_channel))
        .route("/open-channel", get(open_channel))
        .route("/request-withdraw", get(request_withdraw))
        .route("/withdraw", get(withdraw))
        .route("/lnurl-auth", get(lnurl_auth_request))
        .route("/lnurl-auth-callback", get(lnurl_auth_callback))
        .with_state(app_state);

    let bind_addr = "0.0.0.0:3000";
    // Bind to all interfaces so the server is reachable from other machines (e.g. WireGuard)
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            eprintln!("Port 3000 is already in use. Stop the other process (e.g. another LN_Server) or run: lsof -i :3000");
            return;
        }
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", bind_addr, e);
            return;
        }
    };
    info!(bind = %bind_addr, "LNURL server listening");
    // Serve all routes; state (CLN client + k1 store) is shared across handlers
    axum::serve(listener, app).await.unwrap();
}