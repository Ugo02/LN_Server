# LN_Server

HTTP server that exposes **LNURL** endpoints for Lightning Network, backed by a local **Core Lightning** (CLN) node. It implements LNURL-channel, LNURL-withdraw, and LNURL-auth (LUD-04) so that clients can request channel opens, withdrawals, and authentication against your node.

---

## Features

| Flow | Endpoints | Description |
|------|-----------|-------------|
| **LNURL-channel** | `GET /request-channel`, `GET /open-channel` | Issue a channel-open challenge; optionally open the channel in one shot when `remoteid` is provided. |
| **LNURL-withdraw** | `GET /request-withdraw`, `GET /withdraw` | Issue a withdraw challenge; optionally pay the invoice in one shot when `pr` is provided. |
| **LNURL-auth** (LUD-04) | `GET /lnurl-auth`, `GET /lnurl-auth-callback` | Issue a 32-byte hex challenge; verify ECDSA signature with the client’s linking key. |

Health check: `GET /` or `GET /health` returns `OK`.

Single-use challenge tokens (k1) are stored in memory. The server talks to Core Lightning via its **Unix socket RPC** (e.g. `~/.lightning/testnet4/lightning-rpc`).

---

## Prerequisites

- **Rust** (e.g. 1.70+; `rustup` recommended).
- **Core Lightning** (CLN) running on **testnet4**, with its RPC socket available (e.g. `~/.lightning/testnet4/lightning-rpc`).
- **Bitcoin Core** (bitcoind) on **testnet4**, used by Core Lightning for on-chain data and funding.

The server does not run bitcoind or lightningd; it only connects to an existing CLN node.

---

## Configuration

Before building or running, set the following in `src/main.rs` (or make them configurable via env/file if you prefer):

| Constant | Meaning | Example |
|----------|---------|--------|
| `IP_ADDRESS` | Public address of your node (host:port for Lightning P2P). Must be reachable by clients. | `192.168.27.73:49735` (WireGuard) or `YOUR_VPS_IP:49735` |
| `CALLBACK_URL` | Base URL of this HTTP server; used in LNURL callback fields. Must be reachable by clients. | `http://192.168.27.73:3000/` or `https://your-domain.com/` |

At runtime you can override the Core Lightning RPC socket:

```bash
export CLN_RPC_SOCKET=/path/to/lightning-rpc
cargo run
```

Default socket path in code: `/home/ugo/.lightning/testnet4/lightning-rpc`.

---

## Build and run

```bash
cargo build --release
cargo run
```

The server binds to `0.0.0.0:3000`. Ensure:

- Your CLN node is running (testnet4).
- Port **3000** is reachable by clients (firewall, port forwarding, or VPN as needed).
- If you run behind WSL2 and clients use your Windows/VPN IP, you may need a **port proxy** on Windows so that traffic to `YOUR_IP:3000` is forwarded to WSL (see deployment notes below).

If port 3000 is already in use, the process exits with a clear message; free the port (e.g. `lsof -i :3000`, `kill PID`) or run another instance on a different port (would require a code change).

---

## API overview

| Method | Path | Query / behaviour |
|--------|------|-------------------|
| GET | `/`, `/health` | Health check; returns `OK`. |
| GET | `/request-channel` | Returns `uri`, `callback`, `k1`, `tag`. Optional: `remoteid`, `private` → open channel immediately and return funding result. |
| GET | `/open-channel` | `remoteid`, `k1`, `private` → validate k1, then call CLN `fundchannel`. |
| GET | `/request-withdraw` | Returns `callback`, `k1`, `tag`, `minWithdrawable`, `maxWithdrawable`. Optional: `pr` (BOLT11) → pay invoice immediately and return status. |
| GET | `/withdraw` | `k1`, `pr` → validate k1 (single-use), then pay `pr` via CLN. |
| GET | `/lnurl-auth` | Returns `tag`, `k1` (32 bytes hex), `callback` (LUD-04). |
| GET | `/lnurl-auth-callback` | `k1`, `sig`, `key` → verify ECDSA(sig, k1, key), then return OK or error (LUD-04). |

All JSON request/response shapes follow the usual LNURL/LUD conventions (camelCase where specified by the specs).

---

## One-shot vs two-step flows

- **Channel**: A client can call only `GET /request-channel?remoteid=NODE_ID&private=false`; the server opens the channel and returns the funding result in the same response. Or it can call `request-channel` (no params), then `open-channel` with the returned `k1` and its node id.
- **Withdraw**: A client can call only `GET /request-withdraw?pr=BOLT11` (with proper encoding); the server pays the invoice and returns status. Or it can call `request-withdraw`, then the withdraw callback with `k1` and `pr`.
- **Auth**: Always two steps: client gets the challenge from `lnurl-auth`, then calls `lnurl-auth-callback` with `k1`, signature, and linking public key (LUD-04).

---

## Testing with a client

Any HTTP client (e.g. `curl`) or an LNURL-capable wallet/client can call the endpoints above. Example health check:

```bash
curl -s http://YOUR_SERVER:3000/health
```

For full flows (channel, withdraw, auth), use a client that implements LNURL (e.g. a course client that calls `request-channel`, `request-withdraw`, `lnurl-auth` and their callbacks). Ensure the client uses the same base URL (`CALLBACK_URL`) and that your node is reachable at `IP_ADDRESS` for channel opens.

---

## Project layout

```
LN_Server/
├── Cargo.toml
├── README.md           # This file
└── src/
    └── main.rs         # LNURL routes, CLN RPC, k1 store, auth verification
```

Dependencies: **axum** (HTTP), **tokio** (async), **cln-rpc** (Core Lightning RPC), **serde**, **uuid**, **rand**, **hex**, **secp256k1** (LUD-04 auth), **tracing** (logging).

---

## License / context

This project is developed for an educational context (Lightning Network / LNURL). Adjust configuration and deployment to your environment (testnet4, WireGuard, VPS, etc.) as needed.
