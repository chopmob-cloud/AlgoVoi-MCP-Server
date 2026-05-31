> **AlgoVoi is available for acquisition** — [docs.algovoi.co.uk/acquisition](https://docs.algovoi.co.uk/acquisition)

---

# AlgoVoi MCP Server

[![PyPI](https://img.shields.io/pypi/v/algovoi-mcp?label=PyPI)](https://pypi.org/project/algovoi-mcp/)
[![npm](https://img.shields.io/npm/v/@algovoi/mcp-server?label=npm)](https://www.npmjs.com/package/@algovoi/mcp-server)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)
[![Agent Trust Bench](https://img.shields.io/badge/Agent_Trust_Bench-128%2F138_Passed-238636)](https://agent-trust-bench.algovoi.co.uk)

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes AlgoVoi's payment infrastructure as tools any MCP client can call — Claude Desktop, Claude Code, Cursor, Windsurf, or any other MCP-compatible assistant.

Ships as **two packages**:

| Package | Install | Command |
|---------|---------|---------|
| [**TypeScript**](./typescript) | `npm i -g @algovoi/mcp-server` | `npx -y @algovoi/mcp-server` |
| [**Python**](./python) | `pip install algovoi-mcp` | `uvx algovoi-mcp` or `algovoi-mcp` |

Both expose the **same 29 tools** and the same API surface — pick whichever runtime your client prefers.

---

## 29 tools

| # | Tool | What it does |
|---|------|-------------|
| 1 | `create_payment_link` | Hosted-checkout URL for a given amount + chain |
| 2 | `verify_payment` | Verify a checkout token (optionally with a tx_id) |
| 3 | `prepare_extension_payment` | In-page wallet-flow params (Algorand / VOI) |
| 4 | `verify_webhook` | HMAC-SHA256 signature check for AlgoVoi webhooks |
| 5 | `list_networks` | Supported chains + asset IDs (offline, no API call) |
| 6 | `generate_mpp_challenge` | IETF MPP 402 `WWW-Authenticate` headers + challenge_id |
| 7 | `verify_mpp_receipt` | Verify an MPP on-chain receipt |
| 8 | `verify_x402_proof` | Verify an x402 base64 payment proof |
| 9 | `generate_x402_challenge` | x402 `X-Payment-Required` 402 headers + payload |
| 10 | `generate_ap2_mandate` | AP2 v0.1 `PaymentMandate` for AI agent payment flows |
| 11 | `verify_ap2_payment` | Verify an AP2 mandate payment receipt |
| 12 | `try_mpp_endpoint` | Probe any URL for MPP/x402 payment requirements |
| 13 | `discover_resources` | Browse the public AlgoVoi payment resource catalogue |
| 14 | `screen_recipient` | Compliance screen a wallet address (sanctions / risk) |
| 15 | `get_compliance_attestation` | Fetch AlgoVoi's live compliance posture document |
| 16 | `compliance_trust_query` | Composite trust verdict (TRUSTED/PROVISIONAL/UNTRUSTED) over a chain of substrate receipts |
| 17 | `try_mpp_subscription` | Probe an MPP subscription URL; parse the 402 subscription terms |
| 18 | `list_mpp_subscriptions` | List a tenant's MPP subscriptions |
| 19 | `cancel_mpp_subscription` | Cancel an active MPP subscription |
| 20–29 | *(Tier 2 recurring authorities)* | `create_recurring_authority`, `get_authority`, `list_authorities`, `confirm_authority`, `revoke_authority`, `pause_authority`, `resume_authority`, `manual_pull` + protocol helpers |

Supported networks: **Algorand**, **VOI**, **Hedera**, **Stellar**, **Base**, **Solana**, **Tempo** (USDC on all seven).

### Response model — `ALGOVOI_MODE`

Set `ALGOVOI_MODE` to choose how much detail tool results carry:

| Mode | Behaviour |
|------|-----------|
| `substrate` *(default)* | Tools return AlgoVoi substrate primitives — `action_ref`, Ed25519-signed `compliance_receipt` / `settlement_attestation`, and the composite trust-query hash + signed `ctq_response`. |
| `standard` | Those substrate-only keys are stripped, leaving the bare x402 / MPP / AP2 standard response shape. The verdict fields (`verdict`, `reasons`, `trust_outcome`, `paid`) are preserved. |

The underlying API always returns substrate fields (they are additive) — `standard` simply filters them client-side, so you can A/B the two models by flipping one env var.

---

## Two ways to connect

### Option A — AlgoVoi Cloud (recommended)

[AlgoVoi Cloud](https://dash.algovoi.co.uk) is the control plane for all your integrations — WooCommerce, Zapier, n8n, and MCP all in one dashboard. Point `ALGOVOI_API_BASE` at `https://cloud.algovoi.co.uk` and your single `algv_...` API key covers every integration — no tenant ID or payout addresses needed (they're stored in the dashboard).

```json
{
  "mcpServers": {
    "algovoi": {
      "command": "npx",
      "args": ["-y", "@algovoi/mcp-server"],
      "env": {
        "ALGOVOI_API_KEY": "algv_...",
        "ALGOVOI_API_BASE": "https://cloud.algovoi.co.uk"
      }
    }
  }
}
```

Every payment Claude creates appears in your Cloud dashboard alongside payments from every other platform. One place to see everything.

Sign up free at [dash.algovoi.co.uk](https://dash.algovoi.co.uk).

---

### Option B — AlgoVoi direct

Connect straight to the AlgoVoi API with your `algv_...` key and tenant ID.

Both packages read the same env vars:

| Var | Required | Purpose |
|-----|----------|---------|
| `ALGOVOI_API_KEY` | ✅ | `algv_...` API key from the AlgoVoi dashboard |
| `ALGOVOI_TENANT_ID` | ✅ | Tenant UUID from the AlgoVoi dashboard |
| `ALGOVOI_PAYOUT_ALGORAND` | ✅* | Algorand mainnet payout wallet address |
| `ALGOVOI_PAYOUT_VOI` | ✅* | VOI mainnet payout wallet address |
| `ALGOVOI_PAYOUT_HEDERA` | ✅* | Hedera mainnet payout account (e.g. `0.0.123456`) |
| `ALGOVOI_PAYOUT_STELLAR` | ✅* | Stellar mainnet payout address (`G...`) |
| `ALGOVOI_PAYOUT_BASE` | ✅* | Base mainnet payout address (`0x...`) |
| `ALGOVOI_PAYOUT_SOLANA` | ✅* | Solana mainnet payout address |
| `ALGOVOI_PAYOUT_TEMPO` | ✅* | Tempo mainnet payout address (`0x...`) |
| `ALGOVOI_PAYOUT_ADDRESS` | — | Universal fallback if per-chain vars are not set |
| `ALGOVOI_PAYOUT_ALGORAND_TESTNET` | — | Algorand testnet payout address (falls back to mainnet if unset) |
| `ALGOVOI_PAYOUT_VOI_TESTNET` | — | VOI testnet payout address |
| `ALGOVOI_PAYOUT_HEDERA_TESTNET` | — | Hedera testnet payout account |
| `ALGOVOI_PAYOUT_STELLAR_TESTNET` | — | Stellar testnet payout address |
| `ALGOVOI_PAYOUT_BASE_SEPOLIA` | — | Base Sepolia payout address |
| `ALGOVOI_PAYOUT_SOLANA_DEVNET` | — | Solana devnet payout address |
| `ALGOVOI_PAYOUT_TEMPO_TESTNET` | — | Tempo testnet payout address |
| `ALGOVOI_PAYOUT_ARC_TESTNET` | — | ARC testnet payout address |
| `ALGOVOI_WEBHOOK_SECRET` | — | For `verify_webhook` |
| `ALGOVOI_API_BASE` | — | Override the AlgoVoi API base URL (default: `https://api.algovoi.co.uk`) |
| `ALGOVOI_MODE` | — | Response model: `substrate` (default) or `standard` — see "Response model" above |

**\*** At least one per-chain address (or `ALGOVOI_PAYOUT_ADDRESS` as fallback) is required. Testnet vars are optional — if unset, the mainnet sibling address is reused.

**Auth is env-var only.** Secrets never pass through tool arguments — the MCP client never sees the API key.

Sign up at [www.algovoi.co.uk](https://www.algovoi.co.uk) to get your API key and tenant ID.

```json
{
  "mcpServers": {
    "algovoi": {
      "command": "npx",
      "args": ["-y", "@algovoi/mcp-server"],
      "env": {
        "ALGOVOI_API_KEY": "algv_...",
        "ALGOVOI_TENANT_ID": "...",
        "ALGOVOI_PAYOUT_ALGORAND": "<your-algorand-address>",
        "ALGOVOI_PAYOUT_VOI":      "<your-voi-address>",
        "ALGOVOI_PAYOUT_HEDERA":   "0.0.<your-account>",
        "ALGOVOI_PAYOUT_STELLAR":  "G<your-stellar-address>"
      }
    }
  }
}
```

For the Python package, swap `"command": "uvx", "args": ["algovoi-mcp"]`.

Config file locations:
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Claude Code**: `~/.claude.json`
- **Cursor**: `~/.cursor/mcp.json`

---

## Testing

```bash
# TypeScript unit tests
cd typescript && npm test

# Python unit tests
cd python && pytest

# Stdio integration smoke — boots both servers and confirms all 29 tools list
python smoke_stdio.py
```

---

Licensed under the [MIT License](./LICENSE).
