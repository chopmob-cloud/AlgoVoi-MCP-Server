# MCP Server v1.7.0 — Production Readiness Notes

**Date:** 2026-05-29  
**Status:** Production-ready (not yet published)

---

## Changes made to reach production-ready state

### 1. Testnet payout address routing (Python + TypeScript)

**Files:** `python/algovoi_mcp/server.py`, `typescript/src/index.ts`

**Bug:** The `chain_env` mapping only listed 7 mainnet chains. Testnet chains
(`algorand_testnet`, `base_sepolia`, `solana_devnet`, etc.) had no env var entry,
so all testnet checkout requests fell back to the first configured mainnet address —
a Solana checkout on `base_sepolia` would get an Algorand mainnet address.

**Fix:**
- Extended `chain_env` (Python) / `CHAIN_ENV` (TypeScript) from 7 to 15 entries
  covering all 7 mainnet + 8 testnet chains.
- Added `_mainnet_sibling` / `MAINNET_SIBLING` dict and a second-pass loop that
  automatically fills any unset testnet key from its mainnet sibling. This means
  users who only configure mainnet vars still get the correct (mainnet) address
  reused for testnet chains, with no configuration required.
- Dedicated testnet vars (`ALGOVOI_PAYOUT_ALGORAND_TESTNET`, `_VOI_TESTNET`,
  `_HEDERA_TESTNET`, `_STELLAR_TESTNET`, `_BASE_SEPOLIA`, `_SOLANA_DEVNET`,
  `_TEMPO_TESTNET`, `_ARC_TESTNET`) override the mainnet sibling when set.

### 2. JWS truncation bug in redact.scrub (Python + TypeScript)

**Files:** `python/algovoi_mcp/redact.py`, `typescript/src/redact.ts`

**Bug:** `redact.scrub` truncated all string values longer than 512 chars and
appended `"... [truncated N chars]"` (with literal dots). Compact JWS tokens
(`compliance_receipt_jws`, `settlement_attestation_jws`, etc.) are 571+ chars
and were being truncated mid-signature, breaking their base64url encoding. When
the truncated string was split on `.`, the injected `...` separator created extra
parts, making `jws.split('.')` return 6 parts instead of 3 — corrupting the JWS.

**Fix:** Added `NO_TRUNCATE_KEYS` frozenset/Set containing all known JWS field
names and `mandate_b64`. The `scrub` function now passes the parent key context
through recursive calls; strings whose parent key is in `NO_TRUNCATE_KEYS` are
returned intact regardless of length.

**Impact:** Ed25519 JWS signatures are now cryptographically verifiable
end-to-end through the MCP server. The `_verify_ed25519_jws` function in the
test suite confirms this: it extracts the Ed25519 public key from the
`screen_provider_did` (`did:key:...`) in the JWS payload and verifies the
64-byte signature.

### 3. README — missing env vars

**File:** `README.md`

Added three missing mainnet payout vars (`ALGOVOI_PAYOUT_BASE`,
`ALGOVOI_PAYOUT_SOLANA`, `ALGOVOI_PAYOUT_TEMPO`) and all 8 testnet vars to the
env var reference table. Added a footnote explaining the mainnet sibling fallback
behaviour.

### 4. server.json encoding fix

**File:** `server.json`

Fixed mojibake em-dash (`â€"`) in the `ALGOVOI_MODE` description field that had
been corrupted by a character encoding mismatch.

### 5. Testnet wallets

**File:** `~/.secrets/testnet_wallets.env` (not in git)

Generated fresh payout wallets for all 8 testnet chains:
- Algorand testnet — via algosdk
- VOI testnet — via algosdk
- Hedera testnet — `0.0.2` (known treasury; Hedera requires on-chain account creation)
- Stellar testnet — via stellar_sdk; funded via Friendbot
- Base Sepolia — via eth_account (EVM)
- Solana devnet — via solders
- Tempo testnet — via eth_account (EVM)
- ARC testnet — via eth_account (EVM)

---

## Production readiness test suite

**File:** `tests/e2e/test_production_readiness.py`

15-section suite covering all production requirements:

| Section | Covers |
|---------|--------|
| A | All 29 tools listed (both Python + TypeScript) |
| B | `create_payment_link` on all 7 mainnet chains (`--live`) |
| C | `create_payment_link` on all 8 testnet chains (`--live`) |
| D | MPP / x402 / AP2 challenge shapes + verify |
| E | Substrate mode: `action_ref`, `compliance_receipt`, JWS |
| F | Standard mode: substrate keys stripped, verdicts kept |
| G | Mode consistency: same data regardless of `ALGOVOI_MODE` |
| H | Recurr authority lifecycle (`--live`) |
| I | A2A tools: `fetch_agent_card`, `send_a2a_message` |
| J | Discovery: `discover_resources`, `try_mpp_endpoint`, `get_compliance_attestation` |
| K | Webhook HMAC verification (valid, bad sig, non-JSON) |
| L | Schema rejection: bad args must error cleanly, no crash |
| M | `MCP_ENABLED_TOOLS` subset filtering enforced |
| N | Testnet env routing: server starts correctly with testnet vars |
| O | JWS integrity: Ed25519 signature cryptographically valid (live API) |

**Results (2026-05-29):**
```
Python:     ALL PRODUCTION READINESS CHECKS PASSED (0 failures)
TypeScript: ALL PRODUCTION READINESS CHECKS PASSED (0 failures)
```

Unit tests: 74/74 Python, 75/75 TypeScript.

---

## Not yet published

The packages are built and ready:
- `python/dist/algovoi_mcp-1.7.0-py3-none-any.whl`
- `python/dist/algovoi_mcp-1.7.0.tar.gz`
- `typescript/algovoi-mcp-server-1.7.0.tgz`

Publication to PyPI / npm is deliberately withheld pending the IP/licensing
decision documented in `project_mcp_1_7_0_ip_licensing_2026-05-28.md`.
