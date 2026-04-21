/**
 * All 8 MCP tools exposed by the AlgoVoi MCP server.
 *
 * Each tool is a pure async function — the dispatcher in `index.ts` calls
 * the matching parser from `schemas.ts` first, so every function below
 * receives a validated, typed argument object.
 */

import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { AlgoVoiClient } from "./client.js";
import { IdempotencyCache } from "./idempotency.js";
import {
  NETWORKS,
  NETWORK_INFO,
  PROTOCOLS,
  type Network,
} from "./networks.js";
import type {
  CreatePaymentLinkInput,
  GenerateAp2MandateInput,
  GenerateMppChallengeInput,
  GenerateX402ChallengeInput,
  PrepareExtensionPaymentInput,
  VerifyAp2PaymentInput,
  VerifyMppReceiptInput,
  VerifyPaymentInput,
  VerifyWebhookInput,
  VerifyX402ProofInput,
} from "./schemas.js";

const MAX_WEBHOOK_BODY = 64 * 1024;

// Process-wide cache for create_payment_link idempotency.
const IDEMPOTENCY = new IdempotencyCache<Record<string, unknown>>();

// Exported for tests that want to clear cache state between runs.
export function _resetIdempotencyCacheForTests() {
  // `IDEMPOTENCY` is a const, but we can clear via Map semantics exposed
  // indirectly.  Set TTL-expired state by reconstructing — use a test-only
  // hook through the module's closure.
  (IDEMPOTENCY as unknown as { store: Map<string, unknown> }).store?.clear?.();
}

// ── 1. create_payment_link ────────────────────────────────────────────────────

export async function createPaymentLink(
  client: AlgoVoiClient,
  args: CreatePaymentLinkInput
) {
  if (args.idempotency_key) {
    const cached = IDEMPOTENCY.get(args.idempotency_key);
    if (cached) return cached;
  }
  const link = await client.createPaymentLink({
    amount:         args.amount,
    currency:       args.currency,
    label:          args.label,
    network:        args.network,
    redirectUrl:    args.redirect_url,
    idempotencyKey: args.idempotency_key,
  });
  const result = {
    checkout_url:      link.checkout_url,
    token:             link.token,
    chain:             link.chain,
    amount_microunits: link.amount_microunits,
    amount_display:    `${args.amount.toFixed(2)} ${args.currency.toUpperCase()}`,
  };
  if (args.idempotency_key) {
    IDEMPOTENCY.set(args.idempotency_key, result);
  }
  return result;
}

// ── 2. verify_payment ─────────────────────────────────────────────────────────

export async function verifyPayment(
  client: AlgoVoiClient,
  args: VerifyPaymentInput
) {
  if (args.tx_id) {
    const resp     = await client.verifyExtensionPayment(args.token, args.tx_id);
    const verified = resp.success === true;
    return {
      paid:   verified,
      status: verified ? "verified" : "unverified",
      error:  verified ? null : ((resp.error as string) ?? null),
    };
  }
  const resp = await client.verifyHostedReturn(args.token);
  return { paid: resp.paid, status: resp.status };
}

// ── 3. prepare_extension_payment ──────────────────────────────────────────────

export async function prepareExtensionPayment(
  client: AlgoVoiClient,
  args: PrepareExtensionPaymentInput
) {
  const link = await client.createPaymentLink({
    amount:   args.amount,
    currency: args.currency,
    label:    args.label,
    network:  args.network,
  });
  const info = NETWORK_INFO[args.network as Network];
  return {
    token:             link.token,
    checkout_url:      link.checkout_url,
    chain:             link.chain,
    amount_microunits: link.amount_microunits,
    asset_id:          info.asset_id,
    ticker:            info.asset,
    instructions:
      "Use the returned token with your client-side wallet flow, then call verify_payment " +
      "with the tx_id once the on-chain transfer is submitted.",
  };
}

// ── 4. verify_webhook ─────────────────────────────────────────────────────────

export function verifyWebhook(
  webhookSecretFromEnv: string | undefined,
  args: VerifyWebhookInput
) {
  if (!webhookSecretFromEnv) {
    return {
      valid:   false,
      payload: null,
      error:   "webhook_secret not configured (ALGOVOI_WEBHOOK_SECRET env var)",
    };
  }
  const bodyBytes = Buffer.from(args.raw_body, "utf8");
  if (bodyBytes.length > MAX_WEBHOOK_BODY) {
    return { valid: false, payload: null, error: "body exceeds 64 KiB cap" };
  }
  const expected = createHmac("sha256", webhookSecretFromEnv)
    .update(bodyBytes)
    .digest("base64");
  const given = Buffer.from(args.signature, "utf8");
  const exp   = Buffer.from(expected, "utf8");
  if (given.length !== exp.length || !timingSafeEqual(given, exp)) {
    return { valid: false, payload: null, error: "signature mismatch" };
  }
  try {
    return { valid: true, payload: JSON.parse(args.raw_body), error: null };
  } catch {
    return { valid: false, payload: null, error: "body is not valid JSON" };
  }
}

// ── 5. list_networks ──────────────────────────────────────────────────────────

export function listNetworks() {
  return {
    networks: Object.entries(NETWORK_INFO).map(([key, info]) => ({
      key,
      ...info,
    })),
    protocols: [...PROTOCOLS],
    note:      "Use `key` as the `network` argument for other AlgoVoi tools.",
  };
}

// ── 6. generate_mpp_challenge ─────────────────────────────────────────────────

const CAIP2: Record<string, string> = {
  // Mainnet
  algorand_mainnet:      "algorand:mainnet",
  voi_mainnet:           "voi:mainnet",
  hedera_mainnet:        "hedera:mainnet",
  stellar_mainnet:       "stellar:pubnet",
  algorand_mainnet_algo: "algorand:mainnet",
  voi_mainnet_voi:       "voi:mainnet",
  hedera_mainnet_hbar:   "hedera:mainnet",
  stellar_mainnet_xlm:   "stellar:pubnet",
  // Testnet
  algorand_testnet:      "algorand:testnet",
  voi_testnet:           "voi:testnet",
  hedera_testnet:        "hedera:testnet",
  stellar_testnet:       "stellar:testnet",
  algorand_testnet_algo: "algorand:testnet",
  voi_testnet_voi:       "voi:testnet",
  hedera_testnet_hbar:   "hedera:testnet",
  stellar_testnet_xlm:   "stellar:testnet",
};

export function generateMppChallenge(
  client: AlgoVoiClient,
  args: GenerateMppChallengeInput
) {
  const nets      = args.networks ?? ["algorand_mainnet"];
  const expiresIn = args.expires_in_seconds ?? 300;
  const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();

  const accepts = nets.map((n) => ({
    scheme:   "algovoi",
    network:  CAIP2[n],
    asset:    NETWORK_INFO[n as Network].asset_id,
    receiver: client.payoutAddressFor(n),
    amount:   String(args.amount_microunits),
    decimals: NETWORK_INFO[n as Network].decimals,
  }));

  const requestB64 = Buffer.from(
    JSON.stringify({
      intent:   "charge",
      resource: args.resource_id,
      accepts,
      expires:  expiresAt,
    }),
    "utf8"
  ).toString("base64");

  const idInput     = `${client.tenantId}|${args.resource_id}|${expiresAt}`;
  const challengeId = createHmac("sha256", randomBytes(16).toString("hex"))
    .update(idInput)
    .digest("hex")
    .slice(0, 16);

  const wwwAuthenticate =
    `Payment realm="AlgoVoi", id="${challengeId}", method="algovoi", ` +
    `intent="charge", request="${requestB64}", expires="${expiresAt}"`;

  const xPaymentRequired = Buffer.from(
    JSON.stringify({ accepts, expires: expiresAt }),
    "utf8"
  ).toString("base64");

  return {
    status_code: 402,
    headers: {
      "WWW-Authenticate":   wwwAuthenticate,
      "X-Payment-Required": xPaymentRequired,
    },
    challenge_id: challengeId,
    accepts,
    expires: expiresAt,
    note:
      "Return this 402 response from your API. The client must pay on-chain " +
      "and re-send with Authorization: Payment <token>.",
  };
}

// ── 7. verify_mpp_receipt ─────────────────────────────────────────────────────

export async function verifyMppReceipt(
  client: AlgoVoiClient,
  args: VerifyMppReceiptInput
) {
  const resp = await client.verifyMppReceipt(
    args.resource_id,
    args.tx_id,
    args.network
  );
  return {
    verified: Boolean((resp as any).verified ?? (resp as any).valid),
  };
}

// ── 8. verify_x402_proof ──────────────────────────────────────────────────────

export async function verifyX402Proof(
  client: AlgoVoiClient,
  args: VerifyX402ProofInput
) {
  const resp = await client.verifyX402Proof(args.proof, args.network);
  return {
    verified: Boolean((resp as any).verified ?? (resp as any).valid),
  };
}

// ── 9. generate_x402_challenge ────────────────────────────────────────────────

export function generateX402Challenge(
  client: AlgoVoiClient,
  args: GenerateX402ChallengeInput
) {
  const network    = args.network ?? "algorand_mainnet";
  const info       = NETWORK_INFO[network as Network];
  const expiresIn  = args.expires_in_seconds ?? 300;
  const expiresAt  = new Date(Date.now() + expiresIn * 1000).toISOString();

  const payload = {
    version:           "1",
    scheme:            "exact",
    networkId:         CAIP2[network],
    maxAmountRequired: String(args.amount_microunits),
    resource:          args.resource,
    description:       args.description ?? "",
    mimeType:          "application/json",
    payTo:             client.payoutAddressFor(network),
    maxTimeoutSeconds: expiresIn,
    asset:             info.asset_id,
    decimals:          info.decimals,
    extra:             {},
  };

  const xPaymentRequired = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");

  return {
    status_code: 402,
    headers: {
      "X-Payment-Required": xPaymentRequired,
    },
    payload,
    expires: expiresAt,
    note:
      "Return this 402 response from your API. The client must pay on-chain " +
      "and re-send with X-Payment: <base64-proof>, then verify with verify_x402_proof.",
  };
}

// ── 10. generate_ap2_mandate ──────────────────────────────────────────────────

export function generateAp2Mandate(
  client: AlgoVoiClient,
  args: GenerateAp2MandateInput
) {
  const network    = args.network ?? "algorand_mainnet";
  const info       = NETWORK_INFO[network as Network];
  const expiresIn  = args.expires_in_seconds ?? 300;
  const expiresAt  = new Date(Date.now() + expiresIn * 1000).toISOString();

  const idInput  = `${client.tenantId}|${args.resource_id}|${expiresAt}`;
  const mandateId = createHmac("sha256", randomBytes(16).toString("hex"))
    .update(idInput)
    .digest("hex")
    .slice(0, 16);

  const mandate = {
    version:     "0.1",
    type:        "PaymentMandate",
    mandate_id:  mandateId,
    payee: {
      address:  client.payoutAddressFor(network),
      network:  CAIP2[network],
      asset_id: info.asset_id,
    },
    amount: {
      value:    String(args.amount_microunits),
      decimals: info.decimals,
    },
    resource:    args.resource_id,
    description: args.description ?? "",
    expires:     expiresAt,
    protocol:    "algovoi-ap2/0.1",
  };

  const mandateB64 = Buffer.from(JSON.stringify(mandate), "utf8").toString("base64");

  return {
    mandate_id:  mandateId,
    mandate,
    mandate_b64: mandateB64,
    expires:     expiresAt,
    note:
      "Include mandate_b64 in the AP2-Payment-Required header. " +
      "The paying agent submits on-chain, then call verify_ap2_payment " +
      "with the mandate_id and tx_id.",
  };
}

// ── 11. verify_ap2_payment ────────────────────────────────────────────────────

export async function verifyAp2Payment(
  client: AlgoVoiClient,
  args: VerifyAp2PaymentInput
) {
  const resp = await client.verifyAp2Payment(args.mandate_id, args.tx_id, args.network);
  return {
    verified: Boolean((resp as any).verified ?? (resp as any).valid),
  };
}

// ── Tool schemas (MCP wire — JSON Schema) ─────────────────────────────────────

export const TOOL_SCHEMAS = [
  {
    name: "create_payment_link",
    description:
      "Create a hosted AlgoVoi checkout URL for a given amount and chain. " +
      "Use this when the customer will pay via a hosted checkout page (redirect flow). " +
      "For in-page browser-wallet flows use prepare_extension_payment instead. " +
      "For machine-to-machine agent payments use generate_mpp_challenge, generate_x402_challenge, or generate_ap2_mandate. " +
      "Returns a short token and public URL the customer visits to pay in USDC or native tokens (Algorand / VOI / Hedera / Stellar). " +
      "After payment, verify settlement with verify_payment.",
    inputSchema: {
      type: "object",
      properties: {
        amount:   { type: "number",  description: "Payment amount in fiat major units (e.g. 5.00 for $5.00 USD). Converted to on-chain micro-units automatically." },
        currency: { type: "string",  description: "ISO 4217 currency code — e.g. USD, GBP, EUR. Determines the fiat price shown to the customer." },
        label:    { type: "string",  description: 'Short order label shown on the checkout page (e.g. "Order #123" or "Premium access — 30 days").' },
        network:  { type: "string",  enum: [...NETWORKS], description: "Blockchain network the customer will pay on. Use list_networks to see all supported options." },
        redirect_url:    { type: "string", description: "Optional HTTPS URL to redirect the customer to after a successful payment." },
        idempotency_key: { type: "string", description: "Optional 16–64 char client-generated token. Duplicate calls with the same key within 24 h return the original checkout URL without creating a new link." },
      },
      required: ["amount", "currency", "label", "network"],
      additionalProperties: false,
    },
  },
  {
    name: "verify_payment",
    description:
      "Verify that a payment for a given checkout token has settled. Returns paid/unpaid status. If tx_id is supplied, verifies that specific on-chain transaction; otherwise uses hosted-checkout status.",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "Short token returned by create_payment_link." },
        tx_id: { type: "string", description: "Optional on-chain transaction ID to verify against the token." },
      },
      required: ["token"],
      additionalProperties: false,
    },
  },
  {
    name: "prepare_extension_payment",
    description:
      "Prepare an in-page browser-wallet payment for Algorand or VOI (AVM chains only — not Hedera or Stellar). " +
      "Use this instead of create_payment_link when the user already has a browser wallet extension (e.g. Defly, Pera, Kibisis) " +
      "and you want the payment to happen in-page without a redirect. " +
      "Returns the checkout token, chain parameters, and asset details the frontend needs to call the wallet's sign-and-submit API. " +
      "After the wallet submits the transaction, verify settlement with verify_payment providing both the token and the on-chain tx_id.",
    inputSchema: {
      type: "object",
      properties: {
        amount:   { type: "number",  description: "Payment amount in fiat major units (e.g. 5.00 for $5.00 USD). Converted to on-chain micro-units automatically." },
        currency: { type: "string",  description: "ISO 4217 currency code — e.g. USD, GBP, EUR." },
        label:    { type: "string",  description: 'Short label describing the payment (e.g. "Order #123"). Shown to the user in the wallet approval dialog.' },
        network:  { type: "string",  enum: ["algorand_mainnet", "voi_mainnet", "algorand_mainnet_algo", "voi_mainnet_voi", "algorand_testnet", "voi_testnet", "algorand_testnet_algo", "voi_testnet_voi"], description: "AVM network to pay on. Use algorand_mainnet or voi_mainnet for USDC; algorand_mainnet_algo or voi_mainnet_voi for native tokens." },
      },
      required: ["amount", "currency", "label", "network"],
      additionalProperties: false,
    },
  },
  {
    name: "verify_webhook",
    description:
      "Verify an AlgoVoi webhook HMAC-SHA256 signature. Returns {valid: true, payload: <parsed-json>} if the signature matches the server's configured webhook secret (ALGOVOI_WEBHOOK_SECRET env var — never passed as a tool argument).",
    inputSchema: {
      type: "object",
      properties: {
        raw_body:  { type: "string", description: "Raw webhook POST body as a UTF-8 string." },
        signature: { type: "string", description: "Base64 signature from the X-AlgoVoi-Signature header." },
      },
      required: ["raw_body", "signature"],
      additionalProperties: false,
    },
  },
  {
    name: "list_networks",
    description:
      "List the blockchain networks AlgoVoi supports, with asset IDs, decimals, and CAIP-2 identifiers. Offline tool — no API call.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "generate_mpp_challenge",
    description:
      "Generate an IETF MPP (draft-ryan-httpauth-payment) 402 challenge that an API server can return to gate a resource. Produces the WWW-Authenticate and X-Payment-Required headers plus the challenge_id to echo.",
    inputSchema: {
      type: "object",
      properties: {
        resource_id:       { type: "string",  description: 'Logical resource identifier (e.g. "premium-kb").' },
        amount_microunits: { type: "integer", description: "Amount in asset micro-units (1 USDC = 1_000_000)." },
        networks: {
          type: "array",
          items: { type: "string", enum: [...NETWORKS] },
          description: 'Networks to accept. Defaults to ["algorand_mainnet"] if omitted.',
        },
        expires_in_seconds: { type: "integer", description: "Challenge TTL; default 300." },
      },
      required: ["resource_id", "amount_microunits"],
      additionalProperties: false,
    },
  },
  {
    name: "verify_mpp_receipt",
    description:
      "Verify an MPP (IETF draft-ryan-httpauth-payment) receipt after a client has paid a challenge. " +
      "Use this after generate_mpp_challenge: once the client re-sends the request with a payment transaction ID, " +
      "call this tool to confirm the on-chain transaction paid the correct amount to the tenant's payout address. " +
      "Returns {verified: true} on success. For x402-protocol flows use verify_x402_proof instead; " +
      "for hosted checkout flows use verify_payment instead.",
    inputSchema: {
      type: "object",
      properties: {
        resource_id: { type: "string", description: "The resource_id originally passed to generate_mpp_challenge — links the transaction to the specific gated resource." },
        tx_id:       { type: "string", description: "On-chain transaction ID provided by the client in the X-Payment header or equivalent." },
        network:     { type: "string", enum: [...NETWORKS], description: "Blockchain network the transaction was submitted on. Must match the network in the original challenge." },
      },
      required: ["resource_id", "tx_id", "network"],
      additionalProperties: false,
    },
  },
  {
    name: "verify_x402_proof",
    description:
      "Verify a base64-encoded x402 (HTTP 402) payment proof from a client's X-Payment request header. " +
      "Use this after generate_x402_challenge: the client pays on-chain and re-sends the request with " +
      "X-Payment: <base64-proof>; pass that header value here to confirm the payment. " +
      "Returns {verified: true} if the proof corresponds to a confirmed on-chain transfer of the correct amount " +
      "to the tenant's payout address. For MPP-protocol flows use verify_mpp_receipt; " +
      "for hosted checkout flows use verify_payment.",
    inputSchema: {
      type: "object",
      properties: {
        proof:   { type: "string", description: "Base64-encoded payment proof from the client's X-Payment request header." },
        network: { type: "string", enum: [...NETWORKS], description: "Blockchain network the proof was submitted on. Must match the network in the original x402 challenge." },
      },
      required: ["proof", "network"],
      additionalProperties: false,
    },
  },
  {
    name: "generate_x402_challenge",
    description:
      "Generate an x402 (spec v1) 402 Payment Required response for gating a resource. Returns the X-Payment-Required header value and full payload. The client must pay on-chain and re-send with X-Payment: <base64-proof>, then verify with verify_x402_proof.",
    inputSchema: {
      type: "object",
      properties: {
        resource:           { type: "string",  description: "Resource URL or identifier being gated." },
        amount_microunits:  { type: "integer", description: "Amount in asset micro-units (1 USDC = 1_000_000)." },
        network:            { type: "string",  enum: [...NETWORKS], description: "Network to accept. Defaults to algorand_mainnet." },
        expires_in_seconds: { type: "integer", description: "Challenge TTL in seconds; default 300." },
        description:        { type: "string",  description: "Optional human-readable description shown in the payment prompt." },
      },
      required: ["resource", "amount_microunits"],
      additionalProperties: false,
    },
  },
  {
    name: "generate_ap2_mandate",
    description:
      "Generate an AP2 v0.1 PaymentMandate for agent-to-agent payment. Returns the mandate object and its base64 encoding for the AP2-Payment-Required header. After the paying agent submits on-chain, call verify_ap2_payment to confirm.",
    inputSchema: {
      type: "object",
      properties: {
        resource_id:        { type: "string",  description: "Logical resource or task identifier." },
        amount_microunits:  { type: "integer", description: "Amount in asset micro-units (1 USDC = 1_000_000)." },
        network:            { type: "string",  enum: [...NETWORKS], description: "Network to accept. Defaults to algorand_mainnet." },
        expires_in_seconds: { type: "integer", description: "Mandate TTL in seconds; default 300." },
        description:        { type: "string",  description: "Optional description of the resource or task." },
      },
      required: ["resource_id", "amount_microunits"],
      additionalProperties: false,
    },
  },
  {
    name: "verify_ap2_payment",
    description:
      "Verify an AP2 payment — returns {verified: true} if the on-chain transaction satisfies the mandate's amount and recipient.",
    inputSchema: {
      type: "object",
      properties: {
        mandate_id: { type: "string", description: "mandate_id returned by generate_ap2_mandate — links the transaction to the specific AP2 payment mandate." },
        tx_id:      { type: "string", description: "On-chain transaction ID submitted by the paying agent after settling the mandate." },
        network:    { type: "string", enum: [...NETWORKS], description: "Blockchain network the transaction was submitted on. Must match the network in the original mandate." },
      },
      required: ["mandate_id", "tx_id", "network"],
      additionalProperties: false,
    },
  },
] as const;
