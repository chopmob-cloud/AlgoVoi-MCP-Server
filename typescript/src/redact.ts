/**
 * Output sanitisation for tool responses.
 *
 *   - Sensitive keys (api_key, mnemonic, webhook_secret, …) have their
 *     values replaced with `"[REDACTED]"`.
 *   - String values longer than `MAX_STR` are truncated with a visible
 *     suffix — defends against prompt-injection payloads smuggled via
 *     attacker-controlled blockchain data (§4.4 of ALGOVOI_MCP.md).
 *
 * The public checkout `token` is NOT in the sensitive list: it is a
 * short opaque ID meant to be shown to the user, not a credential.
 */

export const MAX_STR = 512;

// Cryptographic fields that must never be truncated — truncation corrupts
// base64url-encoded JWS signatures and other compact binary encodings.
export const NO_TRUNCATE_KEYS: ReadonlySet<string> = new Set([
  "compliance_receipt_jws",
  "settlement_attestation_jws",
  "refund_receipt_jws",
  "cancellation_receipt_jws",
  "ctq_response_jws",
  "mandate_b64",
  "proof",
]);

export const SENSITIVE_KEYS: ReadonlySet<string> = new Set([
  "mnemonic",
  "private_key",
  "privatekey",
  "secret",
  "api_key",
  "apikey",
  "password",
  "passwd",
  "authorization",
  "auth",
  "webhook_secret",
  "webhooksecret",
  "access_token",
  "refresh_token",
  "bearer_token",
  "algovoi_api_key",
  "algovoi_webhook_secret",
]);

const REDACTED = "[REDACTED]";

export function scrub<T>(obj: T): T {
  return _scrub(obj) as T;
}

function _scrub(obj: unknown, parentKey = ""): unknown {
  if (obj === null || obj === undefined) return obj;

  if (Array.isArray(obj)) {
    return obj.map((x) => _scrub(x, parentKey));
  }

  if (typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (SENSITIVE_KEYS.has(k.toLowerCase())) {
        out[k] = REDACTED;
      } else {
        out[k] = _scrub(v, k);
      }
    }
    return out;
  }

  if (typeof obj === "string" && obj.length > MAX_STR) {
    if (NO_TRUNCATE_KEYS.has(parentKey.toLowerCase())) {
      return obj; // preserve intact — truncation corrupts crypto encodings
    }
    const extra = obj.length - MAX_STR;
    return obj.slice(0, MAX_STR) + `... [truncated ${extra} chars]`;
  }

  return obj;
}
