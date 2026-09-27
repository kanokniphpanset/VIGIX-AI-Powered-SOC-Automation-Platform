import { createHmac, timingSafeEqual } from "node:crypto";
import { Request, Response, NextFunction } from "express";

/** Raw request bytes, kept by express.json's `verify` hook in main.ts so the signature is checked on exactly what was sent. */
export type RequestWithRawBody = Request & { rawBody?: Buffer };

/** Keeps the raw body on the request — pass as `express.json({ verify: keepRawBody })`. */
export function keepRawBody(req: Request, _res: Response, buf: Buffer): void {
  (req as RequestWithRawBody).rawBody = buf;
}

/**
 * webhookAuth.middleware.ts — verifies inbound SIEM webhooks (POST /api/v1/webhooks/siem/:source).
 *
 * The sender signs the raw JSON body with HMAC-SHA256 using the shared SIEM_WEBHOOK_SECRET and sends
 * `X-Webhook-Signature: sha256=<hex>` — the scheme infra/wazuh-integration/custom-vigix.py (the Wazuh
 * integration) and scripts/send-test-alert.sh already use. The secret itself never travels on the wire.
 *
 * Fails closed: with no SIEM_WEBHOOK_SECRET configured the webhook rejects everything (500) rather than
 * accepting unsigned alerts. Later hardening: per-tenant keys, IP allowlisting at the proxy, rate limiting.
 */
export function webhookAuth(req: Request, res: Response, next: NextFunction): void {
  const secret = process.env.SIEM_WEBHOOK_SECRET;
  if (!secret) {
    res.status(500).json({ error: "SIEM_WEBHOOK_SECRET is not configured on the server" });
    return;
  }

  const header = req.header("x-webhook-signature") ?? "";
  const match = /^sha256=([0-9a-f]{64})$/i.exec(header.trim());
  const rawBody = (req as RequestWithRawBody).rawBody;
  if (!match || !rawBody) {
    res.status(401).json({ error: "Invalid or missing webhook signature" });
    return;
  }

  const expected = createHmac("sha256", secret).update(rawBody).digest();
  const provided = Buffer.from(match[1], "hex");
  if (!timingSafeEqual(expected, provided)) {
    res.status(401).json({ error: "Invalid or missing webhook signature" });
    return;
  }

  next();
}
