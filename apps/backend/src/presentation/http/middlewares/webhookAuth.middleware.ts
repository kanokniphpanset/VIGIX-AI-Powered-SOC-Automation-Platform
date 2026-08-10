import { Request, Response, NextFunction } from "express";

/**
 * webhookAuth.middleware.ts — validates a shared secret on inbound SIEM webhooks.
 * This is intentionally simple (a static header key) for the prototype stage.
 * Production hardening to layer on later: per-tenant keys stored in the DB,
 * HMAC request signing (verify a signature header instead of a raw secret),
 * IP allowlisting at the reverse proxy, and rate limiting.
 */
export function webhookAuth(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.SIEM_WEBHOOK_SECRET;
  const provided = req.header("x-webhook-secret");

  if (!expected) {
    res.status(500).json({ error: "SIEM_WEBHOOK_SECRET is not configured on the server" });
    return;
  }

  if (provided !== expected) {
    res.status(401).json({ error: "Invalid or missing webhook secret" });
    return;
  }

  next();
}
