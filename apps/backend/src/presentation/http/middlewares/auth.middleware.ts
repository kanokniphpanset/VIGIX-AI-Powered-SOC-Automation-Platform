import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

/**
 * auth.middleware.ts — RBAC FOUNDATION (Checkpoint 3).
 *
 * HONESTY NOTE: before this file, there was ZERO authentication anywhere
 * in this backend — every route (including every Policy/Action/Runbook/
 * Playbook mutation) was open to any caller. This is the first real
 * authentication path: a JWT issued by POST /api/auth/login (bcrypt
 * password check against the existing User table), verified here on
 * every protected route. It is a genuine foundation, not a full identity
 * system — there is no refresh-token rotation, no session revocation, no
 * MFA, and no password-reset flow. Extend this file rather than replacing
 * it once those are needed.
 *
 * Role vocabulary: the pre-existing User.role column is a free-form string
 * (no DB enum) already storing "admin"/"analyst"/"viewer" for the legacy
 * seed user. This RBAC foundation additionally seeds SOC/IR_TEAM
 * users — the same ResponsibleRole vocabulary the Policy Engine already
 * uses (see domain/policy/entities/PolicyEvaluationTypes.ts) — because
 * that is what this task's role gates (Policy mutation, Recommendation
 * generation, Approval, Response execution) are actually expressed in
 * terms of. "admin" is treated as a super-role that passes every
 * requireRole() check, matching its pre-existing meaning in this schema.
 */

const JWT_SECRET = process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-in-production";

export interface AuthenticatedUser {
  id: string;
  tenantId: string;
  role: string;
  principalType?: "HUMAN";
}

export interface ServicePrincipal {
  id: string;
  tenantId: string;
  principalType: "SERVICE";
  scopes: string[];
  jobIds: string[];
}

export type RequestPrincipal = (AuthenticatedUser & { principalType: "HUMAN" }) | ServicePrincipal;

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      principal?: RequestPrincipal;
    }
  }
}

export function signToken(user: AuthenticatedUser): string {
  return jwt.sign({ id: user.id, tenantId: user.tenantId, role: user.role, principalType: "HUMAN" }, JWT_SECRET, { algorithm: "HS256", expiresIn: "8h" });
}

/** Server-side provisioning only. Job grants are explicit; a service gets no human role. */
export function signServiceToken(service: Omit<ServicePrincipal, "principalType">): string {
  if (!service.id.startsWith("service:") || !service.tenantId) throw new Error("Invalid service identity");
  return jwt.sign({ ...service, principalType: "SERVICE" }, JWT_SECRET, { algorithm: "HS256", audience: "vigix-service", issuer: "vigix", expiresIn: "1h" });
}

function readPrincipal(req: Request): RequestPrincipal {
  const header = req.header("authorization") ?? "";
  if (!header.startsWith("Bearer ")) throw new Error("Missing bearer token");
  const payload = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
  if (typeof payload === "string" || typeof payload.id !== "string" || !payload.id ||
      typeof payload.tenantId !== "string" || !payload.tenantId || typeof payload.exp !== "number") throw new Error("Invalid identity claims");
  if (payload.principalType === "SERVICE") {
    if (payload.aud !== "vigix-service" || payload.iss !== "vigix" || !payload.id.startsWith("service:") || payload.role !== undefined ||
        !Array.isArray(payload.scopes) || !payload.scopes.every((s: unknown) => typeof s === "string") ||
        !Array.isArray(payload.jobIds) || !payload.jobIds.every((s: unknown) => typeof s === "string")) throw new Error("Invalid service claims");
    return { id: payload.id, tenantId: payload.tenantId, principalType: "SERVICE", scopes: payload.scopes, jobIds: payload.jobIds };
  }
  // Existing login JWTs without principalType remain human until their normal expiry.
  if ((payload.principalType !== undefined && payload.principalType !== "HUMAN") || payload.aud !== undefined ||
      payload.id.startsWith("service:") || typeof payload.role !== "string" || !payload.role) throw new Error("Invalid human claims");
  return { id: payload.id, tenantId: payload.tenantId, role: payload.role, principalType: "HUMAN" };
}

export function authenticatedTenant(req: Request): string {
  if (!req.principal) throw new Error("Authenticated request context required");
  return req.principal.tenantId;
}

/** Explicit read-only service surface; never populates the human req.user for services. */
export function authenticateScopedRead(scope: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const principal = readPrincipal(req);
      if (principal.principalType === "SERVICE" && !principal.scopes.includes(scope)) {
        res.status(403).json({ error: "SERVICE_SCOPE_REQUIRED" }); return;
      }
      req.principal = principal;
      if (principal.principalType === "HUMAN") req.user = principal;
      next();
    } catch { res.status(401).json({ error: "UNAUTHENTICATED" }); }
  };
}

export function authenticateService(scope: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const principal = readPrincipal(req);
      if (principal.principalType !== "SERVICE" || !principal.scopes.includes(scope)) {
        res.status(403).json({ error: "SERVICE_SCOPE_REQUIRED" }); return;
      }
      req.principal = principal;
      next();
    } catch { res.status(401).json({ error: "UNAUTHENTICATED" }); }
  };
}

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    res.status(401).json({ error: "UNAUTHENTICATED", message: "Missing Bearer token" });
    return;
  }

  try {
    const principal = readPrincipal(req);
    if (principal.principalType !== "HUMAN") {
      res.status(403).json({ error: "HUMAN_PRINCIPAL_REQUIRED" }); return;
    }
    req.principal = principal;
    req.user = principal;
    next();
  } catch {
    res.status(401).json({ error: "UNAUTHENTICATED", message: "Invalid or expired token" });
  }
}

/** Configuration changes (Policy, action / playbook / runbook catalogs): the admin system role only. */
export const requireAdmin = () => requireRole();

/** Gates a route to specific roles. "admin" always passes (super-role, see module docstring). */
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    if (req.user.role === "admin" || allowedRoles.includes(req.user.role)) {
      next();
      return;
    }
    res.status(403).json({ error: "FORBIDDEN", message: `Requires one of: ${allowedRoles.join(", ")}` });
  };
}

/**
 * Like requireRole, but WITHOUT the admin super-role bypass. Used on workflow EXECUTION routes (response
 * start/complete/fail, re-hunt, manual verification): "admin" is a system role and must never stand in for the
 * IR team that executes and verifies a response.
 */
export function requireOperationalRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    if (allowedRoles.includes(req.user.role)) {
      next();
      return;
    }
    res.status(403).json({ error: "FORBIDDEN", message: `Requires one of: ${allowedRoles.join(", ")} (admin cannot execute workflow actions)` });
  };
}
