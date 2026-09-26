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
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export function signToken(user: AuthenticatedUser): string {
  return jwt.sign(user, JWT_SECRET, { expiresIn: "8h" });
}

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    res.status(401).json({ error: "UNAUTHENTICATED", message: "Missing Bearer token" });
    return;
  }

  try {
    const payload = jwt.verify(header.slice("Bearer ".length), JWT_SECRET) as AuthenticatedUser;
    req.user = payload;
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
