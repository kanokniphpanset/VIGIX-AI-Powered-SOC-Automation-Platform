import { Request, Response } from "express";
import { ZodError, ZodType } from "zod";

/**
 * validateBody — parses a request body against a zod schema and writes a
 * 400 response itself on failure, so controllers stay one-liners. Returns
 * `undefined` on failure (response already sent); callers must check for
 * that before continuing. Shared across every module's controllers —
 * "Reject invalid input. Do not silently convert invalid values." — zod's
 * `.strict()` schemas already refuse unknown fields and wrong types, this
 * just wires that into the existing inline error-response convention
 * (`res.status(x).json({ error })`, see IncidentController.ts).
 */
export function validateBody<T>(schema: ZodType<T>, req: Request, res: Response): T | undefined {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({
      error: "VALIDATION_ERROR",
      message: "Invalid request body",
      details: formatZodError(result.error),
    });
    return undefined;
  }
  return result.data;
}

function formatZodError(error: ZodError): { path: string; message: string }[] {
  return error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message }));
}
