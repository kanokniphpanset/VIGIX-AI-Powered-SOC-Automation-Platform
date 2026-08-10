import { NextFunction, Request, Response } from "express";

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction) {
  console.error("[soar-backend] Unhandled error:", err);
  res.status(500).json({
    error: "InternalServerError",
    message: err.message ?? "Unexpected error",
  });
}
