import { RequestHandler } from "express";

/** Express 4 does not forward rejected async handlers to error middleware automatically. */
export function asyncHandler(handler: RequestHandler): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}
