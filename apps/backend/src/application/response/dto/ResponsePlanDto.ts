import { z } from "zod";

export const createResponsePlanSchema = z.object({ recommendationId: z.string().uuid(), stepId: z.string().uuid() }).strict();
export const completeResponseSchema = z.object({ executionResult: z.record(z.unknown()) }).strict();
export const failResponseSchema = z.object({ executionResult: z.record(z.unknown()) }).strict();

export type CreateResponsePlanDto = z.infer<typeof createResponsePlanSchema>;
export type CompleteResponseDto = z.infer<typeof completeResponseSchema>;
export type FailResponseDto = z.infer<typeof failResponseSchema>;
