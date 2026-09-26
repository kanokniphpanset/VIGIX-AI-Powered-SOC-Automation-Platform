import { z } from "zod";

export const requestApprovalSchema = z.object({ recommendationId: z.string().uuid(), responseId: z.string().uuid() }).strict();
/** IR APPROVE / REJECT: the note is mandatory for both (DecideApproval also rejects a blank one: NOTE_REQUIRED). */
export const decideApprovalSchema = z.object({ comment: z.string().trim().max(4000).nullable().optional() }).strict();

export type RequestApprovalDto = z.infer<typeof requestApprovalSchema>;
export type DecideApprovalDto = z.infer<typeof decideApprovalSchema>;
