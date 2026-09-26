import { z } from "zod";

export const generateRecommendationSchema = z
  .object({
    incidentId: z.string().uuid(),
  })
  .strict();

export type GenerateRecommendationDto = z.infer<typeof generateRecommendationSchema>;
