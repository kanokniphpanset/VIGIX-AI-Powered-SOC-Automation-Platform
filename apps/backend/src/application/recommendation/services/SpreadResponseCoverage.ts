import { isRecommendable, RecommendationContextDto } from "../dto/RecommendationContextDto";

/** Target must be tied to the newly affected host's current-cycle evidence. */
export function spreadResponseOptions(context: RecommendationContextDto): { host: string; options: { actionCode: string; target: string }[] }[] {
  if (!context.spreadResponse) return [];
  return context.spreadResponse.newHosts.map(host => {
    const linked = new Set(context.evidence.filter(e => e.host === host).flatMap(e => e.iocValues));
    return { host, options: (context.actionProcedures ?? [])
      .filter(p => isRecommendable(p) && context.spreadResponse!.allowedActions.includes(p.actionCode))
      .flatMap(p => (p.evidence?.targets ?? []).filter(target => target === host || linked.has(target)).map(target => ({ actionCode: p.actionCode, target }))),
    };
  });
}
