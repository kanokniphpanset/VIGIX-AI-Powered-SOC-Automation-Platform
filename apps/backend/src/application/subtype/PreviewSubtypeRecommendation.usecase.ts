import { IRecommendationContextRepository } from "../recommendation/ports/IRecommendationContextRepository";
import { IRecommendationAuditRepository } from "../../domain/recommendation/repositories/IRecommendationAuditRepository";
import { AUTH_LABEL, EXPLAIN_TITLE, GENERIC_CONFIRM, TOOL_NOTE_TITLE } from "../../domain/subtype/composer";
import { InstanceState, PlanInstance } from "../../domain/subtype/planner";
import { KnowledgeBase } from "../../domain/subtype/types";
import { SubtypeKnowledgeLoader } from "../../infrastructure/knowledge/SubtypeKnowledgeLoader";
import { AdaptedAlertInfo, adaptEvidenceForPreview } from "./previewEvidenceAdapter";
import { EvidenceGap, evidenceGap, familyOfIncidentType } from "./previewEvidenceGap";
import { SubtypeEvaluation, SubtypeMode, SubtypeRecommendationService, subtypeModeFromEnv } from "./SubtypeRecommendationService";

/** User-facing label every preview built from knowledge that has not passed IR review must carry. */
export const PREVIEW_UNREVIEWED_LABEL = "ตัวอย่างคำแนะนำ — ยังไม่ผ่านการอนุมัติสำหรับดำเนินการ";
export const PREVIEW_REVIEWED_LABEL = "ตัวอย่างคำแนะนำ — ยังไม่ใช่คำแนะนำที่ SOC ตรวจรับ";

export type PreviewStatusCategory = "effective" | "pending" | "unverified" | "failed";

export interface PreviewInstruction {
  title: string;
  method: string | null;
  methodKind: "method" | "detail";
  preconditions: string[];
  impact: string | null;
  verify: string | null;
  rollback: string | null;
  /** Why it is proposed again (failed / not applied earlier). */
  note: string | null;
  /** Role that must perform it when the IR may not act on its own (label only, never a named person). */
  owner: string | null;
}
export interface PreviewMeasure { label: string; target: string | null; objective: string; instructions: PreviewInstruction[] }

/**
 * Recommendation Preview - the subtype-knowledge recommendation of an incident shown NEXT TO (never instead of) the recommendation the
 * SOC works with. It never writes: no Recommendation, no Ticket, no audit row, no action. Internal ids (subtype, policy, runbook,
 * action code, evidence ref, instance key) are not part of this payload; they stay in the evaluation audit.
 */
export interface SubtypePreview {
  available: boolean;
  /**
   * STORED_SHADOW = text of the shadow evaluation stored by Generate Recommendation; COMPUTED_PREVIEW = evaluated now from this incident,
   * not stored; FIXTURE_PREVIEW = simulated data (recorded/synthetic alerts + fixture organization), never the result of a real incident.
   */
  source: "STORED_SHADOW" | "COMPUTED_PREVIEW" | "FIXTURE_PREVIEW" | null;
  /** FIXTURE_PREVIEW only: what the simulated scenario is. */
  fixture?: { id: string; title: string; note: string };
  label: string;
  reviewed: boolean;
  unavailableReason: string | null;
  generatedAt: string;
  investigationNumber: number | null;
  basis: { ticketCount: number; rehunt: { round: number; result: string; verifiedAt: string | null } | null; organizationContextComplete: boolean } | null;
  summary: string | null;
  explain: string[];
  measures: PreviewMeasure[];
  overallVerify: string[];
  approvals: { label: string; target: string | null; text: string }[];
  missingInfo: string[];
  priorStatus: { category: PreviewStatusCategory; label: string; text: string }[];
  toolNote: string | null;
  /** The contract-format text (the same renderer as stored recommendations). The only content of a STORED_SHADOW preview. */
  text: string | null;
  /** COMPUTED_PREVIEW: what the preview was computed from (real alerts of the incident) and what is still missing, specifically. */
  evidenceBasis?: {
    alerts: AdaptedAlertInfo[];
    /** true when Evidence Contract v2 was derived in memory from the stored raw alert (not stored on the evidence row). */
    adaptedInMemory: boolean;
    analystAssertions: number;
    gap: EvidenceGap;
    /** Why the attack-type-specific needs cannot be listed (no type chosen or detected), or null. */
    familyNote: string | null;
  };
}

/** Attack type of the incident as the SOC response setup sees it (SOC choice, else MITRE-detected), read-only. */
export type IncidentTypeResolver = (incidentId: string, tenantId: string) => Promise<{ incidentType: string | null; source: "SOC" | "MITRE" | null } | null>;

const STATUS_OF: Partial<Record<InstanceState, PreviewStatusCategory>> = {
  EXECUTED_EFFECTIVE: "effective", PROPOSED_PENDING: "pending",
  EXECUTED_UNVERIFIED: "unverified", RECURRED_CONTROL_UNKNOWN: "unverified", RECURRED_CONTROL_APPLIED: "unverified",
  EXECUTED_NOT_APPLIED: "failed", FAILED: "failed",
};
const STATUS_TEXT: Record<PreviewStatusCategory, string> = {
  effective: "มีผลตามผล Re-hunt ล่าสุด", pending: "เสนอแล้ว ยังไม่มีผลดำเนินการ", unverified: "ยังยืนยันผลไม่ได้", failed: "ดำเนินการไม่สำเร็จ / ยังไม่ถูกนำไปใช้",
};

export class PreviewSubtypeRecommendationUseCase {
  constructor(
    private readonly loader: SubtypeKnowledgeLoader,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly assets: { resolve(hosts: string[]): { criticality: string } },
    private readonly audits?: IRecommendationAuditRepository,
    private readonly incidentTypeOf?: IncidentTypeResolver,
    private readonly modeOf: () => SubtypeMode = subtypeModeFromEnv
  ) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<SubtypePreview | null> {
    const ctx = this.contextRepository;
    const incident = await ctx.getIncidentContext(input.incidentId, input.tenantId);
    if (!incident) return null;
    if (this.modeOf() === "off") return unavailable(incident.investigationNumber, "ระบบปิดการประเมินคำแนะนำจากฐานความรู้ใหม่ (SUBTYPE_KNOWLEDGE_MODE=off)");

    const [rehunt, rows, alerts, type] = await Promise.all([
      ctx.getRehuntContext?.(input.incidentId, input.tenantId, incident.investigationNumber) ?? Promise.resolve(null),
      ctx.getSubtypeEvidence?.(input.incidentId, input.tenantId, incident.investigationNumber) ?? Promise.resolve([]),
      ctx.getIncidentAlerts?.(input.incidentId, input.tenantId) ?? Promise.resolve([]),
      this.incidentTypeOf ? this.incidentTypeOf(input.incidentId, input.tenantId).catch(() => null) : Promise.resolve(null),
    ]);
    // Read-only adapter: Evidence Contract v2 derived in memory from the stored raw alerts (nothing written, nothing asserted).
    const adapted = adaptEvidenceForPreview(rows, alerts);
    const previewRepo = Object.create(ctx) as IRecommendationContextRepository;
    previewRepo.getSubtypeEvidence = async () => adapted.rows;
    // The service only reads (evidence above, ticket history, knowledge files); pinned to shadow - a preview is never enforced.
    const service = new SubtypeRecommendationService(this.loader, previewRepo, this.assets, () => "shadow");
    const ev = await service.evaluate({ incidentId: input.incidentId, tenantId: input.tenantId, investigationNumber: incident.investigationNumber, rehunt: rehunt ?? null });
    if (ev.kb.status !== "VALID" || !ev.composition || !ev.plan) {
      return unavailable(incident.investigationNumber, "ฐานความรู้คำแนะนำยังไม่ผ่านการตรวจโครงสร้าง จึงไม่แสดงตัวอย่าง (รายละเอียดอยู่ใน audit)");
    }
    const reviewed = ev.kb.unreviewed.length === 0;
    const label = reviewed ? PREVIEW_REVIEWED_LABEL : PREVIEW_UNREVIEWED_LABEL;
    const ticketCount = Number((ev.audit.meta as { ticketCount?: number } | undefined)?.ticketCount ?? 0);
    const basis = {
      ticketCount,
      rehunt: rehunt ? { round: rehunt.verifiedInvestigationNumber, result: rehunt.result === "RESOLVED" ? "ไม่พบภัยซ้ำ" : "ยังพบกิจกรรม", verifiedAt: rehunt.verifiedAt ? rehunt.verifiedAt.toISOString() : null } : null,
      organizationContextComplete: ev.kb.organization.status === "COMPLETE",
    };
    const adaptedInMemory = adapted.alerts.some((a) => a.mapping === "ADAPTED_IN_MEMORY");

    // Evaluate current linked alerts on every request. A stored shadow row cannot
    // prove freshness from investigation number and knowledge version alone.
    // 2. computed now from the incident's real evidence; nothing is persisted.
    const family = familyOfIncidentType(type?.incidentType);
    const candidates = (ev.audit.targets as { type: string; validated: boolean; findings: string[]; display: string }[] | undefined) ?? [];
    const gap = evidenceGap(ev.kb, ev.facts, candidates, family && type?.source ? { key: family, source: type.source } : null, ev.plan.active);
    const preview = presentEvaluation(ev, "COMPUTED_PREVIEW", incident.investigationNumber);
    const specific = gap.needed.length > 0 || gap.targets.some((t) => !t.ok);
    return {
      ...preview, basis,
      // the generic "confirm the alert" line is replaced by the specific needs shown with the evidence basis
      missingInfo: specific ? preview.missingInfo.filter((m) => m !== GENERIC_CONFIRM) : preview.missingInfo,
      evidenceBasis: {
        alerts: adapted.alerts, adaptedInMemory, analystAssertions: adapted.assertions, gap,
        familyNote: family ? null : "ยังไม่ทราบประเภทของ Incident (SOC ยังไม่เลือก และจับคู่จาก MITRE ไม่ได้) จึงยังระบุหลักฐานที่ต้องใช้ตามประเภทภัยไม่ได้ — เลือกประเภทในส่วนตั้งค่าการรับมือของ Incident",
      },
    };
  }
}

/** User-facing preview of an evaluation (no internal ids). Used for the computed and the fixture preview alike. */
export function presentEvaluation(ev: SubtypeEvaluation, source: "COMPUTED_PREVIEW" | "FIXTURE_PREVIEW", investigationNumber: number): SubtypePreview {
  if (ev.kb.status !== "VALID" || !ev.composition || !ev.plan) return unavailable(investigationNumber, "ฐานความรู้คำแนะนำยังไม่ผ่านการตรวจโครงสร้าง จึงไม่แสดงตัวอย่าง (รายละเอียดอยู่ใน audit)");
  const kb = ev.kb, comp = ev.composition, plan = ev.plan;
  const reviewed = kb.unreviewed.length === 0;
  const label = reviewed ? PREVIEW_REVIEWED_LABEL : PREVIEW_UNREVIEWED_LABEL;
  const actionLabel = (code: string | null) => { const a = code ? kb.actions.get(code) : undefined; return a?.label_th ?? a?.action_name ?? "มาตรการ"; };
  const measures: PreviewMeasure[] = [];
  const overallVerify: string[] = [];
  for (const s of comp.steps.filter((x) => x.stepType === "ACTION")) {
    const instructions: PreviewInstruction[] = [];
    for (const i of s.instructions) {
      if (i.kind === "verify") { overallVerify.push(i.instruction); continue; }
      instructions.push({
        title: i.title, method: i.method ?? null, methodKind: i.methodKind ?? "method", preconditions: i.preconditions ?? [], impact: i.impact, verify: i.verify,
        rollback: i.rollback ?? null, note: i.note ?? null, owner: i.manualOwner ? AUTH_LABEL[i.manualOwner] ?? null : null,
      });
    }
    if (instructions.length) measures.push({ label: actionLabel(s.actionCode), target: s.target, objective: s.objective, instructions });
  }
  const approvals = comp.steps.filter((s) => s.stepType === "MANUAL").flatMap((s) => s.instructions.map((i) => ({ label: s.title, target: s.target, text: i.instruction })));
  const checkItems = (title: string) => comp.steps.filter((s) => s.stepType === "CHECK" && s.title === title).flatMap((s) => s.instructions.map((i) => i.instruction));
  const toolNote = checkItems(TOOL_NOTE_TITLE)[0] ?? null;
  const priorStatus = [...plan.suppressed, ...plan.ordered.filter((i) => i.state === "FAILED" || i.state === "EXECUTED_NOT_APPLIED")]
    .map((i) => statusOf(kb, i)).filter((x): x is SubtypePreview["priorStatus"][number] => !!x);
  return {
    available: true, source, label, reviewed, unavailableReason: null, generatedAt: new Date().toISOString(), investigationNumber, basis: null,
    summary: comp.summary, explain: checkItems(EXPLAIN_TITLE), measures, overallVerify: [...new Set(overallVerify)], approvals, missingInfo: comp.missingInfo, priorStatus, toolNote,
    text: comp.userText,
  };
}

function statusOf(kb: KnowledgeBase, i: PlanInstance): SubtypePreview["priorStatus"][number] | null {
  const category = STATUS_OF[i.state];
  if (!category) return null;
  const a = kb.actions.get(i.action_id);
  const label = `${a?.label_th ?? a?.action_name ?? "มาตรการ"}${i.primary ? ` (${i.primary.display})` : ""}`;
  return { category, label, text: i.stateReason ?? STATUS_TEXT[category] };
}

const empty = (investigationNumber: number | null): SubtypePreview => ({
  available: false, source: null, label: PREVIEW_UNREVIEWED_LABEL, reviewed: false, unavailableReason: null, generatedAt: new Date().toISOString(), investigationNumber, basis: null,
  summary: null, explain: [], measures: [], overallVerify: [], approvals: [], missingInfo: [], priorStatus: [], toolNote: null, text: null,
});
const unavailable = (investigationNumber: number, reason: string): SubtypePreview => ({ ...empty(investigationNumber), unavailableReason: reason });
