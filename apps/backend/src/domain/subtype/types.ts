/**
 * Subtype knowledge model (apps/knowledge/subtype-playbooks). Pure types: the YAML shapes the loader validates and the
 * runtime facts / decisions / plan the engine produces. No I/O here.
 */
export type Tri = "TRUE" | "FALSE" | "UNKNOWN";
export type PolicyDecision = "ELIGIBLE" | "NEEDS_EVIDENCE" | "NEEDS_TARGET" | "NEEDS_AUTHORIZATION" | "UNSUPPORTED" | "PROHIBITED";
export type EvidenceStatus = "PRESENT" | "ABSENT" | "UNKNOWN";
export type AuthorizationStatus = "AUTHORIZED" | "UNAUTHORIZED" | "UNKNOWN";
export type ContainmentStage = "STOP_ACTIVE" | "CLOSE_PATH" | "IDENTITY_EXPOSURE" | "CLEANUP_OBJECT" | "NONE";
export type ReviewStatus = "DRAFT" | "IR_REVIEW_PENDING" | "IR_REVIEWED";

export type Leaf = { field: string; operator: "equals" | "not_equals" | "in" | "not_in" | "gte" | "lte"; value: unknown };
export type Predicate = Leaf | { all_of: Predicate[] } | { any_of: Predicate[] } | { none_of: Predicate[] };

export interface EvidenceDef { id: string; description: string; confirm: string; may_be_authorized: boolean; requires_lineage?: boolean }
export interface ActionDef {
  action_id: string; action_name: string; label_th?: string; objective: string; phase: "CONTAINMENT" | "INVESTIGATION" | "REMEDIATION" | "RECOVERY";
  containment_stage: ContainmentStage; supported_target_types: string[]; evidence_requirements: string[]; target_requirements: string[];
  runbook_refs: string[]; legacy_action_refs: string[]; execution_constraints: string[];
  impact_level?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; review_status?: ReviewStatus; origin?: string;
}
export interface Prohibition { id: string; reason: string; when: Predicate }
export interface CriticalityConstraint { when: Predicate; effect: "USE_VARIANT" | "REQUIRE_AUTHORITY" | "PROHIBIT"; variant?: string; authority?: string; reason?: string }
export interface PolicyDef {
  policy_id: string; rule_type: "ACTION_GATE" | "BRANCH_GATE" | "GLOBAL_PROHIBITION" | "OUTPUT_CONSTRAINT" | "CLASSIFICATION_RULE";
  covers?: string[]; reason?: string; action_id?: string; applicable_subtypes?: string[]; branch_subtype?: string; branch_subtypes?: string[];
  required_evidence?: Predicate; required_targets?: Predicate; prohibitions?: Prohibition[]; authorization_gate?: string[];
  authority_requirements?: Predicate; tool_capability_requirements?: string[]; tool_capability_any_of?: string[];
  criticality_constraints?: CriticalityConstraint[]; fallback?: { action_id: string; when: string } | null; checks?: { check_id: string; rule: string }[]; statements?: string[];
}
export interface ActionRef { action_id: string; condition: "POLICY_ELIGIBLE" | Predicate; depends_on: string[]; order_reason: string; parallel_allowed?: boolean; fallback_action?: string | null }
export interface Scenario { scenario_id: string; description: string; when?: Predicate; ordered_action_refs: ActionRef[] }
export interface Branch { subtype_id: string; open_when: Predicate; gate_policy?: string }
export interface PlaybookDef {
  playbook_id: string; attack_family: string; subtype_id: string; subtype_name: string; classification_evidence: Predicate; insufficient_evidence: string[];
  scenarios: Scenario[]; policy_refs: string[]; related_branches: Branch[]; stop_escalation: { when: Predicate; then: string; note: string }[]; version: string;
}
export interface StepDef {
  step_id: string; title?: string; fold?: boolean; kind?: "verify"; variant?: string; instruction: string; include_runbook?: string; condition?: Predicate;
  expected_result: string; verify: string; on_failure: string; rollback?: string; impact?: string; manual_owner?: string; skip_if_eligible?: string[];
  origin?: "EXPANDED_FROM_REFERENCE" | "DERIVED_ADDITION";
  /** Dedupe identity: the same operation on the same target (operates_on = target type) is rendered once, whatever action asked for it. */
  operation?: string; operates_on?: string;
  /** How the action is performed (scope, flow/session identification). Falls back to the instruction text after its first clause. */
  method?: string;
  /** Shown as ready only when every capability in the condition is explicitly supported; unknown/false moves it to 'information needed'. */
  requires_confirmed_tool?: boolean;
  /** Where `method` comes from. Only EXISTING / NEUTRAL_DERIVED steps can be ready; the other two never become executable instructions. */
  method_basis?: "EXISTING" | "NEUTRAL_DERIVED" | "ORG_INPUT_REQUIRED" | "IR_REVIEW_REQUIRED";
  /** What the organization / IR must supply before a step with no method can be written (shown as information needed). */
  method_requires?: string;
  /** Organization data the method relies on (e.g. approved_access: the IR/management access that must stay open). */
  requires_org?: string[];
  /** Steps of the same runbook that must be ready first (e.g. cut connections only after the deny rule). */
  needs_prior?: string[];
}
export interface RunbookDef {
  runbook_id: string; supported_action_ids: string[]; supported_subtypes: string[]; objective: string; prerequisites: string[]; required_evidence: string[];
  required_targets: string[]; required_capabilities: string[]; required_authority: string[]; operational_impact: string; ordered_steps: StepDef[];
  verification: string[]; failure_handling: string[]; rollback?: string[]; variants?: { variant_id: string; description: string }[]; remediation_followups?: string[];
  review_status?: ReviewStatus;
}
export interface TargetTypeDef {
  description: string; label_th?: string; role: string; required_identity_fields: string[]; optional_fields?: string[]; validation_rules: string[]; exclusions?: string[];
}

export interface OrganizationContext {
  status: string;
  authority: Record<string, boolean | null>;       // authority id -> granted (null = UNKNOWN)
  capability: Record<string, boolean | null>;      // capability id -> supported (null = UNKNOWN)
  approvedAccess: { match: string; note?: string }[];       // addresses / hosts / accounts that must never be cut
  approvedAutomation: { match: string; note?: string }[];   // process images / tool names / task names that are approved
  trustedRmm: { match: string; note?: string }[];
  /** host -> where scoped network/web restrictions can be enforced (never guessed from Wazuh). */
  enforcementPoints: { host: string; service?: string; enforcement_point: string }[];
  /** identity provider / tenant scope used to complete account targets. */
  identity: { provider?: string; tenant_or_scope?: string } | null;
  /** Named contacts per authority role, ONLY when the organization configured them (never guessed). */
  authorityContacts: Record<string, string>;
}

export interface KnowledgeBase {
  /** "2.0.0+<hash8>": every recommendation records it. */
  version: string;
  hash: string;
  status: "VALID" | "INVALID";
  errors: string[];
  evidence: Map<string, EvidenceDef>;
  actions: Map<string, ActionDef>;
  policies: Map<string, PolicyDef>;
  playbooks: Map<string, PlaybookDef>;          // by subtype id
  runbooks: Map<string, RunbookDef>;
  targetTypes: Map<string, TargetTypeDef>;
  scopeFlags: Set<string>;
  capabilities: Set<string>;
  authorities: Set<string>;
  organization: OrganizationContext;
  /** Ids whose IR review is not done -> why enforce mode is not deployable. */
  unreviewed: string[];
  legacyActionMap: Map<string, string[]>;      // legacy ACT-* -> new action ids (migration-map)
}

// ---------------------------------------------------------------- runtime facts
export interface EvidenceFact {
  id: string; status: EvidenceStatus; authorization: AuthorizationStatus;
  /** Evidence rows / event ids this fact rests on (never empty for PRESENT). */
  refs: string[]; source: "WAZUH_V2" | "ANALYST" | "DERIVED"; observedAt?: string | null; note?: string;
  /** event / row refs that chain the evidence (record->consumer->query, command->download->payload ...), required where the evidence def says so. */
  lineage?: string[];
}
export interface TargetCandidate {
  type: string; fields: Record<string, unknown>; evidenceRefs: string[]; origin: "WAZUH_V2" | "ANALYST" | "DERIVED";
  /** Provenance of each field when known: field -> JSON path / source. */
  provenance?: Record<string, string>;
}
export interface ResolvedTarget extends TargetCandidate {
  validated: boolean; findings: string[]; identityKey: string; hostKey: string | null; display: string;
  /** scope.* flags raised by this target (e.g. agent IP used as attacker). */
  scopeFlags: string[];
}
export interface Facts {
  evidence: Map<string, EvidenceFact>;
  targets: ResolvedTarget[];
  scope: Set<string>;
  authority: Map<string, boolean | null>;
  capability: Map<string, boolean | null>;
  context: Record<string, unknown>;
  mode: "platform_neutral" | "strict";
}

export interface DecisionReason { code: string; detail: string }
export interface ActionDecision {
  action_id: string; subtype: string; policies: string[]; decision: PolicyDecision; reasons: DecisionReason[];
  missing_evidence: string[]; missing_targets: string[]; flags: string[]; variant: string | null;
}
