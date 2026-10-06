export interface PlaybookStepProps {
  id: string;
  stepOrder: number;
  title: string;
  description: string | null;
}

export interface PlaybookProps {
  id: string;
  tenantId: string;
  code: string | null;
  name: string;
  description: string | null;
  version: string | null;
  /** DRAFT = created but never published (Phase 1D): never selectable; ACTIVE / DEPRECATED come from a published revision. */
  status: "ACTIVE" | "DEPRECATED" | "DRAFT" | null;
  steps: PlaybookStepProps[];
  /** Incident-level playbooks: { scope: "INCIDENT", incidentType, mitreTechniques[], allowedActions[] }. */
  triggerConditions?: Record<string, unknown>;
}

/**
 * Playbook — the process/lifecycle (spec section 8), e.g. STC-001 Short-
 * Term Containment. Deliberately generic: it never hardcodes attack-
 * specific logic (that's Runbook's job). Reuses the pre-existing Playbook
 * Prisma model (originally n8n-trigger-oriented); `code`/`version`/`status`/
 * `steps` are the new, additive fields this workflow uses.
 */
export class Playbook {
  private constructor(private readonly props: PlaybookProps) {}

  static create(props: PlaybookProps): Playbook {
    if (!props.name) throw new Error("Playbook must have a name");
    return new Playbook(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get code() {
    return this.props.code;
  }
  get name() {
    return this.props.name;
  }
  get description() {
    return this.props.description;
  }
  get version() {
    return this.props.version;
  }
  get status() {
    return this.props.status;
  }
  get triggerConditions(): Record<string, unknown> {
    return this.props.triggerConditions ?? {};
  }
  get steps() {
    return [...this.props.steps].sort((a, b) => a.stepOrder - b.stepOrder);
  }

  toJSON() {
    return { ...this.props, steps: this.steps };
  }
}
