export type ActionCategory = "CONTAINMENT" | "INVESTIGATION" | "VERIFICATION";
export type ActionImpactLevel = "LOW" | "MEDIUM" | "HIGH";

export interface ActionProps {
  id: string;
  tenantId: string;
  code: string;
  name: string;
  description: string | null;
  category: ActionCategory;
  enabled: boolean;
  impactLevel: ActionImpactLevel;
  defaultApprovalRequired: boolean;
  runbookId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Action — one entry of the Recommendation-Response workflow's Action
 * Catalog (an ALLOWLIST; see recommendation module's RecommendationValidator
 * for RULE-001/002: AI may only reference an enabled Action already here,
 * never invent one). `defaultApprovalRequired` is only a catalog baseline —
 * the Policy Engine + current incident context is what actually decides
 * whether a given step needs approval (spec section 9/18).
 */
export class Action {
  private constructor(private readonly props: ActionProps) {}

  static create(props: ActionProps): Action {
    if (!props.code) throw new Error("Action must have a code");
    if (!props.name) throw new Error("Action must have a name");
    return new Action(props);
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
  get category() {
    return this.props.category;
  }
  get enabled() {
    return this.props.enabled;
  }
  get impactLevel() {
    return this.props.impactLevel;
  }
  get defaultApprovalRequired() {
    return this.props.defaultApprovalRequired;
  }
  get runbookId() {
    return this.props.runbookId;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get updatedAt() {
    return this.props.updatedAt;
  }

  toJSON(): ActionProps {
    return { ...this.props };
  }
}
