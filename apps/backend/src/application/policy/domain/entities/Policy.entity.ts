import { PolicyType } from "./PolicyEvaluationTypes";
import { PolicyRule } from "./PolicyRule.entity";

export interface PolicyProps {
  id: string;
  tenantId: string;
  code: string;
  name: string;
  description: string | null;
  type: PolicyType;
  enabled: boolean;
  version: number;
  /** Ascending = evaluated/considered first. Lower precedence number wins
   * when two policies of the same type could otherwise both apply — see
   * PolicyEvaluator.ts, which sorts by this field before matching rules. */
  precedence: number;
  createdAt: Date;
  updatedAt: Date;
  rules: PolicyRule[];
}

export class Policy {
  private constructor(private readonly props: PolicyProps) {}

  static create(props: PolicyProps): Policy {
    if (!props.code) {
      throw new Error("Policy must have a code");
    }
    if (!props.name) {
      throw new Error("Policy must have a name");
    }
    return new Policy(props);
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
  get type() {
    return this.props.type;
  }
  get enabled() {
    return this.props.enabled;
  }
  get version() {
    return this.props.version;
  }
  get precedence() {
    return this.props.precedence;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get updatedAt() {
    return this.props.updatedAt;
  }
  get rules() {
    return this.props.rules;
  }

  /** Enabled rules only — what the evaluator is allowed to consider. */
  activeRules(): PolicyRule[] {
    return this.props.rules.filter((r) => r.enabled);
  }

  toJSON() {
    return {
      id: this.props.id,
      tenantId: this.props.tenantId,
      code: this.props.code,
      name: this.props.name,
      description: this.props.description,
      type: this.props.type,
      enabled: this.props.enabled,
      version: this.props.version,
      precedence: this.props.precedence,
      createdAt: this.props.createdAt,
      updatedAt: this.props.updatedAt,
      rules: this.props.rules.map((r) => r.toJSON()),
    };
  }
}
