import { PolicyCondition } from "./PolicyCondition";
import { PolicyResultFragment } from "./PolicyEvaluationTypes";

export interface PolicyRuleProps {
  id: string;
  policyId: string;
  condition: PolicyCondition;
  result: PolicyResultFragment;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export class PolicyRule {
  private constructor(private readonly props: PolicyRuleProps) {}

  static create(props: PolicyRuleProps): PolicyRule {
    if (!props.condition) {
      throw new Error("PolicyRule must have a condition");
    }
    if (!props.result || typeof props.result !== "object") {
      throw new Error("PolicyRule must have a result");
    }
    return new PolicyRule(props);
  }

  get id() {
    return this.props.id;
  }
  get policyId() {
    return this.props.policyId;
  }
  get condition() {
    return this.props.condition;
  }
  get result() {
    return this.props.result;
  }
  get enabled() {
    return this.props.enabled;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get updatedAt() {
    return this.props.updatedAt;
  }

  toJSON(): PolicyRuleProps {
    return { ...this.props };
  }
}
