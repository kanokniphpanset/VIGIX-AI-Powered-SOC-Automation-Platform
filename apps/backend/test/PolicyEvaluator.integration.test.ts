import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";

describe("PolicyEvaluator integration", () => {
  const tenantId = "tenant-001";

  const makePolicy = (
    code: string,
    type: Policy["type"],
    precedence: number,
    condition: any,
    result: any
  ): Policy => {
    const policyId = `${code}-ID`;

    const rule = PolicyRule.create({
      id: `${code}-RULE`,
      policyId,
      condition,
      result,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    return Policy.create({
      id: policyId,
      tenantId,
      code,
      name: code,
      description: `${code} policy`,
      type,
      enabled: true,
      version: 1,
      precedence,
      createdAt: new Date(),
      updatedAt: new Date(),
      rules: [rule],
    });
  };

  const policies = [
    // ============================================================
    // ASSIGNMENT
    // ============================================================

    makePolicy(
      "POL-011",
      "ASSIGNMENT",
      100,
      {
        any: [
          {
            field: "severity",
            operator: "eq",
            value: "LOW",
          },
          {
            field: "severity",
            operator: "eq",
            value: "MEDIUM",
          },
        ],
      },
      {
        responsibleRole: "SOC",
      }
    ),

    makePolicy(
      "POL-012",
      "ASSIGNMENT",
      100,
      {
        any: [
          {
            field: "severity",
            operator: "eq",
            value: "HIGH",
          },
          {
            field: "severity",
            operator: "eq",
            value: "CRITICAL",
          },
        ],
      },
      {
        responsibleRole: "IR_TEAM",
        reviewRequired: true,
        reviewRole: "IR_TEAM",
        highRiskReview: true,
      }
    ),

    // ============================================================
    // PRIORITY
    // ============================================================

    makePolicy(
      "POL-002",
      "PRIORITY",
      100,
      {
        field: "severity",
        operator: "eq",
        value: "LOW",
      },
      {
        priority: "P3",
      }
    ),

    makePolicy(
      "POL-003",
      "PRIORITY",
      100,
      {
        field: "severity",
        operator: "eq",
        value: "MEDIUM",
      },
      {
        priority: "P2",
        additionalInvestigation: true,
      }
    ),

    makePolicy(
      "POL-004",
      "PRIORITY",
      100,
      {
        field: "severity",
        operator: "eq",
        value: "HIGH",
      },
      {
        priority: "P1",
      }
    ),

    makePolicy(
      "POL-005",
      "PRIORITY",
      100,
      {
        field: "severity",
        operator: "eq",
        value: "CRITICAL",
      },
      {
        priority: "P0",
      }
    ),

    // LEGACY risk rules (POL-006, POL-012-RISK) are kept in this fixture on purpose: riskScore is a retired
    // condition field, so they must never match any more.
    makePolicy(
      "POL-006",
      "PRIORITY",
      90,
      {
        field: "riskScore",
        operator: "gte",
        value: 75,
      },
      {
        priority: "P0",
      }
    ),

    // ============================================================
    // APPROVAL / REVIEW
    // ============================================================

    makePolicy(
      "POL-012-RISK",
      "APPROVAL",
      100,
      {
        field: "riskScore",
        operator: "gte",
        value: 50,
      },
      {
        reviewRequired: true,
        reviewRole: "IR_TEAM",
        highRiskReview: true,
      }
    ),

    makePolicy(
      "POL-013",
      "APPROVAL",
      90,
      {
        field: "severity",
        operator: "eq",
        value: "CRITICAL",
      },
      {
        approvalRequired: true,
        approvalRole: "MANAGER",
        approvalReason: [
          "Critical severity requires Manager approval",
        ],
      }
    ),

    makePolicy(
      "POL-014",
      "APPROVAL",
      90,
      {
        any: [
          {
            field: "actionImpactLevel",
            operator: "eq",
            value: "HIGH",
          },
          {
            field: "actionImpactLevel",
            operator: "eq",
            value: "CRITICAL",
          },
        ],
      },
      {
        approvalRequired: true,
        approvalRole: "MANAGER",
        approvalReason: [
          "High-impact action requires Manager approval",
        ],
      }
    ),

    // ============================================================
    // VERIFICATION
    // ============================================================

    makePolicy(
      "POL-015",
      "VERIFICATION",
      100,
      {
        field: "verificationResult",
        operator: "eq",
        value: "NOT_RESOLVED",
      },
      {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireNewRecommendation: true,
        responseRequired: false,
      }
    ),
  ];

  const repository: IPolicyRepository = {
    findById: jest.fn(),
    findByCode: jest.fn(),
    findAll: jest.fn(),
    findAllEnabled: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    setEnabled: jest.fn(),
  };

  const evaluator = new PolicyEvaluator(repository);

  beforeEach(() => {
    jest.clearAllMocks();

    (repository.findAllEnabled as jest.Mock).mockResolvedValue(
      policies
    );
  });

  // ============================================================
  // 1. LOW
  // ============================================================

  it("should assign LOW severity incident to SOC with P3", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "LOW",
    });

    expect(result.responsibleRole).toBe("SOC");
    expect(result.priority).toBe("P3");
    expect(result.approvalRequired).toBe(false);
  });

  // ============================================================
  // 2. MEDIUM
  // ============================================================

  it("should assign MEDIUM incident to SOC with P2", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "MEDIUM",
    });

    expect(result.responsibleRole).toBe("SOC");
    expect(result.priority).toBe("P2");
    expect(result.additionalInvestigation).toBe(true);
  });

  // ============================================================
  // 3. HIGH
  // ============================================================

  it("should assign HIGH incident to IR_TEAM with IR review", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "HIGH",
    });

    expect(result.responsibleRole).toBe("IR_TEAM");
    expect(result.priority).toBe("P1");
    expect(result.reviewRequired).toBe(true);
    expect(result.reviewRole).toBe("IR_TEAM");
    expect(result.approvalRequired).toBe(false);
  });

  // ============================================================
  // 4. HIGH + risk 80
  // ============================================================

  // Previously: "should require Manager approval when risk score is 80". Risk Score is no longer a decision input:
  // a HIGH incident with a legacy riskScore 80 is decided exactly like any HIGH incident.
  it("a legacy riskScore (80) on a HIGH incident changes nothing: no Manager approval, P1", async () => {
    const plain = await evaluator.evaluate("tenant-001", { severity: "HIGH" });
    const withRisk = await evaluator.evaluate("tenant-001", { severity: "HIGH", riskScore: 80 } as never);

    expect(withRisk).toEqual(plain);
    expect(withRisk.responsibleRole).toBe("IR_TEAM");
    expect(withRisk.priority).toBe("P1");
    expect(withRisk.approvalRequired).toBe(false);
    expect(withRisk.matchedPolicies).not.toContain("POL-006");
    expect(withRisk.matchedPolicies).not.toContain("POL-012-RISK");
  });

  // ============================================================
  // 5. CRITICAL
  // ============================================================

  it("should give CRITICAL severity P0 and Manager approval", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "CRITICAL",
    });

    expect(result.responsibleRole).toBe("IR_TEAM");
    expect(result.priority).toBe("P0");
    expect(result.approvalRequired).toBe(true);
    expect(result.approvalRole).toBe("MANAGER");
  });

  // ============================================================
  // 6. HIGH impact action
  // ============================================================

  it("should require Manager approval for HIGH-impact actions", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "HIGH",
      actionImpactLevel: "HIGH",
    });

    expect(result.responsibleRole).toBe("IR_TEAM");
    expect(result.approvalRequired).toBe(true);
    expect(result.approvalRole).toBe("MANAGER");
  });

  // ============================================================
  // 7. NOT_RESOLVED
  // ============================================================

  it("should create a new investigation and recommendation when NOT_RESOLVED", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "HIGH",
      verificationResult: "NOT_RESOLVED",
    });

    expect(result.incidentStatus).toBe("INVESTIGATING");
    expect(result.requireNewInvestigation).toBe(true);
    expect(result.requireNewRecommendation).toBe(true);

    // Verification does not automatically execute a response.
    expect(result.responseRequired).toBe(false);
  });

  // ============================================================
  // 8. HIGH SLA
  // ============================================================

  it("should apply HIGH severity SLA", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "HIGH",
    });

    expect(result.priority).toBe("P1");

    expect(result.sla).toEqual({
      firstResponseMinutes: 30,
      resolutionMinutes: 480,
    });
  });

  // ============================================================
  // 9. SLA override
  // ============================================================

  // Previously reached P0 through riskScore 80; the P0 (stricter) SLA now comes from CRITICAL severity only.
  it("should use the stricter P0 SLA for CRITICAL severity", async () => {
    const result = await evaluator.evaluate("tenant-001", {
      severity: "CRITICAL",
    });

    expect(result.priority).toBe("P0");

    expect(result.sla).toEqual({
      firstResponseMinutes: 15,
      resolutionMinutes: 240,
    });
  });

  // ============================================================
  // 10. Tenant isolation
  // ============================================================

  it("should evaluate policies using the requested tenant", async () => {
    await evaluator.evaluate("tenant-xyz", {
      severity: "LOW",
    });

    expect(repository.findAllEnabled).toHaveBeenCalledWith(
      "tenant-xyz"
    );
  });
});
