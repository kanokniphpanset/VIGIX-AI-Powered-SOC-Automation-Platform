import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";

describe("PolicyEvaluator integration", () => {
  const tenantId = "tenant-001";

  const makePolicy = (
    code: string,
    type:
      | "PRIORITY"
      | "ASSIGNMENT"
      | "APPROVAL"
      | "VERIFICATION"
      | "ESCALATION",
    condition: any,
    result: any
  ): Policy => {
    const rule = PolicyRule.create({
      id: `${code}-rule`,
      policyId: `${code}-id`,
      condition,
      result,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    return Policy.create({
      id: `${code}-id`,
      tenantId,
      code,
      name: code,
      description: null,
      type,
      enabled: true,
      version: 1,
      precedence: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      rules: [rule],
    });
  };

  const policies = [
    // =========================================================
    // ASSIGNMENT
    // =========================================================

    makePolicy(
      "POL-ASSIGN-SOC",
      "ASSIGNMENT",
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
      "POL-ASSIGN-IR",
      "ASSIGNMENT",
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
      }
    ),

    // =========================================================
    // SEVERITY -> PRIORITY
    // =========================================================

    makePolicy(
      "POL-SEV-CRITICAL",
      "PRIORITY",
      {
        field: "severity",
        operator: "eq",
        value: "CRITICAL",
      },
      {
        priority: "P0",
        responsibleRole: "IR_TEAM",
        approvalRequired: true,
        approvalRole: "MANAGER",
        approvalReason: [
          "CRITICAL severity requires Manager approval",
        ],
        firstResponseSlaMinutes: 15,
        resolutionSlaMinutes: 240,
      }
    ),

    makePolicy(
      "POL-SEV-HIGH",
      "PRIORITY",
      {
        field: "severity",
        operator: "eq",
        value: "HIGH",
      },
      {
        priority: "P1",
        responsibleRole: "IR_TEAM",
        firstResponseSlaMinutes: 30,
        resolutionSlaMinutes: 480,
      }
    ),

    makePolicy(
      "POL-SEV-MEDIUM",
      "PRIORITY",
      {
        field: "severity",
        operator: "eq",
        value: "MEDIUM",
      },
      {
        priority: "P2",
        responsibleRole: "SOC",
        firstResponseSlaMinutes: 240,
        resolutionSlaMinutes: 4320,
      }
    ),

    makePolicy(
      "POL-SEV-LOW",
      "PRIORITY",
      {
        field: "severity",
        operator: "eq",
        value: "LOW",
      },
      {
        priority: "P3",
        responsibleRole: "SOC",
        firstResponseSlaMinutes: 1440,
        resolutionSlaMinutes: 7200,
      }
    ),

    // =========================================================
    // RISK
    // =========================================================

    makePolicy(
      "POL-RISK-CRITICAL",
      "PRIORITY",
      {
        field: "riskScore",
        operator: "gte",
        value: 75,
      },
      {
        priority: "P0",
        responsibleRole: "IR_TEAM",
        highRiskReview: true,
        reviewRequired: true,
        reviewRole: "IR_TEAM",
        approvalRequired: true,
        approvalRole: "MANAGER",
        approvalReason: ["Risk score >= 75"],
      }
    ),

    makePolicy(
      "POL-RISK-HIGH",
      "PRIORITY",
      {
        field: "riskScore",
        operator: "gte",
        value: 50,
      },
      {
        priority: "P1",
        responsibleRole: "IR_TEAM",
        highRiskReview: true,
        reviewRequired: true,
        reviewRole: "IR_TEAM",
      }
    ),

    makePolicy(
      "POL-RISK-MEDIUM",
      "PRIORITY",
      {
        field: "riskScore",
        operator: "gte",
        value: 25,
      },
      {
        priority: "P2",
        additionalInvestigation: true,
      }
    ),

    makePolicy(
      "POL-RISK-LOW",
      "PRIORITY",
      {
        field: "riskScore",
        operator: "lt",
        value: 25,
      },
      {
        priority: "P3",
        standardInvestigation: true,
      }
    ),

    // =========================================================
    // ACTION IMPACT -> APPROVAL
    // =========================================================

    makePolicy(
      "POL-ACTION-HIGH",
      "APPROVAL",
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

    // =========================================================
    // VERIFICATION
    // =========================================================

    makePolicy(
      "POL-VERIFY-NOT-RESOLVED",
      "VERIFICATION",
      {
        field: "verificationResult",
        operator: "eq",
        value: "NOT_RESOLVED",
      },
      {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireNewRecommendation: true,
      }
    ),

    makePolicy(
      "POL-VERIFY-SPREAD",
      "VERIFICATION",
      {
        field: "spreadDetected",
        operator: "eq",
        value: true,
      },
      {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireEscalation: true,
      }
    ),

    makePolicy(
      "POL-VERIFY-NOT-CONTAINED",
      "VERIFICATION",
      {
        field: "threatContained",
        operator: "eq",
        value: false,
      },
      {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireAdditionalEvidence: true,
      }
    ),
  ];

  const repository: IPolicyRepository = {
    findById: jest.fn(),
    findByCode: jest.fn(),
    findAll: jest.fn(),
    findAllEnabled: jest.fn().mockResolvedValue(policies),
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

  // ===========================================================
  // 1. LOW
  // ===========================================================

  it("should assign LOW risk incident to SOC with P3", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "LOW",
      riskScore: 10,
    });

    expect(result.responsibleRole).toBe("SOC");
    expect(result.priority).toBe("P3");
    expect(result.riskLevel).toBe("LOW");
    expect(result.approvalRequired).toBe(false);
  });

  // ===========================================================
  // 2. MEDIUM
  // ===========================================================

  it("should assign MEDIUM incident to SOC with P2", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "MEDIUM",
      riskScore: 30,
    });

    expect(result.responsibleRole).toBe("SOC");
    expect(result.priority).toBe("P2");
    expect(result.riskLevel).toBe("MEDIUM");
    expect(result.additionalInvestigation).toBe(true);
  });

  // ===========================================================
  // 3. HIGH
  // ===========================================================

  it("should assign HIGH incident to IR_TEAM with IR review", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "HIGH",
      riskScore: 60,
    });

    expect(result.responsibleRole).toBe("IR_TEAM");
    expect(result.priority).toBe("P1");
    expect(result.riskLevel).toBe("HIGH");

    expect(result.reviewRequired).toBe(true);
    expect(result.reviewRole).toBe("IR_TEAM");

    expect(result.approvalRequired).toBe(false);
  });

  // ===========================================================
  // 4. HIGH severity + risk 80
  //
  // IMPORTANT:
  // risk >= 75 matches POL-RISK-CRITICAL
  // therefore priority becomes P0.
  // ===========================================================

  it("should require Manager approval when risk score is 80", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "HIGH",
      riskScore: 80,
    });

    expect(result.responsibleRole).toBe("IR_TEAM");

    expect(result.riskLevel).toBe("CRITICAL");

    expect(result.reviewRequired).toBe(true);
    expect(result.reviewRole).toBe("IR_TEAM");

    expect(result.approvalRequired).toBe(true);
    expect(result.approvalRole).toBe("MANAGER");

    // Risk >= 75 produces P0 and overrides the HIGH severity P1.
    expect(result.priority).toBe("P0");
  });

  // ===========================================================
  // 5. CRITICAL
  // ===========================================================

  it("should give CRITICAL severity P0 and Manager approval", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "CRITICAL",
      riskScore: 80,
    });

    expect(result.priority).toBe("P0");
    expect(result.responsibleRole).toBe("IR_TEAM");
    expect(result.riskLevel).toBe("CRITICAL");

    expect(result.approvalRequired).toBe(true);
    expect(result.approvalRole).toBe("MANAGER");
  });

  // ===========================================================
  // 6. HIGH IMPACT ACTION
  // ===========================================================

  it("should require Manager approval for HIGH-impact actions", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "MEDIUM",
      riskScore: 30,
      actionImpactLevel: "HIGH",
    });

    expect(result.approvalRequired).toBe(true);
    expect(result.approvalRole).toBe("MANAGER");

    expect(result.approvalReason).toContain(
      "High-impact action requires Manager approval"
    );
  });

  // ===========================================================
  // 7. NOT RESOLVED
  // ===========================================================

  it("should create a new investigation and recommendation when NOT_RESOLVED", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "HIGH",
      riskScore: 60,
      verificationResult: "NOT_RESOLVED",
    });

    expect(result.incidentStatus).toBe("INVESTIGATING");

    expect(result.requireNewInvestigation).toBe(true);
    expect(result.requireNewRecommendation).toBe(true);

    // Verification policy must NOT automatically execute a response.
    expect(result.responseRequired).toBe(false);
  });

  // ===========================================================
  // 8. HIGH SLA
  // ===========================================================

  it("should apply HIGH severity SLA", async () => {
    const result = await evaluator.evaluate(tenantId, {
      severity: "HIGH",
      riskScore: 60,
    });

    expect(result.sla).toEqual({
      firstResponseMinutes: 30,
      resolutionMinutes: 480,
    });
  });

  // ===========================================================
  // 9. SLA OVERRIDE
  // ===========================================================

  it("should use a more restrictive resolution SLA when multiple policies match", async () => {
    const resolutionOverridePolicy = makePolicy(
      "POL-TEST-RESOLUTION-OVERRIDE",
      "PRIORITY",
      {
        field: "severity",
        operator: "eq",
        value: "HIGH",
      },
      {
        resolutionSlaMinutes: 300,
      }
    );

    (
      repository.findAllEnabled as jest.Mock
    ).mockResolvedValue([
      ...policies,
      resolutionOverridePolicy,
    ]);

    const result = await evaluator.evaluate(tenantId, {
      severity: "HIGH",
      riskScore: 60,
    });

    expect(result.sla?.firstResponseMinutes).toBe(30);
    expect(result.sla?.resolutionMinutes).toBe(300);
  });

  // ===========================================================
  // 10. TENANT
  // ===========================================================

  it("should evaluate policies using the requested tenant", async () => {
    await evaluator.evaluate("tenant-xyz", {
      severity: "LOW",
      riskScore: 10,
    });

    expect(repository.findAllEnabled).toHaveBeenCalledWith(
      "tenant-xyz"
    );
  });
});