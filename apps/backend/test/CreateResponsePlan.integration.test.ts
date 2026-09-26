import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { Recommendation } from "../src/domain/recommendation/entities/Recommendation.entity";
import { ResponsePlan } from "../src/domain/response/entities/ResponsePlan.entity";

describe("CreateResponsePlanUseCase", () => {
  const tenantId = "tenant-1";
  const incidentId = "incident-1";
  const recommendationId = "recommendation-1";
  const actionId = "action-1";
  const stepId = "step-1";

  function createRecommendation(
    overrides: Partial<any> = {}
  ): Recommendation {
    return {
      id: recommendationId,
      tenantId,
      incidentId,
      investigationNumber: 1,
      recommendationNumber: 1,
      status: "VALIDATED",
      summary: "Contain suspicious endpoint activity",
      createdBy: "recommendation-agent-v1",
      steps: [
        {
          id: stepId,
          stepOrder: 1,
          title: "Isolate endpoint",
          objective: "Contain the affected endpoint",
          actionId,
          target: "host-01",
          reason: "Suspicious activity detected",
          evidence: ["IOC detected"],
          sourceRunbookId: null,
          precondition: null,
          expectedResult: "Endpoint isolated",
          requiresApproval: false,
          status: "PENDING",
        },
      ],
      ...overrides,
    } as Recommendation;
  }

  function createAction(overrides: Partial<any> = {}) {
    return {
      id: actionId,
      tenantId,
      code: "ISOLATE_ENDPOINT",
      name: "Isolate Endpoint",
      description: "Isolate affected endpoint",
      category: "CONTAINMENT",
      impactLevel: "MEDIUM",
      defaultApprovalRequired: false,
      runbookId: null,
      ...overrides,
    };
  }

  function createResponsePlan(overrides: Partial<any> = {}) {
    return {
      id: "response-plan-1",
      tenantId,
      incidentId,
      recommendationId,
      recommendationStepId: stepId,
      actionId,
      target: "host-01",
      reason: "Suspicious activity detected",
      expectedResult: "Endpoint isolated",
      approvalStatus: "NOT_REQUIRED",
      assignedRole: "SOC",
      assignedTo: null,
      status: "READY_FOR_EXECUTION",
      executionResult: null,
      executedAt: null,
      completedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    } as ResponsePlan;
  }

  function createDependencies(options: {
    approvalRequired?: boolean;
    responsibleRole?: string;
    recommendation?: Recommendation | null;
  } = {}) {
    const recommendationRepository = {
      findById: jest.fn().mockResolvedValue(
        options.recommendation === undefined
          ? createRecommendation()
          : options.recommendation
      ),
    };

    const actionRepository = {
      findById: jest.fn().mockResolvedValue(createAction()),
    };

    const runbookRepository = {
      findById: jest.fn().mockResolvedValue(null),
    };

    const approvalService = {
      evaluate: jest.fn().mockResolvedValue({
        policy: {
          matchedPolicies: [],
          matchedRules: [],
          priority: options.approvalRequired ? "P0" : "P3",
          severity: options.approvalRequired ? "HIGH" : "LOW",
          riskScore: options.approvalRequired ? 80 : 10,
          riskLevel: options.approvalRequired ? "CRITICAL" : "LOW",
          responsibleRole: options.responsibleRole ?? "SOC",
          reviewRequired: false,
          reviewRole: null,
          approvalRequired: options.approvalRequired ?? false,
          approvalRole: options.approvalRequired ? "MANAGER" : null,
          approvalReason: options.approvalRequired
            ? ["High risk incident"]
            : [],
          highRiskReview: false,
          responseRequired: true,
          investigationRequired: true,
          additionalInvestigation: false,
          standardInvestigation: true,
          incidentStatus: null,
          requireNewInvestigation: false,
          requireNewRecommendation: false,
          requireEscalation: false,
          requireAdditionalEvidence: false,
          sla: null,
          verificationOverrides: {
            incidentStatus: null,
            requireNewInvestigation: false,
            requireNewRecommendation: false,
            requireEscalation: false,
            requireAdditionalEvidence: false,
          },
        },
        incidentContext: {
          alertSeverity: options.approvalRequired ? "high" : "low",
        },
        riskScore: options.approvalRequired ? 80 : 10,
      }),

      open: jest.fn().mockResolvedValue(undefined),
    };

    const responsePlanRepository = {
      // No earlier ticket for the step (duplicate prevention reads this).
      findByRecommendation: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockImplementation(async (data) =>
        createResponsePlan({
          ...data,
          id: "response-plan-1",
        })
      ),
    };

    const auditLogger = {
      record: jest.fn().mockResolvedValue(undefined),
    };

    const notificationDispatcher = {
      emit: jest.fn().mockResolvedValue(undefined),
    };

    const useCase = new CreateResponsePlanUseCase(
      recommendationRepository as any,
      actionRepository as any,
      runbookRepository as any,
      approvalService as any,
      responsePlanRepository as any,
      auditLogger as any,
      notificationDispatcher as any,
      "http://localhost:4000"
    );

    return {
      useCase,
      recommendationRepository,
      actionRepository,
      runbookRepository,
      approvalService,
      responsePlanRepository,
      auditLogger,
      notificationDispatcher,
    };
  }

  it("creates PENDING_IR_DECISION and opens the IR decision even when Policy flags no approval", async () => {
    const deps = createDependencies({
      approvalRequired: false,
      responsibleRole: "SOC",
    });

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(true);

    expect(deps.approvalService.evaluate).toHaveBeenCalledWith({
      tenantId,
      incidentId,
      actionId,
    });

    expect(deps.responsePlanRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId,
        incidentId,
        recommendationId,
        recommendationStepId: stepId,
        actionId,
        approvalStatus: "PENDING",
        assignedRole: "IR_TEAM", // IR decides and executes — SOC owns the investigation but never executes
        status: "PENDING_IR_DECISION",
      })
    );

    // Every ticket waits for the IR decision: one IR approval, opened without its own notification.
    expect(deps.approvalService.open).toHaveBeenCalledWith(expect.objectContaining({ responseId: "response-plan-1", notify: false }));
    // Ticket first, then ONE notification carrying the ticket link.
    const created = deps.responsePlanRepository.create.mock.invocationCallOrder[0];
    const opened = deps.approvalService.open.mock.invocationCallOrder[0];
    const emitted = deps.notificationDispatcher.emit.mock.invocationCallOrder[0];
    expect(created).toBeLessThan(opened);
    expect(opened).toBeLessThan(emitted);
    expect(deps.notificationDispatcher.emit).toHaveBeenCalledTimes(1);
    const event = deps.notificationDispatcher.emit.mock.calls[0][0];
    expect(event).toMatchObject({ eventType: "RESPONSE_ASSIGNED", recipient: { roles: ["IR_TEAM"] }, ticket: { id: "response-plan-1", status: "PENDING_IR_DECISION" } });
    expect(event.links.ticket).toContain("/tickets/response-plan-1");
  });

  it("creates PENDING_IR_DECISION and opens the IR decision when Policy flags approval", async () => {
    const deps = createDependencies({
      approvalRequired: true,
      responsibleRole: "IR_TEAM",
    });

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(true);

    expect(deps.responsePlanRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId,
        incidentId,
        recommendationId,
        recommendationStepId: stepId,
        actionId,
        approvalStatus: "PENDING",
        assignedRole: "IR_TEAM",
        status: "PENDING_IR_DECISION",
      })
    );

    expect(deps.approvalService.open).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId,
        recommendation: expect.anything(),
        responseId: "response-plan-1",
        decision: expect.anything(),
        steps: [
          expect.objectContaining({
            step: expect.objectContaining({
              id: stepId,
              actionId,
            }),
            action: expect.anything(),
            runbook: null,
          }),
        ],
      })
    );
  });

  it("returns STEP_HAS_NO_ACTION and does not create a response plan", async () => {
    const recommendation = createRecommendation({
      steps: [
        {
          id: stepId,
          stepOrder: 1,
          title: "Investigate",
          objective: "Collect evidence",
          actionId: null,
          target: null,
          reason: "Need more evidence",
          evidence: ["Suspicious IOC"],
          sourceRunbookId: null,
          precondition: null,
          expectedResult: "Evidence collected",
          requiresApproval: false,
          status: "PENDING",
        },
      ],
    });

    const deps = createDependencies({
      recommendation,
    });

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("STEP_HAS_NO_ACTION");

    expect(deps.approvalService.evaluate).not.toHaveBeenCalled();
    expect(deps.responsePlanRepository.create).not.toHaveBeenCalled();
  });

  it("returns STEP_NOT_FOUND when the requested step does not exist", async () => {
    const deps = createDependencies();

    const result = await deps.useCase.execute({
      recommendationId,
      stepId: "unknown-step",
      tenantId,
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("STEP_NOT_FOUND");

    expect(deps.approvalService.evaluate).not.toHaveBeenCalled();
    expect(deps.responsePlanRepository.create).not.toHaveBeenCalled();
  });

  it("returns RECOMMENDATION_NOT_FOUND when recommendation does not exist", async () => {
    const deps = createDependencies({
      recommendation: null,
    });

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("RECOMMENDATION_NOT_FOUND");

    expect(deps.approvalService.evaluate).not.toHaveBeenCalled();
    expect(deps.responsePlanRepository.create).not.toHaveBeenCalled();
  });

  it("does not fail response-plan creation when approval notification fails", async () => {
    const deps = createDependencies({
      approvalRequired: true,
      responsibleRole: "IR_TEAM",
    });

    deps.approvalService.open.mockRejectedValueOnce(
      new Error("approval notification failure")
    );

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(true);
    expect(deps.responsePlanRepository.create).toHaveBeenCalled();
  });

  it("does not fail response-plan creation when response notification fails", async () => {
    const deps = createDependencies({
      approvalRequired: false,
      responsibleRole: "SOC",
    });

    deps.notificationDispatcher.emit.mockRejectedValueOnce(
      new Error("notification failure")
    );

    const result = await deps.useCase.execute({
      recommendationId,
      stepId,
      tenantId,
    });

    expect(result.isSuccess).toBe(true);
    expect(deps.responsePlanRepository.create).toHaveBeenCalled();
  });
});