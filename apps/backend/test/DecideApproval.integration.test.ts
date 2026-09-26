import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";

describe("DecideApprovalUseCase", () => {
  const tenantId = "tenant-1";
  const approvalId = "approval-1";
  const responseId = "response-plan-1";
  const recommendationId = "recommendation-1";
  const incidentId = "incident-1";

  function createApproval(overrides: Partial<any> = {}) {
    const status = overrides.status ?? "pending";

    return {
      id: approvalId,
      tenantId,
      recommendationId,
      responseId,
      approvalRole: "MANAGER",
      reason: "High risk incident requires manager approval",
      status,
      requestedTo: null,
      decidedBy: null,
      decidedAt: null,
      comment: null,
      createdAt: new Date(),

      // Mock ของ Approval.isPending
      isPending: status === "pending",

      ...overrides,
    };
  }

  function createResponsePlan(overrides: Partial<any> = {}) {
    return {
      id: responseId,
      tenantId,
      incidentId,
      recommendationId,
      recommendationStepId: "step-1",
      actionId: "action-1",
      target: "host-01",
      reason: "Suspicious activity",
      expectedResult: "Endpoint isolated",
      approvalStatus: "PENDING",
      assignedRole: "IR_TEAM",
      assignedTo: null,
      status: "PENDING_APPROVAL",
      executionResult: null,
      executedAt: null,
      completedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  function createDependencies(
    options: {
      approval?: any;
      responsePlan?: any;
      notificationFails?: boolean;
    } = {}
  ) {
    const approvalRepository = {
      // Single-step chain: no other steps for the ticket / recommendation.
      findByResponse: jest.fn().mockResolvedValue([]),
      findByRecommendation: jest.fn().mockResolvedValue([]),
      activate: jest.fn(),
      cancel: jest.fn().mockResolvedValue(undefined),
      findById: jest.fn().mockResolvedValue(
        options.approval === undefined
          ? createApproval()
          : options.approval
      ),

      decide: jest.fn().mockImplementation(
        async (
          id: string,
          tenant: string,
          data: {
            status: string;
            decidedBy: string;
            comment: string | null;
          }
        ) => {
          return createApproval({
            id,
            tenantId: tenant,
            status: data.status,
            decidedBy: data.decidedBy,
            comment: data.comment,
            decidedAt: new Date(),
          });
        }
      ),
    };

    const auditLogger = {
      record: jest.fn().mockResolvedValue(undefined),
    };

    const recommendationRepository = {
      findById: jest.fn().mockResolvedValue({
        id: recommendationId,
        tenantId,
        incidentId,
        investigationNumber: 1,
        recommendationNumber: 1,
        status: "VALIDATED",
        summary: "Contain suspicious endpoint",
        createdBy: "recommendation-agent-v1",
        steps: [],
      }),
    };

    const contextRepository = {
      getIncidentContext: jest.fn().mockResolvedValue({
        id: incidentId,
        title: "Suspicious endpoint activity",
        priority: "P0",
        investigationNumber: 1,
      }),

      getLatestRiskScore: jest.fn().mockResolvedValue(80),
    };

    const responsePlanRepository = {
      findById: jest.fn().mockResolvedValue(
        options.responsePlan === undefined
          ? createResponsePlan()
          : options.responsePlan
      ),

      updateStatus: jest.fn().mockResolvedValue(
        createResponsePlan({
          approvalStatus: "APPROVED",
          status: "READY_FOR_EXECUTION",
        })
      ),
    };

    const notificationDispatcher = {
      emit: options.notificationFails
        ? jest.fn().mockRejectedValue(
            new Error("notification failure")
          )
        : jest.fn().mockResolvedValue(undefined),
    };

    const useCase = new DecideApprovalUseCase(
      approvalRepository as any,
      auditLogger as any,
      recommendationRepository as any,
      contextRepository as any,
      responsePlanRepository as any,
      notificationDispatcher as any,
      "http://localhost:4000"
    );

    return {
      useCase,
      approvalRepository,
      auditLogger,
      recommendationRepository,
      contextRepository,
      responsePlanRepository,
      notificationDispatcher,
    };
  }

  it("returns NOT_FOUND when approval does not exist", async () => {
    const deps = createDependencies({
      approval: null,
    });

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "manager-1",
      decidedByRole: "MANAGER",
      comment: "Approved",
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("NOT_FOUND");

    expect(deps.approvalRepository.decide).not.toHaveBeenCalled();
    expect(
      deps.responsePlanRepository.updateStatus
    ).not.toHaveBeenCalled();
  });

  it("returns ALREADY_DECIDED when approval is no longer pending", async () => {
    const deps = createDependencies({
      approval: createApproval({
        status: "approved",
        isPending: false,
      }),
    });

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "manager-1",
      decidedByRole: "MANAGER",
      comment: "Approved again",
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("ALREADY_DECIDED");

    expect(
      deps.approvalRepository.decide
    ).not.toHaveBeenCalled();
  });

  it("returns ROLE_MISMATCH when the decider role is not allowed", async () => {
    const deps = createDependencies();

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "ir-1",
      decidedByRole: "IR_TEAM",
      comment: "Trying to approve",
    });

    expect(result.isSuccess).toBe(false);
    expect(result.error).toBe("ROLE_MISMATCH");

    expect(
      deps.approvalRepository.decide
    ).not.toHaveBeenCalled();

    expect(
      deps.responsePlanRepository.updateStatus
    ).not.toHaveBeenCalled();
  });

  it("approves a pending approval and moves its ResponsePlan to READY_FOR_EXECUTION", async () => {
    const deps = createDependencies();

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "manager-1",
      decidedByRole: "MANAGER",
      comment: "Approved for execution",
    });

    expect(result.isSuccess).toBe(true);

    expect(
      deps.approvalRepository.decide
    ).toHaveBeenCalledWith(
      approvalId,
      tenantId,
      {
        status: "approved",
        decidedBy: "manager-1",
        comment: "Approved for execution",
      }
    );

    expect(
      deps.responsePlanRepository.findById
    ).toHaveBeenCalledWith(
      responseId,
      tenantId
    );

    expect(
      deps.responsePlanRepository.updateStatus
    ).toHaveBeenCalledWith(
      responseId,
      tenantId,
      {
        approvalStatus: "APPROVED",
        status: "READY_FOR_EXECUTION",
      }
    );

    expect(
      deps.auditLogger.record
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId,
        actor: "manager-1",
        action: "APPROVAL_DECIDED",
        entity: "Approval",
        entityId: approvalId,
      })
    );
  });

  it("rejects a pending approval and moves its ResponsePlan to REJECTED", async () => {
    const deps = createDependencies();

    deps.responsePlanRepository.updateStatus.mockResolvedValue(
      createResponsePlan({
        approvalStatus: "REJECTED",
        status: "REJECTED",
      })
    );

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "rejected",
      decidedBy: "manager-1",
      decidedByRole: "MANAGER",
      comment: "Rejected due to business impact",
    });

    expect(result.isSuccess).toBe(true);

    expect(
      deps.approvalRepository.decide
    ).toHaveBeenCalledWith(
      approvalId,
      tenantId,
      {
        status: "rejected",
        decidedBy: "manager-1",
        comment: "Rejected due to business impact",
      }
    );

    expect(
      deps.responsePlanRepository.updateStatus
    ).toHaveBeenCalledWith(
      responseId,
      tenantId,
      {
        approvalStatus: "REJECTED",
        status: "REJECTED",
      }
    );
  });

  // Spec (VIGIX role model): admin administers the system but must not stand in for the business approver.
  // This test previously asserted the opposite ("allows admin to decide regardless of the approval role").
  it("does not let admin decide a business approval (ADMIN_NOT_APPROVER), and audits the denied attempt", async () => {
    const deps = createDependencies();

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "admin-1",
      decidedByRole: "admin",
      comment: "Administrative approval",
    });

    expect(result.isFailure).toBe(true);
    expect(result.error).toBe("ADMIN_NOT_APPROVER");
    expect(deps.approvalRepository.decide).not.toHaveBeenCalled();
    expect(deps.responsePlanRepository.updateStatus).not.toHaveBeenCalled();
    expect(deps.auditLogger.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: "APPROVAL_DECISION_DENIED", entityId: approvalId, metadata: expect.objectContaining({ reason: "ADMIN_NOT_APPROVER" }) })
    );
  });

  it("does not fail approval decision when notification fails", async () => {
    const deps = createDependencies({
      notificationFails: true,
    });

    const result = await deps.useCase.execute({
      approvalId,
      tenantId,
      status: "approved",
      decidedBy: "manager-1",
      decidedByRole: "MANAGER",
      comment: "Approved",
    });

    expect(result.isSuccess).toBe(true);

    expect(
      deps.approvalRepository.decide
    ).toHaveBeenCalled();

    expect(
      deps.responsePlanRepository.updateStatus
    ).toHaveBeenCalled();

    expect(
      deps.notificationDispatcher.emit
    ).toHaveBeenCalled();
  });
});
