import { CreateVerificationUseCase } from "../src/application/verification/use-cases/CreateVerification.usecase";
import { Result } from "../src/shared/result/Result";

function createIncident(overrides: Partial<any> = {}) {
  return {
    id: "incident-1",
    tenantId: "tenant-1",
    title: "Test Incident",
    status: "investigating",
    priority: "P1",
    investigationNumber: 1,
    ...overrides,
  };
}

function createResponse(overrides: Partial<any> = {}) {
  return {
    id: "response-1",
    tenantId: "tenant-1",
    incidentId: "incident-1",
    recommendationId: "recommendation-1",
    actionId: "action-1",
    status: "COMPLETED",
    ...overrides,
  };
}

function createVerification(overrides: Partial<any> = {}) {
  return {
    id: "verification-1",
    tenantId: "tenant-1",
    incidentId: "incident-1",
    responseId: "response-1",
    result: "RESOLVED",
    matchingEvents: 0,
    affectedHosts: [],
    iocRecurrence: false,
    spreadDetected: false,
    threatContained: true,
    verifiedBy: "analyst-1",
    ...overrides,
  };
}

function createPolicyResult(overrides: Partial<any> = {}) {
  return {
    matchedPolicies: [],
    matchedRules: [],
    priority: null,
    severity: null,
    riskScore: null,
    riskLevel: null,
    responsibleRole: null,
    reviewRequired: false,
    reviewRole: null,
    approvalRequired: false,
    approvalRole: null,
    approvalReason: [],
    highRiskReview: false,
    responseRequired: false,
    investigationRequired: false,
    additionalInvestigation: false,
    standardInvestigation: false,
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
    ...overrides,
  };
}

function createDependencies(options: {
  incident?: any;
  response?: any;
  existingVerifications?: any[];
  policyResult?: any;
  updatedIncident?: any;
  recommendationResult?: any;
  notificationShouldFail?: boolean;
} = {}) {
  const incidentRepository = {
    findById: jest.fn().mockResolvedValue(
      Object.prototype.hasOwnProperty.call(options, "incident")
        ? options.incident
        : createIncident()
    ),

    incrementInvestigationNumber: jest.fn().mockResolvedValue(
      options.updatedIncident ??
        createIncident({
          investigationNumber: 2,
          status: "investigating",
        })
    ),

    updateStatus: jest.fn().mockResolvedValue(undefined),
  };

  const responsePlanRepository = {
    findById: jest.fn().mockResolvedValue(
      Object.prototype.hasOwnProperty.call(options, "response")
        ? options.response
        : createResponse()
    ),
  };

  const verificationRepository = {
    findById: jest.fn(),

    findAllByIncident: jest.fn().mockResolvedValue(
      options.existingVerifications ?? []
    ),

    findAll: jest.fn(),

    create: jest.fn().mockImplementation(async (data: any) =>
      createVerification({
        ...data,
        id: "verification-1",
      })
    ),
  };

  const policyEvaluator = {
    evaluate: jest.fn().mockResolvedValue(
      options.policyResult ?? createPolicyResult()
    ),
  };

  const auditLogger = {
    record: jest.fn().mockResolvedValue(undefined),
  };

  const contextRepository = {
    getLatestRiskScore: jest.fn().mockResolvedValue(80),
  };

  const notificationDispatcher = {
    emit: options.notificationShouldFail
      ? jest
          .fn()
          .mockRejectedValue(new Error("notification failure"))
      : jest.fn().mockResolvedValue(undefined),
  };

  const generateRecommendationUseCase = {
    execute: jest.fn().mockResolvedValue(
      options.recommendationResult ??
        Result.ok({
          id: "recommendation-2",
        })
    ),
  };

  const useCase = new CreateVerificationUseCase(
    verificationRepository as any,
    responsePlanRepository as any,
    incidentRepository as any,
    policyEvaluator as any,
    auditLogger as any,
    contextRepository as any,
    notificationDispatcher as any,
    "http://localhost:4000",
    generateRecommendationUseCase as any
  );

  return {
    useCase,
    incidentRepository,
    responsePlanRepository,
    verificationRepository,
    policyEvaluator,
    auditLogger,
    contextRepository,
    notificationDispatcher,
    generateRecommendationUseCase,
  };
}

describe("CreateVerificationUseCase", () => {
  it("returns INCIDENT_NOT_FOUND when incident does not exist", async () => {
    const deps = createDependencies({
      incident: null,
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "test query",
      matchingEvents: 0,
      threatContained: true,
    });

    expect(result.isFailure).toBe(true);
    expect(result.error).toBe("INCIDENT_NOT_FOUND");
  });

  it("returns RESPONSE_NOT_FOUND when response does not exist", async () => {
    const deps = createDependencies({
      response: null,
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "test query",
      matchingEvents: 0,
      threatContained: true,
    });

    expect(result.isFailure).toBe(true);
    expect(result.error).toBe("RESPONSE_NOT_FOUND");
  });

  it("returns RESPONSE_NOT_COMPLETED when response is not completed", async () => {
    const deps = createDependencies({
      response: createResponse({
        status: "IN_PROGRESS",
      }),
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "test query",
      matchingEvents: 0,
      threatContained: true,
    });

    expect(result.isFailure).toBe(true);
    expect(result.error).toBe("RESPONSE_NOT_COMPLETED");
  });

  it("returns ALREADY_VERIFIED when the response was already verified", async () => {
    const deps = createDependencies({
      existingVerifications: [
        createVerification({
          id: "old-verification",
          responseId: "response-1",
        }),
      ],
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "test query",
      matchingEvents: 0,
      threatContained: true,
    });

    expect(result.isFailure).toBe(true);
    expect(result.error).toBe("ALREADY_VERIFIED");
  });

  it("returns RESOLVED and closes the incident when verification evidence is clean", async () => {
    const deps = createDependencies();

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "event.code:*",
      matchingEvents: 0,
      affectedHosts: ["host-1"],
      threatContained: true,
      spreadDetected: false,
      iocRecurrence: false,
    });

    expect(result.isSuccess).toBe(true);
    expect(result.value.result).toBe("RESOLVED");

    expect(
      deps.verificationRepository.create
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        result: "RESOLVED",
        threatContained: true,
        spreadDetected: false,
        iocRecurrence: false,
        matchingEvents: 0,
      })
    );

    expect(
      deps.policyEvaluator.evaluate
    ).toHaveBeenCalledWith(
      "tenant-1",
      expect.objectContaining({
        verificationResult: "RESOLVED",
        spreadDetected: false,
        threatContained: true,
      })
    );

    expect(
      deps.incidentRepository.updateStatus
    ).toHaveBeenCalledWith(
      "incident-1",
      "tenant-1",
      "resolved"
    );

    expect(
      deps.incidentRepository.incrementInvestigationNumber
    ).not.toHaveBeenCalled();

    expect(
      deps.generateRecommendationUseCase.execute
    ).not.toHaveBeenCalled();
  });

  it("returns NOT_RESOLVED when matching events remain", async () => {
    const deps = createDependencies({
      policyResult: createPolicyResult({
        requireNewInvestigation: true,
        requireNewRecommendation: true,
      }),
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "event.code:*",
      matchingEvents: 3,
      affectedHosts: ["host-1"],
      threatContained: true,
      spreadDetected: false,
      iocRecurrence: false,
    });

    expect(result.isSuccess).toBe(true);
    expect(result.value.result).toBe("NOT_RESOLVED");

    expect(
      deps.incidentRepository.incrementInvestigationNumber
    ).toHaveBeenCalledWith(
      "incident-1",
      "tenant-1"
    );

    expect(
      deps.generateRecommendationUseCase.execute
    ).toHaveBeenCalledWith({
      incidentId: "incident-1",
      tenantId: "tenant-1",
    });

    expect(
      deps.incidentRepository.updateStatus
    ).not.toHaveBeenCalledWith(
      "incident-1",
      "tenant-1",
      "resolved"
    );
  });

  it("returns NOT_RESOLVED when threat is not contained", async () => {
    const deps = createDependencies({
      policyResult: createPolicyResult({
        requireNewInvestigation: true,
      }),
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "event.code:*",
      matchingEvents: 0,
      affectedHosts: ["host-1"],
      threatContained: false,
      spreadDetected: false,
      iocRecurrence: false,
    });

    expect(result.isSuccess).toBe(true);
    expect(result.value.result).toBe("NOT_RESOLVED");

    expect(
      deps.incidentRepository.incrementInvestigationNumber
    ).toHaveBeenCalled();

    expect(
      deps.generateRecommendationUseCase.execute
    ).toHaveBeenCalled();
  });

  it("returns NOT_RESOLVED and reopens investigation when spread is detected", async () => {
    const deps = createDependencies({
      policyResult: createPolicyResult({
        requireNewInvestigation: true,
      }),
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "event.code:*",
      matchingEvents: 0,
      affectedHosts: ["host-1", "host-2"],
      threatContained: true,
      spreadDetected: true,
      iocRecurrence: false,
    });

    expect(result.isSuccess).toBe(true);
    expect(result.value.result).toBe("NOT_RESOLVED");

    expect(
      deps.incidentRepository.incrementInvestigationNumber
    ).toHaveBeenCalledWith(
      "incident-1",
      "tenant-1"
    );

    expect(
      deps.generateRecommendationUseCase.execute
    ).toHaveBeenCalledWith({
      incidentId: "incident-1",
      tenantId: "tenant-1",
    });
  });

  it("does not fail verification when notification fails", async () => {
    const deps = createDependencies({
      policyResult: createPolicyResult({
        requireNewInvestigation: true,
      }),
      notificationShouldFail: true,
    });

    const result = await deps.useCase.execute({
      incidentId: "incident-1",
      tenantId: "tenant-1",
      verifiedBy: "analyst-1",
      responseId: "response-1",
      query: "event.code:*",
      matchingEvents: 1,
      threatContained: false,
      spreadDetected: false,
      iocRecurrence: false,
    });

    expect(result.isSuccess).toBe(true);
    expect(result.value.result).toBe("NOT_RESOLVED");

    expect(
      deps.verificationRepository.create
    ).toHaveBeenCalled();

    expect(
      deps.incidentRepository.incrementInvestigationNumber
    ).toHaveBeenCalled();
  });
});



describe("CreateVerificationUseCase — New Round -> AI Recommendation -> IR Decision", () => {
  const input = {
    incidentId: "incident-1",
    tenantId: "tenant-1",
    verifiedBy: "ir-1",
    responseId: "response-1",
    query: "event.code:*",
    matchingEvents: 3,
    threatContained: false,
  };
  const build = (recommendationStatus: string) => {
    const deps = createDependencies({
      policyResult: createPolicyResult({ requireNewInvestigation: true }),
      recommendationResult: Result.ok({ id: "recommendation-2", status: recommendationStatus }),
    });
    const sendToIr = { execute: jest.fn().mockResolvedValue(Result.ok({ tickets: [] })) };
    const useCase = new CreateVerificationUseCase(
      deps.verificationRepository as any,
      deps.responsePlanRepository as any,
      deps.incidentRepository as any,
      deps.policyEvaluator as any,
      deps.auditLogger as any,
      deps.contextRepository as any,
      deps.notificationDispatcher as any,
      "http://localhost:4000",
      deps.generateRecommendationUseCase as any,
      undefined,
      sendToIr
    );
    return { useCase, sendToIr };
  };

  it("routes the new round's VALIDATED recommendation straight to the IR decision (no second SOC validation)", async () => {
    const { useCase, sendToIr } = build("VALIDATED");
    expect((await useCase.execute(input)).value.result).toBe("NOT_RESOLVED");
    expect(sendToIr.execute).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-1", recommendationId: "recommendation-2", actor: "system" }));
  });

  it("does not route a recommendation that failed validation", async () => {
    const { useCase, sendToIr } = build("INVALID");
    await useCase.execute(input);
    expect(sendToIr.execute).not.toHaveBeenCalled();
  });
});
