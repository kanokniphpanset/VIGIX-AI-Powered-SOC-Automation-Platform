import {
  RunRehuntVerificationUseCase,
} from "../src/application/verification/use-cases/RunRehuntVerification.usecase";

import {
  ISiemRehuntPort,
  RehuntError,
  RehuntResult,
} from "../src/application/verification/ports/ISiemRehuntPort";

import { Result } from "../src/shared/result/Result";

function createIncident(overrides: Partial<any> = {}) {
  return {
    id: "incident-1",
    tenantId: "tenant-1",
    alertId: "alert-1",
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
    target: null,
    completedAt: new Date("2026-09-22T10:00:00.000Z"),
    updatedAt: new Date("2026-09-22T10:30:00.000Z"),
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

function createEvidence(
  overrides: Partial<RehuntResult> = {}
): RehuntResult {
  return {
    source: "WAZUH_INDEXER",
    index: "wazuh-alerts-*",
    query: '{"query":{"match_all":{}}}',
    timeRange: {
      start: "2026-09-22T10:00:00.000Z",
      end: "2026-09-22T11:00:00.000Z",
    },
    matchingEvents: 0,
    affectedHosts: [],
    iocRecurrence: false,
    spreadDetected: false,
    threatContained: true,
    events: [],
    truncated: false,
    ...overrides,
  };
}

function createDependencies(
  options: {
    configured?: boolean;
    incident?: any;
    response?: any;
    alert?: any;
    existingVerifications?: any[];
    iocs?: any[];
    evidence?: RehuntResult;
    rehuntError?: RehuntError;
    verificationResult?: any;
    investigationNumberAfter?: number;
  } = {}
) {
  const rehunt = {
    isConfigured: jest
      .fn()
      .mockReturnValue(options.configured ?? true),

    health: jest.fn(),

    rehunt: jest.fn().mockImplementation(async () => {
      if (options.rehuntError) {
        throw options.rehuntError;
      }

      return options.evidence ?? createEvidence();
    }),
  } as unknown as ISiemRehuntPort;

  const incidentRepository = {
    findById: jest.fn().mockResolvedValue(
      Object.prototype.hasOwnProperty.call(options, "incident")
        ? options.incident
        : createIncident()
    ),

    incrementInvestigationNumber: jest.fn().mockResolvedValue(
      createIncident({
        investigationNumber:
          options.investigationNumberAfter ?? 2,
      })
    ),

    updateStatus: jest.fn().mockResolvedValue(undefined),
  };

  const alertRepository = {
    findById: jest.fn().mockResolvedValue(
      options.alert ?? {
        id: "alert-1",
        rawPayload: {
          agent: {
            name: "endpoint-01",
          },
          rule: {
            id: "100001",
            description: "Suspicious PowerShell execution",
          },
        },
      }
    ),
  };

  const responsePlanRepository = {
    findById: jest.fn().mockResolvedValue(
      Object.prototype.hasOwnProperty.call(options, "response")
        ? options.response
        : createResponse()
    ),
  };

  const verificationRepository = {
    findAllByIncident: jest.fn().mockResolvedValue(
      options.existingVerifications ?? []
    ),
  };

  const contextRepository = {
    getIocs: jest.fn().mockResolvedValue(
      options.iocs ?? [
        {
          iocType: "ip",
          iocValue: "10.10.10.10",
        },
      ]
    ),
  };

  const verificationEntity = createVerification(
    options.verificationResult ?? {}
  );

  const createVerificationUseCaseMock = {
    execute: jest.fn().mockResolvedValue(
      Result.ok(verificationEntity)
    ),
  };

  const investigations = {
    listByIncident: jest.fn().mockResolvedValue([]),
    createEvidence: jest.fn().mockResolvedValue(undefined),
  };

  const useCase = new RunRehuntVerificationUseCase(
    rehunt,
    createVerificationUseCaseMock as any,
    incidentRepository as any,
    alertRepository as any,
    responsePlanRepository as any,
    verificationRepository as any,
    contextRepository as any,
    investigations as any
  );

  return {
    useCase,
    rehunt,
    incidentRepository,
    alertRepository,
    responsePlanRepository,
    verificationRepository,
    contextRepository,
    createVerification: createVerificationUseCaseMock,
    investigations,
  };
}

describe("RunRehuntVerificationUseCase", () => {
  it(
    "returns REHUNT_NOT_CONFIGURED when Wazuh re-hunt is not configured",
    async () => {
      const deps = createDependencies({
        configured: false,
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("REHUNT_NOT_CONFIGURED");

      expect(
        deps.incidentRepository.findById
      ).not.toHaveBeenCalled();

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "returns INCIDENT_NOT_FOUND when incident does not exist",
    async () => {
      const deps = createDependencies({
        incident: null,
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("INCIDENT_NOT_FOUND");

      expect(
        deps.responsePlanRepository.findById
      ).not.toHaveBeenCalled();

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "returns RESPONSE_NOT_FOUND when response does not exist",
    async () => {
      const deps = createDependencies({
        response: null,
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("RESPONSE_NOT_FOUND");

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "returns RESPONSE_NOT_FOUND when response belongs to another incident",
    async () => {
      const deps = createDependencies({
        response: createResponse({
          incidentId: "incident-999",
        }),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("RESPONSE_NOT_FOUND");

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "returns RESPONSE_NOT_COMPLETED when response is not completed",
    async () => {
      const deps = createDependencies({
        response: createResponse({
          status: "IN_PROGRESS",
        }),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("RESPONSE_NOT_COMPLETED");

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "returns ALREADY_VERIFIED when the response was already verified",
    async () => {
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
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);
      expect(result.error).toBe("ALREADY_VERIFIED");

      expect(
        deps.rehunt.rehunt
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "builds the re-hunt query from alert host, rule, IOC and response target",
    async () => {
      const deps = createDependencies({
        response: createResponse({
          target: "192.168.1.50",
        }),
        iocs: [
          {
            iocType: "ip",
            iocValue: "10.10.10.10",
          },
        ],
      });

      await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(
        deps.rehunt.rehunt
      ).toHaveBeenCalledTimes(1);

      const query =
        (deps.rehunt.rehunt as jest.Mock)
          .mock.calls[0][0];

      expect(query.incidentId).toBe("incident-1");
      expect(query.responseId).toBe("response-1");

      expect(query.hosts).toContain(
        "endpoint-01"
      );

      expect(query.iocs).toEqual(
        expect.arrayContaining([
          {
            type: "ip",
            value: "10.10.10.10",
          },
          {
            type: "ip",
            value: "192.168.1.50",
          },
        ])
      );

      expect(query.rule).toEqual({
        id: "100001",
        description:
          "Suspicious PowerShell execution",
      });

      expect(
        query.timeRange.start
      ).toEqual(
        new Date(
          "2026-09-22T10:00:00.000Z"
        )
      );

      expect(
        query.timeRange.end
      ).toEqual(expect.any(Date));
    }
  );

  it(
    "passes Wazuh evidence to CreateVerificationUseCase",
    async () => {
      const evidence = createEvidence({
        index:
          "wazuh-alerts-2026.09.22",
        query:
          '{"query":{"match":{"agent.name":"endpoint-01"}}}',
        matchingEvents: 0,
        affectedHosts: [],
        iocRecurrence: false,
        spreadDetected: false,
        threatContained: true,
      });

      const deps = createDependencies({
        evidence,
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
        notes: "Post-containment re-hunt",
      });

      expect(result.isSuccess).toBe(true);

      expect(
        deps.createVerification.execute
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          incidentId: "incident-1",
          tenantId: "tenant-1",
          verifiedBy: "analyst-1",
          responseId: "response-1",
          wazuhIndex:
            "wazuh-alerts-2026.09.22",
          query: evidence.query,
          matchingEvents: 0,
          affectedHosts: [],
          iocRecurrence: false,
          spreadDetected: false,
          threatContained: true,
          notes: "Post-containment re-hunt",
          evidenceSource: "WAZUH_INDEXER",
        })
      );
    }
  );

  it(
    "returns NOT_RESOLVED evidence to CreateVerificationUseCase when matching events remain",
    async () => {
      const evidence = createEvidence({
        matchingEvents: 3,
        affectedHosts: ["endpoint-01"],
        iocRecurrence: true,
        spreadDetected: false,
        threatContained: false,
        events: [
          {
            id: "event-1",
            timestamp:
              "2026-09-22T10:45:00.000Z",
            host: "endpoint-01",
            agentId: "001",
            ruleId: "100001",
            ruleLevel: 10,
            ruleDescription:
              "Suspicious PowerShell execution",
            matchedIoc: true,
          },
        ],
      });

      const deps = createDependencies({
        evidence,
        verificationResult: {
          result: "NOT_RESOLVED",
        },
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isSuccess).toBe(true);

      expect(
        result.value.verification.result
      ).toBe("NOT_RESOLVED");

      expect(
        deps.createVerification.execute
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          matchingEvents: 3,
          affectedHosts: ["endpoint-01"],
          iocRecurrence: true,
          threatContained: false,
          evidenceSource: "WAZUH_INDEXER",
        })
      );
    }
  );

  it(
    "maps RehuntError INSUFFICIENT_CRITERIA to REHUNT_INSUFFICIENT_CRITERIA",
    async () => {
      const deps = createDependencies({
        rehuntError: new RehuntError(
          "INSUFFICIENT_CRITERIA",
          "No usable re-hunt criteria"
        ),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);

      expect(result.error).toBe(
        "REHUNT_INSUFFICIENT_CRITERIA"
      );

      expect(
        deps.createVerification.execute
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "maps RehuntError UNREACHABLE to REHUNT_UNREACHABLE",
    async () => {
      const deps = createDependencies({
        rehuntError: new RehuntError(
          "UNREACHABLE",
          "Wazuh Indexer unreachable"
        ),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);

      expect(result.error).toBe(
        "REHUNT_UNREACHABLE"
      );

      expect(
        deps.createVerification.execute
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "maps RehuntError QUERY_FAILED to REHUNT_QUERY_FAILED",
    async () => {
      const deps = createDependencies({
        rehuntError: new RehuntError(
          "QUERY_FAILED",
          "Indexer query failed"
        ),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);

      expect(result.error).toBe(
        "REHUNT_QUERY_FAILED"
      );

      expect(
        deps.createVerification.execute
      ).not.toHaveBeenCalled();
    }
  );

  it(
    "maps RehuntError NOT_CONFIGURED to REHUNT_NOT_CONFIGURED",
    async () => {
      const deps = createDependencies({
        rehuntError: new RehuntError(
          "NOT_CONFIGURED",
          "Re-hunt is not configured"
        ),
      });

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isFailure).toBe(true);

      expect(result.error).toBe(
        "REHUNT_NOT_CONFIGURED"
      );
    }
  );

  it(
    "records re-hunt events as evidence when a new investigation is opened",
    async () => {
      const evidence = createEvidence({
        matchingEvents: 1,
        affectedHosts: ["endpoint-01"],
        threatContained: false,
        events: [
          {
            id: "event-1",
            timestamp:
              "2026-09-22T10:45:00.000Z",
            host: "endpoint-01",
            agentId: "001",
            ruleId: "100001",
            ruleLevel: 10,
            ruleDescription:
              "Suspicious PowerShell execution",
            matchedIoc: true,
          },
        ],
      });

      const deps = createDependencies({
        evidence,
        verificationResult: {
          result: "NOT_RESOLVED",
        },
      });

      deps.incidentRepository.findById
        .mockResolvedValueOnce(
          createIncident()
        )
        .mockResolvedValueOnce(
          createIncident({
            investigationNumber: 2,
          })
        );

      deps.investigations.listByIncident
        .mockResolvedValue([
          {
            id: "investigation-2",
            incidentId: "incident-1",
            investigationNumber: 2,
            isCurrent: true,
          },
        ]);

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isSuccess).toBe(true);

      expect(
        deps.investigations.listByIncident
      ).toHaveBeenCalledWith(
        "incident-1",
        "tenant-1"
      );

      expect(
        deps.investigations.createEvidence
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          investigationId:
            "investigation-2",
          alertId: null,
          type: "WAZUH_EVENT",
          source: "WAZUH_INDEXER",
          origin: "SYSTEM",
          title:
            "Rule 100001: Suspicious PowerShell execution",
          createdBy: "analyst-1",
          iocIds: [],
        })
      );
    }
  );

  it(
    "does not fail verification when recurrence evidence recording fails",
    async () => {
      const evidence = createEvidence({
        matchingEvents: 1,
        threatContained: false,
        events: [
          {
            id: "event-1",
            timestamp:
              "2026-09-22T10:45:00.000Z",
            host: "endpoint-01",
            agentId: "001",
            ruleId: "100001",
            ruleLevel: 10,
            ruleDescription:
              "Suspicious PowerShell execution",
            matchedIoc: true,
          },
        ],
      });

      const deps = createDependencies({
        evidence,
        verificationResult: {
          result: "NOT_RESOLVED",
        },
      });

      deps.incidentRepository.findById
        .mockResolvedValueOnce(
          createIncident()
        )
        .mockResolvedValueOnce(
          createIncident({
            investigationNumber: 2,
          })
        );

      deps.investigations.listByIncident
        .mockResolvedValue([
          {
            id: "investigation-2",
            isCurrent: true,
          },
        ]);

      deps.investigations.createEvidence
        .mockRejectedValue(
          new Error(
            "evidence storage failure"
          )
        );

      const result = await deps.useCase.execute({
        incidentId: "incident-1",
        responseId: "response-1",
        tenantId: "tenant-1",
        verifiedBy: "analyst-1",
      });

      expect(result.isSuccess).toBe(true);

      expect(
        result.value.verification.result
      ).toBe("NOT_RESOLVED");
    }
  );
});

describe("Re-hunt IOC selection: the alert's own endpoint identity is never hunted", () => {
  const alert = { id: "alert-1", rawPayload: { agent: { id: "001", name: "Web-01", ip: "10.20.30.40" }, rule: { id: "5712", description: "sshd: brute force" }, data: { srcip: "198.51.100.23" } } };
  const iocs = [
    { iocType: "DOMAIN", iocValue: "web-01" }, // agent.name (case-insensitive)
    { iocType: "IPV4", iocValue: "10.20.30.40" }, // agent.ip
    { iocType: "IPV4", iocValue: "198.51.100.23" }, // attacker
  ];
  const run = (deps: ReturnType<typeof createDependencies>) =>
    deps.useCase.execute({ incidentId: "incident-1", responseId: "response-1", tenantId: "tenant-1", verifiedBy: "analyst-1" });

  it("A/B/C: excludes agent.name and agent.ip from the search, keeps the attacker IP, records what was excluded", async () => {
    const deps = createDependencies({ alert, iocs });
    await run(deps);
    const query = (deps.rehunt.rehunt as jest.Mock).mock.calls[0][0];
    expect(query.iocs).toEqual([{ type: "IPV4", value: "198.51.100.23" }]);
    const saved = deps.createVerification.execute.mock.calls[0][0];
    expect(saved.beforeState.criteria.iocs).toEqual([{ type: "IPV4", value: "198.51.100.23" }]);
    expect(saved.beforeState.criteria.excludedIocs.map((i: { value: string }) => i.value)).toEqual(["web-01", "10.20.30.40"]);
    expect(saved.afterState.excludedIocs).toHaveLength(2);
    // The stored IOC records are only read, never deleted or changed.
    expect(deps.contextRepository.getIocs).toHaveBeenCalledTimes(1);
  });

  it("keeps the adapter's searched / skipped IOC lists in the verification evidence (no schema change)", async () => {
    const evidence = createEvidence({
      skippedIocTypes: ["DOMAIN"],
      searchedIocs: [{ type: "IPV4", value: "198.51.100.23" }],
      skippedIocs: [{ type: "DOMAIN", value: "evil.example", reason: "No searchable DOMAIN field in current Wazuh index" }],
    });
    const deps = createDependencies({ alert, iocs: [...iocs, { iocType: "DOMAIN", iocValue: "evil.example" }], evidence });
    await run(deps);
    const saved = deps.createVerification.execute.mock.calls[0][0];
    expect(saved.afterState).toMatchObject({
      skippedIocTypes: ["DOMAIN"],
      searchedIocs: [{ type: "IPV4", value: "198.51.100.23" }],
      skippedIocs: [{ type: "DOMAIN", value: "evil.example" }],
    });
  });

  it("an alert without agent identity filters nothing", async () => {
    const deps = createDependencies({ alert: { id: "alert-1", rawPayload: { rule: { id: "1" } } }, iocs });
    await run(deps);
    expect((deps.rehunt.rehunt as jest.Mock).mock.calls[0][0].iocs).toHaveLength(3);
  });
});

describe("Phase 2D: classified re-hunt results", () => {
  const alert = {
    id: "alert-1",
    rawPayload: {
      agent: { name: "attack-endpoint", id: "009", ip: "172.19.0.8" },
      rule: { id: "100301", description: "d", groups: ["syscheck", "malware", "vigix_eval"] },
      syscheck: { path: "/root/Downloads/Invoice.exe", event: "added" },
      data: { win: { eventdata: { processGuid: "{G-1}" } } },
    },
  };
  const run = (deps: ReturnType<typeof createDependencies>) =>
    deps.useCase.execute({ incidentId: "incident-1", responseId: "response-1", tenantId: "tenant-1", verifiedBy: "analyst-1" });
  const classified = (over: Partial<RehuntResult>) => createEvidence({ coverage: { sources: { alerts: "AVAILABLE", archives: "NOT_AVAILABLE" }, indexRange: null, windowCoveredByIndex: true, agents: [], complete: true, gaps: [], limitations: [] }, totalMatched: 0, ignoredEvents: 0, ...over });

  it("passes agent id, rule groups and the original process / file identifiers to the provider", async () => {
    const deps = createDependencies({ alert, evidence: classified({ classification: "NO_MATCH_COVERED" }) });
    await run(deps);
    const q = (deps.rehunt.rehunt as jest.Mock).mock.calls[0][0];
    expect(q.agentIds).toEqual(["009"]);
    expect(q.rule).toMatchObject({ id: "100301", groups: ["syscheck", "malware", "vigix_eval"] });
    expect(q.correlation).toEqual({ processGuids: ["{G-1}"], filePaths: ["/root/Downloads/Invoice.exe"] });
  });

  it.each([
    ["INCOMPLETE", "REHUNT_INCOMPLETE"],
    ["UNCORROBORATED_MATCH", "REHUNT_UNCONFIRMED"],
  ] as const)("%s records NO verification (neither RESOLVED nor NOT_RESOLVED) and fails with %s", async (classification, code) => {
    const deps = createDependencies({ alert, evidence: classified({ classification, matchingEvents: 3, totalMatched: 3, threatContained: false }) });
    const result = await run(deps);
    expect(result.isFailure).toBe(true);
    expect(result.error).toBe(code);
    expect(deps.createVerification.execute).not.toHaveBeenCalled();
    expect(deps.investigations.createEvidence).not.toHaveBeenCalled();
  });

  it("an inconclusive result is audited with the gaps, so the analyst can see why", async () => {
    const audit = { record: jest.fn().mockResolvedValue(undefined) };
    const deps = createDependencies({ alert, evidence: classified({ classification: "INCOMPLETE", coverage: { sources: { alerts: "AVAILABLE", archives: "NOT_AVAILABLE" }, indexRange: null, windowCoveredByIndex: true, agents: [], complete: false, gaps: ["agent X was not active"], limitations: [] } }) });
    const useCase = new RunRehuntVerificationUseCase(deps.rehunt, deps.createVerification as any, deps.incidentRepository as any, deps.alertRepository as any, deps.responsePlanRepository as any, deps.verificationRepository as any, deps.contextRepository as any, deps.investigations as any, audit as any);
    await useCase.execute({ incidentId: "incident-1", responseId: "response-1", tenantId: "tenant-1", verifiedBy: "analyst-1" });
    const failed = audit.record.mock.calls.map((c) => c[0]).find((a) => a.action === "REHUNT_FAILED");
    expect(failed.metadata).toMatchObject({ code: "INCOMPLETE", classification: "INCOMPLETE", gaps: ["agent X was not active"] });
  });

  it("NO_MATCH_COVERED creates the verification with the coverage that justified it", async () => {
    const deps = createDependencies({ alert, evidence: classified({ classification: "NO_MATCH_COVERED", ignoredEvents: 1, totalMatched: 1 }) });
    const result = await run(deps);
    expect(result.isSuccess).toBe(true);
    const saved = deps.createVerification.execute.mock.calls[0][0];
    expect(saved).toMatchObject({ matchingEvents: 0, threatContained: true, spreadDetected: false, iocRecurrence: false });
    expect(saved.afterState).toMatchObject({ classification: "NO_MATCH_COVERED", totalMatched: 1, ignoredEvents: 1 });
    expect(saved.afterState.coverage.complete).toBe(true);
  });

  it("NEW_SCOPE_ACTIVITY creates a NOT_RESOLVED-driving verification and stores the correlation reasons", async () => {
    const deps = createDependencies({ alert, evidence: classified({ classification: "NEW_SCOPE_ACTIVITY", matchingEvents: 2, totalMatched: 2, threatContained: false, iocRecurrence: true, spreadDetected: true, affectedHosts: ["other"], correlationReasons: { SAME_RULE: 2 } }) });
    await run(deps);
    const saved = deps.createVerification.execute.mock.calls[0][0];
    expect(saved).toMatchObject({ spreadDetected: true, iocRecurrence: true, threatContained: false, matchingEvents: 2, affectedHosts: ["other"] });
    expect(saved.afterState.correlationReasons).toEqual({ SAME_RULE: 2 });
  });

  it("a provider that does not classify (mock, older providers) behaves exactly as before", async () => {
    const deps = createDependencies({ alert, evidence: createEvidence({ matchingEvents: 1, iocRecurrence: true, threatContained: false }) });
    const result = await run(deps);
    expect(result.isSuccess).toBe(true);
    expect(deps.createVerification.execute.mock.calls[0][0].afterState.classification).toBeUndefined();
  });
});
