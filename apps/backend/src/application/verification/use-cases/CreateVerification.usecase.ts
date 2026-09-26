import { IVerificationRepository } from "../../../domain/verification/repositories/IVerificationRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { GenerateRecommendationUseCase } from "../../recommendation/use-cases/GenerateRecommendation.usecase";
import { PolicyEvaluator } from "../../../infrastructure/policy-engine/PolicyEvaluator";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Verification, VerificationResult } from "../../../domain/verification/entities/Verification.entity";
import { Result } from "../../../shared/result/Result";
import { INotificationDispatcherPort } from "../../notification/ports/INotificationDispatcherPort";
import { IN_APP_ROLES, InAppNotifier } from "../../notification/services/InAppNotifier";
import {
  buildVerificationNotResolvedEvent,
  buildInvestigationReopenedEvent,
} from "../../notification/services/NotificationEventBuilder";

export interface CreateVerificationInput {
  incidentId: string;
  tenantId: string;
  verifiedBy: string;
  responseId: string;
  wazuhIndex?: string | null;
  query: string;
  timeRangeStart?: Date | null;
  timeRangeEnd?: Date | null;
  matchingEvents: number;
  affectedHosts?: string[];
  iocRecurrence?: boolean;
  spreadDetected?: boolean;
  threatContained: boolean;
  beforeState?: Record<string, unknown> | null;
  afterState?: Record<string, unknown> | null;
  notes?: string | null;

  /**
   * Internal callers only (RunRehuntVerification).
   * The public HTTP DTO has no such field, so a client cannot claim
   * WAZUH_INDEXER evidence.
   */
  evidenceSource?: "MANUAL_ENTRY" | "WAZUH_INDEXER" | "MOCK_REHUNT";

  /**
   * Internal callers only (RunRehuntVerification): runs right after a new investigation cycle is opened and BEFORE
   * its recommendation is generated, so the new cycle's evidence exists when the recommendation is built.
   */
  onInvestigationReopened?: (newInvestigationNumber: number) => Promise<void>;
}

/** cluade.md §27: at most this many investigation/re-hunt rounds per incident; then escalate, never loop. */
export const MAX_INVESTIGATION_ROUNDS = 3;

/**
 * CreateVerificationUseCase — the ONLY place RESOLVED/NOT_RESOLVED is ever
 * decided (spec: "AI cannot declare RESOLVED", "RESOLVED cannot be
 * created without verification evidence").
 *
 * `result` is never accepted as caller input — it is DERIVED deterministically
 * from the evidence fields a human supplies from an actual Wazuh re-hunt:
 *
 *   RESOLVED iff threatContained AND !spreadDetected AND !iocRecurrence
 *             AND (matchingEvents ?? 0) === 0
 *
 * otherwise NOT_RESOLVED.
 *
 * This means even a human caller cannot bypass evidence-based determination
 * via the API — there is no `result` field to set.
 *
 * On NOT_RESOLVED/spread/not-contained, re-evaluates Policy (same call
 * every other module uses) and, if it says requireNewInvestigation, bumps
 * Incident.investigationNumber.
 *
 * When a new investigation is opened, a fresh recommendation is automatically
 * generated from the new investigation context. GenerateRecommendationUseCase
 * is responsible for obtaining the next recommendationNumber and superseding
 * the previous recommendation. Nothing here starts or executes a response —
 * the new recommendation still goes through Policy/Approval and a human.
 *
 * Round limit: when the incident is already on its MAX_INVESTIGATION_ROUNDS-th
 * cycle, no further cycle is opened and no recommendation is generated; the
 * incident is marked "escalated" (unresolved, not closed) and INVESTIGATION_ESCALATED (to IR_TEAM) is audited.
 * Policy's requireEscalation (e.g. RULE-V02 spread) is audited the same way.
 */
export type CreateVerificationError =
  | "INCIDENT_NOT_FOUND"
  | "RESPONSE_NOT_FOUND"
  | "RESPONSE_NOT_COMPLETED"
  | "ALREADY_VERIFIED";

export class CreateVerificationUseCase {
  constructor(
    private readonly verificationRepository: IVerificationRepository,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly incidentRepository: IIncidentRepository,
    private readonly policyEvaluator: PolicyEvaluator,
    private readonly auditLogger: AuditLogger,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly notificationDispatcher: INotificationDispatcherPort,
    private readonly vigixBaseUrl: string,
    private readonly generateRecommendationUseCase: GenerateRecommendationUseCase,
    private readonly inApp?: InAppNotifier
  ) {}

  async execute(
    input: CreateVerificationInput
  ): Promise<Result<Verification, CreateVerificationError>> {
    const incident = await this.incidentRepository.findById(
      input.incidentId,
      input.tenantId
    );

    if (!incident) {
      return Result.fail("INCIDENT_NOT_FOUND");
    }

    // A verification must be about a response that was actually carried out:
    // the ticket has to belong to this incident and be COMPLETED
    // (human-recorded execution result), and each ticket is verified once.
    // Without this a caller could post "contained, 0 events" for nothing
    // and get RESOLVED.
    const response = await this.responsePlanRepository.findById(
      input.responseId,
      input.tenantId
    );

    if (!response || response.incidentId !== input.incidentId) {
      return Result.fail("RESPONSE_NOT_FOUND");
    }

    if (response.status !== "COMPLETED") {
      return Result.fail("RESPONSE_NOT_COMPLETED");
    }

    const existing = await this.verificationRepository.findAllByIncident(
      input.incidentId,
      input.tenantId
    );

    if (existing.some((v) => v.responseId === response.id)) {
      return Result.fail("ALREADY_VERIFIED");
    }

    const spreadDetected = input.spreadDetected ?? false;
    const iocRecurrence = input.iocRecurrence ?? false;
    const matchingEvents = input.matchingEvents;

    const result: VerificationResult =
      input.threatContained &&
      !spreadDetected &&
      !iocRecurrence &&
      (matchingEvents ?? 0) === 0
        ? "RESOLVED"
        : "NOT_RESOLVED";

    const verification = await this.verificationRepository.create({
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      responseId: response.id,
      wazuhIndex: input.wazuhIndex ?? null,
      query: input.query,
      timeRangeStart: input.timeRangeStart ?? null,
      timeRangeEnd: input.timeRangeEnd ?? null,
      matchingEvents,
      affectedHosts: input.affectedHosts ?? [],
      iocRecurrence,
      spreadDetected,
      threatContained: input.threatContained,
      beforeState: input.beforeState ?? null,

      // Provenance is stamped by the backend, never taken from the HTTP body:
      // MANUAL_ENTRY unless an internal caller (the Wazuh re-hunt use case)
      // supplied real indexer evidence.
      afterState: {
        ...(input.afterState ?? {}),
        evidenceSource: input.evidenceSource ?? "MANUAL_ENTRY",
      },

      result,
      notes: input.notes ?? null,
      verifiedBy: input.verifiedBy,
    });

    const policyResult = await this.policyEvaluator.evaluate(input.tenantId, {
      verificationResult: result,
      spreadDetected,
      threatContained: input.threatContained,
    });

    let newInvestigationNumber: number | undefined;
    const roundsExhausted = policyResult.requireNewInvestigation && incident.investigationNumber >= MAX_INVESTIGATION_ROUNDS;
    const escalationReasons = [
      ...(roundsExhausted ? ["MAX_INVESTIGATION_ROUNDS_REACHED"] : []),
      ...(policyResult.requireEscalation ? ["POLICY_REQUIRE_ESCALATION"] : []),
    ];

    if (roundsExhausted) {
      // No new cycle, no new recommendation, nothing executed: the loop ends and a human IR decision is required.
      // The incident is marked ESCALATED (not closed); INVESTIGATION_ESCALATED is audited below.
      await this.incidentRepository.updateStatus(input.incidentId, input.tenantId, "escalated");
    } else if (policyResult.requireNewInvestigation) {
      const updatedIncident =
        await this.incidentRepository.incrementInvestigationNumber(
          input.incidentId,
          input.tenantId
        );

      newInvestigationNumber = updatedIncident.investigationNumber;

      if (input.onInvestigationReopened) {
        try {
          await input.onInvestigationReopened(newInvestigationNumber);
        } catch (err) {
          console.error("Failed to record new-cycle evidence before recommendation", verification.id, err);
        }
      }

      /*
       * Investigation has now moved to the next cycle.
       *
       * GenerateRecommendationUseCase reads the current investigationNumber
       * through RecommendationContextBuilder, so this generates a fresh
       * recommendation for Investigation #2 rather than copying
       * Recommendation #1.
       *
       * Generation failure must not invalidate the already-persisted
       * verification or investigation reopen. The failure is logged and the
       * workflow can still be recovered/retried separately.
       */
      try {
        const recommendationResult =
          await this.generateRecommendationUseCase.execute({
            incidentId: input.incidentId,
            tenantId: input.tenantId,
          });

        if (recommendationResult.isFailure) {
          console.error(
            "Failed to auto-generate recommendation after investigation reopened",
            verification.id,
            recommendationResult.error
          );
        }
      } catch (err) {
        console.error(
          "Failed to auto-generate recommendation after investigation reopened",
          verification.id,
          err
        );
      }

      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: "system",
        action: "INVESTIGATION_REOPENED",
        entity: "Incident",
        entityId: input.incidentId,
        metadata: {
          causedByVerificationId: verification.id,
          newInvestigationNumber,
          matchedPolicies: policyResult.matchedPolicies,
        },
      });

      try {

        await this.notificationDispatcher.emit(
          buildInvestigationReopenedEvent({
            tenantId: input.tenantId,
            baseUrl: this.vigixBaseUrl,
            incident: updatedIncident,
            verification,
          })
        );
      } catch (err) {
        console.error(
          "Failed to emit INVESTIGATION_REOPENED notification for verification",
          verification.id,
          err
        );
      }
    } else if (result === "RESOLVED") {
      await this.incidentRepository.updateStatus(
        input.incidentId,
        input.tenantId,
        "resolved"
      );
      // The only place an incident becomes RESOLVED (manual PATCH /status cannot).
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: input.verifiedBy,
        action: "INCIDENT_RESOLVED",
        entity: "Incident",
        entityId: input.incidentId,
        metadata: { verificationId: verification.id, investigationNumber: incident.investigationNumber, evidenceSource: input.evidenceSource ?? "MANUAL_ENTRY" },
      });
      await this.inApp?.notify({
        tenantId: input.tenantId,
        eventType: "INCIDENT_RESOLVED",
        roles: IN_APP_ROLES.INCIDENT_RESOLVED,
        incidentId: input.incidentId,
        responseId: input.responseId,
        title: `Incident RESOLVED — re-hunt found no recurrence (round ${incident.investigationNumber})`,
      });
    }

    if (result === "NOT_RESOLVED") {
      try {

        await this.notificationDispatcher.emit(
          buildVerificationNotResolvedEvent({
            tenantId: input.tenantId,
            baseUrl: this.vigixBaseUrl,
            incident,
            verification,
          })
        );
      } catch (err) {
        console.error(
          "Failed to emit VERIFICATION_NOT_RESOLVED notification for verification",
          verification.id,
          err
        );
      }
    }

    if (roundsExhausted) {
      // Incident-level event alongside INVESTIGATION_ESCALATED: no automatic response, handed off for human SOC / IR review.
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: "system",
        action: "INCIDENT_ESCALATED",
        entity: "Incident",
        entityId: input.incidentId,
        metadata: { causedByVerificationId: verification.id, reasons: escalationReasons, handoffTo: ["SOC", "IR_TEAM"], investigationNumber: incident.investigationNumber, maxInvestigationRounds: MAX_INVESTIGATION_ROUNDS },
      });
      await this.inApp?.notify({
        tenantId: input.tenantId,
        eventType: "INCIDENT_ESCALATED",
        roles: IN_APP_ROLES.INCIDENT_ESCALATED,
        incidentId: input.incidentId,
        responseId: input.responseId,
        title: `Incident ESCALATED — not resolved after ${MAX_INVESTIGATION_ROUNDS} re-hunt rounds`,
        body: escalationReasons.join(", "),
      });
    }

    if (escalationReasons.length > 0) {
      await this.auditLogger.record({
        tenantId: input.tenantId,
        actor: "system",
        action: "INVESTIGATION_ESCALATED",
        entity: "Incident",
        entityId: input.incidentId,
        metadata: {
          causedByVerificationId: verification.id,
          reasons: escalationReasons,
          escalatedTo: "IR_TEAM",
          investigationNumber: newInvestigationNumber ?? incident.investigationNumber,
          maxInvestigationRounds: MAX_INVESTIGATION_ROUNDS,
          matchedPolicies: policyResult.matchedPolicies,
        },
      });
    }

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.verifiedBy,
      action: "VERIFICATION_COMPLETED",
      entity: "Verification",
      entityId: verification.id,
      metadata: {
        incidentId: input.incidentId,
        result,
        spreadDetected,
        threatContained: input.threatContained,
        iocRecurrence,
        requireNewInvestigation: policyResult.requireNewInvestigation,
        newInvestigationNumber,
        escalated: escalationReasons.length > 0,
        evidenceSource: input.evidenceSource ?? "MANUAL_ENTRY",
      },
    });

    return Result.ok(verification);
  }
}