"""Builds run.json / evidence / metrics for the supplementary escalation test from the runner output and the DB extract.
Read-only over both inputs."""
import json, os, shutil, hashlib

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "..", "..", "extended-evaluation", "runs", "supp-escalation-20261003.json")
run = json.load(open(SRC, encoding="utf8"))
db = json.load(open(os.path.join(ROOT, "evidence", "db-extract.json"), encoding="utf8"))
shutil.copyfile(SRC, os.path.join(ROOT, "run.json"))

vers = db["verifications"]
logs = db["auditLogs"]
act = lambda n: [l for l in logs if l["action"] == n]

metrics_rounds = []
for r in run["rounds"]:
    n = r["round"]
    v = vers[n - 1]
    json.dump(dict(round=n, investigationNumber=r["investigationNumber"], chosenResponseStep=r["recommendation"]["chosenStep"],
                   recommendationUsed=dict(number=r["recommendation"]["number"], investigationNumber=r["recommendation"]["investigationNumber"], fallbackToEarlierRecommendation=r["fallbackToEarlierRecommendation"]),
                   newRoundRecommendationGeneration=r["recommendationGeneration"], responseId=r["responseId"], responseCompletedAt=r["responseCompletedAt"],
                   recurrence=r["recurrence"], verification=dict(id=v["id"], result=v["result"], matchingEvents=v["matchingEvents"], iocRecurrence=v["iocRecurrence"],
                   spreadDetected=v["spread"], threatContained=v["threatContained"], verifiedAt=v["verifiedAt"], evidenceSource=v["afterState"].get("evidenceSource")),
                   incidentAfter=r["incidentAfter"], continues=r["incidentAfter"]["status"] != "escalated"),
              open(os.path.join(ROOT, "evidence", f"rehunt-round-{n}.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
    metrics_rounds.append(dict(round=n, result=v["result"], matchingEvents=v["matchingEvents"], incidentStatusAfter=r["incidentAfter"]["status"]))

esc = [l for l in logs if l["action"] in ("INVESTIGATION_REOPENED", "INVESTIGATION_ESCALATED", "INCIDENT_ESCALATED", "VERIFICATION_COMPLETED", "REHUNT_STARTED")]
final = db["incident"]
json.dump(dict(incidentId=final["id"], finalStatus=final["status"], finalInvestigationNumber=final["investigation_number"], closedAt=final["closed_at"],
               auditTrail=[dict(at=l["at"], action=l["action"], metadata=l["metadata"]) for l in esc]),
          open(os.path.join(ROOT, "evidence", "escalation.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)

max_round = max(r["investigationNumber"] for r in run["rounds"])
metrics = dict(
    purpose="Supplementary escalation test (re-hunt failure x R_max=3 -> ESCALATED); not part of Final Evaluation v3.3",
    rMax=3, rehuntRoundsObserved=len(vers), maxObservedInvestigationRound=max(i["number"] for i in db["investigations"]),
    rounds=metrics_rounds, allRoundsUnresolved=all(v["result"] == "NOT_RESOLVED" for v in vers),
    finalStatus=final["status"], round4Observed=any(i["number"] > 3 for i in db["investigations"]) or len(vers) > 3 or len(act("REHUNT_STARTED")) > 3,
    counts=dict(REHUNT_STARTED=len(act("REHUNT_STARTED")), VERIFICATION_COMPLETED=len(act("VERIFICATION_COMPLETED")), INVESTIGATION_REOPENED=len(act("INVESTIGATION_REOPENED")),
                INVESTIGATION_ESCALATED=len(act("INVESTIGATION_ESCALATED")), INCIDENT_ESCALATED=len(act("INCIDENT_ESCALATED")),
                RESPONSE_PLAN_CREATED=len(act("RESPONSE_PLAN_CREATED")), RECOMMENDATION_GENERATED=len(act("RECOMMENDATION_GENERATED")),
                RECOMMENDATION_GENERATION_FAILED=len(act("RECOMMENDATION_GENERATION_FAILED"))),
    runnerChecks=dict(passed=sum(1 for c in run["checks"] if c["pass"]), total=len(run["checks"])),
    runnerResult=run["result"],
    caveats=["Rounds 2 and 3: no new VALIDATED recommendation (RECOMMENDATION_GENERATION_FAILED reason NO_NEW_RECOMMENDATION, 5 model attempts each); the runner handed an unexecuted step of recommendation #1 to IR (recorded fallback)",
             "The recurrence is produced by the runner; the decisions NOT_RESOLVED / reopen / ESCALATE are the product's",
             "IR approvals are scripted; single scenario (TC-07 telemetry)"],
    notAnApprovalMetric="IR_TEAM approval requirements (3 scripted approvals) are not counted as escalation",
    integrity=dict(runnerOutputSha256=hashlib.sha256(open(SRC, "rb").read()).hexdigest()),
)
json.dump(metrics, open(os.path.join(ROOT, "metrics", "escalation-metrics.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)
print(json.dumps({k: metrics[k] for k in ("rehuntRoundsObserved", "maxObservedInvestigationRound", "allRoundsUnresolved", "finalStatus", "round4Observed", "counts", "runnerChecks")}, indent=1))
