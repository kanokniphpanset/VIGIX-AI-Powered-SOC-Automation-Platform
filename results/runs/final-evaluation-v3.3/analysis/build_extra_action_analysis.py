"""Post-hoc extra-action validity analysis for Final Evaluation v3.3.
Read-only over run.json / cases/*.json / evidence-extract.json (extracted from the frozen soar_v33_eval DB).
Never touches the Ground Truth, the evaluator or any case artifact; does not change the primary metric.
The per-pair judgements below are fixed text written from the evidence in evidence-extract.json and from the
frozen playbook seed / Action Catalog / policy seed; the script only verifies the actual targets and computes counts."""
import csv, hashlib, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.dirname(HERE)


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


cases = {}
for i in range(1, 11):
    cid = f"TC-{i:02d}"
    cases[cid] = json.load(open(os.path.join(RUN, "cases", cid + ".json"), encoding="utf8"))

# ---------------------------------------------------------------- per-case coverage (from the frozen scoring)
cov = []
for cid, c in cases.items():
    cr = c.get("correctRecommendation") or {}
    am = c.get("actionMatch") or {}
    matched = cr.get("matchedRecommendations") or []
    missing = cr.get("missingRecommendations") or []
    unexpected = cr.get("unexpectedRecommendations") or []
    required = len(matched) + len(missing)
    ai_pairs = len(am.get("actualActions") or [])
    if cr.get("correct") is None:  # TC-05: no recommendation, harness did not score; GT has 1 required pair
        required = len((c.get("correctnessGroundTruth") or {}).get("expectedRecommendations") or []) or 1
    cov.append(dict(case=cid, exactMatch="PASS" if cr.get("correct") else "FAIL", required=required, covered=len(matched),
                    aiPairs=ai_pairs, unexpected=len(unexpected), missing=len(missing),
                    unexpectedPairs=[f"{u['action']} -> {u['target']}" for u in unexpected]))

# ---------------------------------------------------------------- judgements
J = {
 ("TC-04", "ACT-REVOKE-SESSION"): dict(
   evidence="SUPPORTED", playbook="ALIGNED", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="VALID_EXTRA_ACTION",
   evidenceNote="Wazuh rule 40112 (L12): sshd 'Accepted password for victim from 172.19.0.3' after repeated failures = a successful authenticated session of 'victim' (authentication evidence). USERNAME IOC 'victim' and IPV4 172.19.0.3 both ACTIVE from the alert.",
   playbookNote="PB-ACCOUNT-COMPROMISE allowedActions includes ACT-REVOKE-SESSION; step 4 (unconditional) = reset credentials AND revoke active sessions of the account recorded in the authentication evidence. The GT lists ACT-RESET-CREDENTIAL (same step 4) but not ACT-REVOKE-SESSION.",
   policyNote="Impact MEDIUM; RULE-P07 (HIGH severity) -> IR_TEAM approval required (recommendation does not execute); catalog evidence (VALIDATED_IOC_TARGET, AUTHENTICATION_EVIDENCE) satisfied and accepted by the validator.",
   targetNote="'victim' = account IOC from alert data.dstuser; targetKind account matches the action."),
 ("TC-07", "ACT-BLOCK-URL"): dict(
   evidence="SUPPORTED", playbook="ALIGNED", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="VALID_EXTRA_ACTION",
   evidenceNote="Rule 100320 (L13) alert data.url = http://vigix-eval-c2.net:8080/gate.php (HTTP 200 beacon); the identical string is an ACTIVE URL IOC of the incident.",
   playbookNote="PB-C2 step 1 (unconditional) lists 'IP / domain / URL' (ACT-BLOCK-DESTINATION-IP / ACT-BLOCK-DOMAIN / ACT-BLOCK-URL); action in allowedActions. Redundant with the (expected) domain block but not contradicting it.",
   policyNote="POL-A02 (validated IOC, related event, supporting evidence) satisfied; RULE-P07 -> IR_TEAM approval.",
   targetNote="Exact URL string present in the alert; no derivation from the domain."),
 ("TC-07", "ACT-ISOLATE-ENDPOINT"): dict(
   evidence="SUPPORTED", playbook="ALIGNED", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="VALID_EXTRA_ACTION",
   evidenceNote="Rule 100320 (L13): regular 2 s HTTP beaconing from 172.19.0.8 (agent attack-endpoint) to 172.19.0.7:8080 / vigix-eval-c2.net. Beaconing to C2 infrastructure is itself an indicator that the endpoint is compromised (catalog condition 'evidence supports compromise of the endpoint'). Caveat: the alert records beacon 1 of 3.",
   playbookNote="PB-C2 step 2 (unconditional): 'Isolate the endpoint that communicated with the C2 destination'; ACT-ISOLATE-ENDPOINT is in allowedActions.",
   policyNote="POL-A01 (HIGH impact) -> IR_TEAM approval; POL-A03 (affected endpoint + suspicious activity) satisfied per validator.",
   targetNote="'attack-endpoint' = Wazuh agent that emitted the alert; its IP 172.19.0.8 is the beacon source; targetKind host matches."),
 ("TC-09", "ACT-BLOCK-URL"): dict(
   evidence="SUPPORTED", playbook="ALIGNED", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="VALID_EXTRA_ACTION",
   evidenceNote="Rule 100340 (L13) alert data.url = http://vigix-eval-exfil.net:8080/upload (3,145,728 bytes of /tmp/test-data.txt uploaded, HTTP 200); the identical string is an ACTIVE URL IOC.",
   playbookNote="PB-DATA-EXFIL step 1 (unconditional) lists 'IP / domain / URL'; action in allowedActions.",
   policyNote="POL-A02 satisfied; RULE-P07 -> IR_TEAM approval. No threat-intel verdict exists for the destination (reputation empty); the justification rests on the alert event.",
   targetNote="Exact URL string present in the alert."),
 ("TC-09", "ACT-ISOLATE-ENDPOINT"): dict(
   evidence="PARTIALLY_SUPPORTED", playbook="ALIGNED", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="PARTIALLY_SUPPORTED",
   evidenceNote="The alert proves a 3 MB upload from the endpoint to an external host, but its own description says 'possible data exfiltration'; no process, hash, intel verdict or other indicator shows the endpoint itself is compromised. Same principle the GT applies to TC-05: activity alone does not establish compromise.",
   playbookNote="PB-DATA-EXFIL step 2 (unconditional): 'Isolate the endpoint the data left from'; in allowedActions.",
   policyNote="POL-A01 -> IR_TEAM approval; POL-A03 requirements satisfied per validator.",
   targetNote="'attack-endpoint' = emitting agent; srcip 172.19.0.8; targetKind host matches."),
 ("TC-10", "ACT-REVOKE-SESSION"): dict(
   evidence="INSUFFICIENT_EVIDENCE (session aspect); account itself implicated", playbook="CONDITIONALLY_ALIGNED (condition not satisfied)", policy="COMPLIANT_WITH_APPROVAL", targetValidity="CORRECT", overall="PARTIALLY_SUPPORTED",
   evidenceNote="Rule 100350 (L14): usermod added 'evaluser' to group sudo. The only evidence is a privilege-change log naming the account; there is no login, session or authentication event, so an active/suspicious session is not evidenced (a username alone is not enough for session revocation). The account is genuinely implicated (privilege change).",
   playbookNote="Action is in PB-ACCOUNT-COMPROMISE allowedActions, but step 4 applies it to 'the account recorded in the authentication evidence'; no authentication evidence exists in this case, so the condition is not satisfied.",
   policyNote="RULE-P07/critical severity -> IR_TEAM approval. The validator accepted the step because its AUTHENTICATION_EVIDENCE check passes when any evidence row names the account; the catalog's analyst-confirmed condition ('active or suspicious session') is not demonstrated.",
   targetNote="'evaluser' = account IOC from alert data.dstuser; targetKind account matches."),
}

rows = []
for cid, c in cases.items():
    cr = c.get("correctRecommendation") or {}
    am = c.get("actionMatch") or {}
    acts, tg = am.get("actualActions") or [], am.get("actualTargets") or []
    for u in cr.get("unexpectedRecommendations") or []:
        key = (cid, u["action"])
        assert key in J, f"unanalysed extra pair {key}"
        # actual target must come from the frozen artifact, never from this script
        actual = [t for a, t in zip(acts, tg) if a == u["action"]]
        assert u["target"] in actual, f"target mismatch for {key}"
        j = dict(J[key])
        rows.append(dict(case=cid, action=u["action"], target=u["target"], **j))
assert {(r["case"], r["action"]) for r in rows} == set(J), "analysed set differs from the requested set"
assert len(rows) == 6

n = len(rows)
cnt = lambda f, v: sum(1 for r in rows if r[f].startswith(v))
tot_req = sum(c["required"] for c in cov)
tot_cov = sum(c["covered"] for c in cov)
tot_ai = sum(c["aiPairs"] for c in cov)
tot_unexp = sum(c["unexpected"] for c in cov)
determinate = [r for r in rows if r["overall"] != "INDETERMINATE"]
valid = sum(1 for r in rows if r["overall"] == "VALID_EXTRA_ACTION")
summary = dict(
    primaryResultUnchanged="Correct Recommendation 4/10 = 40.00% (not recalculated)",
    extraPairs=n,
    evidenceSupported=cnt("evidence", "SUPPORTED"), evidencePartial=cnt("evidence", "PARTIALLY"), evidenceInsufficient=cnt("evidence", "INSUFFICIENT"),
    playbookAligned=sum(1 for r in rows if r["playbook"] == "ALIGNED"), playbookConditionalNotSatisfied=cnt("playbook", "CONDITIONALLY"),
    policyCompliantWithApproval=cnt("policy", "COMPLIANT_WITH_APPROVAL"), policyNonCompliant=cnt("policy", "NON_COMPLIANT"),
    targetCorrect=cnt("targetValidity", "CORRECT"),
    validExtra=valid, partiallySupported=sum(1 for r in rows if r["overall"] == "PARTIALLY_SUPPORTED"),
    unsupported=sum(1 for r in rows if r["overall"] == "UNSUPPORTED_EXTRA_ACTION"),
    policyInvalid=sum(1 for r in rows if r["overall"] == "POLICY_INVALID"), targetInvalid=sum(1 for r in rows if r["overall"] == "TARGET_INVALID"),
    indeterminate=sum(1 for r in rows if r["overall"] == "INDETERMINATE"),
    descriptive=dict(
        requiredActionCoverage=dict(num=tot_cov, den=tot_req, pct=round(100 * tot_cov / tot_req, 2)),
        unexpectedActionRate=dict(num=tot_unexp, den=tot_ai, pct=round(100 * tot_unexp / tot_ai, 2)),
        extraActionValidityRate=dict(num=valid, den=len(determinate), pct=round(100 * valid / len(determinate), 2),
                                     note="VALID_EXTRA_ACTION / extra pairs with determinate validity; the 2 PARTIALLY_SUPPORTED pairs are in the denominator and not counted as valid; 0 INDETERMINATE excluded"),
    ),
)
integrity = dict(runJsonSha256=sha(os.path.join(RUN, "run.json")),
                 caseFilesSha256={f"TC-{i:02d}": sha(os.path.join(RUN, "cases", f"TC-{i:02d}.json")) for i in range(1, 11)},
                 evidenceExtractSha256=sha(os.path.join(HERE, "evidence-extract.json")))
out = dict(analysis="post-hoc extra-action validity, Final Evaluation v3.3", frozenRun="final-evaluation-v3.3", gt="correctness-gt-v3.3",
           gtSha256="d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8", summary=summary, perCaseCoverage=cov, extraPairs=rows, integrity=integrity)
json.dump(out, open(os.path.join(HERE, "extra-action-validity.json"), "w", encoding="utf8"), indent=2, ensure_ascii=False)

with open(os.path.join(HERE, "extra-action-matrix.csv"), "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["case", "extra_action", "actual_target", "evidence_support", "playbook_alignment", "policy_compliance", "target_validity", "overall"])
    for r in rows:
        w.writerow([r["case"], r["action"], r["target"], r["evidence"], r["playbook"], r["policy"], r["targetValidity"], r["overall"]])
print(json.dumps(summary, indent=1))
for c in cov:
    print(c["case"], c["exactMatch"], f"{c['covered']}/{c['required']}", "ai", c["aiPairs"], "unexp", c["unexpected"], "miss", c["missing"])
