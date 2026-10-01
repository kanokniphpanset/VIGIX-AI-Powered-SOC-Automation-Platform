#!/usr/bin/env python3
"""ADDENDUM to the final evaluation (read-only): does every IP-blocking step point at the RIGHT IP ROLE of the alert?
ACT-BLOCK-SOURCE-IP must target the alert's data.srcip, ACT-BLOCK-DESTINATION-IP its data.dstip. The six-criterion
Recommendation Compliance does not check this (evidenceSupport only requires the target to be ANY evidence-linked IOC/host).
Reads soar_final_eval (SELECT only) and results/final-evaluation/final-consistency.json; writes
results/final-evaluation/addendum-target-role-check.json.  Run: PYTHONUTF8=1 python apps/backend/scripts/eval/final/target-role-check.py"""
import json, os, subprocess, datetime
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
os.chdir(ROOT)
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
SQL = """select a.raw_payload->'rule'->>'id', coalesce(a.raw_payload->'data'->>'srcip',''), coalesce(a.raw_payload->'data'->>'dstip',''), ac.code, rs.target, r.recommendation_number, r.status
from recommendation_steps rs join recommendations r on r.id=rs.recommendation_id join incident_alerts ia on ia.incident_id=r.incident_id
join alerts a on a.id=ia.alert_id join actions ac on ac.id=rs.action_id where ac.code in ('ACT-BLOCK-SOURCE-IP','ACT-BLOCK-DESTINATION-IP') and r.status='VALIDATED' order by a.received_at, rs.step_order"""
out = subprocess.run(["docker", "exec", "-i", "soar-postgres", "sh", "-c", 'psql -U "$POSTGRES_USER" -d soar_final_eval -At -F "|"'], input=SQL, capture_output=True, text=True, env=ENV).stdout
rows = [l.split("|") for l in out.splitlines() if l.count("|") >= 6]
RULE = {"5712": "TC-01", "40112": "TC-04", "31103": "TC-06", "100320": "TC-07", "100340": "TC-09"}
steps = []
for rule, src, dst, code, target, num, st in rows:
    want = src if code == "ACT-BLOCK-SOURCE-IP" else dst
    steps.append({"case": RULE.get(rule, rule), "rule": rule, "action": code, "target": target, "alertSrcip": src, "alertDstip": dst, "expectedRoleTarget": want, "correctRole": target == want and want != "", "pointsAtSourceWhenDestinationExpected": code == "ACT-BLOCK-DESTINATION-IP" and target == src})
cons = json.load(open("results/final-evaluation/final-consistency.json", encoding="utf-8"))
rep = []
for r in cons["records"]:
    for s in r["all_steps"]:
        a, t = s.split(">", 1)
        if a in ("ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP"):
            # alert IPs per case taken from the main-run rows above
            ref = next((x for x in steps if x["case"] == r["case_id"]), None)
            if ref:
                want = ref["alertSrcip"] if a == "ACT-BLOCK-SOURCE-IP" else ref["alertDstip"]
                rep.append({"case": r["case_id"], "repetition": r["repetition"], "action": a, "target": t, "correctRole": t == want})
def tally(xs): return {"correct": sum(1 for x in xs if x["correctRole"]), "of": len(xs)}
res = {
    "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "database": "soar_final_eval (SELECT only)",
    "rule": "ACT-BLOCK-SOURCE-IP target must equal the alert's data.srcip; ACT-BLOCK-DESTINATION-IP target must equal its data.dstip",
    "mainRunIpSteps": steps, "mainRun": tally(steps),
    "mainRunDestinationIpSteps": tally([x for x in steps if x["action"] == "ACT-BLOCK-DESTINATION-IP"]),
    "mainRunSourceIpSteps": tally([x for x in steps if x["action"] == "ACT-BLOCK-SOURCE-IP"]),
    "consistencyRepetitionsIpSteps": tally(rep), "consistencyDestinationIpSteps": tally([x for x in rep if x["action"] == "ACT-BLOCK-DESTINATION-IP"]),
    "interpretation": "In TC-07 and TC-09 the endpoint (172.19.0.5) is the SOURCE of the C2/exfiltration traffic and the lab server (172.19.0.7) the destination; BLOCK-DESTINATION-IP was aimed at the endpoint's own address. Executed, it would cut the monitored host off the network. The IR approval gate is the only thing that stops it; the compliance evaluator (evidence-linked target) does not detect it.",
    "reportedInFinalReport": False, "note": "Found after the final report was issued; the final KPI values are unchanged, their meaning is qualified (see CORRECTIONS-final.md).",
}
json.dump(res, open("results/final-evaluation/addendum-target-role-check.json", "w", encoding="utf-8"), indent=1)
print(json.dumps({k: res[k] for k in ("mainRun", "mainRunDestinationIpSteps", "mainRunSourceIpSteps", "consistencyRepetitionsIpSteps", "consistencyDestinationIpSteps")}))
for s in steps: print(s["case"], s["action"], s["target"], "src", s["alertSrcip"], "dst", s["alertDstip"], "OK" if s["correctRole"] else "WRONG ROLE")
