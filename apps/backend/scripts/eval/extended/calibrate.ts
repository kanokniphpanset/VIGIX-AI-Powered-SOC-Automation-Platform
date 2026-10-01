/**
 * calibrate.ts — CALIBRATION ONLY (not an evaluation run, never touches VIGIX or any DB): fires candidate benign events
 * in the isolated lab and prints which stock Wazuh rules/levels they produce, so the extended ground truth can name
 * real rule ids. Usage: ts-node calibrate.ts <A|B|C|D|E|F|...>
 */
import { docker, ENDPOINT, ATTACKER, ENDPOINT_AGENT } from "../simulations";
import { alertsSince } from "./indexer";

const sh = (c: string, s: string, t = 120000) => docker(["exec", c, "sh", "-c", s], undefined, t);
const ssh = (u: string, p: string, cmd = "exit") => `sshpass -p '${p}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o PreferredAuthentications=password -o PubkeyAuthentication=no ${u}@${ENDPOINT} ${cmd} >/dev/null 2>&1 || true`;
const web = (q: string, ua = "curl/8") => `curl -s -o /dev/null -A '${ua}' 'http://${ENDPOINT}${q}'`;

const CANDIDATES: Record<string, () => void> = {
  A: () => sh(ATTACKER, ssh("victim", "VictimPass123!", "id")),
  B: () => sh(ATTACKER, ssh("victim", "definitely-wrong")),
  C: () => sh(ATTACKER, web("/does-not-exist.html")),
  D: () => sh(ATTACKER, web("/app/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E")),
  E: () => sh(ATTACKER, web("/app/search.php?id=1%20union%20select%20username,password%20from%20users", "Mozilla/5.0 (compatible; Nessus)")),
  F: () => sh(ATTACKER, Array.from({ length: 25 }, (_, i) => `curl -s -o /dev/null --path-as-is 'http://${ENDPOINT}/%zz${i}'`).join("; ")),
  G: () => sh(ATTACKER, Array.from({ length: 25 }, (_, i) => web(`/missing-${i}.php`, "SiteCrawler/2.1")).join("; ")),
};

(async () => {
  const keys = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(CANDIDATES);
  for (const k of keys) {
    const since = new Date(Date.now() - 2000).toISOString();
    CANDIDATES[k]();
    await new Promise((r) => setTimeout(r, 45000));
    const a = await alertsSince(ENDPOINT_AGENT, since);
    const byRule = new Map<string, { n: number; level: number; desc: string; mitre: string }>();
    for (const x of a) { const r = x.src.rule; const e = byRule.get(r.id) ?? { n: 0, level: r.level, desc: r.description, mitre: (r.mitre?.id ?? []).join(",") }; e.n++; byRule.set(r.id, e); }
    console.log(`\n[${k}] ${CANDIDATES[k].toString().slice(6, 90)}`);
    for (const [id, v] of byRule) console.log(`   rule ${id} L${v.level} x${v.n}  ${v.desc}  ${v.mitre}`);
    if (!byRule.size) console.log("   (no alert)");
  }
})().catch((e) => { console.error(e); process.exit(1); });
