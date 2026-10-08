/**
 * containment-procedure-samples.ts - generates attack-specific containment recommendations for the TC scenarios with
 * the REAL LLM and runs them through the REAL pipeline (context builder + YAML procedure, prompt builder, validator with
 * its single correction retry, persistence shape) and the 7-criterion containment rubric. No database is touched: the
 * scenarios and repositories are the in-memory fixtures of test/helpers/containmentScenarios.ts.
 *
 * The model, endpoint and key are the ai-orchestrator's own (apps/ai-orchestrator/.env LLM_BASE_URL / LLM_MODEL /
 * LLM_API_KEY) and the system prompt is resources/prompts/recommendation-agent/generate-system.md, so the call matches
 * POST /recommendations/generate except for RAG retrieval (not used here; disclosed in the output).
 *
 * Usage: npx ts-node --transpile-only scripts/eval/containment-procedure-samples.ts [TC-01 TC-06 ...|--all] [--out file.json]
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { IRecommendationAgentPort } from "../../src/application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationContextDto } from "../../src/application/recommendation/dto/RecommendationContextDto";
import { RecommendationPromptBuilder } from "../../src/infrastructure/ai/RecommendationPromptBuilder";
import { evaluateContainmentRubric } from "../../src/evaluation/containmentRubric";
import { SCENARIOS, buildContext, generate } from "../../test/helpers/containmentScenarios";

const REPO = path.resolve(__dirname, "../../../..");

function orchestratorEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const line of fs.readFileSync(path.join(REPO, "apps/ai-orchestrator/.env"), "utf8").split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)\s*=\s*"?([^"]*)"?\s*$/.exec(line);
    if (m) env[m[1]] = m[2];
  }
  return env;
}

function systemPrompt(): string {
  const text = fs.readFileSync(path.join(REPO, "resources/prompts/recommendation-agent/generate-system.md"), "utf8");
  return text.replace(/^---[\s\S]*?---\s*/, "");
}

/** Same request as ai-orchestrator LlamaProvider.complete (temperature 0.2), minus RAG; reply parsed like parse_candidate. */
class DirectLlmAgent implements IRecommendationAgentPort {
  readonly calls: { correction: boolean; ms: number }[] = [];
  constructor(private readonly env: Record<string, string>, private readonly system: string) {}

  async generate(context: RecommendationContextDto, correction?: string): Promise<unknown> {
    const base = new RecommendationPromptBuilder().build(context);
    const user = correction ? `${base}

${correction}` : base;
    // Like the orchestrator route: one re-ask when the reply is not a parseable JSON object (never repaired).
    let lastError = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      const prompt = attempt === 0 ? user : `${user}

Your previous reply was rejected: ${lastError}. Reply with the ONE JSON object only.`;
      const text = await this.complete(prompt, !!correction);
      try {
        return stripNulls(parseFirstObject(text));
      } catch (e) {
        lastError = e instanceof Error ? e.message : String(e);
      }
    }
    throw new Error(`INVALID_LLM_OUTPUT: ${lastError}`);
  }

  private async complete(user: string, correction: boolean): Promise<string> {
    const started = Date.now();
    const res = await fetch(`${this.env.LLM_BASE_URL.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(this.env.LLM_API_KEY ? { Authorization: `Bearer ${this.env.LLM_API_KEY}` } : {}) },
      body: JSON.stringify({ model: this.env.LLM_MODEL, temperature: 0.2, messages: [{ role: "system", content: this.system }, { role: "user", content: user }] }),
      signal: AbortSignal.timeout(Number(this.env.LLM_TIMEOUT_SECONDS ?? 240) * 1000),
    });
    this.calls.push({ correction, ms: Date.now() - started });
    if (!res.ok) throw new Error(`LLM responded ${res.status}`);
    const body = (await res.json()) as { choices: { message: { content: string } }[] };
    return body.choices[0].message.content;
  }
}

/** The orchestrator returns model_dump(exclude_none=True): null-valued fields never reach the backend. Same here. */
function stripNulls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripNulls);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== null).map(([k, v]) => [k, stripNulls(v)]));
  }
  return value;
}

function parseFirstObject(reply: string): unknown {
  const text = reply.replace(/^```(?:json)?\s*|\s*```$/gi, "").trim();
  const start = text.indexOf("{");
  if (start < 0) throw new Error("LLM reply contains no JSON object");
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return JSON.parse(text.slice(start, i + 1));
  }
  throw new Error("LLM reply contains no complete JSON object");
}

async function main() {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf("--out");
  const out = outIdx >= 0 ? args[outIdx + 1] : null;
  const ids = args.includes("--all") ? SCENARIOS.map((s) => s.caseId) : args.filter((a, i) => a.startsWith("TC-") && i !== outIdx + 1);
  const cases = SCENARIOS.filter((s) => (ids.length ? ids : ["TC-01", "TC-06", "TC-09"]).includes(s.caseId));
  const env = orchestratorEnv();
  const system = systemPrompt();
  const report: unknown[] = [];

  for (const s of cases) {
    const agent = new DirectLlmAgent(env, system);
    const ctx = await buildContext(s);
    const { result, created, audit } = await generate(s, agent);
    const rec = created[0];
    const failure = audit.find((a) => a.action === "RECOMMENDATION_GENERATION_FAILED");
    const rubric = rec
      ? evaluateContainmentRubric({
          caseId: s.caseId, expectedAttackType: s.attackType, expectedPlaybook: s.playbook, status: "VALIDATED", playbook: ctx.playbook?.code ?? null,
          procedure: ctx.containmentProcedure ?? null, policyApproval: Object.fromEntries((ctx.actionProcedures ?? []).map((p) => [p.actionCode, p.policy.approvalRequired])),
          steps: rec.steps.map((st) => ({ stepType: st.stepType ?? "ACTION", action: st.actionId?.replace("action-", "") ?? null, target: st.target, title: st.title, precondition: st.precondition, evidence: st.evidence, requiresApproval: st.requiresApproval, verificationCriteria: st.verificationCriteria })),
          groundTruth: null,
        })
      : null;

    console.log(`\n=== ${s.caseId} ${s.attackType} — ${result.isSuccess ? "VALIDATED" : `FAILED (${result.error})`} — LLM calls: ${agent.calls.map((c) => `${c.correction ? "retry " : ""}${Math.round(c.ms / 1000)}s`).join(", ")}`);
    if (rec) {
      console.log(`Summary: ${rec.summary}`);
      rec.steps.forEach((st) => {
        console.log(`  ${st.stepOrder}. [${st.stepType}] ${st.title}${st.requiresApproval ? "  (approval required)" : ""}`);
        if (st.precondition) console.log(`       condition: ${st.precondition}`);
        st.instructions.forEach((i) => console.log(`       - ${i.instruction}`));
        console.log(`       verify: ${st.verificationCriteria}`);
      });
      console.log(`Rubric: ${rubric!.passed}/${rubric!.evaluable} evaluable — ${rubric!.criteria.map((c) => `${c.criterion}=${c.result}`).join(", ")}`);
    } else {
      console.log(`Violations: ${JSON.stringify((failure?.metadata as Record<string, unknown> | undefined)?.violations ?? failure?.metadata, null, 1)}`);
    }
    report.push({ caseId: s.caseId, attackType: s.attackType, status: result.isSuccess ? "VALIDATED" : result.error, llmCalls: agent.calls, recommendation: rec ?? null, rubric, failure: failure?.metadata ?? null });
  }
  if (out) {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify({ generatedAt: new Date().toISOString(), model: env.LLM_MODEL, rag: "not used (direct LLM call)", cases: report }, null, 2));
    console.log(`\nwritten: ${out}`);
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
