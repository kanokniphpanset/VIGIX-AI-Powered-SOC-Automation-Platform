import { z } from "zod";
import { Result } from "../../../shared/result/Result";
import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { IrEmailOutcome, IrEmailService, IrRecipientPreview, safeSubject } from "../../notification/services/IrEmailService";

export type ArticleType = "PLAYBOOK" | "RUNBOOK";

export interface KnowledgeArticle {
  id: string;
  type: ArticleType;
  /** Playbook / runbook code, e.g. PB-SSH-BRUTEFORCE or RB-BLOCK-IP. */
  code: string | null;
  title: string;
  version: string | null;
  status: string | null;
  sections: { heading: string; lines: string[] }[];
}

export interface EmailPreview {
  subject: string;
  body: string;
}

const list = (items: (string | null | undefined)[]) => items.filter((x): x is string => !!x && !!x.trim());

/** A knowledge article is a playbook or runbook from the backend's own libraries (never caller-supplied content). */
export class GetKnowledgeArticleUseCase {
  constructor(private readonly playbooks: IPlaybookRepository, private readonly runbooks: IRunbookRepository) {}

  async execute(input: { tenantId: string; articleId: string }): Promise<Result<KnowledgeArticle, "ARTICLE_NOT_FOUND">> {
    if (!z.string().uuid().safeParse(input.articleId).success) return Result.fail("ARTICLE_NOT_FOUND");
    const playbook = await this.playbooks.findById(input.articleId, input.tenantId);
    if (playbook) {
      const p = playbook.toJSON();
      return Result.ok({
        id: p.id, type: "PLAYBOOK", code: p.code, title: p.name, version: p.version, status: p.status,
        sections: [
          { heading: "Description", lines: list([p.description]) },
          { heading: "Steps", lines: [...p.steps].sort((a, b) => a.stepOrder - b.stepOrder).map((s) => `${s.stepOrder}. ${s.title}${s.description ? ` — ${s.description}` : ""}`) },
        ].filter((s) => s.lines.length),
      });
    }
    const runbook = await this.runbooks.findById(input.articleId, input.tenantId);
    if (!runbook) return Result.fail("ARTICLE_NOT_FOUND");
    const r = runbook.toJSON();
    return Result.ok({
      id: r.id, type: "RUNBOOK", code: r.code, title: r.name, version: r.version, status: r.status,
      sections: [
        { heading: "Description", lines: list([r.description]) },
        { heading: "Trigger", lines: list([r.trigger]) },
        { heading: "Objective", lines: list([r.objective]) },
        { heading: "Preconditions", lines: list(r.preconditions) },
        { heading: "Procedure", lines: r.procedure.map((line, i) => `${i + 1}. ${line}`) },
        { heading: "Decision points", lines: list(r.decisionPoints) },
        { heading: "Expected result", lines: list([r.expectedResult]) },
        { heading: "Verification", lines: list(r.verificationCriteria) },
        { heading: "Escalation", lines: list([r.escalation]) },
      ].filter((s) => s.lines.length),
    });
  }
}

export function renderArticleEmail(article: KnowledgeArticle, baseUrl: string): EmailPreview {
  const kind = article.type === "PLAYBOOK" ? "Playbook" : "Runbook";
  return {
    subject: safeSubject(`[VIGIX] ${kind}${article.code ? ` ${article.code}` : ""} — ${article.title}`),
    body: [
      "VIGIX Knowledge Base — article shared with the IR Team",
      "",
      `Title: ${article.title}`,
      `Type: ${kind}`,
      `${kind} ID: ${article.code ?? "(no code)"}${article.version ? ` · version ${article.version}` : ""}`,
      "",
      ...article.sections.flatMap((s) => [`${s.heading}:`, ...s.lines.map((l) => `  ${l}`), ""]),
      "—",
      `Source: VIGIX Knowledge Base (${kind.toLowerCase()} ${article.id})`,
      `Open in VIGIX: ${baseUrl}/knowledge?section=${article.type === "PLAYBOOK" ? "playbooks" : "runbooks"}`,
    ].join("\n"),
  };
}

export class PreviewArticleEmailUseCase {
  constructor(private readonly getArticle: GetKnowledgeArticleUseCase, private readonly irEmail: IrEmailService, private readonly baseUrl: string) {}

  async execute(input: { tenantId: string; articleId: string }): Promise<Result<{ article: KnowledgeArticle; email: EmailPreview; recipient: IrRecipientPreview }, "ARTICLE_NOT_FOUND">> {
    const article = await this.getArticle.execute(input);
    if (article.isFailure) return Result.fail(article.error);
    return Result.ok({ article: article.value, email: renderArticleEmail(article.value, this.baseUrl), recipient: await this.irEmail.previewRecipient(input.tenantId) });
  }
}

/** SendToIR for a knowledge article: content comes from the article, the recipient from the server. */
export class SendArticleToIrUseCase {
  constructor(private readonly getArticle: GetKnowledgeArticleUseCase, private readonly irEmail: IrEmailService, private readonly baseUrl: string) {}

  async execute(input: { tenantId: string; articleId: string; actor: string; subject?: string | null; idempotencyKey?: string | null }): Promise<Result<IrEmailOutcome, "ARTICLE_NOT_FOUND">> {
    const found = await this.getArticle.execute(input);
    if (found.isFailure) return Result.fail(found.error);
    const article = found.value;
    const email = renderArticleEmail(article, this.baseUrl);
    return Result.ok(
      await this.irEmail.send({
        tenantId: input.tenantId,
        actor: input.actor,
        action: "ARTICLE_SENT_TO_IR",
        entity: "KnowledgeArticle",
        entityId: article.id,
        incidentId: null,
        subject: input.subject?.trim() ? input.subject : email.subject,
        body: email.body,
        idempotencyKey: input.idempotencyKey ?? null,
        metadata: { articleId: article.id, articleType: article.type, articleCode: article.code },
      })
    );
  }
}
