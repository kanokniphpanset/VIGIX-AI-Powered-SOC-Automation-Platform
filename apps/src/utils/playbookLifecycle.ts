// Playbook versions on the Knowledge page (Phase 1D). Pure; runs under `node --test`. Mirrors the backend rules:
// SOC / IR_TEAM (and admin) create and edit drafts; only SOC / IR_TEAM publish and roll back — no review or approval step.
// Internal states (SUPERSEDED, the published pointer, revision ids) are turned into plain Draft / Published wording.

export interface PlaybookRevisionItem {
  id: string
  revisionNumber: number
  version: string
  status: 'DRAFT' | 'IN_REVIEW' | 'APPROVED' | 'PUBLISHED' | 'SUPERSEDED' | 'REJECTED'
  content: Record<string, unknown>
  createdBy: string
  createdAt: string
  publishedAt: string | null
}

export type PlaybookAction = 'view' | 'edit' | 'publish' | 'createVersion' | 'rollback' | 'delete'

export interface PlaybookLifecycle {
  /** Published = live for future recommendations; Draft = never published yet. */
  state: 'DRAFT' | 'PUBLISHED'
  /** Live version (Published) or the draft's version (Draft). */
  version: string
  /** The open draft: the playbook itself (Draft) or a new version of a published playbook. */
  draft: PlaybookRevisionItem | null
  /** The version a rollback goes back to: the most recently published earlier version. */
  rollbackTo: PlaybookRevisionItem | null
  actions: PlaybookAction[]
}

export const PLAYBOOK_EDITOR_ROLES = ['SOC', 'IR_TEAM', 'admin']
export const PLAYBOOK_PUBLISHER_ROLES = ['SOC', 'IR_TEAM']

/** Status and buttons for one playbook row, from its revision list and the viewer's role. */
export function playbookLifecycle(revisions: PlaybookRevisionItem[], role: string | null, fallbackVersion = ''): PlaybookLifecycle {
  const canEdit = PLAYBOOK_EDITOR_ROLES.includes(role ?? '')
  const canPublish = PLAYBOOK_PUBLISHER_ROLES.includes(role ?? '')
  const live = revisions.find((r) => r.status === 'PUBLISHED') ?? null
  const draft = [...revisions].reverse().find((r) => r.status === 'DRAFT') ?? null
  const rollbackTo = live
    ? [...revisions].filter((r) => r.status === 'SUPERSEDED' && r.publishedAt).sort((a, b) => (b.publishedAt ?? '').localeCompare(a.publishedAt ?? ''))[0] ?? null
    : null

  const actions: PlaybookAction[] = ['view']
  if (!live) {
    if (draft && canEdit) actions.push('edit')
    if (draft && canPublish) actions.push('publish')
    if (canEdit) actions.push('delete')
  } else {
    if (draft) {
      if (canEdit) actions.push('edit')
      if (canPublish) actions.push('publish')
    } else if (canEdit) actions.push('createVersion')
    if (rollbackTo && canPublish) actions.push('rollback')
  }
  return { state: live ? 'PUBLISHED' : 'DRAFT', version: live?.version ?? draft?.version ?? fallbackVersion, draft, rollbackTo, actions }
}

/** A draft revision's content in the shape the playbook form reads (status = the status it takes once published). */
export function draftSource(revision: PlaybookRevisionItem): Record<string, unknown> {
  return { ...revision.content, status: revision.content.playbookStatus }
}
