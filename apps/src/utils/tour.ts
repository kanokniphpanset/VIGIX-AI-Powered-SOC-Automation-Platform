// First-use tour (pure; runs under `node --test`): which steps each role sees and which element each step points at.
// Targets are `data-tour` attributes on the shell and the dashboard; a step whose target is not on screen is shown
// as a centred card instead. "Seen" is remembered per user in this browser (a convenience — never required).

export interface TourStep {
  /** Text keys: tour.<key>.title / tour.<key>.body */
  key: string
  /** CSS selector of the element to highlight, or null for a centred card. */
  target: string | null
}

const at = (name: string) => `[data-tour="${name}"]`

export function tourSteps(role: string | null): TourStep[] {
  const end: TourStep[] = [
    { key: 'help', target: at('help') },
    { key: 'lang', target: at('lang') },
  ]
  if (role === 'IR_TEAM')
    return [
      { key: 'welcome-ir', target: null },
      { key: 'mywork', target: at('my-work') },
      { key: 'nav-tickets', target: at('nav-tickets') },
      { key: 'nav-incidents', target: at('nav-incidents') },
      { key: 'ir-rules', target: null },
      ...end,
    ]
  if (role === 'SOC')
    return [
      { key: 'welcome-soc', target: null },
      { key: 'mywork', target: at('my-work') },
      { key: 'nav-alerts', target: at('nav-alerts') },
      { key: 'nav-incidents', target: at('nav-incidents') },
      ...end,
    ]
  return [{ key: 'welcome-admin', target: null }, { key: 'mywork', target: at('my-work') }, ...end]
}

/** Bump the version to show a changed tour to everyone once more. */
export const tourSeenKey = (email: string | null | undefined) => `vigix.tour.v1.${(email ?? 'anonymous').toLowerCase()}`

/** Where to put the card next to a highlighted element (viewport px): right of it if it fits, else below, else centred. */
export function cardPosition(
  rect: { top: number; left: number; right: number; bottom: number } | null,
  viewport: { width: number; height: number },
  card: { width: number; height: number },
  gap = 16,
): { top: number; left: number } | null {
  if (!rect) return null
  const clampTop = (t: number) => Math.max(gap, Math.min(t, viewport.height - card.height - gap))
  const clampLeft = (l: number) => Math.max(gap, Math.min(l, viewport.width - card.width - gap))
  if (rect.right + gap + card.width + gap <= viewport.width) return { top: clampTop(rect.top), left: rect.right + gap }
  if (rect.bottom + gap + card.height + gap <= viewport.height) return { top: rect.bottom + gap, left: clampLeft(rect.left) }
  if (rect.top - gap - card.height >= gap) return { top: rect.top - gap - card.height, left: clampLeft(rect.left) }
  return null
}
