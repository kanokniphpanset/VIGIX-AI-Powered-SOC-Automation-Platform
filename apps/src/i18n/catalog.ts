// Every [Thai, English] message pair, merged into the dictionaries in ./messages.ts. One file per area keeps each
// screen's vocabulary together; a key must be unique across all of them (checked by locale.test.ts).
import { common } from './catalog/common.ts'
import { alerts } from './catalog/alerts.ts'
import { comms } from './catalog/comms.ts'
import { incident } from './catalog/incident.ts'
import { knowledge } from './catalog/knowledge.ts'
import { lists } from './catalog/lists.ts'
import { panels } from './catalog/panels.ts'
import { settings } from './catalog/settings.ts'
import { ticket } from './catalog/ticket.ts'
import { ui } from './catalog/ui.ts'
import { verify } from './catalog/verify.ts'

/** Each area's pairs, kept apart so the test can prove no key is defined twice. */
export const AREAS = { common, alerts, comms, incident, knowledge, lists, panels, settings, ticket, ui, verify } as const

export const PAIRS = { ...common, ...alerts, ...comms, ...incident, ...knowledge, ...lists, ...panels, ...settings, ...ticket, ...ui, ...verify } as const
