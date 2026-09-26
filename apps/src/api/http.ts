// Real backend HTTP client (apps/backend via the Vite /api proxy).
// The JWT from POST /api/auth/login is kept in localStorage so a page reload stays signed in; every read/write of
// storage is guarded because it can be unavailable (private windows, blocked site data).

const TOKEN_KEY = 'vigix.session'

export interface StoredSession {
  token: string
  role: string
  email: string
}

export function loadSession(): StoredSession | null {
  try {
    const raw = localStorage.getItem(TOKEN_KEY)
    return raw ? (JSON.parse(raw) as StoredSession) : null
  } catch {
    return null
  }
}

export function saveSession(session: StoredSession | null): void {
  try {
    if (session) localStorage.setItem(TOKEN_KEY, JSON.stringify(session))
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable — the session simply lasts for this page load */
  }
}

let memorySession: StoredSession | null = loadSession()
let onUnauthorized: (() => void) | null = null

export function setSession(session: StoredSession | null): void {
  memorySession = session
  saveSession(session)
}
export function currentSession(): StoredSession | null {
  return memorySession
}
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly body: unknown
  constructor(
    status: number,
    code: string,
    body: unknown,
  ) {
    super(code)
    this.status = status; this.code = code; this.body = body
  }
}

export async function api<T>(path: string, init: { method?: string; body?: unknown; query?: Record<string, string | number | undefined> } = {}): Promise<T> {
  const qs = init.query
    ? '?' +
      Object.entries(init.query)
        .filter(([, v]) => v !== undefined && v !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join('&')
    : ''
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  if (memorySession) headers.Authorization = `Bearer ${memorySession.token}`

  const res = await fetch(`${path}${qs === '?' ? '' : qs}`, {
    method: init.method ?? 'GET',
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    body = text
  }
  if (res.status === 401) { setSession(null); onUnauthorized?.() }
  if (!res.ok) {
    const code = (body && typeof body === 'object' && 'error' in body && typeof (body as { error: unknown }).error === 'string') ? (body as { error: string }).error : `HTTP_${res.status}`
    throw new ApiError(res.status, code, body)
  }
  return body as T
}
