/** Navigation hint only: JWT signature/authentication is always enforced by the backend. */
export function isExpiredToken(token: string, now = Date.now()): boolean {
  try {
    const part = token.split('.')[1]
    if (!part) return true
    const claim = JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')))
    return typeof claim.exp !== 'number' || claim.exp * 1000 <= now
  } catch { return true }
}
export function safeNext(value: unknown): string {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') && !value.startsWith('/login') ? value : '/dashboard'
}
