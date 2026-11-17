const ALLOWED_PATHS = new Set(['/', '/login', '/dashboard', '/pricing', '/account'])

export function safeRedirect(target: string | null | undefined, fallback = '/'): string {
  if (!target) return fallback
  return ALLOWED_PATHS.has(target) ? target : fallback
}
