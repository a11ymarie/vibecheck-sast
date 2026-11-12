'use client'
// Demo app: deliberately insecure. Do not deploy.
export function rememberSession(session: {access_token: string; refresh_token: string}) {
  localStorage.setItem('refresh_token', session.refresh_token)
}
