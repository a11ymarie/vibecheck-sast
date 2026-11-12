// Demo app: deliberately insecure. Do not deploy.
import crypto from 'crypto'

export function newPasswordResetLink(email: string) {
  const resetCode = Math.random().toString(36).slice(2, 10)
  return {email, url: `/reset?code=${resetCode}`}
}

export const hashPassword = (password: string) =>
  crypto.createHash('sha256').update(password).digest('hex')
