// Demo app: deliberately insecure. Do not deploy.
import jwt from 'jsonwebtoken'

const TOKEN_SECRET = process.env.TOKEN_SECRET || 'demo-app-token-secret'

export const signIn = (userId: string) => jwt.sign({sub: userId}, TOKEN_SECRET, {expiresIn: '90d'})

export function currentUserId(req: Request) {
  const claims = jwt.decode(req.headers.get('authorization') ?? '') as {sub?: string} | null
  return claims?.sub
}
