// Tests for ../vibecheck-rules.yaml. Run from the repo root:
//   semgrep --test --config rules/vibecheck-rules.yaml rules/tests/vibecheck-rules.tsx
// A "ruleid:" comment means the rule must match the next line; "ok:" means it must not.
import express from 'express'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import cp from 'child_process'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import {NextResponse} from 'next/server'
import {redirect} from 'next/navigation'

declare const OpenAI: any, Anthropic: any, prisma: any, supabase: any, db: any, pool: any
declare const DOMPurify: any, exec: any, q: string, html: string, userId: string

const app = express()

// ---- vc-ai-key-in-browser ----
// ruleid: vc-ai-key-in-browser
export const browserAi = new OpenAI({apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true})
// ok: vc-ai-key-in-browser
export const serverAi = new Anthropic({apiKey: process.env.ANTHROPIC_API_KEY})

// ---- vc-secret-fallback ----
// ruleid: vc-secret-fallback
export const signingKey = process.env.JWT_SECRET || 'my-dev-signing-key'
// ruleid: vc-secret-fallback
export const sessionKey = process.env.SESSION_SECRET ?? 'another-long-value'
// ok: vc-secret-fallback
export const port = process.env.PORT || '3000-local'
// ok: vc-secret-fallback
export const strict = process.env.JWT_SECRET
// ruleid: vc-secret-fallback
export const signed = jwt.sign({sub: userId}, 'literal-signing-key')

// ---- vc-secret-in-url ----
// ruleid: vc-secret-in-url
export const exportLink = (t: string) => `https://app.example/export?token=${t}`
// ok: vc-secret-in-url
export const pageLink = (p: number) => `https://app.example/list?page=${p}`

// ---- vc-sql-from-strings ----
export async function sqlCases(id: string) {
  // ruleid: vc-sql-from-strings
  await db.query(`SELECT * FROM users WHERE id = '${id}'`)
  // ruleid: vc-sql-from-strings
  await pool.query("SELECT * FROM users WHERE id = " + id)
  // ruleid: vc-sql-from-strings
  await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${q}'`)
  // ok: vc-sql-from-strings
  await db.query('SELECT * FROM users WHERE id = $1', [id])
  // ok: vc-sql-from-strings
  await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${q}`
  // ok: vc-sql-from-strings
  await prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE email = $1', q)
}

// ---- vc-supabase-filter-injection ----
// ruleid: vc-supabase-filter-injection
export const search = () => supabase.from('notes').select('*').or(`title.ilike.%${q}%,body.ilike.%${q}%`)
// ok: vc-supabase-filter-injection
export const search2 = () => supabase.from('notes').select('*').ilike('title', `%${q}%`)

// ---- vc-shell-command-from-input ----
export function shellCases(file: string) {
  // ruleid: vc-shell-command-from-input
  cp.exec(`convert ${file} out.png`)
  // ruleid: vc-shell-command-from-input
  exec("ls " + file)
  // ok: vc-shell-command-from-input
  cp.execFile('convert', [file, 'out.png'])
}

// ---- vc-dynamic-code ----
export function codeCases(expr: string) {
  // ruleid: vc-dynamic-code
  eval(expr)
  // ruleid: vc-dynamic-code
  const fn = new Function('a', expr)
  // ok: vc-dynamic-code
  eval('1 + 1')
  return fn
}

// ---- vc-path-from-request ----
app.get('/files', (req, res) => {
  // ruleid: vc-path-from-request
  const data = fs.readFileSync(path.join('/srv/uploads', req.query.name as string))
  // ok: vc-path-from-request
  const safe = fs.readFileSync(path.join('/srv/uploads', path.basename(req.query.name as string)))
  res.send(data + safe)
})

export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get('url')
  // ruleid: vc-server-fetches-user-url
  const page = await fetch(url!)
  // ok: vc-server-fetches-user-url
  const fixed = await fetch('https://api.example.com/status')
  const next = new URL(req.url).searchParams.get('next')
  // ruleid: vc-open-redirect
  return NextResponse.redirect(next!) ?? page ?? fixed
}

// ---- vc-open-redirect ----
app.get('/login/done', (req, res) => {
  // ruleid: vc-open-redirect
  res.redirect(req.query.next as string)
})
app.get('/home', (req, res) => {
  // ok: vc-open-redirect
  res.redirect('/dashboard')
})

// ---- vc-mass-assignment ----
export async function PATCH(req: Request) {
  const body = await req.json()
  // ruleid: vc-mass-assignment
  await prisma.user.update({where: {id: userId}, data: body})
  // ok: vc-mass-assignment
  await prisma.user.update({where: {id: userId}, data: {name: body.name, bio: body.bio}})
}
app.post('/profile', async (req, res) => {
  // ruleid: vc-mass-assignment
  await supabase.from('profiles').update(req.body)
  res.end()
})

// ---- vc-jwt-not-verified ----
app.get('/me', (req, res) => {
  // ruleid: vc-jwt-not-verified
  const claims: any = jwt.decode(req.headers.authorization as string)
  // ok: vc-jwt-not-verified
  const verified: any = jwt.verify(req.headers.authorization as string, process.env.JWT_SECRET!, {algorithms: ['HS256']})
  res.json({claims, verified})
})

// ---- vc-tls-check-off ----
// ruleid: vc-tls-check-off
export const dbConfig = {connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: false}}
// ok: vc-tls-check-off
export const dbConfig2 = {connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: true}}
// ruleid: vc-tls-check-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

// ---- vc-token-in-localstorage ----
export function storeSession(session: any) {
  // ruleid: vc-token-in-localstorage
  localStorage.setItem('access_token', session.access_token)
  // ok: vc-token-in-localstorage
  localStorage.setItem('theme', 'dark')
}

// ---- vc-unsanitized-html ----
// ruleid: vc-unsanitized-html
export const Bio = () => <div dangerouslySetInnerHTML={{__html: html}} />
// ok: vc-unsanitized-html
export const SafeBio = () => <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />
// ok: vc-unsanitized-html
export const Welcome = () => <div dangerouslySetInnerHTML={{__html: '<b>Welcome</b>'}} />

// ---- vc-predictable-token ----
// ruleid: vc-predictable-token
export const resetToken = Math.random().toString(36).slice(2)
// ok: vc-predictable-token
export const jitter = Math.random() * 100
// ok: vc-predictable-token
export const inviteToken = crypto.randomBytes(32).toString('hex')

// ---- vc-fast-hash-for-password ----
export function hashes(password: string, file: string) {
  // ruleid: vc-fast-hash-for-password
  const stored = crypto.createHash('sha256').update(password).digest('hex')
  // ok: vc-fast-hash-for-password
  const checksum = crypto.createHash('sha256').update(file).digest('hex')
  return stored + checksum
}

// ---- vc-cors-any-origin-with-cookies ----
// ruleid: vc-cors-any-origin-with-cookies
app.use(cors({origin: true, credentials: true}))
// ok: vc-cors-any-origin-with-cookies
app.use(cors({origin: ['https://app.example'], credentials: true}))

export const unused = redirect
