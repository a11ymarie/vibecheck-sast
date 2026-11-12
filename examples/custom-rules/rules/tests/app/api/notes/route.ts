// Test cases for ../../../../require-auth.yaml
import {requireUser} from '@/lib/auth'

declare const db: any

// ruleid: myapp-route-without-auth
export async function GET(req: Request) {
  return Response.json(await db.notes.findMany())
}

// ok: myapp-route-without-auth
export async function POST(req: Request) {
  const user = await requireUser(req)
  return Response.json(await db.notes.create({data: {owner: user.id}}))
}

// ok: myapp-route-without-auth
export async function DELETE(req: Request) {
  if (!(await requireUser(req))) return new Response(null, {status: 401})
  return new Response(null, {status: 204})
}
