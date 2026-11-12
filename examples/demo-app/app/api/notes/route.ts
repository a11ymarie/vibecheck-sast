// Demo app: deliberately insecure. Do not deploy.
import {PrismaClient} from '@prisma/client'
import {currentUserId} from '@/lib/auth'

const prisma = new PrismaClient()

export async function GET(req: Request) {
  const tag = new URL(req.url).searchParams.get('tag')
  const notes = await prisma.$queryRawUnsafe(`SELECT * FROM "Note" WHERE tag = '${tag}'`)
  return Response.json(notes)
}

export async function PATCH(req: Request) {
  const changes = await req.json()
  const note = await prisma.note.update({where: {id: changes.id}, data: changes})
  return Response.json({note, by: currentUserId(req)})
}
