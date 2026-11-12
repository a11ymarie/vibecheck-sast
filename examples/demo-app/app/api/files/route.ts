// Demo app: deliberately insecure. Do not deploy.
import {readFile} from 'fs/promises'
import path from 'path'

export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get('name')
  const data = await readFile(path.join(process.cwd(), 'uploads', name!))
  return new Response(data)
}
