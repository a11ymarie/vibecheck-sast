// Demo app: deliberately insecure. Do not deploy.
import {NextResponse} from 'next/server'

export async function GET(req: Request) {
  const back = new URL(req.url).searchParams.get('returnTo')
  return NextResponse.redirect(back ?? '/')
}
