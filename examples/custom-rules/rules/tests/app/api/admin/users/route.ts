import {requireUser} from '@/lib/auth'
// Admin code may use the admin client: excluded by the rule's paths.
// ok: myapp-admin-client-outside-admin
import {supabaseAdmin} from '@/lib/supabase-admin'

export async function GET(req: Request) {
  await requireUser(req)
  return Response.json(await supabaseAdmin.from('users').select('*'))
}
