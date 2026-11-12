// Demo app: deliberately insecure. Do not deploy.
import {createClient} from '@supabase/supabase-js'

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
)

export const searchProjects = (term: string) =>
  supabaseAdmin.from('projects').select('*').or(`name.ilike.%${term}%,summary.ilike.%${term}%`)
