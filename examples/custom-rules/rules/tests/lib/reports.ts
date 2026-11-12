// Test cases for ../../admin-client.yaml: user-facing code must not use the admin client.
// ruleid: myapp-admin-client-outside-admin
import {supabaseAdmin} from '@/lib/supabase-admin'
// ok: myapp-admin-client-outside-admin
import {createServerClient} from '@supabase/ssr'

export const monthlyReport = () => supabaseAdmin.from('reports').select('*') ?? createServerClient
