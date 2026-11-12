// Test cases for internal-sql-helper.yaml and no-logging-request-body.yaml
import {requireUser} from '@/lib/auth'

declare function runReport(sql: string, params?: unknown[]): Promise<unknown>
declare function allowColumn(name: string | null): string

export async function GET(req: Request) {
  await requireUser(req)
  const params = new URL(req.url).searchParams
  const sortBy = params.get('sort')
  const team = params.get('team')
  // ruleid: myapp-input-reaches-run-report
  const a = await runReport(`SELECT * FROM sales WHERE team = '${team}'`)
  // ok: myapp-input-reaches-run-report
  const b = await runReport('SELECT * FROM sales WHERE team = $1', [team])
  // ok: myapp-input-reaches-run-report
  const c = await runReport(`SELECT * FROM sales ORDER BY ${allowColumn(sortBy)}`)
  return Response.json({a, b, c})
}

export async function POST(req: Request) {
  await requireUser(req)
  const body = await req.json()
  // ruleid: myapp-logs-request-body
  console.log('report request', body)
  // ok: myapp-logs-request-body
  console.log('report request for', body.reportId)
  return Response.json({ok: true})
}
