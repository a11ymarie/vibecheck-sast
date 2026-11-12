// Public on purpose: excluded by the rule's paths, so nothing may match here.
// ok: myapp-route-without-auth
export async function GET() {
  return Response.json({ok: true})
}
