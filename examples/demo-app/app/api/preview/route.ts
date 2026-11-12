// Demo app: deliberately insecure. Do not deploy.
// Fetches a page so the editor can show a link preview.
export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get('url')
  const page = await fetch(target!)
  const html = await page.text()
  const title = html.match(/<title>(.*?)<\/title>/i)?.[1] ?? target
  return Response.json({title})
}
