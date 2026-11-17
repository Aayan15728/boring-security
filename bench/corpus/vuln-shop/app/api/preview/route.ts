import { NextRequest, NextResponse } from 'next/server'

// Used by the "import product from supplier page" form in the back office.
export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get('url')

  if (!url) {
    return NextResponse.json({ error: 'url required' }, { status: 400 })
  }

  const upstream = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(5000) })
  const html = await upstream.text()
  const title = html.match(/<title>(.*?)<\/title>/is)?.[1]?.trim() ?? ''

  return NextResponse.json({
    status: upstream.status,
    contentType: upstream.headers.get('content-type'),
    title,
    snippet: html.slice(0, 2000),
  })
}
