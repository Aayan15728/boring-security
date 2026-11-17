import { timingSafeEqual } from 'node:crypto'
import { supabaseAdmin } from '@/lib/supabase/server-admin'

function isAuthorized(req: Request) {
  const given = Buffer.from(req.headers.get('authorization') ?? '')
  const expected = Buffer.from(`Bearer ${process.env.CRON_SECRET}`)
  return given.length === expected.length && timingSafeEqual(given, expected)
}

export async function GET(req: Request) {
  if (!isAuthorized(req)) {
    return new Response('unauthorized', { status: 401 })
  }

  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()

  const { count } = await supabaseAdmin
    .from('chat_messages')
    .delete({ count: 'exact' })
    .lt('created_at', cutoff)

  return Response.json({ deleted: count ?? 0 })
}
