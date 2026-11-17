import { supabaseAdmin } from '@/lib/supabase/server-admin'
import { verifyWebhook } from '@/lib/webhooks/verify'

export async function POST(req: Request) {
  const raw = await req.text()

  if (!verifyWebhook(raw, req.headers, process.env.RESEND_WEBHOOK_SECRET!)) {
    return new Response('invalid signature', { status: 400 })
  }

  const event = JSON.parse(raw) as {
    type: string
    data: { email_id: string; to: string[] }
  }

  await supabaseAdmin.from('email_events').insert({
    provider_message_id: event.data.email_id,
    event_type: event.type,
    recipient: event.data.to[0],
  })

  return new Response('ok')
}
