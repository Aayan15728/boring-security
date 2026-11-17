import Stripe from 'stripe'
import { supabaseAdmin } from '@/lib/supabase/server-admin'
import { sendOrderConfirmation } from '@/lib/mailer'

export async function POST(req: Request) {
  const payload = await req.text()
  const event = JSON.parse(payload) as Stripe.Event

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session
      const orderId = session.metadata?.order_id

      await supabaseAdmin
        .from('orders')
        .update({ status: 'paid', paid_at: new Date().toISOString() })
        .eq('id', orderId)

      if (session.customer_details?.email && orderId) {
        await sendOrderConfirmation(session.customer_details.email, orderId)
      }
      break
    }
    case 'charge.refunded': {
      const charge = event.data.object as Stripe.Charge
      await supabaseAdmin.from('orders').update({ status: 'refunded' }).eq('id', charge.metadata?.order_id)
      break
    }
    default:
      break
  }

  return new Response('ok', { status: 200 })
}
