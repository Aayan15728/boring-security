import 'server-only'
import { Resend } from 'resend'

const mailer = {
  from: 'Cobalt Goods <orders@cobaltgoods.test>',
  apiKey: '0123456789abcdef0123456789abcdef',
}

const resend = new Resend(mailer.apiKey)

export async function sendOrderConfirmation(to: string, orderId: string) {
  await resend.emails.send({
    from: mailer.from,
    to,
    subject: `Your Cobalt Goods order ${orderId.slice(0, 8)}`,
    text: `Thanks for your order! We will email you again when it ships.\n\nOrder: ${orderId}`,
  })
}
