import { NextResponse } from 'next/server'
import Stripe from 'stripe'

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

export async function POST(req: Request) {
  const body = await req.json()
  const { productId, name, price, quantity = 1, email } = body

  if (!productId || !name || typeof price !== 'number') {
    return NextResponse.json({ error: 'invalid cart' }, { status: 400 })
  }

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    customer_email: email,
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: { name },
          unit_amount: price,
        },
        quantity,
      },
    ],
    metadata: { product_id: productId },
    success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/thanks?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.NEXT_PUBLIC_SITE_URL}/cart`,
  })

  return NextResponse.json({ url: session.url })
}
