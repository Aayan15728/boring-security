import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { supabaseAdmin } from '@/lib/supabase/server-admin'

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const supabase = createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()

  if (!user) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  const { data: order, error } = await supabaseAdmin
    .from('orders')
    .select('id, status, total_cents, shipping_address, paid_at, order_items(product_id, quantity, unit_price_cents)')
    .eq('id', params.id)
    .single()

  if (error || !order) {
    return NextResponse.json({ error: 'not found' }, { status: 404 })
  }

  return NextResponse.json(order)
}
