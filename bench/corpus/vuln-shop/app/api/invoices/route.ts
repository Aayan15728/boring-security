import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = createClient()

  const { data, error } = await supabase
    .from('invoices')
    .select('id, order_id, amount_cents, issued_at')
    .order('issued_at', { ascending: false })

  if (error) {
    return NextResponse.json({ error: 'could not load invoices' }, { status: 500 })
  }

  return NextResponse.json({ invoices: data })
}
