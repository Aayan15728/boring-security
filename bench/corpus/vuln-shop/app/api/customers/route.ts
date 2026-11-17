import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase/server-admin'

export async function GET(req: Request) {
  const limit = Math.min(Number(new URL(req.url).searchParams.get('limit') ?? 50), 200)

  const { data, error } = await supabaseAdmin
    .from('profiles')
    .select('id, email, full_name, stripe_customer_id, created_at')
    .order('created_at', { ascending: false })
    .limit(limit)

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 })
  }

  return NextResponse.json({ customers: data })
}
