import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase/server-admin'

export async function GET(req: Request) {
  const token = req.headers.get('authorization')?.replace('Bearer ', '')

  if (token !== process.env.NEXT_PUBLIC_ADMIN_API_TOKEN) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  }

  const [orders, customers] = await Promise.all([
    supabaseAdmin.from('orders').select('id', { count: 'exact', head: true }),
    supabaseAdmin.from('profiles').select('id', { count: 'exact', head: true }),
  ])

  return NextResponse.json({ orders: orders.count, customers: customers.count })
}
