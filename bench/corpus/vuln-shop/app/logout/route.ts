import { NextRequest, NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { safeRedirect } from '@/lib/safe-redirect'

export async function POST(request: NextRequest) {
  const next = request.nextUrl.searchParams.get('next')

  const supabase = createClient()
  await supabase.auth.signOut()

  return NextResponse.redirect(new URL(safeRedirect(next), request.url), { status: 303 })
}
