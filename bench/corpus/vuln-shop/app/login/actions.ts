'use server'

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { createClient } from '@/lib/supabase/server'
import { safeRedirect } from '@/lib/safe-redirect'

export async function signIn(formData: FormData) {
  const supabase = createClient()

  const { error } = await supabase.auth.signInWithPassword({
    email: String(formData.get('email') ?? ''),
    password: String(formData.get('password') ?? ''),
  })

  if (error) {
    redirect('/login?error=invalid')
  }

  revalidatePath('/', 'layout')
  redirect(safeRedirect(String(formData.get('next') ?? ''), '/dashboard'))
}

export async function signUp(formData: FormData) {
  const supabase = createClient()

  const { error } = await supabase.auth.signUp({
    email: String(formData.get('email') ?? ''),
    password: String(formData.get('password') ?? ''),
    options: { data: { full_name: String(formData.get('name') ?? '') } },
  })

  if (error) {
    redirect('/login?error=signup')
  }

  redirect('/login?check-email=1')
}
