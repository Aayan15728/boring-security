import type { NextApiRequest, NextApiResponse } from 'next'
import { createPagesServerClient } from '@supabase/auth-helpers-nextjs'
import { supabaseAdmin } from '@/lib/supabase/server-admin'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'PATCH') {
    res.setHeader('Allow', 'PATCH')
    return res.status(405).end()
  }

  const supabase = createPagesServerClient({ req, res })
  const {
    data: { user },
  } = await supabase.auth.getUser()

  if (!user) {
    return res.status(401).json({ error: 'unauthorized' })
  }

  const { data, error } = await supabaseAdmin
    .from('profiles')
    .update(req.body)
    .eq('id', user.id)
    .select('id, email, full_name, role')
    .single()

  if (error) {
    return res.status(400).json({ error: error.message })
  }

  return res.status(200).json(data)
}
