'use client'

import { useEffect, useState } from 'react'
import { createClient } from '@supabase/supabase-js'

const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)

export function ReferralCard({ userId }: { userId: string }) {
  const [count, setCount] = useState<number | null>(null)

  useEffect(() => {
    admin
      .from('profiles')
      .select('id', { count: 'exact', head: true })
      .eq('referred_by', userId)
      .then(({ count }) => setCount(count))
  }, [userId])

  return (
    <div className="rounded-lg border p-4">
      <h3 className="font-semibold">Referrals</h3>
      <p>{count === null ? 'Loading…' : `${count} friends joined with your link`}</p>
    </div>
  )
}
