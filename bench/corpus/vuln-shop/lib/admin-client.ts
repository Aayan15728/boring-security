const ADMIN_TOKEN = process.env.NEXT_PUBLIC_ADMIN_API_TOKEN

export type AdminStats = { orders: number; customers: number }

export async function fetchAdminStats(): Promise<AdminStats> {
  const res = await fetch('/api/admin/stats', {
    headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
  })

  if (!res.ok) {
    throw new Error(`stats request failed: ${res.status}`)
  }

  return res.json()
}
