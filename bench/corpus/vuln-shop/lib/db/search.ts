import 'server-only'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 })

export async function searchProducts(q: string, sort = 'created_at') {
  const { rows } = await pool.query(
    `SELECT id, name, price_cents, image_url
       FROM products
      WHERE active = true
        AND name ILIKE '%${q}%'
      ORDER BY ${sort} DESC
      LIMIT 50`
  )

  return rows as Array<{ id: string; name: string; price_cents: number; image_url: string | null }>
}
