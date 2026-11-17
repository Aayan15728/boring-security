import 'server-only'
import postgres from 'postgres'

const sql = postgres(process.env.DATABASE_URL!)

export async function getProductsByCategory(category: string, limit = 24) {
  return sql`
    SELECT id, name, price_cents, image_url
      FROM products
     WHERE active = true
       AND category = ${category}
     ORDER BY created_at DESC
     LIMIT ${limit}
  `
}
