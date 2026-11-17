import { NextRequest, NextResponse } from 'next/server'
import { searchProducts } from '@/lib/db/search'
import { getProductsByCategory } from '@/lib/db/products'

export async function GET(req: NextRequest) {
  const params = req.nextUrl.searchParams
  const q = params.get('q')?.trim() ?? ''
  const category = params.get('category')
  const sort = params.get('sort') ?? 'created_at'

  if (category) {
    const products = await getProductsByCategory(category)
    return NextResponse.json({ products })
  }

  if (q.length < 2) {
    return NextResponse.json({ products: [] })
  }

  const products = await searchProducts(q, sort)
  return NextResponse.json({ products })
}
