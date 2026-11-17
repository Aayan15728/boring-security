const RULE_BODY = 'return Math.round(subtotal * 0.2)'

export const computeVat = new Function('subtotal', RULE_BODY) as (subtotal: number) => number

export function withVat(subtotalCents: number): number {
  return subtotalCents + computeVat(subtotalCents)
}
