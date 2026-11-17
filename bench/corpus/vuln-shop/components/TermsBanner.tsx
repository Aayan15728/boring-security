const TERMS_HTML =
  '<p>By placing an order you agree to our <a href="/terms">terms</a> and <a href="/privacy">privacy policy</a>.</p>'

export function TermsBanner() {
  return <div className="text-sm text-gray-600" dangerouslySetInnerHTML={{ __html: TERMS_HTML }} />
}
