# Pack: Browser and client-side

## When to use

SPAs, server-rendered pages with significant JS, browser extensions, the web side of webviews, service workers, browser storage, cross-window messaging, CORS consumers, WebSockets, DOM rendering of untrusted data.

## Discipline

```text
- The attacker is another origin the victim visits, an author of stored content, or a URL/file the
  victim opens. Self-XSS with no delivery path to another user is not a finding.
- Framework auto-escaping is a real control. Find where it is bypassed: dangerouslySetInnerHTML,
  v-html, [innerHTML], bypassSecurityTrust*, Markdown/HTML renderers, template strings into the DOM,
  URL attributes accepting javascript:.
- CSP, Trusted Types, SameSite, COOP/COEP/CORP, frame-ancestors are real controls when the repo sets
  them. Report the sink plus the policy the app actually sends.
- Browser-held authority (cookies, tokens in storage, extension permissions) defines the impact.
  Name what the injected script or cross-origin reader gains.
```

## DOM and object state

**DOM-based XSS**
Sources (`location.*`, `postMessage` data, `document.referrer`, storage, API fields, `window.name`) reaching `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, string `setTimeout`/`Function`, `href`/`src`/`action` with `javascript:`, jQuery `html()`/`$()`, or a framework escape hatch. Sanitizer present → check its config and whether output is mutated after sanitizing (mXSS).

**DOM clobbering**
Allowed `id`/`name` attributes in sanitized HTML shadow globals or config objects the script reads (`window.config`, `document.getElementById` assumptions).

**Prototype pollution and gadget chain**
Deep merge, query-string/JSON parsers or `Object.assign` writing `__proto__`/`constructor.prototype`, plus a **gadget** that reads the polluted key into a sink. Pollution without a gadget is hardening.

## Cross-origin messaging and network

**postMessage origin and source trust**
Listeners without an exact `event.origin` check (substring/regex/`endsWith` checks are bugs), trusting `event.source`, acting on message type alone. Senders posting secrets with `targetOrigin: "*"`.

**Cross-site WebSocket hijacking**
Cookie-authenticated WebSocket handshake without `Origin` validation.

**Credentialed CORS trust**
Reflected `Origin`, `null`, or suffix/regex allowlists combined with `Access-Control-Allow-Credentials: true` on responses carrying private data.

## Service workers and storage

**Service-worker scope takeover**
An attacker-influenced script path (uploads, JSONP, user content on the same origin) is registrable as a worker, or `Service-Worker-Allowed` widens its scope.

**Service-worker cache identity confusion**
Authenticated responses cached by the worker and served after logout or to another account.

**Browser-storage disclosure and stale authorization**
Tokens in `localStorage`/IndexedDB reachable by an existing script sink; storage not cleared on logout or account switch.

**Cross-context broadcast confusion**
`BroadcastChannel`, `storage` events or shared workers trusting messages from other tabs, accounts or frames.

## Cross-site leaks

**XS-Leaks and cross-origin state oracles**
Frame counting, error/load events, timing, cache probing, `window.length`, scroll-to-text, or response size revealing victim state to another origin. Name the bit leaked and why it matters.

**Window and opener state disclosure**
Popups or `window.opener` relations that leak state or allow redirecting a trusted tab.

## UI redress and navigation

**Clickjacking**
A one-click, state-changing action frameable by another origin (no `frame-ancestors`/`X-Frame-Options`).

**Client-side navigation confusion**
Router or `location = param` sending victims to attacker origins, especially inside OAuth or payment flows. `javascript:` URLs in router links.

## Extensions

**Extension privilege exposure**
Content scripts trusting page messages; `externally_connectable` too broad; privileged APIs (`tabs`, `cookies`, `<all_urls>`) reachable from page-controlled data; `web_accessible_resources` leaking extension state.

## Moves

- List every sink of untrusted strings in the bundle, every `message` listener, every storage key holding a credential, every place the app sets CSP and framing headers.
- For each sanitizer: library, version, config, and what happens to its output afterwards.
- Reproduce with a local static page and headless browser using dummy data; the proof is a DOM marker or a read of a dummy value.

## Gate

1. Name the attacker origin/content, the victim context, and what the executed or cross-origin code gains.
2. XSS: source → sink with the escaping bypass. Prototype pollution: pollution site **and** gadget.
3. Headers set outside the repo (CDN, proxy) are the blocker when they decide the outcome.
