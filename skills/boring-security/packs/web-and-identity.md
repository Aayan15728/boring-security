# Pack: Web protocol and identity

## When to use

HTTP apps and APIs, reverse proxies/CDNs/gateways, custom HTTP parsing, cookies and sessions, CSRF, JWT, OAuth/OIDC, SAML, MFA, passkeys, recovery and account linking, API keys, mTLS. Browser-side JS → `browser-client`.

## Discipline

```text
- Framing and cache bugs need two interpretations of the same request, response or cache key. Name
  both components and the exact normalized value each one sees.
- For every credential, find the signature/secret verification and every binding its role requires:
  issuer, audience, origin/RP, client, session, principal, resource, assurance level, expiry, one-time
  state. A validly signed token for another service, tenant or purpose is an invalid token here.
- Host, Forwarded/X-Forwarded-*, Origin, Referer, redirect targets, callback state and request-derived
  URLs are trust decisions. Trace each one to the identity or response it affects.
- A missing header, cookie attribute, MFA prompt or rate limit is not a finding alone. Require an
  accepted invalid request, cross-principal effect, assurance downgrade or credential disclosure.
- Session, login, MFA, recovery and linking are state machines. Check transitions the UI never makes.
```

## HTTP framing and cache

**Request framing disagreement**
Front and back end disagree on message length or boundaries: `Content-Length` vs `Transfer-Encoding`, duplicate or obfuscated headers, chunk extensions, HTTP/2→1 downgrade with smuggled CR/LF, pipelining on reused upstream connections. Needs both parsers' code or a repo-visible front-end config.

**Web cache poisoning through unkeyed input**
An input that changes the response (`X-Forwarded-Host`, `X-Original-URL`, locale header, `callback`, fat GET body) but not the cache key, so one crafted response is served to others.

**Cache deception and private-response caching**
Path confusion (`/account/x.css`, `;`/`%2F` handling, extension rules) or missing `private`/`no-store` puts an authenticated response into a shared cache.

**Host and forwarded-header trust**
Reset links, absolute URLs, redirects, tenant routing or IP allowlists built from request headers without a trusted-proxy boundary or an allowlist of hosts.

**Response header injection**
User data in header values or status lines without CR/LF rejection; unvalidated `Location`.

## Browser sessions

**CSRF**
Name the ambient credential (cookie, client cert, HTTP auth), the state-changing route, the cross-site request shape the server accepts (form-encodable, `text/plain` JSON, method override, GET side effect), the effective `SameSite` behaviour, and the missing token/Origin check. Read-only routes and routes that require a non-ambient bearer token don't qualify. Login CSRF counts when the victim then acts in the attacker's account.

**Session fixation and invalidation**
The session id isn't rotated at login or privilege change. Logout, password change, MFA change or account deletion leaves other sessions or refresh tokens alive.

**Cookie scope and transport**
Over-broad `Domain`/`Path` shared with a less-trusted subdomain (cookie tossing), auth cookies without `Secure`, missing `__Host-` where sibling subdomains are untrusted.

## Federated identity

These classes are spec-conformance checks. Paste the matching section of `references/identity-specs.md` into the Hunter brief verbatim; its rows are the checklist.

**JWT verification and claim binding**
Rows J1-J9 (`identity-specs.md#JWT and JWS`) on every path that consumes a token.

**OAuth/OIDC request and callback binding**
Rows O1-O10 (`#OAuth 2.0 (client and authorization server)`), plus C1-C8 (`#OpenID Connect Core 1.0 (relying party)`) when OIDC is used.

**SAML assertion binding**
Rows S1-S8 (`#SAML 2.0 Web Browser SSO (service provider)`).

## MFA, passkeys, account transitions

**MFA enrollment and assurance downgrade**
Adding or removing factors without step-up. A weaker factor offered as fallback. Alternate logins (API tokens, SSO, mobile, "remember this device") skipping MFA.

**Step-up binding**
Step-up proof bound to the exact session, action and time window; not reusable across accounts or actions.

**WebAuthn and passkey verification**
Rows W1-W9 (`identity-specs.md#WebAuthn / passkeys (relying party)`).

**Account linking and identity collision**
Linking by unverified email, case- or Unicode-folding collisions, and pre-account hijack (attacker registers the victim's email before the victim's first SSO login). Draw the before/after account graph: each new edge needs current-principal proof, new-identity proof and a session binding.

**Password reset and recovery**
Token unpredictable, single-use, short-lived and bound to the account. Reset link host not taken from request headers. Support or recovery flows not bypassing MFA. Reset revokes sessions.

## API keys and mTLS

**API-key scope and resource binding**
A key checked for validity but not for scope, tenant, resource or environment. Revocation defeated by caching.

**API-key exposure**
Keys in URLs, logs, referrers, client bundles, error bodies.

**mTLS peer and application identity**
The client cert is verified but its subject isn't mapped to the app principal, the mapping comes from a forgeable proxy header, or any publicly trusted CA is accepted.

**Certificate lifecycle fallback**
Expired, revoked or missing certs fall back to weaker or no authentication.

## Moves

- Walk issue → store → transmit → consume → refresh → revoke for every credential and challenge, on normal, error, retry, legacy and account-switch paths.
- List every door to the same identity and every route to the same sensitive operation. The effective policy is the weakest parallel path.
- Put parser, proxy, router, cache and app normalization side by side; feed the same bounded fixture to each.
- Diff middleware stacks between sibling routes.

## Gate

1. Framing/cache: cite both components and the divergent parse or key; show cross-request, cross-user or private-response impact.
2. Token/MFA/passkey/link/recovery/API-key/mTLS: cite the verification line and the missing binding, and show the server accepting the invalid credential or transition.
3. CSRF: all five elements from the class above.
4. Proxy chains, edge cache keys, IdP policy, cert trust stores and cookie behaviour of the deployed browser are often outside the repo. When one decides the outcome, name it as the blocker.
