# Identity spec checklists

Use one section per protocol the code implements or consumes, whether through a library or by hand. Check every row against the code that actually runs, the library defaults at the pinned version included. A row that fails is a candidate only when a concrete attacker can exploit the gap; record rows that pass as `source` checks in the ledger.

Sources: RFC 7519 (JWT), RFC 7515 (JWS), RFC 8725 (JWT BCP), RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security BCP), RFC 9207 (OAuth `iss` response parameter), OpenID Connect Core 1.0, SAML 2.0 Core and Profiles (OASIS), W3C Web Authentication (Level 2/3). Section numbers below are where to read; quote the line you rely on in the finding.

## JWT and JWS

| # | Requirement | Source | Look for in code | Typical bug |
|---|---|---|---|---|
| J1 | The verifier, not the token, decides the algorithm; allow exactly the expected algorithm(s) | RFC 8725 §3.1 | `algorithms` option pinned; key type matches alg | `alg` read from header; `none` accepted; RS→HS confusion using the public key as an HMAC secret |
| J2 | Signature verified on every path before any claim is trusted | RFC 7515 §5.2; RFC 8725 §3.3 | Every consumer calls verify, not decode | `decode()` result used for authz; verify only on login route |
| J3 | `kid`/`jku`/`x5u`/`x5c` are untrusted input | RFC 8725 §3.10 | Keys selected from a pinned set; no fetch from token-supplied URL; `kid` not used in SQL/paths | JWKS URL taken from the token (SSRF, attacker key); `kid` path traversal or SQL injection |
| J4 | Reject on or after `exp`; honour `nbf` | RFC 7519 §4.1.4, §4.1.5 | Expiry checked, small bounded leeway | `ignoreExpiration`, huge leeway, expiry checked only when present |
| J5 | `aud` must identify this service or the token is rejected | RFC 7519 §4.1.3; RFC 8725 §3.9 | Expected audience configured and enforced | Token for service A accepted by service B under the same issuer |
| J6 | `iss` (and the key bound to it) validated | RFC 8725 §3.8 | Issuer allowlist; key set chosen by issuer | Any issuer accepted; multi-tenant IdP without tenant check |
| J7 | Different token kinds can't substitute for each other | RFC 8725 §3.11, §3.12 | `typ` checked or kinds use different keys/audiences/claims | ID token accepted as access token; refresh token accepted as access token |
| J8 | Unknown `crit` header parameters rejected | RFC 7515 §4.1.11 | Library rejects unknown `crit` | `crit` ignored |
| J9 | HMAC keys have enough entropy; ECDH-ES inputs validated | RFC 8725 §3.4, §3.5 | Key length and source; curve-point validation in JWE | Short or guessable HMAC secret; invalid-curve attack |

## OAuth 2.0 (client and authorization server)

| # | Requirement | Source | Look for in code | Typical bug |
|---|---|---|---|---|
| O1 | Redirect URIs registered and compared by exact string match | RFC 9700 §2.1; RFC 6749 §3.1.2 | Exact match, no prefix/regex/wildcard | Prefix match plus an open redirect leaks codes or tokens |
| O2 | CSRF protection on the redirect (`state` bound to the user agent, or PKCE) | RFC 6749 §10.12; RFC 9700 §2.1 | `state` generated per request, stored in session, compared | `state` missing, constant, or not compared (login CSRF, account linking) |
| O3 | PKCE for public clients (and recommended for confidential), `S256` | RFC 7636 §4.2, §4.6; RFC 9700 §2.1.1 | Verifier generated per flow; AS verifies it; `plain` refused | PKCE optional on the AS; downgrade to `plain`; verifier not tied to the code |
| O4 | Authorization codes short-lived and single-use; reuse rejected (and issued tokens revoked) | RFC 6749 §4.1.2 | Code store marks codes used atomically | Code redeemable twice; race on redemption |
| O5 | Code bound to the client it was issued to, and to `redirect_uri` if it was sent | RFC 6749 §4.1.3 | Token endpoint checks `client_id` and `redirect_uri` | Code from client A redeemable by client B |
| O6 | No implicit grant or resource-owner password grant | RFC 9700 §2.1.2, §2.4 | `response_type=token`, `grant_type=password` disabled | Tokens in URL fragments; ROPC kept for a legacy app |
| O7 | Mix-up defence when more than one AS is used | RFC 9700 §2.1; RFC 9207 | `iss` in the authorization response checked, or per-AS redirect URIs | Code from attacker AS sent to honest AS |
| O8 | Refresh tokens for public clients rotated or sender-constrained | RFC 9700 §2.2.2 | Rotation with reuse detection, or DPoP/mTLS | Long-lived bearer refresh token in mobile/SPAs with no rotation |
| O9 | Access tokens restricted to audience and scope, and checked by the resource server | RFC 9700 §2.3 | RS validates `aud`/scope per endpoint | Any valid token accepted by every API |
| O10 | Client authentication for confidential clients; no secrets in public clients | RFC 6749 §2.3; RFC 9700 §2.5 | Secret only on the server; `private_key_jwt`/mTLS preferred | Client secret in the mobile app or SPA bundle |

## OpenID Connect Core 1.0 (relying party)

| # | Requirement | Source | Look for in code | Typical bug |
|---|---|---|---|---|
| C1 | ID Token `iss` exactly equals the expected issuer | OIDC Core §3.1.3.7 | Exact compare with discovered issuer | Substring or case-insensitive compare; any tenant of a multi-tenant IdP |
| C2 | `aud` contains this client_id; `azp` checked when there are several audiences | §3.1.3.7 | Both checks present | ID token for another client accepted |
| C3 | Signature validated with the agreed alg; `none` rejected unless explicitly agreed | §3.1.3.7 | Library verification enabled, alg pinned | Unsigned ID tokens accepted |
| C4 | `exp` and `iat` checked | §3.1.3.7 | Time checks enabled | Replayed old ID tokens |
| C5 | `nonce` checked when one was sent (required for implicit/hybrid) | §3.1.2.1, §3.1.3.7 | Nonce stored per session and compared | Nonce sent but never compared (token replay/injection) |
| C6 | `at_hash`/`c_hash` validated in implicit/hybrid flows | §3.2.2.9, §3.3.2.11 | Hash checks present when those flows are used | Swapped access token or code |
| C7 | Account keyed by `iss` + `sub`, not by email | §2 (sub), §5.7 | Lookup by (issuer, sub); email used only if `email_verified` and policy allows | Account takeover via an unverified or reassigned email |
| C8 | `acr`/`amr`/`auth_time` checked when step-up or max_age was requested | §3.1.3.7 | Requested assurance compared with returned claims | MFA requested but not verified |

## SAML 2.0 Web Browser SSO (service provider)

| # | Requirement | Source | Look for in code | Typical bug |
|---|---|---|---|---|
| S1 | The element whose signature was verified is the element consumed | Core §5 (signatures); XSW research | Signature reference ID equals the consumed Assertion/Response ID; exactly one assertion; schema-validated | XML signature wrapping: signed copy hidden, unsigned copy used |
| S2 | Assertions (or the Response) signed by the configured IdP key | Profiles §4.1.3.5, §4.1.4.2 | Key pinned from metadata, not taken from `KeyInfo` in the message | Any certificate embedded in the message trusted |
| S3 | `Recipient` matches this ACS URL; `NotOnOrAfter` not passed | Profiles §4.1.4.3 | SubjectConfirmationData checks present | Assertion for another SP or an expired one accepted |
| S4 | `InResponseTo` matches an outstanding request (unless IdP-initiated is deliberately allowed) | Profiles §4.1.4.3 | Request IDs stored and consumed once | Replay; unsolicited responses accepted silently |
| S5 | `AudienceRestriction` contains this SP's entity ID | Core §2.5.1.4 | Audience check enabled | Assertion for another SP reused |
| S6 | Assertion IDs not reused within their validity window | Profiles §4.1.4.5 | One-time-use cache of assertion IDs | Replay within the window |
| S7 | Canonicalization doesn't truncate identifiers | XML-DSig C14N; comment-injection research | NameID read from the full text content after canonicalization | `user@corp.com<!---->.evil.com` resolves to `user@corp.com` |
| S8 | XML parser hardened | (XXE) | DTDs and external entities disabled | XXE in the SAML endpoint before signature check |

## WebAuthn / passkeys (relying party)

| # | Requirement | Source | Look for in code | Typical bug |
|---|---|---|---|---|
| W1 | Challenge random (≥16 bytes), server-stored, single-use, bound to the session/user | WebAuthn §13.4.3, §7.1, §7.2 | Challenge store with expiry; compared to `clientDataJSON.challenge` | Client-chosen or reusable challenge |
| W2 | `clientDataJSON.type` is `webauthn.create` / `webauthn.get` as appropriate | §7.1, §7.2 | Type checked | Registration response replayed as an assertion |
| W3 | `origin` equals an expected origin | §7.1, §7.2 | Exact allowlist | Origin unchecked or suffix-matched |
| W4 | `rpIdHash` equals SHA-256 of the RP ID | §7.1, §7.2 | Hash compared | Credentials for another RP accepted |
| W5 | User Present flag set; User Verified flag set when policy requires UV | §7.1, §7.2 | Flags checked against policy | "Passwordless" without user verification |
| W6 | Signature verified over `authenticatorData ‖ SHA-256(clientDataJSON)` with the stored public key | §7.2 | Library verify called with the stored key | Signature not checked on some path |
| W7 | Credential belongs to the user being authenticated (allowCredentials or userHandle) | §7.2 | Credential→user lookup enforced | Any registered credential logs into any account |
| W8 | Sign counter handled per policy | §7.2, §6.1.1 | Counter regression flagged where cloning matters | Counter ignored where it is relied on |
| W9 | At registration: credential ID not already registered; attestation verified per policy | §7.1 | Uniqueness check; attestation policy explicit | Credential ID collision or takeover |

## Reporting

- Cite the row id and the spec section in the finding (`"cwe": [...]`, and the description names, for example, `OIDC C5`).
- A library-handled row is a pass only if the code enables the check and the pinned version performs it; otherwise it is a candidate or a blocker.
