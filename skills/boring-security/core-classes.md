# Core attack classes

Classes for any target. Pick the ones recon justifies, split large ones per subsystem, and add target-specific classes recon reveals. Each bold block is self-contained and pasted verbatim into Hunter briefs.

**Injection**
Follow untrusted data to any place it becomes code, a query, a path, a command or markup. What a "sink" is depends on the target:
- web/services: SQL/NoSQL/ORM raw fragments, HTML/templates, shell, file paths, redirects, deserializers, LDAP/XPath, GraphQL resolvers that build queries;
- libraries: any API that turns caller bytes into a buffer op, format string, regex, or parser state;
- CLIs: argument and shell construction, path handling, env interpolation;
- browser side: `packs/browser-client.md`.
Don't stop at direct flows. Look for **second-order** injection (stored safely, later used unsafely by different code), injection through **keys, field names, headers and metadata** rather than values, and injection into **secondary systems** (logs, caches, search indexes, analytics, emails, PDFs).

**Access control**
Prove the caller can do something outside its authority — not just that a check exists, but that it checks the *right permission* on the *right object* through the *right mechanism*:
- Another route to the same state change with a weaker check?
- A body/query field that overrides what the permission layer meant to pin (owner_id, role, tenant_id, is_admin)?
- AuthN without AuthZ (logged-in == allowed)?
- Inconsistent checks across REST vs GraphQL vs websocket vs admin vs mobile API for the same resource?
- Bulk, batch, export, import, search endpoints that skip per-item checks?
For complex models, split into "auth bypass" and "authorization logic" units.

**Files, fetches and parsing**
- Path traversal on read/write: `../`, encoded/double-encoded, Unicode normalization, symlinks, NUL, Windows `\`, drive letters, UNC, alternate data streams, case-insensitive FS.
- SSRF: user-chosen URLs fetched server-side, redirect following, DNS rebinding, parser differentials between validator and fetcher, IPv6/decimal/octal IPs, `file://`/`gopher://`.
- Unsafe deserialization, zip/tar slip, temp-file races, upload type confusion.
- Memory safety where relevant (→ `packs/native-memory.md`).
- TOCTOU between checking a file and using it.

**Crypto and secrets**
- Non-CSPRNG for tokens, reset codes, nonces, session IDs, invite links.
- Secrets in source, logs, errors, URLs, client bundles, mobile binaries, crash reports.
- Broken KDF/password hashing, missing or skipped MAC verification, nonce/IV reuse, ECB, unauthenticated encryption, static keys.
- Non-constant-time comparison of secrets.
- What happens when a crypto call fails — does the error path quietly fall back to "no crypto" or "accept"?

**Business logic**
Scanners can't find these, so they're often the highest-value bugs. For each important workflow:
- **State machine**: skip a step, go backwards, replay a finished flow, half-fail (step 2 of 3 fails — is step 1 rolled back?).
- **Races with business impact**: double-spend, double-redeem, double-approve, lost update — anywhere check-then-act isn't atomic.
- **Numbers**: negative, zero, huge, precision loss, currency rounding, string↔number coercion, unit mix-ups.
- **Right check, wrong rule**: the check exists but doesn't match the business rule; one operation's restriction bypassed by another operation with the same effect.
- **Implicit trust**: "we validated it on the way in" — but another path wrote it.
- **Time**: expiry boundaries, clock skew, timezone disagreement between components, scheduling windows.
- **Defaults/fallbacks**: posture when config is missing, a flag is off, a dependency is down, or a migration is half-done.

**Feature abuse and data leakage**
Legit features used for something they weren't meant for:
- **Export/backup** returning data above the caller's level, other users' data, deleted/draft/private content, pruned revisions.
- **Import/restore** overwriting others' data, skipping validation, writing into collections the caller can't write.
- **Search/filter/sort as oracle** — existence, hidden fields or roles revealed through counts, ordering, or facets.
- **Enumeration via side effects** — different errors, status codes, timing or sizes for "doesn't exist" vs "no access"; signup/reset/invite user enumeration.
- **Preview/draft/staging** tokens that unlock more than one item; drafts in sitemaps/RSS/list APIs; cache headers letting a CDN serve private pages.
- **Webhooks/callbacks/notifications** as SSRF, including after redirects.

**Chains and trust gaps**
Things that are fine alone and broken together:
- **Multi-step**: map what a low-privilege actor can read, write, invoke and keep; connect only *proven* outputs to later trust decisions.
- **A→B guarantee mismatch**: what A validates vs what B assumes — truncation, coercion, normalization, tenant scope, plugin access.
- **Second-order use**: a value stored safely in one role is reused in another: a display name used as a JSON path or file path, escaped text later rendered raw, a plain string later treated as a URL, regex, template or policy.
- **Capability growth**: tokens, API keys, OAuth grants, plugin/MCP/agent capabilities that widen after refresh, delegation, caching, role change or composition. Name the exact operation the result shouldn't have.
- **Timing windows**: setup, migration, soft-delete, revoke vs cache expiry, check vs use, validate vs consume.
- **Rollback/recovery**: undelete, restore, revert, cancel — do they re-apply *current* ownership and validation?

**Wildcard**
No category: find what the other classes missed.
- What's the weirdest code here, and why does it exist?
- Half-built, experimental, bolted-on, legacy or compat features.
- API calls the UI never makes. Undocumented routes, params, headers, flags, debug switches.
- Features never designed to meet: i18n + preview + cache; import + plugins + webhooks; OAuth + impersonation + API keys.
- Git history: reverted security fixes, commented-out checks, secrets added then removed.
- Actions by a valid account that hurt *other* users, shared integrity, availability, or operator cost.
- Irreversible or high-stakes actions — is approval bound to the final actor/action/object?
- Environmental assumptions: local DB, accurate clock, trusted DNS, case-sensitive FS.
- Tests: what edge cases did the developer think of, and which did they not?
Chase anomalies in scope until you can say whether they're safe. Verify "this is safe because…" comments. Read anything named `temp`, `hack`, `legacy`, `old`, `bypass`, `skip`.

**Obvious things**
Literal, exhaustive, unglamorous. Check every item and report each result:
- Hardcoded secrets: grep `password`, `passwd`, `secret`, `api[_-]?key`, `token`, `Bearer `, `-----BEGIN`, `AKIA`, `xox[bp]-`, `ghp_`, `sk_live_`, `AIza`, default creds.
- Security TODO/FIXME/HACK/XXX (`TODO: auth`, `FIXME: validate`, `HACK: skip check`).
- Debug/dev mode switchable in prod by env, query param, header or cookie.
- Seed/test/example credentials that would work in prod.
- Unprotected `/debug`, `/admin`, `/test`, `/status`, `/health`, `/metrics`, `/env`, `/.env`, `/config`, `/actuator`, `/graphql` introspection, Swagger UIs.
- Committed `.env*`, `credentials.json`, `*.pem`, `*.key`, `*.p12`, `*.jks`, `google-services.json` with server keys, `GoogleService-Info.plist`.
- `.gitignore` coverage for secrets, uploads, local config.
- Unpinned deps / lockfile drift / known-vulnerable versions visible in lockfiles (offline by default: what you know is stale, so call these leads; a registry or OSV lookup only via the `--advisories` opt-in in `references/advisories.md`).
- `eval`, `exec`, `Function()`, `child_process`, `vm.run*`, dynamic `import()`/`require()`, `pickle.loads`, `yaml.load` (unsafe), `Runtime.exec` with dynamic input.
- CORS `*` or reflected origin with credentials.
- Cookies missing `HttpOnly`/`Secure`/`SameSite` — *only if* they carry something sensitive and JS doesn't need them.
- Open redirects via `redirect`, `return`, `returnTo`, `next`, `url`, `goto`, `continue`, `callback`.
- Plain-HTTP endpoints / TLS not enforced.
- Stack traces, internal paths, SQL errors in production responses.
A flag is not a finding: for each hit, trace whether it's reachable and what it actually exposes before reporting.
