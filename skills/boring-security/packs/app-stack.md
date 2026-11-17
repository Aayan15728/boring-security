# Pack: App stack (BaaS, serverless and starter kits)

## When to use

Apps built on a meta-framework (Next.js, Remix, SvelteKit, Nuxt, Astro) with a backend-as-a-service or hosted database (Supabase, Firebase, Convex, Appwrite, PlanetScale/Neon behind an ORM), a hosted auth provider (Clerk, Auth.js/NextAuth, Supabase Auth, Firebase Auth), payments (Stripe, Lemon Squeezy, Paddle), serverless hosting (Vercel, Netlify, Cloudflare) and paid model APIs. Typical of apps generated or scaffolded quickly: the bugs are mostly missing controls, not subtle ones.

Related packs: `data-lifecycle` (tenant isolation, derived copies and deletion in depth), `web-and-identity` (JWT/OAuth/session protocol detail), `ai-agents` (what a model may do with tools), `availability` (spend and quota as shared impact), `cloud-infra` (IAM and bucket policy beyond the BaaS). This pack covers the starter-stack seams between them.

## Discipline

```text
- In this stack the browser talks to the database and to server functions directly. The client is
  the attacker's tool: they replay any request the app makes, with any arguments, from curl.
- The public/anon/publishable key and the Firebase web config are public by design. Holding them is
  not a finding. The only boundaries are the policy/rules layer and server-side checks.
- "The UI doesn't offer it" is never a control. Hidden buttons, disabled fields, client-side role
  checks and route guards in components are bypassed by the device owner.
- Every server action, route handler, API route, loader/action and edge function is a public HTTP
  endpoint, wherever it is imported from and whether or not any page links to it.
- Middleware matchers are allowlists with gaps. Auth enforced only in middleware or a layout is
  enforced only on the paths the matcher and the render tree actually cover.
- A policy in the repo is not proof it is deployed: tables, rules and buckets are often created in a
  dashboard, and repo migrations may never have run. When the deployed policy decides the outcome,
  it is a needs_validation blocker with the exact owner check from references/deployed-checks.md.
- Proof is two dummy users against a local emulator or local stack (supabase start, Firebase
  emulator suite), or a complete static trace from the public request to the missing check. Never
  the deployed project.
```

## Data layer

**Database exposed without row-level policy**
A table or collection reachable with the public key has no effective per-row rule. Shapes: a Supabase/Postgres table in an API-exposed schema created without `enable row level security` (with the default grants to `anon`/`authenticated` this means full read and often write; verify the grants at the pinned setup); a policy `using (true)` on per-user data; an `insert`/`update` policy whose `with check` is `true` or weaker than its `using` (when `with check` is omitted Postgres reuses `using`, so look for an explicit weak one); RLS is row-level only, so an owner-updatable row that also holds `role`, `plan`, `credits` or `is_admin` lets users promote themselves unless column grants or a trigger stop it; policies keyed on client-writable data such as `auth.jwt() -> 'user_metadata'` (Supabase user metadata is editable by the user; `app_metadata` is not); views that run with owner rights and skip RLS (Postgres 15+ needs `security_invoker = true`); `security definer` functions exposed as RPC and executable by `anon`/`authenticated` (Postgres grants `EXECUTE` to `PUBLIC` by default). Firebase: `allow read, write: if true`, expired-or-not "test mode" rules (`request.time < timestamp.date(...)`), or `if request.auth != null` on per-user documents, which admits every signed-in user. Convex/Appwrite: public queries/mutations or collection permissions (`Role.any()`, `Role.users()`) without an owner check.

**Privileged key in client-reachable code**
A key that bypasses the policy layer reaches the browser or a public bundle: Supabase `service_role`/secret key, Firebase Admin SDK credentials, a database URL with the owner role, a Stripe secret or restricted key, a model provider key. Shapes: imported into a `'use client'` component or a module a client component imports; read from a public-prefixed env var (`NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`, `NUXT_PUBLIC_`/`runtimeConfig.public`, `EXPO_PUBLIC_`, `REACT_APP_`); returned in a server response or serialized into page props. The opposite mistake also counts: a server route that uses the service-role client for a user-scoped query has turned RLS off for that route, so it needs its own owner check.

## Server surface

**Unauthenticated server route or action**
A route handler, API route, server action, loader/action, tRPC procedure or edge function reads or mutates per-user data with no session check on its own code path. Shapes: auth checked in the layout or page but not in the action the page calls (layouts do not wrap server actions or route handlers); a server action exported from a `'use server'` file and callable by its action id with arbitrary arguments, including ids the UI never passes; middleware `matcher` that misses `/api/*`, a rewritten path, a trailing-slash or locale variant, or the action's POST target; `publicProcedure` used where `protectedProcedure` was meant; Supabase edge functions deployed with JWT verification off (`verify_jwt = false`) and no check in code; cron and admin routes protected only by being unlinked. Middleware as the sole check is also exposed to framework bugs (e.g. CVE-2025-29927, `x-middleware-subrequest` bypass in self-hosted Next.js before 15.2.3/14.2.25): check the pinned version.

**Client-trusted price, role or ownership**
The server takes a security-relevant value from the request instead of the server-side record or the verified session: amount, `unit_amount`, `price_data`, quantity, currency, plan, credits, discount, `role`, `isAdmin`, `userId`, `ownerId`, `tenantId`/`orgId`. Shapes: a checkout session created with a client-sent amount instead of a server-side price id; an update that spreads the request body into the row (`update(req.body)`, `.update({...data})`) so the caller sets their own role or owner; a lookup by id with no owner predicate (IDOR) because "only the owner knows the id"; entitlement granted on the `success_url` page or by a client call after redirect instead of from the verified webhook or a server-side retrieve of the payment.

**Webhook without signature verification**
A payment, auth or BaaS webhook acts on an unauthenticated body. Shapes: handler parses JSON and trusts it without `stripe.webhooks.constructEvent` (or Lemon Squeezy `X-Signature` HMAC, Paddle `Paddle-Signature`, Clerk/Svix headers); verification over re-serialized JSON instead of the raw body (`await req.text()` in App Router; body parsing disabled in Pages Router), which fails closed and is then "fixed" by removing it; the secret compared with `==` or verification errors caught and ignored; no deduplication by event id so a replayed or retried event grants twice; entitlement keyed on a `userId`/email in `metadata` or `client_reference_id` that the client chose when creating the session, instead of a value the server set; test-mode and live-mode secrets mixed so test events credit live accounts.

**Paid or model endpoint without auth and limits**
A route that spends operator money (model API, image/audio generation, SMS, email, scraping, paid search) is callable anonymously, or by any signed-up account with no per-user quota, so one actor drains the wallet or exhausts the provider rate limit for everyone. Shapes: no session check on the chat/completion route; rate limiting keyed on a header the caller sets (`x-forwarded-for` read without a trusted proxy) or held in per-instance memory on serverless; user-controlled `model`, `max_tokens`, `n`, image size or tool/loop count; free-tier signups with no verification turning the quota into an open faucet; keys with no provider-side spend cap (owner-observed, see `availability`).

## Files and bundles

**Storage bucket and upload exposure**
Uploaded or generated files readable or writable beyond their owner. Shapes: a public bucket (Supabase `storage.buckets.public`, a public-read S3/GCS/R2 bucket, Firebase Storage rules `if true`) holding private files; storage policies that check `auth.role()`/`request.auth != null` but not the owner path segment; object keys built from client-supplied names so one user overwrites or lists another's (`${userId}/${file.name}` with `userId` from the request); no size or MIME limit on uploads (bucket `file_size_limit`/`allowed_mime_types` or a server check), allowing stored HTML/SVG served from the app's origin; signed upload or download URLs not bound to one object, short expiry and the caller's own path.

**Secrets and source shipped to the browser**
Server-only material reachable in production static output. Shapes: secrets under public env prefixes (inlined at build time, so a later dashboard change needs a rebuild to remove them); `server-only` modules (DB clients, admin SDKs, prompts, pricing logic) imported into client bundles because nothing marks them `import 'server-only'`; browser source maps published in production (`productionBrowserSourceMaps`, Vite `build.sourcemap`, verify defaults at the pinned version) exposing unminified source and comments; `.env`, `.env.local` or `.env.production` committed, or present in git history; API responses and server-component props that return whole rows including other users' fields or internal columns.

**Auth provider misbinding**
The server identifies the user from something the provider does not vouch for. Shapes: trusting unverified cookie or storage data server-side where the provider requires a verifying call (Supabase `getSession()` reads the stored session without re-validating it; server code should use `getUser()` or a signature-verifying claims call, per the pinned client version); accepting `userId`/`email` from the request body or a client-set header instead of `auth()`/`currentUser()`/`verifyIdToken()`; linking or merging accounts by an email the provider has not marked verified; signing app JWTs with the BaaS JWT secret or a public key, or decoding without verifying (`jwt.decode`); Auth.js `callbacks` that copy client-influenced fields into the session; OAuth `redirectTo`/`callbackUrl` and provider redirect-URL allowlists that accept wildcards or any path on a shared preview domain.

## Moves

- Start from `scripts/inventory.cjs <target>`, which lists the server and data surfaces it can see deterministically (route handlers, server actions, edge functions and the like). Treat it as a starting list, not a complete one: add what it misses, and never report a row untraced.
- Table inventory: every table/collection/bucket → its policy or rule per operation → every client type that reaches it (anon key, user session, service role, admin SDK). Mark which come from repo migrations and which only from code references (likely dashboard-created).
- Endpoint inventory: every route handler, server action, loader/action and edge function → the exact auth call on its own path, or the middleware entry that covers it. Diff the middleware matcher against this list, including API, rewritten, locale and action targets.
- For each payment, credit and entitlement flow, find the server-side source of truth (price id lookup, webhook event, payment retrieve) and every write to the entitlement field.
- For each paid endpoint: who can call it, the per-user limit and where it is stored, and which cost parameters the caller controls.
- Follow the client bundle boundary: every module a `'use client'` file imports, every public-prefixed env var.
- When a sandbox is available, stand up the local stack or emulator from repo migrations/rules with two dummy users and replay the attacker's request with only the public key and user A's session.

## Gate

1. Name both principals (anonymous or user A, and user B or the operator) and the resource of B's that A reaches.
2. Give the exact request A sends using only the public key and A's own session: table/RPC/route/action, method, arguments.
3. Cite the server-side line, policy or rule that should have refused it, or show it is absent on that path.
4. Show a local two-user result, or a complete static trace with the policy file and every middleware on the path.
5. When the deployed policy, rule, bucket setting, env var or webhook configuration decides the outcome, the result is a `needs_validation` blocker naming the exact owner-run check from `references/deployed-checks.md`: not a finding, and not a dismissal.
