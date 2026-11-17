---
description: Cheap pre-deploy security pass for apps on the common starter stack (Next.js/SvelteKit/Nuxt + Supabase/Firebase + Stripe + model APIs) - fixed 12-item checklist, verdict, fixes and owner checks; partial by design
argument-hint: "[target] [--advisories]"
---

Use the `boring-security` skill in **Advisor mode** on: `$ARGUMENTS` (default cwd). No run directory. At most one Skeptic subagent (`phases/3-skeptic.md` §Outside a run directory), only for items that look high or critical.

1. Run `scripts/detect.cjs <target>`, `scripts/detect.cjs <target> --history` and `scripts/inventory.cjs <target>`. With `--advisories`, follow `references/advisories.md` (disclose and ask first).
2. Walk this checklist using `packs/app-stack.md` and `core-classes.md#Obvious things`. Trace each hit before marking it.
   1. Every table/collection/bucket has RLS or rules enabled, and no per-user policy is `true` or `auth != null` only.
   2. No privileged key (service role, admin SDK, Stripe secret, model key) in client-reachable code or a public-prefixed env var.
   3. Every mutating route handler, server action and edge function has an auth check on its own path or is covered by middleware (matcher diffed against the inventory).
   4. No lookup or update by id without an owner/tenant predicate.
   5. Prices, plans, credits, roles and ownership come from the server record or session, never the request body.
   6. Webhooks verify the provider signature over the raw body and deduplicate event ids.
   7. Model and other paid endpoints require auth and have a per-user limit; callers can't pick model or token caps.
   8. No committed secrets in the tree or git history; `.env*` ignored.
   9. Storage: private buckets for private files, owner-scoped paths, upload size and type limits.
   10. CORS not `*`/reflected with credentials; no open redirects, including auth callbacks.
   11. No reachable debug, admin, seed or test routes; no browser source maps in production config.
   12. Dependency advisories: checked per `references/advisories.md`, or `not checked`.
3. Never print a secret: type and first 4 characters only.

Reply:
- Verdict line: `ship` / `fix first` / `can't tell — owner checks needed`.
- Checklist table: # · item · ✅ / ❌ / ❓ · `path:line` · one-line note.
- For each ❌, the fix in one or two lines.
- The owner-run checks from `references/deployed-checks.md` that apply to the ❓ items, with the exact command or console location.
- Last line: this is a partial pass over twelve common failures, not an audit; `/full-audit` covers the rest.
