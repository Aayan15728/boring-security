---
description: Web app / API security audit - access control, injection, sessions, OAuth/JWT/SAML, CSRF, CORS, caching, SSRF, DOM XSS
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>] [--untrusted] [--advisories]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on the web/API surface (profile from `--profile`, otherwise `standard` per `references/audit-run.md` §Profiles). Other arguments and reply as in `/full-audit`: `$ARGUMENTS`

Always select all of `core-classes.md`, `web-and-identity` and `browser-client`. Add `app-stack` (meta-framework + BaaS, server actions, payments, paid model endpoints), `data-lifecycle`, `messaging-rpc` (GraphQL/gRPC/webhooks) or `availability` when recon finds their boundary. Seed units per route group.
