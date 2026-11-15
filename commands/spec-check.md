---
description: Check OAuth 2.0 / OpenID Connect / JWT / SAML / WebAuthn code against the MUST-level rules of each standard, row by row, with spec citations
argument-hint: "[jwt|oauth|oidc|saml|webauthn|all] [target or paths]"
---

Use the `boring-security` skill in **Advisor mode** with `references/identity-specs.md` on: `$ARGUMENTS` (default: `all`, cwd).

1. Find every place the code issues, receives or verifies each protocol's artefacts. Include library configuration, and check the library version pinned in the lockfile.
2. Walk every row of each relevant section. Mark it ✅ pass (cite `path:line`), ❌ fails (cite `path:line` and the missing check), or ❓ can't tell from source (name what an owner must confirm).
3. Send each ❌ row with a concrete attacker path to one fresh Skeptic (`phases/3-skeptic.md`). Report the survivors as findings with the row id and spec section.

Reply with one table per protocol (row · status · where · note), then the findings. Write no files unless I ask.
