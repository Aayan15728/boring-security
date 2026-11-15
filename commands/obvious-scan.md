---
description: Fast literal sweep for the obvious - hardcoded secrets, debug switches, open admin endpoints, committed keys, eval, permissive CORS - detector-driven, each hit traced before reporting
argument-hint: "[target or paths]"
---

Use the `boring-security` skill in **Advisor mode** on: `$ARGUMENTS` (default cwd).

1. Run `scripts/detect.cjs <target>` (with `--files` for paths).
2. Go through `core-classes.md#Obvious things` for whatever the detector can't see: unprotected admin/debug routes, seed credentials, `.gitignore` gaps.
3. Report every hit and bullet as ✅ nothing / ⚠️ hit at path:line with traced impact / ❓ needs an owner check. Untraced hits go under hardening. Never print a secret: show its type and first 4 characters only. Write no files unless I ask.
