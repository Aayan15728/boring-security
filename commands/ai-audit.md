---
description: AI / LLM / agent / MCP security audit - injected content reaching real actions, tool authority, confirmation binding, memory poisoning, output rendering
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>] [--untrusted] [--advisories]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on `packs/ai-agents.md` (profile from `--profile`, otherwise `standard` per `references/audit-run.md` §Profiles). Other arguments and reply as in `/full-audit`: `$ARGUMENTS`

Also select `core-classes.md` Injection, Access control and Chains and trust gaps, plus `availability` for outsider-triggered loops or spend. Seed one unit per tool and per context source.
