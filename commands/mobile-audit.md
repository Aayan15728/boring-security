---
description: Mobile app security audit (Android / iOS / React Native / Flutter / Capacitor) - components, intents, deep links, WebView bridges, storage, TLS, embedded keys, client-trusted APIs
argument-hint: "[target] [--profile quick|standard|deep] [--out <run dir>] [--budget <agents>] [--with-backend]"
---

Use the `boring-security` skill in **Audit mode** as a scoped run on `packs/mobile.md` (profile default `deep`). Other arguments as in `/full-audit`: `$ARGUMENTS`

- Recon must find the **final** artefacts: merged AndroidManifest (`build/intermediates/merged_manifests/`), Info.plist, entitlements, `network_security_config.xml`, flavors, `app.json`/`app.config.*`, Capacitor/Cordova config, Firebase/Supabase rules. If the merged manifest is missing, record the blocker; don't build to get it unless the sandbox allows.
- Seed one unit per component, scheme/link, WebView, storage location, network client and embedded key, not one "mobile" unit. Always include Obvious things, Crypto and secrets, and Access control on client-trusted server decisions.
- `--with-backend`: also seed the mobile API server code in the repo (`web-and-identity`); otherwise backend surfaces are `out_of_scope`.

Reply as `/full-audit`, plus a short attack-surface table: item → exposure → status.
