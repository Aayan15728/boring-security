# Dependency advisories (opt-in)

Without this step the skill never contacts a registry, so known-vulnerable dependencies are not checked, and the model's memory of CVEs is stale. `--advisories` (on audit commands and `/ship-check`) turns on one bounded lookup.

## Rules

- **Opt-in only.** Without `--advisories`, or when no suitable tool is installed, the report's run facts say `dependency advisories: not checked`. Never imply dependencies are clean.
- **Disclose first.** Before running, tell the user what leaves the machine: every package name and version in the lockfile (including private/internal package names) sent to the registry or OSV. Run only after a yes.
- **Lead only**, outside any sandbox, with tools already installed. Never install a scanner, never fetch one with `npx`/`pipx run`/`dlx`.
- **Lockfile only.** Nothing is installed and no project code runs. Copy the lockfile (and the manifest if the tool needs it) into an empty scratch directory and run there, so project-local config is not loaded: `.npmrc` can point the request at another host and expand `${TOKEN}` env vars into it, `.yarnrc.yml` `yarnPath` runs a repo-committed Yarn, `packageManager` can make Corepack download one, `.cargo/config.toml` aliases can shadow `cargo audit`. Drop `packageManager` and `scripts` from a copied `package.json`.
- **Read-only.** Never run `audit fix`, `npm update`, `cargo update` or anything that edits lockfiles or manifests.
- Record tool, version, date and command in run facts.

## Invocations

Run from the scratch copy. Flags marked *verify* differ across versions; check `--help` of the installed tool rather than guessing.

| Ecosystem | Lockfile | Command |
|---|---|---|
| npm | `package-lock.json` | `npm audit --package-lock-only --json --registry=https://registry.npmjs.org/` |
| pnpm | `pnpm-lock.yaml` | `pnpm audit --json` (*verify* it runs without `node_modules` at the installed version) |
| Yarn 1 | `yarn.lock` | `yarn audit --json` |
| Yarn Berry (2+) | `yarn.lock` | `yarn npm audit --all --recursive --json` only with a trusted global Yarn and no repo `.yarnrc.yml`; otherwise prefer `osv-scanner` |
| Any OSV-supported lockfile | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `go.mod`, `gradle.lockfile`, `packages.lock.json` … | v1: `osv-scanner --lockfile=<file>`; v2: `osv-scanner scan source -L <file>` (*verify*; supported formats vary by version). Don't enable call analysis. |
| Python, pinned requirements | `requirements.txt` with `==` pins (ideally hashes) | `pip-audit -r requirements.txt --no-deps --disable-pip` (*verify*). Without these flags pip-audit installs the requirements into a temporary venv, which can run package build code: don't. |
| Rust | `Cargo.lock` | `cargo-audit audit --file Cargo.lock` (call the binary directly, from outside the target) |
| Ruby | `Gemfile.lock` | `bundle-audit check --update <scratch dir>` (fetches ruby-advisory-db; *verify* it reads only the lockfile at the installed version) |
| PHP | `composer.lock` | `composer audit --locked --no-plugins --format=json` |

**Not usable here** because they build, resolve or execute project code: `govulncheck` (loads and type-checks the module; may download modules and toolchains), `mvn`/`gradle`/`./gradlew` dependency tasks and OWASP Dependency-Check plugins (run build scripts), `dotnet list package --vulnerable` (needs a restore), Snyk CLI for build-tool ecosystems (invokes the build tool), `pip-audit` in default mode, `safety` against an installed environment. Use `osv-scanner` on the lockfile instead, or report `not checked` for that ecosystem.

## What a result means

An advisory is a **lead**, never a finding, and its CVSS is not the severity.

1. Map the advisory to the vulnerable function, option or input format, and to the installed version range.
2. Find where the target calls it. Not called, or only with constant/trusted input → hardening note: "upgrade `<pkg>` to `<fixed>` (`<advisory id>`), not reachable from lower-trust input in this code".
3. Called with lower-trust input → a candidate like any other: trace from the entry point, prove the boundary, then Skeptic. Severity comes from the demonstrated impact in this target.
4. Dev-only and build-time dependencies matter only when a lower-trust actor feeds them input (PR content in CI, user uploads to a build step) → `supply-chain`.

Run facts line: `dependency advisories: checked <tool> <version> on <date> — <N> advisories, <M> reachable, <K> hardening` or `dependency advisories: not checked (<reason>)`, per ecosystem when there is more than one.
