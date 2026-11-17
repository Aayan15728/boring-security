# Install boring-security

## 1. Ask your agent

Paste this to Claude Code (or any coding agent that can run shell commands):

```text
Install the boring-security skill from https://github.com/Aayan15728/boring-security
```

That is all. The agent follows section 2 below. When it finishes, start a new Claude Code session and run
`/quick-audit`, or ask: "security audit this repo".

## 2. If you are an AI agent asked to install this

Do exactly these steps and nothing else. Requirements: `git` and Node.js 18 or newer on PATH
(`node --version`). If either is missing, stop and tell the user what to install; do not install it yourself.

1. Clone to a stable location (the plugin route loads files from this folder, so it must not be a temp dir).
   - macOS / Linux / Git Bash: `~/.boring-security/src`
   - Windows PowerShell: `$HOME\.boring-security\src`

   ```bash
   # first time
   git clone https://github.com/Aayan15728/boring-security ~/.boring-security/src
   # already cloned: update instead (fast-forward only; if it fails, stop and report)
   git -C ~/.boring-security/src pull --ff-only
   ```

2. Install:

   ```bash
   node ~/.boring-security/src/install.cjs
   ```

   (Windows PowerShell: `node "$HOME\.boring-security\src\install.cjs"`.)
3. Verify:

   ```bash
   node ~/.boring-security/src/install.cjs --check
   ```

4. Tell the user:
   - what was installed and where (the installer prints it: either the plugin `boring-security@boring-security`,
     or files under `~/.claude/` or `$CLAUDE_CONFIG_DIR`);
   - to restart Claude Code or start a new session (or run `/reload-plugins`) before the commands appear;
   - how to uninstall: `node ~/.boring-security/src/install.cjs --uninstall`;
   - if the installer said it fell back to copy mode, that the enforcement hooks are not active in that mode.

What the installer does:

- Plugin route (default when the `claude` CLI supports plugins): runs
  `claude plugin marketplace add <the clone>` and `claude plugin install boring-security@boring-security`.
  Only this route enables the bundled restricted subagents and the enforcement hooks.
- Copy route (fallback, or `--copy`): copies `skills/boring-security/`, `commands/*.md` and `agents/*.md` into
  the Claude config directory and records every file in `skills/boring-security/.install-manifest.json`.

What it does not do: it writes nothing outside `skills/boring-security/`, `commands/`, `agents/` of the config
directory (copy route), never follows symlinks there, never overwrites a file it did not install (unless
`--force`), does not touch settings, credentials, hooks or MCP config, installs no dependencies and makes no
network requests. The only network use in the whole flow is the `git clone`/`pull`. Do not run any other
script from the repository (detector, validators, sandbox probe) as part of installing; the only code that
runs is `install.cjs` and, in `--check`, its read-only self-test.

Windows notes: use the `node` on PATH (a plain `node install.cjs` works in PowerShell, cmd and Git Bash);
paths with spaces are handled, quote them. `claude` may be `claude.exe` or `claude.cmd`; the installer
finds either.

Exit codes: 0 success, 1 error, 2 usage error, 3 conflict with a file you own (nothing written; report it to
the user, do not pass `--force` without asking), 4 `--check` failed.

## 3. Manual

### As a plugin (recommended)

```bash
git clone https://github.com/Aayan15728/boring-security ~/.boring-security/src
claude plugin marketplace add ~/.boring-security/src          # or: claude plugin marketplace add <owner>/<repo>
claude plugin install boring-security@boring-security         # add --scope project or --scope local if you prefer
```

Inside a session the equivalents are `/plugin marketplace add <path or owner/repo>` and
`/plugin install boring-security@boring-security`. Scopes: `user` (default, all your projects), `project`
(shared through the repo's `.claude/settings.json`), `local` (this repo, only you).
Plugin commands can also be called with the namespace, e.g. `/boring-security:quick-audit`.

### Copy files by hand (agents copied, no hooks)

```bash
mkdir -p ~/.claude/skills ~/.claude/commands ~/.claude/agents
cp -r skills/boring-security ~/.claude/skills/
cp commands/*.md ~/.claude/commands/
cp agents/*.md ~/.claude/agents/
```

Use `<project>/.claude/` instead of `~/.claude/` for one project. If `CLAUDE_CONFIG_DIR` is set, it replaces
`~/.claude`. `node install.cjs --copy` does the same with a manifest, conflict checks and clean uninstall.

## Update

```bash
git -C ~/.boring-security/src pull --ff-only
node ~/.boring-security/src/install.cjs
```

Re-running upgrades in place. A plugin added from a local folder loads straight from the clone, so the pull is
the update; run `/reload-plugins` or restart. For a plugin added as `<owner>/<repo>`:
`claude plugin marketplace update boring-security` then `claude plugin update boring-security@boring-security`
(restart to apply).

## Uninstall

```bash
node ~/.boring-security/src/install.cjs --uninstall
```

This removes only files recorded in the manifest and, if present, the plugin. By hand:
`claude plugin uninstall boring-security@boring-security`, and optionally
`claude plugin marketplace remove boring-security`.

## Troubleshooting

- **`node` is missing or older than 18**: install Node 18+ from nodejs.org or your package manager, open a new
  terminal, check `node --version`. The skill's scripts need it; the installer refuses to run without it.
- **Commands do not show up**: start a new session (or `/reload-plugins` for the plugin route). Copy-mode
  commands in a directory Claude Code did not yet watch need a restart. Run `node install.cjs --check`; for the
  plugin route also run `claude plugin list` and confirm `boring-security@boring-security` is enabled.
- **Name clash** (exit code 3): you already have a different `quick-audit.md`, `sec-review.md`, etc. The
  installer lists the files and writes nothing. Rename yours, or use the plugin route and call the namespaced
  `/boring-security:<command>`. `--force` overwrites your file.
- **Both a plugin and a copy are installed**: everything loads twice. Remove one (`--uninstall`).
- **`marketplace add` says the marketplace already exists from another location**: run
  `claude plugin marketplace remove boring-security`, then install again.
- **Hooks are inactive** (or the agent types lack the `boring-security:` prefix): you are on the copy route. Install as a plugin (`node install.cjs --plugin`).
- **Windows, path or `claude.cmd` problems**: run `node install.cjs --copy`, or set
  `BORING_SECURITY_CLAUDE_BIN` to the full path of `claude.exe`.
- **Symlinked `~/.claude/skills` or `commands`**: the installer refuses to write through symlinks. Install with
  `--dest <real directory>` or install as a plugin.
