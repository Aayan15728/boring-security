# Pack: Desktop apps and local IPC

## When to use

Electron, Tauri, Qt, WPF/WinUI, Cocoa, GTK apps; privileged helpers and installers; auto-updaters; local daemons and agents; browser native-messaging hosts; Unix sockets, named pipes, XPC, D-Bus, COM, loopback HTTP servers, shared memory. Android/iOS → `mobile`.

## Discipline

```text
- Name the attacker's starting point: remote web content rendered by the app, a downloaded document,
  a web page reaching a loopback server, another local app, another OS user, a sandboxed child, or a
  lower-privileged account. "Any local user" is too vague, and self-harm within the same account and
  authority is not a boundary crossing.
- Paths, process names, PIDs, bundle ids and caller-declared ids are not authentication. Real peer
  identity: SO_PEERCRED/getpeereid, named-pipe client token, XPC audit token + code-signing
  requirement, D-Bus sender credentials, capability handles.
- A privileged helper authorizes each operation and the final resolved resource itself, whatever
  its trusted front end already checked.
- Code signing, sandbox profiles, entitlements, ACLs and polkit/UAC rules count only as shipped:
  read the final packaging, not just source declarations.
```

## Renderer and bridge

**Renderer to main-process escalation**
Electron: `nodeIntegration`, `contextIsolation: false`, `sandbox: false`, broad `contextBridge` APIs, `ipcMain` handlers doing file/shell/network work on unvalidated arguments, `shell.openExternal` with attacker URLs, missing `will-navigate`/`setWindowOpenHandler` restrictions, `webSecurity: false`. Tauri: over-broad capabilities/allowlist, remote domains granted IPC. The finding needs remote or untrusted content reachable in that renderer.

**Navigation-origin to bridge confusion**
Bridge access checked at the first load or by URL prefix, not per call after redirects, frames, popups and error pages.

## Entry points and IPC

**Custom protocol and file-association handlers**
`myapp://` or file-open events that perform actions, open paths, or pass arguments to a CLI (argument injection such as `--gpu-launcher`, `-o`) without validation or user intent.

**IPC peer-authentication gaps**
Socket, pipe, XPC, D-Bus or native-messaging endpoints accepting any local peer for a meaningful method. Loopback HTTP servers reachable by web pages: missing Host/Origin checks (DNS rebinding, CSRF), wildcard CORS.

**Claimed principal vs channel identity**
The channel is authenticated as user A, but a request field selects user B, a profile, tenant or capability.

**IPC lifecycle and correlation**
Predictable request ids, reused handles, inherited descriptors, world-writable socket paths, pipe-name squatting before the service starts, stale channels across restarts.

## Privilege and filesystem

**Privileged helper as confused deputy**
A lower-privileged caller selects the command, file, service, user or setting a helper acts on. Broad sudoers/polkit/UAC/XPC rules.

**Install, update and repair path trust**
Installers or updaters running scripts or loading DLLs from user-writable places. Packages verified after extraction, or not at all. Downgrades allowed. (Signing policy → `supply-chain`.)

**Library search-order hijack**
DLL/dylib/so loaded from the CWD, user-writable `PATH` entries, writable `@rpath`/`RUNPATH` dirs, or env vars honoured by privileged binaries.

**Local file TOCTOU and link following**
Privileged code checks a path then opens it; temp files in shared directories; symlinks, junctions or hard links planted by a lower-privileged user; case/normalization changes between check and use.

**Credential-store boundary mismatch**
Tokens in config, logs, crash dumps, keychain items with broad ACLs, or the clipboard, readable by a *lower-trust* reader (another user, a sandboxed app). Readable only by the same OS account is usually not a finding.

## App state

**Account switch and logout residue**
Caches, local DBs, webview storage, background tasks or biometric approvals surviving a logout and appearing under the next account.

**Pending-action and user-presence confusion**
Notification, tray, shortcut or deferred actions executing something other than what was displayed, after expiry, or under another profile.

## Moves

- Inventory every process with its privilege, every IPC endpoint and who may connect, every URL scheme and file association, every renderer and its `webPreferences`/capabilities.
- Read final packaging: installer scripts, `electron-builder`/`tauri.conf.json`, launchd/systemd units, service ACLs, entitlements.
- Validate in an isolated VM or sandbox with dummy profiles.

## Gate

1. Name the attacker's starting privilege, channel, accepted argument, the OS/app principal crossed, and the unauthorized operation.
2. Bridge: cite the navigation/origin control **and** the privileged sink. IPC: cite peer authentication **and** per-resource authorization. Helper: cite the final normalized destination.
3. Packaging, signing, entitlements and installer ACLs not available in the repo are the blocker when decisive.
