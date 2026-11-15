# Running target code safely

Recipes that satisfy every control in the RULES block (`SKILL.md §2`). Two things RULES implies that are easy to miss: never mount host sockets (`docker.sock`, ssh-agent) or `RUN_DIR` itself, and apply limits on *every* run, not just risky ones. If no recipe works on this host, the run is source-only; put the exact check in `validation_plan.local`.

## Recipes

**Linux / WSL2 with Docker or Podman**

```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,size=64m \
  -v "$TARGET":/src:ro \
  -v "$RUN_DIR/agents/$AGENT/scratch":/scratch:rw \
  -e HOME=/scratch -e TMPDIR=/scratch/tmp \
  --env-file /dev/null \
  --cpus 1 --memory 512m --pids-limit 128 \
  --ulimit fsize=52428800 \
  --stop-timeout 5 \
  --security-opt no-new-privileges --cap-drop ALL \
  <already-pulled-image> timeout 120 <command>
```

Image must already be present locally (`docker image ls`). Do not `pull`.

**Linux with bubblewrap**

```bash
bwrap --unshare-all --die-with-parent --clearenv \
  --ro-bind / / --bind "$SCRATCH" /scratch --tmpfs /tmp \
  --setenv HOME /scratch --chdir /scratch \
  prlimit --as=536870912 --nproc=128 --fsize=52428800 --cpu=60 -- \
  timeout 120 <command>
```

**macOS** — `sandbox-exec` with a deny-network, deny-file-write-except-scratch profile plus `ulimit` is acceptable if you can show the profile. Otherwise source-only.

**Plain Windows** — no built-in primitive gives all four controls to an agent shell. Use WSL2 + Docker/bwrap, or Windows Sandbox with networking disabled and a mapped read-only folder. Otherwise source-only.

## Mobile-specific

- Android emulator: only an already-installed AVD, no Google account, dummy app data. Emulator flags do not isolate the network; run it where the host blocks egress (no-network VM or firewall rule), otherwise treat app-to-backend traffic as untested.
- iOS simulator: only with a dummy Apple ID-free simulator; no real keychain items.
- Static artefacts (`AndroidManifest.xml`, merged manifest under `build/`, `Info.plist`, entitlements, `network_security_config.xml`) can be read without any sandbox — they're source.

