# Running target code safely

Recipes that satisfy every control in the RULES block (`SKILL.md §2`): no network, empty allowlisted environment, scratch HOME/TMP, target and tools read-only, writes only to scratch, explicit limits.

**What may be mounted.** Only two host paths enter a sandbox: the target (read-only) and this agent's `RUN_DIR/agents/<id>/scratch/` (read-write). Never mount `RUN_DIR` itself, the agent's `out/` directory (`RUN_DIR/agents/<id>/out/`, where the agent writes its result JSON from outside the sandbox), another agent's directory, `evidence/`, `$HOME` or any parent of it, host sockets (`docker.sock`, podman socket, ssh-agent) or `/var/run`. Apply limits on *every* run, not just risky ones.

**Gate.** Run the probe through the same wrapper before any target-controlled execution; it must exit 0 (`node scripts/sandbox-probe.cjs --scratch /scratch --target /src`). It fails on any non-loopback interface or reachable host, proxy variables, readable host secrets, container sockets, non-zero capabilities, overlapping target/scratch, credential-like or out-of-scratch env, a writable target, and missing limits. It checks signals; it does not prove isolation. If no recipe works on this host, or the probe fails, the run is source-only; put the exact check in `validation_plan.local`.

## Recipes

Unverified: neither container recipe below has been run end-to-end by the authors (development was on Windows). Treat them as unverified until the probe passes inside them on your host; the probe is the gate, not this text.

**Linux / WSL2 with Docker or Podman**

```bash
SCRATCH="$RUN_DIR/agents/$AGENT/scratch"
mkdir -p "$SCRATCH/tmp"                      # TMPDIR must exist before the container starts

docker run --rm --pull never \
  --network none --ipc none --read-only \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,size=64m \
  -v "$TARGET":/src:ro \
  -v "$SCRATCH":/scratch:rw \
  -v "$SKILL_DIR/scripts":/tools:ro \
  -e HOME=/scratch -e TMPDIR=/scratch/tmp --workdir /scratch \
  --cpus 1 --memory 512m --memory-swap 512m --pids-limit 128 \
  --ulimit fsize=52428800 --ulimit nofile=1024 \
  --security-opt no-new-privileges --cap-drop ALL \
  <already-pulled-image> timeout 120 <command>
```

- `--network none --ipc none --read-only`: no network, no shared IPC, immutable root filesystem; only `/tmp`, `/scratch` are writable.
- `--user`: non-root, same uid as the host user, so scratch is writable and the target is only as readable as it is for you. Podman rootless also needs `--userns=keep-id`, otherwise bind mounts show up under unmapped uids.
- `--memory-swap` equal to `--memory` disables swap. `--ulimit fsize` caps each file. There is no total disk cap on a bind-mounted scratch; put scratch on a quota-limited or size-limited filesystem if the run could write a lot, or say disk is unbounded.
- The host environment is not passed through, but variables baked into the image are: check `docker image inspect <image>` and the probe's env checks. `timeout` (coreutils or busybox) and `node` (for the probe) must exist in the image.
- The image must already be present locally (`--pull never` refuses to fetch). Do not `pull`, build or `docker login`. Do not add `-v /var/run/docker.sock`, `--privileged`, `--network host` or `--pid host`.
- On SELinux hosts the bind mounts may be denied; do not relabel the target with `:z`/`:Z` (that rewrites host labels). Fall back to source-only.
- The container shares the host kernel; a container escape is out of scope of these controls.

**Linux with bubblewrap**

```bash
SCRATCH="$RUN_DIR/agents/$AGENT/scratch"
mkdir -p "$SCRATCH/tmp"
NPROC=$(( $(ps -L -u "$(id -u)" -o lwp= | wc -l) + 128 ))   # RLIMIT_NPROC counts all of your processes, so add headroom

ROOTFS=(--ro-bind /usr /usr)                  # tools and libraries, read-only
for d in bin sbin lib lib64 lib32; do          # merged-/usr hosts: symlinks; otherwise bind the real directory
  if [ -L "/$d" ]; then ROOTFS+=(--symlink "$(readlink "/$d")" "/$d")
  elif [ -d "/$d" ]; then ROOTFS+=(--ro-bind "/$d" "/$d"); fi
done

sandbox() {
  bwrap --unshare-all --new-session --die-with-parent --clearenv \
    "${ROOTFS[@]}" \
    --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache --ro-bind-try /etc/alternatives /etc/alternatives \
    --tmpfs /tmp --tmpfs /home --tmpfs /root \
    --proc /proc --dev /dev \
    --ro-bind "$TARGET" /src --bind "$SCRATCH" /scratch --ro-bind "$SKILL_DIR/scripts" /tools \
    --setenv PATH /usr/local/bin:/usr/bin:/bin --setenv HOME /scratch --setenv TMPDIR /scratch/tmp \
    --chdir /scratch \
    prlimit --as=4294967296 --nproc="$NPROC" --fsize=52428800 --cpu=60 --nofile=1024 -- \
    timeout 120 "$@"
}

sandbox node /tools/sandbox-probe.cjs --scratch /scratch --target /src   # must exit 0
sandbox <command>
```

- `--unshare-all`: new user, pid, net, ipc, uts, cgroup namespaces (no network, no host processes). `--new-session` stops the sandbox injecting keystrokes into your terminal (TIOCSTI). `--die-with-parent` and `--clearenv` kill it with the agent and drop the inherited environment.
- `--ro-bind /usr` plus the `/bin /sbin /lib /lib64` links or binds, `ld.so.cache` and `alternatives`: just enough to run dynamically linked tools. The rest of `/` is absent, so `~/.ssh`, `~/.aws`, `~/.claude`, browser profiles and `/mnt/c` do not exist inside. Tools outside `/usr` (nvm, asdf, `~/.cargo`) must be bound read-only by their exact install directory, never by a parent of `$HOME`. Add `/etc/passwd` read-only only if a tool needs the user database.
- `--tmpfs /tmp /home /root` give empty, throwaway directories; `--proc`, `--dev` give a private `/proc` and minimal devices.
- Target at `/src` read-only, scratch at `/scratch` read-write, scripts at `/tools` read-only. Nothing else from the host is mounted. HOME and TMPDIR point at scratch; `PATH` is explicit.
- `prlimit` and `timeout` bound address space, processes, file size, CPU and wall time. `--as=4 GiB` suits Node/Go/JVM, which reserve address space; lower it for C or Python tools, or prefer a cgroup limit (for example `systemd-run --user --scope -p MemoryMax=512M -p MemorySwapMax=0 -p TasksMax=128` in front of `bwrap`) where user cgroups are delegated. There is no total disk cap here either; see the Docker note.
- Needs unprivileged user namespaces. Where they are restricted (some Ubuntu/AppArmor and hardened-kernel setups, or inside another container) `bwrap` fails to start; that means source-only, not a weaker recipe. `--proc` can fail when nested.

**macOS** — `sandbox-exec` with a deny-network, deny-file-write-except-scratch profile plus `ulimit` is acceptable if you can show the profile and the probe passes. Otherwise source-only.

**Plain Windows** — no built-in primitive gives all four controls to an agent shell. Use WSL2 + Docker/bwrap (inside WSL, `/mnt/c` is the host's disk: never mount it, and the probe fails if user profiles are readable), or Windows Sandbox with networking disabled and a mapped read-only folder. Otherwise source-only.

## Mobile-specific

- Android emulator: only an already-installed AVD, no Google account, dummy app data. Emulator flags do not isolate the network; run it where the host blocks egress (no-network VM or firewall rule), otherwise treat app-to-backend traffic as untested.
- iOS simulator: only with a dummy Apple ID-free simulator; no real keychain items.
- Static artefacts (`AndroidManifest.xml`, merged manifest under `build/`, `Info.plist`, entitlements, `network_security_config.xml`) can be read without any sandbox — they're source.
