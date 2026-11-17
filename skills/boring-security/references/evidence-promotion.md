# Evidence promotion (lead only)

After a sandboxed run, `scratch/` is attacker-shaped: it can hold symlinks to your secrets, FIFOs that hang a reader, hard links, or files that are still changing. Only the lead copies files to `evidence/`, only after every sandboxed process has exited, and only files declared in advance (relative name, per-file byte cap, total cap). Declare them in the sandboxed agent's prompt next to its brief path, and promote them before `run-state.cjs ingest`, which returns a unit whose `local` check names a missing evidence file to `planned`.

```bash
node "$SKILL_DIR/scripts/promote.cjs" <scratch-root> <evidence-root> <relpath> <maxBytes>
```

The helper enforces:
1. The path is relative, with no `.`, `..`, empty, absolute, drive or backslash segments.
2. Every parent directory is resolved without following links. On Linux this is descriptor-relative (`/proc/self/fd/<dirfd>/<name>` with `O_NOFOLLOW|O_DIRECTORY`), so it holds even against a concurrent writer. Elsewhere it uses per-component `lstat` and relies on no process still running.
3. The leaf is opened `O_NOFOLLOW|O_NONBLOCK`, then `fstat`ed: regular file, exactly one link, within the cap.
4. The read goes through that handle with the cap enforced, then a second `fstat` confirms the same identity, size and link count.
5. Destination parents are walked the same way and created one at a time; the leaf is created exclusively (`O_EXCL|O_NOFOLLOW`) and checked to be a fresh regular file.
6. Nothing is ever globbed, recursed, extracted, or promoted if it is a symlink, FIFO, socket, device or directory.

A non-zero exit means the file is **not evidence**. If it was decisive, the finding stays `needs_validation` with blocker `evidence promotion failed: <reason>`.
