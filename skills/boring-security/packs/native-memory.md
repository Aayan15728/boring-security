# Pack: Native code, memory safety and binaries

## When to use

C/C++, unsafe Rust, Zig, Go `unsafe`/cgo, parsers and decoders for untrusted formats, FFI boundaries, kernel modules and drivers, binary/plugin loaders, JITs, firmware.

## Discipline

```text
- Name who supplies the bytes (network peer, file author, unprivileged user, guest VM, other
  process) and the privilege of the process that parses them.
- Report the observed fault class (OOB read/write, UAF, overflow, assertion, leak), not a
  hypothetical exploit. Severity follows delivered input × observed fault × process privilege.
- Arithmetic claims show concrete values: which input makes which expression wrap or truncate, and
  the exact size that reaches the copy or allocation.
- Preferred evidence: ASan/UBSan/MSan/TSan output from an existing fuzz harness or a minimal harness
  feeding one input. No toolchain → source-only with the arithmetic written out.
- Safe-language wrappers inherit the contract of what they wrap: find where the Rust/Go/Java side
  trusts a length, lifetime or nullability that the native side doesn't guarantee.
```

## Bounds, integers, representation

**Out-of-bounds read or write**
Lengths, counts or offsets taken from input; off-by-one on terminators; a check present on one branch only; signed index compared against an unsigned bound.

**Integer overflow, truncation and signedness**
Size arithmetic wrapping before allocation (`n * size`, `len + header`); `size_t`↔`int`; 64→32-bit truncation; negative values passing a `<` check.

**Unit and pointer-depth confusion**
Bytes vs elements vs UTF-16 code units; `sizeof(ptr)` vs `sizeof(*ptr)`; stride mistakes.

**Uninitialized data**
Stack/heap bytes or padding copied to output, or used in a security decision.

## Lifetime, type, concurrency

**Use-after-free, stale view and double free**
Iterators, slices or borrowed views outliving reallocation; error paths that free twice; callbacks after owner destruction.

**Type confusion**
Tagged unions with input-controlled tags, unchecked downcasts, `reinterpret_cast`/`transmute` on attacker data.

**Reference-count and ownership races**
Non-atomic inc/dec; release-before-use; ownership transferred across threads without synchronization.

**Shared-state races and TOCTOU**
Data races on security state; double fetch of memory shared with a less-trusted party.

**Lock order and deadlock**
Deadlocks or starvation reachable from untrusted input in a shared process (impact → `availability`).

## FFI and ABI

**Pointer-length and ownership contract mismatch**
Rust/Go/Java wrappers trusting a C length or lifetime; who frees what; null vs empty.

**Layout, alignment and enum disagreement**
`repr(C)`/struct packing mismatches; invalid enum discriminants arriving from C; endianness.

**Unwind and thread-affinity violations**
Panics or exceptions crossing `extern "C"`; thread-bound handles used from other threads.

## Loading and runtime

**Library, plugin and executable search order**
Loading from writable directories or env-controlled paths. Shared with `desktop-and-local-ipc`; use this class when the loader itself is the code under review.

**Missing artifact identity binding**
Plugins or modules loaded without a signature or hash pinned to an expected publisher.

**Malformed binary metadata**
ELF/PE/Mach-O/DEX/WASM/font/image parsers trusting header counts, section sizes, relocation targets or offsets.

**JIT and generated-code consistency**
Bounds-check elimination, speculative type assumptions, W^X violations, cache flush omissions.

**Unload and teardown safety**
Callbacks, timers or threads firing after module unload or object teardown.

## Kernel and privileged interfaces

**User-copy bounds and double fetch**
`copy_from_user` sizes taken from user data; the same user memory read twice.

**Privileged object lifecycle**
Handles freed while another process still references them; refcount underflow.

**Under-authorized powerful interfaces**
ioctls, syscalls or device nodes performing privileged operations without capability or permission checks.

## Moves

- List every untrusted-input parser and its entry API; find existing fuzzers and corpora first.
- Write the smallest harness that feeds one input; run under sanitizers with the sandbox limits.
- For FFI, write the contract both sides assume and compare them line by line.

## Gate

1. Name the input supplier, the process privilege, and the exact faulting operation (file:line).
2. Evidence is a sanitizer report or harness output, or a written arithmetic proof when nothing can run.
3. No exploit development beyond demonstrating the fault.
