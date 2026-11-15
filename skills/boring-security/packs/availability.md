# Pack: Resource exhaustion and availability

## When to use

Untrusted work can consume something **shared**: CPU, memory, disk, file handles, connections, worker pools, queues, rate or quota budgets, or operator-paid spend (LLM tokens, SMS, email, egress, serverless invocations).

## Discipline

```text
- Only shared impact counts: other users or tenants degraded, a shared process killed or wedged, or
  operator money spent. Slowing your own request, or crashing a per-request worker that is replaced
  instantly, is not a finding.
- Quantify amplification as attacker cost vs system cost. Measure one small input locally and
  extrapolate with the complexity argument. Never saturate anything to prove it.
- Existing limits are real controls: body/field size, depth, timeouts, rate limits, quotas,
  pagination caps, worker isolation. Cite them, then show the path that evades them or the cost
  that remains below them.
- Who pays matters: pre-authentication and anonymous paths outrank authenticated tenants hurting
  only themselves.
```

## Computational amplification

**Superlinear parsing, matching or evaluation**
ReDoS (nested quantifiers on user input), quadratic string or list algorithms, deep recursion, hash flooding, GraphQL depth/breadth/alias complexity, template or expression evaluation.

**Decompression and representation amplification**
Zip/gzip/brotli bombs, XML entity expansion, YAML anchors, image dimension bombs, PDF object streams, protobuf/JSON nesting.

**Database and downstream query amplification**
N+1 queries or unbounded scans driven by user parameters (`limit`, wildcard search, unindexed filters, sort on unindexed columns); fan-out calls to downstream services.

## Accumulation

**Unbounded buffering and cardinality**
In-memory maps or caches keyed by user input without bounds; metric label explosion; whole uploads buffered in memory.

**Handle and temporary-resource leaks**
File descriptors, sockets, DB connections or temp files not released on error paths.

**Detached work after cancellation**
Client disconnects or timeouts that don't cancel expensive server-side work.

## Quota and scheduling

**Pre-authentication work imbalance**
Expensive work (password hashing, crypto, DB lookups, external calls) done before authentication or rate limiting.

**Quota-accounting scope and reset gaps**
Limits keyed on spoofable values (`X-Forwarded-For`), per endpoint but not per operation, reset by re-login or new API keys, or bypassed by batch endpoints.

**Worker, pool and priority starvation**
One tenant can occupy every worker, connection or queue slot shared with others.

## Failure and recovery

**Reachable fatal error or deadlock**
One input crashes or wedges a shared process (uncaught exception in an event loop, panic in a shared worker, lock-order deadlock).

**Retry storm and fail-open amplification**
Failures trigger exponential retries, or overload causes limits to be skipped.

**Poison-record and head-of-line blocking**
One bad message blocks a shared queue or partition indefinitely.

**Unsafe recovery and capacity rollback**
Restart replays the poison input, or recovery mode drops limits.

## Operator spend

**Uncapped paid actions**
Anonymous or cheap triggers of SMS, email, LLM calls, third-party paid APIs or cloud resources without per-principal caps.

## Moves

- For each untrusted input: the most expensive code path it can reach and the limits on that path.
- Measure one small input with timing/memory in the sandbox; derive the growth curve from the code.

## Gate

1. Name the attacker capability, the shared resource, and who else is affected (or who pays).
2. Show the amplification factor from a bounded measurement or a complexity argument against the cited limits.
3. Infrastructure limits not in the repo (WAF rate limits, autoscaling caps) are blockers when decisive.
