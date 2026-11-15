# Pack: Data isolation and lifecycle

## When to use

Multi-tenant stores, row-level security, caches and search indexes, object/blob links, analytics, logging and tracing pipelines, export/backup/import/restore, migrations, deletion, retention, revocation. Includes BaaS rules (Firestore/RTDB/Storage rules, Supabase RLS, Amplify auth rules).

## Discipline

```text
- Isolation must hold on every path to the data, including derived copies: cache, search index,
  replica, export, backup, log, analytics, embedding store. Name the copy that leaks.
- Show the tenant/owner predicate (or its absence) at the exact query or lookup, and where its
  value comes from: the authenticated session, or something the client controls.
- A policy layer (RLS, BaaS rules, views, grants) counts only for the client that is subject to it:
  service-role keys, admin SDKs and raw connections bypass it.
- Lifecycle bugs live in transitions: create, share, revoke, delete, migrate, restore. Test the
  transition, not only the steady state.
- Proof is two dummy tenants/owners in a local store: B's record returned to, or changed by, A.
```

## Tenant and object isolation

**Missing tenant or owner enforcement**
Lookup by id without a scope predicate; scope taken from the request body, header or path instead of the session.

**Composite-key and namespace collision**
Keys built by concatenation (`tenant + ":" + id`) that collide; case or Unicode folding making two names equal; cache keys missing a dimension.

**Policy and query disagreement**
RLS or BaaS rules say one thing while a raw query, service-role client or admin SDK path ignores them; BaaS rules with `auth != null` as the only check on per-user data.

**Blob and signed-reference overreach**
Predictable object keys; signed URLs not bound to one object, tenant or short expiry; public-read defaults.

## Derived data and disclosure

**Search, cache and index ACL drift**
Indexed documents keep the ACL they had at index time; caches keyed without user/tenant; embeddings retrievable across tenants.

**Analytics, logs, traces and diagnostics as alternate readers**
PII or secrets in telemetry readable by broader roles or third-party vendors than the source data.

**Enumeration and aggregate oracles**
Counts, facets, autocomplete or error differences revealing other tenants' data or existence.

## Export, backup, restore, migration

**Export and backup scope expansion**
Exports include rows, fields or revisions beyond what the requester can read.

**Import and restore authority expansion**
Imported or restored records set owner, tenant, role or id fields chosen by the importer.

**Migration default and ownership confusion**
New columns default to permissive values; backfills assign wrong owners; dual-write windows with mismatched rules.

**Backup and replication boundary drift**
Replicas, snapshots or backups readable by principals who can't read the primary.

## Deletion, revocation, retention

**Soft-delete and tombstone bypass**
Deleted records still reachable through other endpoints, search, exports or caches.

**Stale authorization and derived copy use**
Revoked users keep reading cached, shared-link or exported data.

**Retention and queued-work overrun**
Jobs process or resend data after a deletion request or retention expiry.

**Restore reintroduces invalid state**
Restoring a snapshot or revision resurrects revoked access, deleted users or old ownership.

## Moves

- For each table/collection: every reader and writer path with its scope predicate and the client type it uses.
- For each derived copy: how ACLs propagate, update and expire.
- Two dummy tenants in a local store or emulator (Firebase emulator, local Supabase/Postgres); assert cross-tenant reads and writes fail.

## Gate

1. Name both tenants/owners and the exact path that crosses.
2. Policies applied out-of-band (deployed rules not in the repo) are blockers when decisive.
