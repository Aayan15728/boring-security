# Pack: Data integrity and concurrency

## When to use

The target persists state that must stay correct under concurrent and failing writes: money, balances, credits, inventory, seats, quotas, unique identities, status workflows, relationships, ledgers, counters. Any SQL/NoSQL store or ORM (Prisma, Drizzle, TypeORM, Sequelize, Django, SQLAlchemy, ActiveRecord, Ecto, GORM, Hibernate), plus migrations. Tenant/owner isolation and deletion lifecycle → `data-lifecycle`.

## Discipline

```text
- Start from invariants, not tables. Write each one down: "balance >= 0 and equals the sum of its
  ledger entries", "one active subscription per user", "a seat is sold at most once", "an order
  never goes from refunded back to paid". Every class below is one way an invariant breaks.
- The database is the last trusted decision point. An invariant enforced only in application code,
  or only in the frontend, holds only while every writer runs that code serially. List every writer:
  API routes, jobs, webhooks, admin tools, scripts, migrations, other services.
- Concurrency is an attacker capability: anyone who can send the request can send it 50 times in
  the same millisecond. Ordinary users hit the same races by accident (double-clicks, retries,
  mobile reconnects). Severity follows what breaks: money, other users' data or shared counters
  rank high; a duplicate of your own draft is low.
- Know the real isolation level and lock behaviour of the engine in use. Most default to READ
  COMMITTED, where check-then-act is a race; a transaction alone does not serialize anything. If the
  deployed level isn't in the repo, it's a blocker, unless CONTEXT.md states it.
- Proof is a local database (sandboxed container or SQLite/embedded where the engine semantics
  match) with dummy rows, two or more connections, and a deterministic interleaving (barrier, or
  an explicit pause between read and write). Show the invariant violated in the final state.
```

## Constraints and relationships

**Missing or wrong constraints**
An identity or business key (email, external id, idempotency key, `(user_id, product_id)` for one-per-user rules) has no UNIQUE constraint. A required relationship column is nullable or has no FOREIGN KEY. A domain rule (quantity > 0, start < end, status in an allowed set) has no CHECK. A unique constraint ignores case or normalization (`Alice@x` vs `alice@x`) while lookups normalize. Soft-deleted rows block re-creation, or (with a partial index) allow duplicates of live rows.

**Orphans and broken references**
FKs without the right `ON DELETE` (cascade, restrict, set null) for the business rule. Deletes done in app code in several statements. Polymorphic references (`owner_type` + `owner_id`) or cross-database/cross-service ids no constraint can enforce. Things left behind by partial deletes: files, cache entries, search documents.

## Concurrency

**Check-then-act duplicates**
`SELECT … if not exists → INSERT`, `findFirst` then `create`, `get_or_create` without a unique constraint behind it: two concurrent requests both pass the check. Typical damage: duplicate accounts, double sign-up bonuses, two active subscriptions, double-booked slots.

**Lost updates on counters and balances**
Read a value into the app, compute, write it back (`wallet.balance -= x; save()`). Concurrent writers overwrite each other, giving negative balances, overselling, or reusing a coupon past its limit. Safe forms: one atomic `UPDATE … SET n = n - $x WHERE id = $id AND n >= $x` with a rowcount check, `SELECT … FOR UPDATE` inside a transaction, or optimistic versioning with retry.

**Isolation anomalies and write skew**
Two transactions each read a set, each decide based on it, and write different rows: on-call minimums, "at least one admin", overlapping bookings, total spend limits. Row locks on the rows you write don't prevent this; you need SERIALIZABLE with retry, a lock on the shared parent row, or an exclusion/unique constraint that encodes the rule.

**Idempotency and duplicate delivery**
Payment, webhook, queue and client-retry paths that create effects without an idempotency key stored under a unique constraint, in the same transaction as the effect. Webhook providers deliver more than once; mobile clients retry.

## Atomicity and failure

**Partial multi-step writes**
A business operation spans several writes without one transaction: order created but stock not decremented, user created but wallet missing, transfer debited but not credited. Look for an `await` sequence with no transaction, transactions opened on a different connection or client than the queries use, and ORM calls outside the transaction callback.

**External side effects inside or outside the transaction**
Charging a card, sending email or calling another service inside a transaction that can still roll back (effect without record). Or after commit with no outbox/retry (record without effect). The dual-write needs an outbox, an idempotent retry, or a reconciliation job.

**Swallowed write failures**
`catch {}` / `except: pass` / ignored rowcounts around writes, so the caller reports success; optimistic-lock conflicts treated as success; errors after a partial write returning 200.

## Rules and validation

**Invalid state transitions**
Status fields changed by direct assignment from request input, with no allowed-transition table or a guarded `UPDATE … WHERE status = 'pending'`. Concurrent transitions: two requests both moving `pending → approved`, each triggering payouts.

**Validation outside the trusted writer**
Rules enforced only in the frontend, in one API route but not in bulk/import/admin/job paths, or in a model hook that raw queries bypass. Types coerced loosely (string "-5" → -5, `"1e9"`).

## Types and time

**Imprecise money and quantity types**
FLOAT/DOUBLE/REAL or JS `number` arithmetic for money; mixing currencies or minor/major units; rounding applied at different steps on different paths; integer overflow in 32-bit counters.

**Time, timezone and boundary errors**
Naive timestamps, servers and DB in different zones, `<` vs `<=` at expiry boundaries, comparisons done as strings, DST gaps in daily windows, clocks from the client trusted for ordering or expiry.

## Migrations

**Schema drift between migrations, models and production**
ORM models declaring constraints (unique, not null, FK) that no migration creates. Migrations edited after being applied. `db push`-style sync used in production. Manual hotfixes not captured. Compare the schema produced by replaying migrations in a local database with the models and with what queries assume.

**Unsafe migration steps**
Adding NOT NULL/UNIQUE without backfill or dedupe, which fails or locks in production. Backfills that write wrong defaults. Dropping a column the running code still reads. Long locks on hot tables. (Permission defaults on new columns → `data-lifecycle`.)

## Moves

- Build an invariant table: invariant · enforced where (DB constraint, transaction + lock, app code, nowhere) · every writer path.
- Build a constraint inventory from the replayed-migrations schema, then diff it against ORM models and against the invariants.
- For each money/counter/unique write path: transaction boundary, isolation level, lock or atomic statement, idempotency key, error handling.
- Race harness: start a local DB in the sandbox, seed dummy rows, open N connections, align them at a barrier just before the critical read, run the operation N times, then assert the invariant. Report the exact interleaving and final rows.
- Detector leads for this pack: `db.float-money`, `db.read-modify-write`, `db.get-or-create`, `db.timestamp-without-tz`, `db.prisma-email-not-unique`.

## Gate

1. State the invariant, every writer path, and where (if anywhere) it is enforced.
2. Concurrency claims: show the interleaving and the violated final state from a local multi-connection run, or (source-only) the exact statements and isolation level that permit it. The isolation level is a blocker if it is unknown.
3. Name who can trigger it (anonymous, any user, tenant admin, webhook sender) and what breaks for whom: money, other users' records, shared counters, or only the caller's own data.
4. Migration drift: cite the model line and the missing or different migration statement.
