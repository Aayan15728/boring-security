# Pack: Protocols, RPC and messaging

## When to use

gRPC, GraphQL (transport and resolvers), Protobuf/Thrift/Avro/Cap'n Proto/MessagePack, custom binary protocols, queues and brokers (Kafka, RabbitMQ, SQS, NATS, Redis streams), pub/sub, inbound and outbound webhooks, streaming RPC.

## Discipline

```text
- A message is only as trusted as the least-trusted principal able to publish it to that topic,
  queue or endpoint. Name that producer and the consumer action it triggers.
- Serialization defaults (unknown fields kept or dropped, missing → zero value, unknown enum →
  default) often differ from what consumers assume. Show the concrete bytes and both readings.
- Authentication on the transport (mTLS, broker credentials) and authorization of the message
  content are different controls. Check both, per method and per item.
- Broker ACLs and topic permissions usually live outside the repo; name them when decisive.
```

## Framing, schema, interpretation

**Message boundary and canonicalization disagreement**
Length prefixes vs delimiters, batching, compression, or two decoders reading the same bytes differently (e.g. a validating gateway and a consuming service).

**Union, enum and default confusion**
A missing field decoded as a dangerous default (`role = 0 = ADMIN`), unknown enum values mapped to a permissive branch, `oneof` cases ignored.

**Envelope and payload identity mismatch**
The envelope is authenticated or signed, but inner identity fields (user, tenant, sender) are trusted without being bound to it.

## RPC identity and authorization

**Interceptor and method-path inconsistency**
Auth interceptors skipped for some methods, reflection, health, streaming handlers, or GraphQL batched/aliased/persisted queries; path matching that differs between the interceptor and the router.

**Peer identity to application-principal confusion**
The mTLS peer or service account is mapped to the wrong app principal, or metadata headers override it.

**Per-item and streaming authorization gaps**
The first message is authorized and later stream items are not. GraphQL nested resolvers or batch items skip the object-level check the top-level query enforced.

**Callback and reply-correlation confusion**
Guessable correlation ids or shared reply queues let one client receive or answer another's replies.

## Brokers and queues

**Topic, routing-key and subscription scope gaps**
Wildcard subscriptions or routing keys reaching other tenants' topics; consumer groups shared across trust levels.

**Dead-letter, retry and diagnostic disclosure**
DLQs, retry topics or poison-message logs readable by broader principals than the original topic.

**Untrusted producer treated as control plane**
Consumers executing commands, config changes or code from messages that any producer on the topic can send.

## Webhooks

**Inbound webhook authenticity**
Signature not verified, verified over re-serialized JSON instead of raw bytes, compared with non-constant time, timestamp/replay window not enforced, or the shared secret accepted from the request.

**Outbound webhook target control**
User-configured callback URLs fetched server-side (SSRF; see `core-classes.md#Files, fetches and parsing`), including after redirects.

## Replay, ordering, transactions

**Duplicate delivery and idempotency gaps**
At-least-once delivery causing double credits, payments or grants without an idempotency key checked atomically.

**Out-of-order and stale message acceptance**
Older messages overwriting newer state; a delayed message re-granting revoked access.

**Acknowledgment and commit ordering**
Ack or offset commit before durable processing, or processing after a failed commit.

**Partial multi-consumer transitions**
One consumer applies a change and another fails, leaving an inconsistent security state.

## Moves

- For each topic/queue/RPC method: producers, consumers, transport auth, message-level authz, schema, delivery semantics.
- Feed crafted messages through the consumer function in a unit test, or through a broker started only for the test inside the sandbox.

## Gate

1. Name the lowest-trust producer able to send the message, and the consumer action it causes.
2. Parsing disagreements: show the bytes and both interpretations.
