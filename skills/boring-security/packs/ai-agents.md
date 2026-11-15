# Pack: AI, LLM and agents

## When to use

Model output can influence an action, a stored state or a rendering: chatbots, RAG, long-term memory, tool-calling agents, MCP servers and clients, sub-agent orchestration, prompt assembly, code-executing assistants.

## Discipline

```text
- Prompt injection alone is not a finding; assume the model will sometimes obey injected text. The
  finding is a code-level boundary failure: content from principal X reaches another principal's
  context, invokes authority X lacks, discloses data X can't read, or drives a sink X can't reach.
- Model output, retrieved documents, memory, tool results, tool descriptions and MCP responses are
  untrusted input. Point to the code that grants authority, trusts output, persists state or feeds
  a sink.
- A system prompt or guardrail instruction is not a security boundary. Count only deterministic
  checks: per-principal tool allowlists, argument validation in code, resource-scoped authorization
  against the END user, isolation, constrained credentials, confirmation bound to the exact action.
- State the attacker, the affected principal, the effective execution identity, the resource, the
  exact action, the authority used, and the observable impact.
- Authorization and action binding are separate controls. When attacker content makes the agent act
  under a victim's valid authority on something the victim never requested or approved, that is an
  action-binding failure even though authorization passed. A user directly asking the agent to use
  their own authority is not a delegation defect.
- Validate the plumbing with a stub model that returns the attacker-chosen output or tool call.
  Never depend on real model behaviour or spend real model quota.
```

## Context, retrieval and memory

**Indirect injection through ingested content**
Web pages, emails, documents, tickets, PR text, search results, file names, image text or tool output written by X enter the context of an agent acting for Y with tools Y can use.

**Cross-session or cross-tenant context bleed**
Conversation stores, caches, vector indexes or memories keyed without user/tenant scope; retrieval ACLs applied after similarity search, or not at all; shared prompt caches carrying another user's data.

**Persistent memory poisoning**
Content written into long-term memory or a shared knowledge base by X that later steers Y's sessions or actions.

**Prompt role and provenance confusion**
User or tool text spliced into system/developer roles. Delimiter injection breaking the template. Tool results treated as instructions. Provenance lost when content is summarized or stored.

## Tools and actions

**Tool-argument injection into a sink**
Model-chosen arguments reach SQL, shell, file paths, URLs (SSRF), code execution, templates or other APIs without the validation a normal endpoint would apply.

**Excessive agency and confused deputy**
Tools run with a service credential instead of the end user's. One user's agent can touch another user's resources. Destructive or outbound tools (delete, send, pay, publish) have no scope limit.

**Action-confirmation binding**
Approval shows one action and executes another: arguments change after approval, approval is reused for a later call, or the summary hides parameters.

**Tool-schema and dispatcher disagreement**
The schema declares enum/pattern/required, but the dispatcher doesn't enforce it, accepts extra properties, or coerces types.

**Unbounded delegated loops**
Agent loops, recursive sub-agents or retries triggerable by an outsider and consuming operator money or quota (→ `availability`).

## MCP and sub-agents

**Sub-agent and MCP trust inheritance**
Sub-agents or MCP tools inherit the parent's full credentials, filesystem or network when they need less.

**MCP server and tool identity confusion**
Tool-name collisions or shadowing across servers. Definitions changed after the user approved them. Unauthenticated local MCP transports reachable from browsers (DNS rebinding, missing Origin checks).

**MCP metadata as policy**
Descriptions or annotations ("read-only", `destructiveHint: false`) used to make authorization decisions.

## Output and disclosure

**Insecure output rendering**
Model output rendered as HTML/Markdown with live images or links (exfiltration via URL), executed as code, or inserted into queries or shells without encoding.

**Sensitive context extraction**
Secrets, credentials or other users' data placed into a context a lower-privileged user can query. A non-secret system prompt being extractable is informational at most.

## Moves

- Inventory every tool: name, schema, enforcing code, credential used, side effects, who can trigger the agent.
- Inventory every context source with its author principal and its storage scope.
- Build a harness with a stub model returning the hostile output; assert what the dispatcher, store and renderer do.

## Gate

1. Name the content author, the victim principal, the execution identity, and the tool or sink reached.
2. Show the code path with a stubbed model. "The model might…" is not evidence.
3. Provider-side filtering or model behaviour is the blocker only if the code path otherwise holds.
