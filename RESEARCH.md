# The published agent surface: what 710 advertised MCP tools actually expose

**Maobyte Innovations Ltd (trading as Mainno) — September 2026**

This is a measurement of the *publicly advertised* MCP surface: what servers tell the world
they can do. Every number below was produced by the read-only scanner in this repository,
against endpoints that answered `tools/list` without authentication.

No server is named in this document. Individual findings are not published here — a public
manifest is not an invitation to publish weaknesses. Aggregate patterns are.

## Method

1. Enumerated a public MCP registry and de-duplicated to **204 unique public servers**,
   spanning 151 organisations, of which **168 expose a hosted (HTTP/SSE) endpoint**.
2. Probed those 168 endpoints with a `tools/list` call only. **68 answered without
   authentication.** The remainder were unreachable, stdio-only, or returned 401/403 —
   an auth-gated server is not a finding, it is correct.
3. Classified all **710** advertised tools by capability, matching on **tool name first**
   and description second.

Nothing was invoked. No payload was sent. No authentication was attempted.

## Headline numbers

Across 68 publicly reachable servers advertising 710 tools:

- **read** — 354 (49.9%)
- **write** — 123 (17.3%)
- **financial** — 90 (12.7%)
- **destructive** — 52 (7.3%)
- **credential** — 21 (3.0%)
- **execute** — 13 (1.8%)
- uncategorised — 57 (8.0%)

**22 of the 68 servers (32%)** advertise at least one tool whose *name* indicates a
high-consequence capability — destructive, execute, credential, or financial.

**20 of the 68 (29%)** advertise tools whose names or descriptions reference sensitive data
domains: banking, wallets, credentials, identity documents, patient or medical data.

## The three findings that matter

### 1. Half the advertised surface is read-only — which makes the other half the story

49.9% of tools are read operations. That is expected: MCP is mostly used to give agents
context. But it means the destructive and credential classes are a *minority that is easy
to overlook* — 7.3% and 3.0% respectively. An integration review that skims a tool list
will not notice three tools out of a hundred.

The risk is not proportional to the count. One `delete_*` tool that an agent can reach is
worth more attention than fifty `get_*` tools.

### 2. A third of public agent surfaces carry a high-consequence tool by name

32% ship at least one. Combined with the fact that these servers answered anonymously,
this describes a default where **an agent can be pointed at a public endpoint and handed
destructive authority without any authentication on the surface itself.**

Authentication on the *server* and authorisation to *invoke a specific tool* are different
controls. Many implementations have the first and not the second.

### 3. Names are evidence; descriptions are noise

The most transferable lesson from this work is methodological. Matching on tool
descriptions produced false positives severe enough to make the output unusable: the
token `card` matched "encyclopaedia card" on a documentation site and flagged it as a
financial surface; `fund` matched ordinary marketing prose.

Matching on *names* produced almost no false positives. Tool names are authored by
developers describing function, not by marketers describing value.

There is a trap here worth publishing because it silently breaks naive implementations:
underscore is a word character in regular expressions, so `\bdelete\b` does **not** match
`betterpost_delete_content`, `auteng_docs_delete`, or `delete_list` — precisely the names
that carry the signal. Detection built on `\b` boundaries misses the namespaced tool names
that are the norm in MCP. Fixing this one detail took a real corpus from 13 leads to 22.

## A lead is not a finding

Of the 22 name-matched leads, manual review rejected most of them. They were:

- **price and quote lookups** (`get_price`, `request_quote`, `find_transfer_routes`) —
  reading prices, not moving money
- **public key retrieval** (`get_public_key`) — a public key is supposed to be public
- **payment-instruction lookup** (`how_to_pay`) — documentation, not capability
- **self-revocation** (`auth_revoke_self`) — an agent revoking its own credentials is
  correct security practice

Every one of those matched a keyword. None was a weakness. Anyone publishing counts of
"dangerous tools" without this step is publishing noise.

## What we do not claim

- This measures **advertised capability**, not vulnerability. It does not show that any
  tool is exploitable.
- Capability classes are heuristic. A `delete_*` tool may delete a saved search.
- We did not authenticate, so nothing here speaks to authorisation correctness — only to
  what is advertised to an anonymous caller.
- The sample is public registry servers; it is not a census of all MCP deployments, and
  the large majority of enterprise MCP servers are internal and unmeasured here.

## Why publish this

Agent security has a migration problem: teams adopt agent frameworks faster than they
adopt a model for what an agent is allowed to do. The manifest — the actual list of
authority an agent receives — is the one artifact that is cheap to read, and almost
nobody reads it after integration day.

The tool is MIT-licensed. Point it at your own servers.

**Maobyte Innovations Ltd (trading as Mainno)** — MCP and AI-agent surface review.
