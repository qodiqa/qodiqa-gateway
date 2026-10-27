# Tool gateway: security model and limits

> Code: `src/api/routes/tools.js` (`POST /v1/tools/call`), `src/api/routes/mcpServers.js`, `src/core/mcp/` (`serverUrl`, `mcpClient`, `mcpRegistry`, `toolPolicy`,
> `resultScreen`, `revocationWatch`), migration 105. API: `docs/api/overview.md` ("`/v1/mcp/servers` and `POST /v1/tools/call`").

**What is claimed.** Cryptographic authorisation for tool calls sent through the QODIQA gateway to **registered MCP servers over HTTP**: every call is bound to an
action artifact (`actionHash`, V2-FREEZE section 5), re-derived from the call that is actually made, consumed once and in order, and recorded. **Nothing broader**: this is not
"MCP security" in general, it does not secure an MCP server, and it does not make a tool's output trustworthy.

## What the gateway does and does not do

| It does | It does not |
|---|---|
| Call only servers registered by an operator, over http(s), through a connection that is checked again on the resolved address, pinned to the server's key, never redirected | Start processes, speak stdio, run local commands, or load code |
| Refuse a call whose artifact, arguments, schema, tool, policy, delegation or agent/session no longer match, before the server sees anything | Inspect what the MCP server does with the call: sandboxing the server (symlinks, SQL privileges, file permissions) is the server's and the operator's job |
| Treat every result as untrusted data: screen it (and its decoded forms), withhold what it cannot inspect, mark provenance, separate it structurally | Prove a result is true, or catch every injection: the checks are conservative text rules plus the semantic gates, one layer of several |
| Stop a call in flight when its tool, server, delegation or session is revoked (this process at once, other replicas about a second later) | Guarantee a third-party server stops *its own* work: the connection is dropped, the server may finish |
| Record the call: ledger row, `ACTION_INTENT` / `ACTION_COMMIT` under audit schema v8, a receipt bound to the delivered output hash | Sign the receipt: that needs a new domain tag |

## Threats and where they are met

* **SSRF through a registered URL** - validated at registration (`validateMcpServerUrl`) and again at every connection on the resolved address (`createMcpAgent`: DNS rebinding, IP literals, redirects). Local destinations exist only with `QODIQA_MCP_ALLOW_LOCAL=true`, never in production.
* **A server that is not the server** - https requires a pinned public key; the pin replaces or complements CA validation (`trust: "pin-only" | "ca-and-pin"`); a `configHash` over URL + identity is recomputed on every call and refuses a row whose URL or identity no longer matches it. It is an UNKEYED SHA-256 stored in the same row, so it catches accidental or partial edits, not an attacker who can write the row and recompute the hash; the database role that can write the table is the real boundary.
* **Confused deputy / changed arguments / replay / reordering / schema swap** - the executor re-derives `actionHash` from this very call (`ACTION_MISMATCH`), checks order and consumes the artifact atomically (`ACTION_REPLAY`, `ACTION_ORDER_VIOLATION`), and compares the tool's CURRENT schema (`TOOL_SCHEMA_CHANGED`).
* **A tool announced by a server** - announcing is not authorising: discovery creates `pending_review` proposals; an operator approves them (the registrant of a changed definition cannot).
* **A tool used for more than it should** - default-deny constraints for `file`, `database`, `external_api`, `command`; enforced at authorisation and at the gateway with the policy in force then.
* **Prompt injection through results** - screening of the text and its transformations, instruction-conflict rules, the semantic gates, withholding of non-text content, provenance marking, a delimiter that cannot be forged from inside the data.
* **A compromised tool or server** - disabling takes effect on the next call everywhere and aborts calls in flight; the store is read at every call (no cache), and a one-second watcher closes the gap for calls already running on other replicas.
* **A runaway or hostile server** - bounded time (`QODIQA_TOOL_CALL_TIMEOUT_MS`, default 30 s) and size (`QODIQA_TOOL_MAX_RESPONSE_BYTES`, default 1 MiB); a server request to the client (sampling, roots, elicitation) is refused.

## Known limits (stated, not hidden)

1. Result screening is heuristic. A determined attacker can phrase around the rules; the semantic gates and the structural separation are the other layers. `policy.resultScreening: "strict"` blocks medium-severity findings too.
2. Path / SQL / command / URL constraints are text checks at the proxy. They cannot resolve symlinks, database roles or shell semantics.
3. A revocation reaches a call in flight on another replica within the watcher interval (default 1 s) **plus** the store latency; if the store is unavailable the watcher does not abort (bounded by the call timeout and the kill switch).
4. Tools that require approval (irreversible tools by default) are called only with a human approval bound to the exact action; an approval cancelled after the artifact exists stops the execution and leaves the session waiting for it - open a new session.
5. The receipt is a ledger record, not a signed statement.
6. Streaming results and MCP server-initiated requests are not supported.
