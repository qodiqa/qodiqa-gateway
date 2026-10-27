
(function(){
"use strict";

// shared infrastructure lives in public/js/common/ (see that
// directory for the canonical implementation).
var esc = window.QodiqaCommon.esc;

/* ===================== Deterministic reference-evidence helpers (local generation only) ===================== */
function strSeed(s){ let h=1779033703^s.length; for(let i=0;i<s.length;i++){ h=Math.imul(h^s.charCodeAt(i),3432918353); h=h<<13|h>>>19; } return function(){ h=Math.imul(h^(h>>>16),2246822507); h=Math.imul(h^(h>>>13),3266489909); h^=h>>>16; return (h>>>0); }; }
function mulberry(seedNum){ let a=seedNum>>>0; return function(){ a|=0; a=a+0x6D2B79F5|0; let t=Math.imul(a^a>>>15,1|a); t=t+Math.imul(t^t>>>7,61|t)^t; return ((t^t>>>14)>>>0)/4294967296; }; }
function rngFor(seedStr){ const s=strSeed(String(seedStr))(); return mulberry(s); }
function hexN(seedStr,n){ const r=rngFor(seedStr); let out=""; const chars="0123456789abcdef"; for(let i=0;i<n;i++) out+=chars[Math.floor(r()*16)]; return out; }
const B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64N(seedStr,n,pad){ const r=rngFor(seedStr); let out=""; for(let i=0;i<n;i++) out+=B64[Math.floor(r()*64)]; return out+(pad||""); }
function uuidLike(seedStr){ const h=hexN(seedStr,32); return h.slice(0,8)+"-"+h.slice(8,12)+"-4"+h.slice(13,16)+"-"+"89ab"[Math.floor(rngFor(seedStr+"v")()*4)]+h.slice(17,20)+"-"+h.slice(20,32); }
function fingerprint(seedStr){ const h=hexN(seedStr,32); return h.match(/.{4}/g).join(":"); }
function copyToClipboard(text,btn){
  const done=()=>{ if(btn){ const old=btn.innerHTML; btn.innerHTML='<svg viewBox="0 0 24 24" fill="none"><use href="#i-check"/></svg>'; setTimeout(()=>btn.innerHTML=old,900);} };
  if(navigator.clipboard && window.isSecureContext){ navigator.clipboard.writeText(text).then(done).catch(()=>fallbackCopy(text,done)); }
  else fallbackCopy(text,done);
}
function fallbackCopy(text,cb){ const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.opacity="0"; document.body.appendChild(ta); ta.select(); try{document.execCommand("copy");}catch(e){} document.body.removeChild(ta); cb&&cb(); }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
function icon(name){ return '<svg viewBox="0 0 24 24" fill="none"><use href="#i-'+name+'"/></svg>'; }
function activateOnEnterSpace(e){ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); e.currentTarget.click(); } }

/* ===================== Data model ===================== */
const PIPELINE_STAGES = [
  {key:"request", title:"Request", module:"Load Balancer · /ready gate", desc:"An external client issues an HTTP request to an enforced route (POST /ai/chat, /ai/chat/stream, or their /v1 equivalents). The load balancer's /ready gate has already confirmed the target instance is healthy before traffic reaches it."},
  {key:"canonical", title:"Canonicalization", module:"fast-json-stable-stringify", desc:"The request and policy objects are canonicalized into a stable, key-order-independent form so that identical logical requests always hash identically, and any semantic change produces a different digest."},
  {key:"artifact", title:"Artifact Creation", module:"POST /sign", desc:"A signing authority issues a signed artifact envelope — { expiry, payload, publicKeyId, timestamp } — scoped to the exact HTTP method, path and body of the intended request."},
  {key:"hash", title:"Hash Generation", module:"SHA-256, domain-separated", desc:"requestHash = SHA-256(\"QODIQA::REQUEST::V1\" || method+path+body). policyHash binds the active policy set at signing time. Domain-separation prefixes prevent cross-protocol hash collisions."},
  {key:"signature", title:"Signature", module:"Ed25519", desc:"The full artifact envelope is signed with Ed25519 over \"QODIQA::ARTIFACT::V1\" || stableStringify({expiry, payload, publicKeyId, timestamp}). Tampering with any field invalidates the signature."},
  {key:"replay", title:"Replay Check", module:"Redis SET NX PX", desc:"registerNonce() atomically registers the artifact's unique requestId in Redis. A collision returns REPLAY_DETECTED immediately — even from a different IP address."},
  {key:"consent", title:"Consent Verification", module:"Runtime Consent Registry", desc:"A PostgreSQL-backed consent registry, cached in Redis, resolves whether the request's tenant currently holds valid, unrevoked, unexpired consent for the requested scope."},
  {key:"policy", title:"Policy Evaluation", module:"services/policy/engine.js", desc:"REQUIRE_CONSENT, BLOCK_IP, TIME_WINDOW and RATE_LIMIT evaluators run in order. The first BLOCK wins. Any evaluator error fails the request closed rather than open."},
  {key:"invariant", title:"Execution Invariant", module:"assertExecutionInvariant()", desc:"A synchronous guard throws before any provider call can occur unless every prior stage explicitly returned ALLOW. There is no code path around it."},
  {key:"transparency", title:"Transparency Log", module:"RFC6962-style Merkle tree", desc:"The decision is appended as a leaf to an append-only Merkle tree. A periodically signed root checkpoint makes the log independently auditable via inclusion and consistency proofs."},
  {key:"audit", title:"Audit Persistence", module:"appendMandatory()", desc:"The decision is written to a hash-chained NDJSON audit log with write-ahead-log crash protection before the response is considered final. A write failure fails the request closed."},
  {key:"provider", title:"Provider Execution", module:"routeProviderCall()", desc:"The request is dispatched to the provider named in the artifact through an SSRF-protected, allowlisted client, with automatic failover to a configured backup provider on a retryable error."},
  {key:"evidence", title:"Response Evidence", module:"Evidence chain", desc:"A cryptographic evidence record binds the response to the originating artifact, audit entry and transparency leaf — a portable proof of what executed and why it was authorized."},
  {key:"verified", title:"Verified Completion", module:"decision: EXECUTE", desc:"The caller receives the AI response together with decision: EXECUTE. Every claim in that response is independently checkable — nothing here has to be taken on faith."}
];

const EVIDENCE_GROUPS = [
  {key:"identity", title:"Identity & Binding", readyAt:1, fields:["Artifact ID","Execution ID","Tenant ID","Nonce","Timestamp","TTL (ms)"]},
  {key:"crypto", title:"Cryptographic Proof", readyAt:5, fields:["Request Hash","Policy Hash","Envelope Hash","Artifact Hash","Ed25519 Signature","Public Key","Key Fingerprint","Signature Verification"]},
  {key:"consent", title:"Consent & Policy", readyAt:8, fields:["Replay Verification","Consent Status","Policy Decision"]},
  {key:"transparency", title:"Transparency & Audit", readyAt:11, fields:["Audit Chain","Merkle Root","Transparency Entry","Inclusion Proof","Consistency Proof","Chain Validation"]}
];

function buildEvidence(seed, overrides){
  const e = {
    "Artifact ID": uuidLike(seed+"artifact"),
    "Execution ID": uuidLike(seed+"exec"),
    "Tenant ID": overrides.tenant,
    "Request Hash": hexN(seed+"reqhash",64),
    "Policy Hash": hexN(seed+"polhash",64),
    "Envelope Hash": hexN(seed+"envhash",64),
    "Artifact Hash": hexN(seed+"arthash",64),
    "Ed25519 Signature": b64N(seed+"sig",86,"=="),
    "Public Key": b64N(seed+"pub",43,"="),
    "Key Fingerprint": fingerprint(seed+"fp"),
    "Nonce": uuidLike(seed+"nonce"),
    "Timestamp": overrides.timestamp,
    "TTL (ms)": overrides.ttl || "300000",
    "Signature Verification": overrides.decision==="EXECUTE" || overrides.stoppedAt>5 ? "VALID" : "NOT EVALUATED",
    "Replay Verification": overrides.stoppedAt>=6 ? "NO COLLISION" : "NOT EVALUATED",
    "Consent Status": overrides.consentStatus || (overrides.stoppedAt>=7 ? "GRANTED" : "NOT EVALUATED"),
    "Policy Decision": overrides.stoppedAt>=8 ? (overrides.decision==="EXECUTE"?"ALLOW":"BLOCK") : "NOT EVALUATED",
    "Audit Chain": overrides.stoppedAt>=11 ? "APPENDED · hash-linked" : "PENDING",
    "Merkle Root": hexN(seed+"merkle",64),
    "Transparency Entry": overrides.stoppedAt>=10 ? "#"+ (10000+Math.floor(rngFor(seed+"leaf")()*89999)) : "NOT LOGGED",
    "Inclusion Proof": overrides.stoppedAt>=10 ? hexN(seed+"incl",16)+"…"+hexN(seed+"incl2",16) : "N/A",
    "Consistency Proof": overrides.stoppedAt>=10 ? hexN(seed+"cons",16)+"…"+hexN(seed+"cons2",16) : "N/A",
    "Chain Validation": overrides.stoppedAt>=11 ? "OK" : "N/A"
  };
  return e;
}
function computeTimings(seed){
  const r = rngFor(seed+"timing"); let cum=0; const arr=[];
  for(let i=0;i<14;i++){ const d=1+Math.floor(r()*6); cum+=d; arr.push(cum); }
  return arr;
}

const SAMPLE_EXECUTIONS = [
  {id:"exec_8f21ac2d", decision:"EXECUTE", reason:"All 14 checkpoints passed", provider:"anthropic", tenant:"acmecorp-prod", stoppedAt:14, timestamp:"2026-07-13T09:14:02.118Z"},
  {id:"exec_3d90e7b1", decision:"BLOCK", reason:"POLICY_DENIED · RATE_LIMIT exceeded", provider:"openai", tenant:"acmecorp-prod", stoppedAt:8, timestamp:"2026-07-13T09:11:47.902Z"},
  {id:"exec_c114bb4e", decision:"BLOCK", reason:"REPLAY_DETECTED · requestId already registered", provider:"openai", tenant:"globex-staging", stoppedAt:6, timestamp:"2026-07-13T08:58:30.441Z"},
  {id:"exec_5aa1029f", decision:"BLOCK", reason:"CONSENT_EXPIRED", provider:"gemini", tenant:"initech-dev", stoppedAt:7, timestamp:"2026-07-13T08:40:11.660Z", consentStatus:"EXPIRED"}
].map(e => Object.assign(e, {evidence: buildEvidence(e.id, e), timings: computeTimings(e.id)}));

const SUBSYSTEMS = [
  {id:"execution-verification", name:"Execution Verification", ref:"src/core/enforcement/", desc:"Validates every artifact's Ed25519 signature, schema, expiry and 60-second clock-skew tolerance before a request is allowed to proceed.", long:"validateArtifact() is the first gate in the enforcement chain. It checks signature validity, payload schema, expiry, and clock skew (max 60s backward, zero tolerance forward) before anything else runs. Any failure produces a BLOCK decision and the AI provider is never reached."},
  {id:"policy-engine", name:"Policy Engine", ref:"services/policy/engine.js", desc:"Evaluates REQUIRE_CONSENT, BLOCK_IP, TIME_WINDOW and RATE_LIMIT on every request. First BLOCK wins; every error path fails closed.", long:"The production policy engine loaded by server.js. REQUIRE_CONSENT is mandatory — the loader rejects any policy set without it. BLOCK_IP supports exact and CIDR matching including IPv6. TIME_WINDOW evaluates UTC day-of-week and time-of-day. RATE_LIMIT is a Redis-backed tumbling window per userId or IP."},
  {id:"consent", name:"Consent Management", ref:"src/core/consent/", desc:"Runtime Consent Registry backed by PostgreSQL with a Redis cache layer — grants, suspensions, revocations and expiry are all live, not static.", long:"Consent decisions are resolved by the Runtime Consent Registry, replacing any static or hardcoded consent table. Revocation is propagated via a pub/sub subscriber; if that subscriber fails to start, server startup halts rather than running with stale consent state."},
  {id:"replay", name:"Replay Protection", ref:"Redis SET NX PX", desc:"Each artifact's unique requestId is atomically registered exactly once. A collision is rejected as REPLAY_DETECTED, even from a different IP.", long:"registerNonce() uses Redis SET NX PX so registration and expiry are a single atomic operation. The nonce key expires when the artifact itself expires. When Redis is unavailable, replay protection fails closed rather than allowing unchecked execution."},
  {id:"key-mgmt", name:"Key Management", ref:"src/infra/keys/", desc:"Pluggable KMS backends — local, Vault KV/Transit, AWS/Azure/GCP KMS, or PKCS#11 HSM — with automatic scheduled key rotation.", long:"rotateKey() creates a new active Ed25519 key pair and marks the previous key deprecated; deprecated keys remain valid for verification for a 180-day retention window. An automatic rotation scheduler handles cadence without operator action, using a Redis-backed distributed lock in multi-instance deployments."},
  {id:"transparency", name:"Transparency Log", ref:"src/core/transparency/", desc:"An RFC6962-style Merkle tree over audit entries with periodically signed root checkpoints, supporting inclusion and consistency proofs.", long:"A distinct component from the file-based audit chain, active when QODIQA_PG_ENABLED=true. Inclusion proofs let anyone verify a specific decision was recorded; consistency proofs let anyone verify the log was only ever appended to, never rewritten."},
  {id:"audit", name:"Immutable Audit", ref:"src/core/audit/audit-log.js", desc:"Hash-chained NDJSON audit log with write-ahead-log crash protection — always active, independent of any optional backend.", long:"Every ALLOW and BLOCK decision is durably recorded before a response is considered final. appendMandatory() retries transient filesystem failures a bounded number of times; if it still cannot write, the ALLOW path fails closed with 503 AUDIT_PERSISTENCE_FAILED rather than reporting success with unrecorded evidence."},
  {id:"gateway", name:"AI Gateway", ref:"services/providers/router.js", desc:"Dispatches to OpenAI, Anthropic, Gemini, Mistral, Llama-compatible or local runtimes — with SSRF-protected allowlisting and automatic failover.", long:"routeProviderCall() selects the provider named in the artifact's payload. Public providers are pinned to a hardcoded HTTPS hostname allowlist that cannot be overridden by environment variable. Self-hosted providers (llama, local) use a deliberately relaxed validator for operator-controlled infrastructure."},
  {id:"crypto", name:"Cryptography", ref:"Ed25519 / AES-256-GCM / SHA-256", desc:"Ed25519 signing, AES-256-GCM encryption at rest, and domain-separated SHA-256 hashing across every subsystem.", long:"Domain separation constants — QODIQA::CANONICAL::V1, QODIQA::ARTIFACT::V1, QODIQA::REQUEST::V1, QODIQA::POLICY::V1, QODIQA::AUDIT::V1, QODIQA::TRANSPARENCY::V1 and others — ensure a hash computed for one purpose can never be mistaken for a hash computed for another."},
  {id:"tenancy", name:"Multi-Tenancy", ref:"src/core/tenancy/, src/core/organizations/", desc:"Tenant and organization isolation with per-tenant quotas — requests per minute, streaming session limits, retention windows.", long:"Administered via /v1/admin/tenants and /v1/admin/organizations. Every artifact carries a tenantId derived from the signing key, not the raw client-supplied identifier, so tenant boundaries cannot be spoofed by request payload alone."},
  {id:"observability", name:"Observability", ref:"/metrics, /diagnostics", desc:"Prometheus-format metrics and operational diagnostics, gated behind an ops token.", long:"GET /metrics exposes Prometheus-format counters and histograms for enforcement decisions, latency and subsystem health. GET /diagnostics surfaces deeper operational state for incident response."},
  {id:"dr", name:"Disaster Recovery", ref:"scripts/dr/", desc:"Documented, tested backup, restore and validation cycles for keys, audit chain and policy state.", long:"npm run dr:backup, dr:restore, dr:validate and dr:cycle drive a repeatable disaster-recovery loop."},
  {id:"sdks", name:"SDKs", ref:"sdk/javascript, sdk/python", desc:"Maintained JavaScript/TypeScript (@qodiqa/sdk) and Python (qodiqa) client libraries.", long:"Both SDKs wrap artifact signing and enforced-route calls behind a small client surface."},
  {id:"docs", name:"Documentation", ref:"docs/, *.md", desc:"Architecture, security, compliance and operations documentation spanning threat models, ASVS/OWASP/MITRE mappings and runbooks.", long:"Includes docs/glossary.md, docs/architecture/overview.md, docs/architecture/enforcement-flow.md, the full docs/security/ and docs/compliance/ trees (STRIDE, MITRE ATT&CK, GDPR, SOC 2, ISO 27001, EU AI Act, NIST AI RMF) and per-scenario operations runbooks."},
  {id:"rbac", name:"RBAC", ref:"src/core/rbac/", desc:"Role-based access control gating every administrative and audit-facing route — unconditionally enforced, no disable path.", long:"Permissions include READ_AUDIT, MANAGE_KEYS, MANAGE_CONSENT, MANAGE_POLICIES, GENERATE_EVIDENCE, READ_EVIDENCE_CHAIN and MANAGE_USERS."}
];

const SECURITY_CAPS = [
  {name:"Replay Protection", desc:"Every artifact's requestId is registered exactly once via an atomic Redis SET NX PX. Duplicate submission is rejected as REPLAY_DETECTED even across different source IPs, and the guarantee survives a server restart when Redis persists."},
  {name:"Immutable Audit", desc:"Hash-chained NDJSON with write-ahead-log crash protection. Each entry's prevHash equals the hash of the one before it; a companion .sum file guards against silent truncation."},
  {name:"Ed25519", desc:"Every artifact envelope is signed and verified with Ed25519. Verification never throws on malformed input — it returns a definitive INVALID rather than crashing the request path."},
  {name:"Merkle Trees", desc:"An RFC6962-style transparency log lets any party generate or check an inclusion proof (this entry is in the log) or a consistency proof (the log was only ever appended to) without trusting the operator."},
  {name:"Consent Enforcement", desc:"REQUIRE_CONSENT is a mandatory policy — the loader refuses to start with any policy set that omits it. Revoked, expired or missing consent is enforced at verification time, not just at issuance."},
  {name:"Policy Enforcement", desc:"IP allow/block lists, time-of-day windows, and Redis-backed rate limits are evaluated on every request, with the first BLOCK winning and every evaluator error failing closed."},
  {name:"RBAC", desc:"Administrative and audit-facing routes are gated by role-based permissions with no disable flag — enforcement is unconditional by design, not by configuration."},
  {name:"Tenant Isolation", desc:"tenantId is derived from the signing key, not the raw client-supplied identifier, so one tenant cannot forge membership in another by manipulating request payloads."},
  {name:"Environment Validation", desc:"Four environment variables plus at least one provider credential are mandatory at startup. Placeholder or missing values halt startup with a FATAL reason before the process ever binds a port."},
  {name:"Fail Closed", desc:"When Redis is unavailable, all execution requests are blocked — there is no degraded-but-open fallback. /ready returns 503 and the load balancer removes the instance from rotation."},
  {name:"Cryptographic Evidence", desc:"Every decision produces a portable evidence record binding the response to its artifact, audit entry and transparency leaf — independently verifiable, not merely logged."}
];

const PROVIDERS = [
  {name:"OpenAI", env:"OPENAI_API_KEY", cls:"Public API", note:"Hardcoded HTTPS allowlist (api.openai.com) — base URL cannot be overridden by environment variable."},
  {name:"Anthropic", env:"ANTHROPIC_API_KEY", cls:"Public API", note:"Hardcoded HTTPS allowlist (api.anthropic.com) — base URL cannot be overridden by environment variable."},
  {name:"Google Gemini", env:"GEMINI_API_KEY", cls:"Public API", note:"Hardcoded HTTPS allowlist (generativelanguage.googleapis.com)."},
  {name:"Mistral", env:"MISTRAL_API_KEY", cls:"Public API", note:"Defaults to api.mistral.ai/v1 — the one public provider whose base URL can be overridden, and only if the override still passes the allowlist."},
  {name:"Llama-compatible", env:"LLAMA_BASE_URL", cls:"Self-hosted", note:"Cloud-hosted (Groq, Together AI, Fireworks) or self-managed — relaxed SSRF policy for operator-controlled infrastructure."},
  {name:"Local Runtime", env:"LOCAL_BASE_URL", cls:"Self-hosted", note:"Ollama, llama.cpp, LM Studio or any OpenAI-compatible local runtime — relaxed SSRF policy."}
];

const DEV_RESOURCES = [
  {name:"API Reference", path:"docs/api/overview.md", desc:"Complete HTTP API reference including versioned /v1/* equivalents and admin-only routes."},
  {name:"JavaScript SDK", path:"sdk/javascript (npm: @qodiqa/sdk)", desc:"TypeScript client for signing artifacts and calling enforced routes."},
  {name:"Python SDK", path:"sdk/python (pip: qodiqa)", desc:"Python client with the same signing and enforcement-call surface as the JS SDK."},
  {name:"Protocol Specification", path:"QODIQA-PROTOCOL-SPEC.md", desc:"The normative artifact JSON Schema and protocol-level definitions."},
  {name:"Architecture Overview", path:"docs/architecture/overview.md", desc:"Component topology, enforcement pipeline and key management in depth."},
  {name:"Quick Start", path:"docs/guides/quickstart.md", desc:"Setup and first run, including the development bootstrap script."},
  {name:"Glossary", path:"docs/glossary.md", desc:"Definitions of every QODIQA concept used across the documentation set."}
];

const ENDPOINTS = [
  ["POST","/sign","Issue a signed artifact for a request"],
  ["POST","/ai/chat","Execute AI chat with full enforcement"],
  ["POST","/ai/chat/stream","Streaming variant of /ai/chat"],
  ["POST","/verify/v2","Dry-run enforcement check — no execution, no nonce registration"],
  ["GET","/audit/:artifactId","Look up audit entry and chain integrity for an artifact"],
  ["GET","/audit/chain/integrity","Verify hash-chain integrity"],
  ["GET","/health","Liveness probe"],
  ["GET","/ready","Readiness probe — 503 when Redis unavailable or shutting down"],
  ["GET","/metrics","Prometheus metrics"],
  ["GET","/public-key","Active Ed25519 public key"],
  ["GET","/.well-known/qodiqa/keys","Active and deprecated public keys"]
];

const STATUS_ITEMS = [
  {name:"System Health", sub:"/health · /ready", state:"unknown", live:"__ready"},
  {name:"Execution Trust", sub:"Fail-closed enforcement (readiness gate)", state:"unknown", live:"__ready"},
  {name:"Transparency", sub:"Merkle log · requires QODIQA_PG_ENABLED", state:"optional"},
  {name:"Audit", sub:"Hash-chained audit log", state:"unknown", live:"auditPersistence"},
  {name:"Policy Engine", sub:"services/policy/engine.js", state:"ok"},
  {name:"Consent Engine", sub:"PostgreSQL + Redis cache", state:"unknown", live:"consentSubscriber"},
  {name:"Replay Protection", sub:"Redis SET NX PX", state:"unknown", live:"nonceStore"},
  {name:"Cryptography", sub:"Ed25519 · AES-256-GCM · SHA-256", state:"ok"},
  {name:"AI Gateway", sub:"6 providers registered", state:"ok"},
  {name:"Key Management", sub:"Pluggable KMS backends", state:"ok"},
  {name:"Database", sub:"PostgreSQL — enable via QODIQA_PG_ENABLED", state:"unknown", live:"persistenceStore"},
  {name:"Redis", sub:"Nonce, rate-limit, consent cache", state:"unknown", live:"rateLimitStore"},
  {name:"Provider Connectivity", sub:"Awaiting provider credentials in this environment", state:"config"}
];

const METRICS = [
  {value:"15", label:"Core Subsystems"},
  {value:"100+", label:"Implemented Capabilities"},
  {value:"Ed25519", label:"Cryptography"},
  {value:"Merkle", label:"Transparency"},
  {value:"Fail Closed", label:"Architecture"},
  {value:"Verified", label:"Execution Trust"}
];

/* ===================== Verdict stamp ===================== */
function stampSVG(decision, size){
  const ok = decision==="EXECUTE";
  const inner = ok
    ? '<path class="stamp-check" d="M32 62 L52 80 L92 38" fill="none" stroke="currentColor" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>'
    : '<path class="stamp-x1" d="M42 42 L82 82" fill="none" stroke="currentColor" stroke-width="8" stroke-linecap="round"/><path class="stamp-x2" d="M82 42 L42 82" fill="none" stroke="currentColor" stroke-width="8" stroke-linecap="round"/>';
  return `<svg class="stamp-svg ${ok?'stamp-ok':'stamp-block'}" viewBox="0 0 124 124" style="${size?('width:'+size+'px;height:'+size+'px'):''}">
    <circle cx="62" cy="62" r="54" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="2.2 7" opacity=".55"/>
    <circle cx="62" cy="62" r="44" fill="#12151e" stroke="currentColor" stroke-width="2"/>
    ${inner}
  </svg>`;
}

/* ===================== Render: status + metrics ===================== */
function stateClass(s){ return s==="ok"?"st-ok":s==="optional"?"st-optional":s==="down"?"st-config":s==="unknown"?"st-optional":"st-config"; }
function stateLabel(s){ return s==="ok"?"Operational":s==="optional"?"Optional":s==="down"?"Not ready":s==="unknown"?"Not checked":"Config required"; }
function stateDot(s){ return s==="ok"?"var(--success)":s==="optional"||s==="unknown"?"var(--accent)":s==="down"?"var(--danger, #e5484d)":"var(--warning)"; }
function renderStatus(){
  document.getElementById("status-grid").innerHTML = STATUS_ITEMS.map(s=>`
  <tr>
    <td class="sys-dot-cell"><span class="sys-dot" style="background:${stateDot(s.state)}"></span></td>
    <td><div class="sys-name">${s.name}</div><div class="sys-sub">${s.sub}</div></td>
    <td class="sys-state-cell"><span class="state-pill ${stateClass(s.state)}"><span class="dot"></span>${stateLabel(s.state)}</span></td>
  </tr>`).join("");
}
/* Live state comes from GET /ready (unauthenticated). Items without a live source stay "Not checked" — nothing is asserted without a probe. */
async function refreshStatus(){
  let body=null;
  try { const r = await fetch("/ready",{cache:"no-store"}); body = await r.json(); } catch(e) { body=null; }
  STATUS_ITEMS.forEach(it=>{
    if(!it.live) return;
    if(!body || !body.components){ it.state="unknown"; return; }
    const v = it.live==="__ready" ? body.ready===true : body.components[it.live];
    if(it.live==="persistenceStore" && v===true && !body.components.persistenceStore) { it.state="optional"; return; }
    it.state = v===true ? "ok" : "down";
  });
  const chip=document.querySelector(".status-chip");
  if(chip){
    const down = STATUS_ITEMS.some(i=>i.state==="down");
    chip.lastChild.textContent = !body ? "Status unavailable" : (down||body.ready!==true) ? "Degraded — see System Health" : "Ready";
  }
  renderStatus();
}
renderStatus();
refreshStatus();
setInterval(refreshStatus, 15000);

document.getElementById("metrics-grid").innerHTML = METRICS.map(m=>`
  <div class="metric-cell">
    <div class="metric-value">${m.value}</div>
    <div class="metric-label">${m.label}</div>
  </div>`).join("");

/* ===================== Shared: vertical timeline rail ===================== */
function renderRail(container, stoppedAt, timings, onSelect, opts){
  opts = opts||{};
  container.innerHTML = PIPELINE_STAGES.map((s,i)=>{
    const n=i+1;
    let cls="rail-node";
    let dotHTML;
    if(stoppedAt==null){ cls+=" pass"; dotHTML=icon("check"); }
    else if(n<stoppedAt){ cls+=" pass"; dotHTML=icon("check"); }
    else if(n===stoppedAt){ cls+=" blocked"; dotHTML=icon("x"); }
    else { cls+= opts.live ? " pending" : " skip"; dotHTML='<span style="font-size:9.5px;font-weight:700">'+n+'</span>'; }
    const time = (stoppedAt==null || n<stoppedAt || n===stoppedAt) && timings ? "T+"+timings[i]+"ms" : "—";
    const interactiveAttrs = onSelect ? ` role="button" tabindex="0" aria-label="Stage ${n}, ${s.title}"` : "";
    return `<div class="${cls}" data-idx="${i}"${interactiveAttrs}>
      <div class="rail-time mono">${time}</div>
      <div class="rail-dot">${dotHTML}</div>
      <div class="rail-content">
        <div class="rail-title">${s.title}</div>
        <div class="rail-module mono">${s.module}</div>
      </div>
    </div>`;
  }).join("");
  if(onSelect){
    container.querySelectorAll(".rail-node").forEach(node=>{
      node.addEventListener("click",()=>{
        container.querySelectorAll(".rail-node").forEach(n=>n.classList.remove("sel"));
        node.classList.add("sel");
        onSelect(parseInt(node.dataset.idx,10));
      });
      node.addEventListener("keydown",activateOnEnterSpace);
    });
  }
}
function stageDetailHTML(stage, idx, stoppedAt){
  const n=idx+1;
  let status="Not reached", color="var(--text-faint)";
  if(stoppedAt==null || n<stoppedAt){ status="Passed"; color="var(--success)"; }
  else if(n===stoppedAt){ status="Blocked here"; color="var(--danger)"; }
  return `<h4>${stage.title} <span class="module">${stage.module}</span></h4>
  <p>${stage.desc}</p>
  <p style="margin-top:6px"><b style="color:${color}">${status}</b></p>`;
}

/* ===================== Evidence ledger (grouped) ===================== */
function pillStyleFor(key,val){
  if(key==="Signature Verification"||key==="Replay Verification"||key==="Chain Validation") return String(val).match(/VALID|OK|NO COLLISION/) ? "background:var(--success-dim);color:var(--success)" : "background:var(--surface-3);color:var(--text-faint)";
  if(key==="Policy Decision") return val==="ALLOW" ? "background:var(--success-dim);color:var(--success)" : val==="BLOCK" ? "background:var(--danger-dim);color:var(--danger)" : "background:var(--surface-3);color:var(--text-faint)";
  if(key==="Consent Status") return val==="GRANTED" ? "background:var(--success-dim);color:var(--success)" : (val==="EXPIRED"||val==="REVOKED") ? "background:var(--danger-dim);color:var(--danger)" : "background:var(--surface-3);color:var(--text-faint)";
  return "";
}
function renderEvidenceLedger(execution, container, opts){
  opts = opts||{};
  const filter = (opts.filter||"").toLowerCase();
  const groups = opts.groups ? EVIDENCE_GROUPS.filter(g=>opts.groups.includes(g.key)) : EVIDENCE_GROUPS;
  const effectiveStop = execution.stoppedAt===14 ? 999 : execution.stoppedAt;
  let html="";
  groups.forEach(g=>{
    const rows = g.fields
      .map(f=>[f, execution.evidence[f]])
      .filter(([k,v])=> !filter || k.toLowerCase().includes(filter) || String(v).toLowerCase().includes(filter));
    if(!rows.length) return;
    const verified = effectiveStop >= g.readyAt;
    html += `<div class="ledger-group">
      <div class="ledger-group-head">
        <span class="ledger-group-title">${g.title}</span>
        <span class="ledger-badge ${verified?'lb-verified':'lb-pending'}">${verified?'VERIFIED':'NOT REACHED'}</span>
      </div>
      ${rows.map(([k,v])=>{
        const pillStyle = pillStyleFor(k,v);
        const valHTML = pillStyle ? `<span class="ledger-value pill" style="${pillStyle}">${v}</span>` : `<span class="ledger-value">${v}</span>`;
        return `<div class="ledger-row">
          <span class="ledger-label">${k}</span>
          <span class="ledger-value-wrap">${valHTML}<button class="ev-copy" data-copy="${encodeURIComponent(v)}">${icon("copy")}</button></span>
        </div>`;
      }).join("")}
    </div>`;
  });
  if(!html){ container.innerHTML = '<div class="ledger-empty">No evidence fields match.</div>'; return; }
  container.innerHTML = html;
  container.querySelectorAll(".ev-copy").forEach(btn=>btn.addEventListener("click",()=>copyToClipboard(decodeURIComponent(btn.dataset.copy),btn)));
}

/* ===================== Hero live trust widget ===================== */
let heroExecIdx = 0;
function renderHero(){
  const listEl = document.getElementById("hero-exec-list");
  listEl.innerHTML = SAMPLE_EXECUTIONS.map((e,i)=>`
    <div class="lt-exec ${i===heroExecIdx?'active':''}" data-idx="${i}" role="button" tabindex="0" aria-label="Inspect execution ${e.id}, ${e.decision}">
      <div class="lt-exec-top"><span class="lt-exec-id mono">${e.id}</span><span class="verdict-chip ${e.decision==='EXECUTE'?'v-execute':'v-block'}">${e.decision}</span></div>
      <div class="lt-exec-meta">${e.provider} · ${e.tenant}</div>
    </div>`).join("");
  listEl.querySelectorAll(".lt-exec").forEach(el=>{
    el.addEventListener("click",()=>{ heroExecIdx=parseInt(el.dataset.idx,10); renderHero(); });
    el.addEventListener("keydown",activateOnEnterSpace);
  });

  const e = SAMPLE_EXECUTIONS[heroExecIdx];
  const effStop = e.stoppedAt===14?14:e.stoppedAt;
  const ticks = PIPELINE_STAGES.map((s,i)=>{
    const n=i+1; let cls="mini-tick";
    if(e.stoppedAt===14 || n<e.stoppedAt) cls+=" pass";
    else if(n===e.stoppedAt) cls+=" blocked";
    return `<span class="${cls}" title="${s.title}"></span>`;
  }).join("");
  document.getElementById("hero-exec-main").innerHTML = `
    <div class="stamp-wrap">${stampSVG(e.decision,64)}<span class="stamp-word" style="color:${e.decision==='EXECUTE'?'var(--success)':'var(--danger)'}">${e.decision}</span></div>
    <div class="lt-detail">
      <div class="lt-reason">${e.reason}</div>
      <div class="lt-meta-row">${e.provider} · ${e.tenant} · ${e.timestamp}</div>
      <div class="mini-rail">${ticks}</div>
      <div class="mini-caption"><span>Stage 1</span><span>${effStop===14?'14 of 14 verified':'Blocked at stage '+e.stoppedAt+' of 14'}</span><span>Stage 14</span></div>
    </div>`;
}
renderHero();

/* ===================== Trust Explorer ===================== */
let currentExec = null;
function renderExecList(){
  const el=document.getElementById("exec-list");
  el.innerHTML = SAMPLE_EXECUTIONS.map((e,i)=>`
    <button class="exec-item" data-idx="${i}">
      <div class="exec-item-top">
        <span class="exec-id mono">${e.id}</span>
        <span class="verdict-chip ${e.decision==='EXECUTE'?'v-execute':'v-block'}">${e.decision}</span>
      </div>
      <div class="exec-meta">${e.provider} · ${e.tenant}</div>
      <div class="exec-meta">${e.reason}</div>
    </button>`).join("");
  el.querySelectorAll(".exec-item").forEach(btn=>btn.addEventListener("click",()=>selectExecution(parseInt(btn.dataset.idx,10))));
}
function selectExecution(i){
  currentExec = SAMPLE_EXECUTIONS[i];
  heroExecIdx = i; renderHero();
  document.querySelectorAll("#exec-list .exec-item").forEach((b,idx)=>b.classList.toggle("active", idx===i));
  const e = currentExec;
  const effStopped = e.stoppedAt===14 ? null : e.stoppedAt;
  document.getElementById("stamp-header").innerHTML = `
    ${stampSVG(e.decision)}
    <div class="stamp-header-body">
      <div class="stamp-header-verdict" style="color:${e.decision==='EXECUTE'?'var(--success)':'var(--danger)'}">${e.decision}</div>
      <div class="stamp-header-reason">${e.reason}</div>
      <div class="stamp-header-meta mono">${e.id} · ${e.provider} · ${e.tenant} · ${e.timestamp}</div>
    </div>`;
  renderRail(document.getElementById("trust-rail"), effStopped, e.timings, (idx)=>{
    document.getElementById("stage-detail").innerHTML = stageDetailHTML(PIPELINE_STAGES[idx], idx, effStopped);
  });
  document.getElementById("stage-detail").innerHTML = stageDetailHTML(PIPELINE_STAGES[0],0,effStopped);
  renderEvidenceLedger(currentExec, document.getElementById("evidence-ledger"));
  document.getElementById("evidence-search").value="";
}
document.getElementById("evidence-search").addEventListener("input",(e)=>{
  if(currentExec) renderEvidenceLedger(currentExec, document.getElementById("evidence-ledger"), {filter:e.target.value.trim().toLowerCase()});
});
renderExecList();
selectExecution(0);

/* ===================== Execution Studio — real gateway client ===================== */
//
// This studio is a genuine browser client of the existing, unmodified backend:
// it calls POST /sign then POST /ai/chat exactly as the JS/Python SDKs do.
// The signing token is read from an in-memory input field only — it is never
// embedded in this file, never persisted (no localStorage/sessionStorage),
// and never sent anywhere but this same-origin server's own /sign endpoint.
// No enforcement, consent, policy, replay, audit, transparency or provider
// code is touched or bypassed; every decision below is exactly what the
// gateway returned.

const STUDIO_PROVIDERS = [
  {label:"OpenAI", key:"openai"}, {label:"Anthropic", key:"anthropic"}, {label:"Gemini", key:"gemini"},
  {label:"Mistral", key:"mistral"}, {label:"Llama", key:"llama"}, {label:"Local", key:"local"}
];
// STUDIO_MODEL_HINTS is a CLIENT-SIDE COSMETIC PRE-FILL ONLY — it exists
// purely to save a keystroke when trying the "local" provider in this Studio
// tool. It is deliberately kept independent from, and is NOT, the server's
// model-resolution source of truth:
//   - Real execution always resolves the effective default model server-side,
//     via services/providers/config.js's resolveDefaultModel() —
//     configured per-provider through PROVIDER_DEFAULT_MODEL_<NAME> env vars
//     and never read by, or exposed to, this file.
//   - This deployment's actual configured default may differ from "qwen2.5:7b"
//     — that value is just a common, easy-to-pull Ollama model name, not a
//     claim about what any given deployment has installed.
//   - The pre-fill only ever affects what appears in the #studio-model input;
//     runStudio() (below) omits `model` from the request body entirely when
//     that field is empty, letting the server's own default apply exactly as
//     it would for any other client. The field is always freely editable and
//     clearable — nothing here enforces or overrides the typed value.
//   - Renaming this away from its original name (PROVIDER_DEFAULT_MODEL) was
//     deliberate: that name too closely echoed config.js's server-side
//     PROVIDER_DEFAULT_MODEL_<NAME> mechanism and could be misread as
//     authoritative. It is not — see docs/guides/providers.md's "Model allowlist
//     extensibility and default model" section for the real mechanism.
//   - This constant was intentionally NOT reunified with the server value:
//     doing so would require a brand-new, unauthenticated config-exposure
//     endpoint (none of the existing GET routes — /health, /ready,
//     /public-key — are meant to carry provider configuration) merely to
//     eliminate one harmless, purely-cosmetic hint. That cost is
//     disproportionate to the problem — see the register entry.
const STUDIO_MODEL_HINTS = { local: "qwen2.5:7b" };
let studioProviderKey = "local";
function renderStudioProviders(){
  document.getElementById("studio-providers").innerHTML = STUDIO_PROVIDERS.map(p=>`<button class="provider-pick ${p.key===studioProviderKey?'sel':''}" data-p="${p.key}">${p.label}</button>`).join("");
  document.querySelectorAll("#studio-providers .provider-pick").forEach(btn=>btn.addEventListener("click",()=>{
    studioProviderKey=btn.dataset.p;
    renderStudioProviders();
    const modelInput = document.getElementById("studio-model");
    if(!modelInput.value.trim() || Object.values(STUDIO_MODEL_HINTS).includes(modelInput.value.trim())){
      modelInput.value = STUDIO_MODEL_HINTS[studioProviderKey] || "";
    }
  }));
}
renderStudioProviders();
document.getElementById("studio-model").value = STUDIO_MODEL_HINTS[studioProviderKey] || "";

// Reason codes are taken directly from the real enforcement modules
// (src/validation/*, services/policy/evaluators/*, services/providers/router.js)
// — this only maps a returned reason to the stage that produced it for display.
function reasonToStage(reason){
  if(typeof reason !== "string") return null;
  const r = reason.toUpperCase();
  if(/REQUEST_MISMATCH|REQUESTHASH|INVALID_REQUEST_ID/.test(r)) return 4;
  if(/SIGNATURE|EXPIRED|FUTURE_TIMESTAMP|MALFORMED|KEY_NOT_FOUND|TENANT_|ORGANIZATION_/.test(r)) return 5;
  if(/REPLAY|NONCE|ANOMALY/.test(r)) return 6;
  if(/CONSENT/.test(r)) return 7;
  if(/^IP_|RATE_LIMIT|TIMESTAMP_MISSING|OUTSIDE_TIME_WINDOW|^NO_POLICIES|^NO_ENABLED_POLICIES|EVALUATOR_|POLICY_|INVALID_CONTEXT/.test(r)) return 8;
  if(/PROVIDER_|MISSING_PROVIDER/.test(r)) return 12;
  // REQUEST_TIMEOUT wraps the whole enforce-and-execute call, but everything
  // before the provider dispatch is fast (crypto/Redis/in-process policy
  // checks) and audit/transparency writes only happen after a successful
  // provider response — so in practice a timeout is the provider call itself.
  if(/^REQUEST_TIMEOUT$/.test(r)) return 12;
  if(/AUDIT_PERSISTENCE/.test(r)) return 11;
  return null;
}
function resetStudioRail(railEl){
  railEl.innerHTML = PIPELINE_STAGES.map((s,i)=>`
    <div class="rail-node pending" data-idx="${i}">
      <div class="rail-time mono">—</div>
      <div class="rail-dot"><span style="font-size:9.5px;font-weight:700">${i+1}</span></div>
      <div class="rail-content"><div class="rail-title">${s.title}</div><div class="rail-module mono">${s.module}</div></div>
    </div>`).join("");
}
function markStudioRail(railEl, passThroughStage, blockedAtStage){
  railEl.querySelectorAll(".rail-node").forEach((node,i)=>{
    const n=i+1;
    let cls, dotHTML;
    if(blockedAtStage && n===blockedAtStage){ cls="blocked"; dotHTML=icon("x"); }
    else if(n<=passThroughStage && (!blockedAtStage || n<blockedAtStage)){ cls="pass"; dotHTML=icon("check"); }
    else if(blockedAtStage && n>blockedAtStage){ cls="skip"; dotHTML='<span style="font-size:9.5px;font-weight:700">'+n+'</span>'; }
    else { cls="pending"; dotHTML='<span style="font-size:9.5px;font-weight:700">'+n+'</span>'; }
    node.className="rail-node "+cls;
    node.querySelector(".rail-dot").innerHTML=dotHTML;
  });
}
resetStudioRail(document.getElementById("studio-rail"));

function b64EncodeUtf8(str){
  const bytes = new TextEncoder().encode(str);
  let bin = ""; bytes.forEach(b=>bin+=String.fromCharCode(b));
  return btoa(bin);
}
function addLog(text, cls){ const log=document.getElementById("studio-log"); const d=document.createElement("div"); d.className="l-line "+(cls||"l-info"); d.textContent=text; log.appendChild(d); log.scrollTop=log.scrollHeight; }

let studioRunning=false;
let currentStudioExec=null;

async function runStudio(){
  if(studioRunning) return;
  const prompt    = document.getElementById("studio-prompt").value.trim();
  const signToken = document.getElementById("studio-sign-token").value.trim();
  const model     = document.getElementById("studio-model").value.trim();
  const runBtn    = document.getElementById("studio-run");
  const progress  = document.getElementById("studio-progress");
  const railEl    = document.getElementById("studio-rail");

  if(!prompt){ addLog("✕ Prompt is required — /ai/chat rejects an empty prompt.", "l-block"); return; }
  if(!signToken){ addLog("✕ A gateway signing token is required to call POST /sign. Paste the token printed by `npm run dev`.", "l-block"); return; }

  studioRunning=true; runBtn.disabled=true;
  document.getElementById("studio-log").innerHTML="";
  document.getElementById("studio-result-tabs").style.display="none";
  document.getElementById("studio-result-body").innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none"><use href="#i-refresh"/></svg><div>Calling the gateway…</div></div>';
  resetStudioRail(railEl);

  const requestBody = model ? { prompt, model } : { prompt };
  currentStudioExec = { prompt, providerKey: studioProviderKey, model: model || null, sign: null, signError: null, chat: null, chatError: null, networkError: null };

  // ── Step 1: POST /sign — request an Ed25519-signed artifact for this exact request ──
  progress.textContent = "Signing request…";
  addLog("→ POST /sign  (provider="+studioProviderKey+")");
  let signRes, signJson;
  try{
    signRes = await fetch("/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer "+signToken },
      body: JSON.stringify({ request: { method: "POST", path: "/ai/chat", body: requestBody }, payload: { provider: studioProviderKey }, ttl: 300000 }),
    });
    signJson = await signRes.json().catch(()=>({}));
  } catch(networkErr){
    currentStudioExec.networkError = networkErr.message;
    addLog("✕ Network error contacting /sign: "+networkErr.message, "l-block");
    markStudioRail(railEl, 2, 3);
    progress.textContent = "NETWORK ERROR";
    finishStudioRun();
    return;
  }

  if(!signRes.ok){
    currentStudioExec.signError = { status: signRes.status, reason: signJson.reason || ("HTTP_"+signRes.status), details: signJson.details || {} };
    addLog("✕ /sign returned "+signRes.status+" "+currentStudioExec.signError.reason, "l-block");
    markStudioRail(railEl, 2, 3);
    progress.textContent = "BLOCK · "+currentStudioExec.signError.reason;
    finishStudioRun();
    return;
  }

  currentStudioExec.sign = signJson;
  addLog("✓ artifact signed — artifactId="+signJson.artifactId);
  markStudioRail(railEl, 5, null);

  // ── Step 2: POST /ai/chat — the artifact now passes through the full, unmodified ──
  // enforcement pipeline: request binding, replay check, consent, policy, execution
  // invariant, transparency log, audit persistence, provider dispatch.
  progress.textContent = "Calling /ai/chat…";
  addLog("→ POST /ai/chat  (x-qodiqa-artifact: "+Math.round(JSON.stringify(signJson.artifact).length*4/3)+" bytes, base64)");
  const artifactB64 = b64EncodeUtf8(JSON.stringify(signJson.artifact));
  let chatRes, chatJson;
  try{
    chatRes = await fetch("/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-qodiqa-artifact": artifactB64 },
      body: JSON.stringify(requestBody),
    });
    chatJson = await chatRes.json().catch(()=>({}));
  } catch(networkErr){
    currentStudioExec.networkError = networkErr.message;
    addLog("✕ Network error contacting /ai/chat: "+networkErr.message, "l-block");
    markStudioRail(railEl, 5, null);
    progress.textContent = "NETWORK ERROR";
    finishStudioRun();
    return;
  }

  if(chatRes.ok && chatJson.decision === "EXECUTE"){
    currentStudioExec.chat = chatJson;
    addLog("✓ decision: EXECUTE — "+chatJson.reason);
    markStudioRail(railEl, 14, null);
    progress.textContent = "EXECUTE";
  } else {
    const reason = chatJson.reason || ("HTTP_"+chatRes.status);
    currentStudioExec.chatError = { status: chatRes.status, reason, details: chatJson.details || {} };
    addLog("✕ /ai/chat returned "+chatRes.status+" "+reason, "l-block");
    // The pipeline is strictly sequential — every stage before the one that
    // actually blocked genuinely ran and passed. Only fall back to "5" (just
    // the confirmed /sign stages) when the reason can't be mapped to a stage.
    const blockedStage = reasonToStage(reason);
    markStudioRail(railEl, blockedStage ? blockedStage-1 : 5, blockedStage);
    progress.textContent = "BLOCK · "+reason;
  }
  finishStudioRun();
}
function finishStudioRun(){
  document.getElementById("studio-result-tabs").style.display="flex";
  document.querySelectorAll("#studio-result-tabs .rtab").forEach(b=>b.classList.toggle("active", b.dataset.rtab==="response"));
  renderStudioTab("response");
  studioRunning=false;
  document.getElementById("studio-run").disabled=false;
}

function ledgerGroupHTML(title, verified, rows){
  if(!rows.length) return "";
  return `<div class="ledger-group">
    <div class="ledger-group-head"><span class="ledger-group-title">${title}</span><span class="ledger-badge ${verified?'lb-verified':'lb-pending'}">${verified?'VERIFIED':'NOT AVAILABLE'}</span></div>
    ${rows.map(([k,v])=>`<div class="ledger-row"><span class="ledger-label">${k}</span><span class="ledger-value-wrap"><span class="ledger-value">${esc(String(v))}</span><button class="ev-copy" data-copy="${encodeURIComponent(String(v))}">${icon("copy")}</button></span></div>`).join("")}
  </div>`;
}
function wireLedgerCopyButtons(container){
  container.querySelectorAll(".ev-copy").forEach(btn=>btn.addEventListener("click",()=>copyToClipboard(decodeURIComponent(btn.dataset.copy),btn)));
}

function responseTabHTML(e){
  if(e.networkError){
    return `<div class="response-box"><b style="color:var(--danger)">Network error</b>\n\n${esc(e.networkError)}\n\nThe browser could not reach this server. Confirm \`npm run dev\` is running and this page was opened from the same origin (e.g. http://localhost:3000/console.html).</div>`;
  }
  if(e.signError){
    return `<div class="response-box"><b style="color:var(--danger)">Blocked at /sign — ${esc(e.signError.reason)}</b>\n\nHTTP ${e.signError.status}\n${esc(JSON.stringify(e.signError.details))}\n\nNo artifact was created, so /ai/chat was never called.</div>`;
  }
  if(e.chatError){
    return `<div class="response-box"><b style="color:var(--danger)">Blocked at /ai/chat — ${esc(e.chatError.reason)}</b>\n\nHTTP ${e.chatError.status}\n${esc(JSON.stringify(e.chatError.details))}\n\nThis is the exact decision returned by the gateway — nothing here is fabricated.</div>`;
  }
  if(e.chat){
    return `<div class="response-box"><b style="color:var(--text)">${esc(e.providerKey)} response${e.model?' · '+esc(e.model):''}</b>\n\n${esc(e.chat.response)}</div>`;
  }
  return "";
}
function identityTabHTML(e){
  const s = e.sign;
  return s
    ? ledgerGroupHTML("Identity & Binding", true, [
        ["Artifact ID", s.artifactId], ["Tenant ID", s.meta.tenantId], ["Key ID", s.meta.keyId],
        ["Timestamp", new Date(s.artifact.timestamp).toISOString()], ["Expires At", new Date(s.meta.expiresAt).toISOString()],
      ])
    : `<div class="ledger-empty">No artifact was created — /sign ${e.signError?('failed with '+e.signError.reason):'was not called'}.</div>`;
}
function cryptoTabHTML(e){
  const s = e.sign;
  return s
    ? ledgerGroupHTML("Cryptographic Proof", true, [
        ["Request Hash", s.artifact.payload.requestHash], ["Policy Hash", s.artifact.payload.policyHash],
        ["Ed25519 Signature", s.artifact.signature], ["Public Key ID", s.artifact.publicKeyId],
      ])
    : `<div class="ledger-empty">No signature exists — /sign ${e.signError?('failed with '+e.signError.reason):'was not called'}.</div>`;
}
function consentTabHTML(e){
  const s = e.sign;
  const rows = [];
  if(e.chat) rows.push(["Decision", e.chat.decision], ["Reason", e.chat.reason]);
  else if(e.chatError) rows.push(["Decision", "BLOCK"], ["Reason", e.chatError.reason], ["HTTP Status", e.chatError.status]);
  let html = rows.length ? ledgerGroupHTML("Consent & Policy Decision", !!e.chat, rows) : `<div class="ledger-empty">/ai/chat was not reached.</div>`;
  if(e.chatError && /CONSENT/.test(e.chatError.reason) && s){
    html += `<div class="verify-note">This tenant has not been granted consent for this action yet. Grant it via the existing, RBAC-gated <span class="mono">POST /consent</span> endpoint for <b>actor_id=${esc(s.meta.keyId)}</b>, <b>action=${esc(e.providerKey)}</b>, <b>tenant_id=${esc(s.meta.tenantId)}</b> — this requires an ops token with the MANAGE_CONSENT permission, which this console does not hold.</div>`;
  }
  if(e.chatError && e.chatError.reason==="CONSENT_STORE_UNAVAILABLE"){
    html += `<div class="verify-note">The consent registry requires PostgreSQL (<span class="mono">QODIQA_PG_ENABLED=true</span>). This is not part of the default <span class="mono">npm run dev</span> environment — enable it to allow consent-gated executions.</div>`;
  }
  return html;
}
function transparencyTabHTML(e){
  const artifactId = e.chat?.artifactId || e.sign?.artifactId || null;
  return `<div class="verify-note">POST /ai/chat does not return transparency-log or audit-chain fields inline — those are ops-authenticated reads. Inspect them for real via <span class="mono">GET /audit/${esc(artifactId||':artifactId')}</span> or <span class="mono">GET /audit/chain/integrity</span> (requires an ops token with READ_AUDIT).</div>`;
}
const STUDIO_TAB_HTML = { identity: identityTabHTML, crypto: cryptoTabHTML, consent: consentTabHTML, transparency: transparencyTabHTML };

function renderStudioTab(tab){
  document.querySelectorAll("#studio-result-tabs .rtab").forEach(b=>b.classList.toggle("active", b.dataset.rtab===tab));
  const body = document.getElementById("studio-result-body");
  const e = currentStudioExec;
  if(!e) return;

  let html;
  if(tab==="response") html = responseTabHTML(e);
  else if(tab==="ledger") html = ["identity","crypto","consent","transparency"].map(t=>STUDIO_TAB_HTML[t](e)).join("");
  else html = STUDIO_TAB_HTML[tab](e);

  body.innerHTML = html;
  wireLedgerCopyButtons(body);
}

document.getElementById("studio-run").addEventListener("click", runStudio);
document.getElementById("studio-reset").addEventListener("click", ()=>{
  document.getElementById("studio-log").innerHTML='<div class="l-line l-info">Awaiting execution…</div>';
  document.getElementById("studio-progress").textContent="Idle";
  resetStudioRail(document.getElementById("studio-rail"));
  document.getElementById("studio-result-tabs").style.display="none";
  currentStudioExec=null;
  document.getElementById("studio-result-body").innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none"><use href="#i-zap"/></svg><div>Run an execution to see the response, artifact, proofs, audit and transparency evidence appear here.</div></div>';
});
document.querySelectorAll("#studio-result-tabs .rtab").forEach(b=>b.addEventListener("click",()=>renderStudioTab(b.dataset.rtab)));

/* ===================== Subsystems / Security / Providers / Developer ===================== */
document.getElementById("subsystems-grid").innerHTML = SUBSYSTEMS.map((s,i)=>`
  <div class="manifest-item" data-modal="sub-${s.id}" role="button" tabindex="0" aria-label="${s.name} — view details">
    <div class="manifest-index">${String(i+1).padStart(2,"0")}</div>
    <div class="manifest-body">
      <h3>${s.name}</h3>
      <span class="manifest-ref">${s.ref}</span>
      <div class="manifest-desc">${s.desc}</div>
    </div>
  </div>`).join("");
document.querySelectorAll('#subsystems-grid [data-modal]').forEach(el=>el.addEventListener("keydown",activateOnEnterSpace));
document.querySelectorAll('#subsystems-grid [data-modal]').forEach((card,i)=>card.addEventListener("click",()=>{
  const s=SUBSYSTEMS[i];
  openModal(s.name, `<span class="module">${s.ref}</span><p>${s.long}</p>`);
}));

document.getElementById("security-grid").innerHTML = SECURITY_CAPS.map(c=>`
  <div class="tl-item">
    <div class="tl-check">${icon("check")}</div>
    <div class="tl-body"><h4>${c.name}</h4><p>${c.desc}</p></div>
  </div>`).join("");

function simLatency(seed){ return 80+Math.floor(rngFor(seed)()*420); }
document.getElementById("providers-tbody").innerHTML = PROVIDERS.map(p=>{
  const lat=simLatency(p.name+"lat"); const avail=(97+rngFor(p.name+"av")()*3).toFixed(2);
  const pct = Math.min(100, Math.round((lat/500)*100));
  return `<tr>
    <td><div class="provider-name">${p.name}</div><div class="provider-class">${p.cls}</div></td>
    <td class="provider-env">${p.env}</td>
    <td class="provider-note">${p.note}</td>
    <td><div class="lat-bar"><div class="lat-fill ${lat<220?'fast':''}" style="width:${pct}%"></div></div><span class="lat-text">${lat}ms</span></td>
    <td class="lat-text">${avail}%</td>
    <td><span class="state-pill st-config"><span class="dot"></span>Config required</span></td>
  </tr>`;
}).join("");

document.getElementById("developer-grid").innerHTML = DEV_RESOURCES.map((d,i)=>`
  <div class="card dev-card">
    <div class="dev-idx">${String(i+1).padStart(2,"0")}</div>
    <div class="dev-name">${d.name}</div>
    <div class="dev-desc">${d.desc}</div>
    <div class="dev-path"><code>${d.path}</code><button data-copy="${encodeURIComponent(d.path)}">${icon("copy")}</button></div>
  </div>`).join("");
document.querySelectorAll("#developer-grid .dev-path button").forEach(btn=>btn.addEventListener("click",()=>copyToClipboard(decodeURIComponent(btn.dataset.copy),btn)));

document.getElementById("endpoint-table").innerHTML = ENDPOINTS.map(([m,p,d])=>`<tr><td class="m">${m}</td><td class="p">${p}</td><td class="d">${d}</td></tr>`).join("");

/* ===================== Architecture diagram ===================== */
const ARCH_SVG = `
<svg viewBox="0 0 1180 640" width="1180" height="640" xmlns="http://www.w3.org/2000/svg" font-family="inherit">
  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#5b8cff"/></marker>
  </defs>
  <style>
    .b{fill:#12151e;stroke:#282e40;stroke-width:1.4}
    .bt{fill:#eef1f7;font-size:13px;font-weight:700}
    .bs{fill:#98a1b5;font-size:10.5px}
    .l{stroke:#3a5bb0;stroke-width:1.6;fill:none;marker-end:url(#arrow)}
    .grp{fill:none;stroke:#1c202c;stroke-width:1;stroke-dasharray:4 4}
    .gt{fill:#5b8cff;font-size:10.5px;font-weight:700;letter-spacing:.06em}
  </style>

  <rect x="30" y="20" width="1120" height="60" class="b" rx="10"/>
  <text x="590" y="45" class="bt" text-anchor="middle">External Clients (HTTPS)</text>
  <text x="590" y="64" class="bs" text-anchor="middle">JS / Python SDK · curl · any HTTP client</text>
  <line x1="590" y1="80" x2="590" y2="112" class="l"/>

  <rect x="430" y="112" width="320" height="54" class="b" rx="10"/>
  <text x="590" y="134" class="bt" text-anchor="middle">Load Balancer</text>
  <text x="590" y="152" class="bs" text-anchor="middle">/ready health gate</text>
  <line x1="590" y1="166" x2="590" y2="198" class="l"/>

  <rect x="60" y="198" width="1060" height="330" class="grp" rx="14"/>
  <text x="80" y="216" class="gt">QODIQA — NODE.JS / EXPRESS</text>

  <rect x="330" y="230" width="520" height="200" class="b" rx="12"/>
  <text x="590" y="252" class="bt" text-anchor="middle">Enforcement Chain</text>
  <text x="380" y="278" class="bs">1. validateArtifact() — Ed25519, schema, expiry, clock-skew</text>
  <text x="380" y="298" class="bs">2. verifyRequestBinding() — SHA-256(method+path+body)</text>
  <text x="380" y="318" class="bs">3. registerNonce() — Redis SET NX PX</text>
  <text x="380" y="338" class="bs">4. checkAnomaly() — sliding-window, fail-closed</text>
  <text x="380" y="358" class="bs">5. enforcePolicy() — consent, IP, time, rate limit</text>
  <text x="380" y="382" class="bs" font-weight="700" fill="#eef1f7">→ assertExecutionInvariant() — synchronous guard</text>
  <line x1="590" y1="430" x2="590" y2="462" class="l"/>

  <rect x="410" y="462" width="360" height="50" class="b" rx="10"/>
  <text x="590" y="484" class="bt" text-anchor="middle">routeProviderCall()</text>
  <text x="590" y="502" class="bs" text-anchor="middle">SSRF-allowlisted dispatch · optional failover</text>

  <line x1="410" y1="487" x2="180" y2="487" class="l"/>
  <line x1="180" y1="487" x2="180" y2="560" class="l"/>
  <rect x="70" y="560" width="220" height="60" class="b" rx="10"/>
  <text x="180" y="583" class="bt" text-anchor="middle">Redis</text>
  <text x="180" y="602" class="bs" text-anchor="middle">nonce · anomaly · rate limit · consent cache</text>

  <line x1="770" y1="487" x2="1000" y2="487" class="l"/>
  <line x1="1000" y1="487" x2="1000" y2="560" class="l"/>
  <rect x="890" y="560" width="220" height="60" class="b" rx="10"/>
  <text x="1000" y="583" class="bt" text-anchor="middle">AI Provider</text>
  <text x="1000" y="602" class="bs" text-anchor="middle">OpenAI · Anthropic · Gemini · Mistral · self-hosted</text>

  <line x1="590" y1="430" x2="590" y2="560" class="l" stroke-dasharray="3 5"/>
  <rect x="480" y="560" width="220" height="60" class="b" rx="10"/>
  <text x="590" y="583" class="bt" text-anchor="middle">PostgreSQL (optional)</text>
  <text x="590" y="602" class="bs" text-anchor="middle">audit store · transparency · consent · RBAC</text>
</svg>`;
document.getElementById("arch-inner").innerHTML = ARCH_SVG;
let archScale=1;
function setArchScale(v){ archScale=Math.min(2.2,Math.max(.4,v)); document.getElementById("arch-inner").style.transform="scale("+archScale+")"; }
document.getElementById("arch-zoom-in").addEventListener("click",()=>setArchScale(archScale+.15));
document.getElementById("arch-zoom-out").addEventListener("click",()=>setArchScale(archScale-.15));
document.getElementById("arch-zoom-reset").addEventListener("click",()=>setArchScale(1));

/* ===================== Tabs ===================== */
function gotoTab(name, focusTab){
  document.querySelectorAll(".tab-btn").forEach(b=>{
    const active = b.dataset.tab===name;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
    b.tabIndex = active ? 0 : -1;
    if(active && focusTab) b.focus();
  });
  document.querySelectorAll(".panel").forEach(p=>p.classList.toggle("active", p.id==="panel-"+name));
  window.scrollTo({top:0, behavior:"smooth"});
}
document.querySelectorAll(".tab-btn").forEach(b=>b.addEventListener("click",()=>gotoTab(b.dataset.tab)));
document.querySelectorAll("[data-goto]").forEach(b=>b.addEventListener("click",()=>gotoTab(b.dataset.goto)));

document.getElementById("tabbar").addEventListener("keydown",(e)=>{
  const tabBtns=[...document.querySelectorAll(".tab-btn")];
  const idx=tabBtns.indexOf(document.activeElement);
  if(idx===-1) return;
  let next=null;
  if(e.key==="ArrowRight") next=(idx+1)%tabBtns.length;
  else if(e.key==="ArrowLeft") next=(idx-1+tabBtns.length)%tabBtns.length;
  else if(e.key==="Home") next=0;
  else if(e.key==="End") next=tabBtns.length-1;
  if(next!==null){ e.preventDefault(); gotoTab(tabBtns[next].dataset.tab, true); }
});

/* ===================== Modal ===================== */
let modalReturnFocusEl=null;
function openModal(title, bodyHTML){
  modalReturnFocusEl = document.activeElement;
  const root=document.getElementById("modal-root");
  root.innerHTML = `<div class="modal-backdrop" id="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-head"><h3 id="modal-title">${title}</h3><button class="modal-close" id="modal-close" aria-label="Close">${icon("x")}</button></div>
      <div class="modal-body">${bodyHTML}</div>
    </div>
  </div>`;
  const bd=document.getElementById("modal-backdrop");
  bd.addEventListener("click",(e)=>{ if(e.target===bd) closeModal(); });
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal-close").focus();
}
function closeModal(){
  document.getElementById("modal-root").innerHTML="";
  if(modalReturnFocusEl && typeof modalReturnFocusEl.focus==="function") modalReturnFocusEl.focus();
  modalReturnFocusEl=null;
}
document.addEventListener("keydown",(e)=>{ if(e.key==="Escape") closeModal(); });

/* ===================== Global search ===================== */
const SEARCH_INDEX = [
  ...SUBSYSTEMS.map(s=>({type:"Subsystem", title:s.name, sub:s.ref, tab:"subsystems"})),
  ...SECURITY_CAPS.map(s=>({type:"Security", title:s.name, sub:"Security Center", tab:"security"})),
  ...PROVIDERS.map(p=>({type:"Provider", title:p.name, sub:p.env, tab:"providers"})),
  ...DEV_RESOURCES.map(d=>({type:"Docs", title:d.name, sub:d.path, tab:"developer"}))
];
const searchInput=document.getElementById("global-search");
const searchResults=document.getElementById("search-results");
let searchSel=-1;
function renderSearch(q){
  if(!q){ searchResults.classList.remove("open"); searchResults.innerHTML=""; return; }
  const ql=q.toLowerCase();
  const matches = SEARCH_INDEX.filter(i=> i.title.toLowerCase().includes(ql) || i.sub.toLowerCase().includes(ql)).slice(0,9);
  searchSel=-1;
  if(!matches.length){ searchResults.innerHTML='<div class="sr-empty">No matches for "'+esc(q)+'"</div>'; searchResults.classList.add("open"); return; }
  searchResults.innerHTML = matches.map((m,i)=>`
    <div class="sr-item" data-i="${i}">
      ${icon("search")}
      <div class="sr-main"><span class="sr-title">${m.title}</span><span class="sr-sub">${m.sub}</span></div>
      <span class="sr-tag">${m.type}</span>
    </div>`).join("");
  searchResults.classList.add("open");
  searchResults.querySelectorAll(".sr-item").forEach((el,i)=>el.addEventListener("click",()=>selectSearchResult(matches[i])));
}
function selectSearchResult(m){
  gotoTab(m.tab);
  searchInput.value=""; searchResults.classList.remove("open");
}
searchInput.addEventListener("input",(e)=>renderSearch(e.target.value.trim()));
searchInput.addEventListener("keydown",(e)=>{
  const items=[...searchResults.querySelectorAll(".sr-item")];
  if(e.key==="ArrowDown"){ e.preventDefault(); searchSel=Math.min(searchSel+1,items.length-1); items.forEach((it,i)=>it.classList.toggle("sel",i===searchSel)); }
  else if(e.key==="ArrowUp"){ e.preventDefault(); searchSel=Math.max(searchSel-1,0); items.forEach((it,i)=>it.classList.toggle("sel",i===searchSel)); }
  else if(e.key==="Enter" && searchSel>=0 && items[searchSel]) items[searchSel].click();
  else if(e.key==="Escape"){ searchResults.classList.remove("open"); searchInput.blur(); }
});
document.addEventListener("click",(e)=>{ if(!e.target.closest(".search-wrap")) searchResults.classList.remove("open"); });
document.addEventListener("keydown",(e)=>{
  if(e.key==="/" && document.activeElement!==searchInput && !e.target.closest("textarea,input")){ e.preventDefault(); searchInput.focus(); }
});

/* ===================== Clock ===================== */
function tickClock(){
  const d=new Date();
  document.getElementById("clock").textContent = d.toLocaleTimeString("en-US",{hour12:false})+" UTC"+(-d.getTimezoneOffset()/60>=0?"+":"")+(-d.getTimezoneOffset()/60);
}
tickClock(); setInterval(tickClock,1000);

})();
