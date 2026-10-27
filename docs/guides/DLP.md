# Data loss prevention (DLP)

DLP finds personal data and secrets in the text of a request and of the model's answer, and applies a configured action to what it finds. It lives in a separable directory
(`enterprise/dlp/`); the core reaches it only through one documented extension point (`src/core/dlp/extensionPoint.js`), so the directory can be moved to another repository
or licence without touching the core. A deployment without the directory runs unchanged; a policy that needs it refuses to load.

## What it detects

| Category | Rules |
|---|---|
| `PII` | `EMAIL`, `PHONE` (shape only: needs a `+` or separators) |
| `FINANCIAL` | `CARD` (Luhn + issuer prefix + length), `IBAN` (country length + mod 97) |
| `NATIONAL_ID` | `CNP` (Romania, control digit + date + county), `PESEL`, `BSN`, `DE_TAX_ID`, `US_SSN`, `ES_DNI_NIE`, `UK_NINO` |
| `CREDENTIAL` | `KEY_AWS_ACCESS`, `KEY_GITHUB`, `KEY_STRIPE`, `KEY_SLACK`, `KEY_GOOGLE_API`, `KEY_ANTHROPIC`, `KEY_OPENAI`, `KEY_NPM`, `KEY_SENDGRID`, `KEY_QODIQA`, `JWT`, `CODE_SECRET` |
| `CRYPTO` | `PEM_BLOCK` (private key / secret blocks; a public certificate is not secret) |

Every finding carries a **confidence**. It is high when a checksum or a documented structure validates (a number that fails Luhn is not a card), lower when only a shape
matches (a phone number, a generic `password = "..."`). Policies set `minConfidence` (**default 0.6**).

**Measured performance.** Eight languages, 9,800 synthetic documents, 9,480 labelled values, 95% Wilson intervals; regenerate with
`node enterprise/dlp/eval/evaluate.js --write evidence/f7`. At `minConfidence` 0.6 (the default): precision 100.00% [99.96, 100.00], recall 97.89% [97.58, 98.16], false-positive rate on
look-alike documents (numbers failing their checksum, dates, versions, order ids) 0.00% [0.00, 0.30]. At 0 (every finding): recall 100.00% [99.96, 100.00] but 12.34% [10.65, 14.26] of
look-alike documents produce a finding, almost all of them national-format phone numbers (PHONE precision 66.95% [62.61, 71.01]). The recall lost between the two settings is the values
that have only a weak signal to go on: phone numbers written without a `+` (confidence 0.55) and Dutch BSN numbers (nine digits with an 11-test, confidence 0.5). The slices
"adjacent" (a card or IBAN next to other numbers, including a neighbour that forms a Luhn-valid window with the card's first groups), "separators" (dots, slashes, commas, doubled and
stripped-character separators, lower-case IBANs) and "evasion" (zero-width and format characters, combining marks, blank braille cells, Cyrillic look-alike letters, fullwidth digits) were
added after the independent verifications found those gaps; their 100% describes exactly the variants listed, not evasion in general. Known gaps: national-id shapes
with no detector (French NIR, Italian codice fiscale), 11-digit ids valid under two schemes (reported under one rule), marking-based classification false positives (a sentence that merely
contains the word). **These figures describe a synthetic corpus; they do not predict performance on real traffic.**

**Evasion.** Detectors run on a normalised view: Unicode NFKC (fullwidth, mathematical and circled digits fold to ASCII; no-break and thin spaces become spaces); every format
character (Unicode class Cf), combining mark (Mn, Me), blank braille cell, object-replacement character, soft hyphen, zero-width and bidi control is removed; and the common
Cyrillic and Greek look-alike letters are folded to Latin for detection only. Every finding is mapped back to the original offsets, so redaction removes exactly what was typed. Groups of
a card or IBAN may be separated by one or two characters from: space, dash, dot, slash, underscore, tab, newline, comma, semicolon, colon (three in a row are not read as one number); an IBAN may be lower-case.
When a neighbouring number forms a valid window together with part of a card, the neighbour is replaced with the card (the cluster is redacted as a whole): over-redacting a number is chosen over leaving part of a card. **Not covered:** key-shaped tokens preceded by `_`, a letter or a digit (the prefix must start a word), e-mail addresses with a quoted local part or a single-label domain, a PEM header split across two values, low-entropy `password = "..."` values (confidence 0.5, below the default 0.6), numbers spelled out in words, deliberate
misspellings, text in images, anything encoded (base64, hex, URL-encoding, ROT13), digit systems NFKC does not fold (Arabic-Indic, Devanagari), letters of other look-alike alphabets
beyond the folded set, and **a value split across two messages or two JSON values**: each message and each string is scanned on its own, so `4111 1111` in one message and `1111 1111` in the next
is not seen, although the model sees them together. DLP is one layer, not a guarantee.

**Bounds.** Input is scanned in a window of 1 MiB. No pattern has nested unbounded quantifiers (fuzzed with adversarial shapes in `enterprise/dlp/__tests__/dlp.test.js`, DLP-07/08); the
slowest measured shape on 1 MiB takes about 1 s, so the cost is bounded but not strictly linear. The normalised view is capped at twice the input (NFKC can expand a character 18-fold); a
text that exceeds the window, whose view exceeds its cap, or that holds more than 20,000 findings is treated as **not scanned completely**: `REDACT` / `MASK` / `BLOCK` refuse it unless the rule sets
`onTruncated: "PASS"`. For tool arguments and results the same holds for more than 2,000 values or nesting deeper than 64 levels.

## The policy rule

```json
{ "id": "DLP_PII_IN", "type": "DLP", "priority": 50, "enabled": true,
  "config": { "dlpFormat": 1, "direction": "input", "action": "REDACT", "rules": ["PII", "FINANCIAL", "CREDENTIAL"], "minConfidence": 0.6 } }
```

* `direction`: `input` (the text the provider would receive), `output` (the answer before delivery), `both`.
* `action`: `DETECT` (record only), `REDACT` (stable token `[[RULE:<12 hex>]]`), `MASK` (keep a recognisable tail), `BLOCK` (refuse the request / the answer: `DLP_BLOCKED`).
* The rule is part of the policy set: validated at load, covered by `policyHash` (a changed DLP setting changes the hash recorded in the audit chain), managed through the same
  governance as other rules. **Migration:** a policy file without a DLP rule is unchanged; adding one needs no other change. Derived defaults are stored under underscore keys that
  `policyHash` ignores, so the hash of the loaded rule equals the hash of the live rule.
* Several rules apply in `priority` order, each on the output of the previous one; the first `BLOCK` ends it.

**Stable tokens.** `REDACT` replaces a value by `HMAC-SHA256(QODIQA_DLP_TOKEN_KEY, rule || canonical value)` truncated to 12 hex digits. "The same value" means: for an e-mail address,
the same address ignoring case (dots in the local part are significant); for cards, IBANs, phone numbers and national ids, the same digits however they were grouped; for everything else,
the same characters. The same value gives the same token (a conversation stays coherent), but the token cannot be reversed or looked up without the key. Twelve hex digits are 48 bits: within
one conversation a collision is negligible, across millions of distinct values it is not (about 0.2% at a million values), so tokens are for coherence inside a request, not an identifier
across a data set. `QODIQA_DLP_TOKEN_KEY` is a per-deployment secret of at least 32 characters; **without it a `REDACT` rule blocks** (`DLP_UNAVAILABLE`) rather than being skipped. The same
applies when the module is missing.

## Audit

Each rule that found something produces a `DLP_TRANSFORM` event with `{ rules, action, inputHashBefore, inputHashAfter }`: the SHA-256 of the JSON array of the texts of the request (or of the one answer) as received and as forwarded, so a
log of the transformed request can never be mistaken for the request that arrived. These are plain hashes: for a very short, low-entropy request they could be guessed offline. The values themselves are never logged. Under audit schema v8 (off by default) the same fields
are written as `DLP_TRANSFORM` chain entries (`<requestId>:dlp_in_<n>` / `dlp_out_<n>`); otherwise they are structured events.

## Streaming

An `input` rule applies to a streaming request exactly as to a normal one. An `output` rule needs the whole answer, which a stream does not have: while one is configured a
streaming request is refused (`DLP_OUTPUT_STREAMING_UNSUPPORTED`) and the caller asks without `stream`.

## Classification and exfiltration

A rule may add `classification` and/or `exfiltration` next to its `action`:

```json
{ "dlpFormat": 1, "direction": "both", "action": "DETECT", "rules": ["*"],
  "classification": { "minLevel": "CONFIDENTIAL", "action": "BLOCK", "markings": { "RESTRICTED": ["project falcon"] } },
  "exfiltration": { "action": "BLOCK", "allowHosts": ["docs.example.com", "*.cdn.example.com"], "bulkThreshold": 10, "minSeverity": "MEDIUM" } }
```

* **Classification** assigns PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED from two kinds of evidence, each with a confidence: what is in the text (credentials, key material, financial
  and national-id data are RESTRICTED; personal data CONFIDENTIAL) and what the text says about itself (markings such as "strictly confidential", "streng vertraulich", "uz intern",
  plus the tenant's own `markings`). Signals combine as a noisy-OR capped at 0.99. A marking is evidence, not proof: a sentence that merely mentions the word is a known false-positive source.
  `action`: `DETECT` records the label (`CLASS:<LEVEL>` in the event), `BLOCK` refuses at or above `minLevel`.
* **Exfiltration** judges the **answer** (`direction` output or both): sensitive data the user did not supply (`NEW_SENSITIVE_IN_OUTPUT`), a link or image whose URL carries data to a host
  not in `allowHosts` (`URL_EXFIL`, the markdown-image trick), bulk personal records (`BULK_RECORDS`), large encoded blobs (`ENCODED_BLOB`). What the user typed in the request is
  never "new". `minSeverity` filters; `BLOCK` withholds the answer.

## Tool calls

* `direction: "tool_input"` screens the **arguments** of a tool call when it is authorised (`POST /v1/actions/authorize`), before a chain position is reserved or an artifact exists, so a refused
  call leaves the session where it was. Only `DETECT` and `BLOCK` are allowed: the arguments are bound by the action hash and are never rewritten.
* `direction: "tool_output"` screens what the tool returned (text parts, the text of embedded resources, and every string, number and key inside `structuredContent`; a result that holds a finding in a key, or is too large or too deep to scan completely, is withheld unless the rule only detects) **before** the result is screened for instructions, hashed for the receipt
  and delivered, so the receipt's `outputHash` is over what the caller received. All four actions apply; a blocked result is withheld exactly like a screening block (receipt status `RESULT_BLOCKED`).
* The rules come from the tenant's effective policy set, else the server-wide one. `both` means the two chat directions only.

## What is not covered here

Data residency and retention, encryption at rest and the exposure-incident workflow are described in their own sections as they are added.

## Behaviours worth knowing

* An unterminated `-----BEGIN ... PRIVATE KEY-----` header redacts up to 8,192 following characters of ordinary text (the block cannot be delimited, so it is withheld whole up to a bound).
* A rule in `DETECT` mode that finds nothing writes no event, including when the text was too long to scan completely; a DETECT-only rule does not fail a call for an over-large tool result, it just cannot see the unscanned part.
* The container image ships `enterprise/` (the root `.dockerignore` is an allow-list) except the evaluation harness; a new file under `enterprise/` ships unless it is excluded there.
