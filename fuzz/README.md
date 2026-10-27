# Coverage-guided fuzzing

Targets for [jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) (libFuzzer for Node) over the parsers and verifiers that take untrusted input. They complement the property tests in `test/fuzz.suite.test.js` (fast-check, random generation): a coverage-guided fuzzer keeps the inputs that reach new branches and mutates them, so it gets past checks random generation does not.

| Target | Code under test | Oracle (what must hold for every input) |
|---|---|---|
| `jcs` | `src/validation/jcsP1.js` parser | throws only `JcsError`; the canonical form is a fixed point of parse then canonicalise |
| `requestHash` | `src/validation/requestHash.js` | deterministic; method case does not matter; only `TypeError` on bad input; output is a SHA-256 hex digest |
| `timeCheck` | `src/validation/timeCheck.js` `parseTimestamp` | never throws; never returns a non-finite number |
| `sortedJson` | `src/infra/crypto/hashing.js` `sortedJSON` | deterministic and independent of key insertion order |
| `delegationChain` | `src/core/delegation/delegationToken.js` `verifyChain` | with no trusted key, never `ok: true`, never throws |
| `evidenceBundle` | `tools/verify/verify.bundle.external.js` (the auditor's single-file verifier) | with no trust anchors, never `valid: true`, never throws on hostile JSON |
| `operatorSession` | `src/core/identity/operatorSession.js` `verify` | never throws, never accepts a fuzzed token |

## Run

```bash
npm run fuzz              # 30 s per target; fails on the first crash, reproducer in evidence/fuzz/crashes/
npm run fuzz:replay       # every stored corpus and crash input once, no mutation: fast and deterministic
node scripts/fuzz/run.js --seconds 300 --only jcs,delegationChain
```

jazzer.js needs its native addon. If `npm ci` did not fetch it (newer npm blocks install scripts until approved), run `npx prebuild-install --runtime napi` inside `node_modules/@jazzer.js/fuzzer`.

Seed inputs under `fuzz/corpus/<target>/` that are committed are the regression corpus (`fuzz:replay`). Inputs the fuzzer discovers on a long run stay untracked unless someone promotes them deliberately, together with the reason.

## What this does and does not show

A clean run means no input found in the time given broke the oracle. It is not a proof, and 30 to 60 seconds per target is a smoke run: the recorded runs and their lengths are. Targets exist for 7 components, not for the whole API surface; HTTP-level fuzzing of the routes is not covered here.
