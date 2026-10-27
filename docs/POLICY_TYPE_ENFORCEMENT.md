# Policy types and where each is applied

`services/policy/engine.js` evaluates the enabled policies in priority order; the first refusal decides. Ten policy types are supported. Six are decided inside the engine
loop; four are validated and hashed like every rule but applied by a dedicated stage of the request pipeline, so their evaluator in the loop always passes.

| Type | Applied by |
|---|---|
| `REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`, `RATE_LIMIT`, `ABAC`, `DATA_RESIDENCY` | the engine loop (`services/policy/engine.js`) |
| `DLP` | `src/core/dlp/dlpService.js`, called from `src/api/routes/aiChat.js` (also `actions.js`, `tools.js`) |
| `CONTENT_RULE` | `src/core/content/contentStage.js`, input and output, from `aiChat.js` |
| `BUDGET` | `src/core/budget/budgetStage.js` (`reserve`, `settle`, `refund`), from `aiChat.js` |
| `ROUTING` | `src/core/routing/routingStage.js` (`resolve`), from `aiChat.js` |

Every rule is covered by `policyHash`, so a change of any setting changes the hash recorded in the audit chain. Policy changes go through four-eyes governance.
