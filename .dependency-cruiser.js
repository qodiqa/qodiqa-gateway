'use strict';

/**
 * Architectural layering enforcement.
 *
 * Static dependency direction between layers is enforced in CI. Two governance mechanisms apply: (1) production
 * middleware/ is inside the analysis, with rules that target src/middleware/ specifically, and (2) the tolerated
 * Core->Infrastructure / Core->Services violations are warnings whose count is bounded by a regression-budget gate
 * (`.arch-baseline.json`, exact list in `.arch-baseline-violations.txt`), so they cannot grow unnoticed.
 *
 * Last verified: 2026-10-24 — `npm run arch:check` reports 0 errors; the warning count is pinned in
 * `.arch-baseline.json`. Whenever the `forbidden` rules or `options` below change, bump this date.
 *
 * Target layering (one-directional):
 *   API (src/api) -> Middleware (middleware/ and src/middleware/) ->
 *   Services (services/) -> Core (src/core) -> Infrastructure (src/infra)
 *
 * Middleware (both top-level middleware/ and src/middleware/ — two
 * directories, one logical layer; see item 12, Track D) is API-adjacent, not
 * Core: it may depend on API, Infrastructure, Services, and utilities, but
 * must never become business/domain logic, orchestration, or persistence —
 * enforced by forbidding middleware -> Core and, symmetrically with the
 * existing no-*-to-api rules, forbidding Core/Infrastructure -> middleware.
 *
 * Hard errors (CI-blocking) — the codebase is fully compliant as of this
 * remediation:
 *   - no-circular                 zero circular dependencies anywhere in
 *                                  src/ + services/ + middleware/
 *   - no-infra-to-services        Infrastructure never imports Services (two
 *                                  narrow, documented exceptions below)
 *   - no-infra-to-api / no-core-to-api   neither layer ever imports the API layer
 *   - no-middleware-to-core       neither top-level middleware/ nor
 *                                  src/middleware/ ever imports Core
 *                                  (business/domain/orchestration logic) —
 *                                  as of item 13 (Track D) this covers both
 *                                  directories; see the rule's own comment
 *                                  for the DI pattern that keeps it that way
 *   - no-infra-to-middleware / no-core-to-middleware   neither layer ever
 *                                  imports middleware/ or src/middleware/
 *                                  (mirrors the API rules — middleware sits
 *                                  above Services, so lower layers must
 *                                  never reach up into it)
 *
 * Two rules are warnings (visible, non-blocking, but no longer unbounded —
 * see .arch-baseline.json): eliminating
 * them entirely would require relocating widely-used cross-cutting utilities
 * (services/logger.js, services/secrets/secretsProvider.js) and touching
 * 50+ pre-existing Core call sites — a larger, separate migration than this
 * remediation pass. The WARNING COUNT ITSELF is a regression-budgeted,
 * CI-enforced ceiling: it may hold steady or shrink, never grow. See
 * REMEDIATION-FINDING-64.md and WP-004-REMEDIATION-REPORT.md.
 *
 * @type {import('dependency-cruiser').IConfiguration}
 */
module.exports = {
  forbidden: [
    {
      name: 'no-circular',
      severity: 'error',
      comment:
        'Circular dependencies make module initialization order unpredictable and force lazy ' +
        "require() workarounds inside functions to paper over the cycle. Break the cycle with " +
        'dependency inversion (an injected resolver/setter, see ' +
        'src/infra/postgres/pg-audit-backend.js:setKeyInfoResolver) or by moving the shared ' +
        'concern to the correct layer instead of adding another lazy require.',
      from: {},
      // WAIVER: exactly ONE recorded cycle is exempt —
      // persistenceRecovery/index -> recoveryManager -> infra/postgres/pg-audit-backend -> index (lazy requires on the
      // durability-recovery path; inverting it changes how every recovery-path integration test wires the mirror
      // insert, so it waits for an decision). `viaSomeNot` keeps EVERY other cycle an error, including any cycle
      // that passes through these modules plus anything else. Remove this line when the cycle is broken.
      to: { circular: true, viaSomeNot: '^src/(core/persistenceRecovery/(index|recoveryManager)|infra/postgres/pg-audit-backend)\\.js$' },
    },
    {
      name: 'no-infra-to-services',
      severity: 'error',
      comment:
        'Infrastructure (src/infra/**) must never depend on Services (services/**) — this is ' +
        'the "Infrastructure requires business logic from Services" violation Finding 64 (1.2) ' +
        'requires eliminating everywhere, not just in the one file it named. The only allowed ' +
        'exceptions are services/logger.js and services/secrets/secretsProvider.js, both ' +
        'cross-cutting utilities (structured logging, KEK access) rather than business logic, ' +
        'used throughout Infrastructure. If Infrastructure code needs an actual Services-layer ' +
        'capability, invert the dependency (inject a resolver — see setKeyInfoResolver in ' +
        'src/infra/postgres/pg-audit-backend.js for the pattern) rather than requiring the ' +
        'Services module directly. If the module doing the requiring is itself business/' +
        'orchestration logic rather than infrastructure, move it to services/ instead (see ' +
        'services/artifact/tenantKeyManager.js and rotationScheduler.js, relocated from ' +
        'src/infra/keys/ for exactly this reason).',
      from: { path: '^src/infra' },
      to: {
        path: '^services',
        pathNot: '^services/(logger\\.js|secrets/secretsProvider\\.js)$',
      },
    },
    {
      name: 'no-infra-to-api',
      severity: 'error',
      comment: 'Infrastructure must never depend on the API layer.',
      from: { path: '^src/infra' },
      to: { path: '^src/api' },
    },
    {
      name: 'no-core-to-api',
      severity: 'error',
      comment: 'Core/domain logic must never depend on the API layer.',
      from: { path: '^src/core' },
      to: { path: '^src/api' },
    },
    {
      name: 'no-middleware-to-core',
      severity: 'error',
      comment:
        'Middleware (both top-level middleware/ and src/middleware/ — two directories, one ' +
        'logical layer; see item 12, Track D) is API-adjacent, not Core: it must never become ' +
        'business logic, domain logic, or orchestration. If a middleware module needs a Core ' +
        'capability, either put that capability behind a Services-layer function (middleware -> ' +
        'Services is fine) rather than reaching into src/core directly, or — for src/middleware/ ' +
        'factories that genuinely need a Core function (e.g. a permission check) — accept it as ' +
        'an injected parameter from the composition root (server/startup.js), which is free to ' +
        'import Core directly. Folded back from the temporary no-src-middleware-to-core warning ' +
        '(item 13, Track D): rbac.js, opsAuth.js, and signAuth.js no longer import src/core — ' +
        'rbac.js\'s createRequirePermission() takes isPermitted/isValidPermission as injected ' +
        'params, signAuth.js\'s createSignAuthMiddleware() takes store/isSigningPermitted as ' +
        'injected params (wired by src/api/routes/sign.js), and opsAuth.js\'s NOOP_LOCKOUT ' +
        'default is now defined locally rather than imported from src/core/authLockout.',
      from: { path: '^(middleware|src/middleware)' },
      to: { path: '^src/core' },
    },
    {
      name: 'no-infra-to-middleware',
      severity: 'error',
      comment:
        'Infrastructure must never depend on middleware — mirrors no-infra-to-api. Middleware ' +
        'sits above Services in the layering, so a lower layer reaching up into it is exactly ' +
        'the kind of architectural drift this rule set exists to prevent. Covers both ' +
        'top-level middleware/ and src/middleware/ (item 12, Track D) — they are the same ' +
        'logical layer split across two directories.',
      from: { path: '^src/infra' },
      to: { path: '^(middleware|src/middleware)' },
    },
    {
      name: 'no-core-to-middleware',
      severity: 'error',
      comment:
        'Core must never depend on middleware — mirrors no-core-to-api, for the same reason ' +
        'as no-infra-to-middleware. Covers both top-level middleware/ and src/middleware/ ' +
        '(item 12, Track D) — they are the same logical layer split across two directories.',
      from: { path: '^src/core' },
      to: { path: '^(middleware|src/middleware)' },
    },
    {
      name: 'no-core-to-infra',
      severity: 'warn',
      comment:
        'Core should not depend directly on Infrastructure under the target layered ' +
        'architecture (API -> Services -> Core -> Infrastructure, strictly one-directional; ' +
        'Infrastructure -> Core is the only allowed cross-layer edge in that pair). This is a ' +
        'large, pre-existing pattern (50+ files, e.g. src/core/audit/audit-log.js -> ' +
        'src/infra/postgres/pg-audit-backend.js) that was out of scope for the Finding 64 ' +
        'remediation pass, which targeted the one real circular dependency and every ' +
        'Infrastructure->Services edge. Left as a warning — visible, non-blocking — rather than ' +
        'silently unenforced. Tightening this to an error is a separate, larger migration.',
      from: { path: '^src/core' },
      to: { path: '^src/infra' },
    },
    {
      name: 'no-core-to-services',
      severity: 'warn',
      comment:
        'Core should not depend directly on Services under the target layered architecture. ' +
        'This is a large, pre-existing pattern (e.g. services/artifact/keyManager.js, ' +
        'services/utils/evidencePackage.js, services/policy/** used throughout src/core/**) ' +
        'that was out of scope for the Finding 64 remediation pass. Left as a warning rather ' +
        'than silently unenforced.',
      from: { path: '^src/core' },
      to: { path: '^services' },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    // middleware/ is now a first-class, permanently-governed
    // architecture participant — it must never again be an analysis blind
    // spot the way it was before this change (Architecture Finding #3).
    includeOnly: '^(src|services|middleware)',
    // Test files legitimately cross layers for testing purposes (e.g. an
    // integration test importing a route handler, or a unit test wiring a
    // mock directly into the module under test) — that is not a production
    // architecture violation, so tests are excluded from rule-checking here.
    exclude: { path: '(__tests__|\\.test\\.js$)' },
    tsPreCompilationDeps: false,
    combinedDependencies: false,
  },
};
