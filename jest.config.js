'use strict';

// Extracted from package.json's former "jest" key (items 21/22 follow-up) so
// the modulePathIgnorePatterns addition below can carry an explanatory
// comment — package.json/JSON has no comment syntax, and this setting is
// exactly the kind of thing a future maintainer would otherwise "clean up"
// without knowing why it's there. See
// for the full
// investigation. Every other setting below is a verbatim, unchanged carry-
// over from package.json's prior "jest" key.

module.exports = {
  // ── maxWorkers cap ──
  //
  // History: the previous dev machine (Lenovo AIO, 8 GB, single SODIMM) could
  // not run this suite count at full parallelism — worker OOM kills crashed
  // three separate sessions — so this was pinned to the literal 2 on
  // 2026-08-23. Development moved to a 48 GB / 24-core machine and's
  // full-parallel measurement was finally taken:
  //   2 workers  : 61.5s wall · peak total node RSS 1,186 MB
  //   12 workers : 13.6s wall · peak total node RSS 4,208 MB  <- knee
  //   23 workers : 13.2s wall · peak total node RSS 7,034 MB
  // Wall time is flat beyond ~12 workers while memory keeps climbing, so
  // '50%' (12 of 24 cores here) is the measured sweet spot, not a guess.
  // Percentage form scales with whatever machine runs it instead of pinning
  // yesterday's core count. A CLI --maxWorkers flag still OVERRIDES this —
  // intentional, for CI runners and one-off experiments. If gates ever run
  // on a small-RAM machine again, re-pin a literal value from measurement
  // (the 8 GB-era value was 2) rather than deleting the cap.
  maxWorkers: '50%',

  // per-run list of the per-file setup temp dirs, removed once all
  // workers have finished (see both files' headers).
  globalSetup: './test/support/jest.globalSetup.js',
  globalTeardown: './test/support/jest.globalTeardown.js',

  setupFiles: [
    // step 1: records every mkdtemp a test makes in os.tmpdir(), removed by test/support/jest.globalTeardown.js.
    './test/support/jest.tmpdirTracker.js',
    // first, so the store paths are redirected before test/support/jest.setup.js
    // or any test file requires application code; also installs the data/
    // write guard (see the file header).
    './test/support/jest.dataIsolation.js',
    './test/support/jest.setup.js',
  ],
  // SEM-C session 3: needs the test framework already installed (describe/
  // beforeAll) to register a global beforeAll — see test/support/jest.setup.afterEnv.js's
  // own header for why this can't live in setupFiles above.
  setupFilesAfterEnv: [
    './test/support/jest.setup.afterEnv.js',
    // fails any test that attempted a write under data/.
    './test/support/jest.dataIsolation.afterEnv.js',
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/sdk/',   // the SDK packages have their own gates; anchored so scripts/sdk/ (the generator) is collected
    // evidence of independent verifications (probe sources); never a gate (see the allowlist in test/guards/testGateCoverage.guard.test.js)
    // a test helper kept as a stub in a __tests__ folder (the kit itself is enterprise/identity/testkit/)
    '/enterprise/identity/__tests__/samlTestKit\.js$',
    // _quarantine/: holds files moved aside as dead/
    // superseded per the disposition workflow —
    // gitignored, never part of the live codebase. A stray *.test.js left in
    // there (e.g. a pre-quarantine scratch diagnostic) must not be silently
    // picked up by a broad Jest invocation; found via
    // test/guards/testGateCoverage.guard.test.js surfacing
    // _quarantine/2026-09-10/zzDiag.test.js as an orphan.
    '/_quarantine/',
    // the pinned previous independent verifier — a test ORACLE (plain modules, no tests), required
    // only by; under __tests__/ Jest would run each file.
    '/scripts/audit-repro/__tests__/fixtures/verify-oracle-v1/',
    // the pinned pre-change audit-log.js — a test ORACLE (no tests), required only by
    // src/core/audit/__tests__/compactIdIndex.test.js.
    '/src/core/audit/__tests__/fixtures/previous-audit-log/',
    // the proof-verifier test fixture builder (plain module, no tests), required only by
    //under __tests__/ Jest would run it as a test file.
    '/scripts/audit-repro/__tests__/helpers/',
    '/src/core/audit/__tests__/helpers/',   // the killed-process helper of commitDurable.test.js
    // Stryker's own tempDirName ('.stryker-tmp',
    // gitignored) instruments and copies the ENTIRE source+test tree per
    // concurrent test-runner sandbox (.stryker-tmp/sandbox-<hash>/...),
    // including test files, and `cleanTempDir: true` in stryker.config.js
    // does not reliably remove every sandbox on every exit path (observed:
    // 3 stale sandboxes survived a fully-completed dry run + a
    // fully-completed 7h40m mutation run). Without this exclusion, a plain
    // `npm run test:unit`/`test:coverage` run from the repo root discovers
    // those leftover copies as REAL test files (their paths under
    // .stryker-tmp/sandbox-*/src/... still match the src/ inclusion
    // pattern) and runs them against whatever half-mutated/stale source
    // state Stryker last left in that sandbox — reproduced concretely: a
    // later `test:unit` capture spuriously reported 66 failed suites/
    // 307 failed tests, entirely from 3 leftover sandboxes, on an otherwise
    // clean tree. This is a permanent correctness fix, not scoped to
    // — it protects every future gate run against this exact false-failure
    // mode regardless of whether stale sandboxes happen to exist at the
    // time. Not needed on Stryker's OWN side (stryker.config.js's jest.config
    // override): Stryker's sandboxed Jest run uses the sandbox itself as
    // rootDir, so it never sees a ".stryker-tmp" segment in its own
    // relative test paths.
    // ECS: any Stryker temp-dir NAME (tempDirName is configurable, e.g. the TQ-05 run's
    // .stryker-tmp-tq05), not only the default — a renamed sandbox was otherwise collected as real tests.
    '/\\.stryker-tmp[^/\\\\]*[/\\\\]',
    // Tool-managed agent worktrees (.claude/worktrees/<agent>/) are FULL checkouts inside the repo tree. A gate
    // run from the root collected their copies of every test as real tests and ran them against the worktree's
    // half-changed source - a contaminated run. Same false-collection class as the Stryker sandboxes above.
    '/\\.claude[/\\\\]worktrees[/\\\\]',
    // quarantine/ holds files moved out of
    // the tree with their original relative paths preserved — including test
    // files.
    // Those paths still match the src/ inclusion pattern, so without this entry
    // Jest collects them and fails them (their relative requires no longer
    // resolve) — reproduced: test:unit reported 2 failed suites, 0 failed tests.
    // Same mechanism and fix as the .stryker-tmp entry above. No tracked path
    // contains a quarantine/ segment (git ls-files, 0 matches).
    '/quarantine/',
  ],
  collectCoverageFrom: [
    'src/**/*.js',
    'services/**/*.js',
    'enterprise/**/*.js',
    'middleware/**/*.js',
    '!src/testing/**',
    '!src/benchmark/**',
    '!**/__tests__/**',
    '!**/*.test.js',
    '!**/fixtures/**',
    '!**/mocks/**',
    // ER 2026-10-06: third-party vendored, minified browser bundles are
    // not project code. Counting them added 35,647 statements / 34,316 branches / 10,591 functions at 0% and made the
    // coverage gate unpassable however much QODIQA code was tested. Thresholds unchanged.
    '!src/openapi/vendor/**',
  ],
  coverageThreshold: {
    global: {
      statements: 78,
      branches: 66,
      functions: 78,
      lines: 80,
    },
  },

  // ── modulePathIgnorePatterns (Windows jest-worker flake, root-caused) ──────
  //
  // WHY THIS EXISTS: items 21/22 (KMS/Vault config + cloud SDK declarations)
  // added 6 new optionalDependencies, pulling in ~118 transitive packages —
  // mostly the Google Cloud KMS (@google-cloud/kms → @grpc/grpc-js,
  // google-auth-library, google-gax, the protobufjs family, gaxios,
  // gcp-metadata, ...) and Azure (@azure/identity, @azure/keyvault-keys,
  // @azure-rest/*, @typespec/*) SDK trees. On this Windows dev machine
  // (no watchman installed — Jest falls back to its slower Node-based
  // recursive crawler), the enlarged node_modules tree reproducibly
  // triggered a jest-worker process-pool flake: usually just a cosmetic
  // "A worker process has failed to exit gracefully" warning, but in one
  // observed run an actual ChildProcessWorker.initialize crash that dropped
  // a test suite and under-reported totals (286/287 suites, 7948 instead of
  // 8018 tests) — see the finding report for the full run-by-run table.
  // Original (pre-items-21/22) code ran clean 6/6 consecutive times
  // regardless of worker count, with zero warnings and zero crashes. Every
  // unscoped default-worker run on changed code flaked in some form (9/9).
  // With this exact scoping in place: 0/10 crashes across every tested run,
  // but the cosmetic warning still recurred once (9/10 clean) — this is a
  // real reduction in flake rate, NOT a proven total elimination. Don't
  // read a clean run (or several) as proof this is "fully fixed" — see the
  // finding report's own epistemic-limits section for why.
  //
  // MECHANISM: modulePathIgnorePatterns is compiled directly into
  // jest-haste-map's `ignorePattern` inside jest-runtime (verified against
  // this repo's installed jest@30.4.2 / jest-runtime source,
  // node_modules/jest-runtime/build/index.js, ~line 3608 — the array is
  // joined into the exact RegExp passed to `HasteMap`'s constructor), so it
  // gates the filesystem crawl itself, not just module resolution.
  //
  // WHY THIS IS PARTIAL, DELIBERATELY: modulePathIgnorePatterns has a
  // second, documented effect — a matching path also becomes un-require()-
  // able inside tests. @aws-sdk/*, @smithy/*, and node-vault are
  // deliberately LEFT OUT of this list (even though they're also new)
  // because src/infra/keys/__tests__/sdkAvailability.test.js has one
  // deliberately-real (non-mocked) assertion —
  // require.resolve('@aws-sdk/client-kms') — proving genuine SDK resolution
  // actually works, not just the mocked-resolver paths. Excluding @aws-sdk
  // here would silently break that assertion's ability to test the real
  // thing. This was a declared trade-off at the time this was added, not an
  // oversight — do not "complete" this list to cover @aws-sdk without first
  // either accepting that test becomes mock-only or finding another way to
  // verify real resolution.
  //
  // If you're removing this because "it looks unnecessary" — re-run
  // `npm run test:unit` 6+ times in a row WITHOUT this setting first. A
  // single clean run does not mean the flake is gone; it was intermittent
  // (roughly 1 crash in 8 runs, warning in the rest) even before this fix.
  modulePathIgnorePatterns: [
    'node_modules[\\\\/]@google-cloud[\\\\/]',
    'node_modules[\\\\/]@azure[\\\\/]',
    'node_modules[\\\\/]@azure-rest[\\\\/]',
    'node_modules[\\\\/]@typespec[\\\\/]',
    'node_modules[\\\\/]@grpc[\\\\/]',
    'node_modules[\\\\/]google-auth-library[\\\\/]',
    'node_modules[\\\\/]google-gax[\\\\/]',
    'node_modules[\\\\/]gaxios[\\\\/]',
    'node_modules[\\\\/]gcp-metadata[\\\\/]',
    'node_modules[\\\\/]gtoken[\\\\/]',
    'node_modules[\\\\/]protobufjs[\\\\/]',
    'node_modules[\\\\/]@protobufjs[\\\\/]',
    'node_modules[\\\\/]proto3-json-serializer[\\\\/]',
    'node_modules[\\\\/]@js-sdsl[\\\\/]',
    'node_modules[\\\\/]retry-request[\\\\/]',
    'node_modules[\\\\/]teeny-request[\\\\/]',
    'node_modules[\\\\/]stream-events[\\\\/]',
    'node_modules[\\\\/]duplexify[\\\\/]',
    'node_modules[\\\\/]google-logging-utils[\\\\/]',
    'node_modules[\\\\/]json-bigint[\\\\/]',
    'node_modules[\\\\/]bignumber\\.js[\\\\/]',
    'node_modules[\\\\/]object-hash[\\\\/]',
    'node_modules[\\\\/]stubs[\\\\/]',
    'node_modules[\\\\/]stream-shift[\\\\/]',
  ],

  // ── PG-integration serialized-migration set (test:component split, see ──
  // package.json's test:component:serial / test:component:parallel) ────────
  //
  // These 17 files (16 Jest-collected + 1 non-collected worker helper) each
  // apply the full migrations/001-051 chain to their own disposable
  // database. Migrations 002/018/038 write CREATE ROLE / ALTER ROLE
  // statements to pg_authid/pg_auth_members — cluster-wide shared catalogs,
  // not per-database — so running two or more of these files' chains
  // concurrently can race on those rows ("tuple concurrently updated").
  //'s flake
  // section for the full root-cause writeup.
  //
  // consentActionSemantics.integration.test.js and
  // alertStoreDedup.integration.test.js both call pgPool.runMigrations()
  // (confirmed by grep) but were missing from this list — reproduced their
  // exact "tuple concurrently updated" failure by running them concurrently
  // alongside other unserialized migration-chain files (7/7 attempts hit at
  // least one migration-chain suite; both of these two were individually
  // caught failing with this exact signature across repeated attempts).
  // Moving them here is sufficient on its own: test:component:serial fully
  // completes (via --runInBand) before test:component:parallel starts, so a
  // file in this list never runs concurrently with ANYTHING else, in either
  // group, regardless of what else remains unserialized.
  //
  // action 3: audited every other file flagged as
  // sharing this defect class, by READING each one rather than trusting the
  // earlier grep. mirrorConsistencyCheckConcurrentReorder, tenantConfigStore,
  // auditChainCircuitOpenRecovery, auditChainPoolExhaustionRecovery all call
  // the real, unmocked pgPool.runMigrations() — confirmed and added below.
  // gapScanner.rls.integration.test.js runs migrations via a SPAWNED CHILD
  // PROCESS (`spawnSync(...'src/infra/postgres/migrate.js')`, needed because
  // migration 018's GRANT BYPASSRLS requires a different role than the
  // in-process path uses) rather than calling runMigrations() directly — but
  // it executes the identical SQL against the identical cluster-wide
  // pg_authid catalog, so the race applies equally; added below.
  // replayHorizonPgUniqueness.integration.test.js calls the real
  // pgPool.runMigrations() (migrations 002/018, elevated CREATEROLE+BYPASSRLS
  // credentials) — added below. devConsentActorIdBinding.test.js was
  // FALSELY flagged's grep (which only matched the literal string
  // "runMigrations", not whether the call was real): it explicitly
  // `jest.mock('../src/infra/postgres/migrate', ...)`s AND `jest.mock('pg',
  // ...)`s, by design (its own header comment cites the
  // un-isolated-write hazard) — it never touches real PostgreSQL at all and
  // does NOT belong in this list; deliberately left in the parallel pool.
  // All 6 real additions independently reproduced concurrently (3 attempts,
  // 6 files, ≥3 distinct files caught failing with the exact "tuple
  // concurrently updated" signature) before being added here.
  //
  // test:component:serial runs this exact set with --runInBand (no worker
  // pool) so they never overlap; test:component:parallel runs everything
  // else in test/ at normal concurrency. This list is NOT read by Jest —
  // it must be kept in sync BY HAND with package.json's --testPathPatterns
  // flags. ANY NEW TEST THAT APPLIES THE MIGRATION CHAIN MUST BE ADDED TO
  // BOTH the serial script's pattern list AND this comment, or it silently
  // rejoins the parallel pool and can reintroduce the flake.
  //
  //   test/integration/migration026Idempotency.integration.test.js
  //   test/integration/retentionRoleSeparation.integration.test.js
  //   test/integration/audit-chain-distributed.integration.test.js
  //   test/integration/audit-chain-distributed-migration.integration.test.js
  //   test/integration/governanceReconciliation.integration.test.js
  //   test/persistence-recovery-durability.test.js
  //   test/integration/audit-chain-verifier-pg.integration.test.js
  //   test/dr/postgresFullCoverage.integration.test.js
  //   test/integration/consentActionSemantics.integration.test.js
  //   test/integration/alertStoreDedup.integration.test.js
  //   test/integration/mirrorConsistencyCheckConcurrentReorder.integration.test.js
  //   test/integration/tenantConfigStore.integration.test.js
  //   test/integration/auditChainCircuitOpenRecovery.integration.test.js
  //   test/integration/auditChainPoolExhaustionRecovery.integration.test.js
  //   test/integration/gapScanner.rls.integration.test.js
  //   test/integration/replayHorizonPgUniqueness.integration.test.js
  //   test/helpers/audit-chain-distributed-migration-worker.js — forked as
  //     a child process by audit-chain-distributed-migration's own test, not
  //     itself matched by Jest's testMatch (no .test.js/.spec.js suffix, not
  //     under __tests__/); listed here for completeness only — it runs
  //     inside its parent's serialized window and needs no pattern entry.
};
