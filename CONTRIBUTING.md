# Contributing

Thanks for your interest in QODIQA Gateway.

## Licence of contributions

QODIQA is licensed under the [Apache License 2.0](LICENSE). Unless you state otherwise, a contribution you submit is licensed under the same terms (section 5 of the licence).

The rest of this page describes how the project is built and checked, so that you can build it locally and understand what a change has to satisfy.

## Setting up

```bash
npm ci
npm run lint
npm run typecheck
npm run test:unit
```

Read [docs/README.md](docs/README.md) and the [developer guide](docs/development.md) first. Suites that need PostgreSQL or Redis expect disposable instances; see the developer guide. Never point a test run at a database or Redis that holds data you care about.

## How changes are made

- A change is small and focused: one logical change at a time.
- Tests are added or updated, and a test is never weakened, skipped or deleted to make a build pass.
- The HTTP contract and the SDK operation tables are generated: run `npm run openapi:generate`, `npm run sdk:generate` and `npm run docs:api-reference` after an API change; `npm run contract:check` must pass.
- Protocol test vectors under `docs/protocol/vectors/` change only together with a protocol amendment.
- Secrets, keys, `.env` files, personal data and large data files are never committed; the secret scan runs in CI.
- Documentation and code comments are in English.
- CI must pass: lint, typecheck, unit tests, the documentation checks and the secret scan.
