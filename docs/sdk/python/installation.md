# Python SDK — Installation

## Supported Python versions

`qodiqa` requires **Python 3.9 or later**
([`sdk/python/pyproject.toml`](../../../sdk/python/pyproject.toml),
`requires-python = ">=3.9"`), and is classified (tested) through Python 3.13:

```
Programming Language :: Python :: 3.9
Programming Language :: Python :: 3.10
Programming Language :: Python :: 3.11
Programming Language :: Python :: 3.12
Programming Language :: Python :: 3.13
```

## Installation

> **Publication status: not verified.** Whether `qodiqa` is published to PyPI
> has not been verified for this release (this repository's release process
> does not publish it, and nothing here was checked against the index). The
> supported path is to **install it from this repository**:
>
> ```bash
> pip install /path/to/qodiqa/sdk/python          # or: pip install -e sdk/python
> ```
>
> `pip install qodiqa` below applies only once a published distribution exists.

```bash
pip install qodiqa
```

### Runtime dependencies

The SDK has two runtime dependencies (`[project].dependencies` in
`pyproject.toml`):

- **`httpx>=0.25.0`** — backs both `HttpClient` (sync, `httpx.Client`) and
  `AsyncHttpClient` (async, `httpx.AsyncClient`) in
  [`sdk/python/qodiqa/_http.py`](../../../sdk/python/qodiqa/_http.py);
- **`cryptography>=41`** — Ed25519 signature verification for local (offline)
  artifact and transparency-proof verification.

Installing the package pulls both in automatically — no separate install step
is required.

### Development / optional dependencies

Declared under `[project.optional-dependencies].dev` in `pyproject.toml`:

```bash
pip install -e ".[dev]"
```

Installs: `pytest>=7.4`, `pytest-asyncio>=0.23`, `pytest-httpx>=0.30`,
`anyio[trio]>=4.0`, `mypy>=1.8`.

## Typing

The package ships a `py.typed` marker
([`sdk/python/qodiqa/py.typed`](../../../sdk/python/qodiqa/py.typed)), so type
checkers (mypy, pyright) pick up its type hints automatically — no separate
stub package is needed. `pyproject.toml` configures `mypy --strict` for the
package itself. Response shapes are defined as `TypedDict`s in
[`sdk/python/qodiqa/models.py`](../../../sdk/python/qodiqa/models.py); see
[api.md](api.md#17-typed-models) for the full list.

## Verifying the install

```bash
python -c "import qodiqa; print(qodiqa.__version__)"
# => 1.0.0
```

## Building from source / running tests

```bash
cd sdk/python
pip install -e ".[dev]"
python -m pytest
```

Test configuration (`[tool.pytest.ini_options]` in `pyproject.toml`):
`asyncio_mode = "auto"` (so `async def test_...` functions run without an
explicit `@pytest.mark.asyncio` decorator), `testpaths = ["tests"]`.

## Next steps

- [configuration.md](configuration.md) — every `ClientConfig` field and its default
- [api.md](api.md) — full API reference
- [examples.md](examples.md) — runnable examples for sync/async usage, FastAPI, Flask, and Django
