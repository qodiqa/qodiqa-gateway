# Licence texts shipped with the QODIQA image

| File | Covers | Source / verification |
|---|---|---|
| `Apache-2.0.txt` | The vendored base model `Xenova/all-MiniLM-L6-v2` and QODIQA's modified derivatives FT-2/FT-3 (`MODEL-PROVENANCE.md`); Apache-2.0 npm dependencies (each also ships its own copy in `node_modules`) | Byte-identical to the canonical text (sha256 `cfc7749b96f6…`), copied from `node_modules/@xenova/transformers/LICENSE` |
| `LGPL-3.0.txt` | libvips 8.18.6 (`@img/sharp-libvips-linux-x64`, a dynamically loaded `.so`) and `@img/sharp-wasm32` (`licenses/THIRD-PARTY.md`) | Canonical GNU text, sha256 `a853c2ffec17…` |
| `GPL-3.0.txt` | Incorporated by reference by LGPL-3.0 | Canonical GNU text, sha256 `3972dc9744f6…` |

QODIQA's own code: `../LICENSE` (Apache-2.0).
Datasets: `../DATASET-LICENSES.md`. Not legal advice.
