# Example / Reference KMS overlays

These overlays are **examples only** — starting references for enterprise
customers who need externally-custodied signing keys, not drop-in-ready,
fully turnkey production manifests. Every overlay in this directory:

- Bases on `../../single-node` (the default, working topology — see
  `docs/deployment/topology.md`) and only patches the container `command`, the
  `QODIQA_KMS_PROVIDER` env var, and the additional provider-specific
  config/secrets that provider requires. Nothing about the base topology,
  security context, probes, or the existing `key-encryption-key` /
  `sign-token` / etc. secrets in `base/secret.yaml` is touched.
- Adds its own, separate `Secret`/`ConfigMap` scoped to that overlay only —
  it never modifies `base/secret.yaml`, so applying the default
  `overlays/single-node/` or `overlays/distributed/` continues to work
  exactly as before, unmodified ('s "do not remove existing
  functionality" requirement).
- Still requires `key-encryption-key` from `base/secret.yaml`: per
  `src/infra/keys/keyProviderFactory.js`, `vault-transit` and `hsm` are
  *native-signing* providers (the Ed25519 private key never leaves the
  Vault/HSM boundary) but still default to the `local` KEK provider for the
  local key-store *metadata* file unless `QODIQA_KMS_KEK_PROVIDER` overrides
  it — see that file's `isNativeSigningType`/`kekType` logic. If you also
  want the KEK itself sourced from Vault/a cloud KMS, set
  `QODIQA_KMS_KEK_PROVIDER=vault-kv` (or `aws-kms`/`azure-kv`/`gcp-kms`)
  alongside `QODIQA_KMS_PROVIDER=vault-transit`/`hsm` and provide that
  provider's own credentials the same way — see `src/infra/keys/providers/`
  for each provider's required environment variables.

## Available examples

| Overlay | KMS provider | Guarantee |
|---|---|---|
| `vault-transit/` | HashiCorp Vault Transit | Private key never leaves Vault |
| `hsm/` | PKCS#11 HSM | Private key never leaves the hardware boundary |

Operational examples. They are validated by `npm run deploy:validate` like the overlays above, but none has been applied to a real cluster:

| Overlay | Adds | Finding |
|---|---|---|
| `monitoring/` | Opens the authenticated diagnostics plane. Adds a ServiceMonitor (scrapes with a dedicated viewer operator key) and a PrometheusRule whose alerts use the gateway's real metric names (SD-06 checks them). | |
| `external-secrets/` | Replaces the plaintext `qodiqa-secrets` Opaque Secret with an External Secrets Operator `ExternalSecret` that has exactly the same keys (SD-07 checks them). | |
| `tls-ingress/` | Adds an Ingress with a cert-manager certificate, SSE-safe proxy settings and a forced HTTPS redirect. It deliberately has no HPA: single-node is fixed at `replicas: 1`, and distributed is refused. | |

The previously-shipped `local` (raw env-var KEK) mode remains the default —
see `../../single-node/` / `../../distributed/` — and needs no example
overlay of its own; it already works exactly as documented in
`docs/deployment/cloud-deployment.md`.

## Usage

```bash
kubectl kustomize deploy/kubernetes/overlays/examples/vault-transit/
kubectl apply -k deploy/kubernetes/overlays/examples/vault-transit/
```

Replace every `<...>` placeholder in each overlay's `secret.yaml` and
`configmap-patch.yaml` before applying to a real cluster — see
`base/secret.yaml`'s own header comment for the general secret-handling
guidance (External Secrets Operator / Sealed Secrets / SOPS preferred over
raw `kubectl apply` of real values).

## What these overlays deliberately do NOT solve for you

- **HSM PKCS#11 library / vendor client delivery.** `hsm/statefulset-patch.yaml`
  mounts `HSM_PKCS11_LIB` from a `hostPath` by default and documents this
  inline as the part every real deployment must replace — with a custom
  image layer baking in the vendor's PKCS#11 `.so`, an init container that
  copies it from a vendor-provided volume, or your HSM vendor's own
  Kubernetes device-plugin/sidecar, depending on which HSM you're
  integrating (Thales Luna, AWS CloudHSM, SoftHSM2 for dev/test only — see
  `src/infra/keys/providers/hsm.js`'s header comment for tested
  configurations). There is no vendor-neutral way to solve this generically.
- **Vault network reachability / mTLS specifics** beyond the `VAULT_ADDR` /
  `VAULT_TLS_CA_CERT` env vars already supported by
  `src/infra/keys/providers/vault.js` — if your Vault cluster requires a
  NetworkPolicy egress rule to reach it, add one the same way
  `base/networkpolicy.yaml` already does for Redis.
