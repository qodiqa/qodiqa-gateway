# Terraform module `qodiqa`

Installs the QODIQA Helm chart (`deploy/helm/qodiqa`) into a cluster, optionally creating the namespace (Pod Security `restricted`) and the Secret. It does **not** create the
database, Redis, the MAC keyring or TLS material: bring those (the chart documents their names). Status: tested and verified internally (`terraform validate`, an apply against a
kind cluster); not published.

```hcl
module "qodiqa" {
  source          = "./modules/qodiqa"
  chart_path      = "../helm/qodiqa"
  image           = { repository = "registry.example.com/qodiqa", digest = "sha256:..." }
  postgres        = { host = "pg.internal" }
  redis           = { url = "rediss://redis.internal:6380" }
  existing_secret = "qodiqa-secrets"
}
```

`secret_values` writes the secrets into Terraform state: protect the state, or prefer `existing_secret` managed by your secret manager.
