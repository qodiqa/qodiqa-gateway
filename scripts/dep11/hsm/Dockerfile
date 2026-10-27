# SoftHSM2 (PKCS#11 v3.0, CKM_EDDSA) + pkcs11js for running src/infra/keys/providers/hsm.js
# against a local software HSM. Development/test only. The repository is bind-mounted read-only at /repo at run time;
# nothing from the repo is baked into the image.
FROM node:22-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc && rm -rf /var/lib/apt/lists/*
WORKDIR /hsm
RUN npm init -y >/dev/null && npm install --no-audit --no-fund pkcs11js@2.1.7
ENV NODE_PATH=/hsm/node_modules SOFTHSM2_CONF=/hsm/softhsm2.conf
RUN mkdir -p /hsm/tokens && printf 'directories.tokendir = /hsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /hsm/softhsm2.conf
