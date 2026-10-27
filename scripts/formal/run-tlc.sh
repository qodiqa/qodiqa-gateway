#!/usr/bin/env bash
# model-check the TLA+ specifications in docs/formal with TLC.
#   bash scripts/formal/run-tlc.sh            run every spec: the real configuration must PASS, the *.negative.cfg must FAIL (violation found)
# TLC runs in a container (eclipse-temurin JRE) so no Java is needed on the host; tla2tools.jar is downloaded once into
# scripts/formal/.cache (untracked) and checked against the pinned SHA-256 below. Output of each run goes to evidence/formal/.
set -u
cd "$(dirname "$0")/../.." || exit 2
TLA_VERSION=v1.8.0
TLA_URL="https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
TLA_SHA256="${TLA_SHA256_PIN:-}"          # filled in from the first verified download (see docs/formal/README.md)
CACHE=scripts/formal/.cache
OUT=evidence/formal
IMAGE=${TLC_IMAGE:-eclipse-temurin:21-jre}
mkdir -p "$CACHE" "$OUT"
if [ ! -s "$CACHE/tla2tools.jar" ]; then
  echo "downloading $TLA_URL"
  curl -fsSL -o "$CACHE/tla2tools.jar" "$TLA_URL" || { echo "download failed"; exit 2; }
fi
GOT=$(sha256sum "$CACHE/tla2tools.jar" | cut -d' ' -f1)
echo "tla2tools.jar sha256 $GOT"
if [ -n "$TLA_SHA256" ] && [ "$GOT" != "$TLA_SHA256" ]; then echo "SHA-256 mismatch against the pin"; exit 2; fi
fail=0
for spec in Lifecycle Nonce DelegationChain ActionChain; do
  for kind in "" ".negative"; do
    cfg="docs/formal/${spec}${kind}.cfg"
    log="$OUT/${spec}${kind}.log"
    MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/w" -w /w/docs/formal "$IMAGE" \
      java -XX:+UseParallelGC -cp /w/$CACHE/tla2tools.jar tlc2.TLC -workers auto -deadlock -metadir /tmp/tlcstates -noGenerateSpecTE -config "${spec}${kind}.cfg" "${spec}.tla" > "$log" 2>&1
    rc=$?
    states=$(grep -Eo '[0-9]+ distinct states found' "$log" | tail -1)
    if [ -z "$kind" ]; then
      if grep -q "Model checking completed. No error has been found" "$log"; then echo "PASS  $spec  ($states)"; else echo "FAIL  $spec  (rc=$rc, see $log)"; fail=1; fi
    else
      if grep -q "is violated" "$log"; then echo "PASS  $spec negative control: violation found as expected"; else echo "FAIL  $spec negative control: no violation found (the check proves nothing) rc=$rc"; fail=1; fi
    fi
  done
done
exit $fail
