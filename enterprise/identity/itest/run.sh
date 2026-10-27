#!/usr/bin/env bash
# Integration check of enterprise identity against TEST identity providers in disposable containers (Dex for OIDC, OpenLDAP for LDAP).
# Usage: bash enterprise/identity/itest/run.sh [outdir]   (loopback ports 56931 Dex, 56932 OpenLDAP; containers $DEX / $LDAP, stopped at the end, never deleted by this script)
# Not part of the unit gate (no network containers there). Claim: "validated with a test IdP / test directory", not with a production one.
cd "$(dirname "$0")/../../.." || exit 2
OUT=${1:-./itest-out}
mkdir -p "$OUT"
HERE=enterprise/identity/itest
RC=0
export MSYS_NO_PATHCONV=1      # Git Bash on Windows would rewrite /etc/dex/... and /tmp/... arguments
STAMP=$(date +%s)
DEX=qodiqa-itest-dex-$STAMP
LDAP=qodiqa-itest-ldap-$STAMP     # unique names: containers are stopped at the end, never deleted (they are kept until the owner removes them)
{
  echo "### $(date -u +%FT%TZ) start"
  docker create --name $DEX -p 127.0.0.1:56931:5556 dexidp/dex:v2.41.1 dex serve /etc/dex/config.yaml > /dev/null
  docker cp "$HERE/dex-config.yaml" $DEX:/etc/dex/config.yaml
  docker start $DEX > /dev/null
  docker run -d --name $LDAP -p 127.0.0.1:56932:389 -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.org -e LDAP_ADMIN_PASSWORD=itest-admin-password osixia/openldap:1.5.0 > /dev/null
  for i in $(seq 1 40); do curl -sf http://127.0.0.1:56931/dex/.well-known/openid-configuration > /dev/null && break; sleep 2; done
  for i in $(seq 1 40); do docker exec $LDAP ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w itest-admin-password > /dev/null 2>&1 && break; sleep 2; done
  docker cp "$HERE/users.ldif" $LDAP:/tmp/users.ldif
  docker exec $LDAP ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w itest-admin-password -f /tmp/users.ldif
  echo "### dex"
  node "$HERE/dex.itest.js" || RC=1
  echo "### openldap"
  node "$HERE/openldap.itest.js" || RC=1
  docker stop $DEX $LDAP > /dev/null
  echo "### $(date -u +%FT%TZ) end rc=$RC"
} > "$OUT/idp-itest.txt" 2>&1
tail -n 30 "$OUT/idp-itest.txt"
exit $RC
