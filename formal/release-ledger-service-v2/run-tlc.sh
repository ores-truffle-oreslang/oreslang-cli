#!/usr/bin/env bash
# Actual TLC model checking and two negative mutations, never source-only claims.
set -euo pipefail
cd "$(dirname "$0")"
JAR="/tmp/atto-tlc-20260811.jar"
URL="https://github.com/zactionsz/tla-tools/releases/download/tla2tools-2026.08.11.125311/tla2tools.jar"
SHA256="ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f"
command -v java >/dev/null
command -v curl >/dev/null
command -v sha256sum >/dev/null
java -version
curl --fail --location --silent --show-error --retry 2 --max-time 60 "$URL" -o "$JAR"
echo "$SHA256  $JAR" | sha256sum --check --status
test -s "$JAR"
echo "TLC_TOOL_JAR_SHA256=$SHA256"
echo "ACTUAL_TLC_HEALTHY_START"
timeout 180s java -Xmx1536m -cp "$JAR" tlc2.TLC -deadlock -workers 1 -cleanup \
  -config ReleaseLedgerChecked.cfg ReleaseLedgerChecked.tla \
  2>&1 | tee tlc-healthy.log
grep -Fq "Model checking completed. No error has been found." tlc-healthy.log
grep -Eq "[0-9]+ states generated" tlc-healthy.log
echo "ACTUAL_TLC_HEALTHY_PASS=1"
for spec in ReleaseLedgerPolicyRollbackMutant ReleaseLedgerPublishMutant; do
  echo "ACTUAL_TLC_EXPECTED_MUTANT_START=$spec"
  if timeout 180s java -Xmx1536m -cp "$JAR" tlc2.TLC -deadlock -workers 1 -cleanup \
    -config "$spec.cfg" "$spec.tla" > "$spec.log" 2>&1; then
    cat "$spec.log"
    echo "UNSAFE_MUTANT_NOT_DETECTED=$spec" >&2
    exit 1
  fi
  if [[ "$spec" == "ReleaseLedgerPolicyRollbackMutant" ]]; then
    grep -Eq "Invariant NoPolicyRollback is violated" "$spec.log"
  else
    grep -Eq "Invariant NoReleaseAuthorization is violated" "$spec.log"
  fi
  grep -Fq "Error:" "$spec.log"
  echo "ACTUAL_TLC_UNSAFE_MUTANT_CAUGHT=$spec"
done
echo "ACTUAL_TLC_POSITIVE=1"
echo "ACTUAL_TLC_NEGATIVE_MUTATIONS=2"
