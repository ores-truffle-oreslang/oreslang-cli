#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
JAR="/tmp/atto-witness-tlc-20260811.jar"
URL="https://github.com/zactionsz/tla-tools/releases/download/tla2tools-2026.08.11.125311/tla2tools.jar"
SHA256="ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f"
command -v java >/dev/null
command -v curl >/dev/null
command -v sha256sum >/dev/null
java -version
curl --fail --location --silent --show-error --retry 2 --max-time 60 "$URL" -o "$JAR"
echo "$SHA256  $JAR" | sha256sum --check --status
echo "WITNESS_TLC_PINNED_JAR_SHA256=$SHA256"
timeout 150s java -Xmx1536m -cp "$JAR" tlc2.TLC -deadlock -workers 1 -cleanup -config WitnessProtocol.cfg WitnessProtocol.tla 2>&1 | tee witness-healthy.log
grep -Fq "Model checking completed. No error has been found." witness-healthy.log
grep -Eq "[0-9]+ states generated" witness-healthy.log
echo "WITNESS_TLC_HEALTHY=PASS"
for s in WitnessNoReserveMutant WitnessFakeFinalizeMutant; do
  echo "WITNESS_TLC_EXPECTED_BAD_MUTATION=$s"
  if timeout 150s java -Xmx1536m -cp "$JAR" tlc2.TLC -deadlock -workers 1 -cleanup -config "$s.cfg" "$s.tla" > "$s.log" 2>&1; then
    cat "$s.log"
    echo "UNSAFE_WITNESS_MUTANT_NOT_REJECTED=$s" >&2
    exit 1
  fi
  if [[ "$s" == "WitnessNoReserveMutant" ]]; then
    grep -Fq "Invariant UnfinalizedPrimaryHasReservation is violated" "$s.log"
  else
    grep -Fq "Invariant WitnessNeverAheadOfPrimary is violated" "$s.log"
  fi
  grep -Fq "Error:" "$s.log"
  echo "WITNESS_TLC_MUTATION_CAUGHT=$s"
done
echo "WITNESS_TLC_POSITIVE=1"
echo "WITNESS_TLC_NEGATIVE=2"
