#!/usr/bin/env bash
# Run the full TNR campaign: token, C tests, JUnit, HTML report.
# Exit status is non-zero if any in-scope requirement is not PASS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=init-token.sh
source "$ROOT/scripts/init-token.sh"

if [[ -z "${JAVA_HOME:-}" && -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
  export PATH="$JAVA_HOME/bin:$PATH"
fi

mkdir -p "$ROOT/reports/history" "$ROOT/site" "$ROOT/kms-api/target/tnr" "$ROOT/native/build"

echo "== C PKCS#11 campaign =="
if [[ -z "${CC:-}" ]] && command -v gcc >/dev/null 2>&1; then
  export CC=gcc
fi
set +e
cmake -S "$ROOT/native" -B "$ROOT/native/build"
CMAKE_RC=$?
if [[ $CMAKE_RC -eq 0 ]]; then
  cmake --build "$ROOT/native/build"
  CMAKE_RC=$?
fi
C_RC=$CMAKE_RC
if [[ $CMAKE_RC -eq 0 ]]; then
  "$ROOT/native/build/pkcs11_campaign" --junit "$ROOT/native/build/c-junit.xml" \
    | tee "$ROOT/native/build/c-campaign.log"
  C_RC=${PIPESTATUS[0]}
fi
set -e

# Maven Central answers 429 when two runners resolve the same parent POM at once.
mvn_retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    echo "mvn failed (attempt ${attempt}), waiting $((attempt * 20))s"
    sleep $((attempt * 20))
  done
  return 1
}

echo "== Java TNR campaign =="
set +e
(cd "$ROOT/kms-api" && mvn_retry mvn -B test)
MVN_RC=$?
set -e

echo "== HTML report =="
set +e
(cd "$ROOT/kms-api" && mvn_retry mvn -B -DskipTests compile exec:java \
  -Dexec.classpathScope=compile \
  -Dexec.mainClass=io.github.realnribal.hsmkms.tools.TnrReportGenerator \
  -Dexec.args="$ROOT")
GEN_RC=$?
set -e

echo "C=${C_RC} Java=${MVN_RC} Report=${GEN_RC}"
echo "Report: $ROOT/site/index.html"
if [[ $C_RC -ne 0 || $MVN_RC -ne 0 || $GEN_RC -ne 0 ]]; then
  exit 1
fi
