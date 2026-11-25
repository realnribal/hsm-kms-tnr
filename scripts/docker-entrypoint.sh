#!/usr/bin/env bash
set -euo pipefail
cd /app
mode="${1:-campaign}"
case "$mode" in
  campaign)
    exec /app/scripts/run-campaign.sh
    ;;
  api)
    # shellcheck source=/dev/null
    source /app/scripts/init-token.sh
    exec java -jar /app/kms-api/target/kms-api.jar
    ;;
  *)
    exec "$@"
    ;;
esac
