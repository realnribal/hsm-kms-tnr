#!/usr/bin/env bash
# Initialize the lab SoftHSM2 token. Safe to re-run. Does not print PINs.
# Sourced by run-campaign.sh and by the container entrypoint so the
# variables stay in the calling shell.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_DIR="$ROOT/.softhsm/tokens"
CONF="$ROOT/.softhsm/softhsm2.conf"

mkdir -p "$TOKEN_DIR"
chmod 700 "$TOKEN_DIR"

cat > "$CONF" <<EOF
directories.tokendir = ${TOKEN_DIR}
objectstore.backend = file
log.level = ERROR
EOF

export SOFTHSM2_CONF="$CONF"
export HSM_TOKEN_LABEL="${HSM_TOKEN_LABEL:-kms-token}"
export HSM_PIN="${HSM_PIN:-tnr-user-pin-7f3a}"
export HSM_SO_PIN="${HSM_SO_PIN:-tnr-so-pin-7f3a}"
export KMS_API_KEY="${KMS_API_KEY:-lab-api-key-7f3a}"

if [[ -z "${HSM_LIBRARY:-}" ]]; then
  for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so
  do
    if [[ -f "$candidate" ]]; then
      HSM_LIBRARY="$candidate"
      break
    fi
  done
fi

if [[ -z "${HSM_LIBRARY:-}" || ! -f "$HSM_LIBRARY" ]]; then
  echo "SoftHSM2 library not found. Install softhsm2 or set HSM_LIBRARY." >&2
  exit 1
fi
export HSM_LIBRARY

lib_dir="$(dirname "$HSM_LIBRARY")"
case ":${LD_LIBRARY_PATH:-}:" in
  *":${lib_dir}:"*) ;;
  *) export LD_LIBRARY_PATH="${lib_dir}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
esac

if softhsm2-util --show-slots | grep -Eq "^[[:space:]]*Label:[[:space:]]*${HSM_TOKEN_LABEL}[[:space:]]*$"; then
  echo "SoftHSM token '${HSM_TOKEN_LABEL}' already present"
else
  softhsm2-util --init-token --free \
    --label "$HSM_TOKEN_LABEL" \
    --pin "$HSM_PIN" \
    --so-pin "$HSM_SO_PIN" >/dev/null
  echo "SoftHSM token '${HSM_TOKEN_LABEL}' initialized"
fi

mkdir -p "$ROOT/.softhsm"
softhsm2-util --show-slots > "$ROOT/.softhsm/show-slots.txt" || true
{
  echo "library=${HSM_LIBRARY}"
  echo "token=${HSM_TOKEN_LABEL}"
  softhsm2-util --version 2>&1 || true
  dpkg -s softhsm2 2>/dev/null | grep '^Version:' || true
} > "$ROOT/.softhsm/runtime.txt"

cat > "$ROOT/.softhsm/env" <<EOF
export SOFTHSM2_CONF=$(printf '%q' "$SOFTHSM2_CONF")
export HSM_LIBRARY=$(printf '%q' "$HSM_LIBRARY")
export HSM_TOKEN_LABEL=$(printf '%q' "$HSM_TOKEN_LABEL")
export HSM_PIN=$(printf '%q' "$HSM_PIN")
export HSM_SO_PIN=$(printf '%q' "$HSM_SO_PIN")
export KMS_API_KEY=$(printf '%q' "$KMS_API_KEY")
export LD_LIBRARY_PATH=$(printf '%q' "$LD_LIBRARY_PATH")
EOF

echo "library=${HSM_LIBRARY}"
