#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: bash scripts/build-pam-gate.sh OUTPUT.so' >&2; exit 1; }
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cc -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror -fPIC \
  -fstack-protector-strong -D_FORTIFY_SOURCE=3 -shared \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  "$source_root/pam/pam_omarchy_fallback.c" -lpam -o "$1"
