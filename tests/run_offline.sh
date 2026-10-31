#!/usr/bin/env bash
# Every offline test (no NAS, no network beyond 127.0.0.1), with the current python3 and,
# when `uv python find 3.8` finds one, with Python 3.8 too (DSM 7 ships Python 3.8).
set -u
cd "$(dirname "$0")/.."
tests="offline_check config_check credentials_check incident_check push_check tls_check files_check mcp_check schema_check ioc_check onboard_check contain_check rescue_check"
pys=(python3)
if command -v uv >/dev/null 2>&1 && py38=$(uv python find 3.8 2>/dev/null) && [ -n "$py38" ]; then
  pys+=("$py38")
fi
fail=0
for py in "${pys[@]}"; do
  for t in $tests; do
    if out=$(cd tests && "$py" -E -s -B "$t.py" 2>&1); then
      echo "$out" | tail -1
    else
      echo "FAIL $t ($py):"; echo "$out" | tail -15; fail=1
    fi
  done
done
# every module compiles and the CLI answers --help without a config
for py in "${pys[@]}"; do
  "$py" -I -B -m py_compile nas/*.py || fail=1
  NAS_CONFIG= HOME="$(mktemp -d)" "$py" -I -B bin/nas --help >/dev/null || { echo "FAIL bin/nas --help ($py)"; fail=1; }
done
tests/install_check.sh || fail=1
[ $fail = 0 ] && echo "all offline tests passed (${#pys[@]} interpreter(s))"
exit $fail
