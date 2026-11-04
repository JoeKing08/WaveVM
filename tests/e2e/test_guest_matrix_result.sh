#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/wavevm-matrix-result.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
mkdir "$tmpdir/bin"
# Replace only the guest process boundary; exercise the actual matrix verdict.
cat >"$tmpdir/bin/timeout" <<'SH'
#!/usr/bin/env bash
for arg in "$@"; do
    case "$arg" in WVM_GUEST_SMOKE_ART=*) export "$arg";; esac
done
case "$MATRIX_FIXTURE" in
    pass) printf 'OVERALL=PASS\n' >"$WVM_GUEST_SMOKE_ART/result.txt";;
    timeout) printf 'OVERALL=PASS\n' >"$WVM_GUEST_SMOKE_ART/result.txt"; exit 124;;
    late-failure) printf 'OVERALL=PASS\nOVERALL=FAIL_cleanup\n' >"$WVM_GUEST_SMOKE_ART/result.txt";;
    missing) :;;
esac
SH
chmod +x "$tmpdir/bin/timeout"
for fixture in pass timeout late-failure missing; do
    rc=0
    PATH="$tmpdir/bin:$PATH" MATRIX_FIXTURE="$fixture" \
        WVM_GUEST_CELLS=flat_tcg WVM_GUEST_OUT_DIR="$tmpdir/$fixture" \
        bash "$repo_root/tests/e2e/test_guest_minimum_matrix.sh" \
        >"$tmpdir/$fixture.log" 2>&1 || rc=$?
    if [[ "$fixture" == pass ]]; then
        [[ "$rc" == 0 ]]
    else
        [[ "$rc" != 0 ]]
    fi
done
# A reused directory cannot preserve its previous successful result.
rc=0
PATH="$tmpdir/bin:$PATH" MATRIX_FIXTURE=missing WVM_GUEST_ALLOW_NONEMPTY_OUT=1 \
    WVM_GUEST_CELLS=flat_tcg WVM_GUEST_OUT_DIR="$tmpdir/pass" \
    bash "$repo_root/tests/e2e/test_guest_minimum_matrix.sh" \
    >"$tmpdir/reused.log" 2>&1 || rc=$?
[[ "$rc" != 0 ]]
echo 'guest matrix result: fresh PASS, timeout, final failure, missing/stale result PASS'
