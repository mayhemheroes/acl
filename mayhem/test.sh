#!/usr/bin/env bash
#
# mayhem/test.sh — RUN ACL's own Catch2 unit test suite (built by mayhem/build.sh into
# build-tests/) and assert its reported Catch2 summary output. Does NOT compile anything.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/build-tests/bin/acl_unit_tests"
[ -x "$RUNNER" ] || RUNNER="$(find "$SRC/build-tests" -name acl_unit_tests -type f -perm -u+x | head -1)"
if [ -z "$RUNNER" ] || [ ! -x "$RUNNER" ]; then
  echo "ERROR: acl_unit_tests runner not found — mayhem/build.sh must build it first" >&2
  emit_ctrf "cmake-ctest" 0 1 0
  exit 1
fi

# Run the Catch2 runner directly and assert on its REPORTED output (test-case and assertion
# counts), not just its exit code — a neutered exit(0) binary produces no summary and fails here.
out="$("$RUNNER" 2>&1)"
rc=$?
echo "$out" | tail -10

# Catch2 success: "All tests passed (NNN assertions in MM test cases)"
passed="$(echo "$out" | sed -n -E 's/.*All tests passed \(([0-9]+) assertions in ([0-9]+) test cases?\).*/\2/p' | tail -1)"
asserts="$(echo "$out" | sed -n -E 's/.*All tests passed \(([0-9]+) assertions in ([0-9]+) test cases?\).*/\1/p' | tail -1)"
if [ -n "$passed" ] && [ -n "$asserts" ] && [ "$asserts" -gt 0 ] && [ "$passed" -gt 0 ]; then
  emit_ctrf "catch2" "$passed" 0 0
  exit $?
fi

# Catch2 failure: "test cases: N | P passed | F failed"
total="$(echo "$out" | sed -n -E 's/^test cases:\s*([0-9]+).*/\1/p' | tail -1)"
failed="$(echo "$out" | sed -n -E 's/^test cases:.*\|\s*([0-9]+) failed.*/\1/p' | tail -1)"
if [ -n "$total" ]; then
  failed="${failed:-0}"
  passed=$(( total - failed ))
  [ "$failed" -gt 0 ] || failed=1   # summary without "All tests passed" must not report clean
  emit_ctrf "catch2" "$passed" "$failed" 0
  exit $?
fi

echo "ERROR: could not parse Catch2 summary (runner rc=$rc) — treating as failure" >&2
emit_ctrf "catch2" 0 1 0
exit 1
