#!/usr/bin/env bash
#
# mayhem/test.sh — RUN upstream's own unit tests (regress/unittests, built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Upstream's unit tests (the same list as `make -C regress unit`). Each binary ends its output with
# "<N> tests ok"; that summary is parsed so a neutered or crashing binary (no summary) counts as failed.
UT="$SRC/regress/unittests"
passed=0 failed=0
run_ut() {
  local name="$1"; shift
  local bin="$UT/$name/test_$name" out n rc
  if [ ! -x "$bin" ]; then echo "MISSING test binary $bin (build.sh must build it)" >&2; failed=$((failed+1)); return; fi
  out="$("$bin" "$@" 2>&1)"; rc=$?
  n="$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) tests ok$/\1/p' | tail -n1)"
  if [ "$rc" -eq 0 ] && [ -n "$n" ] && [ "$n" -gt 0 ]; then
    echo "ok   test_$name: $n tests"; passed=$((passed+n))
  else
    echo "FAIL test_$name (rc=$rc)"; printf '%s\n' "$out" | tail -n 15; failed=$((failed+1))
  fi
}
run_ut sshbuf
run_ut sshkey -d "$UT/sshkey/testdata"
run_ut sshsig -d "$UT/sshsig/testdata"
run_ut authopt -d "$UT/authopt/testdata"
run_ut bitmap
run_ut conversion
run_ut kex
run_ut hostkeys -d "$UT/hostkeys/testdata"
run_ut match
run_ut misc
run_ut servconf
run_ut crypto -d "$UT/crypto/testdata"

emit_ctrf "openssh-unittests" "$passed" "$failed" 0
