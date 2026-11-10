#!/usr/bin/env bash
#
# mayhem/build.sh — builds, in order:
#   1) the SANITIZED project (libssh.a + libopenbsd-compat.a + the sftp client objects) and the sftp_ls_fuzz
#      harness, linked twice: libFuzzer binary /mayhem/sftp_ls_fuzz and run-once reproducer
#      /mayhem/sftp_ls_fuzz-standalone;
#   2) the project again with NORMAL flags, plus upstream's unit-test binaries, for mayhem/test.sh.
# Runs in /mayhem as `mayhem`, offline (everything comes from the image's apt packages + the tree).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Mining branch: one harness, sftp_ls_fuzz (mayhem/sftp_ls_fuzz.c), which compiles sftp.c into its own translation
# unit (mayhem/usergroup_reset.c wraps sftp-usergroup.c) and links the sanitized sftp client objects + libssh.a.

# Start from a pristine configure state so re-running on an already-built tree behaves like a first run.
if [ -f Makefile ]; then make distclean >/dev/null 2>&1 || true; fi

# ---------------------------------------------------------------- 1) sanitized project + harness
autoreconf >/dev/null
# SanCov on the project itself (fuzzer-no-link), always, even when SANITIZER_FLAGS is empty.
# -fno-sanitize=function: glob.c calls its readdir/lstat/stat hooks through pointers of a different function type
# than the one they are declared with (fudge_readdir), so UBSan's function check fires on every multi-entry glob.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=function"
./configure CC="$CC" CFLAGS="-O1 $FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS" \
    --without-hardening --without-pam --without-libedit --with-sandbox=no >/dev/null
make -j"$MAYHEM_JOBS" libssh.a openbsd-compat/libopenbsd-compat.a \
    sftp-common.o sftp-client.o sftp-glob.o progressmeter.o >/dev/null

mkdir -p /tmp/mayhem-build
# FIX-era fix-up: upstream's change to sdirent_comp() (sftp.c) at that commit uses `as`/`bs`, which that function
# does not declare, so sftp.c does not compile. Blank those two lines in the copy the harness includes (a no-op
# on BASE); #line keeps backtraces on /mayhem/sftp.c with unchanged line numbers.
{
    printf '#line 1 "%s/sftp.c"\n' "$SRC"
    sed '/^sdirent_comp(/,/^}/{/as == NULL || bs == NULL/s/.*//;/return (as == bs)/s/.*//}' "$SRC/sftp.c"
} > /tmp/mayhem-build/sftp_unit.c
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/mayhem-build/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/mayhem-build/lsan_off.o

# $1 = output suffix ('' or -standalone); $2 = engine flags / main object
build_harness() {
    local suffix="$1" engine="$2"
    $CC -D_GNU_SOURCE=1 -O1 $FUZZ_CFLAGS -Wno-unused-function -I/tmp/mayhem-build -I"$SRC" -I"$SRC/openbsd-compat" \
        -I"$SRC/openbsd-compat/include" $engine "$SRC/mayhem/sftp_ls_fuzz.c" \
        "$SRC/mayhem/usergroup_reset.c" \
        sftp-common.o sftp-client.o sftp-glob.o progressmeter.o /tmp/mayhem-build/lsan_off.o \
        -L"$SRC" -L"$SRC/openbsd-compat" -lssh -lopenbsd-compat -lcrypto -lz -lpthread \
        -o "$SRC/sftp_ls_fuzz$suffix"
}
build_harness "" "$LIB_FUZZING_ENGINE"
build_harness "-standalone" "/tmp/mayhem-build/standalone_main.o"

# ---------------------------------------------------------------- 2) normal project + unit tests
make distclean >/dev/null 2>&1 || true
(
    unset CFLAGS LDFLAGS CPPFLAGS
    ./configure CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" --without-pam >/dev/null
)
# (only the unit-test binaries: they do not need ssh/sftp, and sftp.c does not compile at FIX)
make -j"$MAYHEM_JOBS" regress-unit-binaries >/dev/null
