#!/usr/bin/env bash
#
# mayhem/build.sh — builds, in order:
#   1) the SANITIZED project (libssh.a + libopenbsd-compat.a + the .o files the harnesses link) and
#      upstream's own libFuzzer harnesses from regress/misc/fuzz-harness (via its Makefile), each linked
#      twice: libFuzzer binary /mayhem/<h> and run-once reproducer /mayhem/<h>-standalone;
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
HARNESS_DIR="$SRC/regress/misc/fuzz-harness"

# The harnesses that use --wrap in upstream's Makefile to survive fatal()/ssh_packet_disconnect() (sftp_server_msg,
# sftp_client, ssh_channels, mux, session_channel_req, sshd_auth_session, ssh_client_session) are intentionally
# not built: replacing target code via the linker is against the fleet rules.
# sshconfig_fuzz (readconf.c) is a file-input target instead: readconf fatal()s (exit 255) on any bad option, and
# upstream's libFuzzer harness has no longjmp/--wrap, so it would report a crash on almost every mutation.
# agent_fuzz is linked by hand below (mayhem/agent_fuzz_reset.cc instead of upstream's agent_fuzz.o).
TARGETS="pubkey_fuzz sig_fuzz authopt_fuzz authkeys_fuzz sshsig_fuzz sshsigopt_fuzz privkey_fuzz kex_fuzz
  authfd_reply_fuzz misc_parse_fuzz hostfile_fuzz krl_fuzz"
# sntrup761 is constant-time crypto: every input takes the same path, so these two targets have a low edge count
# (~90 and ~160) by design; it does not mean the harness fails to reach the KEM code.
# Upstream's sntrup761 harnesses `#include "hash.c"` (deleted upstream in 94a78254a) and pull a C file into a
# C++ TU, so they do not compile; mayhem/sntrup761_{enc,dec}_fuzz.c are straight C ports of them.
SNTRUP_TARGETS="sntrup761_enc_fuzz sntrup761_dec_fuzz"

# Start from a pristine configure state so re-running on an already-built tree behaves like a first run.
if [ -f Makefile ]; then make distclean >/dev/null 2>&1 || true; fi
make -C "$HARNESS_DIR" clean >/dev/null 2>&1 || true
rm -f "$HARNESS_DIR"/*.o

# ---------------------------------------------------------------- 1) sanitized project + harnesses
autoreconf >/dev/null
# SanCov on the project itself (fuzzer-no-link), always, even when SANITIZER_FLAGS is empty.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
./configure CC="$CC" CFLAGS="-O1 $FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS" \
    --without-hardening --without-pam --with-sandbox=no >/dev/null
make -j"$MAYHEM_JOBS" libssh.a openbsd-compat/libopenbsd-compat.a \
    ssh-pkcs11-client.o auth-options.o auth2-pubkeyfile.o sshsig.o readconf.o ssh-sk.o >/dev/null

mkdir -p /tmp/mayhem-build
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/mayhem-build/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/mayhem-build/lsan_off.o
$CXX $FUZZ_CFLAGS -c "$SRC/mayhem/agent_fuzz_reset.cc" -o /tmp/mayhem-build/agent_fuzz_reset.o

# $1 = output suffix ('' or -standalone); $2 = engine flags / main object
build_harnesses() {
    local suffix="$1" engine="$2" extra_objs="$3"
    make -C "$HARNESS_DIR" clean >/dev/null 2>&1 || true
    rm -f "$HARNESS_DIR"/*.o
    # Upstream's Makefile hardcodes clang-19 and -lFuzzer; override the knobs, keep its link recipes.
    make -C "$HARNESS_DIR" -j"$MAYHEM_JOBS" $TARGETS agent_fuzz_helper.o sk-dummy.o ssh-sk-null.o \
        CC="$CC" CXX="$CXX" \
        CFLAGS="-D_GNU_SOURCE=1 -O1 $FUZZ_CFLAGS -Wno-unused-parameter -Wno-deprecated -I ../../.. -I ../../../openbsd-compat/include" \
        FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $engine" \
        FUZZ_LIBS="$extra_objs" \
        LIBS='$(COMMON_OBJS) -lssh -lopenbsd-compat -lcrypto -lz $(FUZZ_LIBS)' >/dev/null
    $CXX -o "$HARNESS_DIR/agent_fuzz" /tmp/mayhem-build/agent_fuzz_reset.o "$HARNESS_DIR/agent_fuzz_helper.o" \
        "$HARNESS_DIR/sk-dummy.o" "$SRC/ssh-sk.o" "$SRC/ssh-pkcs11-client.o" -L"$SRC" -L"$SRC/openbsd-compat" $FUZZ_CFLAGS $engine \
        -lssh -lopenbsd-compat -lcrypto -lz $extra_objs
    mv "$HARNESS_DIR/agent_fuzz" "$SRC/agent_fuzz$suffix"
    if [ -z "$suffix" ]; then
        # file-input target (no libFuzzer, so no -standalone twin): see the header of mayhem/sshconfig_fuzz.c
        $CC -D_GNU_SOURCE=1 -O1 $FUZZ_CFLAGS -I"$SRC" -I"$SRC/openbsd-compat" -I"$SRC/openbsd-compat/include" \
            "$SRC/mayhem/sshconfig_fuzz.c" "$SRC/readconf.o" "$HARNESS_DIR/ssh-sk-null.o" \
            "$SRC/ssh-pkcs11-client.o" /tmp/mayhem-build/lsan_off.o -L"$SRC" -L"$SRC/openbsd-compat" \
            -lssh -lopenbsd-compat -lcrypto -lz -o "$SRC/sshconfig_fuzz"
    fi
    for t in $TARGETS; do
        mv "$HARNESS_DIR/$t" "$SRC/$t$suffix"
    done
    for t in $SNTRUP_TARGETS; do
        $CC -D_GNU_SOURCE=1 -O1 $FUZZ_CFLAGS -I"$SRC" -I"$SRC/openbsd-compat" -I"$SRC/openbsd-compat/include" \
            $engine "$SRC/mayhem/$t.c" $extra_objs -L"$SRC" -L"$SRC/openbsd-compat" -lssh -lopenbsd-compat \
            -lcrypto -o "$SRC/$t$suffix"
    done
}
build_harnesses "" "$LIB_FUZZING_ENGINE" /tmp/mayhem-build/lsan_off.o
build_harnesses "-standalone" "" "/tmp/mayhem-build/standalone_main.o /tmp/mayhem-build/lsan_off.o"
make -C "$HARNESS_DIR" clean >/dev/null 2>&1 || true
rm -f "$HARNESS_DIR"/*.o

# ---------------------------------------------------------------- 2) normal project + unit tests
make distclean >/dev/null 2>&1 || true
(
    unset CFLAGS LDFLAGS CPPFLAGS
    ./configure CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" --without-pam >/dev/null
)
make -j"$MAYHEM_JOBS" >/dev/null
make -j"$MAYHEM_JOBS" regress-unit-binaries >/dev/null
