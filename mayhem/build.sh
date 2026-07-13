#!/usr/bin/env bash
#
# mayhem/build.sh — build ACL's fuzz targets, the acl_compressor tool, and the unit test suite.
#
# Produces:
#   /mayhem/fuzz_hash32               libFuzzer harness (sanitized, DWARF-3)
#   /mayhem/fuzz_hash32-standalone    run-once reproducer (no libFuzzer runtime)
#   /mayhem/build-fuzz/tools/acl_compressor/main_generic/acl_compressor   sanitized file-input CLI target
#   /mayhem/build-tests/...           unit test suite (normal flags) for mayhem/test.sh
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# CI's build context has only gitlinks for submodules — fetch them at image-build time.
# On an offline re-run they are already checked out, so this is a no-op.
if [ ! -f external/rtm/includes/rtm/math.h ]; then
    git submodule update --init external/rtm external/sjson-cpp external/catch2
fi

INCLUDES="-I$SRC/includes -I$SRC/external/rtm/includes -I$SRC/external/sjson-cpp/includes"

# 1) Sanitized build of the acl_compressor tool (the acl-compressor Mayhem target).
#    ACL is header-only, so instrumenting the tool instruments the library code it exercises.
cmake -B build-fuzz \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DBUILD_BENCHMARK_EXE=false
cmake --build build-fuzz --target acl_compressor -j"$MAYHEM_JOBS"

# 2) hash32 libFuzzer harness: fuzzer binary + standalone run-once reproducer.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -std=c++14 $INCLUDES \
    "$SRC/mayhem/fuzz_hash32.cpp" -o /mayhem/fuzz_hash32
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++14 $INCLUDES \
    "$SRC/mayhem/fuzz_hash32.cpp" /tmp/standalone_main.o -o /mayhem/fuzz_hash32-standalone

# 3) Unit test suite (Catch2 via ctest), built with the project's NORMAL flags —
#    an independent, clean build that mayhem/test.sh only RUNS.
cmake -B build-tests \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DBUILD_BENCHMARK_EXE=false
cmake --build build-tests --target acl_unit_tests -j"$MAYHEM_JOBS"

echo "build.sh: done"
