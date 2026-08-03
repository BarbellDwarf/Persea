#!/usr/bin/env bash
#
# Build the guacd parser fuzzer.
#
# Usage:
#   ./build.sh              # build with libFuzzer (default)
#   ./build.sh afl          # build with AFL++
#   ./build.sh standalone   # build a standalone test binary (no fuzzer)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUAC_SRC="${SCRIPT_DIR}/../../guacamole-server/src/libguac"

if [ ! -f "${GUAC_SRC}/parser.c" ]; then
    echo "ERROR: guacamole-server source not found at ${GUAC_SRC}" >&2
    echo "Expected: ../guacamole-server relative to persea root" >&2
    exit 1
fi

MODE="${1:-libfuzzer}"
SANITIZERS="-fsanitize=address,undefined"
# Include our stubs first (-I.) so config.h and guacamole/socket.h
# resolve to our minimal stubs before the real guacamole-server headers.
INCLUDES="-I${SCRIPT_DIR} -I${GUAC_SRC}"
CFLAGS="-g -O1 ${SANITIZERS} ${INCLUDES}"

SOURCES=(
    "${SCRIPT_DIR}/fuzz_parser.c"
    "${GUAC_SRC}/parser.c"
    "${GUAC_SRC}/unicode.c"
)

case "${MODE}" in
    libfuzzer)
        echo "Building with libFuzzer..."
        CC="${CC:-clang}"
        $CC ${CFLAGS} -fsanitize=fuzzer "${SOURCES[@]}" -o "${SCRIPT_DIR}/fuzz_parser"
        echo "Built: ${SCRIPT_DIR}/fuzz_parser"
        echo "Run:   ${SCRIPT_DIR}/fuzz_parser ${SCRIPT_DIR}/corpus/"
        ;;
    afl)
        echo "Building with AFL++..."
        CC="${CC:-afl-clang-fast}"
        $CC ${CFLAGS} -DAFL_MODE "${SOURCES[@]}" -o "${SCRIPT_DIR}/fuzz_parser_afl"
        echo "Built: ${SCRIPT_DIR}/fuzz_parser_afl"
        echo "Run:   afl-fuzz -i ${SCRIPT_DIR}/corpus/ -o ${SCRIPT_DIR}/findings/ -- ${SCRIPT_DIR}/fuzz_parser_afl"
        ;;
    standalone)
        # Build a standalone binary that reads from stdin — useful for
        # reproducing crashes without a fuzzer installed.
        echo "Building standalone test binary..."
        CC="${CC:-clang}"
        cat > /tmp/fuzz_standalone_main.c <<'MAIN_EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); continue; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *buf = malloc(sz);
        fread(buf, 1, sz, f);
        fclose(f);
        printf("Testing %s (%ld bytes)... ", argv[i], sz);
        LLVMFuzzerTestOneInput(buf, sz);
        printf("OK\n");
        free(buf);
    }
    return 0;
}
MAIN_EOF
        $CC ${CFLAGS} /tmp/fuzz_standalone_main.c "${SOURCES[@]}" \
            -o "${SCRIPT_DIR}/fuzz_parser_standalone"
        rm /tmp/fuzz_standalone_main.c
        echo "Built: ${SCRIPT_DIR}/fuzz_parser_standalone"
        echo "Run:   ${SCRIPT_DIR}/fuzz_parser_standalone corpus/*.raw"
        ;;
    *)
        echo "Usage: $0 [libfuzzer|afl|standalone]" >&2
        exit 1
        ;;
esac
