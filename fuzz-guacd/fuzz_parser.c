/*
 * AFL++/libFuzzer harness for guacd's Guacamole protocol parser.
 *
 * Fuzzes guac_parser_append() — the core state machine that parses
 * Guacamole wire format data. This is the function that processes
 * all input from persea before any protocol handling occurs.
 *
 * Build with build.sh or manually:
 *   libFuzzer:  clang -fsanitize=fuzzer,address,undefined \
 *               -I. -I$GUAC/src/libguac \
 *               -o fuzz_parser fuzz_parser.c $GUAC/src/libguac/unicode.c \
 *               $GUAC/src/libguac/parser.c
 *
 *   AFL++:      afl-clang-fast -fsanitize=address,undefined \
 *               -I. -I$GUAC/src/libguac \
 *               -o fuzz_parser fuzz_parser.c $GUAC/src/libguac/unicode.c \
 *               $GUAC/src/libguac/parser.c
 *
 * Our config.h and guacamole/socket.h stubs in this directory override
 * the real ones (which need autoconf / pull in the full socket API).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Stubs for libguac internals ────────────────────────────────── */

/* guac_error / guac_error_message are macros expanding to
 * (*__guac_error()) / (*__guac_error_message()). Provide the backing
 * thread-local storage and accessor functions. */
#include "guacamole/error-types.h"

static __thread guac_status _guac_error_value = GUAC_STATUS_SUCCESS;
static __thread const char* _guac_error_message_value = "";

guac_status* __guac_error(void) {
    return &_guac_error_value;
}

const char** __guac_error_message(void) {
    return &_guac_error_message_value;
}

/* Overflow-checked multiply (PRIV_guac_mem_ckd_mul) */
int PRIV_guac_mem_ckd_mul(size_t* result, size_t factor_count,
                          const size_t* factors) {
    if (factor_count == 0) return 1;
    size_t size = factors[0];
    for (size_t i = 1; i < factor_count; i++) {
        if (factors[i] && size > SIZE_MAX / factors[i]) return 1;
        size *= factors[i];
    }
    *result = size;
    return 0;
}

/* guac_mem_alloc — the macro expands to PRIV_guac_mem_alloc() */
void* PRIV_guac_mem_alloc(size_t factor_count, const size_t* factors) {
    size_t size;
    if (PRIV_guac_mem_ckd_mul(&size, factor_count, factors)) return NULL;
    if (size == 0) size = 1;
    return malloc(size);
}

/* guac_mem_free */
void PRIV_guac_mem_free(void* ptr) {
    free(ptr);
}

/* Stubs for socket functions referenced by guac_parser_read() —
 * we don't fuzz that path but the linker needs symbols. */
typedef struct guac_socket guac_socket;
int guac_socket_select(guac_socket* socket, int usec_timeout) {
    (void)socket; (void)usec_timeout;
    return -1;
}
int guac_socket_read(guac_socket* socket, void* buf, int count) {
    (void)socket; (void)buf; (void)count;
    return -1;
}

/* ── Pull in the real parser API ─────────────────────────────────
 * We include the headers (not the .c files) — the .c files are
 * compiled separately and linked by the build script. */
#include "guacamole/parser.h"

/* ── Fuzz target ── */

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* AFL++ persistent mode */
__AFL_FUZZ_INIT();
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* Work on a mutable copy — guac_parser_append() modifies the buffer
     * (it writes NUL terminators at element boundaries). */
    char *buf = malloc(size);
    if (!buf) return 0;
    memcpy(buf, data, size);

    guac_parser* parser = guac_parser_alloc();
    if (!parser) { free(buf); return 0; }

    /* Feed the data in varying chunk sizes to exercise boundary handling */
    size_t pos = 0;
    size_t chunk = 1;
    while (pos < size) {
        size_t remaining = size - pos;
        size_t len = chunk < remaining ? chunk : remaining;

        int parsed = guac_parser_append(parser, buf + pos, (int)len);

        if (parser->state == GUAC_PARSE_ERROR) {
            /* Reset and continue to test recovery */
            guac_parser_free(parser);
            parser = guac_parser_alloc();
            if (!parser) { free(buf); return 0; }
            pos += len;
        } else if (parser->state == GUAC_PARSE_COMPLETE) {
            /* Successfully parsed an instruction — access fields to
             * trigger any potential out-of-bounds reads */
            volatile const char* op = parser->opcode;
            (void)op;
            for (int i = 0; i < parser->argc; i++) {
                volatile const char* arg = parser->argv[i];
                (void)arg;
            }
            /* Reset for next instruction */
            guac_parser_free(parser);
            parser = guac_parser_alloc();
            if (!parser) { free(buf); return 0; }
            pos += len;
        } else {
            pos += (parsed > 0) ? (size_t)parsed : len;
        }

        /* Vary chunk size: 1, 2, 4, 8, ..., 64, then back to 1 */
        chunk = (chunk >= 64) ? 1 : chunk * 2;
    }

    guac_parser_free(parser);
    free(buf);
    return 0;
}

#ifndef __AFL_FUZZ_TESTCASE_LEN
/* When not using AFL, this is a libFuzzer target (no main needed) */
#else
/* AFL persistent mode main */
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }
    return 0;
}
#endif
