/* decompress(buf) -> buf as an identity function: stands in for zstd in the unpacker test. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t tag; int64_t int_; const uint8_t *ptr; size_t len; } TpVal;

static const uint8_t LFNT[] = { 'L','F','N','T', 1,0, 0,0, 1, 3, 10,'d','e','c','o','m','p','r','e','s','s' };

uint32_t qtz_abi_version(void) { return 1; }
const uint8_t *qtz_lfnt(size_t *len_out) { *len_out = sizeof LFNT; return LFNT; }

int32_t qtz_call(uint16_t fn_id, const TpVal *args, uint8_t argc, TpVal *ret) {
    ret->tag = 0; ret->int_ = 0; ret->ptr = NULL; ret->len = 0;
    if (fn_id == 0 && argc == 1 && args[0].tag == 3) {
        uint8_t *p = malloc(args[0].len ? args[0].len : 1);
        if (!p) return 1;
        memcpy(p, args[0].ptr, args[0].len);
        ret->tag = 3; ret->ptr = p; ret->len = args[0].len; return 0;
    }
    return 2;
}

void qtz_free(uint8_t *ptr, size_t len) { (void)len; free(ptr); }
