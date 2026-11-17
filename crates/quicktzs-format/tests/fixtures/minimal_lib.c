#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef struct { uint8_t tag; int64_t int_; const uint8_t *ptr; size_t len; } TpVal;
/* NOTE: the Rust field is named `int`; C layout is identical. */

static const uint8_t LFNT[] = {
  'L','F','N','T', 2,0,
  0,0, 2, 1, 3,'a','d','d',
  1,0, 1, 2, 5,'u','p','p','e','r'
};

uint32_t tunpak_abi_version(void) { return 1; }

const uint8_t *tunpak_lfnt(size_t *len_out) { *len_out = sizeof LFNT; return LFNT; }

int32_t tunpak_call(uint16_t fn_id, const TpVal *args, uint8_t argc, TpVal *ret) {
  ret->tag = 0; ret->int_ = 0; ret->ptr = NULL; ret->len = 0;
  if (fn_id == 0 && argc == 2 && args[0].tag == 1 && args[1].tag == 1) {
    ret->tag = 1; ret->int_ = args[0].int_ + args[1].int_; return 0;
  }
  if (fn_id == 1 && argc == 1 && args[0].tag == 2) {
    uint8_t *p = malloc(args[0].len ? args[0].len : 1);
    if (!p) return 1;
    for (size_t i = 0; i < args[0].len; i++) {
      uint8_t c = args[0].ptr[i];
      p[i] = (c >= 'a' && c <= 'z') ? (uint8_t)(c - 32) : c;
    }
    ret->tag = 2; ret->ptr = p; ret->len = args[0].len; return 0;
  }
  return 2;
}

void tunpak_free(uint8_t *ptr, size_t len) { (void)len; free(ptr); }
