#include <stdint.h>
#include <stdbool.h>

typedef void (*crypto_fn)(uint8_t*, uint8_t*, void*);

extern bool FOUT;

void pp_init(unsigned cache_sets, unsigned cache_line_shift, unsigned cache_level);
uint8_t pp(crypto_fn crypto, void *data, unsigned samples, unsigned idx);
