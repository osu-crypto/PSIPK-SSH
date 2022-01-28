#ifndef BATCHER_SORT_256_H
#define BATCHER_SORT_256_H

#include "config.h"
#include "defines.h"

void batcher_even_odd_sort(u_char *array, size_t elem_size, size_t key_size, size_t n_elems);
void conditional_swap(u_char *x, u_char *y, size_t size, u_char flag);
int sodium_util_memcmp(const void *, const void *, size_t);
int sodium_util_compare(const unsigned char *, const unsigned char *, size_t);

#endif // BATCHER_SORT_256_H
