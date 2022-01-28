#ifndef BATCHER_SORT_256_H
#define BATCHER_SORT_256_H

#include <stddef.h>

void batcher_even_odd_sort(unsigned char *array, size_t elem_size, size_t key_size, size_t n_elems);
void conditional_swap(unsigned char *x, unsigned char *y, size_t size, unsigned char flag);
int sodium_util_memcmp(const void *, const void *, size_t);
int sodium_util_compare(const unsigned char *, const unsigned char *, size_t);

#endif // BATCHER_SORT_256_H
