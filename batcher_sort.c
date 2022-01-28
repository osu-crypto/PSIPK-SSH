#include "batcher_sort.h"

#include <string.h>
#include <stdbool.h>

void batcher_even_odd_sort(u_char *array, size_t elem_size, size_t key_size, size_t n_elems);
{
}

void conditional_swap(u_char *x, u_char *y, size_t size, u_char flag)
{
    flag = -flag;
    for (size_t i = 0; i < size; ++i)
        x[i] ^= flag & (x[i] ^ y[i]);
}


// Copied from libsodium util.c

int
sodium_util_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
    size_t               i;
    unsigned char        d = (unsigned char) 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

int
sodium_util_compare(const unsigned char *b1_, const unsigned char *b2_, size_t len)
{
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
    unsigned char gt = 0U;
    unsigned char eq = 1U;
    size_t        i;

    i = len;
    while (i != 0U) {
        i--;
        gt |= ((b2[i] - b1[i]) >> 8) & eq;
        eq &= ((b2[i] ^ b1[i]) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}
