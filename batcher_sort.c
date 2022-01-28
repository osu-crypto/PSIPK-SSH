#include "batcher_sort.h"

// Key | Data
// |--------|
// Elem size

static void sort2(unsigned char *x, unsigned char *y, size_t elem_size, size_t key_size);

void batcher_even_odd_sort(unsigned char *array, size_t elem_size, size_t key_size, size_t n_elems)
{
    // sort_size = size of sorted chunks at start of loop.
    for (size_t sort_size = 1; sort_size < n_elems; sort_size <<= 1)
    {
        for (size_t merge_skip = sort_size; merge_skip; merge_skip >>= 1)
        {
            for (size_t chunk = 0; chunk < n_elems; chunk += 2 * sort_size)
            {
				size_t skip = merge_skip & ~sort_size;
                for (size_t merge_pos = skip; merge_pos < 2 * sort_size - skip;
                     merge_pos += 2 * merge_skip)
                {
                    for (size_t merge_start = 0; merge_start < merge_skip; merge_start++)
                    {
                        size_t i = chunk + merge_pos + merge_start;
                        size_t j = chunk + merge_pos + merge_skip + merge_start;
                        if (j >= n_elems)
                            goto done;

                        sort2(array + i * elem_size, array + j * elem_size, elem_size, key_size);
                    }
                }
            }

done:   ;
        }
    }
}

// Swap if flag. flag should be in {0,1}.
void conditional_swap(unsigned char *x, unsigned char *y, size_t size, unsigned char flag)
{
    flag = -flag;
    for (size_t i = 0; i < size; ++i)
    {
        unsigned char diff = flag & (x[i] ^ y[i]);
        x[i] ^= diff;
        y[i] ^= diff;
    }
}

static void sort2(unsigned char *x, unsigned char *y, size_t elem_size, size_t key_size)
{
    unsigned char swap = (sodium_util_compare(x, y, key_size) + 1) >> 1;
    conditional_swap(x, y, elem_size, swap);
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
