#include "rijndael256.h"

#include <string.h>
#include <stdbool.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>


// This implement's Rijndael256 RotateRows step, then cancels out the RotateRows of AES so
// that AES-NI can be used to implement Rijndael256.
static inline void rotateRows256Undo128(__m128i state[2], bool encrypt) {
	// Swapping bytes between 128-bit halves is equivalent to rotating left overall, then
	// rotating right within each half. Decrypt is the same idea, but with reverse shifts.
	__m128i mask;
	if (encrypt)
	{
		mask = _mm_setr_epi8(0, -1, -1, -1,
		                     0,  0, -1, -1,
		                     0,  0, -1, -1,
		                     0,  0,  0, -1);
	}
	else
	{
		mask = _mm_setr_epi8(0,  0,  0, -1,
		                     0,  0, -1, -1,
		                     0,  0, -1, -1,
		                     0, -1, -1, -1);
	}
	__m128i b0_blended = _mm_blendv_epi8(state[0], state[1], mask);
	__m128i b1_blended = _mm_blendv_epi8(state[1], state[0], mask);

	// The rotations for 128-bit AES are different, so rotate within the halves to
	// match.
	__m128i perm;
	if (encrypt)
	{
		perm = _mm_setr_epi8( 0,  1,  6,  7,
		                      4,  5, 10, 11,
		                      8,  9, 14, 15,
		                     12, 13,  2,  3);
	}
	else
	{
		perm = _mm_setr_epi8( 0,  1, 14, 15,
		                      4,  5,  2,  3,
		                      8,  9,  6,  7,
		                     12, 13, 10, 11);
	}
	state[0] = _mm_shuffle_epi8(b0_blended, perm);
	state[1] = _mm_shuffle_epi8(b1_blended, perm);
}

static inline void roundEnc(__m128i state[2], const __m128i roundKey[2])
{
	// Use the AES round function to implement the Rijndael256 round function.
	rotateRows256Undo128(state, true);
	state[0] = _mm_aesenc_si128(state[0], roundKey[0]);
	state[1] = _mm_aesenc_si128(state[1], roundKey[1]);
}

static inline void finalEnc(__m128i state[2], const __m128i roundKey[2])
{
	rotateRows256Undo128(state, true);
	state[0] = _mm_aesenclast_si128(state[0], roundKey[0]);
	state[1] = _mm_aesenclast_si128(state[1], roundKey[1]);
}

static inline void roundDec(__m128i state[2], const __m128i roundKey[2])
{
	// Use the AES round function to implement the Rijndael256 round function.
	rotateRows256Undo128(state, false);
	state[0] = _mm_aesdec_si128(state[0], roundKey[0]);
	state[1] = _mm_aesdec_si128(state[1], roundKey[1]);
}

static inline void finalDec(__m128i state[2], const __m128i roundKey[2])
{
	rotateRows256Undo128(state, false);
	state[0] = _mm_aesdeclast_si128(state[0], roundKey[0]);
	state[1] = _mm_aesdeclast_si128(state[1], roundKey[1]);
}

void rijndael256_enc_block(const rijndael256_round_keys* round_keys, const u_char* plaintext, u_char* ciphertext)
{
	__m128i block[2];
	block[0] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&plaintext[0   ]),
	                         _mm_loadu_si128((const __m128i *)&round_keys->rounds[0][0]));
	block[1] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&plaintext[0x10]),
	                         _mm_loadu_si128((const __m128i *)&round_keys->rounds[0][0x10]));

	// Each iteration depends on the previous, so unrolling the outer loop isn't useful,
	// especially because there are a decent number of operations in each iteration.
#ifndef _MSC_VER
#pragma GCC unroll 1
#endif // !_MSC_VER
	for (int i = 1; i < RIJNDAEL256_ROUNDS; ++i)
	{
		__m128i roundKey[2];
		roundKey[0] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[i][0]);
		roundKey[1] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[i][0x10]);
		roundEnc(block, roundKey);
	}

	__m128i roundKey[2];
	roundKey[0] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[RIJNDAEL256_ROUNDS][0]);
	roundKey[1] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[RIJNDAEL256_ROUNDS][0x10]);
	finalEnc(block, roundKey);

	_mm_storeu_si128((__m128i *)&ciphertext[0   ], block[0]);
	_mm_storeu_si128((__m128i *)&ciphertext[0x10], block[1]);
}

void rijndael256_dec_block(const rijndael256_dec_round_keys* round_keys, const u_char* ciphertext, u_char* plaintext)
{
	__m128i block[2];
	block[0] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&plaintext[0   ]),
	                         _mm_loadu_si128((const __m128i *)&round_keys->rounds[RIJNDAEL256_ROUNDS][0]));
	block[1] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&plaintext[0x10]),
	                         _mm_loadu_si128((const __m128i *)&round_keys->rounds[RIJNDAEL256_ROUNDS][0x10]));

	// Each iteration depends on the previous, so unrolling the outer loop isn't useful,
	// especially because there are a decent number of operations in each iteration.
#ifndef _MSC_VER
#pragma GCC unroll 1
#endif // !_MSC_VER
	for (int i = RIJNDAEL256_ROUNDS - 1; i > 0; --i)
	{
		__m128i roundKey[2];
		roundKey[0] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[i][0]);
		roundKey[1] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[i][0x10]);
		roundDec(block, roundKey);
	}

	__m128i roundKey[2];
	roundKey[0] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[0][0]);
	roundKey[1] = _mm_loadu_si128((const __m128i *)&round_keys->rounds[0][0x10]);
	finalDec(block, roundKey);

	_mm_storeu_si128((__m128i *)&plaintext[0   ], block[0]);
	_mm_storeu_si128((__m128i *)&plaintext[0x10], block[1]);
}

#define EXPAND_ROUND(round, round_constant, roundKeys) \
	do \
	{ \
		__m128i t1 = roundKeys[round - 1][0]; \
		__m128i t2; \
		__m128i t3 = roundKeys[round - 1][1]; \
		__m128i t4; \
		t2 = _mm_aeskeygenassist_si128(t3, round_constant); \
		t2 = _mm_shuffle_epi32(t2, 0xff); \
		t4 = _mm_slli_si128(t1, 0x4); \
		t1 = _mm_xor_si128(t1, t4); \
		t4 = _mm_slli_si128(t4, 0x4); \
		t1 = _mm_xor_si128(t1, t4); \
		t4 = _mm_slli_si128(t4, 0x4); \
		t1 = _mm_xor_si128(t1, t4); \
		t1 = _mm_xor_si128(t1, t2); \
		roundKeys[round][0] = t1; \
		t4 = _mm_aeskeygenassist_si128(t1, 0x00); \
		t2 = _mm_shuffle_epi32(t4, 0xaa); \
		t4 = _mm_slli_si128(t3, 0x4); \
		t3 = _mm_xor_si128(t3, t4); \
		t4 = _mm_slli_si128(t4, 0x4); \
		t3 = _mm_xor_si128(t3, t4); \
		t4 = _mm_slli_si128(t4, 0x4); \
		t3 = _mm_xor_si128(t3, t4); \
		t3 = _mm_xor_si128(t3, t2); \
		roundKeys[round][1] = t3; \
	} while(0)

void rijndael256_set_key(rijndael256_round_keys* round_keys, const u_char* key)
{
	__m128i roundKeys[RIJNDAEL256_ROUNDS + 1][2];
	roundKeys[0][0] = _mm_loadu_si128((const __m128i *)&key[0]);
	roundKeys[0][1] = _mm_loadu_si128((const __m128i *)&key[0x10]);

	EXPAND_ROUND( 1, 0x01, roundKeys);
	EXPAND_ROUND( 2, 0x02, roundKeys);
	EXPAND_ROUND( 3, 0x04, roundKeys);
	EXPAND_ROUND( 4, 0x08, roundKeys);
	EXPAND_ROUND( 5, 0x10, roundKeys);
	EXPAND_ROUND( 6, 0x20, roundKeys);
	EXPAND_ROUND( 7, 0x40, roundKeys);
	EXPAND_ROUND( 8, 0x80, roundKeys);
	EXPAND_ROUND( 9, 0x1B, roundKeys);
	EXPAND_ROUND(10, 0x36, roundKeys);
	EXPAND_ROUND(11, 0x6C, roundKeys);
	EXPAND_ROUND(12, 0xD8, roundKeys);
	EXPAND_ROUND(13, 0xAB, roundKeys);
	EXPAND_ROUND(14, 0x4D, roundKeys);

	for (int i = 0; i <= RIJNDAEL256_ROUNDS; ++i)
	{
		_mm_storeu_si128((__m128i *)&round_keys->rounds[i][0   ], roundKeys[i][0]);
		_mm_storeu_si128((__m128i *)&round_keys->rounds[i][0x10], roundKeys[i][1]);
	}
}

void rijndael256_set_key_dec(rijndael256_dec_round_keys* round_keys_dec, const rijndael256_round_keys* round_keys_enc)
{
	memcpy(&round_keys_dec->rounds[0][0], &round_keys_enc->rounds[0][0], 32);
	for (int i = 1; i < RIJNDAEL256_ROUNDS; i++)
		for (int j = 0; j < 2; j++)
			_mm_storeu_si128((__m128i *)&round_keys_dec->rounds[i][j*0x10],
			                 _mm_aesimc_si128(_mm_loadu_si128((__m128i *)&round_keys_enc->rounds[i][j*0x10])));
	memcpy(&round_keys_dec->rounds[RIJNDAEL256_ROUNDS][0],
	       &round_keys_enc->rounds[RIJNDAEL256_ROUNDS][0], 32);
}
