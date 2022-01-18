// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.

#ifndef RIJNDAEL_256_H
#define RIJNDAEL_256_H

#define RIJNDAEL256_ROUNDS 14;

struct rijndael256_round_keys
{
	u_char rounds[RIJNDAEL256_ROUNDS + 1][32];
};

struct rijndael256_dec_round_keys
{
	u_char rounds[RIJNDAEL256_ROUNDS + 1][32];
};

void rijndael256_set_key(rijndael256_round_keys* round_keys, const u_char* key);
void rijndael256_set_key_dec(rijndael256_dec_round_keys* round_keys_dec, const rijndael256_round_keys* round_keys_enc);
void rijndael256_enc_block(const rijndael256_round_keys* round_keys, const u_char* plaintext, u_char* ciphertext);
void rijndael256_dec_block(const rijndael256_dec_round_keys* round_keys, const u_char* ciphertext, u_char* plaintext);

#endif // RIJNDAEL_256_H
