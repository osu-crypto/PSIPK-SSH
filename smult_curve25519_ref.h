#ifndef SMULT_CURVE25519_H
#define SMULT_CURVE25519_H


extern const unsigned char CURVE_WHOLE[32];
extern const unsigned char CURVE_TWIST[32];

int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);
int crypto_scalarmult_curve25519_noclamp(unsigned char *, const unsigned char *, const unsigned char *);
#endif
