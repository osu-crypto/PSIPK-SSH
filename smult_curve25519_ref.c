/* $OpenBSD: smult_curve25519_ref.c,v 1.2 2013/11/02 22:02:14 markus Exp $ */
/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/

#include "smult_curve25519_ref.h"

const unsigned char CURVE_WHOLE[32] = {6, 0};
const unsigned char CURVE_TWIST[32] = {3, 0};
