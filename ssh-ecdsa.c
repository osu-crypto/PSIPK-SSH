/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

/* ARGSUSED */
int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t len, dlen;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = ECDSA_do_sign(digest, dlen, key->ecdsa)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	if ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	explicit_bzero(digest, sizeof(digest));
	sshbuf_free(b);
	sshbuf_free(bb);
	ECDSA_SIG_free(sig);
	return ret;
}

/* ARGSUSED */
int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t dlen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;

	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	if (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((sig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!ECDSA_SIG_set0(sig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	switch (ECDSA_do_verify(digest, dlen, sig, key->ecdsa)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

 out:
	explicit_bzero(digest, sizeof(digest));
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(sig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	free(ktype);
	return ret;
}

// KEM.Msg(pk, r) -> pk^r; will be called for each pk
// KEM.Enc(-pk-) -> g^r, r (sampled); sample constant, find g^r (same as dec)
// KEM.Dec(sk, g^r) -> (g^r)^sk

static int
ssh_ecdsa_kem_dh(const EC_KEY *key, u_char **kem, size_t *klen,
    const EC_GROUP* group, const EC_POINT *point_gr)
{
	int ret = SSH_ERR_INTERNAL_ERROR;

    u_char * temp_kem = NULL;
	BN_CTX *ctx = NULL;

	if (klen != NULL)
		*klen = 0;
	if (kem != NULL)
		*kem = NULL;

    /* KEM start */
	/* Calculate the size of the buffer for the shared secret */
	int out_len = (EC_GROUP_get_degree(group) + 7)/8;

	/* Allocate the memory for the shared secret */
	if ((temp_kem = malloc(out_len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Derive the shared secret */
	out_len = ECDH_compute_key(temp_kem, out_len, point_gr,
						key, NULL);
    /* KEM end */
    if (out_len <= 0)
    {
        ret = -1; // BAD
        goto out;
    }

	if (kem != NULL) {
        *kem = temp_kem;
        temp_kem = NULL;
	}
	if (klen != NULL)
		*klen = out_len;
	ret = 0;
 out:
	BN_CTX_free(ctx);
    free(temp_kem);
	return ret;
}


int
ssh_ecdsa_kem_msg(const struct sshkey *key, u_char **m, size_t *mlen, const EC_KEY *r)
{
    const EC_GROUP* group = EC_KEY_get0_group(key->ecdsa);
    const EC_POINT *point_pk = EC_KEY_get0_public_key(key->ecdsa);
    return ssh_ecdsa_kem_dh(r, m, mlen, group, point_pk);
}

int
ssh_ecdsa_kem_enc(const int nid, u_char **c, size_t *clen, void **r)
{
	int ret = SSH_ERR_INTERNAL_ERROR;

    const EC_POINT* pk;

    EC_KEY *gr = NULL;
	BN_CTX *ctx = NULL;

    size_t bufsize = 0;
    u_char *buf = NULL;

    const EC_GROUP *group;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((gr = EC_KEY_new_by_curve_name(nid)) == NULL) {
        ret = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    group = EC_KEY_get0_group(gr);

    EC_KEY_generate_key(gr);
    pk = EC_KEY_get0_public_key(gr);

    bufsize = EC_POINT_point2oct(group, pk, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

	if ((buf = malloc(bufsize)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

    EC_POINT_point2oct(group, pk, POINT_CONVERSION_COMPRESSED, buf, bufsize, ctx);

    *r = gr; // I'm not afraid
    gr = NULL;

    *c = buf;
    buf = NULL;

    *clen = bufsize;

    ret = 0;

out:
    freezero(buf, bufsize);
    EC_KEY_free(gr);
	BN_CTX_free(ctx);

    return ret;
}

// ECDH_compute_key for KEM.msg

/* ARGSUSED */
int
ssh_ecdsa_kem_dec(const struct sshkey *key, u_char **kem, size_t *klen,
    const u_char *gr, size_t grlen)
{
    int ret = SSH_ERR_INTERNAL_ERROR;

    const EC_GROUP* group = EC_KEY_get0_group(key->ecdsa);
	BN_CTX *ctx = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

    EC_POINT *point_gr = EC_POINT_new(group);
    EC_POINT_oct2point(group, point_gr, gr, grlen, ctx);
    ret = ssh_ecdsa_kem_dh(key->ecdsa, kem, klen, group, point_gr);

    EC_POINT_free(point_gr);
    return ret;
}


#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
