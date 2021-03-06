/* $OpenBSD: ssh-ed25519.c,v 1.9 2020/10/18 11:32:02 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"
#include "sodium.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

int
ssh_ed25519_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	u_char *sig = NULL;
	size_t slen = 0, len;
	unsigned long long smlen;
	int r, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == NULL ||
	    datalen >= INT_MAX - crypto_sign_ed25519_BYTES)
		return SSH_ERR_INVALID_ARGUMENT;
	smlen = slen = datalen + crypto_sign_ed25519_BYTES;
	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ret = crypto_sign_ed25519(sig, &smlen, data, datalen,
	    key->ed25519_sk)) != 0 || smlen <= datalen) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, smlen - datalen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	if (sig != NULL)
		freezero(sig, slen);

	return r;
}

int
ssh_ed25519_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	u_char *sm = NULL, *m = NULL;
	size_t len;
	unsigned long long smlen = 0, mlen = 0;
	int r, ret;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == NULL ||
	    datalen >= INT_MAX - crypto_sign_ed25519_BYTES ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	if (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len > crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (datalen >= SIZE_MAX - len) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	smlen = len + datalen;
	mlen = smlen;
	if ((sm = malloc(smlen)) == NULL || (m = malloc(mlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(sm, sigblob, len);
	memcpy(sm+len, data, datalen);
	if ((ret = crypto_sign_ed25519_open(m, &mlen, sm, smlen,
	    key->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_open failed: %d", ret);
	}
	if (ret != 0 || mlen != datalen) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* XXX compare 'm' and 'data' ? */
	/* success */
	r = 0;
 out:
	if (sm != NULL)
		freezero(sm, smlen);
	if (m != NULL)
		freezero(m, smlen); /* NB mlen may be invalid if r != 0 */
	sshbuf_free(b);
	free(ktype);
	return r;
}

int
ssh_ed25519_kem_dec(const struct sshkey *key, u_char **kem, size_t *klen,
    const u_char *gr, size_t grlen)
{
	u_char *temp_kem = NULL;
    const size_t gelen = 32;
	int r, ret;

	if (klen != NULL)
		*klen = 0;
	if (kem != NULL)
		*kem = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == NULL || grlen != gelen)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((temp_kem = malloc(gelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ret = crypto_kem_dec_ed25519_hash(temp_kem, gr, key->ed25519_sk)) != 0 ) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}

	if (kem != NULL) {
        *kem = temp_kem;
        temp_kem = NULL;
	}
	if (klen != NULL)
		*klen = gelen;
	/* success */
	r = 0;
 out:
	freezero(temp_kem, gelen);

	return r;
}

int
ssh_ed25519_kem_enc(u_char **c, size_t *clen, void **r)
{
    const int len = 32;
	if ((*c = malloc(len)) == NULL) {
        return SSH_ERR_ALLOC_FAIL;
	}

	if ((*r = malloc(2 * len)) == NULL) {
        free(*c);
        return SSH_ERR_ALLOC_FAIL;
	}

    randombytes(*r, 32);
    crypto_scalarmult_ed25519_base(*c, *r);

	if ((*r = realloc(*r, len)) == NULL) {
        free(*c);
        return SSH_ERR_ALLOC_FAIL;
	}

    *clen = len;

    return 0;
}

// m is pk^r
int
ssh_ed25519_kem_msg(const struct sshkey *key, u_char **m, size_t *mlen, const u_char *r)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
    const size_t len = 32;
    u_char* temp_m = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

	if ((temp_m = malloc(len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
    }


    ret = crypto_kem_dec_ed25519(temp_m, key->ed25519_pk, r);

    if (ret == -1)
    {
        ret = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }

    *m = temp_m;
    temp_m = NULL;

    *mlen = len;

out:
    freezero(temp_m, len);
    return ret;
}
