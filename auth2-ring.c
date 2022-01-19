/* $OpenBSD: auth2-none.c,v 1.23 2020/10/18 11:32:01 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include "digest.h"
#include "includes.h"

#include <openssl/ec.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#include "atomicio.h"
#include "poly_interpolate.h"
#include "rijndael.h"
#include "rijndael256.h"
#include "smult_curve25519_ref.h"
#include "ssh_api.h"
#include "xmalloc.h"
#include "hostfile.h"
#include "sshkey.h"
#include "auth.h"
#include "packet.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "ssh2.h"
#include "ssherr.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "uidswap.h"
#include "authfile.h"
#include "ge25519.h"

struct psi_in {
    u_char (*hashes)[SHA256_DIGEST_LENGTH];
    size_t hashcount;
};

/* import */
extern ServerOptions options;

/* "none" is allowed only one time */
static int none_enabled = 1;

int psi_eval_poly(int type, u_int32_t seq, struct ssh *ssh);
int psi_verify_proof(int type, u_int32_t seq, struct ssh *ssh);

static int
get_key_from_line(struct ssh *ssh, struct passwd *pw, char* cp, const char *loc, struct sshkey **keys)
{
	int want_keytype = KEY_ED25519;
	const char *reason = NULL;
	struct sshkey *found = NULL;
	if ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto not_found;
	}
	if (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		if (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		if (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto not_found;
		}
	}
	*keys = found;
	return 0;

fail_reason:
	error("%s", reason);
	auth_debug_add("%s", reason);
not_found:
	return 1;
}


/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
static size_t
check_authkeys_file(struct ssh *ssh, struct passwd *pw, FILE *f, char *file, struct sshkey **keys)
{
	char *cp, *line = NULL, loc[256];
	size_t linesize = 0;
	u_long linenum = 0;
	size_t keyscount = 0;


	while (getline(&line, &linesize, f) != -1) {
		linenum++;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;
		snprintf(loc, sizeof(loc), "%.200s:%lu", file, linenum);
		if (get_key_from_line(ssh, pw, cp, loc, keys + keyscount) == 0)
			keyscount++;
	}
	free(line);
	return keyscount;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
static size_t
get_all_authorized_keys2(struct ssh *ssh, struct passwd *pw, char *file, struct sshkey **keys)
{
	FILE *f;
	size_t foundcount = 0;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	if ((f = auth_openkeyfile(file, pw, options.strict_modes)) != NULL) {
		foundcount += check_authkeys_file(ssh, pw, f, file, keys + foundcount);
		fclose(f);
	}

	restore_uid();
	return foundcount;
}

static int
run_protocol(struct ssh *ssh, struct sshkey **keys, size_t keyslen)
{
	Authctxt *authctxt = (Authctxt *) ssh->authctxt;
	char tmp[32];
	ge25519 gegr;
	ge25519 gega;
	sc25519 scr;
	int err;

	// XXX 256 limit to authorized_keys can overflow; set a limit
	ge25519 geai[256];

	// Generate random r
	randombytes(tmp, 32);
	sc25519_from32bytes(&scr, tmp);

	// Get g^r
	ge25519_scalarmult_base(&gegr, &scr); // g^r

	// Find A_i^r for all A_i
	for (size_t i = 0; i < keyslen; i++)
	{
		// TODO use Lance's constant time impl instead
		ge25519_unpackneg_vartime(&gega, keys[i]->ed25519_pk);

		// Compute A_i^r in constant time
		ge25519_scalarmult(&geai[i], &gega, &scr);
	}

	// Send over g^r, [A_i^r] to the client
	if ((err = sshpkt_start(ssh, SSH2_MSG_USERAUTH_PSI_KEM)) != 0)
		fatal_fr(err, "starting packet");

	ge25519_pack(tmp, &gegr);
	if ((err = sshpkt_put_string(ssh, tmp, 32)) != 0)
		fatal_fr(err, "g^r");

	if ((err = sshpkt_put_u64(ssh, keyslen)) != 0)
		fatal_fr(err, "i");

	for (size_t i = 0; i < keyslen; i++)
	{
		ge25519_pack(tmp, &geai[i]);
		if ((err = sshpkt_put_string(ssh, tmp, 32)) != 0)
			fatal_fr(err, "A_i^r");
	}

	if ((err = sshpkt_send(ssh)) != 0 ||
			(err = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(err, "send packet");


	return 0;
}

static int
get_all_authorized_keys(struct ssh *ssh, struct passwd *pw)
{
	Authctxt *authctxt = (Authctxt *) ssh->authctxt;
	u_int success = 0, i;
	char *file;

	// XXX 256 limit to authorized_keys can overflow; set a limit
	struct sshkey *keys[256];
	size_t keyslen = 0;

	for (i = 0; !success && i < options.num_authkeys_files; i++) {
		if (strcasecmp(options.authorized_keys_files[i], "none") == 0)
			continue;
		file = expand_authorized_keys(options.authorized_keys_files[i], pw);
		debug("Authorized keys file %s", file);
		keyslen += get_all_authorized_keys2(ssh, pw, file, keys + keyslen);
		debug("Authorized keys found %lu", keyslen);
		free(file);
	}
    // Need to support other keys too!!
    // We can check keys[i]->type
    // If ecdsa, call OpenSSL get0group function

    // Basically just need set of unique key types
    // Run c_ec Kem.enc() on all of them to generate 'g^r'
    // Run c_rsa = Kem.enc(pk) for all rsa pks
    // create okvs pk -> c_rsa
    // serlialize and send to client
    // dispatch some other routine
    // Run Kem.msg() to get all the ec kem messages (free for RSA)
    // Forget the r's asap
    // Only realliy need to store KEM decryptions (list of struct ssh)


    // Note before evaluations send to client shuffle keys (or hashes)
    // DO PSI (send KEM decyptions as input)
    // Receive OKVS from client
    // Find xs by evaluating at every (pk, m)
    // sample r' (C25519)
    // Find H(pk, m, x^r') for every x
    // Send first half of hash to client
    // Sample secret s
    // Xor second half with s and send to client
    // Send H(s), g^r', g'^r' (Moller trick): g = 6, g' = 3 (LE)
    // Receive s. Check correctness and allow auth

    //u_char (*psi_inputs)[SHA256_DIGEST_LENGTH];
    struct psi_in *psi_inputs;

	if ((psi_inputs = malloc(sizeof(struct psi_in))) == NULL ||
        (psi_inputs->hashes = malloc(sizeof(*psi_inputs->hashes) * keyslen)) != NULL)
    {
		fatal_fr(SSH_ERR_ALLOC_FAIL, "allocating x/y coords");
	}

    success = sshkey_create_kem_enc(ssh, (const struct sshkey**)keys, keyslen, psi_inputs->hashes);
    ssh_set_app_data(ssh, psi_inputs);
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PSI_INTERPOLATE, &psi_eval_poly);

	authctxt->postponed = 1;

	for (size_t i = 0; i < keyslen; i++)
	{
		sshkey_free(keys[i]);
	}
	return success;
}

// We're going to receive interpolated polynomial (okvs)
// We have to follow the psi protocol
// Lookup P(hash) for hash in hashes
// Encrypt with Lance's AES (ideal permutation)
// Treat as point, x, on C25519
// Find x^r with smult_curve25519_ref.c no clamp
// q output, n exponent, p point
int
psi_eval_poly(int type, u_int32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

    int ret = SSH_ERR_INTERNAL_ERROR;

    u_char r[32];
    u_char *s = NULL; // xor second half of hashes
    u_char h_s[32]; // to the client

    ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PSI_INTERPOLATE, NULL);

    u_char *poly = NULL;
    size_t poly_size = 0;
    u_char (*ys)[SHA256_DIGEST_LENGTH] = NULL;

    struct psi_in *psi_inputs = ssh_get_app_data(ssh);
    ssh_set_app_data(ssh, NULL);

    if ((ret = sshpkt_get_string(ssh, &poly, &poly_size)) != 0 ||
        (ret = sshpkt_get_end(ssh)) != 0)
        goto fail;

    const int too_small = 32;
    if (poly_size < too_small) {
        ret = 0;
        goto fail;
    }

    if ((ys = malloc(sizeof(*ys) * psi_inputs->hashcount)) == NULL ||
        (s  = malloc(sizeof(u_char) * 16)) == NULL) {
        ret = SSH_ERR_ALLOC_FAIL;
        goto fail;
    }

    polynomial_evaluate(psi_inputs->hashes, ys, psi_inputs->hashcount, poly, poly_size/32);

    // Miniclamp (TM)
	randombytes(r, 32);
    r[31] &= 0x7f;

	randombytes(s, 16);
    struct ssh_digest_ctx *hashctx = ssh_digest_start(SSH_DIGEST_SHA256);
    ssh_digest_update(hashctx, s, SHA256_DIGEST_LENGTH);
    ssh_digest_final(hashctx, h_s, SHA256_DIGEST_LENGTH);


    u_char plaintext[32];
    u_char pr[32];
    rijndael256_round_keys round_keys;
    rijndael256_dec_round_keys dec_round_keys;
    for (size_t i=0; i < psi_inputs->hashcount; i++) {
        rijndael256_set_key(&round_keys, psi_inputs->hashes[i]);
        rijndael256_set_key_dec(&dec_round_keys, &round_keys);
        rijndael256_dec_block(&dec_round_keys, ys[i], plaintext);
        crypto_scalarmult_curve25519_noclamp(pr, r, plaintext);

        //H(x||pr)
        struct ssh_digest_ctx *hashctx = ssh_digest_start(SSH_DIGEST_SHA256);
        ssh_digest_update(hashctx, psi_inputs->hashes[i], SHA256_DIGEST_LENGTH);
        ssh_digest_update(hashctx, pr, SHA256_DIGEST_LENGTH);
        ssh_digest_final(hashctx, psi_inputs->hashes[i], SHA256_DIGEST_LENGTH);

        for (int j=0; j<16; j++)
            psi_inputs->hashes[i][j+16] ^= s[j];
    }
    u_char grwhole[32];
    u_char grtwist[32];

    crypto_scalarmult_curve25519_noclamp(grwhole, r, CURVE_WHOLE);
    crypto_scalarmult_curve25519_noclamp(grtwist, r, CURVE_TWIST);

    // XXX sort psi_inputs->hashes

    // h_s, grw, grt, hashes
    if ((ret = sshpkt_start(ssh, SSH2_MSG_USERAUTH_PSI_CHAL)) != 0 ||
        (ret = sshpkt_put(ssh, h_s, SHA256_DIGEST_LENGTH)) != 0  ||
        (ret = sshpkt_put(ssh, grwhole, 32)) != 0 ||
        (ret = sshpkt_put(ssh, grtwist, 32)) != 0 ||
        (ret = sshpkt_put(ssh, h_s, SHA256_DIGEST_LENGTH)) != 0 ||
        (ret = sshpkt_put_string(ssh, psi_inputs->hashes, psi_inputs->hashcount*SHA256_DIGEST_LENGTH)) != 0)
        goto fail;


    ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PSI_CHAL, &psi_verify_proof);
    authctxt->postponed = 1;

    ssh_set_app_data(ssh, s);

    ret = 0;
    goto out;

fail:
    freezero(s, 16);
    authctxt->postponed = 0;
    // XXX arguments??
    userauth_finish(ssh, 0, "ring", NULL);

out:
    memset(r, 0, 32);
    free(psi_inputs->hashes);
    free(psi_inputs);
    free(ys);
    free(poly);

    return ret;
}

int
psi_verify_proof(int type, u_int32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
    int ret = SSH_ERR_INTERNAL_ERROR;
    int authenticated = 0;

    ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_PSI_CHAL, NULL);
    u_char *s = ssh_get_app_data(ssh);
    u_char *sclient = NULL;
    ssh_set_app_data(ssh, NULL);

    if ((ret = sshpkt_get(ssh, sclient, 16)) != 0 ||
        (ret = sshpkt_get_end(ssh)) != 0)
        goto out;

    if (memcmp(s, sclient, 16) == 0)
        authenticated = 1;

    ret = 0;
out:
	authctxt->postponed = 0;
    userauth_finish(ssh, authenticated, "ring", NULL);
    free(s);
    free(sclient);

    return ret;
}

static int
userauth_ring(struct ssh *ssh, const char *method)
{
	debug("RING RING");
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	return get_all_authorized_keys(ssh, pw) == 1;
}


Authmethod method_ring = {
	"ring",
	"psi",
	userauth_ring,
	&none_enabled
};
