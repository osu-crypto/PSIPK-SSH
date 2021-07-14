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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
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

/* import */
extern ServerOptions options;

/* "none" is allowed only one time */
static int none_enabled = 1;

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
	if ((err = sshpkt_start(ssh, SSH2_MSG_USERAUTH_RING_OK)) != 0)
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

	if ((err = sshpkt_send(ssh) != 0) ||
			(err = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(err, "send packet");


	return 0;
}

	static int
get_all_authorized_keys(struct ssh *ssh, struct passwd *pw)
{
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
	for (size_t i = 0; i < keyslen; i++)
	{
		debug2("Authorized key: %s", keys[i]->ed25519_pk);
	}

	run_protocol(ssh, keys, keyslen);

	for (size_t i = 0; i < keyslen; i++)
	{
		sshkey_free(keys[i]);
	}
	return success;
}

	static int
userauth_ring(struct ssh *ssh)
{
	debug("RING RING");
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	get_all_authorized_keys(ssh, pw);
	return 1;
}


Authmethod method_ring = {
	"ring",
	userauth_ring,
	&none_enabled
};
