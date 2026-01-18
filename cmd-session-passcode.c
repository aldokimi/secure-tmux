/* $OpenBSD$ */

/*
 * Copyright (c) 2026 Security Enhancement
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "tmux.h"

/*
 * Set or clear session passcode.
 */

static enum cmd_retval	cmd_session_passcode_exec(struct cmd *,
			    struct cmdq_item *);

const struct cmd_entry cmd_session_passcode_entry = {
	.name = "session-passcode",
	.alias = "sessp",

	.args = { "ct:", 0, 1, NULL },
	.usage = "[-c] " CMD_TARGET_SESSION_USAGE " [passcode]",

	.target = { 't', CMD_FIND_SESSION, 0 },

	.flags = 0,
	.exec = cmd_session_passcode_exec
};

static enum cmd_retval
cmd_session_passcode_exec(struct cmd *self, struct cmdq_item *item)
{
	struct args		*args = cmd_get_args(self);
	struct cmd_find_state	*target = cmdq_get_target(item);
	struct session		*s = target->s;
	struct client		*c = cmdq_get_client(item);
	uid_t			 client_uid;
	const char		*passcode;

	/* Get client UID */
	if (c != NULL && c->peer != NULL)
		client_uid = proc_get_peer_uid(c->peer);
	else
		client_uid = getuid();

	/* Only session owner can set passcode */
	if (s->acl != NULL && session_acl_get_owner(s->acl) != client_uid &&
	    client_uid != 0) {
		cmdq_error(item, "only session owner can set passcode");
		return (CMD_RETURN_ERROR);
	}

	/* Clear passcode if -c flag is set */
	if (args_has(args, 'c')) {
		if (s->acl == NULL) {
			cmdq_error(item, "session has no ACL");
			return (CMD_RETURN_ERROR);
		}
		session_acl_set_passcode(s->acl, NULL);
		cmdq_print(item, "Session passcode cleared");
		return (CMD_RETURN_NORMAL);
	}

	/* Get passcode from argument */
	passcode = args_string(args, 0);
	if (passcode == NULL || *passcode == '\0') {
		/* No passcode provided - show status */
		if (s->acl != NULL && session_acl_has_passcode(s->acl))
			cmdq_print(item, "Session has passcode protection enabled");
		else
			cmdq_print(item, "Session has no passcode protection");
		return (CMD_RETURN_NORMAL);
	}

	/* Validate passcode length */
	if (strlen(passcode) < 4) {
		cmdq_error(item, "passcode must be at least 4 characters");
		return (CMD_RETURN_ERROR);
	}
	if (strlen(passcode) > 64) {
		cmdq_error(item, "passcode must be at most 64 characters");
		return (CMD_RETURN_ERROR);
	}

	/* Ensure session has ACL */
	if (s->acl == NULL) {
		s->acl = session_acl_create(client_uid);
	}

	/* Set the passcode */
	if (session_acl_set_passcode(s->acl, passcode) != 0) {
		cmdq_error(item, "failed to set passcode");
		return (CMD_RETURN_ERROR);
	}

	cmdq_print(item, "Session passcode set successfully");
	return (CMD_RETURN_NORMAL);
}

