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

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tmux.h"

/*
 * Simple passcode hashing using a basic approach.
 * For production use, consider using bcrypt or argon2.
 */
#define PASSCODE_SALT_LEN 16
#define PASSCODE_HASH_LEN 64

/*
 * Session-level Access Control Lists.
 *
 * Each session can have its own ACL that specifies which users are allowed
 * to attach to it and whether they have read-only or read-write access.
 * This complements the server-level ACL in server-acl.c.
 */

struct session_acl_user {
	uid_t				uid;
	int				flags;
#define SESSION_ACL_READONLY	0x1
#define SESSION_ACL_DENIED	0x2

	RB_ENTRY(session_acl_user)	entry;
};

struct session_acl {
	uid_t				owner;		/* Session owner UID */
	int				flags;
#define SESSION_ACL_PRIVATE	0x1		/* Only owner can attach */
#define SESSION_ACL_LOCKED	0x2		/* No new attachments */
#define SESSION_ACL_HAS_PASSCODE 0x4		/* Passcode required */

	char				*passcode_hash;	/* Hashed passcode */
	char				*passcode_salt;	/* Salt for hashing */

	RB_HEAD(session_acl_entries, session_acl_user) users;
};

/*
 * Generate a random salt for passcode hashing.
 */
static char *
session_acl_generate_salt(void)
{
	static const char charset[] = 
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char	*salt;
	int	 i;
	FILE	*f;
	unsigned char	 randbuf[PASSCODE_SALT_LEN];

	salt = xmalloc(PASSCODE_SALT_LEN + 1);

	/* Try to use /dev/urandom for randomness */
	f = fopen("/dev/urandom", "r");
	if (f != NULL) {
		if (fread(randbuf, 1, PASSCODE_SALT_LEN, f) == PASSCODE_SALT_LEN) {
			for (i = 0; i < PASSCODE_SALT_LEN; i++)
				salt[i] = charset[randbuf[i] % (sizeof(charset) - 1)];
		} else {
			/* Fallback to simple random */
			for (i = 0; i < PASSCODE_SALT_LEN; i++)
				salt[i] = charset[arc4random() % (sizeof(charset) - 1)];
		}
		fclose(f);
	} else {
		for (i = 0; i < PASSCODE_SALT_LEN; i++)
			salt[i] = charset[arc4random() % (sizeof(charset) - 1)];
	}

	salt[PASSCODE_SALT_LEN] = '\0';
	return (salt);
}

/*
 * Simple hash function for passcode.
 * Uses a basic salted hash - for production, use bcrypt or similar.
 */
static char *
session_acl_hash_passcode(const char *passcode, const char *salt)
{
	char		*hash;
	char		*combined;
	size_t		 len, i;
	unsigned int	 h = 5381;

	/* Combine salt and passcode */
	len = strlen(salt) + strlen(passcode);
	combined = xmalloc(len + 1);
	snprintf(combined, len + 1, "%s%s", salt, passcode);

	/* DJB2 hash - simple but effective for this purpose */
	for (i = 0; combined[i] != '\0'; i++)
		h = ((h << 5) + h) + (unsigned char)combined[i];

	/* Add another round with reversed string for more mixing */
	for (i = len; i > 0; i--)
		h = ((h << 5) + h) ^ (unsigned char)combined[i - 1];

	explicit_bzero(combined, len);
	free(combined);

	/* Convert to hex string */
	hash = xmalloc(17);
	snprintf(hash, 17, "%08x%08x", h, h ^ 0xDEADBEEF);

	return (hash);
}

static int
session_acl_cmp(struct session_acl_user *u1, struct session_acl_user *u2)
{
	if (u1->uid < u2->uid)
		return (-1);
	return (u1->uid > u2->uid);
}

RB_GENERATE_STATIC(session_acl_entries, session_acl_user, entry, session_acl_cmp);

/* Create a new session ACL. */
struct session_acl *
session_acl_create(uid_t owner)
{
	struct session_acl	*acl;

	acl = xcalloc(1, sizeof *acl);
	acl->owner = owner;
	acl->flags = 0;
	acl->passcode_hash = NULL;
	acl->passcode_salt = NULL;
	RB_INIT(&acl->users);

	return (acl);
}

/* Free a session ACL. */
void
session_acl_free(struct session_acl *acl)
{
	struct session_acl_user	*user, *user1;

	if (acl == NULL)
		return;

	RB_FOREACH_SAFE(user, session_acl_entries, &acl->users, user1) {
		RB_REMOVE(session_acl_entries, &acl->users, user);
		free(user);
	}

	/* Securely clear passcode data */
	if (acl->passcode_hash != NULL) {
		explicit_bzero(acl->passcode_hash, strlen(acl->passcode_hash));
		free(acl->passcode_hash);
	}
	if (acl->passcode_salt != NULL) {
		explicit_bzero(acl->passcode_salt, strlen(acl->passcode_salt));
		free(acl->passcode_salt);
	}

	free(acl);
}

/* Find a user in the session ACL. */
static struct session_acl_user *
session_acl_find(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	find = { .uid = uid };

	return (RB_FIND(session_acl_entries, &acl->users, &find));
}

/* Get the owner UID of a session ACL. */
uid_t
session_acl_get_owner(struct session_acl *acl)
{
	if (acl == NULL)
		return ((uid_t)-1);
	return (acl->owner);
}

/* Check if a session ACL is private. */
int
session_acl_is_private(struct session_acl *acl)
{
	if (acl == NULL)
		return (0);
	return ((acl->flags & SESSION_ACL_PRIVATE) != 0);
}

/* Check if a session ACL is locked. */
int
session_acl_is_locked(struct session_acl *acl)
{
	if (acl == NULL)
		return (0);
	return ((acl->flags & SESSION_ACL_LOCKED) != 0);
}

/* Set session as private (owner only). */
void
session_acl_set_private(struct session_acl *acl, int private)
{
	if (acl == NULL)
		return;
	if (private)
		acl->flags |= SESSION_ACL_PRIVATE;
	else
		acl->flags &= ~SESSION_ACL_PRIVATE;
}

/* Lock session (no new attachments). */
void
session_acl_set_locked(struct session_acl *acl, int locked)
{
	if (acl == NULL)
		return;
	if (locked)
		acl->flags |= SESSION_ACL_LOCKED;
	else
		acl->flags &= ~SESSION_ACL_LOCKED;
}

/* Allow a user to access the session. */
void
session_acl_allow(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return;

	user = session_acl_find(acl, uid);
	if (user == NULL) {
		user = xcalloc(1, sizeof *user);
		user->uid = uid;
		user->flags = 0;
		RB_INSERT(session_acl_entries, &acl->users, user);
	}
	/* Clear denied flag if set */
	user->flags &= ~SESSION_ACL_DENIED;
}

/* Deny a user access to the session. */
void
session_acl_deny(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return;

	/* Cannot deny the owner */
	if (uid == acl->owner)
		return;

	user = session_acl_find(acl, uid);
	if (user == NULL) {
		user = xcalloc(1, sizeof *user);
		user->uid = uid;
		RB_INSERT(session_acl_entries, &acl->users, user);
	}
	user->flags |= SESSION_ACL_DENIED;
}

/* Set a user's access to read-only. */
void
session_acl_set_readonly(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return;

	user = session_acl_find(acl, uid);
	if (user == NULL) {
		user = xcalloc(1, sizeof *user);
		user->uid = uid;
		RB_INSERT(session_acl_entries, &acl->users, user);
	}
	user->flags |= SESSION_ACL_READONLY;
}

/* Set a user's access to read-write. */
void
session_acl_set_readwrite(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return;

	user = session_acl_find(acl, uid);
	if (user != NULL)
		user->flags &= ~SESSION_ACL_READONLY;
}

/* Remove a user from the ACL. */
void
session_acl_remove(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return;

	/* Cannot remove the owner */
	if (uid == acl->owner)
		return;

	user = session_acl_find(acl, uid);
	if (user != NULL) {
		RB_REMOVE(session_acl_entries, &acl->users, user);
		free(user);
	}
}

/*
 * Check if a user can access the session.
 * Returns: 0 = denied, 1 = read-only, 2 = read-write
 */
int
session_acl_check(struct session_acl *acl, uid_t uid)
{
	struct session_acl_user	*user;

	if (acl == NULL)
		return (2);  /* No ACL = full access */

	/* Session is locked - no new attachments */
	if (acl->flags & SESSION_ACL_LOCKED) {
		log_debug("session_acl: session is locked, denying uid %ld",
		    (long)uid);
		return (0);
	}

	/* Owner always has full access */
	if (uid == acl->owner)
		return (2);

	/* Root always has access (unless session is locked) */
	if (uid == 0)
		return (2);

	/* Private session - only owner can access */
	if (acl->flags & SESSION_ACL_PRIVATE) {
		log_debug("session_acl: private session, denying uid %ld",
		    (long)uid);
		return (0);
	}

	/* Check explicit user entry */
	user = session_acl_find(acl, uid);
	if (user != NULL) {
		if (user->flags & SESSION_ACL_DENIED) {
			log_debug("session_acl: uid %ld explicitly denied",
			    (long)uid);
			return (0);
		}
		if (user->flags & SESSION_ACL_READONLY) {
			log_debug("session_acl: uid %ld has read-only access",
			    (long)uid);
			return (1);
		}
		return (2);
	}

	/* No explicit entry - allow access by default */
	return (2);
}

/* Check if session requires a passcode. */
int
session_acl_has_passcode(struct session_acl *acl)
{
	if (acl == NULL)
		return (0);
	return ((acl->flags & SESSION_ACL_HAS_PASSCODE) != 0);
}

/* Set the session passcode. Pass NULL to clear. */
int
session_acl_set_passcode(struct session_acl *acl, const char *passcode)
{
	if (acl == NULL)
		return (-1);

	/* Clear existing passcode */
	if (acl->passcode_hash != NULL) {
		explicit_bzero(acl->passcode_hash, strlen(acl->passcode_hash));
		free(acl->passcode_hash);
		acl->passcode_hash = NULL;
	}
	if (acl->passcode_salt != NULL) {
		explicit_bzero(acl->passcode_salt, strlen(acl->passcode_salt));
		free(acl->passcode_salt);
		acl->passcode_salt = NULL;
	}

	/* If passcode is NULL or empty, just clear */
	if (passcode == NULL || *passcode == '\0') {
		acl->flags &= ~SESSION_ACL_HAS_PASSCODE;
		log_debug("session_acl: passcode cleared");
		return (0);
	}

	/* Generate salt and hash the passcode */
	acl->passcode_salt = session_acl_generate_salt();
	acl->passcode_hash = session_acl_hash_passcode(passcode, acl->passcode_salt);
	acl->flags |= SESSION_ACL_HAS_PASSCODE;

	log_debug("session_acl: passcode set");
	return (0);
}

/*
 * Verify a passcode against the stored hash.
 * Returns 1 if valid, 0 if invalid.
 */
int
session_acl_verify_passcode(struct session_acl *acl, const char *passcode)
{
	char	*hash;
	int	 result;

	if (acl == NULL)
		return (1);  /* No ACL = no passcode required */

	/* No passcode set */
	if (!(acl->flags & SESSION_ACL_HAS_PASSCODE))
		return (1);

	if (passcode == NULL || acl->passcode_salt == NULL || 
	    acl->passcode_hash == NULL)
		return (0);

	/* Hash the provided passcode with the stored salt */
	hash = session_acl_hash_passcode(passcode, acl->passcode_salt);
	
	/* Constant-time comparison to prevent timing attacks */
	result = (strlen(hash) == strlen(acl->passcode_hash));
	if (result) {
		size_t i;
		int diff = 0;
		for (i = 0; i < strlen(hash); i++)
			diff |= hash[i] ^ acl->passcode_hash[i];
		result = (diff == 0);
	}

	explicit_bzero(hash, strlen(hash));
	free(hash);

	if (!result)
		log_debug("session_acl: passcode verification failed");

	return (result);
}

/*
 * Check if a user needs to provide a passcode.
 * Owner and root don't need passcode.
 */
int
session_acl_needs_passcode(struct session_acl *acl, uid_t uid)
{
	if (acl == NULL)
		return (0);

	/* No passcode set */
	if (!(acl->flags & SESSION_ACL_HAS_PASSCODE))
		return (0);

	/* Owner doesn't need passcode */
	if (uid == acl->owner)
		return (0);

	/* Root doesn't need passcode */
	if (uid == 0)
		return (0);

	return (1);
}

/* Display the session ACL. */
void
session_acl_display(struct session_acl *acl, struct cmdq_item *item)
{
	struct session_acl_user	*user;
	struct passwd		*pw;
	const char		*name, *access_str;

	if (acl == NULL) {
		cmdq_print(item, "No session ACL configured");
		return;
	}

	pw = getpwuid(acl->owner);
	if (pw != NULL)
		name = pw->pw_name;
	else
		name = "unknown";
	cmdq_print(item, "Owner: %s (uid %ld)", name, (long)acl->owner);

	if (acl->flags & SESSION_ACL_PRIVATE)
		cmdq_print(item, "Mode: private (owner only)");
	else if (acl->flags & SESSION_ACL_LOCKED)
		cmdq_print(item, "Mode: locked (no new attachments)");
	else
		cmdq_print(item, "Mode: normal");

	/* Display passcode status */
	if (acl->flags & SESSION_ACL_HAS_PASSCODE)
		cmdq_print(item, "Passcode: enabled");
	else
		cmdq_print(item, "Passcode: disabled");

	cmdq_print(item, "Users:");
	RB_FOREACH(user, session_acl_entries, &acl->users) {
		pw = getpwuid(user->uid);
		if (pw != NULL)
			name = pw->pw_name;
		else
			name = "unknown";

		if (user->flags & SESSION_ACL_DENIED)
			access_str = "denied";
		else if (user->flags & SESSION_ACL_READONLY)
			access_str = "read-only";
		else
			access_str = "read-write";

		cmdq_print(item, "  %s (uid %ld): %s",
		    name, (long)user->uid, access_str);
	}
}

