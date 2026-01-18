/* $OpenBSD$ */

/*
 * Copyright (c) 2009 Nicholas Marriott <nicholas.marriott@gmail.com>
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
#include <sys/stat.h>

#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "tmux.h"

/*
 * Environment - manipulate a set of environment variables.
 */

/*
 * Security: List of dangerous environment variables that should never be
 * updated from client connections. These could be used for code injection.
 */
static const char *environ_dangerous_vars[] = {
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"LD_DEBUG",
	"LD_DEBUG_OUTPUT",
	"LD_DYNAMIC_WEAK",
	"LD_ORIGIN_PATH",
	"LD_PROFILE",
	"LD_SHOW_AUXV",
	"LD_USE_LOAD_BIAS",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"DYLD_FRAMEWORK_PATH",
	"DYLD_FALLBACK_LIBRARY_PATH",
	"PYTHONPATH",
	"PERL5LIB",
	"RUBYLIB",
	"CLASSPATH",
	"NODE_PATH",
	NULL
};

/*
 * Security: List of sensitive credential variables that require validation.
 */
static const char *environ_credential_vars[] = {
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"KRB5CCNAME",
	"GNOME_KEYRING_CONTROL",
	"GPG_AGENT_INFO",
	NULL
};

/*
 * Security: Check if a variable name is in the dangerous list.
 */
static int
environ_is_dangerous(const char *name)
{
	const char	**p;

	for (p = environ_dangerous_vars; *p != NULL; p++) {
		if (strcmp(name, *p) == 0)
			return (1);
	}
	return (0);
}

/*
 * Security: Check if a variable is a credential variable that needs validation.
 */
static int
environ_is_credential(const char *name)
{
	const char	**p;

	for (p = environ_credential_vars; *p != NULL; p++) {
		if (strcmp(name, *p) == 0)
			return (1);
	}
	return (0);
}

/*
 * Security: Validate SSH_AUTH_SOCK - check that the socket exists,
 * is a socket, and is owned by the current user.
 */
static int
environ_validate_ssh_auth_sock(const char *value)
{
	struct stat	sb;
	uid_t		uid;

	if (value == NULL || *value == '\0')
		return (0);

	uid = getuid();

	/* Check if the socket file exists */
	if (lstat(value, &sb) != 0) {
		log_debug("SSH_AUTH_SOCK validation failed: %s does not exist",
		    value);
		return (0);
	}

	/* Must be a socket */
	if (!S_ISSOCK(sb.st_mode)) {
		log_debug("SSH_AUTH_SOCK validation failed: %s is not a socket",
		    value);
		return (0);
	}

	/* Must be owned by current user */
	if (sb.st_uid != uid) {
		log_debug("SSH_AUTH_SOCK validation failed: %s not owned by user "
		    "(owner: %ld, user: %ld)", value, (long)sb.st_uid, (long)uid);
		return (0);
	}

	/* Should not be world-accessible */
	if ((sb.st_mode & S_IRWXO) != 0) {
		log_debug("SSH_AUTH_SOCK warning: %s has world permissions", value);
		/* Allow but log warning */
	}

	return (1);
}

/*
 * Security: Validate KRB5CCNAME - check that the credential cache exists
 * and is owned by the current user.
 */
static int
environ_validate_krb5ccname(const char *value)
{
	struct stat	sb;
	uid_t		uid;
	const char	*path;

	if (value == NULL || *value == '\0')
		return (0);

	uid = getuid();

	/* Handle FILE: prefix */
	if (strncmp(value, "FILE:", 5) == 0)
		path = value + 5;
	else if (strncmp(value, "DIR:", 4) == 0)
		path = value + 4;
	else
		path = value;

	/* Skip validation for non-file credential caches */
	if (strncmp(value, "KEYRING:", 8) == 0 ||
	    strncmp(value, "KCM:", 4) == 0 ||
	    strncmp(value, "MEMORY:", 7) == 0)
		return (1);

	if (lstat(path, &sb) != 0) {
		log_debug("KRB5CCNAME validation failed: %s does not exist", path);
		return (0);
	}

	if (sb.st_uid != uid) {
		log_debug("KRB5CCNAME validation failed: %s not owned by user",
		    path);
		return (0);
	}

	return (1);
}

/*
 * Security: Validate a credential variable value.
 */
static int
environ_validate_credential(const char *name, const char *value)
{
	if (strcmp(name, "SSH_AUTH_SOCK") == 0)
		return (environ_validate_ssh_auth_sock(value));
	if (strcmp(name, "KRB5CCNAME") == 0)
		return (environ_validate_krb5ccname(value));
	
	/* For other credential variables, just check they're not empty */
	return (value != NULL && *value != '\0');
}

/*
 * Security: Check if update-environment-deny blocks this variable.
 */
static int
environ_is_denied(struct options *oo, const char *name)
{
	struct options_entry		*o;
	struct options_array_item	*a;
	union options_value		*ov;

	o = options_get(oo, "update-environment-deny");
	if (o == NULL)
		return (0);

	a = options_array_first(o);
	while (a != NULL) {
		ov = options_array_item_value(a);
		if (ov != NULL && ov->string != NULL) {
			if (fnmatch(ov->string, name, 0) == 0) {
				log_debug("environ: %s blocked by update-environment-deny",
				    name);
				return (1);
			}
		}
		a = options_array_next(a);
	}
	return (0);
}

RB_HEAD(environ, environ_entry);
static int environ_cmp(struct environ_entry *, struct environ_entry *);
RB_GENERATE_STATIC(environ, environ_entry, entry, environ_cmp);

static int
environ_cmp(struct environ_entry *envent1, struct environ_entry *envent2)
{
	return (strcmp(envent1->name, envent2->name));
}

/* Initialise the environment. */
struct environ *
environ_create(void)
{
	struct environ	*env;

	env = xcalloc(1, sizeof *env);
	RB_INIT(env);

	return (env);
}

/* Free an environment. */
void
environ_free(struct environ *env)
{
	struct environ_entry	*envent, *envent1;

	RB_FOREACH_SAFE(envent, environ, env, envent1) {
		RB_REMOVE(environ, env, envent);
		free(envent->name);
		free(envent->value);
		free(envent);
	}
	free(env);
}

struct environ_entry *
environ_first(struct environ *env)
{
	return (RB_MIN(environ, env));
}

struct environ_entry *
environ_next(struct environ_entry *envent)
{
	return (RB_NEXT(environ, env, envent));
}

/* Copy one environment into another. */
void
environ_copy(struct environ *srcenv, struct environ *dstenv)
{
	struct environ_entry	*envent;

	RB_FOREACH(envent, environ, srcenv) {
		if (envent->value == NULL)
			environ_clear(dstenv, envent->name);
		else {
			environ_set(dstenv, envent->name, envent->flags,
			    "%s", envent->value);
		}
	}
}

/* Find an environment variable. */
struct environ_entry *
environ_find(struct environ *env, const char *name)
{
	struct environ_entry	envent;

	envent.name = (char *) name;
	return (RB_FIND(environ, env, &envent));
}

/* Set an environment variable. */
void
environ_set(struct environ *env, const char *name, int flags, const char *fmt,
    ...)
{
	struct environ_entry	*envent;
	va_list			 ap;

	va_start(ap, fmt);
	if ((envent = environ_find(env, name)) != NULL) {
		envent->flags = flags;
		free(envent->value);
		xvasprintf(&envent->value, fmt, ap);
	} else {
		envent = xmalloc(sizeof *envent);
		envent->name = xstrdup(name);
		envent->flags = flags;
		xvasprintf(&envent->value, fmt, ap);
		RB_INSERT(environ, env, envent);
	}
	va_end(ap);
}

/* Clear an environment variable. */
void
environ_clear(struct environ *env, const char *name)
{
	struct environ_entry	*envent;

	if ((envent = environ_find(env, name)) != NULL) {
		free(envent->value);
		envent->value = NULL;
	} else {
		envent = xmalloc(sizeof *envent);
		envent->name = xstrdup(name);
		envent->flags = 0;
		envent->value = NULL;
		RB_INSERT(environ, env, envent);
	}
}

/* Set an environment variable from a NAME=VALUE string. */
void
environ_put(struct environ *env, const char *var, int flags)
{
	char	*name, *value;

	value = strchr(var, '=');
	if (value == NULL)
		return;
	value++;

	name = xstrdup(var);
	name[strcspn(name, "=")] = '\0';

	environ_set(env, name, flags, "%s", value);
	free(name);
}

/* Unset an environment variable. */
void
environ_unset(struct environ *env, const char *name)
{
	struct environ_entry	*envent;

	if ((envent = environ_find(env, name)) == NULL)
		return;
	RB_REMOVE(environ, env, envent);
	free(envent->name);
	free(envent->value);
	free(envent);
}

/* Copy variables from a destination into a source environment. */
void
environ_update(struct options *oo, struct environ *src, struct environ *dst)
{
	struct environ_entry		*envent;
	struct environ_entry		*envent1;
	struct options_entry		*o;
	struct options_array_item	*a;
	union options_value		*ov;
	int				 found;
	int				 secure_mode;

	o = options_get(oo, "update-environment");
	if (o == NULL)
		return;

	/* Check if secure environment update mode is enabled */
	secure_mode = options_get_number(global_options, "secure-update-environment");

	a = options_array_first(o);
	while (a != NULL) {
		ov = options_array_item_value(a);
		found = 0;
		RB_FOREACH_SAFE(envent, environ, src, envent1) {
			if (fnmatch(ov->string, envent->name, 0) == 0) {
				/*
				 * Security: Block dangerous variables that could
				 * be used for code injection attacks.
				 */
				if (environ_is_dangerous(envent->name)) {
					log_debug("environ: blocking dangerous variable %s",
					    envent->name);
					continue;
				}

				/*
				 * Security: Check explicit deny list.
				 */
				if (environ_is_denied(oo, envent->name))
					continue;

				/*
				 * Security: In secure mode, validate credential
				 * variables before updating.
				 */
				if (secure_mode && environ_is_credential(envent->name)) {
					if (!environ_validate_credential(envent->name,
					    envent->value)) {
						log_debug("environ: rejecting stale/invalid "
						    "credential %s=%s", envent->name,
						    envent->value ? envent->value : "(null)");
						environ_clear(dst, envent->name);
						continue;
					}
					log_debug("environ: validated credential %s",
					    envent->name);
				}

				environ_set(dst, envent->name, 0, "%s", envent->value);
				found = 1;
			}
		}
		if (!found)
			environ_clear(dst, ov->string);
		a = options_array_next(a);
	}
}

/* Push environment into the real environment - use after fork(). */
void
environ_push(struct environ *env)
{
	struct environ_entry	*envent;

	environ = xcalloc(1, sizeof *environ);
	RB_FOREACH(envent, environ, env) {
		if (envent->value != NULL &&
		    *envent->name != '\0' &&
		    (~envent->flags & ENVIRON_HIDDEN))
			setenv(envent->name, envent->value, 1);
	}
}

/* Log the environment. */
void
environ_log(struct environ *env, const char *fmt, ...)
{
	struct environ_entry	*envent;
	va_list			 ap;
	char			*prefix;

	va_start(ap, fmt);
	vasprintf(&prefix, fmt, ap);
	va_end(ap);

	RB_FOREACH(envent, environ, env) {
		if (envent->value != NULL && *envent->name != '\0') {
			log_debug("%s%s=%s", prefix, envent->name,
			    envent->value);
		}
	}

	free(prefix);
}

/* Create initial environment for new child. */
struct environ *
environ_for_session(struct session *s, int no_TERM)
{
	struct environ	*env;
	const char	*value;
	int		 idx;

	env = environ_create();
	environ_copy(global_environ, env);
	if (s != NULL)
		environ_copy(s->environ, env);

	if (!no_TERM) {
		value = options_get_string(global_options, "default-terminal");
		environ_set(env, "TERM", 0, "%s", value);
		environ_set(env, "TERM_PROGRAM", 0, "%s", "tmux");
		environ_set(env, "TERM_PROGRAM_VERSION", 0, "%s", getversion());
		environ_set(env, "COLORTERM", 0, "truecolor");
	}

#ifdef HAVE_SYSTEMD
	environ_clear(env, "LISTEN_PID");
	environ_clear(env, "LISTEN_FDS");
	environ_clear(env, "LISTEN_FDNAMES");
#endif

	if (s != NULL)
		idx = s->id;
	else
		idx = -1;
	environ_set(env, "TMUX", 0, "%s,%ld,%d", socket_path, (long)getpid(),
	    idx);

	return (env);
}
