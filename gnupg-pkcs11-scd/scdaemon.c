/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
   @file
   Main command loop for scdaemon. For compatibility with GnuPG's scdaemon,
   all command-line options are silently ignored.

   @todo True daemon mode and multi-server mode are not yet implemented. Only
   one card is currently supported. Client notification of card status change
   is not implemented.
*/

#include "common.h"
#include "command.h"
#include "dconfig.h"
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include <pkcs11-helper-1.0/pkcs11h-token.h>
#if !defined(HAVE_W32_SYSTEM)
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#endif

#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#endif

#ifdef HAVE_W32_SYSTEM
typedef void *gnupg_fd_t;
#define GNUPG_INVALID_FD ((void*)(-1))
#define INT2FD(s) ((void *)(s))
#define FD2INT(h) ((unsigned int)(h))
#else
typedef int gnupg_fd_t;
#define GNUPG_INVALID_FD (-1)
#define INT2FD(s) (s)
#define FD2INT(h) (h)
#endif

typedef enum {
	ACCEPT_THREAD_STOP,
	ACCEPT_THREAD_CLEAN
} accept_command_t;

struct global_s;

#if !defined(HAVE_W32_SYSTEM)
typedef struct thread_list_s {
	struct thread_list_s *next;
	int fd;
	pthread_t thread;
	int stopped;
	struct global_s *global;
} *thread_list_t;
#endif

typedef struct global_s {
	dconfig_data_t config;
	char *socket_name;
#if !defined(HAVE_W32_SYSTEM)
	thread_list_t *threads;
	char *socket_dir;
	int fd_accept_terminate[2];
	uid_t uid_acl;
#endif

} global_t;

#if !defined(HAVE_W32_SYSTEM)
static int s_parent_pid = -1;
#endif

#define ALARM_INTERVAL 10
#define SOCKET_DIR_TEMPLATE ( PACKAGE ".XXXXXX" )

/** Register commands with assuan. */
static
int
register_commands (const assuan_context_t ctx)
{
	static struct {
		const char *name;
		assuan_handler_t handler;
		const char * const help;
	} table[] = {
		{ "SERIALNO",	cmd_serialno, NULL },
		{ "LEARN",	cmd_learn, NULL },
		{ "READCERT",	cmd_readcert, NULL },
		{ "READKEY",	cmd_readkey, NULL },
		{ "KEY-DATA",	NULL, NULL },
		{ "SETDATA",	cmd_setdata, NULL },
		{ "PKSIGN",	cmd_pksign, NULL },
		{ "PKAUTH",	cmd_pkauth, NULL },
		{ "PKDECRYPT",	cmd_pkdecrypt, NULL },
		{ "INPUT",	NULL, NULL }, 
		{ "OUTPUT",	NULL, NULL }, 
		{ "GETATTR",	cmd_getattr, NULL },
		{ "SETATTR",	cmd_setattr, NULL },
		{ "WRITECERT",	NULL, NULL },
		{ "WRITEKEY",	NULL, NULL },
		{ "GENKEY",	cmd_genkey, NULL },
		{ "RANDOM",	NULL, NULL },
		{ "PASSWD",	NULL, NULL },
		{ "CHECKPIN",	cmd_null, NULL },
		{ "LOCK",	NULL, NULL },
		{ "UNLOCK",	NULL, NULL },
		{ "GETINFO",	cmd_getinfo, NULL },
		{ "KEYINFO",	cmd_keyinfo, NULL },	/* gnupg-2.3.x */
		{ "RESTART",	cmd_restart, NULL },
		{ "DISCONNECT",	cmd_null, NULL },
		{ "APDU",	NULL, NULL },
		{ "CHV-STATUS-1", cmd_null, NULL },	/* gnupg-1.X */
		{ NULL, NULL, NULL }
	};
	int i, ret;

	for(i=0; table[i].name; i++) {
		if (
			(ret = assuan_register_command (
				ctx,
				table[i].name,
				table[i].handler,
				table[i].help
			))
		) {
			return ret;
		}
	} 

	assuan_set_hello_line (ctx, "PKCS#11 smart-card server for GnuPG ready");
	/*assuan_register_reset_notify(ctx, reset_notify);*/
	/*assuan_register_option_handler(ctx, option_handler);*/
	return 0;
}

/**
   Command handler (single-threaded). If fd == -1, this is a pipe server,
   otherwise fd is UNIX socket fd to which client connected.
*/
static
void
command_handler (global_t *global, const int fd)
{
	assuan_context_t ctx = NULL;
	cmd_data_t data;
	int ret;

#if !defined(HAVE_W32_SYSTEM)
	if (fd != -1 && global->uid_acl != (uid_t)-1) {
		uid_t peeruid = -1;
#if HAVE_DECL_LOCAL_PEERCRED
		struct xucred xucred;
		socklen_t len = sizeof(xucred);
		if (getsockopt(fd, SOL_SOCKET, LOCAL_PEERCRED, &xucred, &len) == -1) {
			common_log (LOG_WARNING, "Cannot get socket credentials: %s", strerror (errno));
			goto cleanup;
		}
		if (xucred.cr_version != XUCRED_VERSION) {
			common_log (LOG_WARNING, "Mismatch credentials version actual %d expected %d", xucred.cr_version, XUCRED_VERSION);
			goto cleanup;
		}
		peeruid = xucred.cr_uid;
#elif HAVE_DECL_SO_PEERCRED
		struct ucred ucred;
		socklen_t len = sizeof(ucred);
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
			common_log (LOG_WARNING, "Cannot get socket credentials: %s", strerror (errno));
			goto cleanup;
		}
		peeruid = ucred.uid;
#endif
		if (peeruid != global->uid_acl) {
			common_log (LOG_WARNING, "Mismatch credentials actual %d expected %d", peeruid, global->uid_acl);
			goto cleanup;
		}
	}
#endif

	memset (&data, 0, sizeof (data));
	data.config = &global->config;
	data.socket_name = global->socket_name;

	if ((ret = assuan_new(&ctx)) != 0) {
		common_log (LOG_ERROR,"failed to create assuan context %s", gpg_strerror (ret));
		goto cleanup;
	}

	if(fd < 0) {
#if !defined(HAVE_W32_SYSTEM)
		assuan_fd_t fds[2] = {INT2FD(0), INT2FD(1)};
#else
		assuan_fd_t fds[2] = {GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE)};
#endif
		ret = assuan_init_pipe_server (ctx, fds);
	} else {
		ret = assuan_init_socket_server (ctx, INT2FD(fd), ASSUAN_SOCKET_SERVER_ACCEPTED);
	}

	if (ret != 0) {
		common_log (LOG_ERROR,"failed to initialize server: %s", gpg_strerror (ret));
		goto cleanup;
	}

	if(((ret = register_commands(ctx))) != 0) {
		common_log (LOG_ERROR,"failed to register assuan commands: %s", gpg_strerror (ret));
		goto cleanup;
	}

	if (global->config.verbose) {
		assuan_set_log_stream (ctx, common_get_log_stream());
	}

	assuan_set_pointer (ctx, &data);

	while (1) {
		common_log (LOG_DEBUG, "accepting connection");

		if ((ret = assuan_accept (ctx)) == -1) {
			break;
		}

		if (ret != 0) {
			common_log (LOG_WARNING,"assuan_accept failed: %s", gpg_strerror(ret));
			break;
		}

		common_log (LOG_DEBUG, "processing connection");

		if ((ret = assuan_process (ctx)) != 0) {
			common_log (LOG_WARNING,"assuan_process failed: %s", gpg_strerror(ret));
		}

		common_log (LOG_DEBUG, "post-processing connection");
	}

cleanup:

	common_log (LOG_DEBUG, "cleanup connection");

	if (ctx != NULL) {
		cmd_free_data (ctx);
		assuan_release (ctx);
		ctx = NULL;
	}
}

#if !defined(HAVE_W32_SYSTEM)
static
void
server_socket_close (global_t *global, const int fd) {
	if (fd != -1) {
		assuan_sock_close (fd);
	}
	if (global->socket_name != NULL) {
		unlink (global->socket_name);
		free (global->socket_name);
		global->socket_name = NULL;
	}
	if (global->socket_dir != NULL) {
		rmdir (global->socket_dir);
		free (global->socket_dir);
		global->socket_dir = NULL;
	}
	assuan_sock_deinit();
}

static
void
server_socket_create_name (global_t *global) {

	char *socketdir = getenv("GNUPG_PKCS11_SOCKETDIR");
	if (socketdir == NULL) {
		socketdir = getenv("TMPDIR");
	}
	if (socketdir == NULL) {
		socketdir = "/tmp";
	}

	if ((global->socket_dir = malloc(strlen(socketdir) + strlen(SOCKET_DIR_TEMPLATE) + 100)) == NULL) {
		common_log (LOG_FATAL, "malloc");
	}
	sprintf(global->socket_dir, "%s/%s", socketdir, SOCKET_DIR_TEMPLATE);

	if (mkdtemp (global->socket_dir) == NULL) {
		common_log (LOG_FATAL, "Cannot mkdtemp");
	}

	if ((global->socket_name = (char *)malloc (strlen (global->socket_dir) + 100)) == NULL) {
		common_log (LOG_FATAL, "Cannot malloc");
	}

	sprintf (global->socket_name, "%s/agent.S", global->socket_dir);

}

static
int
server_socket_create (global_t *global) {
	struct sockaddr_un serv_addr;
	int fd = -1;
	int rc = -1;

	if ((rc = assuan_sock_init()) != 0) {
		common_log (LOG_ERROR,"Cannot init socket %s", gpg_strerror (rc));
		goto cleanup;
	}

	memset (&serv_addr, 0, sizeof (serv_addr));
	serv_addr.sun_family = AF_UNIX;
	assert (strlen (global->socket_name) + 1 < sizeof (serv_addr.sun_path));
	strcpy (serv_addr.sun_path, global->socket_name);

	if ((fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0)) == -1) {
		common_log (LOG_ERROR, "Cannot create  socket", global->socket_name);
		goto cleanup;
	}

	if ((rc = assuan_sock_bind (fd, (struct sockaddr*)&serv_addr, sizeof (serv_addr))) == -1) {
		common_log (LOG_ERROR, "Cannot bing to  socket '%s'", global->socket_name);
		goto cleanup;
	}

#if !defined(HAVE_W32_SYSTEM)
	if (global->uid_acl != (uid_t)-1) {
		if (chmod(global->socket_name, 0666) == -1) {
			common_log (LOG_ERROR, "Cannot chmod '%s'", global->socket_name);
			goto cleanup;
		}
		if (chmod(global->socket_dir, 0755) == -1) {
			common_log (LOG_ERROR, "Cannot chmod '%s'", global->socket_dir);
			goto cleanup;
		}
	}
#endif

	if ((rc = listen (fd, SOMAXCONN)) == -1) {
		common_log (LOG_ERROR, "Cannot listen to socket '%s'", global->socket_name);
		goto cleanup;
	}

	rc = 0;

cleanup:

	if (rc != 0) {
		server_socket_close (global, fd);
		common_log (LOG_FATAL, "Cannot handle socket");
	}

	common_log (LOG_INFO, "Listening to socket '%s'", global->socket_name);

	return fd;
}

static
void *
_server_socket_command_handler (void *arg) {
	thread_list_t entry = (thread_list_t)arg;
	accept_command_t clean = ACCEPT_THREAD_CLEAN;

	command_handler (entry->global, entry->fd);
	entry->stopped = 1;

	if (write (entry->global->fd_accept_terminate[1], &clean, sizeof (clean)) == -1) {
		common_log (LOG_FATAL, "write failed");
	}

	return NULL;
}

static
void *
_server_socket_accept (void *arg) {
	thread_list_t _entry = (thread_list_t)arg;
	global_t *global = _entry->global;
	int fd = _entry->fd;
	thread_list_t thread_list_head = NULL;
	int rc = 0;

	free (_entry);
	_entry = NULL;

	if (pipe (global->fd_accept_terminate) == -1) {
		common_log (LOG_FATAL, "pipe failed");
	}

	while (rc != -1) {
		fd_set fdset;

		FD_ZERO (&fdset);
		FD_SET (global->fd_accept_terminate[0], &fdset);
		FD_SET (fd, &fdset);

		rc = select (FD_SETSIZE, &fdset, NULL, NULL, NULL);

		if (rc != -1 && rc != 0) {
			if (FD_ISSET (global->fd_accept_terminate[0], &fdset)) {
				accept_command_t cmd;

				if (
					(rc = read (
						global->fd_accept_terminate[0],
						&cmd,
						sizeof (cmd))
					) == sizeof (cmd)
				) {
					if (cmd == ACCEPT_THREAD_STOP) {
						common_log (LOG_DEBUG, "Thread command terminate");
						rc = -1;
					}
					else if (cmd == ACCEPT_THREAD_CLEAN) {
						thread_list_t entry = thread_list_head;
						thread_list_t prev = NULL;

						common_log (LOG_DEBUG, "Cleaning up closed thread");
						while (entry != NULL) {
							if (entry->stopped) {
								thread_list_t temp = entry;

								common_log (LOG_DEBUG, "Cleaning up closed thread1");
								pthread_join (entry->thread, NULL);
								close (entry->fd);

								if (prev == NULL) {
									thread_list_head = entry->next;
								}
								else {
									prev->next = entry->next;
								}

								entry = entry->next;

								free (temp);
							}
							else {
								prev = entry;
								entry = entry->next;
							}
						}
					}
				}
			}
			else if (FD_ISSET (fd, &fdset)) {
				struct sockaddr_un addr;
				socklen_t addrlen = sizeof (addr);
				int fd2;

				if ((rc = fd2 = accept (fd, (struct sockaddr *)&addr, &addrlen)) != -1) {
					thread_list_t entry = NULL;

					common_log (LOG_DEBUG, "Accepted new socket connection");

					if ((entry = (thread_list_t)malloc (sizeof (struct thread_list_s))) == NULL) {
						common_log (LOG_FATAL, "malloc failed");
					}
					memset (entry, 0, sizeof (struct thread_list_s));
					entry->next = thread_list_head;
					entry->fd = fd2;
					entry->global = global;
					thread_list_head = entry;

					if (
						pthread_create (
							&entry->thread,
							NULL,
							_server_socket_command_handler,
							entry
						)
					) {
						common_log (LOG_FATAL, "pthread failed");
					}

				}
			}
		}
	}

	common_log (LOG_DEBUG, "Cleaning up threads");
	while (thread_list_head != NULL) {
		thread_list_t entry = thread_list_head;
		thread_list_head = thread_list_head->next;
		common_log (LOG_DEBUG, "Cleaning up thread1");
		close (entry->fd);
		pthread_join (entry->thread, NULL);
		free (entry);
	}

	return NULL;
}

static
void
server_socket_accept (global_t *global, const int fd, pthread_t *thread) {
	thread_list_t entry = malloc (sizeof (struct thread_list_s));
	memset (entry, 0, sizeof (struct thread_list_s));
	entry->fd = fd;
	entry->global = global;
	if (pthread_create (thread, NULL, _server_socket_accept, (void *)entry)) {
		common_log (LOG_FATAL, "pthread failed");
	}
}

static
void
server_socket_accept_terminate (global_t *global, pthread_t thread) {
	accept_command_t stop = ACCEPT_THREAD_STOP;
	if (write (global->fd_accept_terminate[1], &stop, sizeof (stop)) == -1) {
		common_log (LOG_FATAL, "write failed");
	}
	pthread_join (thread, NULL);
	close (global->fd_accept_terminate[0]);
	close (global->fd_accept_terminate[1]);
}
#endif				/* HAVE_W32_SYSTEM */

static
void
pkcs11_log_hook (
	void * const data,
	const unsigned flags,
	const char * const fmt,
	va_list args
) {
	(void)data;
	(void)flags;

	common_vlog (LOG_INFO, fmt, args);
}

static
PKCS11H_BOOL
pkcs11_token_prompt_hook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry
) {
	char cmd[1024];
	unsigned char *user_read = NULL;
	size_t user_read_len = 0;
	assuan_context_t ctx = user_data;
	int rc;
	int ret = FALSE;
	char *ser = NULL;
	size_t n;

	(void)global_data;
	(void)retry;

	if (
		(rc = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				NULL,
				&n,
				token
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((ser = (char *)malloc(n)) == NULL) {
		rc = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(rc = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				ser,
				&n,
				token
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	snprintf (
		cmd,
		sizeof(cmd),
		"NEEDPIN %s",
		ser
	);

	if ((rc = assuan_inquire (ctx, cmd, &user_read, &user_read_len, 1024))) {
		common_log (LOG_WARNING, "Token inquire error: %d", rc);
		goto cleanup;
	}

	if (!strcmp ((char *)user_read, "cancel") || !strcmp((char *)user_read, "no")) {
		goto cleanup;
	}

	ret = TRUE;

cleanup:

	if (ser != NULL) {
		free(ser);
		ser = NULL;
	}

	if (user_read != NULL) {
		memset (user_read, 0, strlen ((char *)user_read));
		free (user_read);
		user_read = NULL;
	}

	return ret;
}

static
PKCS11H_BOOL
pkcs11_pin_prompt_hook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t max_pin
) {
	char cmd[1024];
	assuan_context_t ctx = user_data;
	unsigned char *pin_read = NULL;
	size_t pin_len;
	int rc;
	int ret = FALSE;
	char *ser = NULL;
	size_t n;

	(void)global_data;

	if (
		(rc = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				NULL,
				&n,
				token
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	if ((ser = (char *)malloc(n)) == NULL) {
		rc = GPG_ERR_ENOMEM;
		goto cleanup;
	}

	if (
		(rc = common_map_pkcs11_error(
			pkcs11h_token_serializeTokenId(
				ser,
				&n,
				token
			)
		)) != GPG_ERR_NO_ERROR
	) {
		goto cleanup;
	}

	snprintf (
		cmd,
		sizeof(cmd),
		"NEEDPIN %s",
		ser
	);

	if ((rc = assuan_inquire (ctx, cmd, &pin_read, &pin_len, 1024))) {
		common_log (LOG_WARNING,"PIN inquire error: %d", rc);
		goto cleanup;
	}

	if (pin_len==0 || (pin_len+1 > max_pin)) {
		rc = GPG_ERR_TOO_LARGE;
		goto cleanup;
	}

	strcpy (pin, (char *)pin_read);

	ret = TRUE;

cleanup:

	if (ser != NULL) {
		free(ser);
		ser = NULL;
	}

	if (pin_read != NULL) {
		memset (pin_read, 0, strlen ((char *)pin_read));
		free (pin_read);
		pin_read = NULL;
	}

	return ret;
}

#if !defined(HAVE_W32_SYSTEM)
static RETSIGTYPE on_alarm (int signo)
{
	(void)signo;

	if (s_parent_pid != -1 && kill (s_parent_pid, 0) == -1) {
		kill (getpid (), SIGTERM);
	}

	signal (SIGALRM, on_alarm);
	alarm (ALARM_INTERVAL);

#if RETSIGTYPE != void
	return 0
#endif
}

static RETSIGTYPE on_signal (int signo)
{
	(void)signo;

	/*
	 * This is the only way to notify
	 * assuan to return from its main loop...
	 */
	close (0);
	close (1);

#if RETSIGTYPE != void
	return 0
#endif
}
#endif				/* HAVE_W32_SYSTEM */

static void usage (const char * const argv0)
{

	printf (
		(
"%s %s\n"
"\n"
"Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>\n"
"Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>\n"
"This program comes with ABSOLUTELY NO WARRANTY.\n"
"This is free software, and you are welcome to redistribute it\n"
"under certain conditions. See the file COPYING for details.\n"
"\n"
"Syntax: %s [options]\n"
"Smartcard daemon for GnuPG\n"
"\n"
"Options:\n"
" \n"
"     --server              run in server mode (foreground)\n"
"     --multi-server        run in multi server mode (foreground)\n"
"     --daemon              run in daemon mode (background)\n"
" -v, --verbose             verbose\n"
" -q, --quiet               be somewhat more quiet\n"
" -s, --sh                  sh-style command output\n"
" -c, --csh                 csh-style command output\n"
"     --options             read options from file\n"
"     --no-detach           do not detach from the console\n"
"     --homedir             specify home directory\n"
#if !defined(HAVE_W32_SYSTEM)
"     --uid-acl             accept only this uid, implies world read/write socket\n"
#endif
"     --log-file            use a log file for the server\n"
"     --help                print this information\n"
		),
		PACKAGE,
		PACKAGE_VERSION,
		argv0
	);
}

static char *get_home_dir (void) {
#if defined(HAVE_W32_SYSTEM)
	static const char * GPG_HOME_KEY = "Software\\GNU\\GnuPG";
	const char *HOME_ENV = getenv ("USERPROFILE");
#else
	const char *HOME_ENV = getenv ("HOME");
#endif
	char *home_dir = NULL;

	if (home_dir == NULL && getenv ("GNUPGHOME") != NULL) {
		home_dir=strdup (getenv ("GNUPGHOME"));
	}
#if defined(HAVE_W32_SYSTEM)
	if (home_dir == NULL) {
		char key_val[1024];
		HKEY hkey = NULL;
		DWORD dw = 0;

		if (RegOpenKeyEx (HKEY_CURRENT_USER, GPG_HOME_KEY, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
			if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, GPG_HOME_KEY, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
				hkey = NULL;
			}
		}
		if (hkey != NULL) {
			if (
				RegQueryValueEx (
					hkey,
					"HomeDir",
					NULL,
					NULL,
					(PBYTE)key_val,
					&dw
				) == ERROR_SUCCESS
			) {
				home_dir = strdup (key_val);
			}
		}
		if (hkey != NULL) {
			RegCloseKey (hkey);
		}

	}
#endif

	if (home_dir == NULL) {
		if (
			CONFIG_GPG_HOME[0] == '~' &&
			HOME_ENV != NULL
		) {
			if ((home_dir=(char *)malloc (strlen (CONFIG_GPG_HOME) + strlen (HOME_ENV))) == NULL) {
				common_log (LOG_FATAL, "malloc failed");
			}
			sprintf (home_dir, "%s%s", HOME_ENV, CONFIG_GPG_HOME+1);
		}
		else {
			home_dir = strdup (CONFIG_GPG_HOME);
		}
	}

	return home_dir;
}

int main (int argc, char *argv[])
{
	enum {
		OPT_SERVER,
		OPT_MUTLI_SERVER,
		OPT_DAEMON,
		OPT_VERBOSE,
		OPT_QUIET,
		OPT_SH,
		OPT_CSH,
		OPT_OPTIONS,
		OPT_NO_DETACH,
		OPT_HOMEDIR,
#if !defined(HAVE_W32_SYSTEM)
		OPT_UID_ACL,
#endif
		OPT_LOG_FILE,
		OPT_VERSION,
		OPT_HELP
	};

	static struct option long_options[] = {
		{ "server", no_argument, NULL, OPT_SERVER },
		{ "multi-server", no_argument, NULL, OPT_MUTLI_SERVER },
		{ "daemon", no_argument, NULL, OPT_DAEMON },
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "quiet", no_argument, NULL, OPT_QUIET },
		{ "sh", no_argument, NULL, OPT_SH },
		{ "csh", no_argument, NULL, OPT_CSH },
		{ "options", required_argument, NULL, OPT_OPTIONS },
		{ "no-detach", no_argument, NULL, OPT_NO_DETACH },
		{ "homedir", required_argument, NULL, OPT_HOMEDIR },
#if !defined(HAVE_W32_SYSTEM)
		{ "uid-acl", required_argument, NULL, OPT_UID_ACL },
#endif
		{ "log-file", required_argument, NULL, OPT_LOG_FILE },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	enum {
		RUN_MODE_NONE,
		RUN_MODE_SERVER,
		RUN_MODE_MULTI_SERVER,
		RUN_MODE_DAEMON
	} run_mode = RUN_MODE_NONE;
	int env_is_csh = 0;
	int log_verbose = 0;
	int log_quiet = 0;
	int no_detach = 0;
	char *config_file = NULL;
	char *log_file = NULL;
	char *home_dir = NULL;
	int have_at_least_one_provider=0;
	FILE *fp_log = NULL;
	int i;
	CK_RV rv;

	global_t global;

	const char * CONFIG_SUFFIX = ".conf";
	char *default_config_file = NULL;

	/* unused intentionally */
	(void)log_quiet;

	memset(&global, 0, sizeof(global));

#if !defined(HAVE_W32_SYSTEM)
	s_parent_pid = getpid ();
	global.fd_accept_terminate[0] = -1;
	global.fd_accept_terminate[1] = -1;
	global.uid_acl = (uid_t)-1;
#endif

	if ((default_config_file = (char *)malloc (strlen (PACKAGE)+strlen (CONFIG_SUFFIX)+1)) == NULL) {
		common_log (LOG_FATAL, "malloc failed");
	}
	sprintf (default_config_file, "%s%s", PACKAGE, CONFIG_SUFFIX);

	common_set_log_stream (stderr);

	while ((opt = getopt_long (argc, argv, "vqsc", long_options, NULL)) != -1) {
		switch (opt) {
			case OPT_SERVER:
				run_mode = RUN_MODE_SERVER;
			break;
			case OPT_MUTLI_SERVER:
				run_mode = RUN_MODE_MULTI_SERVER;
			break;
			case OPT_DAEMON:
				run_mode = RUN_MODE_DAEMON;
			break;
			case OPT_VERBOSE:
			case 'v':
				log_verbose = 1;
			break;
			case OPT_QUIET:
			case 'q':
				log_quiet = 1;
			break;
			case OPT_SH:
			case 's':
			break;
			case OPT_CSH:
			case 'c':
				env_is_csh = 1;
			break;
			case OPT_OPTIONS:
				config_file = strdup (optarg);
			break;
			case OPT_NO_DETACH:
				no_detach = 1;
			break;
			case OPT_HOMEDIR:
				home_dir = strdup (optarg);
			break;
#if !defined(HAVE_W32_SYSTEM)
			case OPT_UID_ACL:
				global.uid_acl = atoi(optarg);
			break;
#endif
			case OPT_LOG_FILE:
				log_file = optarg;
			break;
			case OPT_VERSION:
				printf (
					"%s %s\n"
					"\n"
					"Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>\n"
					"Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>\n"
					"\n"
					"This is free software; see the source for copying conditions.\n"
					"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
					PACKAGE,
					PACKAGE_VERSION
				);
				exit (0);
			break;
			case OPT_HELP:
				usage(argv[0]);
				exit(0);
			break;
			default:
				fprintf(stderr, "Invalid usage\n");
				exit(1);
			break;
		}
	}

	if (run_mode == RUN_MODE_NONE) {
		common_log (LOG_FATAL, "please use the option `--daemon' to run the program in the background");
	}

#if defined(HAVE_W32_SYSTEM)
	if (run_mode == RUN_MODE_DAEMON) {
		common_log (LOG_FATAL, "daemon mode is not supported");
	}
#endif

	if (home_dir == NULL) {
		home_dir = get_home_dir ();
	}

	if (config_file == NULL) {
		if ((config_file = (char *)malloc (strlen (home_dir) + strlen (default_config_file)+2)) == NULL) {
			common_log (LOG_FATAL, "malloc failed");
		}
		sprintf (config_file, "%s%c%s", home_dir, CONFIG_PATH_SEPARATOR, default_config_file);
	}

	if (
		!dconfig_read (config_file, &global.config) &&
		!dconfig_read (CONFIG_SYSTEM_CONFIG, &global.config)
	) {
		common_log (LOG_FATAL, "Cannot open configuration file");
	}

	if (log_verbose) {
		global.config.verbose = 1;
	}

#if !defined(HAVE_W32_SYSTEM)
	signal (SIGPIPE, SIG_IGN);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(action));
		action.sa_handler = on_signal;
		sigaction(SIGINT, &action, NULL);
		sigaction(SIGTERM, &action, NULL);
		sigaction(SIGABRT, &action, NULL);
		sigaction(SIGHUP, &action, NULL);
	}
#endif

	if (log_file == NULL) {
		log_file = global.config.log_file;
	}

	if (log_file != NULL) {
		if (strcmp (log_file, "stderr") != 0) {
			if ((fp_log = fopen (log_file, "a")) != NULL) {
#if !defined(HAVE_W32_SYSTEM)
				fchmod(fileno(fp_log), 0600);
#else
				_chmod(log_file, 0600);
#endif
				common_set_log_stream (fp_log);
			}
		}
	}

	if (global.config.debug) {
		common_log (LOG_DEBUG, "version: %s", PACKAGE_VERSION);
		dconfig_print (&global.config);
		common_log (LOG_DEBUG, "run_mode: %d", run_mode);
		common_log (LOG_DEBUG, "crypto: %s",
#if defined(ENABLE_OPENSSL)
			"openssl"
#elif defined(ENABLE_GNUTLS)
			"gnutls"
#else
			"invalid"
#endif
		);
	}

	if (!gcry_check_version (GCRYPT_VERSION)) {
		common_log (LOG_FATAL, "Cannot initialize libcrypt");
	}
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

#if !defined(HAVE_W32_SYSTEM)
	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_create_name (&global);
	}

	/*
	 * fork before doing PKCS#11 stuff
	 * some providers don't behave well
	 */
	if (run_mode == RUN_MODE_DAEMON) {
		pid_t pid;

		pid = fork ();

		if (pid == -1) {
			common_log (LOG_FATAL, "fork failed");
		}

		if (pid != 0) {
			static const char *key = "SCDAEMON_INFO";
			char env[1024];
			snprintf (env, sizeof (env), "%s:%lu:1", global.socket_name, (unsigned long)pid);

			if (optind < argc) {
				setenv(key, env, 1);
				execvp (argv[optind], &(argv[optind]));
				kill (pid, SIGTERM);
				exit (1);
			}
			else {
				if (env_is_csh) {
					*strchr (env, '=') = ' ';
					printf ("setenv %s %s\n", key, env);
				}
				else {
					printf ("%s=%s; export %s\n", key, env, key);
				}
				exit (0);
			}
		}

		if (!no_detach) {
			int i;

			for (i=0;i<3;i++) {
				if (fileno (common_get_log_stream ()) != i) {
					close (i);
				}
			}

			if (setsid () == -1) {
				common_log (LOG_FATAL, "setsid failed");
			}
		}

		if (chdir ("/") == -1) {
			common_log (LOG_FATAL, "chdir failed");
		}

		if (optind < argc) {
			struct sigaction sa;

			memset (&sa, 0, sizeof (sa));
			sigemptyset (&sa.sa_mask);
#if defined(SA_INTERRUPT)
			sa.sa_flags |= SA_INTERRUPT;
#endif
			sa.sa_handler = on_alarm;
			sigaction (SIGALRM, &sa, NULL);
			alarm (10);
		}
	}
#endif				/* HAVE_W32_SYSTEM */

	assuan_set_assuan_log_prefix (PACKAGE);
	assuan_set_assuan_log_stream (common_get_log_stream ());

#if defined(USE_GNUTLS)
	if (gnutls_global_init () != GNUTLS_E_SUCCESS) {
		common_log (LOG_FATAL, "Cannot initialize gnutls");
	}
#endif

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		common_log (LOG_FATAL, "Cannot initialize PKCS#11: %s", pkcs11h_getMessage (rv));
	}

	pkcs11h_setLogLevel (global.config.verbose ? PKCS11H_LOG_DEBUG2 : PKCS11H_LOG_INFO);
	pkcs11h_setLogHook (pkcs11_log_hook, NULL);
	pkcs11h_setTokenPromptHook (pkcs11_token_prompt_hook, NULL);
	pkcs11h_setPINPromptHook (pkcs11_pin_prompt_hook, NULL);
	pkcs11h_setProtectedAuthentication (TRUE);
	pkcs11h_setPINCachePeriod(global.config.pin_cache);

	for (i=0;i<DCONFIG_MAX_PROVIDERS;i++) {
		if (
			global.config.providers[i].name != NULL &&
			global.config.providers[i].library != NULL
		) {
			if (
				(rv = pkcs11h_addProvider (
					global.config.providers[i].name,
					global.config.providers[i].library,
					global.config.providers[i].allow_protected,
					global.config.providers[i].private_mask,
					PKCS11H_SLOTEVENT_METHOD_POLL,
					0,
					global.config.providers[i].cert_is_private
				)) != CKR_OK
			) {
				common_log (LOG_WARNING, "Cannot add PKCS#11 provider '%s': %ld-'%s'", global.config.providers[i].name, rv, pkcs11h_getMessage (rv));
			}
			else {
				have_at_least_one_provider = 1;
			}
		}
	}

	if (!have_at_least_one_provider) {
		common_log (LOG_FATAL, "Could not load any provider");
	}

#if defined(HAVE_W32_SYSTEM)
	command_handler (&global, -1);
#else
{
	pthread_t accept_thread = 0;
	int accept_socket = -1;

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		accept_socket = server_socket_create (&global);

		server_socket_accept (&global, accept_socket, &accept_thread);
	}

	if (run_mode == RUN_MODE_DAEMON) {
		/*
		 * Emulate assuan behavior
		 */
		int fds[2];
		char c;
		if (pipe (fds)==-1) {
			common_log (LOG_FATAL, "Could not create pipe");
		}
		close (0);
		dup2 (fds[0], 0);
		close (fds[0]);
		while (read (0, &c, 1) == -1 && errno == EINTR);
		close (fds[1]);
	}
	else {
		command_handler (&global, -1);
	}

	common_log (LOG_DEBUG, "Terminating");

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_accept_terminate (&global, accept_thread);
		server_socket_close (&global, accept_socket);
	}
}
#endif

	pkcs11h_terminate ();

#if defined(USE_GNUTLS)
	gnutls_global_deinit ();
#endif

	dconfig_free (&global.config);

	if (config_file != NULL) {
		free (config_file);
		config_file = NULL;
	}

	if (default_config_file != NULL) {
		free (default_config_file);
		default_config_file = NULL;
	}

	if (home_dir != NULL) {
		free (home_dir);
		home_dir = NULL;
	}

	if (fp_log != NULL) {
		fclose (fp_log);
		fp_log = NULL;
	}

	return 0;
}

