/*
 * Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "scdaemon.h"
#include "command.h"
#include "dconfig.h"
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <errno.h>

#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#endif

typedef enum {
	ACCEPT_THREAD_STOP,
	ACCEPT_THREAD_CLEAN
} accept_command_t;

typedef struct thread_list_s {
	struct thread_list_s *next;
	int fd;
	pthread_t thread;
	int stopped;
} *thread_list_t;

#define ALARM_INTERVAL 10
#define SOCKET_DIR_TEMPLATE ( "/tmp/" PACKAGE ".XXXXXX" )

static char *s_socket_dir = NULL;
static char *s_socket_name = NULL;
static int s_fd_accept_terminate[2] = {-1, -1};
static int s_parent_pid = -1;

const char *
scdaemon_get_socket_name () {
	return s_socket_name;
}

/** Register commands with assuan. */
static
int
register_commands (const assuan_context_t ctx)
{
	static struct {
		const char *name;
		int (*handler)(assuan_context_t ctx, char *line);
	} table[] = {
		{ "SERIALNO",  cmd_serialno, },
		{ "LEARN",     cmd_learn },
		{ "READCERT",  cmd_readcert },
		{ "READKEY",   cmd_readkey },
		{ "SETDATA",   cmd_setdata },
		{ "PKSIGN",    cmd_pksign },
		{ "PKAUTH",    NULL },
		{ "PKDECRYPT", cmd_pkdecrypt },
		{ "INPUT",     NULL }, 
		{ "OUTPUT",    NULL }, 
		{ "GETATTR",   NULL },
		{ "SETATTR",   NULL },
		{ "WRITEKEY",  NULL },
		{ "GENKEY",    NULL },
		{ "RANDOM",    NULL },
		{ "PASSWD",    NULL },
		{ "CHECKPIN",  NULL },
		{ "LOCK",      NULL },
		{ "UNLOCK",    NULL },
		{ "GETINFO",   cmd_getinfo },
		{ NULL, NULL }
	};
	int i, ret;

	for(i=0; table[i].name; i++) {
		if (
			(ret = assuan_register_command(
				ctx,
				table[i].name,
				table[i].handler)
			)
		) {
			return ret;
		}
	} 
	assuan_set_hello_line(ctx, "PKCS#11 smart-card server for GnuPG ready");
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
command_handler (const int fd)
{
	assuan_context_t ctx = NULL;
	int ret;

	if(fd < 0) {
		int fds[2] = {0, 1};
		ret = assuan_init_pipe_server(&ctx, fds);
	} else {
		ret = assuan_init_connected_socket_server(&ctx, fd);
	}

	if (ret != ASSUAN_No_Error) {
		common_log (LOG_FATAL,"failed to initialize server: %s", assuan_strerror (ret));
	}

	if(((ret = register_commands(ctx))) != ASSUAN_No_Error) {
		common_log (LOG_FATAL,"failed to register assuan commands: %s", assuan_strerror (ret));
	}

	assuan_set_log_stream (ctx, assuan_get_assuan_log_stream ());
	assuan_set_pointer (ctx, NULL);

	while (1) {
		if ((ret = assuan_accept (ctx)) == -1) {
			break;
		}

		if (ret != ASSUAN_No_Error) {
			common_log (LOG_WARNING,"assuan_accept failed: %s", assuan_strerror(ret));
			break;
		}
		
		if ((ret = assuan_process (ctx)) != ASSUAN_No_Error) {
			common_log (LOG_WARNING,"assuan_process failed: %s", assuan_strerror(ret));
		}
	}

	cmd_free_data (ctx);

	if (ctx != NULL) {
		assuan_deinit_server (ctx);
		ctx = NULL;
	}
}

static
void
server_socket_close (const int fd) {
	if (fd != -1) {
		close (fd);
	}
	if (s_socket_name != NULL) {
		unlink (s_socket_name);
		free (s_socket_name);
		s_socket_name = NULL;
	}
	if (s_socket_dir != NULL) {
		rmdir (s_socket_dir);
		free (s_socket_dir);
		s_socket_dir = NULL;
	}
}

static
void
server_socket_create_name () {

	if ((s_socket_dir = strdup (SOCKET_DIR_TEMPLATE)) == NULL) {
		common_log (LOG_FATAL, "strdup");
	}

	if (mkdtemp (s_socket_dir) == NULL) {
		common_log (LOG_FATAL, "Cannot mkdtemp");
	}

	if ((s_socket_name = (char *)malloc (strlen (s_socket_dir) + 100)) == NULL) {
		common_log (LOG_FATAL, "Cannot malloc");
	}

	sprintf (s_socket_name, "%s/agent.S", s_socket_dir);

}

static
int
server_socket_create () {
	struct sockaddr_un serv_addr;
	int fd = -1;
	int rc = 0;

	if (rc == 0) {
		memset (&serv_addr, 0, sizeof (serv_addr));
		serv_addr.sun_family = AF_UNIX;
		assert (strlen (s_socket_name) + 1 < sizeof (serv_addr.sun_path));
		strcpy (serv_addr.sun_path, s_socket_name);
	}

	if (rc == 0 && (fd = socket (AF_UNIX, SOCK_STREAM, 0)) == -1) {
		common_log (LOG_ERROR, "Cannot create  socket", s_socket_name);
		rc = -1;
	}

	if (rc == 0 && (rc = bind (fd, (struct sockaddr*)&serv_addr, sizeof (serv_addr))) == -1) {
		common_log (LOG_ERROR, "Cannot bing to  socket '%s'", s_socket_name);
	}

	if (rc == 0 && (rc = listen (fd, SOMAXCONN)) == -1) {
		common_log (LOG_ERROR, "Cannot listen to socket '%s'", s_socket_name);
	}

	if (rc == -1) {
		server_socket_close (fd);

		common_log (LOG_FATAL, "Cannot handle socket");
	}

	common_log (LOG_INFO, "Listening to socket '%s'", s_socket_name);

	return fd;
}

static
void *
_server_socket_command_handler (void *arg) {
	thread_list_t entry = (thread_list_t)arg;
	accept_command_t clean = ACCEPT_THREAD_CLEAN;

	command_handler (entry->fd);
	entry->stopped = 1;

	write (s_fd_accept_terminate[1], &clean, sizeof (clean));

	return NULL;
}

static
void *
_server_socket_accept (void *arg) {
	int fd = (int)arg;
	int rc = 0;

	thread_list_t thread_list_head = NULL;
	if (pipe (s_fd_accept_terminate) == -1) {
		common_log (LOG_FATAL, "pipe failed");
	}

	while (rc != -1) {
		fd_set fdset;

		FD_ZERO (&fdset);
		FD_SET (s_fd_accept_terminate[0], &fdset);
		FD_SET (fd, &fdset);

		rc = select (FD_SETSIZE, &fdset, NULL, NULL, NULL);

		if (rc != -1 && rc != 0) {
			if (FD_ISSET (s_fd_accept_terminate[0], &fdset)) {
				accept_command_t cmd;
				
				if (
					(rc = read (
						s_fd_accept_terminate[0],
						&cmd,
						sizeof (cmd))
					) == sizeof (cmd)
				) {
					if (cmd == ACCEPT_THREAD_STOP) {
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
server_socket_accept (const int fd, pthread_t *thread) {
	if (pthread_create (thread, NULL, _server_socket_accept, (void *)fd)) {
		common_log (LOG_FATAL, "pthread failed");
	}
}

static
void
server_socket_accept_terminate (pthread_t thread) {
	accept_command_t stop = ACCEPT_THREAD_STOP;
	write (s_fd_accept_terminate[1], &stop, sizeof (stop));
	pthread_join (thread, NULL);
	close (s_fd_accept_terminate[0]);
	close (s_fd_accept_terminate[1]);
}

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
	int ret = TRUE;

	(void)global_data;

	if (ret) {
		snprintf (
			cmd,
			sizeof(cmd),
			"NEEDPIN PIN required for token %s (try %u)",
			token->display,
			retry
		);
	}

	if(ret && (rc = assuan_inquire (ctx, cmd, &pin_read, &pin_len, 1024))) {
		common_log (LOG_WARNING,"PIN inquire error: %d", rc);
		ret = FALSE;
	}

	if (ret && (pin_len==0 || (pin_len+1 > max_pin))) {
		ret = FALSE;
	}

	if (ret) {
		strcpy (pin, (char*)pin_read);
	}

	if (pin_read != NULL) {
		free (pin_read);
		pin_read = NULL;
	}

	return ret;
}

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

#if RETSIGTYPE != void
	return 0
#endif
}

static void usage (const char * const argv0)
{

	printf (
		(
"%s %s\n"
"\n"
"Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>\n"
"Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>\n"
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
"     --log-file            use a log file for the server\n"
"     --help                print this information\n"
		),
		PACKAGE,
		PACKAGE_VERSION,
		argv0
	);
	exit(1);
}

int main (int argc, char *argv[])
{
	enum {
		OPT_SERVER,
		OPT_MUTLI_SERVER,
		OPT_DAEMON,
		OPT_VERBOSE,
		OPT_QUITE,
		OPT_SH,
		OPT_CSH,
		OPT_OPTIONS,
		OPT_NO_DETACH,
		OPT_LOG_FILE,
		OPT_VERSION,
		OPT_HELP
	};

	static struct option long_options[] = {
		{ "server", no_argument, NULL, OPT_SERVER },
		{ "multi-server", no_argument, NULL, OPT_MUTLI_SERVER },
		{ "daemon", no_argument, NULL, OPT_DAEMON },
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "quite", no_argument, NULL, OPT_QUITE },
		{ "sh", no_argument, NULL, OPT_SH },
		{ "csh", no_argument, NULL, OPT_CSH },
		{ "options", required_argument, NULL, OPT_OPTIONS },
		{ "no-detach", no_argument, NULL, OPT_NO_DETACH },
		{ "log-file", required_argument, NULL, OPT_LOG_FILE },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int long_options_ret;
	int base_argc = 1;

	int usage_ok = 1;
	enum {
		RUN_MODE_NONE,
		RUN_MODE_SERVER,
		RUN_MODE_MULTI_SERVER,
		RUN_MODE_DAEMON
	} run_mode = RUN_MODE_NONE;
	int env_is_csh = 0;
	int log_verbose = 0;
	int log_quite = 0;
	int no_detach = 0;
	char *config_file = NULL;
	char *log_file = NULL;
	char *home_dir = NULL;
	int have_at_least_one_provider=0;
	FILE *fp_log = NULL;
	int i;
	CK_RV rv;

	dconfig_data config;

	const char * CONFIG_SUFFIX = ".conf";
	char *default_config_file = NULL;

	s_parent_pid = getpid ();

	if ((default_config_file = (char *)malloc (strlen (PACKAGE)+strlen (CONFIG_SUFFIX)+1)) == NULL) {
		common_log (LOG_FATAL, "malloc failed");
	}
	sprintf (default_config_file, "%s%s", PACKAGE, CONFIG_SUFFIX);

	common_set_log_stream (stderr);

	while ((long_options_ret = getopt_long (argc, argv, "vqsc", long_options, NULL)) != -1) {
		base_argc++;

		switch (long_options_ret) {
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
			case OPT_QUITE:
			case 'q':
				log_quite = 1;
			break;
			case OPT_SH:
			case 's':
			break;
			case OPT_CSH:
			case 'c':
				env_is_csh = 1;
			break;
			case OPT_OPTIONS:
				base_argc++;
				config_file = strdup (optarg);
			break;
			case OPT_NO_DETACH:
				no_detach = 1;
			break;
			case OPT_LOG_FILE:
				base_argc++;
				log_file = strdup (optarg);
			break;
			case OPT_VERSION:
				printf (
					"%s %s\n"
					"\n"
					"Copyright (c) 2006 Zeljko Vrba <zvrba@globalnet.hr>\n"
					"Copyright (c) 2006 Alon Bar-Lev <alon.barlev@gmail.com>\n"
					"\n"
					"This is free software; see the source for copying conditions.\n"
					"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
					PACKAGE,
					PACKAGE_VERSION
				);
				exit (1);
			break;
			case OPT_HELP:
				usage_ok = 0;
			break;
			default:
				usage_ok = 0;
			break;
		}
	}

	if (base_argc < argc) {
		if (!strcmp (argv[base_argc], "--")) {
			base_argc++;
		}
	}

	if (!usage_ok) {
		usage (argv[0]);
	}

	if (run_mode == RUN_MODE_NONE) {
		common_log (LOG_FATAL, "please use the option `--daemon' to run the program in the background");
	}

	if (getenv ("GNUPGHOME") != NULL) {
		home_dir=strdup (getenv ("GNUPGHOME"));
	}
	else if (
		CONFIG_GPG_HOME[0] == '~' &&
		getenv ("HOME") != NULL
	) {
		if ((home_dir=(char *)malloc (strlen (CONFIG_GPG_HOME) + strlen (getenv ("HOME")))) == NULL) {
			common_log (LOG_FATAL, "malloc failed");
		}
		sprintf (home_dir, "%s%s", getenv ("HOME"), CONFIG_GPG_HOME+1);
	}
	else {
		home_dir = strdup (CONFIG_GPG_HOME);
	}

	if (home_dir == NULL) {
		common_log (LOG_FATAL, "Cannot determine home home directory");
	}

	if (config_file == NULL) {
		if ((config_file = (char *)malloc (strlen (home_dir) + strlen (default_config_file)+2)) == NULL) {
			common_log (LOG_FATAL, "malloc failed");
		}
		sprintf (config_file, "%s/%s", home_dir, default_config_file);
	}

	dconfig_read (config_file, &config);
	if (log_file != NULL) {
		if (config.log_file != NULL) {
			free (config.log_file);
		}
		if ((config.log_file = strdup (log_file)) == NULL) {
			common_log (LOG_FATAL, "strdup failed");
		}
	}

	if (log_verbose) {
		config.verbose = 1;
	}

	signal (SIGPIPE, SIG_IGN);
	signal (SIGINT, on_signal);
	signal (SIGTERM, on_signal);
	signal (SIGABRT, on_signal);
	signal (SIGHUP, on_signal);

	if (log_file != NULL) {
		if (strcmp (log_file, "stderr")) {
			if ((fp_log = fopen (log_file, "a")) != NULL) {
				common_set_log_stream (fp_log);
			}
		}
	}
	else if (config.log_file != NULL) {
		if (strcmp (config.log_file, "stderr")) {
			if ((fp_log = fopen (config.log_file, "a")) != NULL) {
				common_set_log_stream (fp_log);
			}
		}
	}

	if (config.debug) {
		common_log (LOG_DEBUG, "version: %s", PACKAGE_VERSION);
		dconfig_print (&config);
		common_log (LOG_DEBUG, "run_mode: %d", run_mode);
	}

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_create_name ();
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

			snprintf (env, sizeof (env), "%s=%s:%lu:1", key, s_socket_name, (unsigned long)pid);

			if (argc - base_argc > 0) {
				putenv (env);
				execvp (argv[base_argc], &(argv[base_argc]));
				kill (pid, SIGTERM);
				exit (1);
			}
			else {
				if (env_is_csh) {
					*strchr (env, '=') = ' ';
					printf ("setenv %s\n", env);
				}
				else {
					printf ("%s; export %s\n", env, key);
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

		chdir ("/");

		if (argc - base_argc > 0) {
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

	assuan_set_assuan_log_prefix (PACKAGE);
	assuan_set_assuan_log_stream (common_get_log_stream ());

#if defined(USE_GNUTLS)
	if (gnutls_global_init () != GNUTLS_E_SUCCESS) {
		common_log (LOG_FATAL, "Cannot initialize gnutls");
	}
#endif

	if((rv = pkcs11h_initialize ()) != CKR_OK) {
		common_log (LOG_FATAL, "Cannot initialize PKCS#11: %s", pkcs11h_getMessage (rv));
	}

	pkcs11h_setLogLevel (config.verbose ? PKCS11H_LOG_DEBUG2 : PKCS11H_LOG_INFO);
	pkcs11h_setLogHook (pkcs11_log_hook, NULL);
	pkcs11h_setPINPromptHook (pkcs11_pin_prompt_hook, NULL);
	pkcs11h_setProtectedAuthentication (TRUE);

	for (i=0;i<DCONFIG_MAX_PROVIDERS;i++) {
		if (
			config.providers[i].name != NULL &&
			config.providers[i].library != NULL
		) {
			if (
				(rv = pkcs11h_addProvider (
					config.providers[i].name,
					config.providers[i].library,
					config.providers[i].allow_protected,
					config.providers[i].sign_mode,
					PKCS11H_SLOTEVENT_METHOD_POLL,
					0,
					config.providers[i].cert_is_private
				)) != CKR_OK
			) {
				common_log (LOG_WARNING, "Cannot add PKCS#11 provider: '%s'-'%s'", rv, pkcs11h_getMessage (rv));
			}
			else {
				have_at_least_one_provider = 1;
			}
		}
	}

	if (!have_at_least_one_provider) {
		common_log (LOG_FATAL, "Could not load any provider");
	}

{
	pthread_t accept_thread = 0;
	int accept_socket = -1;

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		accept_socket = server_socket_create ();

		server_socket_accept (accept_socket, &accept_thread);
	}

	if (run_mode == RUN_MODE_DAEMON) {
		/*
		 * Emulate assuan behavior
		 */
		int fds[2];
		char c;
		pipe (fds);
		close (0);
		dup2 (fds[0], 0);
		close (fds[0]);
		while (read (0, &c, 1) == -1 && errno == EINTR);
		close (fds[1]);
	}
	else {
		command_handler (-1);
	}

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_accept_terminate (accept_thread);
		server_socket_close (accept_socket);
	}
}

	pkcs11h_terminate ();

#if defined(USE_GNUTLS)
	gnutls_global_deinit ();
#endif

	dconfig_free (&config);

	if (log_file != NULL) {
		free (log_file);
		log_file = NULL;
	}

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
