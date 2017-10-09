/*
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

static volatile int s_stop = 0;

static RETSIGTYPE sigterm(int signo) {
	(void)signo;
	s_stop = 1;
#if RETSIGTYPE != void
	return 0
#endif
}

static RETSIGTYPE sigchld(int signo) {
	int status;
	(void)signo;
	wait(&status);
#if RETSIGTYPE != void
	return 0
#endif
}

static void usage(char *name) {
	printf (
		(
"%s %s\n"
"\n"
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
"     --socket=FILE         use this socket\n"
"     --socket-group=GROUP  set socket group\n"
"     --scd=FILE            use this smartcard daemon\n"
"     --scd-config=FILE     scd configuration (required)\n"
" -v, --verbose             verbose\n"
"     --log-file            use a log file for the server\n"
"     --help                print this information\n"
		),
		PACKAGE,
		PACKAGE_VERSION,
		name
	);
}


int main(int argc, char *argv[]) {
	struct sockaddr_un addr;
	int fd = -1;
	int null = -1;
	int ret = 1;
	char *socket_name = CONFIG_PROXY_SOCKET;
	char *scd_bin = CONFIG_SCD_BIN;
	char *socket_group = CONFIG_PROXY_GROUP;
	char *scd_config = NULL;
	gid_t socket_gid;

	enum {
		OPT_VERBOSE,
		OPT_LOG_FILE,
		OPT_SOCKET,
		OPT_SOCKET_GROUP,
		OPT_SCD_BIN,
		OPT_SCD_CONFIG,
		OPT_VERSION,
		OPT_HELP
	};

	static struct option long_options[] = {
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "log-file", required_argument, NULL, OPT_LOG_FILE },
		{ "socket", required_argument, NULL, OPT_SOCKET },
		{ "socket-group", required_argument, NULL, OPT_SOCKET_GROUP },
		{ "scd", required_argument, NULL, OPT_SCD_BIN },
		{ "scd-config", required_argument, NULL, OPT_SCD_CONFIG },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	while ((opt = getopt_long (argc, argv, "v", long_options, NULL)) != -1) {
		switch (opt) {
			case OPT_SOCKET:
				socket_name = optarg;
			break;
			case OPT_SOCKET_GROUP:
				socket_group = optarg;
			break;
			case OPT_SCD_BIN:
				scd_bin = optarg;
			break;
			case OPT_SCD_CONFIG:
				scd_config = optarg;
			break;
			case OPT_VERBOSE:
			case 'v':
			break;
			case OPT_LOG_FILE:
			break;
			case OPT_VERSION:
				printf (
					"%s %s\n"
					"\n"
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
				fprintf(stderr, "invalid usage\n");
				exit(1);
			break;
		}
	}

	if (scd_config == NULL) {
		fprintf(stderr, "--scd-config is missing\n");
		goto cleanup;
	}

	{
		struct group *g = getgrnam(socket_group);
		if (g == NULL) {
			fprintf(stderr, "cannot resolve group '%s'\n", socket_group);
			goto cleanup;
		}
		socket_gid = g->gr_gid;
	}

	signal(SIGCHLD, sigchld);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(action));
		action.sa_handler = sigterm;
		sigaction(SIGTERM, &action, NULL);
		sigaction(SIGINT, &action, NULL);
	}

	if ((null = open("/dev/null", O_RDWR)) == -1) {
		perror("open null");
		goto cleanup;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen (socket_name) + 1 >= sizeof (addr.sun_path)) {
		fprintf(stderr, "Socket '%s' too long, expected %ld\n", socket_name, (long)sizeof (addr.sun_path));
		goto cleanup;
	}
	strcpy(addr.sun_path, socket_name);

	unlink(addr.sun_path);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		goto cleanup;
	}

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		fprintf(stderr, "Cannot bind '%s': %s\n", socket_name, strerror(errno));
		goto cleanup;
	}

	if (listen(fd, SOMAXCONN) == -1) {
		fprintf(stderr, "Cannot listen '%s': %s\n", socket_name, strerror(errno));
		goto cleanup;
	}

	if (chown(socket_name, -1, socket_gid) == -1) {
		fprintf(stderr, "Cannot chown '%s': %s\n", socket_name, strerror(errno));
		goto cleanup;
	}

	if (chmod(socket_name, 0660) == -1) {
		fprintf(stderr, "Cannot chmod '%s': %s\n", socket_name, strerror(errno));
		goto cleanup;
	}

	while(!s_stop) {
		uid_t peeruid;
		int accepted = -1;
		pid_t pid;

		if ((accepted = accept(fd, NULL, NULL)) == -1) {
			if (errno != EINTR && errno != EAGAIN) {
				perror("accept");
				goto cleanup;
			}
			goto cleanup1;
		}

#if HAVE_DECL_LOCAL_PEERCRED
		{
			struct xucred xucred;
			socklen_t len = sizeof(xucred);
			if (getsockopt(fd, SOL_SOCKET, LOCAL_PEERCRED, &xucred, &len) == -1) {
				perror("getsockopt");
				goto cleanup1;
			}
			if (xucred.cr_version != XUCRED_VERSION) {
				fprintf(stderr, "Mismatch credentials version actual %d expected %d", xucred.cr_version, XUCRED_VERSION);
				goto cleanup1;
			}
			peeruid = xucred.cr_uid;
		}
#elif HAVE_DECL_SO_PEERCRED
		{
			struct ucred ucred;
			socklen_t len = sizeof(ucred);
			if (getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
				perror("getsockopt");
				goto cleanup1;
			}
			peeruid = ucred.uid;
		}
#else
		fprintf(stderr, "Cannot determine credentials\n");
		goto cleanup;
#endif

		if ((pid = fork()) == -1) {
			perror("fork");
			goto cleanup;
		}

		if (pid == 0) {
			struct rlimit rlim;
			char uid_string[100];
			int i;

			if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
				perror("getrlimit");
				exit(1);
			}

			sprintf(uid_string, "%d", peeruid);
			dup2(accepted, 0);
			dup2(accepted, 1);

			for (i = 3; i < (int)rlim.rlim_cur; i++) {
				close(i);
			}

			execl(
				scd_bin,
				scd_bin,
				"--multi-server",
				"--options",
				scd_config,
				"--uid-acl",
				uid_string,
				NULL
			);
			fprintf(stderr, "Cannot execute '%s': %s\n", scd_bin, strerror(errno));
			exit(1);
		}

	cleanup1:
		if (accepted != -1) {
			close(accepted);
		}
	}

	ret = 0;

cleanup:
	if (null != -1) {
		close(null);
	}

	if (fd != -1) {
		close(fd);
	}

	return ret;
}
