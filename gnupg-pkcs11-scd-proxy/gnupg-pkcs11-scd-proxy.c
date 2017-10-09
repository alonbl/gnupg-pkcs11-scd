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
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static volatile int s_stop = 0;

static RETSIGTYPE sigterm(int signo) {
	(void)signo;
	s_stop = 1;
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
"     --multi-server        run in multi server mode (foreground)\n"
"     --homedir             specify home directory\n"
"     --socket=FILE         use this socket\n"
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
	int ret = 1;
	long on = 1;
	char *socket_name = CONFIG_PROXY_SOCKET;

	typedef struct fds_s {
		int fd;
		char *name;
		int peer;
		char buffer[1024];
		size_t buffer_n;
	} fds_t;

	fds_t fds[] = {
		{ -1, "outgoing.out", 2, {0}, 0},
		{ 0, "incoming.in", 0, {0}, 0},
		{ 1, "incoming.out", 1, {0}, 0},
	};
	int fds_n = sizeof(fds) / sizeof(fds[0]);
	int disconnect = 0;

	enum {
		OPT_MUTLI_SERVER,
		OPT_HOMEDIR,
		OPT_SOCKET,
		OPT_VERBOSE,
		OPT_LOG_FILE,
		OPT_VERSION,
		OPT_HELP
	};

	static struct option long_options[] = {
		{ "multi-server", no_argument, NULL, OPT_MUTLI_SERVER },
		{ "homedir", required_argument, NULL, OPT_HOMEDIR },
		{ "socket", required_argument, NULL, OPT_SOCKET },
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "log-file", required_argument, NULL, OPT_LOG_FILE },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	while ((opt = getopt_long (argc, argv, "v", long_options, NULL)) != -1) {
		switch (opt) {
			case OPT_MUTLI_SERVER:
			break;
			case OPT_HOMEDIR:
			break;
			case OPT_SOCKET:
				socket_name = optarg;
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

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	if (strlen (socket_name) + 1 >= sizeof (addr.sun_path)) {
		fprintf(stderr, "Socket '%s' too long, expected %ld\n", socket_name, (long)sizeof (addr.sun_path));
		goto cleanup;
	}
	strcpy(addr.sun_path, socket_name);

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		goto cleanup;
	}

	if (ioctl(fd, FIONBIO, &on) == -1) {
		perror("ioctl sock");
		goto cleanup;
	}

	if (connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
		fprintf(stderr, "Cannot connect '%s': %s\n", socket_name, strerror(errno));
		goto cleanup;
	}

	fds[0].fd = fd;
	while (!s_stop && !disconnect) {
		struct pollfd pollfds[fds_n];
		int i;

		memset(&pollfds, 0, sizeof(pollfds));

		for (i = 0; i < fds_n; i++) {
			fds_t *peer = &fds[fds[i].peer];
			pollfds[i].fd = fds[i].fd;
			if (peer->buffer_n < sizeof(peer->buffer)) {
				pollfds[i].events |= POLLIN;
			}
			if (fds[i].buffer_n > 0) {
				pollfds[i].events |= POLLOUT;
			}
		}

		if (poll(pollfds, sizeof(pollfds) / sizeof(struct pollfd), -1) == -1) {
			if (errno != EINTR && errno != EAGAIN) {
				perror("poll");
				goto cleanup;
			}
			continue;
		}

		for (i = 0; i < fds_n && !disconnect; i++) {
			if ((pollfds[i].revents & POLLHUP) != 0) {
				disconnect = 1;
			}
			if ((pollfds[i].revents & POLLERR) != 0) {
				fprintf(stderr, "error %s\n", fds[i].name);
				goto cleanup;
			}
		}

		for (i = 0; i < fds_n && !disconnect; i++) {
			if ((pollfds[i].revents & POLLIN) != 0) {
				fds_t *peer = &fds[fds[i].peer];
				int n;
				if ((n = read(fds[i].fd, peer->buffer + peer->buffer_n, sizeof(peer->buffer) - peer->buffer_n)) == -1) {
					fprintf(stderr, "error %s read\n", fds[i].name);
					goto cleanup;
				}
				if (n == 0) {
					disconnect = 1;
				}
				peer->buffer_n += n;
			}

			if ((pollfds[i].revents & POLLOUT) != 0) {
				int n;
				if ((n = write(fds[i].fd, fds[i].buffer, fds[i].buffer_n)) == -1) {
					fprintf(stderr, "error %s write\n", fds[i].name);
					goto cleanup;
				}
				fds[i].buffer_n -= n;
				memmove(fds[i].buffer, fds[i].buffer + n, fds[i].buffer_n);
			}
		}
	}

	ret = 0;

cleanup:
	if (fd != -1) {
		close(fd);
	}

	return ret;
}
