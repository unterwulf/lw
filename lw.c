/*
 * Copyright (c) 2024 Vitaly Sinilin <vs@kp4.ru>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

bool g_debug;
sig_atomic_t g_need_reopen;
sig_atomic_t g_shutdown_reason;
struct file *g_files;

struct action {
	char *buf;
	struct action *next;
	size_t argc;
	char *argv[];
};

struct pattern {
	regex_t regex;
	struct action *action;
	struct pattern *next;
};

struct file {
	const char *name;
	int fd;
	bool is_error_reported;
	char buf[1024];
	char nul; /* makes buf always nul-teminated */
	size_t data_len;
	struct action *actions;
	struct pattern *patterns;
	struct file *next;
};

static void open_log(void)
{
	if (!g_debug)
		openlog("lw", LOG_PID, LOG_DAEMON);
}

static void close_log(void)
{
	if (!g_debug)
		closelog();
}

static void vlwlog(int priority, const char *fmt, va_list args)
{
	if (g_debug) {
		vfprintf(stderr, fmt, args);
		putc('\n', stderr);
	} else {
		vsyslog(priority, fmt, args);
	}
}

static void lwlog(int priority, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vlwlog(priority, fmt, args);
	va_end(args);
}

#define debug0(msg)      lwlog(LOG_DEBUG, "%s", msg)
#define debug(fmt, ...)  lwlog(LOG_DEBUG, fmt, __VA_ARGS__)
#define error(fmt, ...)  lwlog(LOG_ERR, fmt, __VA_ARGS__)
#define notice0(msg)     lwlog(LOG_NOTICE, "%s", msg)
#define notice(fmt, ...) lwlog(LOG_NOTICE, fmt, __VA_ARGS__)

static void die(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vlwlog(LOG_CRIT, fmt, args);
	lwlog(LOG_CRIT, "%s", "terminated abnormally");
	va_end(args);
	exit(EXIT_FAILURE);
}

static char *xstrdup(const char *str)
{
	char *dup = strdup(str);
	if (!dup)
		die("out of memory");
	return dup;
}

static void *xalloc(size_t size)
{
	void *obj = malloc(size);
	if (!obj)
		die("out of memory");
	return obj;
}

static inline const char *strerrno(void)
{
	return strerror(errno);
}

static const char *argv_to_str(char * const argv[])
{
	static char buf[1024];
	char *ptr = buf;
	size_t avail = sizeof buf;

	for (size_t i = 0; avail && argv[i]; i++) {
		size_t len = strlen(argv[i]);
		if (len > avail)
			len = avail;

		memcpy(ptr, argv[i], len);
		ptr += len;
		avail -= len;

		if (avail) {
			*ptr = ' ';
			ptr++;
			avail--;
		}
	}

	if (avail) {
		*ptr = '\0';
	} else {
		strcpy(ptr - 4, "...");
	}

	return buf;
}

static void run_command(char * const argv[])
{
	pid_t pid = fork();

	switch (pid) {
	case 0:
		close_log();
		execv(argv[0], argv);
		exit(EXIT_FAILURE);
	case -1:
		error("could not fork() to run %s", argv_to_str(argv));
		break;
	default:
		notice("run %s (PID %ju)", argv_to_str(argv), (uintmax_t)pid);
		/* TODO */
	}
}

static int recognize_special_arg(const char *value)
{
	if (value[0] == '$' && isdigit(value[1])) {
		int idx = atoi(&value[1]);
		if (idx < 10)
			return idx;
	}
	return -1;
}

static void run_action(struct action *act, const char *buf, regmatch_t *matches)
{
	bool oom = true;
	char **argv = calloc(act->argc + 1, sizeof(char *));

	if (argv) {
		oom = false;
		argv[act->argc] = NULL;

		/* Construct argv using regex matches. */
		for (size_t i = 0; i < act->argc; i++) {
			char *arg = act->argv[i];
			int idx = recognize_special_arg(arg);

			if (idx != -1) {
				regmatch_t *m = &matches[idx];
				if (m->rm_so != -1) {
					size_t len = m->rm_eo - m->rm_so;
					argv[i] = malloc(len + 1);
					if (argv[i]) {
						memcpy(argv[i], buf + m->rm_so, len);
						argv[i][len] = '\0';
					} else {
						oom = true;
					}
				} else {
					argv[i] = "";
				}
			} else if (arg[0] == '\\' && strchr("\\$", arg[1])) {
				/* Skip escaping backslash. */
				argv[i] = arg + 1;
			} else {
				argv[i] = arg;
			}
		}
	}

	if (!oom) {
		run_command(argv);
	} else {
		error("could not run command %s: out of memory",
		      argv_to_str(act->argv));
	}

	if (argv) {
		/* Free allocated arguments. */
		for (size_t i = 0; i < act->argc; i++) {
			int idx = recognize_special_arg(act->argv[i]);
			if (idx != -1 && matches[idx].rm_so != -1 && argv[i])
				free(argv[i]);
		}
		free(argv);
	}
}

static void check_line(struct file *file)
{
	debug("got new line in %s: %s", file->name, file->buf);
	for (struct pattern *pat = file->patterns; pat; pat = pat->next) {
		regmatch_t matches[10];
		if (regexec(&pat->regex, file->buf, 10, matches, 0) != REG_NOMATCH) {
			debug0("got pattern matching");
			run_action(pat->action, file->buf, matches);
		}
	}
}

static void check_file(struct file *file)
{
	if (file->fd < 0) {
		file->fd = open(file->name, O_RDONLY | O_CLOEXEC);

		if (file->fd < 0) {
			if (!file->is_error_reported) {
				error("could not open file %s: %s",
				      file->name, strerrno());
				file->is_error_reported = true;
				return;
			}
		} else {
			notice("opened file %s", file->name);
			lseek(file->fd, 0, SEEK_END);
			file->is_error_reported = false;
		}
	}

	while (!g_shutdown_reason) {
		size_t avail = sizeof(file->buf) - file->data_len;
		ssize_t nread = read(file->fd, &file->buf[file->data_len], avail);

		if (nread == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				/* TODO */
				return;
			}
		} else if (nread == 0) {
			/* No more data. */
			return;
		}

		char *nl = memchr(&file->buf[file->data_len], '\n', nread);
		file->data_len += nread;

		while (nl) {
			size_t len = nl - file->buf;
			*nl = '\0';

			check_line(file);

			if (file->data_len > len + 1) {
				file->data_len -= len + 1;
				memmove(file->buf, &file->buf[len + 1],
				        file->data_len);
				nl = memchr(file->buf, '\n', file->data_len);
			} else {
				file->data_len = 0;
				nl = NULL;
			}
		}

		if (file->data_len == sizeof file->buf) {
			/* Line is too long, we have no choice but to analyse
			 * it by chunks. */
			check_line(file);
			file->data_len = 0;
		}
	}
}

static void mainloop(void)
{
	struct file *file = g_files;

	while (!g_shutdown_reason) {
		check_file(file);

		if (g_shutdown_reason)
			break;

		if (g_need_reopen) {
			for (struct file *f = g_files; f; f = f->next) {
				close(f->fd);
				f->fd = -1;
				f->is_error_reported = false;
			}
			g_need_reopen = false;
			notice0("reopening monitored files");
		}

		if (file->next) {
			file = file->next;
		} else if (!g_shutdown_reason) {
			file = g_files;
			sleep(1);
		}
	}
}

static void add_action(struct file *file, char *cmd)
{
	/* Count number of words in cmd. */
	size_t nwords = 1;
	char *ptr = cmd;
	while (ptr = strchr(ptr, ' ')) {
		ptr += strspn(ptr, " ");
		if (*ptr)
			nwords++;
	}

	struct action *act = xalloc(sizeof(*act) + nwords * sizeof(char *));
	act->buf = xstrdup(cmd);
	act->argc = nwords;
	act->next = file->actions;
	file->actions = act;

	act->argv[0] = act->buf;
	ptr = act->buf;
	size_t argind = 1;
	while (ptr = strchr(ptr, ' ')) {
		*ptr = '\0';
		ptr += strspn(ptr + 1, " ") + 1;
		if (*ptr)
			act->argv[argind++] = ptr;
	}

	for (struct pattern *pat = file->patterns; pat; pat = pat->next)
		if (!pat->action)
			pat->action = act;
}

static void add_pattern(struct file *file, const char *regex)
{
	struct pattern *pat = xalloc(sizeof *pat);

	if (regcomp(&pat->regex, regex, REG_EXTENDED) != 0)
		die("cannot compile regex %s", regex);

	pat->action = NULL;
	pat->next = file->patterns;
	file->patterns = pat;
}

static struct file *add_file(const char *filename)
{
	debug("adding file %s", filename);

	struct file *file = xalloc(sizeof *file);
	file->name = xstrdup(filename);
	file->fd = -1;
	file->is_error_reported = false;
	file->data_len = 0;
	file->nul = '\0';
	file->actions = NULL;
	file->patterns = NULL;
	file->next = g_files;
	g_files = file;
	return file;
}

static inline char *skip_whitespace(const char *buf)
{
	return (char *)buf + strspn(buf, " \t");
}

static char *consume_token(const char *buf, const char *token)
{
	size_t len = strlen(token);
	if (!strncmp(buf, token, len)) {
		buf += len;
		char *next_word = skip_whitespace(buf);
		if (next_word != buf || *buf == '\0')
			return next_word;
	}
	return NULL;
}

static bool file_has_pending_patterns(const struct file *file)
{
	for (struct pattern *pat = file->patterns; pat; pat = pat->next)
		if (!pat->action)
			return true;
	return false;
}

static const char *validate_file_config(const struct file *file)
{
	if (!file->patterns) {
		return "there must be a pattern";
	} else if (file_has_pending_patterns(file)) {
		return "there must be an action";
	}
	return NULL;
}

static void read_config(const char *filename)
{
	char line[1024];
	int lineno = 0;
	const char *error = NULL;
	struct file *file = NULL;
	FILE *fp = fopen(filename, "r");
	if (!fp)
		die("could not open config file %s", filename);

	while (fgets(line, sizeof line, fp)) {
		lineno++;
		size_t len = strlen(line);
		if (len && line[len-1] == '\n')
			line[len-1] = '\0';

		char *ptr = skip_whitespace(line);
		if (*ptr == '#' || *ptr == '\0') {
			/* Ignore comment/empty lines. */
			continue;
		}

		char *arg;
		if (arg = consume_token(ptr, "file")) {
			if (file) {
				error = validate_file_config(file);
				if (error)
					break;
			}
			if (!*arg) {
				error = "expected filename";
				break;
			}
			file = add_file(arg);
		} else if (arg = consume_token(ptr, "pattern")) {
			if (!file) {
				error = "unexpected pattern statement";
				break;
			} else if (!*arg) {
				error = "expected regular expression";
				break;
			}
			add_pattern(file, arg);
		} else if (arg = consume_token(ptr, "action")) {
			if (!file || !file_has_pending_patterns(file)) {
				error = "unexpected action statement";
				break;
			} else if (!*arg) {
				error = "expected command";
				break;
			}
			add_action(file, arg);
		} else {
			error = "unexpected statement";
			break;
		}
	}

	if (!error) {
		if (!file)
			die("no files configured, no reason to keep running");
		else
			error = validate_file_config(file);
	}

	if (error)
		die("%s at config line %d", error, lineno);

	fclose(fp);
}

static int write_completely(int fd, const void *buf, size_t len)
{
	ssize_t nwritten;
	while ((nwritten = write(fd, buf, len)) != (ssize_t)len) {
		if (nwritten == -1) {
			if (errno != EINTR)
				return -1;
		} else {
			len -= nwritten;
			buf += nwritten;
		}
	}
	return 0;
}

static void create_pidfile(const char *pidfile)
{
	/* Don't use O_TRUNC here -- we want to leave the pidfile unmodified
	 * if we could not lock it. */
	int fd = open(pidfile, O_CREAT | O_WRONLY | O_CLOEXEC, 0640);
	if (fd < 0)
		die("could not open pidfile %s: %s", pidfile, strerrno());

	/* Try to lock the pidfile. */
	if (lockf(fd, F_TLOCK, 0) < 0) {
		close(fd);

		if (errno == EACCES || errno == EAGAIN)
			die("pidfile is locked -- lw already running?");

		die("could not lock pidfile %s: %s", pidfile, strerrno());
	}

	/* Now that we locked the file, erase its contents. */
	if (ftruncate(fd, 0) < 0) {
		close(fd);
		die("could not truncate pidfile %s: %s", pidfile, strerrno());
	}

	char pidstr[16];
	pid_t pid = getpid();
	snprintf(pidstr, sizeof pidstr, "%ju\n", (uintmax_t)pid);

	/* Write our PID to the pidfile. */
	if (write_completely(fd, pidstr, strlen(pidstr)) != 0)
		die("could not write to pidfile %s: %s", pidfile, strerrno());

	notice("created pidfile %s", pidfile);

	/* Don't close(fd) here!
	 * We want the fd to remain opened so the lock is held until the
	 * process exits. */
}

static void close_all_fds(void)
{
	close_log();

	int fd = getdtablesize() - 1;
	while (fd >= 0)
		close(fd--);

	fd = open("/dev/null", O_RDWR); /* stdin */
	if (fd >= 0) {
		dup(fd); /* stdout */
		dup(fd); /* stderr */
	}

	open_log();

	if (fd < 0)
		die("could not open /dev/null");
	else if (fd != STDIN_FILENO)
		die("could not setup stdin");
}

static void daemonize(void)
{
	switch (fork()) {
	case 0:
		/* Child (daemon) continues. */
		setsid(); /* obtain a new process group */
		close_all_fds();
		chdir("/");
		break;
	case -1:
		die("could not fork()");
	default:
		/* Parent exits. */
		exit(EXIT_SUCCESS);
	}
}

static void signal_handler(int signum)
{
	switch (signum) {
	case SIGHUP:
		g_need_reopen = true;
		break;
	case SIGTERM:
	case SIGINT:
		g_shutdown_reason = signum;
		break;
	}
}

static void setup_signal_handlers(void)
{
	struct sigaction sa = { .sa_handler = signal_handler };
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGHUP, &sa, NULL) == -1)
		die("could not set SIGHUP handler");

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		die("could not set SIGTERM handler");

	if (sigaction(SIGINT, &sa, NULL) == -1)
		die("could not set SIGINT handler");

	/* We are not going to wait for our children. */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		die("could not set SIGCHLD handler");
}

static const char *shutdown_reason_string(void)
{
	if (g_shutdown_reason == SIGINT)
		return "INT signal received";
	else if (g_shutdown_reason == SIGTERM)
		return "TERM signal received";

	return "Batman came to kill us";
}

static void version(void)
{
	fputs("lw " LW_VERSION "\n", stderr);
	exit(EXIT_SUCCESS);
}

static void usage(int status)
{
	fputs("usage: lw -fdhv [-p <pidfile>] <config_file>\n", stderr);
	exit(status);
}

int main(int argc, char *argv[])
{
	int ch;
	bool foreground = false;
	char *pidfile = NULL;

	while ((ch = getopt(argc, argv, "fdhvp:")) != EOF) {
		switch (ch) {
		case 'f':
			foreground = true;
			break;
		case 'd':
			foreground = g_debug = true;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'v':
			version();
		case 'h':
			usage(EXIT_SUCCESS);
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (argc != optind + 1)
		usage(EXIT_FAILURE);

	open_log();
	notice0("starting lw version " LW_VERSION);
	read_config(argv[optind]);
	setup_signal_handlers();

	if (!foreground)
		daemonize();

	if (pidfile)
		create_pidfile(pidfile);

	mainloop();

	notice("%s", shutdown_reason_string());
	notice0("shutting down");
	close_log();

	if (pidfile)
		unlink(pidfile);

	return 0;
}
