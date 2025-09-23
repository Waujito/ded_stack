#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "types.h"

struct gdb_pipes {
	int gdb_pipefd_stdout[2];
	int gdb_pipefd_stdin[2];
	int signaling_fd;
};

static const char *GDB_STOPPED_PREFIX = "*stopped";
static const char *GDB_CONTINUE = "c\n";
static const char *GDB_INFO_LOCALS = "info locals\n";
static const char *GDB_INFO_LOCALS_OUT = "&\"info locals\\n\"";
static const char *GDB_CONSOLE_INTERPRETER = "new-ui console /dev/tty\n";
static const char *GDB_DONE_OUT = "^done";
static const char *GDB_DETACH = "detach\n";

static int gdb_interactive_loop(FILE *gdb_stdout_stream, 
				FILE *gdb_stdin_stream, int signaling_fd) {
	int ret = -1;

	char *lineptr = NULL;
	size_t line_cap = 0;
	ssize_t getline_readlen = 0;

	int stops_ct = 0;

	int info_locals_printing = 0;
	int print_gdb = 0;

	const size_t STOPPED_PREF_LEN		= strlen(GDB_STOPPED_PREFIX);
	const size_t GDB_INFO_LOCALS_OUT_LEN	= strlen(GDB_INFO_LOCALS);
	const size_t GDB_DONE_OUT_LEN		= strlen(GDB_DONE_OUT);

	while ((getline_readlen = getline(&lineptr, &line_cap, gdb_stdout_stream)) != -1) {
		if (!strncmp(lineptr, GDB_STOPPED_PREFIX, STOPPED_PREF_LEN)) {
			if (stops_ct == 0) {
				const eventfd_t eventfd_one = 1;
				if (eventfd_write(signaling_fd, eventfd_one) < 0) {
					log_perror("eventfd signaling_fd");
					goto exit;
				}
				ct_close (signaling_fd);
				signaling_fd = -1;

				fprintf(gdb_stdin_stream, "%s", GDB_CONTINUE);
			} else if (stops_ct == 1) {
				fprintf(gdb_stdin_stream, "%s", GDB_INFO_LOCALS);
			}

			stops_ct++;
		}

		if (!strncmp(lineptr, GDB_DONE_OUT, GDB_DONE_OUT_LEN)) {
			if (info_locals_printing) {
				info_locals_printing = 0;

				printf(
					"Locals printed. What do you want to do next? \n"
					"[c]ontinue the program execution, [e]xit the program, "
					"continue with [g]db: "
				);
				fflush(stdout);
				char cmd = 0;
				scanf("%c", &cmd);

				switch (cmd) {
					case 'c':
						fprintf(gdb_stdin_stream, "%s", GDB_CONTINUE);
						ret = 0;
						goto exit;
					case 'g':
						print_gdb = 1;
						break;
					case 'e':
					default:
						fprintf(gdb_stdin_stream, "%s", GDB_DETACH);
						goto exit;
				}

				if (print_gdb) {
					break;
				}

			} else {
				log_error("GDB Parsing error");
				goto exit;
			}
		}

		if (info_locals_printing) {
			lineptr[getline_readlen - 4] = '\n';
			lineptr[getline_readlen - 3] = '\0';
			printf("%s", lineptr + 2);
		}

		if (!strncmp(lineptr, GDB_INFO_LOCALS_OUT, GDB_INFO_LOCALS_OUT_LEN)) {
			info_locals_printing = 1;
		}
	}

	if (print_gdb) {
		eprintf("Redirecting tty to gdb in console variant...\n");
		fprintf(gdb_stdin_stream, "%s", GDB_CONSOLE_INTERPRETER);
		gdb_stdin_stream = NULL;

		ret = 0;
		goto exit;
	}

exit:
	ct_close (signaling_fd);
	ct_fclose (gdb_stdout_stream);
	ct_fclose (gdb_stdin_stream);
	return ret;
}

static int gdb_interactive(struct gdb_pipes pipes, int program_pid, int forked_pid) {
	int ret = -1;

	ct_close (pipes.gdb_pipefd_stdin[0]);
	pipes.gdb_pipefd_stdin[0] = -1;
	ct_close (pipes.gdb_pipefd_stdout[1]);
	pipes.gdb_pipefd_stdout[1] = -1;

	/* Bufferize up the stdout/stdin pipe to the FILE */
	FILE *gdb_stdout_stream	= NULL;
	FILE *gdb_stdin_stream	= NULL;

	if (!(gdb_stdout_stream = fdopen(pipes.gdb_pipefd_stdout[0], "r"))) {
		log_perror("fdopen stdout pipe");
		goto exit;
	}
	if (!(gdb_stdin_stream = fdopen(pipes.gdb_pipefd_stdin[1], "w"))) {
		log_perror("fdopen stdin pipe");
		goto exit;
	}

	/* Disable buffering for the stream */
	if (setvbuf(gdb_stdin_stream, NULL, _IONBF, 0)) {
		log_perror("setvbuf for stdin filebuf");
		goto exit;
	}

	ret = gdb_interactive_loop(gdb_stdout_stream, gdb_stdin_stream, pipes.signaling_fd);
	pipes.signaling_fd = -1;
	gdb_stdout_stream = NULL;
	gdb_stdin_stream = NULL;

	if (ret) {
		kill(forked_pid, SIGHUP);
		kill(program_pid, SIGKILL);
	}

exit:
	ct_fclose (gdb_stdin_stream);
	ct_fclose (gdb_stdout_stream);
	ct_close  (pipes.signaling_fd);
	ct_close (pipes.gdb_pipefd_stdin[0]);
	ct_close (pipes.gdb_pipefd_stdout[1]);
	return ret;
}

#define GDB_COMMAND_LEN 128

static int execv_gdb(struct gdb_pipes pipes, pid_t program_pid) {
	int ret = 0;

	/*
	 * Redirects stdout to pipe.
	 */

	/* Close unused read end */
	ct_close (pipes.gdb_pipefd_stdout[0]);	
	pipes.gdb_pipefd_stdout[0] = -1;

	/* Redirect stdout to pipe */
	if (dup2(pipes.gdb_pipefd_stdout[1], STDOUT_FILENO) == -1) {
		log_perror("dup2 pipes.gdb_pipefd_stdout[1] STDOUT");
		goto exit;
	}
	/* Close pipe write end since stdout is used now */
	ct_close (pipes.gdb_pipefd_stdout[1]);
	pipes.gdb_pipefd_stdout[1] = -1;

	// Uncomment if you want to redirect stderr to stdout => to the pipefd
	// if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1) {
	// 	perror("redirect stderr to stdout");
	// 	return -1;
	// }

	/**
	 * Redirects pipe to stdin
	 */
	/* Close unused write end */
	ct_close(pipes.gdb_pipefd_stdin[1]);
	pipes.gdb_pipefd_stdin[1] = -1;

	/* Redirect pipe write end to stdin */
	if (dup2(pipes.gdb_pipefd_stdin[0], STDIN_FILENO) == -1) {
		log_perror("dup2 pipes.gdb_pipefd_stdin[0] STDIN");
		goto exit;
	}
	/* Close pipe read end since stdin is used now */
	ct_close(pipes.gdb_pipefd_stdin[0]);
	pipes.gdb_pipefd_stdin[0] = -1;

	ct_close (pipes.signaling_fd);
	pipes.signaling_fd = -1;

	{
		char cmd[GDB_COMMAND_LEN] = {0};

		ret = snprintf(cmd, GDB_COMMAND_LEN, "gdb -p %d -i=mi", program_pid);
		if (ret >= GDB_COMMAND_LEN) {
			log_error("The gdb command is larger than buf");
			goto exit;
		}

		ret = execl("/bin/sh", "sh", "-c", cmd, (char *) NULL);
	}

exit:
	ct_close (pipes.gdb_pipefd_stdin[0]);
	ct_close (pipes.gdb_pipefd_stdin[1]);
	ct_close (pipes.gdb_pipefd_stdout[0]);
	ct_close (pipes.gdb_pipefd_stdout[1]);
	ct_close (pipes.signaling_fd);

	return -1;
}

static int gdb_running(pid_t program_pid, int signaling_fd) {
	pid_t forked_pid = -1;
	struct gdb_pipes pipes = {
		.gdb_pipefd_stdout = {-1, -1},
		.gdb_pipefd_stdin = {-1, -1},
		.signaling_fd = -1,
	};
	pipes.signaling_fd = signaling_fd;
	
	if (pipe2(pipes.gdb_pipefd_stdout, O_CLOEXEC)) {
		log_perror("pipe2 pipes.gdb_pipefd_stdout");
		goto exit;
	}

	if (pipe2(pipes.gdb_pipefd_stdin, O_CLOEXEC)) {
		log_perror("pipe2 pipes.gdb_pipefd_stdin");
		goto exit;
	}

	if ((forked_pid = fork()) < 0) {
		log_perror("fork_gdb_execv/interactive");
		goto exit;
	}

	if (forked_pid == 0) {
		if (execv_gdb(pipes, program_pid)) {
			_exit(EXIT_FAILURE);
		}
	} else {
		if (gdb_interactive(pipes, program_pid, forked_pid)) {
			kill(forked_pid, SIGHUP);
			goto exit;
		}

		if (wait(NULL) == -1) /* Wait for child */
			return -1;
	}

	return 0;

exit:
	ct_close (pipes.gdb_pipefd_stdin[0]);
	ct_close (pipes.gdb_pipefd_stdin[1]);
	ct_close (pipes.gdb_pipefd_stdout[0]);
	ct_close (pipes.gdb_pipefd_stdout[1]);
	ct_close (pipes.signaling_fd);

	return -1;
}

static int fork_for_gdb(void) {
	int first_eventfd	= -1;
	int second_eventfd	= -1;
	pid_t gdb_pid		= -1;
	int ret			= -1;

	first_eventfd = eventfd(0, 0);
	if (first_eventfd < 0) {
		log_perror("first_eventfd");
		goto exit;
	}

	second_eventfd = eventfd(0, 0);
	if (second_eventfd < 0) {
		log_perror("second_eventfd");
		goto exit;
	}

	;
	if ((gdb_pid = fork()) < 0) {
		log_perror("fork_for_gdb fork");
		goto exit;
	}

	if (gdb_pid == 0) {
		if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) < 0) {
			log_perror("prctl set any ptracer");
			goto exit;
		}

		const eventfd_t eventfd_one = 1;
		if (eventfd_write(first_eventfd, eventfd_one) < 0) {
			log_perror("eventfd_write");
			goto exit;
		}

		close(first_eventfd);
		first_eventfd = -1;

		eventfd_t eventfd_ct = 0;
		if (eventfd_read(second_eventfd, &eventfd_ct) < 0) {
			log_perror("eventfd_read");
			goto exit;
		}

		close(second_eventfd);
		second_eventfd = -1;

		return 0;
	} else {
		eventfd_t eventfd_ct = 0;

		if (eventfd_read(first_eventfd, &eventfd_ct) < 0) {
			log_perror("eventfd_read");
			goto exit;
		}

		close(first_eventfd);
		first_eventfd = -1;

		ret = gdb_running(gdb_pid, second_eventfd);
		second_eventfd = -1;
		if (ret) {
			goto exit;
		}

		if (wait(NULL) == -1) {	/* Wait for child */
			log_perror("Wait for gdb");
			goto exit;
		}

		ret = 0;
	}

exit:
	ct_close (first_eventfd);
	ct_close (second_eventfd);

	if (ret && gdb_pid > 0) {
		kill(gdb_pid, SIGKILL);
	}

	return ret;
}

void _i_assert_gdb_fork(void) {
	if (fork_for_gdb()) {
		exit(EXIT_FAILURE);
	}
}
