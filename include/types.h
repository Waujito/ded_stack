#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <errno.h>

enum status_codes {
	S_OK	= 0,
	S_FAIL	= -1
};

#define _CT_REQUIRE_SEMICOLON (void)0

#define _CT_FAILED(status)		(status != S_OK)
#define _CT_SUCCEEDED(status)		(status == S_OK)


#define _CT_EXIT_POINT exit
#define	_CT_FAIL(...)	{ ret = S_FAIL; goto exit; } \
			_CT_REQUIRE_SEMICOLON

#define _CT_CHECKED(cmd)	{ if (_CT_FAILED(ret = (cmd))) goto exit; } \
				_CT_REQUIRE_SEMICOLON

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define _CT_STRINGIZING(x)	#x
#define _CT_STR(x)		_CT_STRINGIZING(x)
#define _CT_FILE_LINE		__FILE__ ":" _CT_STR(__LINE__)
#define _CT_FUNC_NAME		__func__

#define log_error(fmt, ...)						\
	eprintf("An error captured in " _CT_FILE_LINE			\
	": " fmt "\n", ##__VA_ARGS__)

#define log_perror(fmt, ...)						\
	log_error(fmt ": %s", ##__VA_ARGS__, strerror(errno))

#ifdef _DEBUG
	#define log_debug(...) eprintf(__VA_ARGS__)
#else /* _DEBUG */
	#define log_debug(...) _CT_REQUIRE_SEMICOLON
#endif /* _DEBUG */

void _i_assert_gdb_fork(void);

#define _i_assert(condition)							\
	if (!(condition)) {							\
		eprintf("\nAn assertion %s failed!\n\n", #condition);		\
		_i_assert_gdb_fork();						\
										\
		asm ("int $3");							\
	}									\
	_CT_REQUIRE_SEMICOLON							\

#ifdef _DEBUG
	#define i_assert(...) _i_assert(__VA_ARGS__)
#else /* _DEBUG */
	#define i_assert(...) _CT_REQUIRE_SEMICOLON
#endif /* _DEBUG */

#define ct_close(fd) if ((fd) >= 0) close(fd)
#define ct_fclose(file) if ((file)) fclose(file)

#endif /* TYPES_H */
