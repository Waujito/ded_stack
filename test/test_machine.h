/**
 * @file
 *
 * @brief A Test Framework
 */

#ifndef TEST_MACHINE_H
#define TEST_MACHINE_H

#include <math.h>
#include <stdio.h>


#ifndef TEST_MACHINE_COLORS_H
#define TEST_MACHINE_COLORS_H

#include <stdio.h>

/**
 * ANSI colors for text in terminal
 */

#define TEST_MACHINE_COLOR_RED       "\033[31m"
#define TEST_MACHINE_COLOR_GREEN     "\033[92m"
#define TEST_MACHINE_COLOR_CLEAR     "\033[0m"

#define TEST_MACHINE_FPRINTF_COLORED(color, file, fmt, ...)                  \
        fprintf(file, color fmt TEST_MACHINE_COLOR_CLEAR, ##__VA_ARGS__)

#endif /* TEST_MACHINE_COLORS_H */

#ifdef TM_T_TEST_DEBUG
	#define TM_T_PRINT_DEBUG(...) printf(__VA_ARGS__)

#else /* TM_T_TEST_DEBUG */
	#define TM_T_PRINT_DEBUG(...) (void)0

#endif /* TM_T_TEST_DEBUG */

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

typedef void (*test_fn_t)(void);

#define TM_T_TEST_FN_NAME(test_group, test_name)		\
	tm_t_##test_group_##test_name##_fn			\

#define TM_T_TEST_FN(test_group, test_name)			\
	void TM_T_TEST_FN_NAME(test_group, test_name)(void)	\

#define TM_T_TEST_DUMMY(test_group, test_name)			\
	const test_fn_t tm_t__##test_group##_##test_name##_dummy

/**
 * @brief Registers the test within the global test tracker
 */
test_fn_t tm_t_add_test(test_fn_t test,
			const char *fname, int line,
			const char *test_group, const char *test_name);


/**
 * @brief Collects tests before main() function run.
 *
 * Here are two ways to perform this:
 * - Use \_\_attribute\_\_((constructor)) which is a GCC extension.
 *   This way is good, but is not portable between compilers
 * - Use C++ style dummy global variable which initializes with a function.
 *   Such initialization in C++ calls the function before main().
 */
#if __has_attribute(constructor)
#define TM_T_TEST_CONSTRUCTOR(test_group, test_name)		\
__attribute__((constructor))					\
static void tm_t__##test_group##_##test_name##_constructor() {	\
	tm_t_add_test(						\
		TM_T_TEST_FN_NAME(test_group, test_name),	\
		__FILE__, __LINE__,				\
		#test_group, #test_name				\
	);							\
}
#else /* __has_attribute(constructor) */
#define TM_T_TEST_CONSTRUCTOR(test_group, test_name)		\
	TM_T_TEST_DUMMY(test_group, test_name) = tm_t_add_test(	\
		TM_T_TEST_FN_NAME(test_group, test_name),	\
		__FILE__, __LINE__,				\
		#test_group, #test_name				\
	);
#endif /* __has_attribute(constructor) */

/**
 * @brief A Test entry
 *
 * Declares and registers the test.
 *
 * Usage:
 * @code
 * 	TEST(MyTestGroup, MyTestName) {
 * 		ASSERT_EQ (2 * 2, 5);
 * 	}
 * @endcode
 */
#define TEST(test_group, test_name)				\
	TM_T_TEST_FN(test_group, test_name);			\
	TM_T_TEST_CONSTRUCTOR(test_group, test_name);		\
	TM_T_TEST_FN(test_group, test_name)			\

void tm_t_assert_fail_exit(void) __attribute__ ((__noreturn__));

#define STRINGIZING(x)	#x
#define STR(x)		STRINGIZING(x)
#define TM_T_FILE_LINE	__FILE__ ":" STR(__LINE__)

// static const double TM_T_DOUBLE_EPS = 1e-9;
#define TM_T_DOUBLE_EPS (1e-9)

static inline int tm_t_is_zero(double n) {
	return fabs(n) < TM_T_DOUBLE_EPS;
}

static inline int tm_t_is_eq_int(int pred, int target) {
	return pred == target;
}

static inline int tm_t_is_eq_double(double pred, double target) {
	return tm_t_is_zero(pred - target);
}

/**
 * Pass type qualifiers here
 */

static const char tm_t_int_fmt[]	= "%d";
static const char tm_t_double_fmt[]	= "%lg";

/**
 * Here is two ways to logging.
 * One is pure C-style defines and another is C++ templates
 */

#ifndef __cplusplus
#define TM_T_ASSERT_LOGGING_DEFINES
#endif

#ifdef TM_T_ASSERT_LOGGING_DEFINES
#define TM_T_ASSERTION_FAILURE_OPEN(file_line)		\
	eprintf(TEST_MACHINE_COLOR_RED "In %s \n", file_line);	\
	eprintf("Assertion failed: \n");		\

#define TM_T_ASSERTION_FAILURE_CLOSE			\
	eprintf(TEST_MACHINE_COLOR_CLEAR)				\

#define TM_T_EQUAL_ASSERTION(pred, target, assert_func, printf_specifier)	\
	if (!assert_func(pred, target)) {					\
		TM_T_ASSERTION_FAILURE_OPEN(TM_T_FILE_LINE);			\
		eprintf("\tExpected:\t%s := ", #target);			\
		eprintf(printf_specifier, target);				\
		eprintf("\n");							\
		eprintf("\tFound:\t\t%s := ", #pred);				\
		eprintf(printf_specifier, pred);				\
		eprintf("\n");							\
		TM_T_ASSERTION_FAILURE_CLOSE;					\
		tm_t_assert_fail_exit();					\
	}
#else /* TM_T_ASSERT_LOGGING_DEFINES */

template <typename T>
struct TypeToPrintfSpec {
	static constexpr const char *value = NULL;
};

template <>
struct TypeToPrintfSpec<int> {
	static constexpr const char *value = tm_t_int_fmt;
};

template <>
struct TypeToPrintfSpec<double> {
	static constexpr const char *value = tm_t_double_fmt;
};

template<typename T>
static void tm_t_assert_fail_log(T pred, T target,
				 const char *file_line,
				 const char *pred_name, const char *target_name) {

	static_assert(	TypeToPrintfSpec<T>::value != NULL,
			"No valid logging function for type");

	eprintf("\n");
	eprintf(TEST_MACHINE_COLOR_RED);

	eprintf("In %s \n", file_line);
	eprintf("Assertion failed: \n");

	eprintf("\tExpected:\t%s := ", target_name);
	eprintf(TypeToPrintfSpec<T>::value, target);
	eprintf("\n");

	eprintf("\tFound:\t\t%s := ", pred_name);
	eprintf(TypeToPrintfSpec<T>::value, pred);
	eprintf("\n");

	eprintf(TEST_MACHINE_COLOR_CLEAR);
}

#define TM_T_EQUAL_ASSERTION(pred, target, assert_func, printf_specifier)	\
	if (!assert_func(pred, target)) {					\
		tm_t_assert_fail_log(pred, target,				\
					TM_T_FILE_LINE,	#pred, #target);	\
		tm_t_assert_fail_exit();					\
	}
#endif /* TM_T_ASSERT_LOGGING_DEFINES */

#define ASSERT_EQ(pred, target) 	\
	TM_T_EQUAL_ASSERTION(pred, target, tm_t_is_eq_int, 	tm_t_int_fmt);

#define ASSERT_DOUBLE_EQ(pred, target)	\
	TM_T_EQUAL_ASSERTION(pred, target, tm_t_is_eq_double, 	tm_t_double_fmt);


/*
 * void assert_eq_int(	int pred, int target,
 * 			const char *file_line,
 * 			const char *pred_name, const char *target_name);
 * void assert_eq_double(	int pred, int target,
 * 			const char *file_line,
 * 		   	const char *pred_name, const char *target_name);
 *
 * #define ASSERT_EQ(a, b) 		assert_eq_int	(a, b, FILE_LINE, #a, #b);
 * #define ASSERT_DOUBLE_EQ(a, b) 	assert_eq_double(a, b, FILE_LINE, #a, #b);
 */

#endif /* TEST_MACHINE_H */
