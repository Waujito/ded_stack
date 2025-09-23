#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include <stdlib.h>
#include <time.h>

#include "test_machine.h"

struct test_unit {
	test_fn_t fun_ptr;
	const char *fname;
	const char *test_group;
	const char *test_name;
	int line;
};

static const size_t TESTS_VECTOR_INITIAL_SZ = 4;

struct tests_vector {
	struct test_unit *tests;
	size_t tests_capacity;
	size_t tests_len;
} tests_vector = {0};

static int tests_add_entry(struct test_unit *test) {
	TM_T_PRINT_DEBUG("cap %zu len %zu\n", tests_capacity, tests_len);
	if (tests_vector.tests_len >= tests_vector.tests_capacity) {
		size_t new_capacity = tests_vector.tests_capacity * 2;
		if (new_capacity == 0) {
			new_capacity = TESTS_VECTOR_INITIAL_SZ;
		}

		struct test_unit *ntests = (struct test_unit *) realloc(
			tests_vector.tests,
			new_capacity * sizeof(struct test_unit)
		);

		if (!ntests) {
			return -1;
		}

		tests_vector.tests = ntests;
		tests_vector.tests_capacity = new_capacity;
	}

	tests_vector.tests[tests_vector.tests_len++] = *test;

	return 0;
}

test_fn_t tm_t_add_test(test_fn_t test,
			const char *fname, int line,
			const char *test_group, const char *test_name) {
	struct test_unit test_unit = {
		.fun_ptr	= test,
		.fname		= fname,
		.test_group	= test_group,
		.test_name	= test_name,
		.line		= line
	};

	int ret = tests_add_entry(&test_unit);
	if (ret) {
		exit(EXIT_FAILURE);
	}

	TM_T_PRINT_DEBUG("Adding test from file %s and line %d\n", fname, line);
	return test;
}

static jmp_buf tm_t_jmp_point = {0};

void tm_t_assert_fail_exit(void) {
	longjmp(tm_t_jmp_point, 1);
}

static double millis_diff (struct timespec end_time, struct timespec start_time) {
	double sec_diff = (double)(end_time.tv_sec - start_time.tv_sec);
	double nsec_diff = (double)(end_time.tv_nsec - start_time.tv_nsec);
	double millisec_diff = sec_diff * 1'000 + nsec_diff / 1'000'000;

	return millisec_diff;
}

static int test_runner(struct test_unit *test) {
	TM_T_PRINT_DEBUG(
		"Running test %s.%s with function ptr=%p from file %s on line %d\n",
		test.test_group, test.test_name,
		test.fun_ptr, test.fname, test.line);

	int failed = 0;

	struct timespec start_time = {0};
	if (!timespec_get(&start_time, TIME_UTC)) return -1;

	if (!setjmp(tm_t_jmp_point)) {
		test->fun_ptr();
	} else {
		// If longjmp was called, the program will jump here
		failed = 1;
	}
	// If longjmp was not called, the program will omit failed = 1

	struct timespec end_time = {0};
	if (!timespec_get(&end_time, TIME_UTC)) return -1;

	double millisec_diff = millis_diff(end_time, start_time);


	if (failed) {
		TEST_MACHINE_FPRINTF_COLORED(TEST_MACHINE_COLOR_RED, stderr, "[%s.%s][FAIL][in %lg ms]", 
			test->test_group, test->test_name, millisec_diff);
		fprintf(stderr, "\n\n");
	} else {
		TEST_MACHINE_FPRINTF_COLORED(TEST_MACHINE_COLOR_GREEN, stdout, "[%s.%s][PASS][in %lg ms]", 
			test->test_group, test->test_name, millisec_diff);
		fprintf(stdout, "\n");
	}

	TM_T_PRINT_DEBUG("Test finished\n\n");

	return failed;
}

int main() {
	int ret = 0;

	TM_T_PRINT_DEBUG("In main() \n");

	int passed_tests = 0;
	int failed_tests = 0;

	for (size_t i = 0; i < tests_vector.tests_len; i++) {
		struct test_unit *test_unit = &tests_vector.tests[i];
		ret = test_runner(test_unit);

		if (ret == 0) {
			passed_tests++;
		} else if (ret == 1) {
			failed_tests++;
		} else {
			eprintf("Internal error\n");
			exit(EXIT_FAILURE);
		}
	}

	printf(	"\n"
		"passed tests: %d; failed tests: %d\n", passed_tests, failed_tests);

	if (failed_tests != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
