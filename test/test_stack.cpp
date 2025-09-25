#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "stack.h"

TEST(Stack, StackDumps) {
	STACK_CREATE(stk);
	STACK_DUMP(&stk, stderr);
	
	int asfd = 0x11eedd11;
	stack_push(&stk, asfd);

	STACK_DUMP(&stk, stderr);
	stack_destroy(&stk);
}

TEST(Stack, StackDumpRaw) {
	struct stack stk = {{0}};
	stack_init(&stk);
	STACK_DUMP(&stk, stderr);
}
