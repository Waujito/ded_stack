#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "stack.h"

TEST(Stack, StackDumps) {
	STACK_CREATE(stk);
	stack_dump(&stk, stderr);
	
	int asfd = 0x11eedd11;
	stack_push(&stk, &asfd);

	stack_dump(&stk, stderr);
	stack_destroy(&stk);
}

TEST(Stack, StackDumpRaw) {
	struct stack stk = {{0}};
	stack_init(&stk);
	stack_dump(&stk, stderr);
}
