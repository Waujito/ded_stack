#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "stack.h"

TEST(Stack, StackDumps) {
	STACK_CREATE(stk);
	STACK_DUMP(&stk, stderr);
	
	int asfd = 0x11eedd11;
	ASSERT_EQ((int)stack_push(&stk, asfd), 0);
	ASSERT_EQ(stack_top(&stk), asfd);
	ASSERT_EQ((int)stack_pop(&stk), 0);

	ASSERT_EQ((int)stack_destroy(&stk), 0);
}
