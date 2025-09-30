#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "pvector.h"

#ifdef __cplusplus

TEST(Stack, StackDumps) {
	CPPVECTOR_CREATE(pv, int);
	CPPVECTOR_DUMP(&pv, stderr);

	pv.push_back(1234);
	pv.push_back(432);
	pv.push_back(9999);

	pv.pop_back(NULL);

	int a = 0;
	pv.pop_back(&a);
	ASSERT_EQ(a, 432);

	pv.dump(stderr);
}

#endif /* __cplusplus */
