#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "pvector.h"

TEST(PVector, PvectorDumps) {
	PVECTOR_CREATE(pv, sizeof (int));

	pvector_dump(&pv, stderr);
	int a = 0xffeedd;
	ASSERT_EQ((int) pvector_push_back(&pv, &a), 0);
	pv.arr[5] = 0xdd;
	printf("\n");

	PVECTOR_DUMP(&pv, stderr);
	ASSERT_EQ((int) pvector_pop_back(&pv), (int) DS_POISONED);
	pv.arr[5] = 0xca;
	ASSERT_EQ((int) pvector_pop_back(&pv), 0);
	pvector_dump(&pv, stderr);
	ASSERT_EQ((int) pvector_verify(&pv), 0);

	pvector_destroy(&pv);
}


TEST(PVector, PvectorDumpRaw) {
	struct pvector pv = {0};
	pvector_init(&pv, sizeof (int));

	pvector_dump(&pv, stderr);
	pvector_destroy(&pv);
}
