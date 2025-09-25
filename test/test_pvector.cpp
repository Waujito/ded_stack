#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "pvector.h"

TEST(PVector, PvectorDumps) {
	PVECTOR_CREATE(pv, sizeof (int));

	int a = 0xffeedd;
	ASSERT_EQ((int) pvector_push_back(&pv, &a), 0);
	// pv.arr[5] = 0xdd;
	// (pv.arr) = (char *)100;
	pv.len--;

	PVECTOR_DUMP(&pv, stderr);
	pv.arr[5] = 0xca;

	ASSERT_EQ((int) pvector_verify(&pv), 0);

	pvector_destroy(&pv);
}

TEST(PVector, PvectorDumpRaw) {
	struct pvector pv = {0};
	pvector_init(&pv, sizeof (int));

	pvector_dump(&pv, stderr);
	pvector_destroy(&pv);
}
