#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "pvector.h"

TEST(PVector, PvectorDumps) {
	PVECTOR_CREATE(pv, sizeof (short));
	pvector_set_flags(&pv, FPVECTOR_USE_CANARY | FPVECTOR_USE_ARRAY_HASH);
	pvector_set_capacity(&pv, 13);

	uint32_t a = 0xffeedd;
	ASSERT_EQ((int) pvector_push_back(&pv, &a), 0);
	ASSERT_EQ((int) pvector_pop_back(&pv, NULL), 0);
	ASSERT_EQ((int) pvector_push_back(&pv, &a), 0);
	// pv.arr[-1] = 1;
	// ASSERT_EQ((int) pvector_pop_back(&pv), 0);
	// pv.arr[5] = 0xdd;
	// (pv.arr) = (char *)100;
	// pv.len--;
	// pv.arr++;

	PVECTOR_DUMP(&pv, stderr);

	pv.arr[0] = 0x11;
	PVECTOR_DUMP(&pv, stderr);
	ASSERT_EQ((int) pvector_verify(&pv), (int)DS_ARRAY_HASH_CORRUPT);
	pv.arr[0] = 0xdd;
	ASSERT_EQ((int) pvector_verify(&pv), 0);

	pvector_destroy(&pv);
}

TEST(PVector, PvectorDumpRaw) {
	struct pvector pv = {0};
	pvector_init(&pv, sizeof (int));

	pvector_dump(&pv, stderr);
	pvector_destroy(&pv);
}
