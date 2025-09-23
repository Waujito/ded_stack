#include <string.h>

#include "test_config.h" // IWYU pragma: keep

#include "pvector.h"

TEST(PVector, PvectorDumps) {
	pvector_create(pv, sizeof (int));

	pvector_dump(&pv);
	int a = 0xffeedd;
	pvector_push_back(&pv, &a);
	printf("\n");

	pvector_dump(&pv);
	pvector_destroy(&pv);
}


TEST(PVector, PvectorDumpRaw) {
	struct pvector pv = {0};
	pvector_init(&pv, sizeof (int));

	pvector_dump(&pv);
	pvector_destroy(&pv);
}
