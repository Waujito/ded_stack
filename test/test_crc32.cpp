#include "test_config.h"

#include "hash.h"

TEST(TestCRC32, TestHashing) {
	const uint8_t data[] = "00aaasdf\x00\x23\xdd\xfd\xaa\xed\xa0";
	const uint32_t hash_sum = hash_crc32(data, sizeof(data));

	ASSERT_UINT32_T_EQ(hash_sum, 0xfd4b3435u);
}
