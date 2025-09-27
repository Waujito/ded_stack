#include <stdint.h>
#include <stddef.h>

#include "hash.h"

// CRC implementation by Wikipedia

static const uint32_t CRC32_MAGIC = 0xEDB88320;
static uint32_t CRCTable[256];

// Initialization by multiple threads is redundant, but safe.
static void crc32_init(void)
{
	uint32_t crc32 = 1;

	// C guarantees CRCTable[0] = 0 already.
	for (unsigned int i = 128; i; i >>= 1) {
		crc32 = (crc32 >> 1) ^ (crc32 & 1 ? CRC32_MAGIC : 0);

		for (unsigned int j = 0; j < 256; j += 2*i)
			CRCTable[i + j] = crc32 ^ CRCTable[j];
	}
}

uint32_t hash_crc32(const uint8_t data[], size_t data_length)
{
	uint32_t crc32 = ~0u;

	if (CRCTable[255] == 0)
		crc32_init();
	
	for (size_t i = 0; i < data_length; i++) {
		crc32 ^= data[i];
		crc32 = (crc32 >> 8) ^ CRCTable[crc32 & 0xff];
	}
	
	// Finalize the CRC-32 value by inverting all the bits
	return ~crc32;
}
