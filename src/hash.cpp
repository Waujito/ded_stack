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

uint32_t hash_crc32_add(uint32_t base_hash, 
			const uint8_t data[], size_t data_length)
{
	uint32_t crc32 = ~base_hash;

	if (CRCTable[255] == 0)
		crc32_init();
	
	for (size_t i = 0; i < data_length; i++) {
		crc32 ^= data[i];
		crc32 = (crc32 >> 8) ^ CRCTable[crc32 & 0xff];
	}
	
	// Finalize the CRC-32 value by inverting all the bits
	return ~crc32;
}

// typedef int64_t hash_t;
// static const hash_t HASH_MOD = 1'000'000'007;
//
// static inline hash_t positive_mod(hash_t a, hash_t b) {
//     hash_t result = a % b;
//     if (result < 0) {
//         result += (b < 0) ? -b : b;
//     }
//     return result;
// }
//
// static const hash_t ALPHABET_STRENGTH = 256;
//
// hash_t poly_hash_calc(const uint8_t data[], size_t dlen) {
// 	hash_t hash = (hash_t) data[0];
//
// 	for (size_t i = 1; i < dlen; i++) {
// 		hash = ((hash * ALPHABET_STRENGTH) % HASH_MOD + 
// 			(hash_t) data[i]) % HASH_MOD;
// 	}
//
// 	return hash;
// }
//
// hash_t poly_hash_add(hash_t base_hash, const uint8_t data[], size_t dlen) {
// 	for (size_t i = 0; i < dlen; i++) {
// 		base_hash = ((base_hash * ALPHABET_STRENGTH) % HASH_MOD + 
// 			(hash_t) data[i]) % HASH_MOD;
// 	}
//
// 	return base_hash;
// }
//
// hash_t poly_hash_del(hash_t base_hash, const uint8_t data[], size_t dlen) {
// 	hash_t nhash = base_hash;
// 	
//
// 	for (size_t i = 0; i < dlen; i++) {
// 		nhash = positive_mod(nhash - data[i], HASH_MOD);
// 		nhash = (((nhash * ALPHABET_STRENGTH) % HASH_MOD) + str[i]) % HASH_MOD;
// 		base_hash - data[i];
// 		base_hash = ((base_hash * ALPHABET_STRENGTH) % HASH_MOD +
// 			(hash_t) data[i]) % HASH_MOD;
// 	}
//
// 	return base_hash;
// }
