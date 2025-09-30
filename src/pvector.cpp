#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"

#include "pvector.h"

static const size_t PVECTOR_INIT_CAPACITY = 128;

// 64 bit for 8-byte alignment
// Alignment is preserved in the backbone of stack allocators
// Use special canary functions instead of direct access to raw ptr
static const uint64_t PVECTOR_CANARY = 0x00edac0ffe00UL;

#ifdef PVECTOR_DEBUG
#define PVECTOR_POISONING
#define PVECTOR_DEBUG_LOGGING
#define PVECTOR_DEBUG_CANARY

#define PVECTOR_DEBUG_ARRAY_HASH
#endif

#ifdef PVECTOR_POISONING
static const unsigned char PVECTOR_DEBUG_POISON = 0xca;
#endif /* PVECTOR_POISONING */

#ifdef PVECTOR_DEBUG_LOGGING
#define pv_log_debug(...) eprintf("[DEBUG] " __VA_ARGS__)
#else
#define pv_log_debug(...) (void)0
#endif /* PVECTOR_DEBUG_LOGGING */


#ifdef PVECTOR_DEBUG
#define PVECTOR_VERIFY(pv)				\
	(pvector_verify(pv))
#define PVECTOR_VERIFY_AND_RETURN(pv)			\
do {							\
	DSError_t error = PVECTOR_VERIFY(pv);		\
	if (error) {					\
		return error;				\
	}						\
} while (0)
#else /* PVECTOR_DEBUG */

#define PVECTOR_VERIFY(...) (0)

#define PVECTOR_VERIFY_AND_RETURN(...) (void)0

#endif /* PVECTOR_DEBUG */

#define IS_PVECTOR_USE_CANARY(pv) (pv->flags & FPVECTOR_USE_CANARY)
#define IS_PVECTOR_USE_ARRAY_HASH(pv) (pv->flags & FPVECTOR_USE_ARRAY_HASH)

static inline uint32_t pvector_rehash(struct pvector *pv) {
	assert (pv);

	pv->struct_hash = 0;
	uint32_t hash = hash_crc32((const uint8_t *)pv, sizeof(struct pvector));
	pv->struct_hash = hash;

	return hash;
}
static int pvector_hash_validate(const struct pvector *pv) {
	assert (pv);

	struct pvector npv = *pv;
	pvector_rehash(&npv);

	return pv->struct_hash == npv.struct_hash;
}

static inline uint32_t pvector_array_hash(const struct pvector *pv) {
	assert (pv);

	return hash_crc32((const uint8_t *)pv->arr, pv->len * pv->el_size);
}

DSError_t pvector_init(struct pvector *pv, size_t el_size) {
	assert (pv);
	assert (el_size && "el_size MUST NOT be zero");

	pv->arr = NULL;
	pv->el_size = el_size;
	pv->capacity = 0;
	pv->len = 0;
	pv->flags = 0;

#ifdef PVECTOR_DEBUG_CANARY
	pv->flags |= FPVECTOR_USE_CANARY;
#endif

#ifdef PVECTOR_DEBUG_ARRAY_HASH
	pv->flags |= FPVECTOR_USE_ARRAY_HASH;
#endif

	pv->element_destructor = NULL;

	pv->arr_hash = 0;

	PVECTOR_ONDEBUG(
		pv->_debug_info = (struct ds_debug){0};
	)

	pvector_rehash(pv);
	return DS_OK;
}

DSError_t pvector_set_flags(struct pvector *pv, int flags) {
	assert(pv);
	PVECTOR_VERIFY_AND_RETURN(pv);

	// We can't change canary state if it is already set
	if (pv->arr) {
		if (	IS_PVECTOR_USE_CANARY(pv) && 
			!(flags & FPVECTOR_USE_CANARY)) {
			return DS_INVALID_ARG;
		}

		if (	!IS_PVECTOR_USE_CANARY(pv) && 
			(flags & FPVECTOR_USE_CANARY)) {
			return DS_INVALID_ARG;
		}

		if (!IS_PVECTOR_USE_ARRAY_HASH(pv) &&
			flags & FPVECTOR_USE_ARRAY_HASH) {
			pv->arr_hash = pvector_array_hash(pv);
		}
	}
	

	pv->flags = flags;

	pvector_rehash(pv);
	return DS_OK;
}

#ifdef PVECTOR_DEBUG
DSError_t pvector_set_debug_info(struct pvector *pv,
				 struct ds_debug debug_info,
				 const char *el_size_name) {
	assert(pv);

	PVECTOR_ONDEBUG(
		pv->_debug_info = debug_info;
		pv->el_size_name = el_size_name;
	)

	pvector_rehash(pv);
	return DS_OK;
}
#endif

DSError_t pvector_set_element_destructor(struct pvector *pv, pvector_el_destructor_t destructor) {
	assert (pv);

	pv->element_destructor = destructor;

	pvector_rehash(pv);
	return DS_OK;
}

static inline char *pvector_real_ptr(struct pvector *pv) {
	assert (pv);

	if (!pv->arr) {
		return NULL;
	}

	if (IS_PVECTOR_USE_CANARY(pv)) {
		return pv->arr - sizeof(PVECTOR_CANARY);
	} else {
		return pv->arr;
	}
}

static inline uint64_t *starting_canary_ptr(struct pvector *pv) {
	if (!IS_PVECTOR_USE_CANARY(pv)) {
		return NULL;
	}

	return (uint64_t *)pvector_real_ptr(pv);
}

static inline size_t pad_canary_alignment(size_t carry) {
	size_t padding_offset = 8 - carry % 8;
	if (padding_offset == 8) {
		return 0;
	}

	return padding_offset;
}

static inline uint64_t *ending_canary_ptr(struct pvector *pv) {
	if (!IS_PVECTOR_USE_CANARY(pv)) {
		return NULL;
	}

	char *real_ptr = pvector_real_ptr(pv);
	if (real_ptr == NULL) {
		return NULL;
	}

	real_ptr += sizeof(PVECTOR_CANARY);
	real_ptr += pv->capacity * pv->el_size;
	real_ptr += pad_canary_alignment((uintptr_t)real_ptr % 8);

	return (uint64_t *)real_ptr;
}

/**
 * Adds the canaries for pvector.
 * Note that it works out of bounds of the pvector->arr:
 * _CANARY_ (pv->arr + pv->capacity) _CANARY_
 */
static inline void pvector_set_canaries(struct pvector *pv) {
	assert(pv);

	if (!IS_PVECTOR_USE_CANARY(pv)) {
		return;
	}

	char *real_ptr = pvector_real_ptr(pv);
	if (!real_ptr) {
		return;
	}

	*starting_canary_ptr(pv) = PVECTOR_CANARY;
	*ending_canary_ptr(pv) = PVECTOR_CANARY;
}

DSError_t pvector_set_capacity(struct pvector *pv, size_t new_capacity) {
	assert (pv);
	PVECTOR_VERIFY_AND_RETURN(pv);

	if (new_capacity < pv->len) {
		return DS_INVALID_ARG;
	}

	if (new_capacity == 0) {
		new_capacity = PVECTOR_INIT_CAPACITY;
	}

	pv_log_debug("Setting capacity %zu for vector of len %zu\n", 
		new_capacity, pv->len);

	size_t realloc_size = new_capacity * pv->el_size;
	if (IS_PVECTOR_USE_CANARY(pv)) {
		realloc_size += sizeof(PVECTOR_CANARY);
		realloc_size += sizeof(PVECTOR_CANARY);
		realloc_size += pad_canary_alignment(realloc_size);
	}

	char *new_arr = (char *)realloc(pvector_real_ptr(pv), realloc_size);
	if (!new_arr) {
		return DS_ALLOCATION;
	}

	pv->arr = new_arr;
	if (IS_PVECTOR_USE_CANARY(pv)) { 
		pv->arr += sizeof(PVECTOR_CANARY);
	}

#ifdef PVECTOR_POISONING
	size_t old_capacity = pv->capacity;
#endif
	pv->capacity = new_capacity;	

	if (IS_PVECTOR_USE_CANARY(pv)) { 
		pvector_set_canaries(pv);
	}

#ifdef PVECTOR_POISONING
	if (old_capacity < new_capacity) {
		memset(pv->arr + old_capacity * pv->el_size,
			PVECTOR_DEBUG_POISON,
			(new_capacity - old_capacity) * pv->el_size
		);
	}
#endif /* PVECTOR_POISONING */

	pvector_rehash(pv);
	return DS_OK;
}

DSError_t pvector_destroy(struct pvector *pv) {
	assert (pv);
	// Should I do something to free the pointer when verification fails?
#ifdef PVECTOR_DEBUG
	DSError_t error = pvector_verify(pv);
	if (error & DS_INVALID_POINTER) {
		return error;
	}
#endif

PVECTOR_ONDEBUG(if (!error) {)
		if (pv->element_destructor) {
			for (size_t i = 0; i < pv->len; i++) {
				pv->element_destructor(pv->arr + i * pv->el_size);
			}
		}
PVECTOR_ONDEBUG(})

	free(pvector_real_ptr(pv));
	pv->arr = NULL;
	pv->capacity = 0;
	pv->len = 0;
	pv->element_destructor = NULL;
	pv->flags = 0;

	pv->arr_hash = 0;

	pvector_rehash(pv);
	return DS_OK;
}

DSError_t pvector_clone(struct pvector *npv, const struct pvector *pv) {
	assert (npv);
	assert (pv);
	PVECTOR_VERIFY_AND_RETURN(pv);

	size_t calloc_size = pv->len * pv->el_size;
	if (IS_PVECTOR_USE_CANARY(pv)) {
		calloc_size += 2 * sizeof(PVECTOR_CANARY);
		calloc_size += pad_canary_alignment(calloc_size);
	}

	char *arr = (char *)calloc(calloc_size, sizeof(char));
	if (!arr) {
		return DS_ALLOCATION;
	}

	npv->arr = arr;

	if (IS_PVECTOR_USE_CANARY(pv)) {
		arr += sizeof(PVECTOR_CANARY);
	}

	npv->len = pv->len;
	npv->capacity = pv->len;
	npv->el_size = pv->el_size;
	npv->arr_hash = pv->arr_hash;

	if (IS_PVECTOR_USE_CANARY(pv)) {
		pvector_set_canaries(npv);
	}

	memcpy(npv->arr, pv->arr, pv->len * pv->el_size);

	pvector_rehash(npv);
	return DS_OK;
}

int pvector_has(const struct pvector *pv, size_t idx) {
	assert (pv);
	if (PVECTOR_VERIFY(pv)) {
		return 0;
	}

	return idx < pv->len;
}

DSError_t pvector_get(struct pvector *pv, size_t idx, void **dst) {
	assert (pv);
	assert (dst);
	PVECTOR_VERIFY_AND_RETURN(pv);

	if (idx >= pv->len) {
		return DS_INVALID_ARG;
	}

	*dst = pv->arr + idx * pv->el_size;

	return DS_OK;
}

#ifdef PVECTOR_POISONING
static int pvector_el_is_poisonous(const struct pvector *pv, const char *ptr) {
	assert (pv);
	assert (ptr);

	int is_poisonous = 1;
	for (size_t j = 0; j < pv->el_size; j++) {
		if ((unsigned char) ptr[j] != PVECTOR_DEBUG_POISON) {
			is_poisonous = 0;
		}
	}

	return is_poisonous;
}
#endif /* PVECTOR_DEBUG */


DSError_t pvector_push_back(struct pvector *pv, const void *ptr) {
	assert (pv);
	assert (ptr);
	PVECTOR_VERIFY_AND_RETURN(pv);

	// Do not include poisonous elements
#ifdef PVECTOR_POISONING
	if (pvector_el_is_poisonous(pv, (const char *)ptr)) {
		return DS_POISONED;
	}
#endif

	DSError_t ret = DS_OK;

	if (pv->len >= pv->capacity) {
		size_t new_capacity = pv->capacity * 2;
		if ((ret = pvector_set_capacity(pv, new_capacity))) {
			return ret;
		}
	}

	size_t idx = pv->len++;
	char *el_pos = pv->arr + idx * pv->el_size;

	switch (pv->el_size) {
		case 1:
			*el_pos = *(const char *)ptr;
			break;
		case 2:
			*(uint16_t *)el_pos = *(const uint16_t *)ptr;
			break;
		case 4:
			*(uint32_t *)el_pos = *(const uint32_t *)ptr;
			break;
		case 8:
			*(uint64_t *)el_pos = *(const uint64_t *)ptr;
			break;
		default:
			memcpy(el_pos, ptr, pv->el_size);
	}

	if (IS_PVECTOR_USE_ARRAY_HASH(pv)) {
		pv->arr_hash = hash_crc32_add(pv->arr_hash,
				(const uint8_t *)ptr, pv->el_size);
	}

	pvector_rehash(pv);
	return DS_OK;
}

DSError_t pvector_pop_back(struct pvector *pv, void *_Nullable ptr) {
	assert (pv);
	PVECTOR_VERIFY_AND_RETURN(pv);

	DSError_t ret = DS_OK;

	if (pv->len == 0) {
		return DS_INVALID_STATE;
	}

	void *top = NULL;
	if ((ret = pvector_get(pv, pv->len - 1, &top))) {
		return ret;
	}

	if (ptr) {
		memcpy(ptr, top, pv->el_size);
	}

	pv->len--;

	// Do something with this stupid O(n)
	if (IS_PVECTOR_USE_ARRAY_HASH(pv)) {
		pv->arr_hash = pvector_array_hash(pv);
	}

#ifdef PVECTOR_POISONING
	memset(pv->arr + pv->len * pv->el_size, PVECTOR_DEBUG_POISON, pv->el_size);
#endif /* PVECTOR_POISONING */

	if (pv->element_destructor) {
		char *el_ptr = pv->arr + pv->len * pv->el_size;
		pv->element_destructor(el_ptr);
	}

	pvector_rehash(pv);
	if (pv->len < pv->capacity / 4 && pv->len > PVECTOR_INIT_CAPACITY) {
		if ((ret = pvector_set_capacity(pv, pv->len))) {
			return ret;
		}
	}

	pvector_rehash(pv);
	return DS_OK;
}

DSError_t pvector_verify(const struct pvector *pv) {
	assert (pv);
	DSError_t error = DS_OK;

	size_t last_bit_pos = sizeof(size_t) * 8 - 2;

	if (!pvector_hash_validate(pv)) {
		error |= DS_STRUCT_HASH_CORRUPT;
	}

	if (pv->capacity >> last_bit_pos) {
		error |= DS_STRUCT_CORRUPT;
	}

	if (pv->len > pv->capacity) {
		error |= DS_STRUCT_CORRUPT;
	}

	if (pv->capacity) {
		if (!pv->arr) {
			error |= DS_INVALID_POINTER;
		}
	}

	// Test for Canary
	if (IS_PVECTOR_USE_CANARY(pv)) {
		const char *real_ptr = pvector_real_ptr((struct pvector *)pv);
		if (real_ptr && (
			!(error & (DS_STRUCT_CORRUPT | DS_INVALID_POINTER))
		)) {
			uint64_t *start_canary = 
				starting_canary_ptr((struct pvector *)pv);
			uint64_t *end_canary = 
				ending_canary_ptr((struct pvector *)pv);

			if (	(start_canary && *start_canary != 
					PVECTOR_CANARY) ||
				(end_canary && *end_canary != 
					PVECTOR_CANARY)) {
				error |= DS_CANARY_CORRUPT;
			}
		}
	}

	// Test for array hash
	if (IS_PVECTOR_USE_ARRAY_HASH(pv) && 
		!(error & (DS_STRUCT_CORRUPT | DS_INVALID_POINTER))) {
		uint32_t real_hash = pvector_array_hash(pv);
		if (real_hash != pv->arr_hash) {
			error |= DS_ARRAY_HASH_CORRUPT;
		}
	}

	// Conditions for poison verification
#ifdef PVECTOR_POISONING
	if (!(error & (DS_STRUCT_CORRUPT | DS_INVALID_POINTER))) {
		for (size_t i = 0; i < pv->len; i++) {
			const char *el = 
				(const char *) pv->arr + i * pv->el_size;

			if (pvector_el_is_poisonous(pv, el)) {
				error |= DS_POISONED;
				break;
			}
		}

		for (size_t i = pv->len; i < pv->capacity; i++) {
			const char *el = 
				(const char *) pv->arr + i * pv->el_size;
			if (!pvector_el_is_poisonous(pv, el)) {
				error |= DS_POISONED;
				break;
			}
		}
	}
#endif /* PVECTOR_POISONING */

	return error;
}

const size_t PVECTOR_DUMP_CONTENT_MAXLEN = 16;

static DSError_t pvector_dump_canary(FILE *stream, const unsigned char *canary_ptr) {
	const unsigned char *real_canary_ptr = 
		(const unsigned char *)(&PVECTOR_CANARY);

	int canary_pass = 1;
	for (size_t j = 0; j < sizeof(PVECTOR_CANARY); j++) {
		if (canary_ptr[j] != real_canary_ptr[j]) {
			canary_pass = 0;
		}

		fprintf(stream, " %02x", canary_ptr[j]);
	}

	fprintf(stream, ";");
	if (!canary_pass) {
		fprintf(stream, " (CORRUPTED)");
	}
	fprintf(stream, "\n");

	return 0;
}

DSError_t pvector_dump(struct pvector *pv, FILE *stream) {
	assert(stream);

	fprintf(stream, "PVector dump: \n");	

	if (!pv) {
		fprintf(stream, "\tpvector is NULL\n");
		return DS_OK;
	}	


	fprintf(stream, "pvector<{%zu bytes}" PVECTOR_ONDEBUG(":{%s}") ">\n", 
		pv->el_size
		PVECTOR_ONDEBUG(, pv->el_size_name)
	);
	fprintf(stream, "\tPassed as [%p]\n", pv);

#ifdef PVECTOR_DEBUG
	FPRINT_DS_DEBUG(stream, pv->_debug_info,  "\t");
#else
	fprintf(stream, "\tNo debug symbols provided\n");
#endif /* PVECTOR_DEBUG */

	DSError_t pv_error = pvector_verify(pv);
	fprintf(stream, "\tStatus: ");
	fprint_DSError(stream, pv_error);
	fprintf(stream, "\n");

	fprintf(stream, "\t{\n");
	fprintf(stream, "\t\tcapacity\t= <%zu>;\n",	pv->capacity);
	fprintf(stream, "\t\tlen\t\t= <%zu>;\n",	pv->len);
	fprintf(stream, "\t\tel_size\t\t= <%zu>;\n",	pv->el_size);
	fprintf(stream, "\t\t*element_destructor\t= [%p];\n",	pv->element_destructor);
	fprintf(stream, "\n");
	fprintf(stream, "\t\t*arr\t\t= [%p];\n",		pv->arr);
	fprintf(stream, "\t}\n");

	fprintf(stream, "\n");
	fprintf(stream, "With contents:\n"
	       "\t{\n");

	size_t contents_len = pv->capacity;
	int contents_truncated = 0;
	if (contents_len > PVECTOR_DUMP_CONTENT_MAXLEN) {
		contents_len = PVECTOR_DUMP_CONTENT_MAXLEN;
		contents_truncated = 1;
	}

	if (contents_len == 0) {
		fprintf(stream, "\t\t(EMPTY)\n");
	}

	uint64_t *start_canary = starting_canary_ptr(pv);
	if (start_canary) {
		fprintf(stream, "\t[BCANARY]\t=");
		pvector_dump_canary(stream, (unsigned char *)start_canary);
	}

	for (size_t i = 0; i < contents_len; i++) {
		fprintf(stream, "\t\t*[%zu]\t=", i);
		unsigned char *el = (unsigned char *)pv->arr + i * pv->el_size;

#ifdef PVECTOR_POISONING 
			int is_poisonous = 1;
#endif /* PVECTOR_POISONING  */

		for (size_t j = 0; j < pv->el_size; j++) {
#ifdef PVECTOR_POISONING 
				if (el[j] != PVECTOR_DEBUG_POISON) {
					is_poisonous = 0;
				}
#endif /* PVECTOR_POISONING  */

			fprintf(stream, " %02x", el[j]);
		}

		fprintf(stream, ";");

#ifdef PVECTOR_POISONING 
			if (is_poisonous) {
				fprintf(stream, " (POISON)");
			}
#endif /* PVECTOR_POISONING  */

		fprintf(stream, "\n");
	}

	if (contents_truncated) {
		fprintf(stream, "\t\t[truncated]\n");
	}

	uint64_t *end_canary = ending_canary_ptr(pv);
	if (end_canary) {
		fprintf(stream, "\t[ECANARY]\t=");
		pvector_dump_canary(stream, (unsigned char *)end_canary);
	}

	fprintf(stream, "\t}\n");

	return DS_OK;
}
