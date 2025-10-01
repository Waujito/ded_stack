#ifndef PVECTOR_H
#define PVECTOR_H

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "types.h"
#include "data_structure.h"

#ifndef _Nullable
#define _Nullable
#define PV_Nullable_
#endif

#define PVECTOR_DEBUG

#ifdef PVECTOR_DEBUG
	#define PVECTOR_ONDEBUG(...) __VA_ARGS__
#else /* PVECTOR_DEBUG */
	#define PVECTOR_ONDEBUG(...)
#endif /* PVECTOR_DEBUG */

#define FPVECTOR_USE_CANARY	(1 << 0)
#define FPVECTOR_USE_ARRAY_HASH	(1 << 1)

typedef void (*pvector_el_destructor_t)(void *);

struct pvector {
	char *arr;
	size_t capacity;
	size_t len;
	size_t el_size;

	int flags;

	pvector_el_destructor_t element_destructor;

	PVECTOR_ONDEBUG(
		struct ds_debug _debug_info;

		const char *_Nullable el_size_name;
	);

	uint32_t arr_hash;

	// Should be zeroed before hash calculation
	uint32_t struct_hash;
};

DSError_t pvector_init(struct pvector *pv, size_t el_size);
DSError_t pvector_set_flags(struct pvector *pv, int flags);

#ifdef PVECTOR_DEBUG
DSError_t pvector_set_debug_info(struct pvector *pv,
				 struct ds_debug debug_info,
				 const char *el_size_name);
#endif

#ifdef PVECTOR_DEBUG
#define pvector_spec_debug(varName, el_size)				\
	pvector_set_debug_info(&varName, GET_DS_DEBUG(varName),		\
				#el_size)
#else /* PVECTOR_DEBUG */
#define pvector_spec_debug(varName, el_size) (void)0
#endif /* PVECTOR_DEBUG */

#define PVECTOR_CREATE(varName, el_size)				\
	struct pvector varName = {0};					\
	do {								\
		pvector_init(&varName, el_size);			\
		pvector_spec_debug(varName, el_size);			\
	} while (0)

DSError_t pvector_verify(const struct pvector *pv);

DSError_t pvector_dump(struct pvector *pv, FILE *stream);

#define PVECTOR_DUMP(pv, stream)					\
	DS_DUMP_CALLEE_REPORT(stream);					\
	pvector_dump(pv, stream);

DSError_t pvector_set_element_destructor(struct pvector *pv, 
					 pvector_el_destructor_t destructor);

DSError_t pvector_set_capacity(struct pvector *pv, size_t new_cap);

DSError_t pvector_destroy(struct pvector *pv);

DSError_t pvector_push_back(struct pvector *pv, const void *ptr);
/**
 * NOTE!!! Copies the element to pointer.
 * The pointer is nullable. If you don't want the element, pass NULL.
 */
DSError_t pvector_pop_back(struct pvector *pv, void *_Nullable ptr);

DSError_t pvector_clone(struct pvector *npv, const struct pvector *pv);

int pvector_has(const struct pvector *pv, size_t idx);
DSError_t pvector_get(struct pvector *pv, size_t idx, void **dst);

static inline DSError_t pvector_top(struct pvector *pv, void **dst) {
	if (pv->len > 0) {
		return pvector_get(pv, pv->len - 1, dst);
	} else {
		return DS_INVALID_STATE;
	}
}

#ifdef __cplusplus

#include <typeinfo>

template<typename T>
class vector {
private:
	struct pvector pv = {0};
	// vector(struct pvector *pv) : pv(*pv) { }

public:
	vector() {
		pvector_init(&pv, sizeof(T));
	}

	~vector() {
		pvector_destroy(&pv);
	}

#ifdef PVECTOR_DEBUG
	DSError_t set_debug_info(struct ds_debug debug_info) {
		return pvector_set_debug_info(&pv, debug_info, typeid(T).name());
	}
#endif


	DSError_t set_flags(int flags) {
		return pvector_set_flags(&pv, flags);
	}

	int get_flags() const {
		return pv.flags;
	}

	DSError_t push_back(const T &el) {
		return pvector_push_back(&pv, &el);
	}

	DSError_t pop_back(T *_Nullable el) {
		return pvector_pop_back(&pv, el);
	}

	DSError_t clone(vector<T> *new_vector) const {
		assert (new_vector);
		struct pvector npv = {0}; 

		DSError_t error = DS_OK;
		if ((error = pvector_clone(&npv, &pv))) {
			return error;
		}

		*new_vector = vector<T>(npv);

		return DS_OK;
	}

	T *get(size_t idx) {
		T *dst = NULL;
		if (pvector_get(&pv, idx, &dst))
			return NULL;

		return dst;
	}

	T *top() {
		if (len()) {
			return pvector_get(len() - 1);
		}

		return NULL;
	}

	DSError_t set_capacity(size_t capacity) {
		return pvector_set_capacity(&pv, capacity);
	}

	size_t capacity() const {
		return pv.capacity;
	}

	size_t len() const {
		return pv.len;
	}

	DSError_t dump(FILE *stream) {
		return pvector_dump(&pv, stream);
	}
};

#ifdef PVECTOR_DEBUG
#define cppvector_spec_debug(varName)				\
	varName.set_debug_info(GET_DS_DEBUG(varName))
#else /* PVECTOR_DEBUG */
#define cppvector_spec_debug(varName) (void)0
#endif /* PVECTOR_DEBUG */

#define CPPVECTOR_CREATE(varName, element_type)				\
	vector<element_type> varName = vector<element_type>();		\
	do {								\
		cppvector_spec_debug(varName);				\
	} while (0)

#define CPPVECTOR_DUMP(pv, stream)					\
	DS_DUMP_CALLEE_REPORT(stream);					\
	(pv)->dump(stream);

#endif /* __cplusplus */

#ifdef PV_Nullable_
#undef _Nullable
#undef PV_Nullable_
#endif

#endif /* PVECTOR_H */
