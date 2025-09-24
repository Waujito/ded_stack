#ifndef PVECTOR_H
#define PVECTOR_H

#include <stdlib.h>
#include "types.h"
#include "data_structure.h"

#define PVECTOR_DEBUG

#ifdef PVECTOR_DEBUG
	#define PVECTOR_ONDEBUG(...) __VA_ARGS__
#else /* PVECTOR_DEBUG */
	#define PVECTOR_ONDEBUG(...)
#endif /* PVECTOR_DEBUG */

typedef void (*pvector_el_destructor_t)(void *);
struct pvector {
	char *arr;
	size_t capacity;
	size_t len;
	size_t el_size;

	pvector_el_destructor_t element_destructor;

	PVECTOR_ONDEBUG(
		struct ds_debug _debug_info;

		/* nullable */
		const char *el_size_name;
	)
};

DSError_t pvector_init(struct pvector *pv, size_t el_size);
DSError_t pvector_set_debug_info(struct pvector *pv,
				 struct ds_debug debug_info,
				 const char *el_size_name);
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

DSError_t pvector_set_element_destructor(struct pvector *pv, 
					 pvector_el_destructor_t destructor);

DSError_t pvector_set_capacity(struct pvector *pv, size_t new_cap);

DSError_t pvector_destroy(struct pvector *pv);

DSError_t pvector_push_back(struct pvector *pv, void *ptr);
DSError_t pvector_pop_back(struct pvector *pv);

DSError_t pvector_clone(struct pvector *npv, const struct pvector *pv);

int pvector_has(const struct pvector *pv, size_t idx);
void *pvector_get(const struct pvector *pv, size_t idx);


#endif /* PVECTOR_H */
