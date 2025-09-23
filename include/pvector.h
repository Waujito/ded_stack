#ifndef PVECTOR_H
#define PVECTOR_H

#include <stdlib.h>
#include "types.h"

typedef enum DSError {
	DS_OK			= 0,
	DS_ALLOCATION		= 1 << 0,
	DS_INVALID_ARG		= 1 << 1,
	DS_INVALID_STATE	= 1 << 2,
} DSError_t;

#define PVECTOR_DEBUG

#ifdef PVECTOR_DEBUG
	#define PVECTOR_ONDEBUG(...) __VA_ARGS__
#else /* PVECTOR_DEBUG */
	#define PVECTOR_ONDEBUG(...)
#endif /* PVECTOR_DEBUG */

struct ds_debug {
	/* nullable */
	const char *var_name;

	/* nullable */
	void *var_ptr;

	/* nullable */
	const char *filename;

	/* if null = 0 */
	int line;

	/* nullable */
	const char *func_name;
};

#define GET_DS_DEBUG(varName)						\
	((struct ds_debug) {						\
		.var_name	= #varName,				\
		.var_ptr	= &varName,				\
		.filename	= __FILE__,				\
		.line		= __LINE__,				\
		.func_name	= _CT_FUNC_NAME				\
	})

#define PRINT_DS_DEBUG(ds_debug, line_pref)				\
	printf(								\
		line_pref "Created as &(%s) = [%p]\n"			\
		line_pref "Created at %s:%s():%d\n",			\
		(ds_debug).var_name, (ds_debug).var_ptr,		\
		(ds_debug).filename, (ds_debug).func_name,		\
			(ds_debug).line					\
	)

typedef void (*pvector_el_destructor_t)(void *);
struct pvector {
	char *arr;
	size_t capacity;
	size_t len;
	size_t el_size;

	pvector_el_destructor_t destructor;

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
#define pvector_spec_debug(varName, el_size) _CT_REQUIRE_SEMICOLON 
#endif /* PVECTOR_DEBUG */

#define pvector_create(varName, el_size)				\
	struct pvector varName = {0};					\
	pvector_init(&varName, el_size);				\
	pvector_spec_debug(varName, el_size);				\
	_CT_REQUIRE_SEMICOLON
	
DSError_t pvector_dump(struct pvector *pv);

DSError_t pvector_set_destructor(struct pvector *pv, pvector_el_destructor_t destructor);

DSError_t pvector_set_capacity(struct pvector *pv, size_t new_cap);

DSError_t pvector_destroy(struct pvector *pv);

DSError_t pvector_push_back(struct pvector *pv, void *ptr);
DSError_t pvector_pop_back(struct pvector *pv);

DSError_t pvector_clone(struct pvector *npv, const struct pvector *pv);

int pvector_has(const struct pvector *pv, size_t idx);
void *pvector_get(const struct pvector *pv, size_t idx);


#endif /* PVECTOR_H */
