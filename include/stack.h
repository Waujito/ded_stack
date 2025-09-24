#ifndef STACK_H
#define STACK_H

#include <assert.h>

#include "data_structure.h"
#include "pvector.h"

#ifdef PVECTOR_DEBUG
#define STACK_DEBUG
#endif

#ifdef STACK_DEBUG
	#define STACK_ONDEBUG(...) __VA_ARGS__
#else /* STACK_DEBUG */
	#define STACK_ONDEBUG(...)
#endif /* STACK_DEBUG */


typedef int stack_dtype;
static const char *STACK_DTYPE_NAME = "int";

typedef struct stack {
	struct pvector pv;
	
	STACK_ONDEBUG(
		struct ds_debug _debug_info;
	)
} stack_t;

static DSError_t stack_init(struct stack *stk) {
	assert (stk);

	DSError_t ret = DS_OK;

	if ((ret = pvector_init(&stk->pv, sizeof(stack_dtype)))) {
		return ret;
	}

#ifdef PVECTOR_DEBUG
	if ((ret = pvector_set_debug_info(&stk->pv, 
			GET_DS_DEBUG(stk->pv), STACK_DTYPE_NAME))) {
		pvector_destroy(&stk->pv);
		return ret;
	}
#endif /* PVECTOR_DEBUG */

	return DS_OK;
}

static DSError_t stack_set_debug_info(struct stack *stk,
				      struct ds_debug debug_info) {
	assert (stk);

#ifdef STACK_DEBUG
	stk->_debug_info = debug_info;
#endif
	
	return DS_OK;
}

static DSError_t stack_destroy(struct stack *stk) {
	assert (stk);

	return pvector_destroy(&stk->pv);
}

static DSError_t stack_push(struct stack *stk, stack_dtype *el) {
	assert (stk);

	return pvector_push_back(&stk->pv, el);
}

static DSError_t stack_pop(struct stack *stk) {
	assert (stk);

	return pvector_pop_back(&stk->pv);
}

static DSError_t stack_verify(struct stack *stk) {
	assert (stk);

	return pvector_verify(&stk->pv);
}

static stack_dtype *stack_head(struct stack *stk) {
	assert (stk);

	if (stk->pv.len == 0) {
		return NULL;
	}

	return (stack_dtype *)pvector_get(&stk->pv, stk->pv.len - 1);
}

#ifdef STACK_DEBUG
#define STACK_SPEC_DEBUG(varName)					\
	stack_set_debug_info(&varName, GET_DS_DEBUG(varName))
#else /* STACK_DEBUG */
#define STACK_SPEC_DEBUG(varName) (void)0
#endif /* STACK_DEBUG */

#define STACK_CREATE(varName)						\
	struct stack varName = {{0}};					\
	do {								\
		stack_init(&varName);					\
		STACK_SPEC_DEBUG(varName);				\
	} while (0)		

static DSError_t stack_dump(struct stack *stk, FILE *stream) {
	assert (stk);
	assert (stream);

	fprintf(stream, "Stack dump: \n");

	if (!stk) {
		fprintf(stream, "\tstack is NULL\n");
		return DS_OK;
	}

	fprintf(stream, "stack<{%zu bytes}:{%s}\n",
		sizeof(stack_dtype), STACK_DTYPE_NAME);

	fprintf(stream, "\tPassed as [%p]\n", stk);

#ifdef STACK_DEBUG
	FPRINT_DS_DEBUG(stream, stk->_debug_info,  "\t");
#else
	fprintf(stream, "\tNo debug symbols provided\n");
#endif /* STACK_DEBUG */

	fprintf(stream, "\nBacked by pvector: \n");
	pvector_dump(&stk->pv, stream);

	return DS_OK;
}

#endif /* STACK_H */
