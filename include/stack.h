#ifndef STACK_H
#define STACK_H

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
static const char *stack_dtype_name = "int";

typedef struct stack {
	struct pvector pv;
	
	STACK_ONDEBUG(
		struct ds_debug _debug_info;
	)
} stack_t;

static DSError_t stack_init(struct stack *stk) {
	DSError_t ret = DS_OK;

	if ((ret = pvector_init(&stk->pv, sizeof(stack_dtype)))) {
		return ret;
	}

#ifdef PVECTOR_DEBUG
	if ((ret = pvector_set_debug_info(&stk->pv, 
			GET_DS_DEBUG(stk->pv), stack_dtype_name))) {
		return ret;
	}
#endif /* PVECTOR_DEBUG */

	return DS_OK;
}

static DSError_t stack_set_debug_info(struct stack *stk,
				      struct ds_debug debug_info) {
#ifdef STACK_DEBUG
	stk->_debug_info = debug_info;
#endif
	
	return DS_OK;
}

static DSError_t stack_destroy(struct stack *stk) {
	return pvector_destroy(&stk->pv);
}

static DSError_t stack_push(struct stack *stk, stack_dtype *el) {
	return pvector_push_back(&stk->pv, el);
}

static DSError_t stack_pop(struct stack *stk) {
	return pvector_pop_back(&stk->pv);
}

static stack_dtype *stack_head(struct stack *stk) {
	if (stk->pv.len == 0) {
		return NULL;
	}

	return (stack_dtype *)pvector_get(&stk->pv, stk->pv.len - 1);
}

#ifdef STACK_DEBUG
#define stack_spec_debug(varName)					\
	stack_set_debug_info(&varName, GET_DS_DEBUG(varName))
#else /* STACK_DEBUG */
#define stack_spec_debug(varName) _CT_REQUIRE_SEMICOLON 
#endif /* STACK_DEBUG */

#define stack_create(varName)						\
	struct stack varName = {{0}};					\
	stack_init(&varName);						\
	stack_spec_debug(varName);					\
	_CT_REQUIRE_SEMICOLON

static DSError_t stack_dump(struct stack *stk) {
	printf("Stack dump: \n");

	if (!stk) {
		printf("\tstack is NULL\n");
		return DS_OK;
	}

	printf("stack<{%zu bytes}:{%s}\n",
		sizeof(stack_dtype), stack_dtype_name);

	printf("\tPassed as [%p]\n", stk);

#ifdef STACK_DEBUG
	PRINT_DS_DEBUG(stk->_debug_info,  "\t");
#else
	printf("\tNo debug symbols provided\n");
#endif /* STACK_DEBUG */

	printf("\nBacked by pvector: \n");
	pvector_dump(&stk->pv);

	return DS_OK;
}

#endif /* STACK_H */
