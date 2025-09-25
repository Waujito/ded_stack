#ifndef	DATA_STRUCTURE_H
#define DATA_STRUCTURE_H

#include "types.h"

// ======================================================
// Debug symbols
// ======================================================

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

#define FPRINT_DS_DEBUG(stream, ds_debug, line_pref)			\
	fprintf(stream,							\
		line_pref "Created as &(%s) = [%p]\n"			\
		line_pref "Created at %s:%d:%s()\n",			\
		(ds_debug).var_name, (ds_debug).var_ptr,		\
		(ds_debug).filename, (ds_debug).line,			\
		(ds_debug).func_name					\
	)

#define DS_DUMP_CALLEE_REPORT(stream)					\
	fprintf(stream, "Data Structure Dump called at\n");		\
	fprintf(stream, "%s:%d:%s()\n", __FILE__, __LINE__,		\
			_CT_FUNC_NAME);

// ======================================================
// Error handling
// ======================================================


enum DSError {
	DS_OK			= 0,
	DS_ALLOCATION		= 1 << 0,
	DS_INVALID_ARG		= 1 << 1,
	DS_INVALID_STATE	= 1 << 2,
	DS_POISONED		= 1 << 3,
	DS_STRUCT_CORRUPT	= 1 << 4,
	DS_INVALID_POINTER	= 1 << 5,
}; 

typedef unsigned int DSError_t;


int fprint_DSError(FILE *stream, DSError_t derror);

#endif /* DATA_STRUCTURE_H */
