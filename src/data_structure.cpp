#include "types.h"
#include "data_structure.h"


int fprint_DSError(FILE *stream, DSError_t derror) {
	fprintf(stream, "[");
	if (!derror) {
		fprintf(stream, "(No error)");
	}

	unsigned int err_ct = derror;
	int set_comma = 0;
	#define LOG_DS_ERROR_(err_spec, err_desc)		\
		if (err_ct & err_spec) {			\
			if (set_comma)				\
				fprintf(stream, ",");		\
			else					\
				set_comma = 1;			\
								\
			fprintf(stream, err_desc);		\
			err_ct ^= err_spec;			\
		}

	LOG_DS_ERROR_(DS_ALLOCATION,		"Allocation Error");
	LOG_DS_ERROR_(DS_INVALID_ARG,		"Invalid Argument");
	LOG_DS_ERROR_(DS_INVALID_STATE,		"Invalid State");
	LOG_DS_ERROR_(DS_POISONED,		"Poisoned Storage");
	LOG_DS_ERROR_(DS_STRUCT_CORRUPT,	"Structure Corrupted");
	LOG_DS_ERROR_(DS_INVALID_POINTER,	"Invalid Pointer");
	LOG_DS_ERROR_(DS_CANARY_CORRUPT,	"The Canary Corrupted");
	LOG_DS_ERROR_(DS_STRUCT_HASH_CORRUPT,	"Structure Hash Corrupted");
	LOG_DS_ERROR_(DS_ARRAY_HASH_CORRUPT,	"Array Hash Corrupted");

	#undef LOG_DS_ERROR_

	fprintf(stream, "]");

	if (err_ct) {
		fprintf(stream, "+<Unlisted error value: 0x%x>", err_ct);
	}


	return 0;
}

