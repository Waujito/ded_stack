#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pvector.h"

#ifdef PVECTOR_DEBUG
const static unsigned char PVECTOR_DEBUG_POISON = 0xca;
#endif /* PVECTOR_DEBUG */

DSError_t pvector_init(struct pvector *pv, size_t el_size) {
	assert (pv);
	assert (el_size && "el_size MUST NOT be zero");

	pv->arr = NULL;
	pv->el_size = el_size;
	pv->capacity = 0;
	pv->len = 0;

	pv->destructor = NULL;

	PVECTOR_ONDEBUG(
		pv->_debug_info = (struct ds_debug){0};
	)

	return DS_OK;
}


DSError_t pvector_set_debug_info(struct pvector *pv,
				 struct ds_debug debug_info,
				 const char *el_size_name) {
	assert(pv);

	PVECTOR_ONDEBUG(
		pv->_debug_info = debug_info;
		pv->el_size_name = el_size_name;
	)

	return DS_OK;
}

DSError_t pvector_set_destructor(struct pvector *pv, pvector_el_destructor_t destructor) {
	assert (pv);

	pv->destructor = destructor;

	return DS_OK;
}

DSError_t pvector_set_capacity(struct pvector *pv, size_t new_cap) {
	assert (pv);

	if (new_cap < pv->len) {
		return DS_INVALID_ARG;
	}

	if (new_cap == 0) {
		static const size_t PVECTOR_INIT_CAPACITY = 128;
		new_cap = PVECTOR_INIT_CAPACITY;
	}

	char *new_arr = (char *)realloc(pv->arr, 
			    new_cap * pv->el_size);
	if (!new_arr) {
		return DS_ALLOCATION;
	}

	pv->arr = new_arr;

	size_t old_capacity = pv->capacity;
	pv->capacity = new_cap;

#ifdef PVECTOR_DEBUG
	if (old_capacity < new_cap) {
		memset(pv->arr + old_capacity * pv->el_size,
			PVECTOR_DEBUG_POISON,
			(new_cap - old_capacity) * pv->el_size
		);
	}
#endif /* PVECTOR_DEBUG */
	
	return DS_OK;
}

DSError_t pvector_destroy(struct pvector *pv) {
	assert (pv);

	if (!pv) {
		return DS_OK;
	}

	if (pv->destructor) {
		for (size_t i = 0; i < pv->len; i++) {
			pv->destructor(pv->arr + i * pv->el_size);
		}
	}

	free(pv->arr);
	pv->arr = NULL;
	pv->capacity = 0;
	pv->len = 0;

	return DS_OK;
}

DSError_t pvector_clone(struct pvector *npv, const struct pvector *pv) {
	assert (npv);
	assert (pv);

	char *arr = (char *)calloc(pv->len * pv->el_size, sizeof(char));
	if (!arr) {
		return DS_ALLOCATION;
	}

	npv->arr = arr;
	npv->len = pv->len;
	npv->capacity = pv->len;
	npv->el_size = pv->el_size;

	memcpy(npv->arr, pv->arr, pv->len * pv->el_size);

	return DS_OK;
}

DSError_t pvector_push_back(struct pvector *pv, void *ptr) {
	assert (pv);
	assert (ptr);

	DSError_t ret = DS_OK;

	if (pv->len >= pv->capacity) {
		size_t new_cap = pv->capacity * 2;
		if ((ret = pvector_set_capacity(pv, new_cap))) {
			return ret;
		}
	}

	size_t idx = pv->len++;
	char *el_pos = pv->arr + idx * pv->el_size;
	memcpy(el_pos, ptr, pv->el_size);

	return DS_OK;
}

DSError_t pvector_pop_back(struct pvector *pv) {
	assert (pv);

	if (pv->len == 0) {
		return DS_INVALID_STATE;
	}

	pv->len--;
	if (pv->destructor) {
		char *el_ptr = pv->arr + pv->len * pv->el_size;
		pv->destructor(el_ptr);
	}

	if (pv->len <= pv->capacity / 4) {
		DSError_t ret = pvector_set_capacity(pv, pv->len);

		if (ret) {
			return ret;
		}
	}

	return DS_OK;
}

int pvector_has(const struct pvector *pv, size_t idx) {
	assert (pv);

	return idx < pv->len;
}

void *pvector_get(const struct pvector *pv, size_t idx) {
	assert (pv);

	if (idx >= pv->len) {
		return NULL;
	}

	return pv->arr + idx * pv->el_size;
}


DSError_t pvector_verify(struct pvector *pv) {
	assert (pv);
	DSError_t error = DS_OK;

	size_t last_bit_pos = sizeof(size_t) * 8 - 2;
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

#ifdef PVECTOR_DEBUG
	// Condition for poison verification
	if (!(error & (DS_STRUCT_CORRUPT | DS_INVALID_POINTER))) {
		for (size_t i = 0; i < pv->len; i++) {
			unsigned char *el = (unsigned char *) pv->arr + 
						i * pv->el_size;
			int is_poisonous = 1;

			for (size_t j = 0; j < pv->el_size; j++) {
				if (el[j] != PVECTOR_DEBUG_POISON) {
					is_poisonous = 0;
				};
			}

			if (is_poisonous) {
				error |= DS_POISONED;
				break;
			}
		}

		for (size_t i = pv->len * pv->el_size; 
			i < pv->capacity * pv->el_size; i++) {

			if ((unsigned char) pv->arr[i] != 
				PVECTOR_DEBUG_POISON) {

				error |= DS_POISONED;
				break;
			}
		}
	}
#endif /* PVECTOR_DEBUG */

	return error;
}

const size_t PVECTOR_DUMP_CONTENT_MAXLEN = 16;

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
	fprintf(stream, "\t\tlen\t\t= <%zu>;\n",		pv->len);
	fprintf(stream, "\t\tel_size\t\t= <%zu>;\n",	pv->el_size);
	fprintf(stream, "\t\t*destructor\t= [%p];\n",	pv->destructor);
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

	for (size_t i = 0; i < contents_len; i++) {
		fprintf(stream, "\t\t*[%zu]\t=", i);
		unsigned char *el = (unsigned char *)pv->arr + i * pv->el_size;

		PVECTOR_ONDEBUG(
			int is_poisonous = 1;
		);

		for (size_t j = 0; j < pv->el_size; j++) {
			PVECTOR_ONDEBUG(
				if (el[j] != PVECTOR_DEBUG_POISON) {
					is_poisonous = 0;
				}
			);

			fprintf(stream, " %02x", el[j]);
		}

		fprintf(stream, ";");

		PVECTOR_ONDEBUG(
			if (is_poisonous) {
				fprintf(stream, " (POISON)");
			}
		);

		fprintf(stream, "\n");
	}

	if (contents_truncated) {
		fprintf(stream, "\t\t[truncated]\n");
	}

	
	fprintf(stream, "\t}\n");

	return DS_OK;
}
