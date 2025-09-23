#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pvector.h"

DSError_t pvector_init(struct pvector *pv, size_t el_size) {
	assert (pv);
	assert (el_size);

	pv->arr = NULL;
	pv->el_size = el_size;
	pv->capacity = 0;
	pv->len = 0;

	pv->destructor = NULL;

	PVECTOR_ONDEBUG(
		pv->_debug_info = {0};
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

const size_t PVECTOR_DUMP_CONTENT_MAXLEN = 128;

DSError_t pvector_dump(struct pvector *pv) {
	printf("PVector dump: \n");

	if (!pv) {
		printf("\tpvector is NULL\n");
		return DS_OK;
	}

	printf("pvector<{%zu bytes}" PVECTOR_ONDEBUG(":{%s}") ">\n", 
		pv->el_size
		PVECTOR_ONDEBUG(, pv->el_size_name)
	);
	printf("\tPassed as [%p]\n", pv);

#ifdef PVECTOR_DEBUG
	PRINT_DS_DEBUG(pv->_debug_info,  "\t");
#else
	printf("\tNo debug symbols provided\n");
#endif /* PVECTOR_DEBUG */
	printf("\t{\n");
	printf("\t\tcapacity\t= <%zu>;\n",	pv->capacity);
	printf("\t\tlen\t\t= <%zu>;\n",		pv->len);
	printf("\t\tel_size\t\t= <%zu>;\n",	pv->el_size);
	printf("\t\t*destructor\t= [%p];\n",	pv->destructor);
	printf("\n");
	printf("\t\t*arr\t\t= [%p];\n",		pv->arr);
	printf("\t}\n");

	printf("\n");
	printf("With contents:\n"
	       "\t{\n");

	size_t contents_len = pv->len;
	if (contents_len > PVECTOR_DUMP_CONTENT_MAXLEN) {
		contents_len = PVECTOR_DUMP_CONTENT_MAXLEN;
	}

	if (contents_len == 0) {
		printf("\t\t(EMPTY)\n");
	}

	for (size_t i = 0; i < contents_len; i++) {
		printf("\t\t*[%zu]\t=", i);
		unsigned char *el = (unsigned char *) pvector_get(pv, i);

		if (el == NULL) {
			printf(" (POISON);\n");
			continue;
		}

		for (size_t j = 0; j < pv->el_size; j++) {
			printf(" %02x", el[j]);
		}
		printf(";\n");
	}

	
	printf("\t}\n");

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
	pv->capacity = new_cap;
	
	return DS_OK;
}

DSError_t pvector_destroy(struct pvector *pv) {
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
	assert (pv);
	assert (npv);

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
