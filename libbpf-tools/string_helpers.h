/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __STRING_HELPERS_H
#define __STRING_HELPERS_H

struct string_array {
	char **data;
	int size;
	int cap;
};

struct string_array *string_array__init();

void string_array__free(struct string_array *arr);

int string_array__push(struct string_array *arr, const char *s);

#endif /* __STRING_HELPERS_H */
