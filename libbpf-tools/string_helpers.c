// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Tiago Ilieve
//
// 15-Apr-2024   Tiago Ilieve   Created this.
#include <stdlib.h>
#include <string.h>
#include "string_helpers.h"

struct string_array *string_array__init() {
	struct string_array *arr;

	arr = (struct string_array *) malloc(sizeof(struct string_array));
	if (arr == NULL) {
		return NULL;
	}

	arr->data = (char **) malloc(sizeof(char *));
	if (arr->data == NULL) {
		free(arr);
		return NULL;
	}

	arr->size = 0;
	arr->cap = 1;

	return arr;
}

void string_array__free(struct string_array *arr) {
	if (arr == NULL || arr->data == NULL) {
		return;
	}

	for (int i = 0; i < arr->size; i++) {
		free(arr->data[i]);
	}

	free(arr->data);
	free(arr);
	arr = NULL;
}

int string_array__push(struct string_array *arr, const char *s) {
	char **data;
	char *str;
	int cap;

	if (arr->size == arr->cap) {
		cap = arr->cap * 2;
		data = (char **) realloc(arr->data, cap * sizeof(char *));
		if (data == NULL) {
			return -1;
		}

		arr->cap = cap;
		arr->data = data;
	}

	str = strdup(s);
	if (str == NULL) {
		return -1;
	}

	arr->data[arr->size] = str;
	arr->size++;

	return 0;
}
