#include <stdio.h>
#include <string.h>
#include "plugin.h"

extern int Load(char*, char*);
extern result Invoke(int, char*);
extern int Free(int);

pluginSymbol plugin_load(char* namespace, char* name) {
	char* i = strdup(namespace);
	char* j = strdup(name);

	return Load(i, j);
};

result plugin_invoke(pluginSymbol fd, char* request) {
	return Invoke(fd, strdup(request));
};

int plugin_free_result(pluginSymbol fd) {
	return Free(fd);
};

result result_error(char* err) {
	struct result ret = { .err = strdup(err) };
	return ret;
};

result result_success(char* response) {
	struct result ret = { .response = strdup(response) };
	return ret;
};
