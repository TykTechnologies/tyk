#ifndef LIBPLUGIN_TYPES_H
#define LIBPLUGIN_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int pluginSymbol;

typedef struct result {
	char* err;
	char* response;
} result;

result result_error(char* err);
result result_success(char* response);

pluginSymbol plugin_load(char* name, char* symbol);
result plugin_invoke(pluginSymbol fd, char* request);
int plugin_free_result(pluginSymbol fd);

#ifdef __cplusplus
}
#endif

#endif