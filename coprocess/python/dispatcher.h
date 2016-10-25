#include <Python.h>

#ifndef TYK_COPROCESS_PYTHON_DISPATCHER
#define TYK_COPROCESS_PYTHON_DISPATCHER

extern void dispatch_hook(char*, char*);

static char* dispatcher_module_name = "dispatcher";
static char* dispatcher_class_name = "TykDispatcher";
static char* hook_name = "dispatch_hook";
static char* load_bundle_name = "load_bundle";

static char* dispatch_event_name_s = "dispatch_event";
static PyObject* dispatch_event_name;
static PyObject* dispatch_event;

static PyObject* dispatcher_module;
static PyObject* dispatcher_module_dict;
static PyObject* dispatcher_class;

static PyObject* dispatcher_args;
static PyObject* dispatcher;

static PyObject* dispatcher_hook_name;
static PyObject* dispatcher_hook;

static PyObject* dispatcher_load_bundle_name;
static PyObject* dispatcher_load_bundle;

static char* dispatcher_reload = "reload";
static PyObject* dispatcher_reload_hook;

#endif
