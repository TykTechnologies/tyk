// +build coprocess
// +build python

#include <Python.h>
#include "coprocess/api.h"


static PyObject *store_data(PyObject *self, PyObject *args) {
	char *key, *value;
	int ttl;

	if (!PyArg_ParseTuple(args, "ssi", &key, &value, &ttl))
		return NULL;

	TykStoreData(key, value, ttl);

	Py_RETURN_NONE;
}

static PyObject *get_data(PyObject *self, PyObject *args) {
	char *key, *value;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "s", &key))
		return NULL;

	value = TykGetData(key);
	// TykGetData doesn't currently handle storage errors so let's at least safeguard against null pointer
	if (value == NULL) {
		PyErr_SetString(PyExc_ValueError, "Null pointer from TykGetData");
		return NULL;
	}
	ret = Py_BuildValue("s", value);
	// CGO mallocs it in TykGetData and Py_BuildValue just copies strings, hence it's our responsibility to free it now
	free(value);

	return ret;
}

static PyObject *trigger_event(PyObject *self, PyObject *args) {
	char *name, *payload;

	if (!PyArg_ParseTuple(args, "ss", &name, &payload))
		return NULL;

	TykTriggerEvent(name, payload);

	Py_RETURN_NONE;
}

static PyObject *coprocess_log(PyObject *self, PyObject *args) {
	char *message, *level;

	if (!PyArg_ParseTuple(args, "ss", &message, &level))
		return NULL;

	CoProcessLog(message, level);

	Py_RETURN_NONE;
}


static PyMethodDef module_methods[] = {
	{"store_data", store_data, METH_VARARGS, "Stores the data in gateway storage by given key and TTL"},
	{"get_data", get_data, METH_VARARGS, "Retrieves the data from gateway storage by given key"},
	{"trigger_event", trigger_event, METH_VARARGS, "Triggers a named gateway event with given payload"},
	{"log", coprocess_log, METH_VARARGS, "Logs a message with given level"},
	{NULL, NULL, 0, NULL} /* Sentinel */
};

static PyModuleDef module = {
	PyModuleDef_HEAD_INIT, "gateway_wrapper", NULL, -1, module_methods,
	NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_gateway_wrapper(void) {
	return PyModule_Create(&module);
}
