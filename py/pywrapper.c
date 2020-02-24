#include "Python.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vulns.h"

PyObject* vulns_init(PyObject* self, PyObject* args) {
	Py_ssize_t i, size;
	char *confFile, *g, **p;
	PyObject *vulns, *impacts, *tmp;

	if (!PyArg_ParseTuple(args, "s", &confFile))
		return NULL;
	/*printf("confFile = %s\n", confFile);*/

	if (vulnsInit(confFile)<0) {
		puts("vulnsInit error");
		return NULL;
	}
	return Py_BuildValue("");
}

PyObject* vulns_report(PyObject* self, PyObject* args) {
	Py_ssize_t i, size;
	char *id;
	PyObject *dict;

	if (!PyArg_ParseTuple(args, "s", &id))
		return NULL;
	/*printf("id = %s\n", id);*/
	dict = PyDict_New();
	if (!dict) {
		return NULL;
	}	
	if (vulnsReport(id, dict)<0) {
		puts("vulnsReport error");
		/*
                return NULL;
                */
	}
	return Py_BuildValue("O", dict);

}

PyObject* vulns_digest(PyObject* self, PyObject* args) {
	Py_ssize_t i, size;
	char *id;
	PyObject *dict;

	if (!PyArg_ParseTuple(args, "s", &id))
		return NULL;
	/*printf("id = %s\n", id);*/
	dict = PyDict_New();
	if (!dict) {
		return NULL;
	}	
	vulnsDigest(id, dict);
	return Py_BuildValue("O", dict);
}

static PyMethodDef vulnsmethods[] = {
	{"init", vulns_init, METH_VARARGS},
	{"report", vulns_report, METH_VARARGS},
	{"digest", vulns_digest, METH_VARARGS},
	{NULL},
};

void initvulns() {
	Py_InitModule("vulns", vulnsmethods);
}
