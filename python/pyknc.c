
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "libknc.h"

void pyknc_delete(PyObject *ctx);
static PyObject *pyknc_connect(PyObject *self, PyObject *args);
static PyObject *pyknc_write(PyObject *self, PyObject *args);
static PyObject *pyknc_read(PyObject *self, PyObject *args);

static PyObject *KncException;

void
pyknc_delete(PyObject *ctx)
{
	struct knc_ctx *knc = PyCapsule_GetPointer(ctx, NULL);

	if (ctx == NULL)
		return;

	knc_ctx_destroy(knc);
}

static PyObject *
pyknc_connect(PyObject *self, PyObject *args)
{
	struct knc_ctx	*ctx;
	char		*service;
	char		*hostname
	char		*port;

	if (!PyArg_ParseTuple(args, "sss", &service, &hostname, &port))
		return NULL;

	ctx = knc_connect(NULL, hostname, service, port, 0);
	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		knc_ctx_destroy(knc);
		PyErr_SetString(KncException, knc_errstr(ctx));
		return NULL;
	}

	return Py_BuildValue("O", PyCapsule_New(ctx, NULL, &pyknc_delete));
}

static PyObject *
pyknc_write(PyObject *self, PyObject *args)
{
	PyObject	*knc;
	struct knc_ctx	*ctx;
	char		*buffer;
	Py_ssize_t	 buffer_len;
	ssize_t		 nwrite;

	if (!PyArg_ParseTuple(args, "Os#", &knc, &buffer, &buffer_len))
		return NULL;

	ctx = PyCapsule_GetPointer(knc, NULL);
	if (ctx == NULL)
		return NULL;

	nwrite = knc_write(ctx, buffer, buffer_len);

	if (knc_error(ctx)) {
		PyErr_SetString(KncException, knc_errstr(ctx));
		return NULL;
	}

	return PyLong_FromLong(nwrite);
}

static PyObject *
pyknc_read(PyObject *self, PyObject *args)
{
	PyObject	*knc;
	PyObject	*robj;
	struct knc_ctx	*ctx;
	ssize_t		 nread;
	char		*buf;
	Py_ssize_t	 buffer_sz;

	if (!PyArg_ParseTuple(args, "Oi", &knc, &buffer_sz))
		return NULL;

	ctx = PyCapsule_GetPointer(knc, NULL);
	buf = malloc(buffer_sz);
	if (buf == NULL)
		return PyErr_NoMemory();

	nread = knc_read(ctx, buf, buffer_sz);

	if (nread < 0) {
		free(buf);

		if (knc_error(ctx)) {
			PyErr_SetString(KncException, knc_errstr(ctx));
			return NULL;
		}

		return PyErr_SetFromErrno(PyExc_OSError);
	}

	if (knc_error(ctx)) {
		PyErr_SetString(KncException, knc_errstr(ctx));
		free(buf);
		return NULL;
	}

	robj = PyString_FromStringAndSize(buf, nread);
	free(buf);
	return robj;
}

static PyMethodDef PyKncMethods[] = {
    {"connect", pyknc_connect, METH_VARARGS, "Make a KNC Connection"},
    {"knc_read", pyknc_read, METH_VARARGS, "Read some data from a KNC stream"},
    {"knc_write", pyknc_write, METH_VARARGS, "Write some data to a KNC stream"},
    { NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpyknc(void)
{
	PyObject	*m;

	m = Py_InitModule3("pyknc", PyKncMethods,
	    "Python bindings for KNC simple interface");
	if (m == NULL)
		return;

	KncException = PyErr_NewException("pyknc.KncException", NULL, NULL);
	Py_INCREF(KncException);
	PyModule_AddObject(m, "KncException", KncException);
}
