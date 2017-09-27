
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "libknc.h"

void pyknc_delete(PyObject *ctx);
static PyObject *pyknc_connect(PyObject *self, PyObject *args);
static PyObject *pyknc_write(PyObject *self, PyObject *args);
static PyObject *pyknc_read(PyObject *self, PyObject *args);

static PyObject *KncException;

void
pyknc_delete(PyObject *knc)
{
	knc_ctx	ctx;

	if (knc == NULL)
		return;

	ctx = PyCapsule_GetPointer(knc, NULL);
	if (ctx == NULL)
		return NULL;

	knc_ctx_destroy(ctx);
}

static PyObject *
pyknc_connect(PyObject *self, PyObject *args)
{
	knc_ctx	 ctx;
	char	*service;
	char	*hostname;
	char	*port;

	if (!PyArg_ParseTuple(args, "sss", &service, &hostname, &port))
		return NULL;

	ctx = knc_connect(NULL, hostname, service, port, 0);
	knc_authenticate(ctx);

	if (knc_error(ctx)) {
		PyErr_SetString(KncException, knc_errstr(ctx));
		knc_ctx_destroy(ctx);
		return NULL;
	}

	return PyCapsule_New(ctx, NULL, &pyknc_delete);
}

static PyObject *
pyknc_write(PyObject *self, PyObject *args)
{
	PyObject	*knc;
	knc_ctx		 ctx;
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
	knc_ctx		 ctx;
	ssize_t		 nread;
	char		*buf;
	Py_ssize_t	 buffer_sz;

	if (!PyArg_ParseTuple(args, "On", &knc, &buffer_sz))
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
