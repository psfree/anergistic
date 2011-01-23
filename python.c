// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "emulate.h"
#include "helper.h"

struct ctx_t _ctx;
struct ctx_t *ctx;

static PyObject *anergistic_execute(PyObject *self, PyObject *args)
{
	unsigned char *local_store, *registers;
	Py_ssize_t local_store_size, registers_size;
	int pc;
	PyObject *breakpoints = NULL;
	PyObject *breakpoints_insns = NULL;
	
	(void)self;
	if (!PyArg_ParseTuple(args, "w#w#I|OO", 
		&local_store, &local_store_size, 
		&registers, &registers_size,
		&pc,
		&breakpoints,
		&breakpoints_insns))
		return NULL;
	
	// XXX: why is (int) required?	
	if ((int)local_store_size != 256 * 1024)
	{
		PyErr_SetString(PyExc_TypeError, "The local storage must be a 256kb string array");
		return NULL;
	}
	
	// XXX: why is (int) required?	
	if ((int)registers_size != 128 * 16)
	{
		PyErr_SetString(PyExc_TypeError, "The registers must be a 128*16 string array");
		return NULL;
	}
	
	if (pc < 0 || (pc >= 256 * 1024) || (pc & 3))
	{
		PyErr_SetString(PyExc_TypeError, "PC must be aligned pointer within ls");
		return NULL;
	}
	
	memset(&_ctx, 0, sizeof _ctx);
	ctx = &_ctx;
	ctx->ls = (unsigned char*)local_store;
	ctx->pc = pc;
	
	int i;
	for (i = 0; i < 128; ++i)
		byte_to_reg(i, registers + i * 16);

	ctx->paused = 0;
	ctx->trap = 1;
	
	ctx->pc &= LSLR;
	
	while(emulate() == 0)
	{
		if (breakpoints)
		{
			PyObject *pc = PyInt_FromLong(ctx->pc);
			if (PySet_Contains(breakpoints, pc))
			{
				Py_DECREF(pc);
				break;
			}
			Py_DECREF(pc);
		}
		if (breakpoints_insns)
		{
			PyObject *pc = PyInt_FromLong(be32(ctx->ls + ctx->pc) >> 21);
			if (PySet_Contains(breakpoints_insns, pc))
			{
				Py_DECREF(pc);
				break;
			}
			Py_DECREF(pc);
		}
		if (PyErr_CheckSignals())
			return NULL;
		if (PyErr_Occurred())
			return NULL;
	}

	for (i = 0; i < 128; ++i)
		reg_to_byte(registers + i * 16, i);

	return PyInt_FromLong(ctx->pc);
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	PyErr_SetString(PyExc_RuntimeError, msg);
}

static PyMethodDef AnergisticMethods[] = {
	{"execute", anergistic_execute, METH_VARARGS, "execute"},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initanergistic(void)
{
	(void) Py_InitModule("anergistic", AnergisticMethods);
}
