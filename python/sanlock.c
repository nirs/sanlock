/*
 * Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <Python.h>
#include <sanlock.h>
#include <sanlock_resource.h>
#include <sanlock_admin.h>

int __sanlock_fd = -1;
PyObject *py_module;

/* SANLock exception */
static PyObject *sanlock_exception;

static PyObject *
py_register(PyObject *self, PyObject *args)
{
    __sanlock_fd = sanlock_register();

    if (__sanlock_fd < 0) {
        PyErr_SetString(sanlock_exception, "SANLock registration failed");
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
__parse_lockspace(PyObject *args, struct sanlk_lockspace *ret_ls)
{
    char *lockspace;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &lockspace)) {
        return -1;
    }

    /* convert lockspace string to structure */
    if (sanlock_str_to_lockspace(lockspace, ret_ls) != 0) {
        PyErr_SetString(sanlock_exception, "Invalid sanlock resource");
        return -1;
    }

    return 0;
}

static PyObject *
py_add_lockspace(PyObject *self, PyObject *args)
{
    struct sanlk_lockspace ls;

    if (__parse_lockspace(args, &ls) != 0) {
        return NULL;
    }

    /* add sanlock lockspace */
    if (sanlock_add_lockspace(&ls, 0 ) != 0) {
        PyErr_SetString(sanlock_exception, "SANLock lockspace add failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_rem_lockspace(PyObject *self, PyObject *args)
{
    struct sanlk_lockspace ls;

    if (__parse_lockspace(args, &ls) != 0) {
        return NULL;
    }

    /* remove sanlock lockspace */
    if (sanlock_rem_lockspace(&ls, 0 ) != 0) {
        PyErr_SetString(sanlock_exception, "SANLock lockspace remove failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
__parse_resource(PyObject *args, struct sanlk_resource **ret_res)
{
    char *resource;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &resource)) {
        return -1;
    }

    /* convert resource string to structure */
    if (sanlock_str_to_res(resource, ret_res) != 0) {
        PyErr_SetString(sanlock_exception, "Invalid sanlock resource");
        return -1;
    }

    return 0;
}

static PyObject *
py_acquire(PyObject *self, PyObject *args)
{
    struct sanlk_resource *res;

    if (__parse_resource(args, &res) != 0) {
        return NULL;
    }

    /* acquire resource */
    if (sanlock_acquire(__sanlock_fd, -1, 0, 1, &res, 0) != 0) {
        PyErr_SetString(sanlock_exception, "SANLock resource not acquired");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyObject *
py_release(PyObject *self, PyObject *args)
{
    struct sanlk_resource *res;

    if (__parse_resource(args, &res) != 0) {
        return NULL;
    }

    /* release resource */
    if (sanlock_release(__sanlock_fd, -1, 0, 1, &res) != 0) {
        PyErr_SetString(sanlock_exception, "SANLock resource not released");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyMethodDef
sanlock_methods[] = {
    {"register", py_register, METH_NOARGS, "Register to sanlock daemon."},
    {"add_lockspace", py_add_lockspace, METH_VARARGS,
                      "Add a lockspace, acquiring a host_id in it."},
    {"rem_lockspace", py_rem_lockspace, METH_VARARGS,
                      "Remove a lockspace, releasing our host_id in it."},
    {"acquire", py_acquire, METH_VARARGS,
                "Acquire leases for the current process."},
    {"release", py_release, METH_VARARGS,
                "Release leases for the current process."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initsanlock(void)
{
    py_module = Py_InitModule("sanlock", sanlock_methods);

    /* Python's module loader doesn't support clean recovery from errors */
    if (py_module == NULL)
        return;

    /* Initializing sanlock exception */
    sanlock_exception = PyErr_NewException("sanlock.exception", NULL, NULL);
    Py_INCREF(sanlock_exception);
    PyModule_AddObject(py_module, "exception", sanlock_exception);
}
