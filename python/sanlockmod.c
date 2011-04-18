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
#include <sanlock_direct.h>

int __sanlockmod_fd = -1;
PyObject *py_module;

/* SANLock exception */
static PyObject *sanlockmod_exception;

static int
__parse_lockspace(char *lockspace, struct sanlk_lockspace *ret_ls)
{
    char *lockspace_arg;

    /* sanlock_str_to_lockspace is destructive */
    lockspace_arg = strdup(lockspace);

    if (lockspace_arg == NULL) {
        PyErr_SetString(sanlockmod_exception, "SANLock extension memory error");
        return -1;
    }

    /* convert lockspace string to structure */
    if (sanlock_str_to_lockspace(lockspace_arg, ret_ls) != 0) {
        PyErr_SetString(sanlockmod_exception, "Invalid SANLock lockspace");
        goto exit_fail;
    }

    free(lockspace_arg);
    return 0;

exit_fail:
    free(lockspace_arg);
    return -1;
}

static int
__parse_resource(char *resource, struct sanlk_resource **ret_res)
{
    /* convert resource string to structure */
    if (sanlock_str_to_res(resource, ret_res) != 0) {
        PyErr_SetString(sanlockmod_exception, "Invalid SANLock resource");
        return -1;
    }

    return 0;
}

static PyObject *
py_register(PyObject *self, PyObject *args)
{
    if (__sanlockmod_fd < 0) {
        __sanlockmod_fd = sanlock_register();
    }

    if (__sanlockmod_fd < 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock registration failed");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *py_init_lockspace(PyObject *self, PyObject *args)
{
    int rv, max_hosts, num_hosts, use_aio;
    char *lockspace;
    struct sanlk_lockspace ls;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "siii", &lockspace,
                          &max_hosts, &num_hosts, &use_aio)) {
        return NULL;
    }

    /* parse and check sanlock lockspace */
    if (__parse_lockspace(lockspace, &ls) != 0) {
        return NULL;
    }

    /* init sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_direct_init(&ls, NULL, max_hosts, num_hosts, use_aio);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock lockspace init failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *py_init_resource(PyObject *self, PyObject *args)
{
    int rv, max_hosts, num_hosts, use_aio;
    char *resource;
    struct sanlk_resource *res;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "siii", &resource,
                          &max_hosts, &num_hosts, &use_aio)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(resource, &res) != 0) {
        return NULL;
    }

    /* init sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_direct_init(NULL, res, max_hosts, num_hosts, use_aio);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock resource init failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_add_lockspace(PyObject *self, PyObject *args)
{
    int rv;
    char *lockspace;
    struct sanlk_lockspace ls;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &lockspace)) {
        return NULL;
    }

    /* parse and check sanlock lockspace */
    if (__parse_lockspace(lockspace, &ls) != 0) {
        return NULL;
    }

    /* add sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_add_lockspace(&ls, 0 );
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock lockspace add failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_rem_lockspace(PyObject *self, PyObject *args)
{
    int rv;
    char *lockspace;
    struct sanlk_lockspace ls;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &lockspace)) {
        return NULL;
    }

    /* parse and check sanlock lockspace */
    if (__parse_lockspace(lockspace, &ls) != 0) {
        return NULL;
    }

    /* remove sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_rem_lockspace(&ls, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock lockspace remove failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_acquire(PyObject *self, PyObject *args)
{
    int rv;
    char *resource;
    struct sanlk_resource *res;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &resource)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(resource, &res) != 0) {
        return NULL;
    }

    /* acquire sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_acquire(__sanlockmod_fd, -1, 0, 1, &res, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock resource not acquired");
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
    int rv;
    char *resource;
    struct sanlk_resource *res;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &resource)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(resource, &res) != 0) {
        return NULL;
    }

    /* release sanlock resource (gil disabled)*/
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_release(__sanlockmod_fd, -1, 0, 1, &res);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        PyErr_SetString(sanlockmod_exception, "SANLock resource not released");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyMethodDef
sanlockmod_methods[] = {
    {"register", py_register, METH_NOARGS, "Register to SANLock daemon."},
    {"init_lockspace", py_init_lockspace, METH_VARARGS,
                      "Initialize a device to be used as SANLock lockspace."},
    {"init_resource", py_init_resource, METH_VARARGS,
                      "Initialize a device to be used as SANLock resource."},
    {"add_lockspace", py_add_lockspace, METH_VARARGS,
                      "Add a lockspace, acquiring a host_id in it."},
    {"rem_lockspace", py_rem_lockspace, METH_VARARGS,
                      "Remove a lockspace, releasing our host_id in it."},
    {"acquire", py_acquire, METH_VARARGS,
                "Acquire a resource lease for the current process."},
    {"release", py_release, METH_VARARGS,
                "Release a resource lease for the current process."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initsanlockmod(void)
{
    py_module = Py_InitModule("sanlockmod", sanlockmod_methods);

    /* Python's module loader doesn't support clean recovery from errors */
    if (py_module == NULL)
        return;

    /* Initializing sanlock exception */
    sanlockmod_exception = PyErr_NewException("sanlockmod.exception", NULL, NULL);
    Py_INCREF(sanlockmod_exception);
    PyModule_AddObject(py_module, "exception", sanlockmod_exception);
}
