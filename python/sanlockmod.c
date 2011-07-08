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

#define SKERRNO(x) (-x)

PyObject *py_module;

/* SANLock exception */
static PyObject *sanlockmod_exception;

static void
__set_exception(int en, char *msg)
{
    PyObject *exc_tuple;

    exc_tuple = Py_BuildValue("(is)", en, msg);

    if (exc_tuple == NULL) {
        PyErr_NoMemory();
    } else {
        PyErr_SetObject(sanlockmod_exception, exc_tuple);
        Py_DECREF(exc_tuple);
    }
}

static int
__parse_lockspace(char *lockspace, struct sanlk_lockspace *ret_ls)
{
    int rv;
    char *lockspace_arg;

    /* sanlock_str_to_lockspace is destructive */
    lockspace_arg = strdup(lockspace);

    if (lockspace_arg == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    /* convert lockspace string to structure */
    rv = sanlock_str_to_lockspace(lockspace_arg, ret_ls);

    if (rv != 0) {
        __set_exception(SKERRNO(rv), "Invalid SANLock lockspace");
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
    int rv;

    /* convert resource string to structure */
    rv = sanlock_str_to_res(resource, ret_res);

    if (rv != 0) {
        __set_exception(SKERRNO(rv), "Invalid SANLock resource");
        return -1;
    }

    return 0;
}

static PyObject *
py_register(PyObject *self, PyObject *args)
{
    int sanlockfd;

    sanlockfd = sanlock_register();

    if (sanlockfd < 0) {
        __set_exception(SKERRNO(sanlockfd),
                        "SANLock registration failed");
        return NULL;
    }

    return PyInt_FromLong(sanlockfd);
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
        __set_exception(SKERRNO(rv), "SANLock lockspace init failure");
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
        __set_exception(SKERRNO(rv), "SANLock resource init failure");
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
        __set_exception(SKERRNO(rv), "SANLock lockspace add failure");
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
        __set_exception(SKERRNO(rv), "SANLock lockspace remove failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_acquire(PyObject *self, PyObject *args)
{
    int rv, sanlockfd;
    char *resource;
    struct sanlk_resource *res;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "is", &sanlockfd, &resource)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(resource, &res) != 0) {
        return NULL;
    }

    /* acquire sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_acquire(sanlockfd, -1, 0, 1, &res, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(SKERRNO(rv), "SANLock resource not acquired");
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
    int rv, sanlockfd;
    char *resource;
    struct sanlk_resource *res;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "is", &sanlockfd, &resource)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(resource, &res) != 0) {
        return NULL;
    }

    /* release sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_release(sanlockfd, -1, 0, 1, &res);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(SKERRNO(rv), "SANLock resource not released");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyObject *
py_get_alignment(PyObject *self, PyObject *args)
{
    int rv;
    char *path;
    struct sanlk_disk disk;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return NULL;
    }

    memset(&disk, 0, sizeof(struct sanlk_disk));
    strncpy(disk.path, path, SANLK_PATH_LEN - 1);

    /* get device alignment (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_direct_align(&disk);
    Py_END_ALLOW_THREADS

    if (rv < 0) {
        __set_exception(SKERRNO(rv), "Unable to get device alignment");
        return NULL;
    }

    return PyInt_FromLong(rv);
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
    {"get_alignment", py_get_alignment, METH_VARARGS,
                "Get device alignment."},
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
