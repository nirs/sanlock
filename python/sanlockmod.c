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

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

/* Sanlock module */
PyObject *py_module;

/* Sanlock exception */
static PyObject *py_exception;

static void
__set_exception(int en, char *msg)
{
    char *err_name;
    PyObject *exc_tuple;

    if (en < 0 && en > -200) {
        en = -en;
        err_name = strerror(en);
    } else {
        err_name = "Sanlock exception";
    }

    exc_tuple = Py_BuildValue("(iss)", en, msg, err_name);

    if (exc_tuple == NULL) {
        PyErr_NoMemory();
    } else {
        PyErr_SetObject(py_exception, exc_tuple);
        Py_DECREF(exc_tuple);
    }
}

static int
__parse_resource(PyObject *obj, struct sanlk_resource **res_ret)
{
    int i, num_disks, res_len;
    struct sanlk_resource *res;

    num_disks = PyList_Size(obj);

    res_len = sizeof(struct sanlk_resource) +
                        (sizeof(struct sanlk_disk) * num_disks);
    res = malloc(res_len);

    if (res == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    memset(res, 0, res_len);
    res->num_disks = num_disks;

    for (i = 0; i < num_disks; i++) {
        char *p = NULL;
        PyObject *tuple, *path = NULL, *offset = NULL;

        tuple = PyList_GetItem(obj, i);

        if (PyTuple_Check(tuple)) {
            if (PyTuple_Size(tuple) != 2) {
                __set_exception(EINVAL, "Invalid resource tuple");
                goto exit_fail;
            }

            path = PyTuple_GetItem(tuple, 0);
            offset = PyTuple_GetItem(tuple, 1);

            p = PyString_AsString(path);

            if (!PyInt_Check(offset)) {
                __set_exception(EINVAL, "Invalid resource offset");
                goto exit_fail;
            }
        } else if (PyString_Check(tuple)) {
            p = PyString_AsString(tuple);
        }

        if (p == NULL) {
            __set_exception(EINVAL, "Invalid resource path");
            goto exit_fail;
        }

        strncpy(res->disks[i].path, p, SANLK_PATH_LEN - 1);

        if (offset == NULL) {
            res->disks[i].offset = 0;
        } else {
            res->disks[i].offset = PyInt_AsLong(offset);
        }
    }

    *res_ret = res;
    return 0;

exit_fail:
    free(res);
    return -1;
}

static PyObject *
py_register(PyObject *self __unused, PyObject *args)
{
    int sanlockfd;

    sanlockfd = sanlock_register();

    if (sanlockfd < 0) {
        __set_exception(sanlockfd, "Sanlock registration failed");
        return NULL;
    }

    return PyInt_FromLong(sanlockfd);
}

static PyObject *
py_init_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, num_hosts = 0, use_aio = 1;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "path", "offest",
                                "max_hosts", "num_hosts", "use_aio", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss|kiii", kwlist,
        &lockspace, &path, &ls.host_id_disk.offset, &max_hosts,
        &num_hosts, &use_aio)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN);

    /* init sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_direct_init(&ls, NULL, max_hosts, num_hosts, use_aio);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace init failure");
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject *
py_init_resource(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, num_hosts = 0, use_aio = 1;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks;

    static char *kwlist[] = {"lockspace", "resource", "disks", "max_hosts",
                                "num_hosts", "use_aio", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iii",
        kwlist, &lockspace, &resource, &PyList_Type, &disks, &max_hosts,
        &num_hosts, &use_aio)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) != 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* init sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_direct_init(NULL, res, max_hosts, num_hosts, use_aio);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock resource init failure");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyObject *
py_add_lockspace(PyObject *self __unused, PyObject *args)
{
    int rv;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "sks|k",
        &lockspace, &ls.host_id, &path, &ls.host_id_disk.offset)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN);

    /* add sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_add_lockspace(&ls, 0 );
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace add failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_rem_lockspace(PyObject *self __unused, PyObject *args)
{
    int rv;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "sks|k",
        &lockspace, &ls.host_id, &path, &ls.host_id_disk.offset)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN);

    /* remove sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_rem_lockspace(&ls, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace remove failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_acquire(PyObject *self __unused, PyObject *args)
{
    int rv, sanlockfd;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "issO!",
        &sanlockfd, &lockspace, &resource, &PyList_Type, &disks)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) != 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* acquire sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_acquire(sanlockfd, -1, 0, 1, &res, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock resource not acquired");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyObject *
py_release(PyObject *self __unused, PyObject *args)
{
    int rv, sanlockfd;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks;

    /* parse python tuple */
    if (!PyArg_ParseTuple(args, "issO!",
        &sanlockfd, &lockspace, &resource, &PyList_Type, &disks)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) != 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* release sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_release(sanlockfd, -1, 0, 1, &res);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock resource not released");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

static PyObject *
py_get_alignment(PyObject *self __unused, PyObject *args)
{
    int rv;
    const char *path;
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
        __set_exception(rv, "Unable to get device alignment");
        return NULL;
    }

    return PyInt_FromLong(rv);
}

static PyMethodDef
sanlockmod_methods[] = {
    {"register",
            py_register, METH_NOARGS, "Register to sanlock daemon."},
    {"get_alignment",
            py_get_alignment, METH_VARARGS, "Get device alignment."},
    {"init_lockspace",
            (PyCFunction) py_init_lockspace, METH_VARARGS|METH_KEYWORDS,
            "Initialize a device to be used as sanlock lockspace."},
    {"init_resource",
            (PyCFunction) py_init_resource, METH_VARARGS|METH_KEYWORDS,
            "Initialize a device to be used as sanlock resource."},
    {"add_lockspace",
            py_add_lockspace, METH_VARARGS,
            "Add a lockspace, acquiring a host_id in it."},
    {"rem_lockspace",
            py_rem_lockspace, METH_VARARGS,
            "Remove a lockspace, releasing our host_id in it."},
    {"acquire",
            py_acquire, METH_VARARGS,
            "Acquire a resource lease for the current process."},
    {"release",
            py_release, METH_VARARGS,
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
    py_exception = PyErr_NewException("sanlockmod.SanlockException", NULL, NULL);
    Py_INCREF(py_exception);
    PyModule_AddObject(py_module, "SanlockException", py_exception);
}
