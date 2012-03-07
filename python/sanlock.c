/*
 * Copyright 2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
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
PyDoc_STRVAR(pydoc_sanlock, "\
Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.\n\
This copyrighted material is made available to anyone wishing to use,\n\
modify, copy, or redistribute it subject to the terms and conditions\n\
of the GNU General Public License v2 or (at your option) any later version.");
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

/* register */
PyDoc_STRVAR(pydoc_register, "\
register() -> int\n\
Register to sanlock daemon and return the connection fd.");

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

/* get_alignment */
PyDoc_STRVAR(pydoc_get_alignment, "\
get_alignment(path) -> int\n\
Get device alignment.");

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

/* init_lockspace */
PyDoc_STRVAR(pydoc_init_lockspace, "\
init_lockspace(lockspace, path, offset=0, max_hosts=0, num_hosts=0, \
use_aio=True)\n\
Initialize a device to be used as sanlock lockspace.");

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

/* init_resource */
PyDoc_STRVAR(pydoc_init_resource, "\
init_resource(lockspace, resource, disks, max_hosts=0, num_hosts=0, \
use_aio=True)\n\
Initialize a device to be used as sanlock resource.\n\
The disks must be in the format: [(path, offset), ... ]");

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

/* add_lockspace */
PyDoc_STRVAR(pydoc_add_lockspace, "\
add_lockspace(lockspace, host_id, path, offset=0)\n\
Add a lockspace, acquiring a host_id in it.");

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

/* inq_lockspace */
PyDoc_STRVAR(pydoc_inq_lockspace, "\
inq_lockspace(lockspace, host_id, path, offset=0)\n\
Return True if the sanlock daemon currently owns the host_id in lockspace,\n\
False otherwise. The special value None is returned when the daemon is\n\
still in the process of acquiring or releasing the host_id.");

static PyObject *
py_inq_lockspace(PyObject *self __unused, PyObject *args)
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
    rv = sanlock_inq_lockspace(&ls, 0 );
    Py_END_ALLOW_THREADS

    if (rv == 0) {
        Py_RETURN_TRUE;
    } else if (rv == -ENOENT) {
        Py_RETURN_FALSE;
    } else if (rv == -EINPROGRESS) {
        Py_RETURN_NONE;
    }

    __set_exception(rv, "Sanlock lockspace inquire failure");
    return NULL;
}

/* rem_lockspace */
PyDoc_STRVAR(pydoc_rem_lockspace, "\
rem_lockspace(lockspace, host_id, path, offset=0)\n\
Remove a lockspace, releasing the acquired host_id.");

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

/* acquire */
PyDoc_STRVAR(pydoc_acquire, "\
acquire(lockspace, resource, disks [, slkfd=fd, pid=owner, shared=False])\n\
Acquire a resource lease for the current process (using the slkfd argument\n\
to specify the sanlock file descriptor) or for an other process (using the\n\
pid argument). If shared is True the resource will be acquired in the shared\n\
mode.\n\
The disks must be in the format: [(path, offset), ... ]\n");

static PyObject *
py_acquire(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, sanlockfd = -1, pid = -1, shared = 0;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks;

    static char *kwlist[] = {"lockspace", "resource", "disks", "slkfd",
                                "pid", "shared", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iii", kwlist,
        &lockspace, &resource, &PyList_Type, &disks, &sanlockfd, &pid,
        &shared)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) != 0) {
        return NULL;
    }

    /* check if any of the slkfd or pid parameters was given */
    if (sanlockfd == -1 && pid == -1) {
        __set_exception(EINVAL, "Invalid slkfd and pid values");
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* prepare sanlock flags */
    if (shared) {
        res->flags |= SANLK_RES_SHARED;
    }

    /* acquire sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_acquire(sanlockfd, pid, 0, 1, &res, 0);
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

/* release */
PyDoc_STRVAR(pydoc_release, "\
release(lockspace, resource, disks [, slkfd=fd, pid=owner])\n\
Release a resource lease for the current process.\n\
The disks must be in the format: [(path, offset), ... ]");

static PyObject *
py_release(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, sanlockfd = -1, pid = -1;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks;

    static char *kwlist[] = {"lockspace", "resource", "disks", "slkfd",
                                "pid", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|ii", kwlist,
        &lockspace, &resource, &PyList_Type, &disks, &sanlockfd, &pid)) {
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
    rv = sanlock_release(sanlockfd, pid, 0, 1, &res);
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

/* exception_errno */
PyDoc_STRVAR(pydoc_errno, "exception errno");

static PyObject *
py_exception_errno(PyObject *self, PyBaseExceptionObject *exc_obj)
{
    PyObject *exc_errno;

    exc_errno = PyTuple_GetItem(exc_obj->args, 0);

    if (exc_errno == NULL)
        return NULL;

    Py_INCREF(exc_errno);
    return exc_errno;
}

static PyMethodDef
sanlock_methods[] = {
    {"register", py_register, METH_NOARGS, pydoc_register},
    {"get_alignment", py_get_alignment, METH_VARARGS, pydoc_get_alignment},
    {"init_lockspace", (PyCFunction) py_init_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_init_lockspace},
    {"init_resource", (PyCFunction) py_init_resource,
                        METH_VARARGS|METH_KEYWORDS, pydoc_init_resource},
    {"add_lockspace", py_add_lockspace, METH_VARARGS, pydoc_add_lockspace},
    {"inq_lockspace", py_inq_lockspace, METH_VARARGS, pydoc_inq_lockspace},
    {"rem_lockspace", py_rem_lockspace, METH_VARARGS, pydoc_rem_lockspace},
    {"acquire", (PyCFunction) py_acquire,
                METH_VARARGS|METH_KEYWORDS, pydoc_acquire},
    {"release", (PyCFunction) py_release,
                METH_VARARGS|METH_KEYWORDS, pydoc_release},
    {NULL, NULL, 0, NULL}
};

static PyMethodDef
sanlock_exception = {
    "errno", (PyCFunction) py_exception_errno, METH_O, pydoc_errno
};

static void
initexception(void)
{
    int rv;
    PyObject *dict, *func, *meth;

    dict = PyDict_New();

    if (dict == NULL)
        return;

    func = PyCFunction_New(&sanlock_exception, NULL);
    meth = PyObject_CallFunction((PyObject *) &PyProperty_Type, "O", func);
    Py_DECREF(func);

    if (meth == NULL)
        return;

    rv = PyDict_SetItemString(dict, sanlock_exception.ml_name, meth);
    Py_DECREF(meth);

    if (rv < 0)
        return;

    py_exception = PyErr_NewException("sanlock.SanlockException", NULL, dict);
    Py_DECREF(dict);
}

PyMODINIT_FUNC
initsanlock(void)
{

    py_module = Py_InitModule4("sanlock",
                sanlock_methods, pydoc_sanlock, NULL, PYTHON_API_VERSION);

    /* Python's module loader doesn't support clean recovery from errors */
    if (py_module == NULL)
        return;

    /* Initializing sanlock exception */
    initexception();

    if (py_exception == NULL)
        return;

    Py_INCREF(py_exception);
    PyModule_AddObject(py_module, "SanlockException", py_exception);
}
