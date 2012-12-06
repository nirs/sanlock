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
*DEPRECATED* use write_lockspace instead.\n\
Initialize a device to be used as sanlock lockspace.");

static PyObject *
py_init_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, num_hosts = 0, use_aio = 1;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "path", "offset",
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
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

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
*DEPRECATED* use write_resource instead.\n\
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

/* write_lockspace */
PyDoc_STRVAR(pydoc_write_lockspace, "\
write_lockspace(lockspace, path, offset=0, max_hosts=0, iotimeout=0)\n\
Initialize or update a device to be used as sanlock lockspace.");

static PyObject *
py_write_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0;
    uint32_t io_timeout = 0;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "path", "offset", "max_hosts",
                                "iotimeout", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss|kiiI", kwlist,
        &lockspace, &path, &ls.host_id_disk.offset, &max_hosts,
        &io_timeout)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* write sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_write_lockspace(&ls, max_hosts, 0, io_timeout);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace write failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

/* write_resource */
PyDoc_STRVAR(pydoc_write_resource, "\
write_resource(lockspace, resource, disks, max_hosts=0, num_hosts=0)\n\
Initialize a device to be used as sanlock resource.\n\
The disks must be in the format: [(path, offset), ... ]");

static PyObject *
py_write_resource(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, num_hosts = 0;
    const char *lockspace, *resource;
    struct sanlk_resource *rs;
    PyObject *disks;

    static char *kwlist[] = {"lockspace", "resource", "disks", "max_hosts",
                                "num_hosts", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iii",
        kwlist, &lockspace, &resource, &PyList_Type, &disks, &max_hosts,
        &num_hosts)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &rs) != 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(rs->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(rs->name, resource, SANLK_NAME_LEN);

    /* init sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_write_resource(rs, max_hosts, num_hosts, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock resource write failure");
        goto exit_fail;
    }

    free(rs);
    Py_RETURN_NONE;

exit_fail:
    free(rs);
    return NULL;
}

/* add_lockspace */
PyDoc_STRVAR(pydoc_add_lockspace, "\
add_lockspace(lockspace, host_id, path, offset=0, iotimeout=0, async=False)\n\
Add a lockspace, acquiring a host_id in it. If async is True the function\n\
will return immediatly and the status can be checked using inq_lockspace.\n\
The iotimeout option configures the io timeout for the specific lockspace,\n\
overriding the default value (see the sanlock daemon parameter -o).");

static PyObject *
py_add_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, async = 0, flags = 0;
    uint32_t iotimeout = 0;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "host_id", "path", "offset",
                                "iotimeout", "async", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sks|kIi", kwlist,
        &lockspace, &ls.host_id, &path, &ls.host_id_disk.offset, &iotimeout,
        &async)) {
        return NULL;
    }

    /* prepare sanlock_add_lockspace flags */
    if (async) {
        flags |= SANLK_ADD_ASYNC;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* add sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_add_lockspace_timeout(&ls, flags, iotimeout);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace add failure");
        return NULL;
    }

    Py_RETURN_NONE;
}

/* inq_lockspace */
PyDoc_STRVAR(pydoc_inq_lockspace, "\
inq_lockspace(lockspace, host_id, path, offset=0, wait=False)\n\
Return True if the sanlock daemon currently owns the host_id in lockspace,\n\
False otherwise. The special value None is returned when the daemon is\n\
still in the process of acquiring or releasing the host_id. If the wait\n\
flag is set to True the function will block until the host_id is either\n\
acquired or released.");

static PyObject *
py_inq_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, waitrs = 0, flags = 0;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "host_id", "path", "offset",
                                "wait", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sks|ki", kwlist,
        &lockspace, &ls.host_id, &path, &ls.host_id_disk.offset,
        &waitrs)) {
        return NULL;
    }

    /* prepare sanlock_inq_lockspace flags */
    if (waitrs) {
        flags |= SANLK_INQ_WAIT;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* add sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_inq_lockspace(&ls, flags);
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
rem_lockspace(lockspace, host_id, path, offset=0, async=False, unused=False)\n\
Remove a lockspace, releasing the acquired host_id. If async is True the\n\
function will return immediately and the status can be checked using\n\
inq_lockspace. If unused is True the command will fail (EBUSY) if there is\n\
at least one acquired resource in the lockspace (instead of automatically\n\
release it).");

static PyObject *
py_rem_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, async = 0, unused = 0, flags = 0;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "host_id", "path", "offset",
                                "async", "unused", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sks|kii", kwlist,
        &lockspace, &ls.host_id, &path, &ls.host_id_disk.offset, &async,
        &unused)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* prepare sanlock_rem_lockspace flags */
    if (async) {
        flags |= SANLK_REM_ASYNC;
    }

    if (unused) {
        flags |= SANLK_REM_UNUSED;
    }

    /* remove sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_rem_lockspace(&ls, flags);
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

    /* check if any of the slkfd or pid parameters was given */
    if (sanlockfd == -1 && pid == -1) {
        __set_exception(EINVAL, "Invalid slkfd and pid values");
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) != 0) {
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

/* killpath */
PyDoc_STRVAR(pydoc_killpath, "\
killpath(path, args [, slkfd=fd])\n\
Configure the path and arguments of the executable used to fence a\n\
process either by causing the pid to exit (kill) or putting it into\n\
a safe state (resources released).\n\
The arguments must be in the format: [\"arg1\", \"arg2\", ...]");

static PyObject *
py_killpath(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, i, j, n, num_args, sanlockfd = -1;
    char *p, *path, kpargs[SANLK_HELPER_ARGS_LEN];
    PyObject *argslist, *item;

    static char *kwlist[] = {"path", "args", "slkfd", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sO!|i", kwlist,
        &path, &PyList_Type, &argslist, &sanlockfd)) {
        return NULL;
    }

    /* checking the path length */
    if (strlen(path) + 1 > SANLK_HELPER_PATH_LEN) {
        __set_exception(EINVAL, "Killpath path argument too long");
        return NULL;
    }

    num_args = PyList_Size(argslist);
    memset(kpargs, 0, SANLK_HELPER_ARGS_LEN);

    /* creating the arguments string from a python list */
    for (i = 0, n = 0; i < num_args; i++) {
        size_t arg_len;

        item = PyList_GetItem(argslist, i);
        p = PyString_AsString(item);

        if (p == NULL) {
            __set_exception(EINVAL, "Killpath argument not a string");
            return NULL;
        }

        /* computing the argument length considering the escape chars */
        for (j = 0, arg_len = 0; p[j]; j++, arg_len++) {
            if (p[j] == ' ' || p[j] == '\\') arg_len++;
        }

        /* adding 2 for the space separator ' ' and the '\0' terminator */
        if (n + arg_len + 2 > SANLK_HELPER_ARGS_LEN) {
            __set_exception(EINVAL, "Killpath arguments are too long");
            return NULL;
        }

        /* adding the space separator between arguments */
        if (n > 0) {
            kpargs[n++] = ' ';
        }

        while (*p) {
            if (*p == ' ' || *p == '\\') {
                kpargs[n++] = '\\';
            }

            kpargs[n++] = *p++;
        }
    }

    /* configure killpath (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_killpath(sanlockfd, 0, path, kpargs);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Killpath script not configured");
        return NULL;
    }

    Py_RETURN_NONE;
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
    {"write_lockspace", (PyCFunction) py_write_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_write_lockspace},
    {"write_resource", (PyCFunction) py_write_resource,
                        METH_VARARGS|METH_KEYWORDS, pydoc_write_resource},
    {"add_lockspace", (PyCFunction) py_add_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_add_lockspace},
    {"inq_lockspace", (PyCFunction) py_inq_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_inq_lockspace},
    {"rem_lockspace", (PyCFunction) py_rem_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_rem_lockspace},
    {"acquire", (PyCFunction) py_acquire,
                METH_VARARGS|METH_KEYWORDS, pydoc_acquire},
    {"release", (PyCFunction) py_release,
                METH_VARARGS|METH_KEYWORDS, pydoc_release},
    {"killpath", (PyCFunction) py_killpath,
                METH_VARARGS|METH_KEYWORDS, pydoc_killpath},
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
