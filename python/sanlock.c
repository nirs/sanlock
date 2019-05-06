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

#ifdef WITH_CPYCHECKER_SETS_EXCEPTION_ATTRIBUTE
#define __sets_exception \
    __attribute__((cpychecker_sets_exception))
#else
#define __sets_exception
#endif

#ifdef WITH_CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION_ATTRIBUTE
#define __neg_sets_exception \
    __attribute__((cpychecker_negative_result_sets_exception))
#else
#define __neg_sets_exception
#endif

#define MODULE_NAME "sanlock"

/* Functions prototypes */
static void __set_exception(int en, char *msg) __sets_exception;
static int __parse_resource(PyObject *obj, struct sanlk_resource **res_ret) __neg_sets_exception;

/* Sanlock module */
PyDoc_STRVAR(pydoc_sanlock, "\
Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.\n\
This copyrighted material is made available to anyone wishing to use,\n\
modify, copy, or redistribute it subject to the terms and conditions\n\
of the GNU General Public License v2 or (at your option) any later version.");

/* Sanlock exception */
static PyObject *py_exception;

/*
    Python 2 forward compatibility functions with Python 3
    TODO: Once Python 2 will reach EOL at 2020 discrad this section
*/
#if PY_MAJOR_VERSION == 2

static const char*
PyUnicode_AsUTF8(PyObject* obj)
{
    return PyString_AsString(obj);
}

#endif

static void
__set_exception(int en, char *msg)
{
    const char *err_name;
    PyObject *exc_tuple;

    if (en < 0 && en > -200) {
        en = -en;
        err_name = strerror(en);
    } else {
        /* Safe to call without releasing the GIL. */
        err_name = sanlock_strerror(en);
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
        const char *p = NULL;
        PyObject *tuple, *path = NULL, *offset = NULL;
        int offset_is_int = 0;

        tuple = PyList_GetItem(obj, i);

        if (PyTuple_Check(tuple)) {
            if (PyTuple_Size(tuple) != 2) {
                __set_exception(EINVAL, "Invalid resource tuple");
                goto exit_fail;
            }

            path = PyTuple_GetItem(tuple, 0);
            offset = PyTuple_GetItem(tuple, 1);

            p = PyUnicode_AsUTF8(path);

#if PY_MAJOR_VERSION == 2
            offset_is_int = PyInt_Check(offset) || PyLong_Check(offset);
#else
            offset_is_int = PyLong_Check(offset);
#endif

            if (!offset_is_int) {
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
            res->disks[i].offset = PyLong_AsLong(offset);
        }
    }

    *res_ret = res;
    return 0;

exit_fail:
    free(res);
    return -1;
}

enum {SECTOR_SIZE_512 = 512, SECTOR_SIZE_4K = 4096};

static int
add_sector_flag(int sector, uint32_t *flags)
{
    switch (sector) {
    case SECTOR_SIZE_512:
        *flags |= SANLK_LSF_SECTOR512;
	break;
    case SECTOR_SIZE_4K:
        *flags |= SANLK_LSF_SECTOR4K;
	break;
    default:
	PyErr_Format(PyExc_ValueError, "Invalid sector value: %d", sector);
	return -1;
    }
    return 0;
}

enum {
    ALIGNMENT_1M = 1048576,
    ALIGNMENT_2M = 2097152,
    ALIGNMENT_4M = 4194304,
    ALIGNMENT_8M = 8388608
};

static int
add_align_flag(long align, uint32_t *flags)
{
    switch (align) {
    case ALIGNMENT_1M:
        *flags |= SANLK_RES_ALIGN1M;
	break;
    case ALIGNMENT_2M:
        *flags |= SANLK_RES_ALIGN2M;
	break;
    case ALIGNMENT_4M:
        *flags |= SANLK_RES_ALIGN4M;
	break;
    case ALIGNMENT_8M:
        *flags |= SANLK_RES_ALIGN8M;
	break;
    default:
	PyErr_Format(PyExc_ValueError, "Invalid align value: %ld", align);
	return -1;
    }
    return 0;
}

static PyObject *
__hosts_to_list(struct sanlk_host *hss, int hss_count)
{
    int i, rv;
    PyObject *ls_list = NULL, *ls_entry = NULL, *ls_value = NULL;

    /* prepare the dictionary holding the information */
    if ((ls_list = PyList_New(0)) == NULL)
        goto exit_fail;

    for (i = 0; i < hss_count; i++) {
        if ((ls_entry = PyDict_New()) == NULL)
            goto exit_fail;

        /* fill the dictionary information: host_id */
        if ((ls_value = PyLong_FromLong(hss[i].host_id)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "host_id", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: generation */
        if ((ls_value = PyLong_FromLong(hss[i].generation)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "generation", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: timestamp */
        if ((ls_value = PyLong_FromLong(hss[i].timestamp)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "timestamp", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: io_timeout */
        if ((ls_value = PyLong_FromLong(hss[i].io_timeout)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "io_timeout", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: flags */
        if ((ls_value = PyLong_FromLong(hss[i].flags)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "flags", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        if (PyList_Append(ls_list, ls_entry) != 0)
            goto exit_fail;

        Py_DECREF(ls_entry);
    }

    return ls_list;

    /* failure */
exit_fail:
    Py_XDECREF(ls_entry);
    Py_XDECREF(ls_list);
    return NULL;
}

/* register */
PyDoc_STRVAR(pydoc_register, "\
register() -> int\n\
Register to sanlock daemon and return the connection fd.");

static PyObject *
py_register(PyObject *self __unused, PyObject *args)
{
    int sanlockfd;

    /* This sholdn't block, but we don't want to take any chance, as blocking
     * hangs all threads in the caller process. */
    Py_BEGIN_ALLOW_THREADS
    sanlockfd = sanlock_register();
    Py_END_ALLOW_THREADS

    if (sanlockfd < 0) {
        __set_exception(sanlockfd, "Sanlock registration failed");
        return NULL;
    }

    return PyLong_FromLong(sanlockfd);
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

    return PyLong_FromLong(rv);
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
    if (__parse_resource(disks, &res) < 0) {
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
write_lockspace(lockspace, path, offset=0, max_hosts=0, iotimeout=0, \
align=1048576, sector=512)\n\
Initialize or update a device to be used as sanlock lockspace.\n\
Align can be one of (1048576, 2097152, 4194304, 8388608).\n\
Sector can be one of (512, 4096).");

static PyObject *
py_write_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, sector = SECTOR_SIZE_512;
    long align = ALIGNMENT_1M;
    uint32_t io_timeout = 0;
    const char *lockspace, *path;
    struct sanlk_lockspace ls;

    static char *kwlist[] = {"lockspace", "path", "offset", "max_hosts",
                                "iotimeout", "align", "sector", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss|kiIli", kwlist,
        &lockspace, &path, &ls.host_id_disk.offset, &max_hosts,
        &io_timeout, &align, &sector)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.name, lockspace, SANLK_NAME_LEN);
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* set alignment/sector flags */
    if (add_align_flag(align, &ls.flags) == -1)
        return NULL;

    if (add_sector_flag(sector, &ls.flags) == -1)
        return NULL;

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

/* read_lockspace */
PyDoc_STRVAR(pydoc_read_lockspace, "\
read_lockspace(path, offset=0, align=1048576, sector=512)\n -> dict\n\
Read the lockspace information from a device at a specific offset.\n\
Align can be one of (1048576, 2097152, 4194304, 8388608).\n\
Sector can be one of (512, 4096).");

static PyObject *
py_read_lockspace(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, sector = SECTOR_SIZE_512;
    long align = ALIGNMENT_1M;
    uint32_t io_timeout = 0;
    const char *path;
    struct sanlk_lockspace ls;
    PyObject *ls_info = NULL, *ls_entry = NULL;

    static char *kwlist[] = {"path", "offset", "align", "sector", NULL};

    /* initialize lockspace structure */
    memset(&ls, 0, sizeof(struct sanlk_lockspace));

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|kli", kwlist,
        &path, &ls.host_id_disk.offset, &align, &sector)) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(ls.host_id_disk.path, path, SANLK_PATH_LEN - 1);

    /* set alignment/sector flags */
    if (add_align_flag(align, &ls.flags) == -1)
        return NULL;

    if (add_sector_flag(sector, &ls.flags) == -1)
        return NULL;

    /* read sanlock lockspace (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_read_lockspace(&ls, 0, &io_timeout);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock lockspace read failure");
        return NULL;
    }

    /* prepare the dictionary holding the information */
    if ((ls_info = PyDict_New()) == NULL)
        goto exit_fail;

    /* fill the dictionary information: lockspace */
    if ((ls_entry = PyBytes_FromString(ls.name)) == NULL)
        goto exit_fail;
    rv = PyDict_SetItemString(ls_info, "lockspace", ls_entry);
    Py_DECREF(ls_entry);
    if (rv != 0)
        goto exit_fail;

    /* fill the dictionary information: iotimeout */
    if ((ls_entry = PyLong_FromLong(io_timeout)) == NULL)
        goto exit_fail;
    rv = PyDict_SetItemString(ls_info, "iotimeout", ls_entry);
    Py_DECREF(ls_entry);
    if (rv != 0)
        goto exit_fail;

    /* success */
    return ls_info;

    /* failure */
exit_fail:
    Py_XDECREF(ls_info);
    return NULL;
}

/* read_resource */
PyDoc_STRVAR(pydoc_read_resource, "\
read_resource(path, offset=0, align=1048576, sector=512) -> dict\n\
Read the resource information from a device at a specific offset.\n\
Align can be one of (1048576, 2097152, 4194304, 8388608).\n\
Sector can be one of (512, 4096).");

static PyObject *
py_read_resource(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, rs_len, sector = SECTOR_SIZE_512;
    long align = ALIGNMENT_1M;
    const char *path;
    struct sanlk_resource *rs;
    PyObject *rs_info = NULL, *rs_entry = NULL;

    static char *kwlist[] = {"path", "offset", "align", "sector", NULL};

    /* allocate the needed memory for the resource and one disk */
    rs_len = sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk);
    rs = malloc(rs_len);

    if (rs == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    /* initialize resource and disk structures */
    memset(rs, 0, rs_len);
    rs->num_disks = 1;

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|kli", kwlist,
        &path, &(rs->disks[0].offset), &align, &sector)) {
        goto exit_fail;
    }

    /* prepare the resource disk path */
    strncpy(rs->disks[0].path, path, SANLK_PATH_LEN - 1);

    /* set alignment/sector flags */
    if (add_align_flag(align, &rs->flags) == -1)
        goto exit_fail;

    if (add_sector_flag(sector, &rs->flags) == -1)
        goto exit_fail;

    /* read sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_read_resource(rs, 0);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock resource read failure");
        goto exit_fail;
    }

    /* prepare the dictionary holding the information */
    if ((rs_info = PyDict_New()) == NULL)
        goto exit_fail;

    /* fill the dictionary information: lockspace */
    if ((rs_entry = PyBytes_FromString(rs->lockspace_name)) == NULL)
        goto exit_fail;
    rv = PyDict_SetItemString(rs_info, "lockspace", rs_entry);
    Py_DECREF(rs_entry);
    if (rv != 0)
        goto exit_fail;

    /* fill the dictionary information: resource */
    if ((rs_entry = PyBytes_FromString(rs->name)) == NULL)
        goto exit_fail;
    rv = PyDict_SetItemString(rs_info, "resource", rs_entry);
    Py_DECREF(rs_entry);
    if (rv != 0)
        goto exit_fail;

    /* fill the dictionary information: version */
    if ((rs_entry = PyLong_FromUnsignedLong(rs->lver)) == NULL)
        goto exit_fail;
    rv = PyDict_SetItemString(rs_info, "version", rs_entry);
    Py_DECREF(rs_entry);
    if (rv != 0)
        goto exit_fail;

    /* success */
    free(rs);
    return rs_info;

    /* failure */
exit_fail:
    free(rs);
    Py_XDECREF(rs_info);
    return NULL;
}

/* write_resource */
PyDoc_STRVAR(pydoc_write_resource, "\
write_resource(lockspace, resource, disks, max_hosts=0, num_hosts=0, \
clear=False, align=1048576, sector=512)\n\
Initialize a device to be used as sanlock resource.\n\
The disks must be in the format: [(path, offset), ... ].\n\
If clear is True, the resource is cleared so subsequent read will\n\
return an error.\n\
Align can be one of (1048576, 2097152, 4194304, 8388608).\n\
Sector can be one of (512, 4096).");

static PyObject *
py_write_resource(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, max_hosts = 0, num_hosts = 0, clear = 0, sector = SECTOR_SIZE_512;
    long align = ALIGNMENT_1M;
    const char *lockspace, *resource;
    struct sanlk_resource *rs;
    PyObject *disks;
    uint32_t flags = 0;

    static char *kwlist[] = {"lockspace", "resource", "disks", "max_hosts",
                                "num_hosts", "clear", "align", "sector", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iiili",
        kwlist, &lockspace, &resource, &PyList_Type, &disks, &max_hosts,
        &num_hosts, &clear, &align, &sector)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &rs) < 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(rs->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(rs->name, resource, SANLK_NAME_LEN);

    /* set alignment/sector flags */
    if (add_align_flag(align, &rs->flags) == -1)
        goto exit_fail;

    if (add_sector_flag(sector, &rs->flags) == -1)
        goto exit_fail;

    if (clear) {
        flags |= SANLK_WRITE_CLEAR;
    }

    /* init sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_write_resource(rs, max_hosts, num_hosts, flags);
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
at least one acquired resource in the lockspace. Otherwise (the default)\n\
sanlock will try to terminate processes holding resource leases and upon\n\
successful termination these leases will be released.");

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

/* get_lockspaces */
PyDoc_STRVAR(pydoc_get_lockspaces, "\
get_lockspaces() -> list\n\
Return the list of lockspaces currently managed by sanlock. The reported\n\
flag indicates whether the lockspace is acquired (0) or in transition.\n\
The possible transition values are LSFLAG_ADD if the lockspace is in the\n\
process of being acquired, and LSFLAG_REM if it's in the process of being\n\
released.\n");

static PyObject *
py_get_lockspaces(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, i, lss_count;
    struct sanlk_lockspace *lss = NULL;
    PyObject *ls_list = NULL, *ls_entry = NULL, *ls_value = NULL;

    /* get all the lockspaces (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_get_lockspaces(&lss, &lss_count, 0);
    Py_END_ALLOW_THREADS

    if (rv < 0) {
        __set_exception(rv, "Sanlock get lockspaces failure");
        goto exit_fail;
    }

    /* prepare the dictionary holding the information */
    if ((ls_list = PyList_New(0)) == NULL)
        goto exit_fail;

    for (i = 0; i < lss_count; i++) {
        if ((ls_entry = PyDict_New()) == NULL)
            goto exit_fail;

        /* fill the dictionary information: lockspace */
        if ((ls_value = PyBytes_FromString(lss[i].name)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "lockspace", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: host_id */
        if ((ls_value = PyLong_FromLong(lss[i].host_id)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "host_id", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: path */
        if ((ls_value = PyUnicode_FromString(lss[i].host_id_disk.path)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "path", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: offset */
        if ((ls_value = PyLong_FromLong(lss[i].host_id_disk.offset)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "offset", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        /* fill the dictionary information: flags */
        if ((ls_value = PyLong_FromLong(lss[i].flags)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(ls_entry, "flags", ls_value);
        Py_DECREF(ls_value);
        if (rv != 0)
            goto exit_fail;

        if (PyList_Append(ls_list, ls_entry) != 0)
            goto exit_fail;

        Py_DECREF(ls_entry);
    }

    /* success */
    free(lss);
    return ls_list;

    /* failure */
exit_fail:
    if (lss) free(lss);
    Py_XDECREF(ls_entry);
    Py_XDECREF(ls_list);
    return NULL;
}

/* get_hosts */
PyDoc_STRVAR(pydoc_get_hosts, "\
get_hosts(lockspace, host_id=0) -> list\n\
Return the list of hosts currently alive in a lockspace. When the host_id\n\
is specified then only the requested host status is returned. The reported\n\
flag indicates whether the host is free (HOST_FREE), alive (HOST_LIVE),\n\
failing (HOST_FAIL), dead (HOST_DEAD) or unknown (HOST_UNKNOWN).\n\
The unknown state is the default when sanlock just joined the lockspace\n\
and didn't collect enough information to determine the real status of other\n\
hosts. The dictionary returned also contains: the generation, the last\n\
timestamp and the io_timeout.\n");

static PyObject *
py_get_hosts(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, hss_count = 0;
    uint64_t host_id = 0;
    const char *lockspace = NULL;
    struct sanlk_host *hss = NULL;
    PyObject *ls_list = NULL;

    static char *kwlist[] = {"lockspace", "host_id", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|k", kwlist,
        &lockspace, &host_id)) {
        return NULL;
    }

    /* get all the lockspaces (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_get_hosts(lockspace, host_id, &hss, &hss_count, 0);
    Py_END_ALLOW_THREADS

    if (rv < 0) {
        __set_exception(rv, "Sanlock get hosts failure");
        goto exit_fail;
    }

    ls_list = __hosts_to_list(hss, hss_count);

exit_fail:
    if (hss) free(hss);
    return ls_list;
}

/* acquire */
PyDoc_STRVAR(pydoc_acquire, "\
acquire(lockspace, resource, disks \
[, slkfd=fd, pid=owner, shared=False, version=None])\n\
Acquire a resource lease for the current process (using the slkfd argument\n\
to specify the sanlock file descriptor) or for an other process (using the\n\
pid argument). If shared is True the resource will be acquired in the shared\n\
mode. The version is the version of the lease that must be acquired or fail.\n\
The disks must be in the format: [(path, offset), ... ]\n");

static PyObject *
py_acquire(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, sanlockfd = -1, pid = -1, shared = 0;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks, *version = Py_None;

    static char *kwlist[] = {"lockspace", "resource", "disks", "slkfd",
                                "pid", "shared", "version", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iiiO", kwlist,
        &lockspace, &resource, &PyList_Type, &disks, &sanlockfd, &pid,
        &shared, &version)) {
        return NULL;
    }

    /* check if any of the slkfd or pid parameters was given */
    if (sanlockfd == -1 && pid == -1) {
        __set_exception(EINVAL, "Invalid slkfd and pid values");
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) < 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* prepare sanlock flags */
    if (shared) {
        res->flags |= SANLK_RES_SHARED;
    }

    /* prepare the resource version */
    if (version != Py_None) {
        res->flags |= SANLK_RES_LVER;
        res->lver = PyLong_AsUnsignedLongMask(version);
        if (res->lver == -1) {
            __set_exception(EINVAL, "Unable to convert the version value");
            goto exit_fail;
        }
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
    if (__parse_resource(disks, &res) < 0) {
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

/* request */
PyDoc_STRVAR(pydoc_request, "\
request(lockspace, resource, disks [, action=REQ_GRACEFUL, version=None])\n\
Request the owner of a resource to do something specified by action.\n\
The possible values for action are: REQ_GRACEFUL to request a graceful\n\
release of the resource and REQ_FORCE to sigkill the owner of the\n\
resource (forcible release). The version should be either the next version\n\
to acquire or None (which automatically uses the next version).\n\
The disks must be in the format: [(path, offset), ... ]");

static PyObject *
py_request(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, action = SANLK_REQ_GRACEFUL, flags = 0;
    const char *lockspace, *resource;
    struct sanlk_resource *res;
    PyObject *disks, *version = Py_None;

    static char *kwlist[] = {"lockspace", "resource", "disks", "action",
                                "version", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!|iO", kwlist,
        &lockspace, &resource, &PyList_Type, &disks, &action, &version)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) < 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* prepare the resource version */
    if (version == Py_None) {
        flags = SANLK_REQUEST_NEXT_LVER;
    } else {
        res->flags |= SANLK_RES_LVER;
        res->lver = PyLong_AsUnsignedLongMask(version);
        if (res->lver == -1) {
            __set_exception(EINVAL, "Unable to convert the version value");
            goto exit_fail;
        }
    }

    /* request sanlock resource (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_request(flags, action, res);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Sanlock request not submitted");
        goto exit_fail;
    }

    free(res);
    Py_RETURN_NONE;

exit_fail:
    free(res);
    return NULL;
}

/* read_resource_owners */
PyDoc_STRVAR(pydoc_read_resource_owners, "\
read_resource_owners(lockspace, resource, disks) -> list\n\
Returns the list of hosts owning a resource, the list is not filtered and\n\
it might contain hosts that are currently failing or dead. The hosts are\n\
returned in the same format used by get_hosts.\n\
The disks must be in the format: [(path, offset), ... ]");

static PyObject *
py_read_resource_owners(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    int rv, hss_count = 0;
    const char *lockspace, *resource;
    struct sanlk_resource *res = NULL;
    struct sanlk_host *hss = NULL;
    PyObject *disks, *ls_list = NULL;

    static char *kwlist[] = {"lockspace", "resource", "disks", NULL};

    /* parse python tuple */
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ssO!", kwlist,
        &lockspace, &resource, &PyList_Type, &disks)) {
        return NULL;
    }

    /* parse and check sanlock resource */
    if (__parse_resource(disks, &res) < 0) {
        return NULL;
    }

    /* prepare sanlock names */
    strncpy(res->lockspace_name, lockspace, SANLK_NAME_LEN);
    strncpy(res->name, resource, SANLK_NAME_LEN);

    /* read resource owners (gil disabled) */
    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_read_resource_owners(res, 0, &hss, &hss_count);
    Py_END_ALLOW_THREADS

    if (rv != 0) {
        __set_exception(rv, "Unable to read resource owners");
        goto exit_fail;
    }

    ls_list = __hosts_to_list(hss, hss_count);

exit_fail:
    if (res) free(res);
    if (hss) free(hss);
    return ls_list;
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
    char kpargs[SANLK_HELPER_ARGS_LEN];
    const char *p, *path;
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
        p = PyUnicode_AsUTF8(item);

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

/* reg_event */
PyDoc_STRVAR(pydoc_reg_event, "\
reg_event(lockspace) -> int\n\
Register an event listener for lockspace and return an open file descriptor\n\
for waiting for lockspace events. When the file descriptor becomes readable,\n\
you can use get_event to get pending events. When you are done, you must\n\
unregister the event listener using end_event.");

static PyObject *
py_reg_event(PyObject *self __unused, PyObject *args)
{
    const char *lockspace = NULL;
    int fd = -1;

    if (!PyArg_ParseTuple(args, "s", &lockspace))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    fd = sanlock_reg_event(lockspace, NULL /* event */, 0 /* flags */);
    Py_END_ALLOW_THREADS

    if (fd < 0) {
        __set_exception(fd, "Unable to register event fd");
        return NULL;
    }

    return Py_BuildValue("i", fd);
}

/* get_event */
PyDoc_STRVAR(pydoc_get_event, "\
get_event(fd) -> list\n\
Get list of lockspace events.\n\
\n\
Each event is a dictionary with the following keys:\n\
  from_host_id      host id of the host setting this event (int)\n\
  from_generation   host generation of the host setting this event (int)\n\
  host_id           my host id (int)\n\
  generation        my generation where the event was set (int)\n\
  event             event number (int)\n\
  data              optional event data (int)\n\
");

static PyObject *
py_get_event(PyObject *self __unused, PyObject *args)
{
    int fd = -1;
    struct sanlk_host_event he;
    uint64_t from_host_id;
    uint64_t from_generation;
    PyObject *events = NULL;
    PyObject *item = NULL;
    PyObject *value = NULL;
    int rv;

    if (!PyArg_ParseTuple(args, "i", &fd))
        return NULL;

    if ((events = PyList_New(0)) == NULL)
        goto exit_fail;

    for (;;) {
        Py_BEGIN_ALLOW_THREADS
        rv = sanlock_get_event(fd, 0, &he, &from_host_id, &from_generation);
        Py_END_ALLOW_THREADS

        if (rv == -EAGAIN)
            break;

        if (rv != 0) {
            __set_exception(rv, "Unable to get events");
            goto exit_fail;
        }

        if ((item = PyDict_New()) == NULL)
            goto exit_fail;

        /* from_host_id */
        if ((value = PyLong_FromUnsignedLongLong(from_host_id)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "from_host_id", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        /* from_generation */
        if ((value = PyLong_FromUnsignedLongLong(from_generation)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "from_generation", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        /* host_id */
        if ((value = PyLong_FromUnsignedLongLong(he.host_id)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "host_id", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        /* generation */
        if ((value = PyLong_FromUnsignedLongLong(he.generation)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "generation", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        /* event */
        if ((value = PyLong_FromUnsignedLongLong(he.event)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "event", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        /* data */
        if ((value = PyLong_FromUnsignedLongLong(he.data)) == NULL)
            goto exit_fail;
        rv = PyDict_SetItemString(item, "data", value);
        Py_DECREF(value);
        if (rv != 0)
            goto exit_fail;

        if (PyList_Append(events, item) != 0)
            goto exit_fail;

        Py_DECREF(item);
        item = NULL;
    }

    return events;

exit_fail:
    Py_XDECREF(item);
    Py_XDECREF(events);
    return NULL;
}

/* end_event */
PyDoc_STRVAR(pydoc_end_event, "\
end_event(fd, lockspace)\n\
Unregister an event listener for lockspace registered with reg_event.");

static PyObject *
py_end_event(PyObject *self __unused, PyObject *args)
{
    int fd = -1;
    const char *lockspace = NULL;
    int rv;

    if (!PyArg_ParseTuple(args, "is", &fd, &lockspace))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_end_event(fd, lockspace, 0 /* flags */);
    Py_END_ALLOW_THREADS

    if (rv < 0) {
        __set_exception(rv, "Unable to unregister event fd");
        return NULL;
    }

    Py_RETURN_NONE;
}

/* set_event */
PyDoc_STRVAR(pydoc_set_event, "\
set_event(lockspace, host_id, generation, event, data=0, flags=0)\n\
Set events to hosts on a lockspace.\n\
\n\
Arguments\n\
  lockspace         lockspace name (str)\n\
  host_id           recipient host_id (int)\n\
  generation        recipient generation (int)\n\
  event             event number (int)\n\
  data              optional event data (int)\n\
  flags             optional combination of event flags (int)\n\
\n\
Flags\n\
  SETEV_CUR_GENERATION      if generation is zero, use current host\n\
                            generation.\n\
  SETEV_CLEAR_HOSTID        clear the host_id in the next renewal so host_id\n\
                            will stop seeing this event. If the same event\n\
                            was sent to other hosts, they will continue to\n\
                            see the event until the event is cleared.\n\
  SETEV_CLEAR_EVENT         Clear the event/data/generation values in the\n\
                            next renewal, ending this event.\n\
  SETEV_REPLACE_EVENT       Replace the existing event/data values of the\n\
                            current event. Without this flag, the operation\n\
                            will raise SanlockException with -EBUSY error.\n\
  SETEV_ALL_HOSTS           set event for all hosts.\n\
\n\
Examples\n\
\n\
  Send event 1 to host 42 on lockspace 'foo', using current host generation:\n\
  set_event('foo', 42, 0, 1, flags=SETEV_CUR_GENERATION)\n\
\n\
  Send the same event also to host 7 on lockspace 'foo', using current host\n\
  generation. Both host 42 and host 7 will see the same event:\n\
  set_event('foo', 7, 0, 1, flags=SETEV_CUR_GENERATION)\n\
\n\
  Send event 3 to all hosts on lockspace 'foo', replacing previous events\n\
  sent to other hosts. Note that you must use a valid host_id, but the\n\
  generation is ignored:\n\
  set_event('foo', 1, 0, 3, flags=SETEV_ALL_HOSTS|SETEV_REPLACE_EVENT)\n\
\n\
Notes\n\
\n\
Sequential set_events with different event/data values, within a short\n\
time span is likely to produce unwanted results, because the new\n\
event/data values replace the previous values before the previous values\n\
have been read.\n\
\n\
Unless SETEV_REPLACE_EVENT flag is used, sanlock will raise SanlockException\n\
with -EBUSY error in this case.\n\
");

static PyObject *
py_set_event(PyObject *self __unused, PyObject *args, PyObject *keywds)
{
    const char *lockspace;
    struct sanlk_host_event he = {0};
    uint32_t flags = 0;
    int rv;

    static char *kwlist[] = {"lockspace", "host_id", "generation", "event",
                             "data", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sKKK|KI", kwlist,
        &lockspace, &he.host_id, &he.generation, &he.event, &he.data,
        &flags)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    rv = sanlock_set_event(lockspace, &he, flags);
    Py_END_ALLOW_THREADS

    if (rv < 0) {
        __set_exception(rv, "Unable to set event");
        return NULL;
    }

    Py_RETURN_NONE;
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
    {"read_lockspace", (PyCFunction) py_read_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_read_lockspace},
    {"read_resource", (PyCFunction) py_read_resource,
                        METH_VARARGS|METH_KEYWORDS, pydoc_read_resource},
    {"add_lockspace", (PyCFunction) py_add_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_add_lockspace},
    {"inq_lockspace", (PyCFunction) py_inq_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_inq_lockspace},
    {"rem_lockspace", (PyCFunction) py_rem_lockspace,
                        METH_VARARGS|METH_KEYWORDS, pydoc_rem_lockspace},
    {"get_lockspaces", (PyCFunction) py_get_lockspaces,
                        METH_VARARGS|METH_KEYWORDS, pydoc_get_lockspaces},
    {"get_hosts", (PyCFunction) py_get_hosts,
                        METH_VARARGS|METH_KEYWORDS, pydoc_get_hosts},
    {"read_resource_owners", (PyCFunction) py_read_resource_owners,
                METH_VARARGS|METH_KEYWORDS, pydoc_read_resource_owners},
    {"acquire", (PyCFunction) py_acquire,
                METH_VARARGS|METH_KEYWORDS, pydoc_acquire},
    {"release", (PyCFunction) py_release,
                METH_VARARGS|METH_KEYWORDS, pydoc_release},
    {"request", (PyCFunction) py_request,
                METH_VARARGS|METH_KEYWORDS, pydoc_request},
    {"killpath", (PyCFunction) py_killpath,
                METH_VARARGS|METH_KEYWORDS, pydoc_killpath},
    {"reg_event", (PyCFunction) py_reg_event, METH_VARARGS, pydoc_reg_event},
    {"get_event", (PyCFunction) py_get_event, METH_VARARGS, pydoc_get_event},
    {"end_event", (PyCFunction) py_end_event, METH_VARARGS, pydoc_end_event},
    {"set_event", (PyCFunction) py_set_event,
                METH_VARARGS|METH_KEYWORDS, pydoc_set_event},
    {NULL, NULL, 0, NULL}
};

static PyMethodDef
sanlock_exception = {
    "errno", (PyCFunction) py_exception_errno, METH_O, pydoc_errno
};

static PyObject *
initexception(void)
{
    int rv;
    PyObject *dict, *func, *meth, *excp = NULL;

    if ((dict = PyDict_New()) == NULL)
        goto exit_fail;

    if ((func = PyCFunction_New(&sanlock_exception, NULL)) == NULL)
        goto exit_fail;

    meth = PyObject_CallFunction((PyObject *) &PyProperty_Type, "O", func);
    Py_DECREF(func);
    if (meth == NULL)
        goto exit_fail;

    rv = PyDict_SetItemString(dict, sanlock_exception.ml_name, meth);
    Py_DECREF(meth);
    if (rv < 0)
        goto exit_fail;

    excp = PyErr_NewException("sanlock.SanlockException", NULL, dict);

exit_fail:
    Py_XDECREF(dict);

    return excp;
}

static int
util_module_init(PyObject* m)
{
	PyObject *align = NULL, *sector = NULL;

    if (py_exception == NULL) {
        py_exception = initexception();
        if (py_exception == NULL)
			goto exit_fail;
    }

    Py_INCREF(py_exception);
    if (PyModule_AddObject(m, "SanlockException", py_exception))
		goto exit_fail;

    /* lockspaces list flags */
    if (PyModule_AddIntConstant(m, "LSFLAG_ADD", SANLK_LSF_ADD))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "LSFLAG_REM", SANLK_LSF_REM))
		goto exit_fail;

    /* resource request flags */
    if (PyModule_AddIntConstant(m, "REQ_FORCE", SANLK_REQ_FORCE))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "REQ_GRACEFUL", SANLK_REQ_GRACEFUL))
		goto exit_fail;

    /* hosts list flags */
    if (PyModule_AddIntConstant(m, "HOST_FREE", SANLK_HOST_FREE))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "HOST_LIVE", SANLK_HOST_LIVE))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "HOST_FAIL", SANLK_HOST_FAIL))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "HOST_DEAD", SANLK_HOST_DEAD))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "HOST_UNKNOWN", SANLK_HOST_UNKNOWN))
		goto exit_fail;

    /* set event flags */
    if (PyModule_AddIntConstant(m, "SETEV_CUR_GENERATION", SANLK_SETEV_CUR_GENERATION))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "SETEV_CLEAR_HOSTID", SANLK_SETEV_CLEAR_HOSTID))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "SETEV_CLEAR_EVENT", SANLK_SETEV_CLEAR_EVENT))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "SETEV_REPLACE_EVENT", SANLK_SETEV_REPLACE_EVENT))
		goto exit_fail;
    if (PyModule_AddIntConstant(m, "SETEV_ALL_HOSTS", SANLK_SETEV_ALL_HOSTS))
		goto exit_fail;

    /* Tuples with supported sector size and alignment values */
    sector = Py_BuildValue("ii", SECTOR_SIZE_512, SECTOR_SIZE_4K);
    if (!sector || PyModule_AddObject(m, "SECTOR_SIZE", sector))
		goto exit_fail;

    align = Py_BuildValue("llll",
                        ALIGNMENT_1M, ALIGNMENT_2M, ALIGNMENT_4M, ALIGNMENT_8M);
    if (!align || PyModule_AddObject(m, "ALIGN_SIZE", align))
		goto exit_fail;

	return 0;

exit_fail:
	Py_XDECREF(py_exception);
	Py_XDECREF(sector);
	Py_XDECREF(align);
	return -1;
}

#if PY_MAJOR_VERSION >= 3 /* Python 3 module init */

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE_NAME,
        pydoc_sanlock,
        -1,
        sanlock_methods,
};

PyMODINIT_FUNC
PyInit_sanlock(void)
{
    PyObject *m = NULL;

    m = PyModule_Create(&moduledef);

    if (m == NULL)
        return NULL;

    if (util_module_init(m)) {
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

#else /* Python 2 module init */

PyMODINIT_FUNC
initsanlock(void)
{
    PyObject *m = NULL;

    m = Py_InitModule4(MODULE_NAME,
                sanlock_methods, pydoc_sanlock, NULL, PYTHON_API_VERSION);

    if (m == NULL)
        return;

    if (util_module_init(m))
        Py_DECREF(m);
}

#endif
