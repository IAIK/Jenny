#include "sf_internal.h"
#include "pk.h"
#include "common_seccomp.h"
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/seccomp.h>
#include "pk_internal.h"


/**
 *
 * WARNING:
 * Seccomp_user cannot filter syscalls, but can only emulate them.
 * This means all "filtered" and "allowed" syscalls are actually
 * executed in the context of the tracer, which is the monitor!
 * 
 * Retrieves current_did and filter_syscalls from TTLS.
 * However, TTLS might not be initialized. We can assume,
 * that in this state, a thread is in monitor mode, i.e.,
 * all syscalls are allowed. 
 *
 */

FORCE_INLINE bool _filter_syscalls_sameprocess(_pk_tls *tls)
{
    if (tls != NULL && tls->filter_syscalls) {
        return true;
    }
    return false;
}

FORCE_INLINE _pk_tls *_get_tls_by_pid(pid_t tracee)
{
    for (size_t tix = 0; tix < NUM_THREADS; tix++) {
        _pk_tls *t = pk_data.threads[tix];
        if (t != THREAD_UNUSED && t != THREAD_EXITING && t->init && t->gettid == tracee) {
            return t;
        }
    }
    return NULL;
}

#define DEBUG_SYSCALL(format, data) \
    DEBUG_SF(format, \
        sysno_to_str(data->nr), data->args[0], data->args[1], \
        data->args[2], data->args[3], data->args[4], \
        data->args[5]);

static void PK_CODE _handle_req_sameprocess(struct seccomp_notif *req,
        struct seccomp_notif_resp *resp, int _listener)
{
    resp->id = req->id;
    resp->error = 0;

    struct seccomp_data *data = &req->data;

    assert(data->nr >= 0 && data->nr < NUM_DOMAIN_FILTERS);
    sysent_t *sysent = &sf_table[data->nr];
    if (sysent->filter == SYSCALL_DENIED) {
        ERROR("denying %s(%llu, %llu, %llu, %llu, %llu, %llu)",
                sysno_to_str(data->nr), data->args[0], data->args[1],
                data->args[2], data->args[3], data->args[4],
                data->args[5]);
        resp->error = -EPERM;
    }
    else if (sysent->filter == SYSCALL_ALLOWED) {
        // emulating syscall in tracer (can not execute in tracee)
        DEBUG_SYSCALL("allowing %s(%llu, %llu, %llu, %llu, %llu, %llu)", data);
        resp->val = syscall(data->nr, data->args[0], data->args[1],
                data->args[2], data->args[3], data->args[4],
                data->args[5]);
    }
    else {
        _pk_tls *tls = _get_tls_by_pid(req->pid);
        if (!_filter_syscalls_sameprocess(tls)) {
            DEBUG_SYSCALL("allowing %s(%llu, %llu, %llu, %llu, %llu, %llu) in monitor", data);
            resp->val = syscall(data->nr, data->args[0], data->args[1],
                data->args[2], data->args[3], data->args[4],
                data->args[5]);
            return;
        }

        DEBUG_SYSCALL("emulating %s(%llu, %llu, %llu, %llu, %llu, %llu)", data);
        int did = tls->current_did;
        _pk_thread_domain* filteree_thread_domain = _pk_get_thread_domain_data_tls_nodidcheck(did, tls);
        trace_info_t ti = { .syscall_nr = data->nr,
            .args = {(long)data->args[0], (long)data->args[1], (long)data->args[2], (long)data->args[3], (long)data->args[4], (long)data->args[5]},
            .did = did, .mem = filteree_thread_domain->syscall.filter_mem };

        if (sysent->filter == SYSCALL_UNSPECIFIED) {
            ERROR_FAIL("unhandled syscall %3ld '%s'", ti.syscall_nr, sysent_to_syscall_str(sysent));
        }
        assert_ifdebug((long)sysent->filter > 0);

        _pk_acquire_lock();
        if (sf_arg_copy_syscall_enter(&ti, sysent->arg_copy) == -1) {
            _pk_release_lock();
            resp->val = -errno;
            return;
        }
        _pk_release_lock();

        SET_SYSCALL_ENTER(&ti);
        sysent->filter(&ti);

        if (IS_SYSCALL_ALLOWED(&ti)) {
            // emulating syscall in tracer (can not execute in tracee)
            ti.return_value = syscall(ti.syscall_nr, ti.args[0], ti.args[1], ti.args[2], ti.args[3], ti.args[4], ti.args[5]);
            if (ti.return_value == -1) {
                ti.return_value = -errno;
            }

            SET_SYSCALL_EXIT(&ti);
            sysent->filter(&ti);
        }
        
        // also restore args for filters that don't execute the syscall
        _pk_acquire_lock();
        if (sf_arg_copy_syscall_exit(&ti, sysent->arg_copy) == -1) {
            _pk_release_lock();
            resp->val = -errno;
            return;
        }
        _pk_release_lock();

        resp->val = ti.return_value;
        return;
    }
}
//------------------------------------------------------------------------------

int PK_API PK_CODE sf_seccomp_user_tracer(pid_t listener)
{
    assert(-1 != listener);
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;

    if (_seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        ERROR("seccomp: GET_NOTIF_SIZES");
        goto out_close;
    }

    req = malloc(sizes.seccomp_notif);
    if (!req)
        goto out_close;

    resp = malloc(sizes.seccomp_notif_resp);
    if (!resp)
        goto out_req;
    memset(resp, 0, sizes.seccomp_notif_resp);

    while (1) {
        memset(req, 0, sizes.seccomp_notif);
restart_ioctl_recv:
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (EINTR == errno) {
                goto restart_ioctl_recv;
            }
            ERROR("ioctl recv SECCOMP_IOCTL_NOTIF_RECV");
            perror("ioctl");
            goto out_resp;
        }

        _handle_req_sameprocess(req, resp, listener);


        // ENOENT here means that the task may have gotten a
        // signal and restarted the syscall.
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 &&
            errno != ENOENT) {
            ERROR("ioctl send SECCOMP_IOCTL_NOTIF_SEND");
            goto out_resp;
        }
    }

out_resp:
    free(resp);
out_req:
    free(req);
out_close:
    close(listener);
    return 0;
}
//------------------------------------------------------------------------------
