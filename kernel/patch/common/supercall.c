/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <sucompat.h>
#include <kstorage.h>
#include <supercall_ioctl.h>
#include <hook.h>
#include <kallsyms.h>
#ifdef ANDROID
#include <userd.h>
#endif

#include <linux/fs.h>

// Minimal file_operations definition matching the kernel's layout
// The full definition exists at runtime but isn't available at compile time
struct kp_file_operations {
    struct module *owner;
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *, bool);
    int (*iterate)(struct file *, struct dir_context *);
    int (*iterate_shared)(struct file *, struct dir_context *);
    __poll_t (*poll)(struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
    long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
    int (*mmap)(struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open)(struct inode *, struct file *);
    int (*flush)(struct file *, fl_owner_t id);
    int (*release)(struct inode *, struct file *);
    int (*fsync)(struct file *, loff_t, loff_t, int datasync);
    int (*fasync)(int, struct file *, int);
    int (*lock)(struct file *, int, struct file_lock *);
    ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock)(struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *, int, loff_t, loff_t);
    void (*show_fdinfo)(struct seq_file *, struct file *);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
    int (*fadvise)(struct file *, loff_t, loff_t, int);
};

static long call_test(long arg1, long arg2, long arg3)
{
    return 0;
}

static long call_bootlog()
{
    print_bootlog();
    return 0;
}

static long call_panic()
{
    unsigned long panic_addr = kallsyms_lookup_name("panic");
    ((void (*)(const char *fmt, ...))panic_addr)("!!!! kernel_patch panic !!!!");
    return 0;
}

static long call_klog(const char __user *arg1)
{
    char buf[1024];
    long len = compat_strncpy_from_user(buf, arg1, sizeof(buf));
    if (len <= 0) return -EINVAL;
    if (len > 0) logki("user log: %s", buf);
    return 0;
}

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
}

static long call_kpm_load(const char __user *arg1, const char *__user arg2, void *__user reserved)
{
    char path[1024], args[KPM_ARGS_LEN];
    long pathlen = compat_strncpy_from_user(path, arg1, sizeof(path));
    if (pathlen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args, reserved);
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

static long call_su(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = commit_su(profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_su_task(pid_t pid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = task_su(pid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

#ifdef ANDROID
extern int android_is_safe_mode;
static long call_su_get_safemode()
{
    int result = android_is_safe_mode;
    logkfd("[call_su_get_safemode] %d\n", result);
    return result;
}

extern int load_ap_package_config(void);
static long call_ap_load_package_config()
{
    int result = load_ap_package_config();
    logkfd("[call_ap_load_package_config] loaded %d entries\n", result);
    return result;
}
#endif

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(1, uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(1, uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    return su_reset_path(strndup_user(upath, SU_PATH_MAX_LEN));
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    const char *path = su_get_path();
    int len = strlen(path);
    if (buf_len <= len) return -ENOBUFS;
    return compat_copy_to_user(ubuf, path, len + 1);
}

static long call_su_get_allow_sctx(char *__user usctx, int ulen)
{
    int len = strlen(all_allow_sctx);
    if (ulen <= len) return -ENOBUFS;
    return compat_copy_to_user(usctx, all_allow_sctx, len + 1);
}

static long call_su_set_allow_sctx(char *__user usctx)
{
    char buf[SUPERCALL_SCONTEXT_LEN];
    buf[0] = '\0';
    int len = compat_strncpy_from_user(buf, usctx, sizeof(buf));
    if (len >= SUPERCALL_SCONTEXT_LEN && buf[SUPERCALL_SCONTEXT_LEN - 1]) return -E2BIG;
    return set_all_allow_sctx(buf);
}

static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)
{
    return read_kstorage(gid, did, out_data, offset, dlen, true);
}

static long call_kstorage_write(int gid, long did, void *data, int offset, int dlen)
{
    return write_kstorage(gid, did, data, offset, dlen, true);
}

static long call_list_kstorage_ids(int gid, long *ids, int ids_len)
{
    return list_kstorage_ids(gid, ids, ids_len, false);
}

static long call_kstorage_remove(int gid, long did)
{
    return remove_kstorage(gid, did);
}

// Ioctl argument structures for userspace layout
struct kp_ioctl_kpm_load_args {
    char path[1024];
    char args[KPM_ARGS_LEN];
};

struct kp_ioctl_kpm_control_args {
    char name[KPM_NAME_LEN];
    char args[KPM_ARGS_LEN];
    int outlen;
    char out_buf[0];
};

struct kp_ioctl_kpm_unload_args {
    char name[KPM_NAME_LEN];
};

struct kp_ioctl_kpm_info_args {
    char name[64];
    int out_len;
    char out_buf[0];
};

struct kp_ioctl_kpm_list_args {
    int len;
    char buf[0];
};

struct kp_ioctl_kstorage_args {
    int gid;
    long did;
    int offset;
    int dlen;
    char data[0];
};

struct kp_ioctl_kstorage_list_args {
    int gid;
    int ids_len;
    long ids[0];
};

// Permission check functions
static bool perm_check_always(void)
{
    return true;
}

static bool perm_check_manager(void)
{
#ifdef ANDROID
    return is_trusted_manager_uid(current_uid());
#else
    return false;
#endif
}

static bool perm_check_su_allowed(void)
{
    uid_t uid = current_uid();
    return is_su_allow_uid(uid) || perm_check_manager();
}

// Ioctl handler wrappers
static int ioctl_hello(void __user *arg)
{
    return SUPERCALL_HELLO_MAGIC;
}

static int ioctl_kp_ver(void __user *arg)
{
    return kpver;
}

static int ioctl_k_ver(void __user *arg)
{
    return kver;
}

static int ioctl_klog(void __user *arg)
{
    return call_klog((const char __user *)arg);
}

static int ioctl_buildtime(void __user *arg)
{
    return call_buildtime((char __user *)arg, 256);
}

static int ioctl_su(void __user *arg)
{
    return call_su((struct su_profile __user *)arg);
}

static int ioctl_su_task(void __user *arg)
{
    // arg layout: { pid_t pid; struct su_profile profile; }
    pid_t __user *pidp = (pid_t __user *)arg;
    long plen = compat_strncpy_from_user((char *)pidp, (const char __user *)pidp, sizeof(pid_t));
    if (plen <= 0) return -EFAULT;
    return call_su_task(*pidp, (struct su_profile __user *)(pidp + 1));
}

static int ioctl_su_grant(void __user *arg)
{
    return call_grant_uid((struct su_profile __user *)arg);
}

static int ioctl_su_revoke(void __user *arg)
{
    uid_t uid;
    long rlen = compat_strncpy_from_user((char *)&uid, arg, sizeof(uid));
    if (rlen <= 0) return -EFAULT;
    return call_revoke_uid(uid);
}

static int ioctl_su_nums(void __user *arg)
{
    return call_su_allow_uid_nums();
}

static int ioctl_su_list(void __user *arg)
{
    // arg layout: { int num; uid_t uids[]; }
    int __user *nump = (int __user *)arg;
    int num;
    long rlen = compat_strncpy_from_user((char *)&num, (const char __user *)nump, sizeof(num));
    if (rlen <= 0) return -EFAULT;
    return call_su_list_allow_uid((uid_t *)(nump + 1), num);
}

static int ioctl_su_profile(void __user *arg)
{
    uid_t __user *uidp = (uid_t __user *)arg;
    uid_t uid;
    long rlen = compat_strncpy_from_user((char *)&uid, (const char __user *)uidp, sizeof(uid));
    if (rlen <= 0) return -EFAULT;
    return call_su_allow_uid_profile(uid, (struct su_profile __user *)(uidp + 1));
}

static int ioctl_su_get_path(void __user *arg)
{
    int __user *lenp = (int __user *)arg;
    int len;
    long rlen = compat_strncpy_from_user((char *)&len, (const char __user *)lenp, sizeof(len));
    if (rlen <= 0) return -EFAULT;
    return call_su_get_path((char __user *)(lenp + 1), len);
}

static int ioctl_su_reset_path(void __user *arg)
{
    return call_reset_su_path((const char __user *)arg);
}

static int ioctl_su_get_allow_sctx(void __user *arg)
{
    int __user *lenp = (int __user *)arg;
    int len;
    long rlen = compat_strncpy_from_user((char *)&len, (const char __user *)lenp, sizeof(len));
    if (rlen <= 0) return -EFAULT;
    return call_su_get_allow_sctx((char __user *)(lenp + 1), len);
}

static int ioctl_su_set_allow_sctx(void __user *arg)
{
    return call_su_set_allow_sctx((char __user *)arg);
}

static int ioctl_kpm_load(void __user *arg)
{
    // arg layout: { char path[1024]; char args[KPM_ARGS_LEN]; }
    // call_kpm_load already uses compat_strncpy_from_user
    struct kp_ioctl_kpm_load_args __user *uargs = (struct kp_ioctl_kpm_load_args __user *)arg;
    return call_kpm_load(uargs->path, uargs->args, 0);
}

static int ioctl_kpm_unload(void __user *arg)
{
    struct kp_ioctl_kpm_unload_args __user *uargs = (struct kp_ioctl_kpm_unload_args __user *)arg;
    return call_kpm_unload(uargs->name, 0);
}

static int ioctl_kpm_control(void __user *arg)
{
    struct kp_ioctl_kpm_control_args __user *uargs = (struct kp_ioctl_kpm_control_args __user *)arg;
    // Read outlen from user, then pass name/args directly (call_kpm_control uses compat_strncpy_from_user)
    int outlen;
    long rlen = compat_strncpy_from_user((char *)&outlen, (const char __user *)&uargs->outlen, sizeof(outlen));
    if (rlen <= 0) return -EFAULT;
    return call_kpm_control(uargs->name, uargs->args, uargs->out_buf, outlen);
}

static int ioctl_kpm_nums(void __user *arg)
{
    return call_kpm_nums();
}

static int ioctl_kpm_list(void __user *arg)
{
    struct kp_ioctl_kpm_list_args __user *uargs = (struct kp_ioctl_kpm_list_args __user *)arg;
    int len;
    long rlen = compat_strncpy_from_user((char *)&len, (const char __user *)&uargs->len, sizeof(len));
    if (rlen <= 0) return -EFAULT;
    return call_kpm_list(uargs->buf, len);
}

static int ioctl_kpm_info(void __user *arg)
{
    struct kp_ioctl_kpm_info_args __user *uargs = (struct kp_ioctl_kpm_info_args __user *)arg;
    int out_len;
    long rlen = compat_strncpy_from_user((char *)&out_len, (const char __user *)&uargs->out_len, sizeof(out_len));
    if (rlen <= 0) return -EFAULT;
    return call_kpm_info(uargs->name, uargs->out_buf, out_len);
}

static int ioctl_kstorage_read(void __user *arg)
{
    struct kp_ioctl_kstorage_args __user *uargs = (struct kp_ioctl_kstorage_args __user *)arg;
    int gid, offset, dlen;
    long did;
    long r1 = compat_strncpy_from_user((char *)&gid, (const char __user *)&uargs->gid, sizeof(gid));
    if (r1 <= 0) return -EFAULT;
    long r2 = compat_strncpy_from_user((char *)&did, (const char __user *)&uargs->did, sizeof(did));
    if (r2 <= 0) return -EFAULT;
    long r3 = compat_strncpy_from_user((char *)&offset, (const char __user *)&uargs->offset, sizeof(offset));
    if (r3 <= 0) return -EFAULT;
    long r4 = compat_strncpy_from_user((char *)&dlen, (const char __user *)&uargs->dlen, sizeof(dlen));
    if (r4 <= 0) return -EFAULT;
    return call_kstorage_read(gid, did, uargs->data, offset, dlen);
}

static int ioctl_kstorage_write(void __user *arg)
{
    struct kp_ioctl_kstorage_args __user *uargs = (struct kp_ioctl_kstorage_args __user *)arg;
    int gid, offset, dlen;
    long did;
    long r1 = compat_strncpy_from_user((char *)&gid, (const char __user *)&uargs->gid, sizeof(gid));
    if (r1 <= 0) return -EFAULT;
    long r2 = compat_strncpy_from_user((char *)&did, (const char __user *)&uargs->did, sizeof(did));
    if (r2 <= 0) return -EFAULT;
    long r3 = compat_strncpy_from_user((char *)&offset, (const char __user *)&uargs->offset, sizeof(offset));
    if (r3 <= 0) return -EFAULT;
    long r4 = compat_strncpy_from_user((char *)&dlen, (const char __user *)&uargs->dlen, sizeof(dlen));
    if (r4 <= 0) return -EFAULT;
    return call_kstorage_write(gid, did, uargs->data, offset, dlen);
}

static int ioctl_kstorage_list_ids(void __user *arg)
{
    struct kp_ioctl_kstorage_list_args __user *uargs = (struct kp_ioctl_kstorage_list_args __user *)arg;
    int gid, ids_len;
    long r1 = compat_strncpy_from_user((char *)&gid, (const char __user *)&uargs->gid, sizeof(gid));
    if (r1 <= 0) return -EFAULT;
    long r2 = compat_strncpy_from_user((char *)&ids_len, (const char __user *)&uargs->ids_len, sizeof(ids_len));
    if (r2 <= 0) return -EFAULT;
    return call_list_kstorage_ids(gid, uargs->ids, ids_len);
}

static int ioctl_kstorage_remove(void __user *arg)
{
    struct kp_ioctl_kstorage_args __user *uargs = (struct kp_ioctl_kstorage_args __user *)arg;
    int gid;
    long did;
    long r1 = compat_strncpy_from_user((char *)&gid, (const char __user *)&uargs->gid, sizeof(gid));
    if (r1 <= 0) return -EFAULT;
    long r2 = compat_strncpy_from_user((char *)&did, (const char __user *)&uargs->did, sizeof(did));
    if (r2 <= 0) return -EFAULT;
    return call_kstorage_remove(gid, did);
}

static int ioctl_bootlog(void __user *arg)
{
    return call_bootlog();
}

static int ioctl_panic(void __user *arg)
{
    return call_panic();
}

static int ioctl_test(void __user *arg)
{
    return call_test(0, 0, 0);
}

#ifdef ANDROID
static int ioctl_su_get_safemode(void __user *arg)
{
    return call_su_get_safemode();
}

static int ioctl_ap_load_package_config(void __user *arg)
{
    return call_ap_load_package_config();
}
#endif

static struct kp_ioctl_cmd_map cmd_maps[] = {
    // Public commands
    { SUPERCALL_HELLO, "hello", ioctl_hello, perm_check_always },
    { SUPERCALL_KERNELPATCH_VER, "kp_ver", ioctl_kp_ver, perm_check_always },
    { SUPERCALL_KERNEL_VER, "k_ver", ioctl_k_ver, perm_check_always },

    // Manager-only commands
    { SUPERCALL_KLOG, "klog", ioctl_klog, perm_check_manager },
    { SUPERCALL_BUILD_TIME, "buildtime", ioctl_buildtime, perm_check_manager },
#ifdef ANDROID
    { SUPERCALL_AP_LOAD_PACKAGE_CONFIG, "ap_load_package_config", ioctl_ap_load_package_config, perm_check_manager },
#endif

    // SU commands (su-allowed or manager)
    { SUPERCALL_SU, "su", ioctl_su, perm_check_su_allowed },
    { SUPERCALL_SU_TASK, "su_task", ioctl_su_task, perm_check_su_allowed },

    // SU management commands (manager-only)
    { SUPERCALL_SU_GRANT_UID, "su_grant_uid", ioctl_su_grant, perm_check_manager },
    { SUPERCALL_SU_REVOKE_UID, "su_revoke_uid", ioctl_su_revoke, perm_check_manager },
    { SUPERCALL_SU_NUMS, "su_nums", ioctl_su_nums, perm_check_manager },
    { SUPERCALL_SU_LIST, "su_list", ioctl_su_list, perm_check_manager },
    { SUPERCALL_SU_PROFILE, "su_profile", ioctl_su_profile, perm_check_manager },
    { SUPERCALL_SU_RESET_PATH, "su_reset_path", ioctl_su_reset_path, perm_check_manager },
    { SUPERCALL_SU_GET_PATH, "su_get_path", ioctl_su_get_path, perm_check_manager },
    { SUPERCALL_SU_GET_ALLOW_SCTX, "su_get_allow_sctx", ioctl_su_get_allow_sctx, perm_check_manager },
    { SUPERCALL_SU_SET_ALLOW_SCTX, "su_set_allow_sctx", ioctl_su_set_allow_sctx, perm_check_manager },
#ifdef ANDROID
    { SUPERCALL_SU_GET_SAFEMODE, "su_get_safemode", ioctl_su_get_safemode, perm_check_manager },
#endif

    // KPM commands (manager-only)
    { SUPERCALL_KPM_LOAD, "kpm_load", ioctl_kpm_load, perm_check_manager },
    { SUPERCALL_KPM_UNLOAD, "kpm_unload", ioctl_kpm_unload, perm_check_manager },
    { SUPERCALL_KPM_CONTROL, "kpm_control", ioctl_kpm_control, perm_check_manager },
    { SUPERCALL_KPM_NUMS, "kpm_nums", ioctl_kpm_nums, perm_check_manager },
    { SUPERCALL_KPM_LIST, "kpm_list", ioctl_kpm_list, perm_check_manager },
    { SUPERCALL_KPM_INFO, "kpm_info", ioctl_kpm_info, perm_check_manager },

    // kstorage commands (manager-only)
    { SUPERCALL_KSTORAGE_READ, "kstorage_read", ioctl_kstorage_read, perm_check_manager },
    { SUPERCALL_KSTORAGE_WRITE, "kstorage_write", ioctl_kstorage_write, perm_check_manager },
    { SUPERCALL_KSTORAGE_LIST_IDS, "kstorage_list_ids", ioctl_kstorage_list_ids, perm_check_manager },
    { SUPERCALL_KSTORAGE_REMOVE, "kstorage_remove", ioctl_kstorage_remove, perm_check_manager },

    // Diagnostic commands (manager-only)
    { SUPERCALL_BOOTLOG, "bootlog", ioctl_bootlog, perm_check_manager },
    { SUPERCALL_PANIC, "panic", ioctl_panic, perm_check_manager },
    { SUPERCALL_TEST, "test", ioctl_test, perm_check_manager },
};

#define CMD_MAPS_SIZE (sizeof(cmd_maps) / sizeof(cmd_maps[0]))

static long kp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return -ENOSYS;

    struct kp_ioctl_cmd_map *entry = NULL;
    for (int i = 0; i < CMD_MAPS_SIZE; i++) {
        if (cmd_maps[i].cmd == cmd) {
            entry = &cmd_maps[i];
            break;
        }
    }

    if (!entry) return -ENOSYS;

    if (!entry->perm_check()) return -EPERM;

    return entry->handler((void __user *)arg);
}

static int kp_open(struct inode *inode, struct file *file)
{
#ifdef ANDROID
    if (!is_trusted_manager_uid(current_uid())) return -EPERM;
#else
    return -EPERM;
#endif
    return 0;
}

static const struct kp_file_operations kp_fops = {
    .owner = NULL,
    .open = kp_open,
    .unlocked_ioctl = kp_ioctl,
    .compat_ioctl = kp_ioctl,
};

#define KP_DEVICE_NAME "kp_dev"

// Kernel function pointers for fd management
int kfunc_def(get_unused_fd_flags)(int) = 0;
void kfunc_def(put_unused_fd)(int) = 0;
struct file *kfunc_def(anon_inode_getfile)(const char *, const struct file_operations *, void *, int) = 0;
void kfunc_def(fd_install)(int, struct file *) = 0;

int kp_install_fd(void)
{
#ifdef ANDROID
    if (!is_trusted_manager_uid(current_uid())) return -EPERM;
#endif

    int fd = kfunc(get_unused_fd_flags)(O_CLOEXEC);
    if (fd < 0) return fd;

    struct file *file = kfunc(anon_inode_getfile)(KP_DEVICE_NAME, (const struct file_operations *)&kp_fops, NULL, O_RDWR);
    if (IS_ERR(file)) {
        kfunc(put_unused_fd)(fd);
        return PTR_ERR(file);
    }

    kfunc(fd_install)(fd, file);
    logkfi("kp_install_fd: %d for uid: %d\n", fd, current_uid());
    return fd;
}

int is_trusted_manager_uid(uid_t uid)
{
#ifdef ANDROID
    return is_trusted_manager_uid_android(uid);
#endif
    return 0;
}

#define KP_DEVICE_PATH "/dev/kp"

static void before_supercall_install(hook_fargs6_t *args, void *udata)
{
    // Hook openat to intercept manager opening /dev/kp
    // Install anonymous inode with ioctl handler instead
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char buf[64];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0) return;
    if (strcmp(buf, KP_DEVICE_PATH)) return;

    uid_t uid = current_uid();
    if (!is_trusted_manager_uid(uid)) return;

    int fd = kp_install_fd();
    if (fd < 0) return;

    args->skip_origin = 1;
    args->ret = fd;
}

void kp_supercalls_init(void)
{
    kfunc_lookup_name(get_unused_fd_flags);
    kfunc_lookup_name(put_unused_fd);
    kfunc_lookup_name(anon_inode_getfile);
    kfunc_lookup_name(fd_install);

    if (!kfunc(get_unused_fd_flags) || !kfunc(put_unused_fd) || !kfunc(anon_inode_getfile) || !kfunc(fd_install)) {
        log_boot("kp_supercalls_init: failed to resolve kernel functions\n");
        log_boot("  get_unused_fd_flags: %llx\n", (unsigned long)kfunc(get_unused_fd_flags));
        log_boot("  put_unused_fd: %llx\n", (unsigned long)kfunc(put_unused_fd));
        log_boot("  anon_inode_getfile: %llx\n", (unsigned long)kfunc(anon_inode_getfile));
        log_boot("  fd_install: %llx\n", (unsigned long)kfunc(fd_install));
        return;
    }

    // Hook openat to install ioctl fd when manager opens /dev/kp
    hook_err_t err = hook_syscalln(__NR_openat, 6, before_supercall_install, 0, 0);
    if (err) {
        log_boot("kp_supercalls_init: hook openat error: %d\n", err);
        return;
    }

    log_boot("kp_supercalls_init done\n");
}

void kp_supercalls_exit(void)
{
}
