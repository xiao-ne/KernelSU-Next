#include <asm/ptrace.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/static_key.h>
#include <linux/slab.h>

#include "adb_root.h"
#include "arch.h"
#include "policy/feature.h"
#include "selinux/selinux.h"

#include "klog.h" // IWYU pragma: keep

DEFINE_STATIC_KEY_FALSE(ksu_adb_root);

static long is_exec_adbd(const char __user *filename_user)
{
    static const char kAdbd[] = "/adbd";
    static const size_t kAdbdLen = sizeof(kAdbd) - 1;
    // should be bigger than `/apex/com.android.adbd/bin/adbd`
    char buf[40];
    char __user *fn;
    long ret;
    fn = (char __user *)untagged_addr((unsigned long)filename_user);
    memset(buf, 0, sizeof(buf));

    ret = strncpy_from_user(buf, fn, sizeof(buf));
    if (ret < 0) {
        pr_warn("Access filename when adb_root_handle_execve failed: %ld\n", ret);
        return ret;
    }

    // strncpy_from_user may copy `sizeof(buf)` bytes
    if (ret < kAdbdLen || ret >= sizeof(buf) || memcmp(buf + ret - kAdbdLen, kAdbd, kAdbdLen + 1) != 0) {
        return 0;
    }

    return 1;
}

static long is_libadbroot_ok()
{
    static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
    struct path path;
    long ret = kern_path(kLibAdbRoot, 0, &path);
    if (ret < 0) {
        if (ret == -ENOENT) {
            pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
            ret = 0;
        } else {
            pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
        }
        return ret;
    } else {
        ret = 1;
    }
    path_put(&path);
    return ret;
}

static long setup_ld_preload(struct pt_regs *regs, unsigned long *envp_p)
{
    static const char kLdPreload[] = "LD_PRELOAD=/data/adb/ksu/lib/libadbroot.so";
    static const char kLdLibraryPath[] = "LD_LIBRARY_PATH=/data/adb/ksu/lib";
    static const size_t kPtrSize = sizeof(unsigned long);
    static const size_t kMaxEnvCount = 1024;
    unsigned long stackp = user_stack_pointer(regs);
    unsigned long envp, ld_preload_p, ld_library_path_p;
    unsigned long *tmp_env_p = NULL, *tmp_env_p2 = NULL;
    size_t env_count = 0, total_size;
    long ret;

    envp = (char __user **)untagged_addr((unsigned long)*envp_p);

    ld_preload_p = stackp = ALIGN_DOWN(stackp - sizeof(kLdPreload), 8);
    ret = copy_to_user(ld_preload_p, kLdPreload, sizeof(kLdPreload));
    if (ret != 0) {
        pr_warn("write ld_preload when adb_root_handle_execve failed: %ld\n", ret);
        return -EFAULT;
    }

    ld_library_path_p = stackp = ALIGN_DOWN(stackp - sizeof(kLdLibraryPath), 8);
    ret = copy_to_user(ld_library_path_p, kLdLibraryPath, sizeof(kLdLibraryPath));
    if (ret != 0) {
        pr_warn("write ld_library_path when adb_root_handle_execve failed: %ld\n", ret);
        return -EFAULT;
    }

    /*
     * Walk the caller's envp one pointer at a time: copying a whole batch
     * faults as soon as the array is followed by an unmapped page, and a
     * single element read tells us exactly where the array ends.
     */
    for (;;) {
        unsigned long entry;

        if (env_count >= kMaxEnvCount) {
            pr_err("envp array too long, skip adb root\n");
            ret = -E2BIG;
            goto out_release_env_p;
        }

        tmp_env_p2 = krealloc(tmp_env_p, (env_count + 3) * kPtrSize, GFP_KERNEL);
        if (tmp_env_p2 == NULL) {
            pr_err("alloc tmp env failed\n");
            ret = -ENOMEM;
            goto out_release_env_p;
        }
        tmp_env_p = tmp_env_p2;

        if (copy_from_user(&entry, (void __user *)(envp + env_count * kPtrSize),
                           kPtrSize)) {
            /* unmapped tail counts as the end of the array */
            break;
        }
        if (!entry) {
            break;
        }
        tmp_env_p[env_count++] = entry;
    }

    if (env_count == 0) {
        pr_err("adb_root: cannot read envp, skip\n");
        ret = -EFAULT;
        goto out_release_env_p;
    }

    // We should have allocated enough memory
    // TODO: handle existing LD_PRELOAD
    tmp_env_p[env_count++] = ld_preload_p;
    tmp_env_p[env_count++] = ld_library_path_p;
    tmp_env_p[env_count++] = 0;
    total_size = env_count * kPtrSize;

    stackp -= total_size;
    ret = copy_to_user(stackp, tmp_env_p, total_size);
    if (ret != 0) {
        pr_err("copy new env failed: %ld\n", ret);
        ret = -EFAULT;
        goto out_release_env_p;
    }

    *envp_p = stackp;
    ret = 0;

out_release_env_p:
    if (tmp_env_p) {
        kfree(tmp_env_p);
    }

    return ret;
}

static long adb_root_apply(struct pt_regs *regs, unsigned long *envp_p)
{
    long ret;

    if (unlikely(is_libadbroot_ok() != 1)) {
        return 0;
    }

    ret = setup_ld_preload(regs, envp_p);
    if (ret) {
        return ret;
    }

    pr_info("escape to root for adb\n");
    escape_to_root_for_adb_root();
    return 0;
}

static long do_ksu_adb_root_handle_execve(const char __user *filename_user,
					  struct pt_regs *regs,
					  unsigned long *envp_p)
{
    if (likely(is_exec_adbd(filename_user) != 1)) {
        return 0;
    }

    return adb_root_apply(regs, envp_p);
}

long ksu_adb_root_handle_execve(struct pt_regs *regs)
{
    if (static_branch_unlikely(&ksu_adb_root)) {
        return do_ksu_adb_root_handle_execve(
                (const char __user *)PT_REGS_PARM1(regs), regs,
                (unsigned long *)&PT_REGS_PARM3(regs));
    }
    return 0;
}

long ksu_adb_root_handle_execveat(struct pt_regs *regs)
{
    if (static_branch_unlikely(&ksu_adb_root)) {
        return do_ksu_adb_root_handle_execve(
                (const char __user *)PT_REGS_PARM2(regs), regs,
                (unsigned long *)&PT_REGS_SYSCALL_PARM4(regs));
    }
    return 0;
}

/*
 * Manual-hook entry point.  On kernels below 4.17 with CONFIG_KSU_MANUAL_HOOK
 * there is no kprobe and no syscall-table hook, so the pt_regs based helpers
 * above never run.  fs/exec.c already resolved the path into a kernel
 * filename and owns the struct user_arg_ptr copy of envp, so matching the
 * name here and rewriting the caller's envp pointer through the same
 * user-stack trick is enough to preload libadbroot.so.
 */
static long is_adbd_kernel_path(const char *name)
{
    static const char kAdbd[] = "/adbd";
    static const size_t kAdbdLen = sizeof(kAdbd) - 1;
    size_t len;

    if (!name) {
        return 0;
    }

    len = strlen(name);
    if (len < kAdbdLen) {
        return 0;
    }

    return memcmp(name + len - kAdbdLen, kAdbd, kAdbdLen + 1) == 0 ? 1 : 0;
}

long ksu_adb_root_handle_execve_kargs(const char *path, void *envp_p)
{
    struct pt_regs *regs;
    int ppid;

    if (!static_branch_unlikely(&ksu_adb_root)) {
        return 0;
    }

    if (is_adbd_kernel_path(path) != 1) {
        return 0;
    }

    /*
     * init starts services through a forked child and sets the service's
     * SELinux label (setexeccon) before execve(), so the creds are already
     * u:r:adbd:s0 by the time the exec reaches us and is_init() alone would
     * reject every adbd start.  Accept init's direct children as well.
     */
    ppid = current->real_parent ? current->real_parent->pid : -1;
    if (current->pid == 1 || (ppid != 1 && !is_init(current_cred()))) {
        return 0;
    }

    regs = current_pt_regs();
    if (!regs) {
        pr_warn("adb_root: no pt_regs, skip\n");
        return 0;
    }

    return adb_root_apply(regs, (unsigned long *)envp_p);
}

static int kernel_adb_root_feature_get(u64 *value)
{
    *value = static_key_enabled(&ksu_adb_root) ? 1 : 0;
    return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
    bool enable = value != 0;
    if (enable) {
        static_key_enable(&ksu_adb_root.key);
    } else {
        static_key_disable(&ksu_adb_root.key);
    }
    pr_info("adb_root: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
    .feature_id = KSU_FEATURE_ADB_ROOT,
    .name = "adb_root",
    .get_handler = kernel_adb_root_feature_get,
    .set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
    if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
        pr_err("Failed to register adb_root feature handler\n");
    }
}

void __exit ksu_adb_root_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}
