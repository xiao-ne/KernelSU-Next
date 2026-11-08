#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>

long ksu_adb_root_handle_execve(struct pt_regs *regs);
long ksu_adb_root_handle_execveat(struct pt_regs *regs);

/* manual-hook (fs/exec.c do_execveat_common) entry point */
long ksu_adb_root_handle_execve_kargs(const char *path, void *envp_p);

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif