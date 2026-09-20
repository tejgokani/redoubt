#ifndef SHIM_SYSCALL_H
#define SHIM_SYSCALL_H
#include_next <sys/syscall.h>
#ifndef SYS_getdents64
#define SYS_getdents64 217
#endif
#ifndef SYS_sched_getaffinity
#define SYS_sched_getaffinity 204
#endif
#endif
