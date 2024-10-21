/*
 * fsampler.h - fault sampling (with stacktrace support) for the handler threads
 */

#ifndef __FSAMPLER_H__
#define __FSAMPLER_H__

/* fault sample flags */
#define FSAMPLER_FAULT_FLAG_WRITE   UFFD_PAGEFAULT_FLAG_WRITE
#define FSAMPLER_FAULT_FLAG_WP      UFFD_PAGEFAULT_FLAG_WP
/* reserving couple extra bits for future uffd flags */
#define FSAMPLER_FAULT_FLAG_ZERO    (1<<5)


#if defined(EXTRA_REGS_KERNEL)
#include <asm/ptrace.h>
#endif


int fsampler_init(int _samples_per_sec);
int fsampler_get_sampler();
void fsampler_add_fault_sample(int fsid, unsigned long addr, int flags, 
#if defined(EXTRA_IP_KERNEL)
unsigned long ip, 
#elif defined(EXTRA_REGS_KERNEL)
struct pt_regs regs,
#endif
pid_t tid);
void fsampler_dump(int fsid);
int fsampler_destroy(void);

#endif  // __FSAMPLER_H__