#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

// TODO: add keygrab
#define ksu_filp_open_compat filp_open

// TODO: add < 4.14 compat
#define ksu_kernel_read_compat kernel_read
#define ksu_kernel_write_compat kernel_write

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void *ksu_kvmalloc(size_t size, gfp_t flags)
{
	void *buf = kmalloc(size, flags);
	if (!buf)
		buf = vmalloc(size);
	
	return buf;
}

static inline void ksu_kvfree(void *buf)
{
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
}
#define kvmalloc ksu_kvmalloc
#define kvfree ksu_kvfree
#endif

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME 1
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define close_fd sys_close
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#include <linux/fdtable.h>
__weak int close_fd(unsigned fd)
{
	// this is ksys_close, but that shit is inline
	// its problematic to cascade a weak symbol for it
	return __close_fd(current->files, fd);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
static inline struct file *ksu_dentry_open(const struct path *path, int flags, const struct cred *cred)
{
	return dentry_open((*path).dentry, (*path).mnt, flags, cred);
}
#define dentry_open ksu_dentry_open
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#ifndef replace_fops
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#endif
#endif

/**
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
extern long copy_from_user_nofault(void *dst, const void __user *src, size_t size);
static __always_inline long ksu_copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

#endif
