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
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0) && !defined(TWA_RESUME)
#define TWA_RESUME 1
#endif

// this is ksys_close, however that is spotty to use 
// as 5.10 backported close_fd and rekt ksys_close
// so we use what it does internally, __close_fd
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define close_fd(fd) __close_fd(current->files, fd)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define close_fd sys_close
#endif

#endif
