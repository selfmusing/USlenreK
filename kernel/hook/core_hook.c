int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	if (!current->mm) {
		// skip kernel threads
		return 0;
	}

	if (current_uid().val != 1000) {
		// skip non system uid
		return 0;
	}

	if (!old_dentry || !new_dentry) {
		return 0;
	}

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list")) {
		return 0;
	}

	char path[128];
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list")) {
		return 0;
	}
	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
		new_dentry->d_iname, buf);

	track_throne(false);

	return 0;
}

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	if (!new || !old) {
		return 0;
	}

	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;

	// old process is not root, ignore it.
	if (0 != old_uid)
		return 0;

	// we dont have those new fancy things upstream has
	// lets just do original thing where we disable seccomp
	if (likely(ksu_is_manager_appid_valid()) && unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		disable_seccomp();
		pr_info("install fd for: %d\n", new_uid);
		ksu_install_fd(); // install fd for ksu manager
	}

	if (unlikely(ksu_is_allow_uid_for_current(new_uid))) {
		disable_seccomp();
		return 0;
	}

	return ksu_handle_umount(new, old);
}

int ksu_bprm_check(struct linux_binprm *bprm)
{
	if (likely(!ksu_execveat_hook))
		return 0;

	ksu_handle_pre_ksud((const char *)bprm->filename);

	return 0;
}

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return ksu_handle_rename(old_dentry, new_dentry);
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	return ksu_handle_setuid(new, old);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
}

#else
static void ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
}
#endif // 4.11
#endif // 4.2

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
