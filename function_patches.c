/*
 * These method replacements were created for kernel 5.14.13
 * You must manually enable enforcing mode if you want it
 * (read the code)
 * You put the generated code somewhere in the file before the method
 * (the module needs to be compiled against the kernel and be made to load)
 * Read the code to disable uneeded printk
 */

//FILE:fs/open.c
//METHOD:do_sys_openat2
static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		//printk(KERN_INFO "LD_master Checking: %s\n", filename);


		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			if(ld_master_check(f,tmp) != 0) {
				filp_close(f, NULL);
				put_unused_fd(fd);
				fd = PTR_ERR(f);
				goto out;
			}
			fsnotify_open(f);
			//printk(KERN_INFO "LD_master Checking: %s\n", tmp->name);
			fd_install(fd, f);
		}
	}
	out:
	putname(tmp);
	return fd;
}
//FILE:fs/exec.c
//METHOD:do_open_execat
static struct file *do_open_execat(int fd, struct filename *name, int flags)
{
	struct file *file;
	int err, file_size, reset_spot;
	struct open_flags open_exec_flags = {
		.open_flag = O_LARGEFILE | O_RDONLY | __FMODE_EXEC,
		.acc_mode = MAY_EXEC,
		.intent = LOOKUP_OPEN,
		.lookup_flags = LOOKUP_FOLLOW,
	};


	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return ERR_PTR(-EINVAL);
	if (flags & AT_SYMLINK_NOFOLLOW)
		open_exec_flags.lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		open_exec_flags.lookup_flags |= LOOKUP_EMPTY;


	// try a do_filp_open
	if (snarf_check(fd, name, &open_exec_flags) != 0)
		return NULL;

	file = do_filp_open(fd, name, &open_exec_flags);
	if (IS_ERR(file))
		goto out;

	/*
	 * may_open() has already checked for this, so it should be
	 * impossible to trip now. But we need to be extra cautious
	 * and check again at the very end too.
	 */
	err = -EACCES;
	if (WARN_ON_ONCE(!S_ISREG(file_inode(file)->i_mode) ||
			 path_noexec(&file->f_path)))
		goto exit;

	err = deny_write_access(file);
	if (err)
		goto exit;

	if (name->name[0] != '\0')
		fsnotify_open(file);

out:
	return file;

exit:
	fput(file);
	return ERR_PTR(err);
}
//FILE:init/main.c
//METHOD:kernel_init
static int __ref kernel_init(void *unused)
{
	int ret;

	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	kprobe_free_init_mem();
	ftrace_free_init_mem();
	kgdb_free_init_mem();
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();


	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

	do_sysctl_args();


	slowboot_mod_init();
	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}

	if (CONFIG_DEFAULT_INIT[0] != '\0') {
		ret = run_init_process(CONFIG_DEFAULT_INIT);
		if (ret)
			pr_err("Default init %s failed (error %d)\n",
			       CONFIG_DEFAULT_INIT, ret);
		else
			return 0;
	}



	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}
