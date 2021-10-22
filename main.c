// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/acpi.h>
#include <linux/bootconfig.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/kfence.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/buildid.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/padata.h>
#include <linux/pid_namespace.h>
#include <linux/device/driver.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>
#include <linux/jump_label.h>
#include <linux/mem_encrypt.h>
#include <linux/kcsan.h>
#include <linux/init_syscalls.h>
#include <linux/stackdepot.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

#include <kunit/test.h>

static int kernel_init(void *);

extern void init_IRQ(void);
extern void radix_tree_init(void);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Untouched extra command line */
static char *extra_command_line;
/* Extra init arguments */
static char *extra_init_args;

#ifdef CONFIG_BOOT_CONFIG
/* Is bootconfig on command line? */
static bool bootconfig_found;
static bool initargs_found;
#else
# define bootconfig_found false
# define initargs_found false
#endif

static char *execute_command;
static char *ramdisk_execute_command = "/init";

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

#ifdef CONFIG_BLK_DEV_INITRD
static void * __init get_boot_config_from_initrd(u32 *_size, u32 *_csum)
{
	u32 size, csum;
	char *data;
	u32 *hdr;
	int i;

	if (!initrd_end)
		return NULL;

	data = (char *)initrd_end - BOOTCONFIG_MAGIC_LEN;
	/*
	 * Since Grub may align the size of initrd to 4, we must
	 * check the preceding 3 bytes as well.
	 */
	for (i = 0; i < 4; i++) {
		if (!memcmp(data, BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_LEN))
			goto found;
		data--;
	}
	return NULL;

found:
	hdr = (u32 *)(data - 8);
	size = le32_to_cpu(hdr[0]);
	csum = le32_to_cpu(hdr[1]);

	data = ((void *)hdr) - size;
	if ((unsigned long)data < initrd_start) {
		pr_err("bootconfig size %d is greater than initrd size %ld\n",
			size, initrd_end - initrd_start);
		return NULL;
	}

	/* Remove bootconfig from initramfs/initrd */
	initrd_end = (unsigned long)data;
	if (_size)
		*_size = size;
	if (_csum)
		*_csum = csum;

	return data;
}
#else
static void * __init get_boot_config_from_initrd(u32 *_size, u32 *_csum)
{
	return NULL;
}
#endif

#ifdef CONFIG_BOOT_CONFIG

static char xbc_namebuf[XBC_KEYLEN_MAX] __initdata;

#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

static int __init xbc_snprint_cmdline(char *buf, size_t size,
				      struct xbc_node *root)
{
	struct xbc_node *knode, *vnode;
	char *end = buf + size;
	const char *val;
	int ret;

	xbc_node_for_each_key_value(root, knode, val) {
		ret = xbc_node_compose_key_after(root, knode,
					xbc_namebuf, XBC_KEYLEN_MAX);
		if (ret < 0)
			return ret;

		vnode = xbc_node_get_child(knode);
		if (!vnode) {
			ret = snprintf(buf, rest(buf, end), "%s ", xbc_namebuf);
			if (ret < 0)
				return ret;
			buf += ret;
			continue;
		}
		xbc_array_for_each_value(vnode, val) {
			ret = snprintf(buf, rest(buf, end), "%s=\"%s\" ",
				       xbc_namebuf, val);
			if (ret < 0)
				return ret;
			buf += ret;
		}
	}

	return buf - (end - size);
}
#undef rest

/* Make an extra command line under given key word */
static char * __init xbc_make_cmdline(const char *key)
{
	struct xbc_node *root;
	char *new_cmdline;
	int ret, len = 0;

	root = xbc_find_node(key);
	if (!root)
		return NULL;

	/* Count required buffer size */
	len = xbc_snprint_cmdline(NULL, 0, root);
	if (len <= 0)
		return NULL;

	new_cmdline = memblock_alloc(len + 1, SMP_CACHE_BYTES);
	if (!new_cmdline) {
		pr_err("Failed to allocate memory for extra kernel cmdline.\n");
		return NULL;
	}

	ret = xbc_snprint_cmdline(new_cmdline, len + 1, root);
	if (ret < 0 || ret > len) {
		pr_err("Failed to print extra kernel cmdline.\n");
		return NULL;
	}

	return new_cmdline;
}

static int __init bootconfig_params(char *param, char *val,
				    const char *unused, void *arg)
{
	if (strcmp(param, "bootconfig") == 0) {
		bootconfig_found = true;
	}
	return 0;
}

static int __init warn_bootconfig(char *str)
{
	/* The 'bootconfig' has been handled by bootconfig_params(). */
	return 0;
}

static void __init setup_boot_config(void)
{
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;
	const char *msg;
	int pos;
	u32 size, csum;
	char *data, *copy, *err;
	int ret;

	/* Cut out the bootconfig data even if we have no bootconfig option */
	data = get_boot_config_from_initrd(&size, &csum);

	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	err = parse_args("bootconfig", tmp_cmdline, NULL, 0, 0, 0, NULL,
			 bootconfig_params);

	if (IS_ERR(err) || !bootconfig_found)
		return;

	/* parse_args() stops at '--' and returns an address */
	if (err)
		initargs_found = true;

	if (!data) {
		pr_err("'bootconfig' found on command line, but no bootconfig found\n");
		return;
	}

	if (size >= XBC_DATA_MAX) {
		pr_err("bootconfig size %d greater than max size %d\n",
			size, XBC_DATA_MAX);
		return;
	}

	if (xbc_calc_checksum(data, size) != csum) {
		pr_err("bootconfig checksum failed\n");
		return;
	}

	copy = memblock_alloc(size + 1, SMP_CACHE_BYTES);
	if (!copy) {
		pr_err("Failed to allocate memory for bootconfig\n");
		return;
	}

	memcpy(copy, data, size);
	copy[size] = '\0';

	ret = xbc_init(copy, &msg, &pos);
	if (ret < 0) {
		if (pos < 0)
			pr_err("Failed to init bootconfig: %s.\n", msg);
		else
			pr_err("Failed to parse bootconfig: %s at %d.\n",
				msg, pos);
	} else {
		pr_info("Load bootconfig: %d bytes %d nodes\n", size, ret);
		/* keys starting with "kernel." are passed via cmdline */
		extra_command_line = xbc_make_cmdline("kernel");
		/* Also, "init." keys are init arguments */
		extra_init_args = xbc_make_cmdline("init");
	}
	return;
}

#else

static void __init setup_boot_config(void)
{
	/* Remove bootconfig data from initrd */
	get_boot_config_from_initrd(NULL, NULL);
}

static int __init warn_bootconfig(char *str)
{
	pr_warn("WARNING: 'bootconfig' found on the kernel command line but CONFIG_BOOT_CONFIG is not set.\n");
	return 0;
}
#endif
early_param("bootconfig", warn_bootconfig);

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
		} else
			BUG();
	}
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	size_t len = strlen(param);

	repair_env_string(param, val);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strnchr(param, len, '.'))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], len+1))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	size_t len, xlen = 0, ilen = 0;

	if (extra_command_line)
		xlen = strlen(extra_command_line);
	if (extra_init_args)
		ilen = strlen(extra_init_args) + 4; /* for " -- " */

	len = xlen + strlen(boot_command_line) + 1;

	saved_command_line = memblock_alloc(len + ilen, SMP_CACHE_BYTES);
	if (!saved_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len + ilen);

	static_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!static_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	if (xlen) {
		/*
		 * We have to put extra_command_line before boot command
		 * lines because there could be dashes (separator of init
		 * command line) in the command lines.
		 */
		strcpy(saved_command_line, extra_command_line);
		strcpy(static_command_line, extra_command_line);
	}
	strcpy(saved_command_line + xlen, boot_command_line);
	strcpy(static_command_line + xlen, command_line);

	if (ilen) {
		/*
		 * Append supplemental init boot args to saved_command_line
		 * so that user can check what command line options passed
		 * to init.
		 */
		len = strlen(saved_command_line);
		if (initargs_found) {
			saved_command_line[len++] = ' ';
		} else {
			strcpy(saved_command_line + len, " -- ");
			len += 4;
		}

		strcpy(saved_command_line + len, extra_init_args);
	}
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	tsk->flags |= PF_NO_SETAFFINITY;
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak mem_encrypt_init(void) { }

void __init __weak poking_init(void) { }

void __init __weak pgtable_cache_init(void) { }

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void);
#else
static inline void initcall_debug_enable(void)
{
}
#endif

/* Report memory auto-initialization states for this boot. */
static void __init report_meminit(void)
{
	const char *stack;

	if (IS_ENABLED(CONFIG_INIT_STACK_ALL_PATTERN))
		stack = "all(pattern)";
	else if (IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO))
		stack = "all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL))
		stack = "byref_all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF))
		stack = "byref(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_USER))
		stack = "__user(zero)";
	else
		stack = "off";

	pr_info("mem auto-init: stack:%s, heap alloc:%s, heap free:%s\n",
		stack, want_init_on_alloc(GFP_KERNEL) ? "on" : "off",
		want_init_on_free() ? "on" : "off");
	if (want_init_on_free())
		pr_info("mem auto-init: clearing system memory may take some time...\n");
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_ext_init_flatmem();
	init_mem_debugging_and_hardening();
	kfence_alloc_pool();
	report_meminit();
	stack_depot_init();
	mem_init();
	mem_init_print_info();
	/* page_owner must be initialized after buddy is ready */
	page_ext_init_flatmem_late();
	kmem_cache_init();
	kmemleak_init();
	pgtable_init();
	debug_objects_mem_init();
	vmalloc_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up. */
	pti_init();
}

#ifdef CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
			   randomize_kstack_offset);
DEFINE_PER_CPU(u32, kstack_offset);

static int __init early_randomize_kstack_offset(char *buf)
{
	int ret;
	bool bool_result;

	ret = kstrtobool(buf, &bool_result);
	if (ret)
		return ret;

	if (bool_result)
		static_branch_enable(&randomize_kstack_offset);
	else
		static_branch_disable(&randomize_kstack_offset);
	return 0;
}
early_param("randomize_kstack_offset", early_randomize_kstack_offset);
#endif

void __init __weak arch_call_rest_init(void)
{
	rest_init();
}

static void __init print_unknown_bootoptions(void)
{
	char *unknown_options;
	char *end;
	const char *const *p;
	size_t len;

	if (panic_later || (!argv_init[1] && !envp_init[2]))
		return;

	/*
	 * Determine how many options we have to print out, plus a space
	 * before each
	 */
	len = 1; /* null terminator */
	for (p = &argv_init[1]; *p; p++) {
		len++;
		len += strlen(*p);
	}
	for (p = &envp_init[2]; *p; p++) {
		len++;
		len += strlen(*p);
	}

	unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!unknown_options) {
		pr_err("%s: Failed to allocate %zu bytes\n",
			__func__, len);
		return;
	}
	end = unknown_options;

	for (p = &argv_init[1]; *p; p++)
		end += sprintf(end, " %s", *p);
	for (p = &envp_init[2]; *p; p++)
		end += sprintf(end, " %s", *p);

	pr_notice("Unknown command line parameters:%s\n", unknown_options);
	memblock_free(__pa(unknown_options), len);
}

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	set_task_stack_end_magic(&init_task);
	smp_setup_processor_id();
	debug_objects_early_init();
	init_vmlinux_build_id();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	early_security_init();
	setup_arch(&command_line);
	setup_boot_config();
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	boot_cpu_hotplug_init();

	build_all_zonelists(NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", saved_command_line);
	/* parameters may set static keys */
	jump_label_init();
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	print_unknown_bootoptions();
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);
	if (extra_init_args)
		parse_args("Setting extra init args", extra_init_args,
			   NULL, 0, -1, -1, NULL, set_init_arg);

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_init();

	ftrace_init();

	/* trace_printk can be enabled here */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();

	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

	rcu_init();

	/* Trace events are available after this */
	trace_init();

	if (initcall_debug)
		initcall_debug_enable();

	context_tracking_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();
	tick_init();
	rcu_init_nohz();
	init_timers();
	srcu_init();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	kfence_init();

	/*
	 * For best initial stack canary entropy, prepare it after:
	 * - setup_arch() for any UEFI RNG entropy and boot cmdline access
	 * - timekeeping_init() for ktime entropy used in rand_initialize()
	 * - rand_initialize() to get any arch-specific entropy like RDRAND
	 * - add_latent_entropy() to get any latent entropy
	 * - adding command line entropy
	 */
	rand_initialize();
	add_latent_entropy();
	add_device_randomness(command_line, strlen(command_line));
	boot_init_stack_canary();

	time_init();
	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_init();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	setup_per_cpu_pageset();
	numa_policy_init();
	acpi_early_init();
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	calibrate_delay();
	pid_idr_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_stack_cache_init();
	cred_init();
	fork_init();
	proc_caches_init();
	uts_ns_init();
	key_init();
	security_init();
	dbg_late_init();
	vfs_caches_init();
	pagecache_init();
	signals_init();
	seq_file_init();
	proc_root_init();
	nsfs_init();
	cpuset_init();
	cgroup_init();
	taskstats_init_early();
	delayacct_init();

	poking_init();
	check_bugs();

	acpi_subsystem_init();
	arch_post_acpi_subsys_init();
	kcsan_init();

	/* Do the rest non-__init'ed, we're now alive */
	arch_call_rest_init();

	prevent_tail_call_optimization();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
/*
 * For UML, the constructors have already been called by the
 * normal setup code as it's just a normal ELF binary, so we
 * cannot do it again - but we do need CONFIG_CONSTRUCTORS
 * even on UML for modules.
 */
#if defined(CONFIG_CONSTRUCTORS) && !defined(CONFIG_UML)
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = memblock_alloc(sizeof(*entry),
					       SMP_CACHE_BYTES);
			if (!entry)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, sizeof(*entry));
			entry->buf = memblock_alloc(strlen(str_entry) + 1,
						    SMP_CACHE_BYTES);
			if (!entry->buf)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = (ktime_t *)data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t *calltime = (ktime_t *)data;
	ktime_t delta, rettime;
	unsigned long long duration;

	rettime = ktime_get();
	delta = ktime_sub(rettime, *calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, duration);
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
#endif /* !TRACEPOINTS_ENABLED */

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


extern initcall_entry_t __initcall_start[];
extern initcall_entry_t __initcall0_start[];
extern initcall_entry_t __initcall1_start[];
extern initcall_entry_t __initcall2_start[];
extern initcall_entry_t __initcall3_start[];
extern initcall_entry_t __initcall4_start[];
extern initcall_entry_t __initcall5_start[];
extern initcall_entry_t __initcall6_start[];
extern initcall_entry_t __initcall7_start[];
extern initcall_entry_t __initcall_end[];

static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
			       const char *unused, void *arg)
{
	return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = strlen(saved_command_line) + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();
	init_irq_proc();
	do_ctors();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static int run_init_process(const char *init_filename)
{
	const char *const *p;

	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	pr_debug("  with arguments:\n");
	for (p = argv_init; *p; p++)
		pr_debug("    %s\n", *p);
	pr_debug("  with environment:\n");
	for (p = envp_init; *p; p++)
		pr_debug("    %s\n", *p);
	return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;
static int __init set_debug_rodata(char *str)
{
	return strtobool(str, &rodata_enabled);
}
__setup("rodata=", set_debug_rodata);
#endif

#ifdef CONFIG_STRICT_KERNEL_RWX
static void mark_readonly(void)
{
	if (rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned
		 * up with call_rcu().  Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		rcu_barrier();
		mark_rodata_ro();
		rodata_test();
	} else
		pr_info("Kernel memory protection disabled.\n");
}
#elif defined(CONFIG_ARCH_HAS_STRICT_KERNEL_RWX)
static inline void mark_readonly(void)
{
	pr_warn("Kernel memory protection not selected by kernel config.\n");
}
#else
static inline void mark_readonly(void)
{
	pr_warn("This architecture does not have kernel memory protection.\n");
}
#endif

void __weak free_initmem(void)
{
	free_initmem_default(POISON_FREE_INITMEM);
}

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// TINFOIL : 38678932-3492-4a47-b783-66c5f9a5ac44 - 2021-10-20 21:34 EST       @
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/gfp.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>


#define SLWBT_MODE_REG 1
#define SLWBT_MODE_TPM 2
#define SLWBT_MODE_TPM2 3

#define SHA512_HASH_LEN 130

#define GLOW printk(KERN_ERR "GLOWING\n");

typedef struct slowboot_validation_item {
	char hash[130];
	u8 b_hash[65];
	char path[PATH_MAX];
	int is_ok;
	char *buf;
	size_t buf_len;
	struct file *fp;
	long long int pos;
} slowboot_validation_item;

//##########TEMPLATE_PARM_ST##################################################=>
typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[1863];
	int failures;
} slowboot_tinfoil;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static u32 mode;
static slowboot_tinfoil tinfoil;
//static struct kstat *st;



/*******************************************************************************
* Register data in array                                                       *
*******************************************************************************/
static void svi_reg(slowboot_validation_item *item,
		const char *hash,
		const char *path)
{
	strncpy(item->hash, hash, SHA512_HASH_LEN);
	strncpy(item->path, path, PATH_MAX);
	
	switch (mode) {
	case SLWBT_MODE_TPM:
		break;
	case SLWBT_MODE_TPM2:
		break;
	default:
		break;		
	}
}


static int tinfoil_open(slowboot_validation_item *item)
{
	item->fp = filp_open(item->path, O_RDONLY, 0);
	if (IS_ERR(item->fp) || item->fp == NULL) {
		printk(KERN_ERR "F:%s:%s:%d\n", 
			item->hash, 
			item->path, 
			item->is_ok);
		return -1;
	}
	item->pos = 0;
	return 0;
}

static int tinfoil_stat_alloc(slowboot_validation_item *item)
{
	if (
		vfs_getattr(&(item->fp->f_path), 
			tinfoil.st,
			STATX_SIZE,
			AT_STATX_SYNC_AS_STAT
		) != 0) {
		printk(KERN_ERR "Cannot stat:%s\n",
			item->path);
		return -1;
	}

	item->buf_len = tinfoil.st->size;
	return 0;
}

static void tinfoil_close(slowboot_validation_item *item)
{
	filp_close(item->fp, NULL);
}

static int tinfoil_read(slowboot_validation_item *item)
{
	size_t number_read;
	number_read = 0;
	
	item->buf = kmalloc(item->buf_len+1, GFP_KERNEL);
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		return -1;
	}
	memset(item->buf,0,item->buf_len+1);
	
	
	number_read = kernel_read(
		item->fp,
		item->buf,
		tinfoil.st->size,
		&(item->pos));
	if (number_read != item->buf_len) {
		kfree(item->buf);
		return -1;
	}
	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "StoredHashFail:%s\n", item->path);
	}
	kfree(item->buf);
	return 0;
}

typedef struct sdesc {
    struct shash_desc shash;
    char ctx[];
} sdesc;

static sdesc* init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static void tinfoil_check(slowboot_validation_item *item)
{
	struct crypto_shash *alg;
	sdesc *sd;
	unsigned char *digest;
	int j;
	
	alg = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(alg)) {
		printk(KERN_ERR "Can't allocate alg\n");
	}
	
	digest = kmalloc(64, GFP_KERNEL);
	memset(digest,0,64);
	sd = init_sdesc(alg);
	
	crypto_shash_digest(&(sd->shash), item->buf, item->buf_len, digest);
	for(j=0;j<64;j++){
		if(item->b_hash[j]!=digest[j]) {
			item->is_ok = 1;
		}
	}
}

/*******************************************************************************
* Open file, read contents, hash it, compare, log state, free                  *
*******************************************************************************/
static int tinfoil_unwrap (slowboot_validation_item *item)
{
	if (tinfoil_open(item) != 0)
		return 1;
		
	if (tinfoil_stat_alloc(item) != 0) {
		tinfoil_close(item);
		return 1;
	}
	
	if (tinfoil_read(item) != 0) {
		tinfoil_close(item);
		return 1;
	}
	
	tinfoil_check(item);
	printk(KERN_INFO "File:%s:%s\n", 
	       item->path, 
	       (item->is_ok == 0 ? "PASS" : "FAIL"));	
	tinfoil_close(item);
	return item->is_ok;
}

/*******************************************************************************
* This section contains dynamically generated functions numbered 1-infinity    *
* It will simply register the hash/path for each file to be validated at the   *
* correct location in the array                                                *
*******************************************************************************/
//##########TEMPLATE_PARM_FN##################################################=>
static void svir_1(void) 
{
	svi_reg(&(tinfoil.validation_items[0]),
	        "c035b7772981c9422868e0d5026b198bb9366c345e4372a8ed549297b5a56339d343d20587b25336168dc613cf957626a56498c261b66efc2e01536f39423736",
	        "/usr/share/terminfo/v/vt220"
	);
}
static void svir_2(void) 
{
	svi_reg(&(tinfoil.validation_items[1]),
	        "a6541c0c25cb53b2dd980972d2cd8138ffd0fde4e8f5f0085b5980ca6084d69d8548fef50cb4b39033a0d02a1565c65d90fc25bedf2564e8bb5d92dfda3ab383",
	        "/usr/share/terminfo/v/vt102"
	);
}
static void svir_3(void) 
{
	svi_reg(&(tinfoil.validation_items[2]),
	        "bc005e7d1e8126b0bec4e78861cf49223eca0d313ee2a78181f993adb634d20afc1e4462694d2e859ac3be78c38b44420d3bb71273e8e4bb261b218241749138",
	        "/usr/share/terminfo/v/vt100"
	);
}
static void svir_4(void) 
{
	svi_reg(&(tinfoil.validation_items[3]),
	        "972f753448d95bca266a3af848c7345efb917c97a15ea267415b48db538ab8fa11484dac029236c8f6c26f5e9f9683a9d9d6df54c9c75d6bf1f66cccad27834f",
	        "/usr/share/terminfo/l/linux"
	);
}
static void svir_5(void) 
{
	svi_reg(&(tinfoil.validation_items[4]),
	        "a961b2652d17699499d505ae4f07ea2a8c1fd7c1bf65732ce9da09bf282960ed8b7f7f3bf7c73d656d8fe36aac8c9d6e9601148a94d9f18115a93cb7c7a296c5",
	        "/usr/share/plymouth/themes/text/text.plymouth"
	);
}
static void svir_6(void) 
{
	svi_reg(&(tinfoil.validation_items[5]),
	        "fce070efa969fbab80f87d3433b34a357c52abd6df37559c77e6e77b194baf8fc0326682a71a5aca7b6ff0b81b2c1e03a43d3a217be7b44d14beb11c19e09956",
	        "/usr/share/plymouth/themes/spinner/watermark.png"
	);
}
static void svir_7(void) 
{
	svi_reg(&(tinfoil.validation_items[6]),
	        "b1923ec035c6c165e7974ef1a22bd5d4614df891a35c9f2ec6d476a1026eb1f574d776f0cc5a7f08b33ef83024ea4e4ede74793d469779c03e093aebf5b446b7",
	        "/usr/share/plymouth/themes/spinner/throbber-0030.png"
	);
}
static void svir_8(void) 
{
	svi_reg(&(tinfoil.validation_items[7]),
	        "12e6ee64a5c6b563219d4964f2b6e634a2337101842c95054d719e595c05afac5d35fe57cb8d7d5615c97664feff12b72b092e62b9e4b97ae45f484bcd1985b9",
	        "/usr/share/plymouth/themes/spinner/throbber-0029.png"
	);
}
static void svir_9(void) 
{
	svi_reg(&(tinfoil.validation_items[8]),
	        "e8d116ad4214cf1298d7f196b58fa8b37f6d58d83695b38179cf48e28f0b299823b3661a214b731c846dc2a0840e68ec42dc3f5545688360cd16dcf0bc7e7830",
	        "/usr/share/plymouth/themes/spinner/throbber-0028.png"
	);
}
static void svir_10(void) 
{
	svi_reg(&(tinfoil.validation_items[9]),
	        "7203d0f60ca0a8827a95b50f93c139b1fcb10a1969d9a916f379e36cca6846b2d5f475e4ac6c80cc60cc2b582261634e1dd4056cbb3a6d5724e0f6bec28d8a74",
	        "/usr/share/plymouth/themes/spinner/throbber-0027.png"
	);
}
static void svir_11(void) 
{
	svi_reg(&(tinfoil.validation_items[10]),
	        "a113e08eec5fa2ee8759021ea276b3aee63fdff37d7463901549bb96ba07f9804edf532ac3b8076406e188daa0a55c96b4a82ebf8be8a05474c7e176fa5eeb12",
	        "/usr/share/plymouth/themes/spinner/throbber-0026.png"
	);
}
static void svir_12(void) 
{
	svi_reg(&(tinfoil.validation_items[11]),
	        "fef0e98459534e8c625070f1bcd565beefe51e0397cfc64d7a3d4d9be9edc06c0d43ac349fefc2ce5712768aa8f3aba9b014969ee09cc5f0ab1fcd9c2be573c0",
	        "/usr/share/plymouth/themes/spinner/throbber-0025.png"
	);
}
static void svir_13(void) 
{
	svi_reg(&(tinfoil.validation_items[12]),
	        "eeec298e69ac5b4fc0aa4f823788c60d9ca5f3468709691fdada2e532931696e51f892f39ebc7b3798aeb1dd372943af856493cffd5743caae1b732ddb48219a",
	        "/usr/share/plymouth/themes/spinner/throbber-0024.png"
	);
}
static void svir_14(void) 
{
	svi_reg(&(tinfoil.validation_items[13]),
	        "08524b9508455fe0ea938f533d82f5ca903c6e203128e5dde7fd010fd57f0c86f1e761a86b7a2dfa09acf5788c2ba076a31abf919eacbabd2c78a3cf04120836",
	        "/usr/share/plymouth/themes/spinner/throbber-0023.png"
	);
}
static void svir_15(void) 
{
	svi_reg(&(tinfoil.validation_items[14]),
	        "7d7b3cc2571d4cd2c2a9fd2cfe9558592567e1fb5d7759dd729858e00f4f2a43e898cc079041af5e9728bfc0b0a8b999fce49032889c6ee1238d277db29c2e12",
	        "/usr/share/plymouth/themes/spinner/throbber-0022.png"
	);
}
static void svir_16(void) 
{
	svi_reg(&(tinfoil.validation_items[15]),
	        "e631da70861aff376bc2797bc4b3ac241c984325397965f20cec2430944810f9aa86a93d5ede6182d7d65a95ca4514c36fb77da471b59fb967ebf72fec3ebd7c",
	        "/usr/share/plymouth/themes/spinner/throbber-0021.png"
	);
}
static void svir_17(void) 
{
	svi_reg(&(tinfoil.validation_items[16]),
	        "7f9779e2709d82c830152cc7d27f652be812c934c89be9e3889930586826eee5ef1f0823bf0f5efad3b9495fe19f058b9cc2e3b84083c36f92bf8ffb35bf5fc9",
	        "/usr/share/plymouth/themes/spinner/throbber-0020.png"
	);
}
static void svir_18(void) 
{
	svi_reg(&(tinfoil.validation_items[17]),
	        "5432435a10f7b2da5e6be2376bbc6da43f666d748e2f1b5827023b0bfa6f045d8f95e998cff07f5b4bb82c4c0a033fdb5bf42e7dc6c91dc0d0aa86cdb40b76df",
	        "/usr/share/plymouth/themes/spinner/throbber-0019.png"
	);
}
static void svir_19(void) 
{
	svi_reg(&(tinfoil.validation_items[18]),
	        "c454bc5a3a83a7c2d257f733eb0921bc6799f1b0de03a950f7bea98a2721e6103f94fd29f4a5bde8d806d19b760ecac8cc567ce8501e251bc7cac0c5b352e3d5",
	        "/usr/share/plymouth/themes/spinner/throbber-0018.png"
	);
}
static void svir_20(void) 
{
	svi_reg(&(tinfoil.validation_items[19]),
	        "17bf6ff01b0e4469e07b3e427e09fe1096d5514ca7091986e510299abcd85de59780d1085d666536b582fcc5c98b850f6a6261e6e1a4de568b801ca463e2228d",
	        "/usr/share/plymouth/themes/spinner/throbber-0017.png"
	);
}
static void svir_21(void) 
{
	svi_reg(&(tinfoil.validation_items[20]),
	        "66d74d693acb427b4f936482a65adb23417e22ec31b4dc5dd39253ee7f2add2cc93962bdd506e2583529da5f51ee8a584d43039caafbf3b242317f20373e65f9",
	        "/usr/share/plymouth/themes/spinner/throbber-0016.png"
	);
}
static void svir_22(void) 
{
	svi_reg(&(tinfoil.validation_items[21]),
	        "0d2bc126006af4398162e5f4d2acaca000e817508a6cc485836b3068c6f84cebc909663daecdf9e5ad5ae09fe6a9a405b6ad0f0f2535595c2720d256091a9c4f",
	        "/usr/share/plymouth/themes/spinner/throbber-0015.png"
	);
}
static void svir_23(void) 
{
	svi_reg(&(tinfoil.validation_items[22]),
	        "59178d4fbdee855e10d9f65b7beb221c63ca8cb4f1e887aae74674c7f369733689a2f6b3d147d35d000b7b312b464757d207d038581612150ceb9c496eab516b",
	        "/usr/share/plymouth/themes/spinner/throbber-0014.png"
	);
}
static void svir_24(void) 
{
	svi_reg(&(tinfoil.validation_items[23]),
	        "be2a2bfac29506e33f31b4b4ada51f733b8188f7a0c42b893defeeb9d8c5c779fff6ffe852d18bcb5970b6291ce077f27495711688908f7a249fc0b6e51114f7",
	        "/usr/share/plymouth/themes/spinner/throbber-0013.png"
	);
}
static void svir_25(void) 
{
	svi_reg(&(tinfoil.validation_items[24]),
	        "98760af1d20315d540b88d04d0f94e845606c0f72f0331f058d3be2e88da9bf558da74f2be18ac3f1e133dcae629f8a541b76e9138e9f1571301829c8c6a8186",
	        "/usr/share/plymouth/themes/spinner/throbber-0012.png"
	);
}
static void svir_26(void) 
{
	svi_reg(&(tinfoil.validation_items[25]),
	        "5f2d4af4f8acb3e82efade39886396b5580bbeff1e30d2b76e0b871ab02668cc805fd76f447d3c751bfa031fc35736eb7871b0eaff4ed9d6c18f7c2dca740992",
	        "/usr/share/plymouth/themes/spinner/throbber-0011.png"
	);
}
static void svir_27(void) 
{
	svi_reg(&(tinfoil.validation_items[26]),
	        "b49936f4124d3bc8b8edcd9f2c0a4fb6f5170b59507ef42610bc37f7c3cffb5ae1d90aacefe8e5acb8411889f0e945e0401e81b8f82e3eb0469121b929fd89d8",
	        "/usr/share/plymouth/themes/spinner/throbber-0010.png"
	);
}
static void svir_28(void) 
{
	svi_reg(&(tinfoil.validation_items[27]),
	        "3a289690980480df10cf023b68efb25f2fb01ab5f47c003175e7a914b591c0089ec30fffc5a793582936274179d1317c043149a351d259101fbb26a67fc671de",
	        "/usr/share/plymouth/themes/spinner/throbber-0009.png"
	);
}
static void svir_29(void) 
{
	svi_reg(&(tinfoil.validation_items[28]),
	        "bfc375172ca066ac8d0e17e9f7fb0505ac8d746ac65f818caffad73c5720b26a9c77c9e2991702647aedf963ffeec01238f4a26e8dc89245db6d0e281aec641a",
	        "/usr/share/plymouth/themes/spinner/throbber-0008.png"
	);
}
static void svir_30(void) 
{
	svi_reg(&(tinfoil.validation_items[29]),
	        "1bdf0acd26c814ee4324e32cb10d20e6c3fd82e5d67bea9dff4abecbbb64c114b0e13c4a67d26d6748e1282b3bad0eaa7a8490a9bef957ba85e443458132530e",
	        "/usr/share/plymouth/themes/spinner/throbber-0007.png"
	);
}
static void svir_31(void) 
{
	svi_reg(&(tinfoil.validation_items[30]),
	        "868850a42a327b268587211bf94a97f5c9ed3ee39cd966aaf0e7fd00c15f36c8af5161b12325ea4add4c6c5c126b84ef5383af0928dff8c5f40a912badcb1d51",
	        "/usr/share/plymouth/themes/spinner/throbber-0006.png"
	);
}
static void svir_32(void) 
{
	svi_reg(&(tinfoil.validation_items[31]),
	        "2c645f60b4d2237c6a756164ed853943891321f81cf65bd059bca36dbad2d2f4272a80b27135700faba866c2f7cf3399b646d39674834cf4a3937090639dcdb1",
	        "/usr/share/plymouth/themes/spinner/throbber-0005.png"
	);
}
static void svir_33(void) 
{
	svi_reg(&(tinfoil.validation_items[32]),
	        "da6ae889315579ed46a3da8d611dd6b3505c97f1570d700866d8a4eddb41073cb4e8aa05ddb0a2d9b6e4154703dfbb9cdc51591a1f21002e86dc4b6099ffc47b",
	        "/usr/share/plymouth/themes/spinner/throbber-0004.png"
	);
}
static void svir_34(void) 
{
	svi_reg(&(tinfoil.validation_items[33]),
	        "6fc97b707501f62561907b5dbd5012394713bab1b0aae8c5b3a466af403ee26ebe8a732d74e8c6bccd82de9aa21edac60fb618af86e979b0f999a50e2fe18086",
	        "/usr/share/plymouth/themes/spinner/throbber-0003.png"
	);
}
static void svir_35(void) 
{
	svi_reg(&(tinfoil.validation_items[34]),
	        "105f2e8f1432ab24afe4a629d8f2cdcd66fa633265a2db6926a3040e805405f7394dfa034617063e13581c094d9b6bfd975123a0f7bb5268ffa72dbc7e3d8488",
	        "/usr/share/plymouth/themes/spinner/throbber-0002.png"
	);
}
static void svir_36(void) 
{
	svi_reg(&(tinfoil.validation_items[35]),
	        "3d55e9d861b0074676ba1e13f6a2f8414f08071d600b4676fe49e142709e90f2257413a8f120aa8703eaa37bd558314763533666e61ff22300b2fc8165464591",
	        "/usr/share/plymouth/themes/spinner/throbber-0001.png"
	);
}
static void svir_37(void) 
{
	svi_reg(&(tinfoil.validation_items[36]),
	        "a7fc451b4ef5b414cf4e126d0f46723989b9a4b522326cfa33de5ad12ac0ab429c67d1d6a2205840ff4eea41ee3af3101aadb9a975b72c51cf79865c328dcf5c",
	        "/usr/share/plymouth/themes/spinner/spinner.plymouth"
	);
}
static void svir_38(void) 
{
	svi_reg(&(tinfoil.validation_items[37]),
	        "08849601bbd638a2d1ae473e55784d8e0c86a5f16ae0b8fa2704aa927e31ed11237eeedc90b680b0083bbbc9fa7bf711de1747cea8f3b137133b7ea48cf741d4",
	        "/usr/share/plymouth/themes/spinner/lock.png"
	);
}
static void svir_39(void) 
{
	svi_reg(&(tinfoil.validation_items[38]),
	        "afca722b4f5572f2a19a5f6ca02bcba5c62af97b1a8ada7014e5b3954ecd0d5bcbe0eabd885dcaa094dd1c9106a443922d103f052f2506efb7a3bcd91d832c55",
	        "/usr/share/plymouth/themes/spinner/keymap-render.png"
	);
}
static void svir_40(void) 
{
	svi_reg(&(tinfoil.validation_items[39]),
	        "3f9302ca97a010614d41c5de3c71945756c236d2c01dd5c143ab33d6bc28c229ce2ac88fbdf25ed847b77cb06b145d72c75e74781fcd72da65c4dec02622b4af",
	        "/usr/share/plymouth/themes/spinner/keyboard.png"
	);
}
static void svir_41(void) 
{
	svi_reg(&(tinfoil.validation_items[40]),
	        "86eb713d9801990fda0992f363dd334d915067556c7ec2cc84a56d8a0bd87206124d0f7d567d1c650cc19af0596deb2b821979a94b9b0fdaa842c31e46f5d5b6",
	        "/usr/share/plymouth/themes/spinner/entry.png"
	);
}
static void svir_42(void) 
{
	svi_reg(&(tinfoil.validation_items[41]),
	        "770458b1448dae61ae79371d75ed110cfddbb644a9bca2301b862929cddc54674ba53feb51d1be6227cd7e4c7a5739e8eccc94217dcc48323b4e9242e563eab3",
	        "/usr/share/plymouth/themes/spinner/capslock.png"
	);
}
static void svir_43(void) 
{
	svi_reg(&(tinfoil.validation_items[42]),
	        "f71ea0719aa765a04453ab8f7afec97229b30875b08397931f9b3920784fc7d462913eca0b524033e8dac1381e2e7fe213966eb4d657f492f51b4c215230ec7a",
	        "/usr/share/plymouth/themes/spinner/bullet.png"
	);
}
static void svir_44(void) 
{
	svi_reg(&(tinfoil.validation_items[43]),
	        "00693927f294e6ae90bc1aef9a0859f9977df17337446f772ed80154ac3e498e4c9bb897d96008ab34be26fc2c8cf986b0202229e8085de41d0f58af31576718",
	        "/usr/share/plymouth/themes/spinner/animation-0036.png"
	);
}
static void svir_45(void) 
{
	svi_reg(&(tinfoil.validation_items[44]),
	        "6900b91031f35fe90e5eaa0379cb499074c1b1a49fd7f3c467f59af27818d9ecd812ea40cc30a2902ccfa658bdebbc7a72be3c2b1b0e3ad54778c1a7650be898",
	        "/usr/share/plymouth/themes/spinner/animation-0035.png"
	);
}
static void svir_46(void) 
{
	svi_reg(&(tinfoil.validation_items[45]),
	        "c4e8f6b624b38b62c597f19e5a332034d64295312cab4e7c1b7446728d8947ee3341084a6709f61fb17e2ccd165c3ed17cc681b6d121887d8f979f82ab208427",
	        "/usr/share/plymouth/themes/spinner/animation-0034.png"
	);
}
static void svir_47(void) 
{
	svi_reg(&(tinfoil.validation_items[46]),
	        "4d58ca2445388d8dc27b82290d3e0a1d27e4703985afc131a6f1d58ac052306fd22bc2f438af2e878f09216c969f510f2b27cf318f618067054f909e4b4d37a7",
	        "/usr/share/plymouth/themes/spinner/animation-0033.png"
	);
}
static void svir_48(void) 
{
	svi_reg(&(tinfoil.validation_items[47]),
	        "6ed55230cbb5d3a639cf90be99c2274d938b54a2a6078fdf05f9cd5e1383c2261fcc83dbfcfab9610249d174a15e72f00edea9156f39c27a045203c5cadda332",
	        "/usr/share/plymouth/themes/spinner/animation-0032.png"
	);
}
static void svir_49(void) 
{
	svi_reg(&(tinfoil.validation_items[48]),
	        "53cbe6e7d5b05abb7d0120335405d22d1e074703e84d82d2be9a37c754ea4b6dab7aa88aa37be02773429dbadee00186a2a6e6592333fbe03393b0c8f6254d6e",
	        "/usr/share/plymouth/themes/spinner/animation-0031.png"
	);
}
static void svir_50(void) 
{
	svi_reg(&(tinfoil.validation_items[49]),
	        "4cc578d9d6289bcb4ceae12b8135b4ac758c692ea5b5665fe9ac01da9ef59b15763d0a420af8cb0106b2b34d931b4c2fd3fea2c67edd762a5cd1ea6b8c6c26e1",
	        "/usr/share/plymouth/themes/spinner/animation-0030.png"
	);
}
static void svir_51(void) 
{
	svi_reg(&(tinfoil.validation_items[50]),
	        "cfe60569b57c5e387ff12483509bb258e90a3164fd2e6385064531710aeb5ee3da6242e3944a9d4fe3ce214443ed56ce5d2b9cd0e06bc85a1aefd1f5b5fe935d",
	        "/usr/share/plymouth/themes/spinner/animation-0029.png"
	);
}
static void svir_52(void) 
{
	svi_reg(&(tinfoil.validation_items[51]),
	        "7510f90a6bcfdaaab3b9916de31a8fcd2cb255975ac34ac031e16a2428de11a106d3d2b0e3e7ba42acc31ce2ae8e97c2bf6929bb14d9c651f6032ac3a328adc5",
	        "/usr/share/plymouth/themes/spinner/animation-0028.png"
	);
}
static void svir_53(void) 
{
	svi_reg(&(tinfoil.validation_items[52]),
	        "3408b01af5170e23ef4abe7cb197060c61630fee108312dc09fb7d1e10031937f844a7a0b696493403bc925b96271e0e2d0c50453556dc7c34576c336a7b1c80",
	        "/usr/share/plymouth/themes/spinner/animation-0027.png"
	);
}
static void svir_54(void) 
{
	svi_reg(&(tinfoil.validation_items[53]),
	        "a9738e4e31e3a7fe0abf401f0e2ffb52e77c6dd5a7ddc4c32fb90ab8bac30dbd45d4c7da7298df1dd7411c49304bb36d400357314c9103d8e693668746d6c49b",
	        "/usr/share/plymouth/themes/spinner/animation-0026.png"
	);
}
static void svir_55(void) 
{
	svi_reg(&(tinfoil.validation_items[54]),
	        "7ddc255af968d476bcd5ed8dbe896fb9f4d42787720855365a7e5daeb84e63507a9cef2bc8252806f0ba9bcd062153ee2760894aa61fe297105da154e28a5f00",
	        "/usr/share/plymouth/themes/spinner/animation-0025.png"
	);
}
static void svir_56(void) 
{
	svi_reg(&(tinfoil.validation_items[55]),
	        "08e5c7229ec3ccc03833dd531cb0333f038253bb485605234baa74bad60a2ada99468ed4bda1fb99bcd2b8ba9d787649d7ab320d9be1db3f0a6cfb4aed06d839",
	        "/usr/share/plymouth/themes/spinner/animation-0024.png"
	);
}
static void svir_57(void) 
{
	svi_reg(&(tinfoil.validation_items[56]),
	        "26aa23c17af0282dbe8a2e19728ef02fa38c60410b960eda5e30a373f166dd28061c404dca245d53bce1758acab5c12f78dd419f016ea0425ce851b569fcb53a",
	        "/usr/share/plymouth/themes/spinner/animation-0023.png"
	);
}
static void svir_58(void) 
{
	svi_reg(&(tinfoil.validation_items[57]),
	        "4721bad3b79cc6d853dbc7c1408fabb7c498dec4fd27758779b7f919fb329117d6e6c64a8f3281d9e9c22dbc4f334d2c9d0763ff368811d913178a6a3f973815",
	        "/usr/share/plymouth/themes/spinner/animation-0022.png"
	);
}
static void svir_59(void) 
{
	svi_reg(&(tinfoil.validation_items[58]),
	        "d7d3bcfd32627b646e409b691a678aca49883c336a4dad43694b527b27ca68d21b1cee30522d67f7589641df7061e079245d16c3b777b5129cc2ebeeb535920c",
	        "/usr/share/plymouth/themes/spinner/animation-0021.png"
	);
}
static void svir_60(void) 
{
	svi_reg(&(tinfoil.validation_items[59]),
	        "fabefcc7c1e31185051e2237016d5c39a8ce412f5fb775cf96ca9eab76e0f18507ef8de648a026790567624e90704b5049b80ff441b729d170bb23ba36a0e290",
	        "/usr/share/plymouth/themes/spinner/animation-0020.png"
	);
}
static void svir_61(void) 
{
	svi_reg(&(tinfoil.validation_items[60]),
	        "518b9bbbd966e501884743e7d44a0d28db07245229821910b6660620f2a588ea14a599fae26c55b045ccde618d702e3314f73d2244d7f2df8a048acd2bcfb0e7",
	        "/usr/share/plymouth/themes/spinner/animation-0019.png"
	);
}
static void svir_62(void) 
{
	svi_reg(&(tinfoil.validation_items[61]),
	        "d9cd1de544e62a40f48d506811fc2260d626f999f51ab500b2d5fbdb63d4606e05e00d003e5532eca1744d754c2b2e18ae50268fb45a0979fd7f6ae32b43fbb7",
	        "/usr/share/plymouth/themes/spinner/animation-0018.png"
	);
}
static void svir_63(void) 
{
	svi_reg(&(tinfoil.validation_items[62]),
	        "509100f1d75af5fba4d0240b25998879ff2c52fdaedbbc6d8d532bf88f45a6a11e6d9f09c605f176a857d064740fd64f0ee81fff0d4a691e2b2e78b2830b9383",
	        "/usr/share/plymouth/themes/spinner/animation-0017.png"
	);
}
static void svir_64(void) 
{
	svi_reg(&(tinfoil.validation_items[63]),
	        "84864e3ed2456b5fc54455615fb5bc1e54cc137b4bcacab8f9275dcb8c742bdd09e6f1eba2134ff69c92947f2b3de3ac2c026e32d00f14c460a23374a23e108a",
	        "/usr/share/plymouth/themes/spinner/animation-0016.png"
	);
}
static void svir_65(void) 
{
	svi_reg(&(tinfoil.validation_items[64]),
	        "cf200fb0a9bfbfba248d37c40a6262441177bd68cb8b4a533a2c8291297be3a6de5b2828598979db2f6c6b3a20c2e880169045a5e2c39d03d1da1c97da6ad0d9",
	        "/usr/share/plymouth/themes/spinner/animation-0015.png"
	);
}
static void svir_66(void) 
{
	svi_reg(&(tinfoil.validation_items[65]),
	        "74f1058131a0ae4ca697b505c0809fae2b79a3f725b49890e05f702652cae412aceb6c762d70f423f914e196d7230633540b1de0923dc7a9ed3149a635d01962",
	        "/usr/share/plymouth/themes/spinner/animation-0014.png"
	);
}
static void svir_67(void) 
{
	svi_reg(&(tinfoil.validation_items[66]),
	        "d0c93239692b0efc49ad3f154d8bda442753b52e446bfa508cbf19b02e7199c47308ccc9f3dd799f1b3feef42f867600e799744d586e6e86e7c7d9d50b66ab76",
	        "/usr/share/plymouth/themes/spinner/animation-0013.png"
	);
}
static void svir_68(void) 
{
	svi_reg(&(tinfoil.validation_items[67]),
	        "d7dfd8a34512ba270797d723601b7193a759bb86e6a7b5fac567bab343e6d554bfad41c352aaf8586e4f31c77ced33140e9e373ae74e898683756e6bd7f3c910",
	        "/usr/share/plymouth/themes/spinner/animation-0012.png"
	);
}
static void svir_69(void) 
{
	svi_reg(&(tinfoil.validation_items[68]),
	        "4d7ba333e8ea9eca70a10acbefcfcd7c91be2794db1236a608f2f0f7c78d44dbde900ab18812c8aa20f25b5ed04792e76f1d72d1b7a7a2ff92fda932ed91ac9c",
	        "/usr/share/plymouth/themes/spinner/animation-0011.png"
	);
}
static void svir_70(void) 
{
	svi_reg(&(tinfoil.validation_items[69]),
	        "c510542f1d935a4374bdb3f200fc231bc9c75b72f60f233d5b7b7295cfd01fe42c75998efcbb6674dbf96f6344543e16f6957bb0b51399eca28b45dfdc263648",
	        "/usr/share/plymouth/themes/spinner/animation-0010.png"
	);
}
static void svir_71(void) 
{
	svi_reg(&(tinfoil.validation_items[70]),
	        "91687b5434e22bbf5003750a2400ade7fd5cf2d3a7073577e539c419b7280f2bb88f9c689706233c76c9e7f80865018afc1a2097e7e61ff47ee4a08ee164641d",
	        "/usr/share/plymouth/themes/spinner/animation-0009.png"
	);
}
static void svir_72(void) 
{
	svi_reg(&(tinfoil.validation_items[71]),
	        "044055b73c058022080bc56436469ee51884d1af1c54619d6d1734f7c0da94b2316389111d4faf7458c075edcd409606ae025c28e2cbbd60f3037fd6f180f017",
	        "/usr/share/plymouth/themes/spinner/animation-0008.png"
	);
}
static void svir_73(void) 
{
	svi_reg(&(tinfoil.validation_items[72]),
	        "d2a17707c6f83bd081b3491cb40e5295b729713bdb29b9418dd8cd19b905a28164487fb57fea6a55f1d1882a0b433a1407680a05d6192db0d256cf1a6805a289",
	        "/usr/share/plymouth/themes/spinner/animation-0007.png"
	);
}
static void svir_74(void) 
{
	svi_reg(&(tinfoil.validation_items[73]),
	        "8f8107982fbbcfd08cfe46d7167469211d8f2c2abdd1f888975737280ef7a2e2499cc81a3554d9d9d524d6509248eb59ccdb3f7171e1f2dbcffeb38135c52b4c",
	        "/usr/share/plymouth/themes/spinner/animation-0006.png"
	);
}
static void svir_75(void) 
{
	svi_reg(&(tinfoil.validation_items[74]),
	        "2ff905b3a2000438ec1703478182e98bdef3369cd5078431728449eef09082876a0e7a0e0952550d974590a18e3e2ed04927823d4aafe9a62650e273ee069cbc",
	        "/usr/share/plymouth/themes/spinner/animation-0005.png"
	);
}
static void svir_76(void) 
{
	svi_reg(&(tinfoil.validation_items[75]),
	        "bf65da52d2cc369f40aa127096eebfc41ec380fdd8fc8ecc097a8c1c925616e2da9baa91285fc15aa0f6fb88ae850c6d94a61f1a62707e23fc0b4e1deb6ebb77",
	        "/usr/share/plymouth/themes/spinner/animation-0004.png"
	);
}
static void svir_77(void) 
{
	svi_reg(&(tinfoil.validation_items[76]),
	        "e33313cddd70f00011c747f76fa62aa7890c606a7a18e69d29198bbb009ae220e7d82a30cdaeed22cf96595d2688abc427eb8b22d06eebadbcf74af32837deae",
	        "/usr/share/plymouth/themes/spinner/animation-0003.png"
	);
}
static void svir_78(void) 
{
	svi_reg(&(tinfoil.validation_items[77]),
	        "6906205982769b35ed8becc6507d648c868f9dfabb772e4015054541609b1c3504de7756cf3b0f241d0b470c9fbbafe3b2fc30ff982c53f2c10d9926dd90fdc3",
	        "/usr/share/plymouth/themes/spinner/animation-0002.png"
	);
}
static void svir_79(void) 
{
	svi_reg(&(tinfoil.validation_items[78]),
	        "fcb43df01ed6683f97a082f73d72ae19f6b1a18938bdd5be76fa9aad9fabdfcecbf5691bfe4a9016d9cb7851357745677b332c9db19462cc1a163234d54c6818",
	        "/usr/share/plymouth/themes/spinner/animation-0001.png"
	);
}
static void svir_80(void) 
{
	svi_reg(&(tinfoil.validation_items[79]),
	        "5d245490bd1e2c5be7e8cee2cf1b3f36aa676a6f99b3c412bb9ee090234ae910a98c6bbb9b139ae5fef3d8d798bf6333c784f70713f2183aafec4d71f872f7cd",
	        "/usr/share/plymouth/themes/details/details.plymouth"
	);
}
static void svir_81(void) 
{
	svi_reg(&(tinfoil.validation_items[80]),
	        "75e3d6d943c769f4982bd5bf400321986910978f50a698f97665eb6901d7e422893d7973b4df23556d8dee1f475748ea29a114c42da44759d058fda6d469c222",
	        "/usr/share/plymouth/themes/bgrt/bgrt.plymouth"
	);
}
static void svir_82(void) 
{
	svi_reg(&(tinfoil.validation_items[81]),
	        "d15a5fdc10d0ef2df9e7578c30e657fa57342d951534082479c000c9681e24626f9900299de1506f854781461c1118d48c4309f8ebb5118d30c0dc53a5829960",
	        "/usr/share/plymouth/plymouthd.defaults"
	);
}
static void svir_83(void) 
{
	svi_reg(&(tinfoil.validation_items[82]),
	        "2e7868963b4d1acc551367d42eb831711e455f43578040e238e9a6b88022b6d2161d30cff70deac6123d1214aad0d1edbfe037cb77c57e4942fa4fb360217916",
	        "/usr/share/pixmaps/system-logo-white.png"
	);
}
static void svir_84(void) 
{
	svi_reg(&(tinfoil.validation_items[83]),
	        "04b2978e1d6f0c1ce15d205ff2011031d16ed862c8da0043b41137c4568b197712e97d850cf8764389bf8473df81ad96ddc1b8fd9ddbb6e5320c5f9c2c2c3181",
	        "/usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf"
	);
}
static void svir_85(void) 
{
	svi_reg(&(tinfoil.validation_items[84]),
	        "4d8ff0c458ffafc6db658dddc41359ff3378d1033e2981924418d719ff076b63ec0d60013e2130e94876b6bd13c83883149213187df341bf85c3917422ed23a7",
	        "/usr/share/dbus-1/system.d/org.freedesktop.NetworkManager.conf"
	);
}
static void svir_86(void) 
{
	svi_reg(&(tinfoil.validation_items[85]),
	        "1b14e62c2db0b223eb972db9077f39467c12a42ab37d91927b28897038b5077455b56c555bb6888d3ea748dfa9537058624fee9de06b2f4125df63e82b825ad6",
	        "/usr/share/dbus-1/system.conf"
	);
}
static void svir_87(void) 
{
	svi_reg(&(tinfoil.validation_items[86]),
	        "801cb1dda581ca509f365deb1353461d4a2c025d002a0860560e230ce3e26949d81a56c059e8b7c4f1b27e0b90c82a2dfd9539cdc68746cae0b9a4ffa7a89a12",
	        "/usr/share/dbus-1/system-services/org.freedesktop.systemd1.service"
	);
}
static void svir_88(void) 
{
	svi_reg(&(tinfoil.validation_items[87]),
	        "98929b66ebe93fcc272e3d0ff65fb7e41a6eb69fb9f4529da2b55453ba81d6c8b2614e89510ea538e18fcc924d21e76f76fdf4b610524fe4fd21d51aa466cb51",
	        "/usr/share/dbus-1/session.conf"
	);
}
static void svir_89(void) 
{
	svi_reg(&(tinfoil.validation_items[88]),
	        "0bfb28fbeacce74902a92234b6ce38e911923986a76468d0a7ebaaa66b6f144e43b143819c46b467b97383768c8e15ea1e09a305ae9d347c0f14936327de9815",
	        "/usr/sbin/swapoff"
	);
}
static void svir_90(void) 
{
	svi_reg(&(tinfoil.validation_items[89]),
	        "727123f197e62f4397c928cf3f7feea2cad47515a6a73e1af965a7166a4529c02e8588f985db59b4cbfcebec1b87897840e287da4b520f60c870cd678da8a62d",
	        "/usr/sbin/sulogin"
	);
}
static void svir_91(void) 
{
	svi_reg(&(tinfoil.validation_items[90]),
	        "1dbf433d6b5ea6250e085f2ce22a44eae9f9de24234867a5885e148fbf1899d88f94635dbd807d43e3cd7fcf978aae33d1f666e922867229087a35ef31b36166",
	        "/usr/sbin/rdsosreport"
	);
}
static void svir_92(void) 
{
	svi_reg(&(tinfoil.validation_items[91]),
	        "cc7d3ea6bff118e4f781e7cc98160323a81d96f06fe0501cb0425e7d7d1e9c2fde18dcc61f6775685be5ec5680ca5988fb81f51c30abe6ffe42bc4e6ed1735eb",
	        "/usr/sbin/plymouthd"
	);
}
static void svir_93(void) 
{
	svi_reg(&(tinfoil.validation_items[92]),
	        "b637db5ca66c2b80427d5fdc73ee276fc811bcee3033124163487e606c5d72590e7d53a8f0d88d154a3cb77fdd2bba077e3dc69045e72de9ca53ddf53b5105f0",
	        "/usr/sbin/plymouth-set-default-theme"
	);
}
static void svir_94(void) 
{
	svi_reg(&(tinfoil.validation_items[93]),
	        "86e7877f8065db1e3e85ecad559ccf7dc15c00006fd27f9eb30e0a892f7401be7bbe4113452e3e5bbe912fcd4e15fc4e6c2d564f1625a967497179da1453c6d6",
	        "/usr/sbin/nologin"
	);
}
static void svir_95(void) 
{
	svi_reg(&(tinfoil.validation_items[94]),
	        "2e6608d88c1c457a636a8e74e000e90699ebb2b4dcf86a2d31b8c36c3f47e7e761c49f42328bdbe7747a779d4728edacb4f0c6d64e7f1dbccbca4f669bd5019d",
	        "/usr/sbin/netroot"
	);
}
static void svir_96(void) 
{
	svi_reg(&(tinfoil.validation_items[95]),
	        "ff4f5364ac4a67de88d3988675eef8c35d7a6199a68a76e84e6e1b7a1d16f94822216f7ce5b088555537186fcbf549022a293f8dbd4401a745b9c913f0c93d3d",
	        "/usr/sbin/losetup"
	);
}
static void svir_97(void) 
{
	svi_reg(&(tinfoil.validation_items[96]),
	        "eef9b1a8ee72c4094d8575aaba8c7cab58b31f08839615268446dd4b8b9edf3b51c12800bbfe6d8c00d8296264dda12d3946075fe3f3f1463845eaa70ff1e926",
	        "/usr/sbin/loginit"
	);
}
static void svir_98(void) 
{
	svi_reg(&(tinfoil.validation_items[97]),
	        "fe59361e7ee38ec831c1878e73cd2f5e1f172a4f19c543e6f337d31934753189b91ce37852c385bc10c7adf19125aff65744f061f3acb5f9f4321563aceb1039",
	        "/usr/sbin/kexec"
	);
}
static void svir_99(void) 
{
	svi_reg(&(tinfoil.validation_items[98]),
	        "0aaa85942f9d493d00b6066678a068839f79d445bca57f821c88e90cb9569cea0f2bbd58f4af5eebf211ea6cd26bdceb8ee978b4251632342c93faa73e3dfc0f",
	        "/usr/sbin/ip"
	);
}
static void svir_100(void) 
{
	svi_reg(&(tinfoil.validation_items[99]),
	        "b2084eec74016bb1edac98ca78d9ee99255d9d95d3f860d702a929d9651ac4388af4107f44520cff757c153dae774219b8a43a2db271d8fbe8a6e1492bc9922b",
	        "/usr/sbin/insmodpost.sh"
	);
}
static void svir_101(void) 
{
	svi_reg(&(tinfoil.validation_items[100]),
	        "23f60be049539c63a5b008f5f6b1572d3176c4d5c61b8cc43cd34d38f2567e7593c07a638c2b618d26868606e8314504a8e03f1a53a3e6ecf04fc8a904f0dddb",
	        "/usr/sbin/initqueue"
	);
}
static void svir_102(void) 
{
	svi_reg(&(tinfoil.validation_items[101]),
	        "26b1c82026591a4737afbcf9057c5976344b89356b5bb6285da4cb72e4c62472e19e188e1c6e7a71fb40c081428752008b31883528e1b4056d7c53d2e72b093b",
	        "/usr/sbin/fsck.fat"
	);
}
static void svir_103(void) 
{
	svi_reg(&(tinfoil.validation_items[102]),
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        "/usr/sbin/e2fsck"
	);
}
static void svir_104(void) 
{
	svi_reg(&(tinfoil.validation_items[103]),
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        "/usr/sbin/fsck.ext4"
	);
}
static void svir_105(void) 
{
	svi_reg(&(tinfoil.validation_items[104]),
	        "c4ae2fd25c6619cc5c2f63ee5e9b94cd1ff8a3fe239f1df7fc84e4ede6b506fde673eb8c3fb7c287e8c2775f7ed1806f4984ac54a71187c8d66c72f3304e2404",
	        "/usr/sbin/fsck.btrfs"
	);
}
static void svir_106(void) 
{
	svi_reg(&(tinfoil.validation_items[105]),
	        "c3ea684a8031727c58d5de6b99d460848df480b2e823351d124e7775f0ffa87ceac3970e835064d2a764b37e0e6f59614b240287e4a22dd1930c53e1c0fa0d05",
	        "/usr/sbin/fsck"
	);
}
static void svir_107(void) 
{
	svi_reg(&(tinfoil.validation_items[106]),
	        "a1ad5646e9a645dcbbbd9d214a513c8f91a34a828f2c1b0fed756673ddce71a20f236838b0362e6b7b2100bf46470aaa7ab4b662341d663b22387e9d18ed8f54",
	        "/usr/sbin/dhclient"
	);
}
static void svir_108(void) 
{
	svi_reg(&(tinfoil.validation_items[107]),
	        "abe8d08a84d0487bf202006042f4ff706637e499d7b0f0bf6f06a20347607ae45be5f871fe1e561c522e98a97fc7fbdd599f7a595225cedc4cec94682b1603b3",
	        "/usr/sbin/chroot"
	);
}
static void svir_109(void) 
{
	svi_reg(&(tinfoil.validation_items[108]),
	        "bade5883b38d9340eec437adf5450e5f867c4ffc0cdb21a04ec200a46ef1b26ae746e6b954ebde4d063b91de5ba84bdd79bbb2f1aa2cce2dcd20b492965461fb",
	        "/usr/sbin/btrfs"
	);
}
static void svir_110(void) 
{
	svi_reg(&(tinfoil.validation_items[109]),
	        "1c5f9b600d70e169ddb59fa47886ec40f320faa7ef6e919b689af408c925067dc94fa7c77deedc89eda95d8cd5e1e2e744fb09968f6cd156faa627e3bb8b7580",
	        "/usr/sbin/blkid"
	);
}
static void svir_111(void) 
{
	svi_reg(&(tinfoil.validation_items[110]),
	        "1b455ef04b9e5264e70bb7bb1dd44d4a67404af48ac7ae8b6550e2fc6053de2c331a0a720aad06d0753dccae1709f100ac888eaa6902354d39aa520abc2bd557",
	        "/usr/sbin/NetworkManager"
	);
}
static void svir_112(void) 
{
	svi_reg(&(tinfoil.validation_items[111]),
	        "45714246af66f045609dc5f71d0f7e1aa7b2f693d02680b09903ad115b77771702c47cc8d4da63f68de92dcb79f04c3ac78dd8265c034a5fc4961474915a1bd5",
	        "/usr/libexec/plymouth/plymouthd-drm-escrow"
	);
}
static void svir_113(void) 
{
	svi_reg(&(tinfoil.validation_items[112]),
	        "3dd8b7283e0afde105a740434a46cf5816223c05d35431e369a0829ace1faf23a694a356ca833c0bfad0d1ec4f5cfb2dae0c8079d8d385c21463ee393563888e",
	        "/usr/libexec/nm-initrd-generator"
	);
}
static void svir_114(void) 
{
	svi_reg(&(tinfoil.validation_items[113]),
	        "72c3000d1e2b614451aaab0f9942ea621692fc26566ed799906a47417206999d24709508858d6be01f58f3fd66fa224528db32450088f68514f6a37d14b0391e",
	        "/usr/libexec/nm-dhcp-helper"
	);
}
static void svir_115(void) 
{
	svi_reg(&(tinfoil.validation_items[114]),
	        "30d79069725451b9af646080da1ed08e40cb9b2be6c13d14610470bce52eeb382ac0fc8c6891ebe0d70064d7e07caedf7cdc3760f6df56d781a2f061b88cd548",
	        "/usr/lib64/plymouth/two-step.so"
	);
}
static void svir_116(void) 
{
	svi_reg(&(tinfoil.validation_items[115]),
	        "02b8131594e00680e089a50b38ce803a1736f0a475cea767f2d75d90354e5b156d853c5d9b90c3dc6dd155fdc5eb1f3264f3a71694ed99960c3d5aafb19a124f",
	        "/usr/lib64/plymouth/text.so"
	);
}
static void svir_117(void) 
{
	svi_reg(&(tinfoil.validation_items[116]),
	        "9445de829d05ecebbd8c5cf2a03e3f62afc22803a5585bd7121122bcfcab3f0a17e2d6b59e915d0fe8a215c575d79f3736de995e977b20c7a148317264450cab",
	        "/usr/lib64/plymouth/renderers/frame-buffer.so"
	);
}
static void svir_118(void) 
{
	svi_reg(&(tinfoil.validation_items[117]),
	        "e63bc9ff0036c47eed2f72124731eeb674d94017218db672d2bc15969d23e68adabdb171744ae39c6c206f078c6a197063afa8261c9e4b70389a4f2e74097c6c",
	        "/usr/lib64/plymouth/renderers/drm.so"
	);
}
static void svir_119(void) 
{
	svi_reg(&(tinfoil.validation_items[118]),
	        "17da7b1a5b28d4c715c2af45d1cd7714696324b09805da3d3a9fda8193db01daee2b1e6d84686e9541d01fc2da89920d3b213988a466a5a98d3085a7297127fb",
	        "/usr/lib64/plymouth/details.so"
	);
}
static void svir_120(void) 
{
	svi_reg(&(tinfoil.validation_items[119]),
	        "1a855666ab3870a403e379c2b24da4eca16a762b756517ec5fc2a8694866929ef43644a876150e210acb24e2f25d1608e620d4be67824dd8e967354dedfc96d6",
	        "/usr/lib64/libzstd.so.1.5.0"
	);
}
static void svir_121(void) 
{
	svi_reg(&(tinfoil.validation_items[120]),
	        "654598d4f149484e1ce0e3150729a8d4da81ab1cb2f83e2c13d87e352352854aa6830ac98e86dd42e61474f03d97ab4feee6e97f1ed6877f517b2a1934a37322",
	        "/usr/lib64/libz.so.1.2.11"
	);
}
static void svir_122(void) 
{
	svi_reg(&(tinfoil.validation_items[121]),
	        "c2e5dacc12909bbc594738da3701f156ea0732d61698c92ddc0a2d4683dc27e14b1c1a7bf8ee4e6905d9da203307eeccfd1063d2aad56f74c1051696ca883bdc",
	        "/usr/lib64/libuuid.so.1.3.0"
	);
}
static void svir_123(void) 
{
	svi_reg(&(tinfoil.validation_items[122]),
	        "28728238eb9e4c35bdaafa2b2cbac0c65aec1c4f4cb5a0655259e605440cfe7df5c395761ddcc80fd3ca69bbf7823cca8db2eada388bf7a95992b8eddd2612ea",
	        "/usr/lib64/libunistring.so.2.1.0"
	);
}
static void svir_124(void) 
{
	svi_reg(&(tinfoil.validation_items[123]),
	        "7eb017c3497752fed653cb52eddc2e52ef7344046fca99e9fc6223dbd684db0eb66a0367a8bb4ede69fa1d82bebc216ace5635f52bd87dbc168bed246b06ddcc",
	        "/usr/lib64/libudev.so.1.7.2"
	);
}
static void svir_125(void) 
{
	svi_reg(&(tinfoil.validation_items[124]),
	        "754687f380d5b0e3359e19705b3913ad1a948bf0963d86730f86a0736030a6f3398c7a9826e100ab95876d890ada6374e2ff0ed74a0999342835c0a72a8c3d95",
	        "/usr/lib64/libtinfo.so.6.2"
	);
}
static void svir_126(void) 
{
	svi_reg(&(tinfoil.validation_items[125]),
	        "8b3db40ecc40a18e729e476734564c15b2fc371a27511a4360021c10e0c6a7c01140148857c3cc3fb0241685ced8980dd771d1645f87483b3acab14ee2d496f4",
	        "/usr/lib64/libteamdctl.so.0.1.5"
	);
}
static void svir_127(void) 
{
	svi_reg(&(tinfoil.validation_items[126]),
	        "b4112d10e5c92c3420c93f5abee2fd7dc928cccf029ff3a53211b6a6a6558d1acf0df5fb76ebb42c196956503bc6ce03f51fd2f2e8da432fbbdbd6a4d7614e57",
	        "/usr/lib64/libteam.so.5.6.1"
	);
}
static void svir_128(void) 
{
	svi_reg(&(tinfoil.validation_items[127]),
	        "879848ab7e7aaf185082a007d343012ed23edfa9ce098f4ee8e8c290eb054040c6a1bf7e9875b1074134ef1528cf0fd069057a33eaac239194512b30edb07911",
	        "/usr/lib64/libtasn1.so.6.6.0"
	);
}
static void svir_129(void) 
{
	svi_reg(&(tinfoil.validation_items[128]),
	        "d8881687eeb716e069674939760f09e620ee42aedce2cec5183930e37d266629ca704167d901a0e98771f65b00448c252b3436a90e8b29a59318cc5a56716e4b",
	        "/usr/lib64/libsystemd.so.0.32.0"
	);
}
static void svir_130(void) 
{
	svi_reg(&(tinfoil.validation_items[129]),
	        "7a96433c45ae21580fe8ee379cf1cb5634052c335d044f75d7313d2df5bb47b3dd9e6a31ea9c994b42023d2d6fc91d96ee966abd3da7d647c6e6ea3fdcb3efde",
	        "/usr/lib64/libssl.so.1.1.1l"
	);
}
static void svir_131(void) 
{
	svi_reg(&(tinfoil.validation_items[130]),
	        "c7075ff4878557d2b79017a6302cd9d1637fdd6f9217dfe3ed51dfe4036dfc42879feeec2135b89dc41fb06383a9684e1595daf944510a24f2a3603a7518cd90",
	        "/usr/lib64/libssh.so.4.8.7"
	);
}
static void svir_132(void) 
{
	svi_reg(&(tinfoil.validation_items[131]),
	        "501796a22f522767c67bbde455b4eefda3b74e5dec13104e5cac8682eb030683374c41f237b22b54e9ffa4a285a0e22603abb7eecd72b8a77bff1b363368bb66",
	        "/usr/lib64/libsmartcols.so.1.1.0"
	);
}
static void svir_133(void) 
{
	svi_reg(&(tinfoil.validation_items[132]),
	        "32bb5738e1b3d125fdfb913b3328067b25cf01f1b09a97ba13f9822a7e87c95398fc6ce09378a72b9acccaf6c3e25d9e7c84928e80e77f84d108a392de13f655",
	        "/usr/lib64/libsigsegv.so.2.0.6"
	);
}
static void svir_134(void) 
{
	svi_reg(&(tinfoil.validation_items[133]),
	        "db703ccb059f65706fa1e945ed82f04c3882e8121b1a52c438cd9892bd54b8a7580f278b60ba777ec72d88945b679839d414a0e487878c1f161fe1fa0e8e0a5b",
	        "/usr/lib64/libselinux.so.1"
	);
}
static void svir_135(void) 
{
	svi_reg(&(tinfoil.validation_items[134]),
	        "94afe835d287d18588374a28d34b7b7adf7c21eda3c6c2b55668571d7008e8b6ece1fe86554f0e179516d5ea9fcc103e878a52d5fb3d93901384cf9841823e29",
	        "/usr/lib64/libseccomp.so.2.5.0"
	);
}
static void svir_136(void) 
{
	svi_reg(&(tinfoil.validation_items[135]),
	        "8cf6c8b968077b8bf4dc8598eb26e0b4b800f4bdfdf197dee5b4614097a03a235b1e26421925d057cd25e22f3367fb6f638f94c01d9594723b768937fa63bff7",
	        "/usr/lib64/libsasl2.so.3.0.0"
	);
}
static void svir_137(void) 
{
	svi_reg(&(tinfoil.validation_items[136]),
	        "d0cda4b11c76effaae73e7dfa3ca3e8bb84e88ed66e59c4fbb68e05496952e8c500f02b7572bf662b2cf2a3bf0467bd47813ff44a18373c93fdfee3d5f65ebc0",
	        "/usr/lib64/libresolv.so.2"
	);
}
static void svir_138(void) 
{
	svi_reg(&(tinfoil.validation_items[137]),
	        "3b64b048b69983499e3b6121194f6078b4eb4111b420e1dec0547fc210c156372a948bee0f3e4279a9d837a5e2ae66ed575a6fa39b655c96c7fd907df38692e9",
	        "/usr/lib64/libreadline.so.8.1"
	);
}
static void svir_139(void) 
{
	svi_reg(&(tinfoil.validation_items[138]),
	        "e26c44b812a99ff6be237edad3a57f4cc03e20b73090f6d39852997a97f694712cf081be2f6f8f4860178d094fb58b1cc0a8efd13f5ea9b5ccc38a648f3de59c",
	        "/usr/lib64/libpsl.so.5.3.3"
	);
}
static void svir_140(void) 
{
	svi_reg(&(tinfoil.validation_items[139]),
	        "1d44fcd0b4b140a7997ef92951b1a9b42b71a342e84ba1401b89985ba6789c7eddaaab6218dfe2de5c38559193f7680ffae0df2147f927e533044355cac23844",
	        "/usr/lib64/libprocps.so.8.0.3"
	);
}
static void svir_141(void) 
{
	svi_reg(&(tinfoil.validation_items[140]),
	        "9b7855dfb84c67350968649813bfe1261c0544c9511417700e3826a32b31a3454b7414ee5d1d2d284f3c2aa776d3bb8527b20012f72d4bf8429ff26677a63340",
	        "/usr/lib64/libpng16.so.16.37.0"
	);
}
static void svir_142(void) 
{
	svi_reg(&(tinfoil.validation_items[141]),
	        "4ed11e46e4a46a71487c5fc5ee811dfa520118ac776058c79c52814a5d5872a66861e81a859ebf1a3d4700e10282b35eb326b3ff2dcdf39195415a49d7dbfe20",
	        "/usr/lib64/libply.so.4.0.0"
	);
}
static void svir_143(void) 
{
	svi_reg(&(tinfoil.validation_items[142]),
	        "a6986fb1646e5c324141ccbc9a9b1f6d13662dd7107c2f6f199a5cecb5685e5242806740f82409bcbc8c0401992b66ca6b0e74ddc6fbf03afe5d47639a5450d3",
	        "/usr/lib64/libply-splash-graphics.so.4.0.0"
	);
}
static void svir_144(void) 
{
	svi_reg(&(tinfoil.validation_items[143]),
	        "59436ac843a2aebd33d6a3dcd8f48f3f9fd60c34bd3a4d6ff66d5c43a22cc8108edcaacf0a0fc393cb389b14627cc010541eea1cb6fbd2242c187c189e75f720",
	        "/usr/lib64/libply-splash-core.so.4.0.0"
	);
}
static void svir_145(void) 
{
	svi_reg(&(tinfoil.validation_items[144]),
	        "8e9d327785083b4aa245cb7e57983de404a3b7602d122cda03e8da0be1153bfa5f36daa5617df0631225346d817a5146412ba750feee458fd2880857a84cdbd1",
	        "/usr/lib64/libpcre2-8.so.0.10.2"
	);
}
static void svir_146(void) 
{
	svi_reg(&(tinfoil.validation_items[145]),
	        "bd8183ff468a3666e7a981dc0c03466fbc29f8f7644a66a036e106ab040790aedb14d7553808ac772600f7658c7a94ca7fc109ce5cdd39671d1dfbf6063ed9d1",
	        "/usr/lib64/libpcre.so.1.2.13"
	);
}
static void svir_147(void) 
{
	svi_reg(&(tinfoil.validation_items[146]),
	        "2553045a006713ec27966f9b414b46781246da63b83901f5780a4d103f81699aea94e2f5ead300ef6dfe31745c1167c6370b4ead866967f57e8b084b4fc40f2f",
	        "/usr/lib64/libpcap.so.1.10.1"
	);
}
static void svir_148(void) 
{
	svi_reg(&(tinfoil.validation_items[147]),
	        "0e2928eb1bd2376b9239333deffe4d0b1e7fb6b31fdaeef908eed9d01a6784487ced335d8bc694f630fdee6aa02c8c1f1db387d1545ac16dc35c72e06719846e",
	        "/usr/lib64/libpam.so.0.85.1"
	);
}
static void svir_149(void) 
{
	svi_reg(&(tinfoil.validation_items[148]),
	        "8e31e0700c2486bc29ab190d3d5ed6962ae2195368f1f918d3ef39839e724bd0a6af7d182d30fc7119ca06a5953191a2dc254490a3713ed4c5718cd8bc14165e",
	        "/usr/lib64/libp11-kit.so.0.3.0"
	);
}
static void svir_150(void) 
{
	svi_reg(&(tinfoil.validation_items[149]),
	        "89409d76df5541d6cd45facef906c11d88b6d3364d960c9ed4d5f3225baf0c3e9aacceb9278e0298e697cda1786a04b68f6f58093caa2c76b04b18cfa578bfde",
	        "/usr/lib64/libnss_systemd.so.2"
	);
}
static void svir_151(void) 
{
	svi_reg(&(tinfoil.validation_items[150]),
	        "455d8c2d34af34fb919a4c0048d836b18b6959792e398b24c15c633ae4837984a9a210de25857d61c9503416f6ad23d07fe6c1ba535a5e2a0d0e2cf43e672563",
	        "/usr/lib64/libnss_sss.so.2"
	);
}
static void svir_152(void) 
{
	svi_reg(&(tinfoil.validation_items[151]),
	        "ef8cb82b7b21e61529f971f2a5c1c40fa835392cf1b963b2f6767917940157f41d9527d26758f4d46efac7ae6e20e1b53b7224c6fdee9dfd3a0683479c1c75f2",
	        "/usr/lib64/libnss_resolve.so.2"
	);
}
static void svir_153(void) 
{
	svi_reg(&(tinfoil.validation_items[152]),
	        "45e16342b691084d19c83d2b0a77682be560509f904a6a2a192a03ef0b6b8c2600ad0ebb263ec83b1969183f6683f778675f4421cb1cab43336ee9d4d73143e9",
	        "/usr/lib64/libnss_mymachines.so.2"
	);
}
static void svir_154(void) 
{
	svi_reg(&(tinfoil.validation_items[153]),
	        "4247be62f5968ac514a96f3f2ca71a619040477997c9c87517e4a37602dbd8c817236c17fba60070bff99e0c6dd63313da5f8da2534484f32a6cfb1fcb024e25",
	        "/usr/lib64/libnss_myhostname.so.2"
	);
}
static void svir_155(void) 
{
	svi_reg(&(tinfoil.validation_items[154]),
	        "5eaf062405830c7be4e0b8e66bd8b7cba00f80af2586ab3609f84cd9f818ddbb1b9f155a2354d9f4963b3331519f1fde6ba1675d9acdf809045e149e59df2c79",
	        "/usr/lib64/libnss_mdns_minimal.so.2"
	);
}
static void svir_156(void) 
{
	svi_reg(&(tinfoil.validation_items[155]),
	        "0f15bd67fadfcc903c180d2968bf9833eace38fe6917f137dc80c31addc271759c5814aa116f12cd25c3b2d81fbb1b8ebcf8f168fb0eeaa7fc8518938716b247",
	        "/usr/lib64/libnss_mdns6_minimal.so.2"
	);
}
static void svir_157(void) 
{
	svi_reg(&(tinfoil.validation_items[156]),
	        "4c1efd4ce089f715c1906a1e01ac6dfe782409920c3228959ccf8811771f02bc7ab08a1d6524ada685f6ea6976a3d4b2ef00b76b06ea79f67929c7449a2f1a9b",
	        "/usr/lib64/libnss_mdns6.so.2"
	);
}
static void svir_158(void) 
{
	svi_reg(&(tinfoil.validation_items[157]),
	        "578405e3f0a6e23baca23a2b2f0f9cd81ed18b55c44d16e451e577f0d6021f3dedd20946e4dd3cb7cf06b2d2b4a84cd5686a8cd9c6885120ca43594d7bd901cf",
	        "/usr/lib64/libnss_mdns4_minimal.so.2"
	);
}
static void svir_159(void) 
{
	svi_reg(&(tinfoil.validation_items[158]),
	        "d3e58e309fdcc1d5b965136ff0f4287fb96ddcd5099a720bc654935a874e24a54b80612be4bcc6ef28c92ded5a2ce7a1fe16619b28743ae49eaebab5aee67c7d",
	        "/usr/lib64/libnss_mdns4.so.2"
	);
}
static void svir_160(void) 
{
	svi_reg(&(tinfoil.validation_items[159]),
	        "04fae3dc6bd851bfcaf6e6867c475687f85e804edaa1b5fe5153b2b7b620c845a63cb4cb9d6988729cfdf2f72371bb56372d852c6619377aedfb6a1189b57c6e",
	        "/usr/lib64/libnss_mdns.so.2"
	);
}
static void svir_161(void) 
{
	svi_reg(&(tinfoil.validation_items[160]),
	        "9005c536dd4abbdbfbd0abec7e46ebd2c2ac6397d41082a58a359abdd4b6039ebf082fead63a525b3c854657f8ba567265212e37dc910e2472815bb7ae58a012",
	        "/usr/lib64/libnss_files.so.2"
	);
}
static void svir_162(void) 
{
	svi_reg(&(tinfoil.validation_items[161]),
	        "87e4d0e14081f8a8485dd5645b3b36f8e54a7d2cf4dc6fd4383f82e9d62ec5e7b11b3eec5bfc7aa4b118f1bcc02d2c92901250312041bd4b79b9fd6bad88b585",
	        "/usr/lib64/libnss_dns.so.2"
	);
}
static void svir_163(void) 
{
	svi_reg(&(tinfoil.validation_items[162]),
	        "befc7cb10690edf4add8b69e086c8fd4ba07c8d15db482d0e1b069b8074d159e8f82c398c4ee3797fe2d8f0adef7e493082ac8994503e62bf6a3c49d343e39ec",
	        "/usr/lib64/libnss_compat.so.2"
	);
}
static void svir_164(void) 
{
	svi_reg(&(tinfoil.validation_items[163]),
	        "93d22c5bd06527d2cbbd857206ec670dc20ec369efbdac975b101041926061abfa3c8b0b3542660cddf974c8892c08e9a44d4073ce4b4968bae8b364aaca6f1b",
	        "/usr/lib64/libnm.so.0.1.0"
	);
}
static void svir_165(void) 
{
	svi_reg(&(tinfoil.validation_items[164]),
	        "232505f482d1a65c81cac3f4997627e75f59e4e0ea673fcdeae68edfb32c77d90ce26ebc4742e683b3e8afdec28dde0b2158925378ccc263370d44cc6690a5ce",
	        "/usr/lib64/libnl-route-3.so.200.26.0"
	);
}
static void svir_166(void) 
{
	svi_reg(&(tinfoil.validation_items[165]),
	        "87038a874f2f40b67b03ef8d9137f3eca51be6629344cef350196778408f85e6cf5a130a54d34be286f925fd9e6f48983c87f5391872065362c606ffffd3ea05",
	        "/usr/lib64/libnl-nf-3.so.200.26.0"
	);
}
static void svir_167(void) 
{
	svi_reg(&(tinfoil.validation_items[166]),
	        "846b26bcbe4f2c3506ef6e26264d7448562de1e563e3347c706fc67013b6a7a755a946ed15f3f3da423ffcc5c0668b3f9d68218dca1ba495eb90ee369ff57a0d",
	        "/usr/lib64/libnl-genl-3.so.200.26.0"
	);
}
static void svir_168(void) 
{
	svi_reg(&(tinfoil.validation_items[167]),
	        "8079f10be4f43a77b4269acd65f3e6ce792c16e25116483fa94f9ff618919a98d03bcda42887cff624183c291e733669e6d4c698b5d3d600be7eeaabd668cfd3",
	        "/usr/lib64/libnl-cli-3.so.200.26.0"
	);
}
static void svir_169(void) 
{
	svi_reg(&(tinfoil.validation_items[168]),
	        "62e5b936290ee2119e399093f449ad8ab5d8adf09952717e8eae93a4f77b1d22cbd8630b830c94cdad0d9d005b5acd8d0eb1e8ddf08e00f50131af7c6d255b95",
	        "/usr/lib64/libnl-3.so.200.26.0"
	);
}
static void svir_170(void) 
{
	svi_reg(&(tinfoil.validation_items[169]),
	        "280c8fd3166112ab1f97ec8ef9a949c60fee6c856d3dc9c97754b86f2df8c46ab9f5b60d53ba7a75999742baf0a9e819500e7c2ebc57df4f1cc49515850af9a2",
	        "/usr/lib64/libnghttp2.so.14.21.0"
	);
}
static void svir_171(void) 
{
	svi_reg(&(tinfoil.validation_items[170]),
	        "faa9a77e1215cbc42f222ce488071f00ca5fe3fffbb5073d408acb36d25432a9add1c411157350af94ab6c026b4e258fdfc75434933ed44a3fb19fa72c144c52",
	        "/usr/lib64/libnettle.so.8.4"
	);
}
static void svir_172(void) 
{
	svi_reg(&(tinfoil.validation_items[171]),
	        "91bb7ad9d2885bbc0e441a222d19dd3efce2924c98a4d5f5c967b2b1fdc2fbf5054b5e499268cbc103857bdc710037829659b89e38bf25042f609c32f5585c2a",
	        "/usr/lib64/libndp.so.0.2.0"
	);
}
static void svir_173(void) 
{
	svi_reg(&(tinfoil.validation_items[172]),
	        "0345e1e2119d4de6e79f9d7a47a22b9ba359e06dae33e9bc5ea8f4c6030dba20f0d825c3c5c3cf1bd05f56dac9fea72a91927650e15178ac1df12ab94ac711e1",
	        "/usr/lib64/libndctl.so.6.19.1"
	);
}
static void svir_174(void) 
{
	svi_reg(&(tinfoil.validation_items[173]),
	        "96db756f2f2db17ae5ca977454b2abc5e1c837b96846061df1555fa2874174f589c2b3ef2dc06248de47316e340069ae0d0eff52bd82668730b86f0d2262e302",
	        "/usr/lib64/libncurses.so.6.2"
	);
}
static void svir_175(void) 
{
	svi_reg(&(tinfoil.validation_items[174]),
	        "91fab5cd15608aa304595924519c8b495d9da5f082103b32e7a251a42424d2b50903a7e40a766e41122ba8fdd1ebf3091b746964e200bacc89e3d83c6bda0a3b",
	        "/usr/lib64/libncurses.so"
	);
}
static void svir_176(void) 
{
	svi_reg(&(tinfoil.validation_items[175]),
	        "98314c4261cdc8b7ae5f4abdad5a497693f8477b6afe95cc22a50cb264d44d5fbcdcbfce12b5ea390e670be94ccd54591d2885806f073a4dcecfc6bac2967d6d",
	        "/usr/lib64/libmpfr.so.6.1.0"
	);
}
static void svir_177(void) 
{
	svi_reg(&(tinfoil.validation_items[176]),
	        "227a70f0a149d71281d1a23b05ef73dc578a65e77398b28e44b4bbb6606cb290a310bc0612017c4a0466a0edd997d4f7a49f5db4d71ced5fde7eb6204fcd345e",
	        "/usr/lib64/libmount.so.1.1.0"
	);
}
static void svir_178(void) 
{
	svi_reg(&(tinfoil.validation_items[177]),
	        "49067d3308a9168815e4836fc6b30a004adcfec87177bb5b84cd963bbe5979e28411c988a2085434ad396c7137c89820d7c06ba0535218e6f20cc79abd045e7e",
	        "/usr/lib64/libmnl.so.0.2.0"
	);
}
static void svir_179(void) 
{
	svi_reg(&(tinfoil.validation_items[178]),
	        "5324a28c9361f0cb04517a1bc9ce4832a51509e74132b6521a38bf6f5012fa03dfbd29ed376031289299e154bcee3762edb69a47b99b1e7844eb9cd29002f943",
	        "/usr/lib64/libm.so.6"
	);
}
static void svir_180(void) 
{
	svi_reg(&(tinfoil.validation_items[179]),
	        "6156b8a9faf0b09e9b741e4bd4b4a94ef6e42645beab7d3f4e8c93d3f778102e942ff05411a9eb3c2e31c7fc39f3b57bab76063e89028efe12807412fddbc067",
	        "/usr/lib64/libm.so"
	);
}
static void svir_181(void) 
{
	svi_reg(&(tinfoil.validation_items[180]),
	        "c41288490686d598df4f663360551b9ae70e789d967e775bbcd1657abb0878084bb45ed5429673c5e530ca9e603d6025c2c631d2dc5314e9abe0d1f97a7d6d2e",
	        "/usr/lib64/liblzo2.so.2.0.0"
	);
}
static void svir_182(void) 
{
	svi_reg(&(tinfoil.validation_items[181]),
	        "271869d919db1a74fd2995a91af88c753dcfddb73b0b550983d6998fda7d5a1b1f45aa4fb8d3381e27823a8d3c49faf6ecdffd2cc0daee37b58106fc8e3a1d1f",
	        "/usr/lib64/liblzma.so.5.2.5"
	);
}
static void svir_183(void) 
{
	svi_reg(&(tinfoil.validation_items[182]),
	        "1a08045bd5a6312d4400cde34fff9aea64b151fc7113db8d7bd60319522ece9f544f48fe6c62ca8962c076d24a65687c147c9d2452d5a132ae805635b126682c",
	        "/usr/lib64/liblz4.so.1.9.3"
	);
}
static void svir_184(void) 
{
	svi_reg(&(tinfoil.validation_items[183]),
	        "707b28f9fd7a1db23468cba0fffeb7a47695dd2f93f29ac9fa033b27d5da8a5dee4fa2b42ead5f8b6ab887000122242cee852991e50a36513b0167101d41863b",
	        "/usr/lib64/libldap_r-2.4.so.2.11.7"
	);
}
static void svir_185(void) 
{
	svi_reg(&(tinfoil.validation_items[184]),
	        "d8d514e53c59da939af489043f958c036feed075d11c3a554f6a0e322d73c17b2e564f6fba4590f5bc7c891489e322c20347c8c9df2ed474f4924a37f558b172",
	        "/usr/lib64/liblber-2.4.so.2.11.7"
	);
}
static void svir_186(void) 
{
	svi_reg(&(tinfoil.validation_items[185]),
	        "aaecc0ffc94ae9cbf83ef7f3f0f232095407eee30d728f736f1f76bee1f9a314d623caa75d035349a26b06894274e80309998cbea0727d1344804245e6f0d45b",
	        "/usr/lib64/libkrb5support.so.0.1"
	);
}
static void svir_187(void) 
{
	svi_reg(&(tinfoil.validation_items[186]),
	        "76fe643a5678209eca467cb4eab612dff876ec806b7b8e235d854680acae4e2981d82da7108e77c65b7004caacab2997228df8a272f2e31eeb7b4c383d8bccff",
	        "/usr/lib64/libkrb5.so.3.3"
	);
}
static void svir_188(void) 
{
	svi_reg(&(tinfoil.validation_items[187]),
	        "8c8759d2ef2fc039653d9657e3117efa76a9051d1069d14c410c41ac75e7bf65cb18a731acb2e06b27777e02422ecadd394e603a11aea92beffc8bff30b12b9a",
	        "/usr/lib64/libkmod.so.2.3.7"
	);
}
static void svir_189(void) 
{
	svi_reg(&(tinfoil.validation_items[188]),
	        "bf36c453b33848dda1f01726f21101fdd26d462ec610020647abd6fc965c2d75dc4050e39abd153db6e668ce0f4c28a9c2fcb36eef5ea04f4e02787b5c086fb0",
	        "/usr/lib64/libkeyutils.so.1.9"
	);
}
static void svir_190(void) 
{
	svi_reg(&(tinfoil.validation_items[189]),
	        "247ba720c4e44aeccd4e757ba709d8643906733a34213020f2301550d6bba06bd338df341090d208828499ccc2031411e257a751034378c64b07233085bb598e",
	        "/usr/lib64/libk5crypto.so.3.1"
	);
}
static void svir_191(void) 
{
	svi_reg(&(tinfoil.validation_items[190]),
	        "15fb4425ac3aacbe90a44faaffe21d2ce144ca310ec9774010195ba502cec7cb4b8e172156d49651dd1ef24efefd9f48e9b72a20de0980c53b59f7c92c5f3754",
	        "/usr/lib64/libjson-c.so.5.1.0"
	);
}
static void svir_192(void) 
{
	svi_reg(&(tinfoil.validation_items[191]),
	        "d2a2b6183c4c852b525f60a1feca8758ad61c0e6b40defa1356da9a75ee3ca6423f2366fee7ea49ddf463578f8e0c9bc71458aa46950dd9ff0989168adb879c0",
	        "/usr/lib64/libjansson.so.4.13.0"
	);
}
static void svir_193(void) 
{
	svi_reg(&(tinfoil.validation_items[192]),
	        "a89cd174c3d537ab8adf96a86aadc768906bd94770cdec136aa63f2fd755b691c55c9dfa0d9908f9491963dd34483a459e9d3ad3bcd89dfc4ca2737af93cf51f",
	        "/usr/lib64/libip4tc.so.2.0.0"
	);
}
static void svir_194(void) 
{
	svi_reg(&(tinfoil.validation_items[193]),
	        "bae4ebd990c2bcead7de5ec7faac6a625520ae3e2e2c3424390d5239c6b7b73138a470b15b9329b047791177df9b0c3e4b641a2303e9db0acb0da04bfb059d2f",
	        "/usr/lib64/libidn2.so.0.3.7"
	);
}
static void svir_195(void) 
{
	svi_reg(&(tinfoil.validation_items[194]),
	        "2595edec4ec363be3406a5028bb5ee5485074ce1e1d3b1f1c731ae6ffbd768663981d88c5875bd50a632214c4c69b65f5c0034d8913fb7d6521265c624fc7a79",
	        "/usr/lib64/libibverbs.so.1.14.37.0"
	);
}
static void svir_196(void) 
{
	svi_reg(&(tinfoil.validation_items[195]),
	        "2f5207be549b700f3adcd49834a5e16ee8ea139f0ffe0bf4a86c1573f7aa490f9f66a5e67d68ee038c79eb2ed0392faa90ffbd0379dfe5c65aebd1db88b83d51",
	        "/usr/lib64/libhogweed.so.6.4"
	);
}
static void svir_197(void) 
{
	svi_reg(&(tinfoil.validation_items[196]),
	        "2cf6c05c502644b798643507dae5bbc8894ca2f0d43922ee7185de1160c118ef2a618cf3e4a665b27105efaf2095f1f3b1dfb96ca244a447b85417010b8a96a7",
	        "/usr/lib64/libgssapi_krb5.so.2.2"
	);
}
static void svir_198(void) 
{
	svi_reg(&(tinfoil.validation_items[197]),
	        "a9c0fbf6dc3b3c3ca2be034d99652240824dae7a5155232ea805cc20504406feadb3daa733b28ed1e250f3b2ad6bbc0bd7728c372a41e1ba615525a3e1578eee",
	        "/usr/lib64/libgpg-error.so.0.32.0"
	);
}
static void svir_199(void) 
{
	svi_reg(&(tinfoil.validation_items[198]),
	        "47f7dbee84418bf218805a8e2f3f258a632b692e803a1665a01000691f292f6f6dd350fa43e5fcff98fd3db57185c3e593c425fa54131e43ba14901afd710f67",
	        "/usr/lib64/libgobject-2.0.so.0.7000.0"
	);
}
static void svir_200(void) 
{
	svi_reg(&(tinfoil.validation_items[199]),
	        "00806ea9e81bf01632c00dfbfa2719581ef7b54141025716a143991d21a2ae659927b14b6f571f0d52f1e7e99b26e31d0190909cfb61605b2d3aac11a7efaa55",
	        "/usr/lib64/libgnutls.so.30.30.0"
	);
}
static void svir_201(void) 
{
	svi_reg(&(tinfoil.validation_items[200]),
	        "756b547d064c171ffb10d64a4636ae5ccb89740d56744a244ccf50ae87956f7348d77c5f236a448886f52cd605323da1512dd5e7a575d78bbaa74b186cd8945d",
	        "/usr/lib64/libgmp.so.10.4.0"
	);
}
static void svir_202(void) 
{
	svi_reg(&(tinfoil.validation_items[201]),
	        "21c3d642cdf291f3e0ef38981981f58b6c595e8f4c78679b4007725bd2d1d65d1552c68604660f6e23793f2ed487510b0b1b31a624129833bb24888b7f28317a",
	        "/usr/lib64/libgmodule-2.0.so.0.7000.0"
	);
}
static void svir_203(void) 
{
	svi_reg(&(tinfoil.validation_items[202]),
	        "6ac69b79138d4aa03cbe71bbb307e928b02569155da5195bc91ffcc585dec0da207257c0d89136adf1a80dbaa734b42d687eaae2afab4628d68755a5f48b2743",
	        "/usr/lib64/libglib-2.0.so.0.7000.0"
	);
}
static void svir_204(void) 
{
	svi_reg(&(tinfoil.validation_items[203]),
	        "af3ce92f28a00f206b628fd4520f776325373667eb43d67c8fac6df03b113cbdcecfe5c928b66132ce1b35ebd1aa721866b9aedfcbb6281bf8344cdd4726ceee",
	        "/usr/lib64/libgio-2.0.so.0.7000.0"
	);
}
static void svir_205(void) 
{
	svi_reg(&(tinfoil.validation_items[204]),
	        "d460bcc4990a3f4ff430f61f945696adc18f5bccf892477a3b25ec587f1e9b396c3b43a7d7f09f3dc08398ec7b2454af7ac8de78c0715420a4b92abb6529f60e",
	        "/usr/lib64/libgcrypt.so.20.3.4"
	);
}
static void svir_206(void) 
{
	svi_reg(&(tinfoil.validation_items[205]),
	        "9b71e8d9f91bcab7d805a530aaca58636c5609edf64e4cef17f2c15db60a07650706c7344c611fcc17d663fd7a0ee6f2ced5abb8964df243c9a72c479f68a4cf",
	        "/usr/lib64/libgcc_s-11-20210728.so.1"
	);
}
static void svir_207(void) 
{
	svi_reg(&(tinfoil.validation_items[206]),
	        "97ea6ee5e96fe61ef7a99dfe34383d0233ae2a9d542084de3d7f99f0d0cf08cec7bbcf5f2ae835d61bc0764dd42d29517a25f1f67a4dea3d254d90c4fff90819",
	        "/usr/lib64/libfreeblpriv3.so"
	);
}
static void svir_208(void) 
{
	svi_reg(&(tinfoil.validation_items[207]),
	        "7701a332f560cf71a786930d1b84ad2b03ba4c6b437c89cd5c23010de963bea8cc4247d5a35b84a670a8e6bdaac1dd85ca3e233e83687351f390fb51c381e497",
	        "/usr/lib64/libfreeblpriv3.chk"
	);
}
static void svir_209(void) 
{
	svi_reg(&(tinfoil.validation_items[208]),
	        "682f8ea49648538b78f2c818b1cbe2bef98fdf26a77cbd4581c3b669a4ced7079b432982be7ad07654c8c94d67e45b5085ecbf5714146a0611eee538a136567e",
	        "/usr/lib64/libfreebl3.so"
	);
}
static void svir_210(void) 
{
	svi_reg(&(tinfoil.validation_items[209]),
	        "75817ba2d0306e10ff63fec8e676b14088de65fe5b5e8a48ea883e3478768e1ae119b3f964a2ae56afb6fc8946d5ddac76036b432d39499296e92a44bbbe93a0",
	        "/usr/lib64/libffi.so.6.0.2"
	);
}
static void svir_211(void) 
{
	svi_reg(&(tinfoil.validation_items[210]),
	        "b6393be5eb9ed065a1666d63297a36adcc7d743c108a17caaea67012661b47c7a9a270aa15045ef32c496d096529d301c7dd5571d205f9d4fc671afb8553cc06",
	        "/usr/lib64/libext2fs.so.2.4"
	);
}
static void svir_212(void) 
{
	svi_reg(&(tinfoil.validation_items[211]),
	        "76bb06cb41893090d0711adbdcbfa62f2cc01f5559d3ad0c8d1b803d616c6affa655867d0cdab9d647d59f1c39e182818117407da5ed1f22cc49b42a2be5cdec",
	        "/usr/lib64/libexpat.so.1.8.1"
	);
}
static void svir_213(void) 
{
	svi_reg(&(tinfoil.validation_items[212]),
	        "1ada711750e714f95f55e5e833827811c2adcd0e8014906f990ce838438da2e6195af593f4ef8589aa35666a6e2fe9535548f2bbac6f5d07ff6a1720c0f28176",
	        "/usr/lib64/libelf-0.185.so"
	);
}
static void svir_214(void) 
{
	svi_reg(&(tinfoil.validation_items[213]),
	        "f91a9d5e8cfd48a8a03d8d0b5e48c8693bcc63783028d2eb0f88578412c2bfc0fa5169cb3c9b153f3bff53f1236248fd57e58cc34e2ffb1b6e95e4d05fddb54a",
	        "/usr/lib64/libeconf.so.0.4.0"
	);
}
static void svir_215(void) 
{
	svi_reg(&(tinfoil.validation_items[214]),
	        "af85657241f1bf3e358569403847eda4586e5b47658fc7af6bd82d5d206018c0b3bf19c25c76520ac9e4230e4116d1b9ed3d115e7dcbc0c5d23af00d953317f6",
	        "/usr/lib64/libe2p.so.2.3"
	);
}
static void svir_216(void) 
{
	svi_reg(&(tinfoil.validation_items[215]),
	        "d539858e3d6966babbfbb42809cb4e4ac511764929cbe5a508d0d6ecd0629b35bc2da00760d90106a98cdc03be413015ffef497e19e364274697dea896288566",
	        "/usr/lib64/libdw-0.185.so"
	);
}
static void svir_217(void) 
{
	svi_reg(&(tinfoil.validation_items[216]),
	        "f313629b13f675ddee06acea3af22bbd3623762e5169381c4a06d344e560f9282e8acb10a365ea130f68ed03d61887746abab8d1b31b290d4a81c82c16e00e64",
	        "/usr/lib64/libdrm.so.2.4.0"
	);
}
static void svir_218(void) 
{
	svi_reg(&(tinfoil.validation_items[217]),
	        "a4de6a0db0dcbcc6f896628c6d35e974e314fdbba6dab78ea7ce363af3d6d49d7fe5b1ff54726412aae1d6afd72fd97e4a9e6fc7038da9aeaf2b1353b0eede61",
	        "/usr/lib64/libdbus-1.so.3.19.13"
	);
}
static void svir_219(void) 
{
	svi_reg(&(tinfoil.validation_items[218]),
	        "9a66b0beddd70278eb9052f0e37360292ed42d5143cde8d4b2de41777734a8a644a14b78d46da2a8037d9bb516b23042c5ce6808865703dcff2def82a027c41a",
	        "/usr/lib64/libdaxctl.so.1.5.0"
	);
}
static void svir_220(void) 
{
	svi_reg(&(tinfoil.validation_items[219]),
	        "5e354b633eb08b5c877b326f91eb6e05fbb9da492d38e25bf99c5ddfdd305d7a0761f861ba392938265e0e9952ccce5d8c4ba5abc73e3fe7e7e17925bebc09f4",
	        "/usr/lib64/libdaemon.so.0.5.0"
	);
}
static void svir_221(void) 
{
	svi_reg(&(tinfoil.validation_items[220]),
	        "607b17c757706e82345b8ba4efebe88ed5ef94d944b87caa1703347f5ecd511db1f27998fe09048c852e45cf1073f7bdac496be24439914fa1ba12888ba26b23",
	        "/usr/lib64/libcurl.so.4.7.0"
	);
}
static void svir_222(void) 
{
	svi_reg(&(tinfoil.validation_items[221]),
	        "3e7b11446bc7ff2db8d3179ba976d4e6d98e13ca3f4a60d8bcd1b9dff8d69f6dac2ee85838a20dbb78a6e09d5407cceaa9130b48ed54904140ea1e74edabaa4a",
	        "/usr/lib64/libcrypto.so.1.1.1l"
	);
}
static void svir_223(void) 
{
	svi_reg(&(tinfoil.validation_items[222]),
	        "dbbe916f63a49ea6983f3e02bb28963330885eb49756411e5ee7dc1dafd9f846a71cdc9f07a0e206b553f06acb25d76e817849d0eeb0c13de8baaa4f67226f4b",
	        "/usr/lib64/libcrypt.so.2.0.0"
	);
}
static void svir_224(void) 
{
	svi_reg(&(tinfoil.validation_items[223]),
	        "4335e7ea3c7139cad4840bf6cf9d4557519f76b383c3b68cc537f0be7bb69a041f147f4e8eef8fa63c5b8f67d5b394eeff3a7cfadcc3eb5608eace87a94c6e2b",
	        "/usr/lib64/libcom_err.so.2.1"
	);
}
static void svir_225(void) 
{
	svi_reg(&(tinfoil.validation_items[224]),
	        "5e253856c0b19a2b8629965fb8845b80fdc6c8ff78ed3b95ed12d7819dd43166b8f5de0266d342ae886628924c71919bf5a134cb9d50eeae9cf32c33fa26c508",
	        "/usr/lib64/libcap.so.2.48"
	);
}
static void svir_226(void) 
{
	svi_reg(&(tinfoil.validation_items[225]),
	        "56da592866a38b1f901ed4b60076cb2a12ede05a4eef20a6cfeb2a32263a65645fb9a2e37340ca09ba41308596364ea3826d309711c6f06063be98690aa2686b",
	        "/usr/lib64/libcap-ng.so.0.0.0"
	);
}
static void svir_227(void) 
{
	svi_reg(&(tinfoil.validation_items[226]),
	        "5b4effdba4bfd29bd6cb22ec2dc89e533448b83b565edede005acce93d49e51467eb2a7e21fa840c061f76bbe9a4c45b87317d94e0236c889209c48a4eb1999f",
	        "/usr/lib64/libc.so.6"
	);
}
static void svir_228(void) 
{
	svi_reg(&(tinfoil.validation_items[227]),
	        "04cf63a3cef6f5fbfab2d23e36c5644c222a1916d09d191765fa3c8822a97e8d76583e21394003637c2e4b94f4b1071d310b3c7fad079c1518d822a3b5d4da62",
	        "/usr/lib64/libc.so"
	);
}
static void svir_229(void) 
{
	svi_reg(&(tinfoil.validation_items[228]),
	        "4d4cc38dcc631829d9caae30d57e3c02bcce36dcb10afc0bd033b9df2bed992fc9005339770f06174528b5721f9b5d8f14c70b78b0f838db3cf1f1c2c0f2724e",
	        "/usr/lib64/libbz2.so.1.0.8"
	);
}
static void svir_230(void) 
{
	svi_reg(&(tinfoil.validation_items[229]),
	        "e6a46215f5c0a9d1ef45178c4601e242b441fdc9d7821eccea200ae02a43af22d1ebdebd7d00b79e563608b9db1b140247e7bf69e3f8f552274f069a5332a9d1",
	        "/usr/lib64/libbrotlidec.so.1.0.9"
	);
}
static void svir_231(void) 
{
	svi_reg(&(tinfoil.validation_items[230]),
	        "6678b15e924d06ad0deacfbf118f625ec3d84d669635e30d9167dd12ba30ca07c7279899fcce5f55f781906774b23729c4923a4f1b5b9b3cb2b5225c1c56963a",
	        "/usr/lib64/libbrotlicommon.so.1.0.9"
	);
}
static void svir_232(void) 
{
	svi_reg(&(tinfoil.validation_items[231]),
	        "204ac666854364c803adbd083e51eef1e59500770bf07c6d2be38b9a1ca2ab0644dca1a3ad67b23e3fa8a0d7c8f4942a42b3cbe54ca46ee6ef8c40c53f049956",
	        "/usr/lib64/libblkid.so.1.1.0"
	);
}
static void svir_233(void) 
{
	svi_reg(&(tinfoil.validation_items[232]),
	        "ce3e7af9680ca4462f5b4ed4b2e820e30370bc0008a50673ac558208883ee13dad636c3c083a8895486da4e12699255bfcb1ec3e12b2be4c9e91c42d8751be4c",
	        "/usr/lib64/libaudit.so.1.0.0"
	);
}
static void svir_234(void) 
{
	svi_reg(&(tinfoil.validation_items[233]),
	        "f69a1989768d0104474bb7ca825b2b9a7fe14275309263b49b820498ef7b45f8735f809332ccdd7f298cb0bbdc3ec32fd78e7248ebbbd535402f39e1acfc93c8",
	        "/usr/lib64/libattr.so.1.1.2501"
	);
}
static void svir_235(void) 
{
	svi_reg(&(tinfoil.validation_items[234]),
	        "270d7f8629d6efa9f285590f3fa7f2f4c22c781a3452bd874170b0c5e6c5c9fee95cb915efdc6ea561f28681eab77350dce91460e499b69a860b2369bf9348bc",
	        "/usr/lib64/libacl.so.1.1.2301"
	);
}
static void svir_236(void) 
{
	svi_reg(&(tinfoil.validation_items[235]),
	        "b7d7e4b9ca4849dec0565a9902c50293f9c79422a03115dedbd426402db1d772efd3cbd173c6b13a422eeb30d34f35b7a33b57ecf84902888fcc04c28fa0684d",
	        "/usr/lib64/ld-linux-x86-64.so.2"
	);
}
static void svir_237(void) 
{
	svi_reg(&(tinfoil.validation_items[236]),
	        "796e457be98b71e5971fb42a2ad9aaea89c7ff056a6122f1a492db5c26021caa2b99d7e9475ed2d456517f55608fd5492f6c4f4a2dcf9df4c4ed5e702e59be16",
	        "/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-settings-plugin-ifcfg-rh.so"
	);
}
static void svir_238(void) 
{
	svi_reg(&(tinfoil.validation_items[237]),
	        "cd8259d561a9f267dab3866c0b5cbbc854e082cd04811289e44d411373406b1237ea2c47f6b953c5123bccfeac2587b9b17eba204b4ff5a6f476ddbde78642d2",
	        "/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-device-plugin-team.so"
	);
}
static void svir_239(void) 
{
	svi_reg(&(tinfoil.validation_items[238]),
	        "1193d70e966151c1255f981f1557889cae4abb94282c2868b032c3a23d360c4d675857d14f0ad3ab61bfc8c76f6b349ddb8336c768612b8afb7e7a814cdeb9e9",
	        "/usr/lib/udev/scsi_id"
	);
}
static void svir_240(void) 
{
	svi_reg(&(tinfoil.validation_items[239]),
	        "b7b39811b8613ff439db74e43723ce46a079d566bf8ab7ac724b47e28a534d998598915575637dcdde8f8ee378bc31cab3c8ad5bf2699fedba104ccf8146b137",
	        "/usr/lib/udev/rules.d/99-systemd.rules"
	);
}
static void svir_241(void) 
{
	svi_reg(&(tinfoil.validation_items[240]),
	        "f3c3a70aba6db6ef7503326d9a1c32037bae5c0d26d945340ad78284fd1bec28b0868af6c55297eeb7dd0419ca63f3f04f6a250a5c15a2aab6be0595a024a28a",
	        "/usr/lib/udev/rules.d/90-vconsole.rules"
	);
}
static void svir_242(void) 
{
	svi_reg(&(tinfoil.validation_items[241]),
	        "91989bae029262a6e1e3873a6165b34e2cb5843f1668e30ee61729f466d2096eaadd60009ba5988e871667146816753700509912044566afeb688d27bf74530b",
	        "/usr/lib/udev/rules.d/85-nm-unmanaged.rules"
	);
}
static void svir_243(void) 
{
	svi_reg(&(tinfoil.validation_items[242]),
	        "b203bfa0c770109caf65eb7aed7e872b1ec2e157c4ee6274b999785637550948d51a143bdc7cecc2ec1be887a5da4aa5169a1a6ecb128f240ac2439e1a6878a3",
	        "/usr/lib/udev/rules.d/80-net-setup-link.rules"
	);
}
static void svir_244(void) 
{
	svi_reg(&(tinfoil.validation_items[243]),
	        "3009241c8448d5ad63a078d98d17907dc10e7eb64e133bc4c7d5436ba4745e17a38a63da1b040761f6e7a2d044c6dbb7e122314357d655851a2adfa63aa6c07d",
	        "/usr/lib/udev/rules.d/80-drivers.rules"
	);
}
static void svir_245(void) 
{
	svi_reg(&(tinfoil.validation_items[244]),
	        "084db40c963e57b7a3e1b3a5d8ceee624905fb9eacbf0240d3bfc25f58eb3a40dc98c20d6f68ac61b1b46ce4fe362c18ef7f7a94be639725c287fd6f52cf1b06",
	        "/usr/lib/udev/rules.d/75-net-description.rules"
	);
}
static void svir_246(void) 
{
	svi_reg(&(tinfoil.validation_items[245]),
	        "d62740456c2360f5c0de616fe6edafe0302c8251d59ccbda850c3a7c629c228edfe02739e53596b2be4a52f8dbbb120dedf52030624a767158873b5035d924db",
	        "/usr/lib/udev/rules.d/73-seat-late.rules"
	);
}
static void svir_247(void) 
{
	svi_reg(&(tinfoil.validation_items[246]),
	        "0c22448a227f5873b6f51b6938d42bfa7e6aacd2f086adc233197f7a4bae4d819ea61b271c876cbafec2d121d4dc8e255135027a6d3bfdc8a8f371a69680b4a2",
	        "/usr/lib/udev/rules.d/71-seat.rules"
	);
}
static void svir_248(void) 
{
	svi_reg(&(tinfoil.validation_items[247]),
	        "e1e59546f22850a42dfdba5028de51debe85f55a72071a22877f7e0d3208e22c02f1562a1f76ad5447912b3f1fbc64228e17c9dc219d635678981c7c669ae100",
	        "/usr/lib/udev/rules.d/70-uaccess.rules"
	);
}
static void svir_249(void) 
{
	svi_reg(&(tinfoil.validation_items[248]),
	        "882b29613fd70df3682fc9bcba62d680699b5f7a8f367bad3392ce05aff93ef4aba77d7ef4fd7babd11ebe7d3937a52e41db38354bbe040e5e2139843676c2df",
	        "/usr/lib/udev/rules.d/64-btrfs.rules"
	);
}
static void svir_250(void) 
{
	svi_reg(&(tinfoil.validation_items[249]),
	        "7c6fbe135a65991d56bfe156c7c20075c13d64f9c17a5de7f84e5848fa0790df5a4e5ddac650eb6c5753d03d190d7a09fed17a0cab3b3ae9752d5acb28386025",
	        "/usr/lib/udev/rules.d/64-btrfs-dm.rules"
	);
}
static void svir_251(void) 
{
	svi_reg(&(tinfoil.validation_items[250]),
	        "608f91fd32f29026e7b2ae911d5bd743ab166546bddb9a4d471ee82187c10ff9155b88b7e96389f9c7a080affa278dca3e86d027e557a4012ab5f11ba42ba89e",
	        "/usr/lib/udev/rules.d/60-persistent-storage.rules"
	);
}
static void svir_252(void) 
{
	svi_reg(&(tinfoil.validation_items[251]),
	        "8e1b9bfb3b125c350b5efe806ff4b0bab105091e4883b97d3776ada8edf0991f072abec3e60453c9a06325ba1d49514576fb13495d321b981f55686b50bd1828",
	        "/usr/lib/udev/rules.d/60-block.rules"
	);
}
static void svir_253(void) 
{
	svi_reg(&(tinfoil.validation_items[252]),
	        "69ec3e81cff3ec5deafb1937029b5586a4886bbafb48b8b9ff775676e66ed16087d37b7c6e05da1e4055c87549691be89a93a6a222e043f4fe82f13ccf6dcda8",
	        "/usr/lib/udev/rules.d/50-udev-default.rules"
	);
}
static void svir_254(void) 
{
	svi_reg(&(tinfoil.validation_items[253]),
	        "b0838ae1932a04c9d4906f7793ba9aa7d3738ee1262308c5c414e0ca098babaacd8ef20b0d9aac25ed286d745122fd23dfb45fe1992a19a1739b9b88ca23881f",
	        "/usr/lib/udev/cdrom_id"
	);
}
static void svir_255(void) 
{
	svi_reg(&(tinfoil.validation_items[254]),
	        "35ef1626a3d310fe169b11cc55194c72f9cfbfd76d89c01e59a4ddf9c7605bb758f2bbe994ccfaddbdfd5fe0fb887f8dff843ed310131d23f0a2d9aaea49f474",
	        "/usr/lib/udev/ata_id"
	);
}
static void svir_256(void) 
{
	svi_reg(&(tinfoil.validation_items[255]),
	        "ac19c9b3b88b85fb57ed37f59a43e84e60c6105dd40d80dd214eb97c12cc3e3ffd0839ac8e2e8e74de4832177f76229845c2729ddba64368770416fbfcad483c",
	        "/usr/lib/tmpfiles.d/systemd.conf"
	);
}
static void svir_257(void) 
{
	svi_reg(&(tinfoil.validation_items[256]),
	        "76d412ed2dbd05a6419cc6d6d365500a6baee8227e15b3f6cacf944346cac69826e5fc5fb2ebc65291bf74e135cda55b66c36e289ea9e70b5a95c0f54cacaed4",
	        "/usr/lib/tmpfiles.d/dracut-tmpfiles.conf"
	);
}
static void svir_258(void) 
{
	svi_reg(&(tinfoil.validation_items[257]),
	        "c7930a1b64966786089f53b4cde538ebc32a761174778ad6d36a0f6b273d03b5edf9bd2365d0e01d21263084c1d7f70b79c155d9eefb49ebd836c009fd3e2d62",
	        "/usr/lib/sysusers.d/systemd.conf"
	);
}
static void svir_259(void) 
{
	svi_reg(&(tinfoil.validation_items[258]),
	        "3fe4aa169c3a795ebac4e249ed416f9ca88da0dc3e46e2c6f2d83bd2631262699cddd47ea2de42206bda1e0b5b46bccc985fc80a0db12862c653df3f4a80cd41",
	        "/usr/lib/sysusers.d/dbus.conf"
	);
}
static void svir_260(void) 
{
	svi_reg(&(tinfoil.validation_items[259]),
	        "292f1ade4fc0bade3a79ac273eb91226cabc6101415c383148bac41e3ef97b0805eadd7bf686b718276d71b57783e0bfdc274b5cfe70f80dadd0d926fa58880c",
	        "/usr/lib/sysusers.d/basic.conf"
	);
}
static void svir_261(void) 
{
	svi_reg(&(tinfoil.validation_items[260]),
	        "9119944d8bf6882a7f853854504a921219940d63e9cd9a14212ecadee324305773e2d4469e542ccf54cd8a0b34fe47dac2f005a66c1a0d6d97c901eca040bf9b",
	        "/usr/lib/systemd/user/dbus.socket"
	);
}
static void svir_262(void) 
{
	svi_reg(&(tinfoil.validation_items[261]),
	        "0e2a1449bbf7a7da6ec47a4a6a43e484020816a15838e77046bbe7727690659109bfc88cf0ff5377c9d4153cbaffccb33de85e71d6b29ba28cae1fea99f83189",
	        "/usr/lib/systemd/user/dbus-broker.service"
	);
}
static void svir_263(void) 
{
	svi_reg(&(tinfoil.validation_items[262]),
	        "a4ae0e06989b79d443de78b1797183878aef58184ab6bb411300b3f12fd440b77b08bba7ee9035010664febd31bc6bac6ea6d46fc47a40b4d10cbaa45d33b4b1",
	        "/usr/lib/systemd/systemd-volatile-root"
	);
}
static void svir_264(void) 
{
	svi_reg(&(tinfoil.validation_items[263]),
	        "97c183ab876e1b3fdb534363893789f7919e4ff7bdfa0e27807361e187b7f25b0a0f8ff842534331424ec1c954c09ce4cf665bb5c223687ad3e202cbcad8fb28",
	        "/usr/lib/systemd/systemd-vconsole-setup"
	);
}
static void svir_265(void) 
{
	svi_reg(&(tinfoil.validation_items[264]),
	        "058f5e542ee0c57db34544a61aa31e15abdffcfcd7e2fac788794ad8858aba38ad72555647e6178a9c58e99da0b5b3dc4408c87a251bdcbd6079a0918211433b",
	        "/usr/lib/systemd/systemd-sysctl"
	);
}
static void svir_266(void) 
{
	svi_reg(&(tinfoil.validation_items[265]),
	        "cba3fffe157f1b370b4edab1e674dec9fc5413e471eedf6f12b2b69fd327e5337e2f7a97647e8fd6b37ffb37fedac400e1075a9dd5863cae454efb0aaf036657",
	        "/usr/lib/systemd/systemd-shutdown"
	);
}
static void svir_267(void) 
{
	svi_reg(&(tinfoil.validation_items[266]),
	        "f53660d38790af7701b3fe48c9f771214042a3df822b1446f2d0d6d2c7c21a0c4d145f74ba4e032e91c6738fb49e177777cac31c123117d1de170879d2b56275",
	        "/usr/lib/systemd/systemd-reply-password"
	);
}
static void svir_268(void) 
{
	svi_reg(&(tinfoil.validation_items[267]),
	        "5c0fa5054f06e2641d72d4ac64a56ed7deffa5ba095e1232a14d23f4d29dff801972cba1c71893af326b5983d2948e49181617d941ebe1b15aadaa5cbc3dc6ce",
	        "/usr/lib/systemd/systemd-modules-load"
	);
}
static void svir_269(void) 
{
	svi_reg(&(tinfoil.validation_items[268]),
	        "67076789b802f54ef6be5d9d86a975efd02eb483c25e4dc3385964ee46b9644da85ea3977dc18387b32b6076ab6b1b778fc9c42e60f591e6f83a33ca1209b68b",
	        "/usr/lib/systemd/systemd-journald"
	);
}
static void svir_270(void) 
{
	svi_reg(&(tinfoil.validation_items[269]),
	        "7f94a6095df9780245f797123b835713352b288214b40cb938fad004f2fa700a1de61b00af02c2e959dc46497506347c21fcf46a54e4ec6fcf82389bd753054d",
	        "/usr/lib/systemd/systemd-fsck"
	);
}
static void svir_271(void) 
{
	svi_reg(&(tinfoil.validation_items[270]),
	        "d7e0640f3098403ddc039d778b88b2209ee4d28c5c76f48ca2b6fc908eba16960f17346737e679ff52da04884d580bc22d36028e8c11ae7f9330487cbc9c0277",
	        "/usr/lib/systemd/systemd-coredump"
	);
}
static void svir_272(void) 
{
	svi_reg(&(tinfoil.validation_items[271]),
	        "4d115c6ba06df4517d05449957ae8dfd5f040658322ecec9840dab6c9de27685d00a90a91451d7a4b79953d3fc181c2a1c17d2221e61b8247fa6a7f28b4212af",
	        "/usr/lib/systemd/systemd-cgroups-agent"
	);
}
static void svir_273(void) 
{
	svi_reg(&(tinfoil.validation_items[272]),
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        "/usr/lib/systemd/systemd"
	);
}
static void svir_274(void) 
{
	svi_reg(&(tinfoil.validation_items[273]),
	        "c3562221328b407e6c65125b5dfbef23f7bf646bcb3f43909bdab2d1f43f47089e64fd11ebcee487ce9bb26704afcb00c642ee3abd296348145134ffaadb7c40",
	        "/usr/lib/systemd/system-generators/systemd-gpt-auto-generator"
	);
}
static void svir_275(void) 
{
	svi_reg(&(tinfoil.validation_items[274]),
	        "cba9690c6bd6636c831343aa15e51212022ce61eb17b056440a8d1581fcb11433f76e2cd665c1ad530634182f1321c077061c716900f49f9a904e60e6039f58c",
	        "/usr/lib/systemd/system-generators/systemd-fstab-generator"
	);
}
static void svir_276(void) 
{
	svi_reg(&(tinfoil.validation_items[275]),
	        "d28760bfb13fae9081426b839ae97e9ff15b95f88286a3beebcba1cf8831f45a25c411e8b4210c4e3fa317913528367524da64f328afa7a3677e193dcd30fdf1",
	        "/usr/lib/systemd/system-generators/systemd-debug-generator"
	);
}
static void svir_277(void) 
{
	svi_reg(&(tinfoil.validation_items[276]),
	        "eb5b83d61e201ff9b9b19f212d85e7ba1b27087bc89caef72c889328da3784f3520052938b34b3827655fe0f32e0b0322651405d106f0f7eca7cd18f9eab0caa",
	        "/usr/lib/systemd/system-generators/dracut-rootfs-generator"
	);
}
static void svir_278(void) 
{
	svi_reg(&(tinfoil.validation_items[277]),
	        "99b8a15cd1bfcb8467bbe28262645204d78f2d5310376e5d804e34d3ae3a24141b2c4fccae29b02ea6f87adbc0857b5d2cca35c4c86b6addb174862d6ebce189",
	        "/usr/lib/systemd/system/umount.target"
	);
}
static void svir_279(void) 
{
	svi_reg(&(tinfoil.validation_items[278]),
	        "00fabbdda72c1d0faf6236484db599a4082caa5576cbcd48ec5e0c2954ed352b33da145702bd739b45493b2dffcb237211cea97361b9ba61f9d9f1fcf551c807",
	        "/usr/lib/systemd/system/timers.target"
	);
}
static void svir_280(void) 
{
	svi_reg(&(tinfoil.validation_items[279]),
	        "4d5ca5f3b609b03680ab2144aec5142b60350780c6bb665feee3a5977631f7912dd485f1e7d1166724f3b74d4f2bb1692aaa4ac193ab1988ba1352fe5923fa42",
	        "/usr/lib/systemd/system/systemd-volatile-root.service"
	);
}
static void svir_281(void) 
{
	svi_reg(&(tinfoil.validation_items[280]),
	        "ec2a06ad78b371364d9f5d3ee3e7b997eb0ceccf60baaa0c1f3982bef684e64a4395b3ff73f2f01e415eb85cb2c4f2c8863087808617e576f06ec7b1e005ec91",
	        "/usr/lib/systemd/system/systemd-vconsole-setup.service"
	);
}
static void svir_282(void) 
{
	svi_reg(&(tinfoil.validation_items[281]),
	        "59a776f9131d7eb06414d36cbaaae9f8e1304525155d615121d469335939d734ea80e2e02979db73152e0d6ba8495f2f4bd030856fb8b6e3d2b1c6882dcce83a",
	        "/usr/lib/systemd/system/systemd-udevd.service"
	);
}
static void svir_283(void) 
{
	svi_reg(&(tinfoil.validation_items[282]),
	        "7897edcaa2c059062c887b2a50d4afbe785e23d89ecd490bc9d4cee62a81f2fa9e43f31a560a7366c35e80645ce87c672944007c2fd49045aa6514c400b4a41e",
	        "/usr/lib/systemd/system/systemd-udevd-kernel.socket"
	);
}
static void svir_284(void) 
{
	svi_reg(&(tinfoil.validation_items[283]),
	        "ece3549b70d3f3e22908c58343bae8e5b066d49897e12eac27932b722875b3ba1cf4d4db8db515548b3d362d9edc66e0041aaa01bb0e1ca067f01be13bde14d6",
	        "/usr/lib/systemd/system/systemd-udevd-control.socket"
	);
}
static void svir_285(void) 
{
	svi_reg(&(tinfoil.validation_items[284]),
	        "75e494f1b20edacf5369e3a830ecc81dd75000d647572e8bfc7e131c77292b90a8b761b16b306d99dd51c0bdbe797cd944a0af93935dbfd2a0f98c059166468f",
	        "/usr/lib/systemd/system/systemd-udev-trigger.service"
	);
}
static void svir_286(void) 
{
	svi_reg(&(tinfoil.validation_items[285]),
	        "686dd5559bb501b5b40b9aa11ac7b9c6566b93cec0fa25b614c8b1b8189498f3a918906f4b8a71be45d45a804459d812642e297b43658b4f5c0c76156f8402d8",
	        "/usr/lib/systemd/system/systemd-udev-settle.service"
	);
}
static void svir_287(void) 
{
	svi_reg(&(tinfoil.validation_items[286]),
	        "9de5cc6a1c9f772c7c3fe687040e7445d78dc8889d2c9847c775460d164f8cc7f851b51fa7c11ce3757effd0c916f49080809f59582b054bf79fc17bb25c05cb",
	        "/usr/lib/systemd/system/systemd-tmpfiles-setup.service"
	);
}
static void svir_288(void) 
{
	svi_reg(&(tinfoil.validation_items[287]),
	        "663e53b4ab75aa65735c8416bf34c72f72e868def15ac56de79d84e291d7116974ec522e67129c82e2bfc45772f7dc7a5bee666391fbd0826b959f275554b5df",
	        "/usr/lib/systemd/system/systemd-tmpfiles-setup-dev.service"
	);
}
static void svir_289(void) 
{
	svi_reg(&(tinfoil.validation_items[288]),
	        "ca72cf9662b6eac85d7a24aa51d41c5a31b897ce2974280502349473d809e55a6b7db195371e1ffe9bd8cd60a2a147159d649c9c936d3d4c9c2c6b843f940bba",
	        "/usr/lib/systemd/system/systemd-sysusers.service"
	);
}
static void svir_290(void) 
{
	svi_reg(&(tinfoil.validation_items[289]),
	        "633997508b500198596bbf58d7a964d1cd59fe2d49c42490835ff7a00febbcc759634523f0093e556373a5a43103e2d362952990ec52ea568b19a69583baa6dd",
	        "/usr/lib/systemd/system/systemd-sysctl.service"
	);
}
static void svir_291(void) 
{
	svi_reg(&(tinfoil.validation_items[290]),
	        "2731f8cd2af96ff04aa6dc7803f952beea1b0b853e169c7ee72b60191b3390857c2ff72c46951691da2af0253582df443570180652619905d8f112fca6602492",
	        "/usr/lib/systemd/system/systemd-reboot.service"
	);
}
static void svir_292(void) 
{
	svi_reg(&(tinfoil.validation_items[291]),
	        "4c8d3a4ba6d2f96929ac153b94548325e0f19ed1519efd3f9484cda91c5a304aa820bee50621cc40da8da522d2010d35930ccf152c41b6b074449293691453fa",
	        "/usr/lib/systemd/system/systemd-random-seed.service"
	);
}
static void svir_293(void) 
{
	svi_reg(&(tinfoil.validation_items[292]),
	        "89a1a8b6258b42623477c3a7d6330bbe1dbb5dd80006304de26f794e61bc05af604f96baacb2de278a9bdb671232b1dcb3a51150ccb240ced404a72711811960",
	        "/usr/lib/systemd/system/systemd-poweroff.service"
	);
}
static void svir_294(void) 
{
	svi_reg(&(tinfoil.validation_items[293]),
	        "5a3dc386d9c703133c493fcf8cc7f8bd93486bdd0f159e885926609e4a7eba4ee53e477017d52df26a049642bb3a8b1bff8a5c90c70ec5d30d0bc5d75552e3e2",
	        "/usr/lib/systemd/system/systemd-modules-load.service"
	);
}
static void svir_295(void) 
{
	svi_reg(&(tinfoil.validation_items[294]),
	        "9e39cf17d28e94594c4a009d4622ea333c37652705e7089c2d174ec7d44ce19d6fa6b8a19b03177e18a6b28eccc7950c55de9818e46fc9b3d736568ab23be5c7",
	        "/usr/lib/systemd/system/systemd-kexec.service"
	);
}
static void svir_296(void) 
{
	svi_reg(&(tinfoil.validation_items[295]),
	        "b2c2f9359e55418dc15c97c5db56a375811c981b1a1b49360aef9e1534b98e5a898853e6446f98ce23245b4ff16ba938f6c16e031df47869360249856a26aea2",
	        "/usr/lib/systemd/system/systemd-journald.socket"
	);
}
static void svir_297(void) 
{
	svi_reg(&(tinfoil.validation_items[296]),
	        "5c22f4818d20015003a58586f3cf4954e181154aefcf51ff8af78e843945a70b94d9d4c8eaf9be78e84a35ed5d07c4b3f4724fac808c999b1508687d3d781dc1",
	        "/usr/lib/systemd/system/systemd-journald.service"
	);
}
static void svir_298(void) 
{
	svi_reg(&(tinfoil.validation_items[297]),
	        "c5324e22ebe42377e5d4d0f365037ced41384343126fc78a801045bbcda3921a5904e057b4929626b10f9425d1faf24993b945bf765349fe1f20c20f546c6a53",
	        "/usr/lib/systemd/system/systemd-journald-dev-log.socket"
	);
}
static void svir_299(void) 
{
	svi_reg(&(tinfoil.validation_items[298]),
	        "877a94ee6ec1f8e20f556b15d884535fa19de52ee541c5ef48182970dada4ca8952a45e39127aceb51a8514dc286a62a239d3ba3857976bb09be47e767086dca",
	        "/usr/lib/systemd/system/systemd-journald-audit.socket"
	);
}
static void svir_300(void) 
{
	svi_reg(&(tinfoil.validation_items[299]),
	        "7af4817da87a12d8f55a7478c0b624f55654b3fa6abc894e34ef9c17a6f3dff1969a2d920fce696de86e51f33e5ab8a322b0b4a0302d349f35f263eb3b0fed27",
	        "/usr/lib/systemd/system/systemd-halt.service"
	);
}
static void svir_301(void) 
{
	svi_reg(&(tinfoil.validation_items[300]),
	        "f6196c0ea4b68110b256d90a34931c4db243ca0a0dc2f5bdbae57098449c17cd57e4cefcb382c4d42cc55939693be24f8fbfc37a859b4ad829390973a6da2db2",
	        "/usr/lib/systemd/system/systemd-fsck@.service"
	);
}
static void svir_302(void) 
{
	svi_reg(&(tinfoil.validation_items[301]),
	        "df691d6871b9f6a5fbb1e4bb3e2ff45be09e8b38e3c68654b9ef7cc0cf828541e9a9b304788e51232c87a58ecca6e03af5860d1362aea83e951c70e57b3f8533",
	        "/usr/lib/systemd/system/systemd-ask-password-plymouth.service"
	);
}
static void svir_303(void) 
{
	svi_reg(&(tinfoil.validation_items[302]),
	        "15fa20b10680c5152ab80aef73a3fe27eb6562c35bf0fe73cc5789902d80a34cf9db24beeb09c82e0855a187acdf973bb8cb826e9a6099ebe86b0246e4ca4cbb",
	        "/usr/lib/systemd/system/systemd-ask-password-plymouth.path"
	);
}
static void svir_304(void) 
{
	svi_reg(&(tinfoil.validation_items[303]),
	        "8dce784f3e14f64185113eb2f9712482188c2ecaf474b2e836a7b9598f74ae56c4e9ca81a5af6ab709fd8553dc6595bbdc18f1310cf3d11c09de60eca3f61ec7",
	        "/usr/lib/systemd/system/systemd-ask-password-console.service"
	);
}
static void svir_305(void) 
{
	svi_reg(&(tinfoil.validation_items[304]),
	        "923fb4f79eb9e75798ea0deedc82c767a732c42d29a38e374e53f966fcd67ccbd28bd4f0a5e5a70d3bf6be344b5ec2aebd2948d9cd5f1870a7baff808e549bfc",
	        "/usr/lib/systemd/system/systemd-ask-password-console.path"
	);
}
static void svir_306(void) 
{
	svi_reg(&(tinfoil.validation_items[305]),
	        "bbfe8ca8afdc60f0051be94fbcef51cb7346d2c4fefb96a5a05538078e011d44fd16845956ef9aef43ed26366683f4b5ab94557ebf8bba8620c1ccc7c93fd489",
	        "/usr/lib/systemd/system/syslog.socket"
	);
}
static void svir_307(void) 
{
	svi_reg(&(tinfoil.validation_items[306]),
	        "6beb22fb1ad55d38c7cf09dd2221733698d37df517397840e6901ed6b3a3c2f33177718d6573566ce78f137d6f25c69f57f93b0122c703e74cccde09ca3ea541",
	        "/usr/lib/systemd/system/sysinit.target"
	);
}
static void svir_308(void) 
{
	svi_reg(&(tinfoil.validation_items[307]),
	        "3465700ef74598ae4839a5d27496ccbd912d9d69d0af80aa493744211bf5e01e6d6a0f2fe548f2868d3b88112f6f62a3e5421e3dc2b52f4b723b2190618728a1",
	        "/usr/lib/systemd/system/sys-kernel-config.mount"
	);
}
static void svir_309(void) 
{
	svi_reg(&(tinfoil.validation_items[308]),
	        "2b403f14419779645aa1226bac34759a05f06af1e7cfefd7ab7a6f5d3a78b61718884d5695d3b6714979ad79b22f546646f110d9b6e168e8ad4b5e18440ac692",
	        "/usr/lib/systemd/system/swap.target"
	);
}
static void svir_310(void) 
{
	svi_reg(&(tinfoil.validation_items[309]),
	        "f72d46793fe778523616ec5ed68406017e29eeac4317f95ce9f9de797d3bf977d002900a896c58c7b1d8333eb3c33332d53b212eb35bc8189f375343aba3db2d",
	        "/usr/lib/systemd/system/sockets.target"
	);
}
static void svir_311(void) 
{
	svi_reg(&(tinfoil.validation_items[310]),
	        "4abfe15bfc58aa93f8fc2325b03a68628643481d04f89ebf984f36a8c62635f617a8fbb7e144ac0a2e31ba588acef0c9b999d516950cd1d00762ded87bcb0085",
	        "/usr/lib/systemd/system/slices.target"
	);
}
static void svir_312(void) 
{
	svi_reg(&(tinfoil.validation_items[311]),
	        "c1d96c535e01d7c0f899da2f88671e52f2a6473ec1519ea566ef3b7feae4fb8fe6dc740acd754d26b9198dd17411af8c2e45869413cd906bed222c328ed3259c",
	        "/usr/lib/systemd/system/sigpwr.target"
	);
}
static void svir_313(void) 
{
	svi_reg(&(tinfoil.validation_items[312]),
	        "731855444c11be66175ca2d54857863947297aba895474d425ab6c57432360d725851659f00c937c958c638f773e2af35033ba14966f11cd15f33860f6619524",
	        "/usr/lib/systemd/system/shutdown.target"
	);
}
static void svir_314(void) 
{
	svi_reg(&(tinfoil.validation_items[313]),
	        "4248da8e62134aa444956477d8025c8cd953966773a90fade11e78df4309ea037eaaa4c251da960502d29e3bc579f78e10ffd417ccb26625652e087db0d07947",
	        "/usr/lib/systemd/system/rpcbind.target"
	);
}
static void svir_315(void) 
{
	svi_reg(&(tinfoil.validation_items[314]),
	        "11e786d0360bd7cfe008930bf85713187dafb4be605445480f4737cb360f7f69e8ab66de3055cb0c08b0f1106e8d2a220175732538c918e7033287f789762ab6",
	        "/usr/lib/systemd/system/rescue.target"
	);
}
static void svir_316(void) 
{
	svi_reg(&(tinfoil.validation_items[315]),
	        "3c3489d9f4d9a1922a28c3a7b37b49d2076602ecf6b6a7e1f793756d07acc81c9195a691330cde8e7d8810d0e64baa53fbe9788e42e55b8414fda249e89025b9",
	        "/usr/lib/systemd/system/emergency.service"
	);
}
static void svir_317(void) 
{
	svi_reg(&(tinfoil.validation_items[316]),
	        "3c3489d9f4d9a1922a28c3a7b37b49d2076602ecf6b6a7e1f793756d07acc81c9195a691330cde8e7d8810d0e64baa53fbe9788e42e55b8414fda249e89025b9",
	        "/usr/lib/systemd/system/rescue.service"
	);
}
static void svir_318(void) 
{
	svi_reg(&(tinfoil.validation_items[317]),
	        "61173dec82d62994231d4cb1a33f62812a7edb5ce0a5e26e64ef4695b05211da999c3ec092837d625023781e4b752bc45e9aa2b404fabfdd1b16315fc7dfe276",
	        "/usr/lib/systemd/system/remote-fs.target"
	);
}
static void svir_319(void) 
{
	svi_reg(&(tinfoil.validation_items[318]),
	        "04fd9b7821f11ab2f9ccea2c6b47ba135262bcd9d2b40c7db228c6961e825b796b57b0e19689c9950a64aa15a6a25bcb6d03ed6c9e61284de724a07044194aea",
	        "/usr/lib/systemd/system/remote-fs-pre.target"
	);
}
static void svir_320(void) 
{
	svi_reg(&(tinfoil.validation_items[319]),
	        "afb64448c60d2f64da2828b48f251d12a4f43b4af3440dd2605949d4ba8abc94b71466352e96a55d6a6f2eaee493001e935323c2c7d883a250a88528bf078db6",
	        "/usr/lib/systemd/system/remote-cryptsetup.target"
	);
}
static void svir_321(void) 
{
	svi_reg(&(tinfoil.validation_items[320]),
	        "e6d1a5544f39c504297ebe8587b863e321c90f06c0d5e6b105c74441b81d8f290c90655985dd545888e575d654ffd3360fd74ce85e16ee7fb31c7d0f1f5202b7",
	        "/usr/lib/systemd/system/reboot.target"
	);
}
static void svir_322(void) 
{
	svi_reg(&(tinfoil.validation_items[321]),
	        "f0b6e53361c2702c3903b63893f9fd9274bd3e6862518f99cfed4a040ea4fd8d330dacb042d2d1a49dc818cd1440ed30869931dcdc06424786fea21c6b14352b",
	        "/usr/lib/systemd/system/poweroff.target"
	);
}
static void svir_323(void) 
{
	svi_reg(&(tinfoil.validation_items[322]),
	        "e7511e0edc3f9e2cceff37077e5ae6fd1c04fb9bf24c7a9f5719f6b8d6314d5b962bb86f3989622f5ab9afeb74273693cb5a93a7e09a32f8b9e0983355f17257",
	        "/usr/lib/systemd/system/plymouth-switch-root.service"
	);
}
static void svir_324(void) 
{
	svi_reg(&(tinfoil.validation_items[323]),
	        "e7c12013770cc1a42e979271a2dc93d7eeff2089afcfe1e3fe5c8b49cf7f015e11ade98a7196cdefafbb827f026cdf5d40e9ac77f30e1c4ed8583bfbd108a9f4",
	        "/usr/lib/systemd/system/plymouth-start.service"
	);
}
static void svir_325(void) 
{
	svi_reg(&(tinfoil.validation_items[324]),
	        "9ddf7cea3e7d9161d025cb51ea34d4e3b401688de70aa0b5b9182ed5fbdd6bbdd3bd998618a902964f9c15b9b2a68ee686a84bd61c7a5195d3439de44beed9d9",
	        "/usr/lib/systemd/system/plymouth-reboot.service"
	);
}
static void svir_326(void) 
{
	svi_reg(&(tinfoil.validation_items[325]),
	        "3fd142157dada7ca56e91cd5635a0ca982aacf6ab1ca508f3762af27d6a8d9fccd43dff6c2dcc0d8eddae4b23ea2436c6edb0404330bd10389374940de9d5b4b",
	        "/usr/lib/systemd/system/plymouth-quit.service"
	);
}
static void svir_327(void) 
{
	svi_reg(&(tinfoil.validation_items[326]),
	        "410d6c24644929f44120c156619952db31085b58709fe60067f6261a05a30264172ab6bfcabff8952ab5e3ddda2ea2c1737750931b5d9e6ca2b7903e8f29f84b",
	        "/usr/lib/systemd/system/plymouth-quit-wait.service"
	);
}
static void svir_328(void) 
{
	svi_reg(&(tinfoil.validation_items[327]),
	        "16e7ac8ec20c02473f7ee7026e02c95cedafaec97cb63f1b71a0ecdd7e87dee2ead9513dd653b061ffb3f5f224a3d55cb3a693ae49ec3bcd4b82fb76b49481dd",
	        "/usr/lib/systemd/system/plymouth-poweroff.service"
	);
}
static void svir_329(void) 
{
	svi_reg(&(tinfoil.validation_items[328]),
	        "79593453f03fb6db77084c8103f734d1e1c4a882cac1b7845dfde7cfce36e75d5aa6355be752897c53419d1377c5e35b90a9c2fb97f9b2bf0e54c4ff47ea74a2",
	        "/usr/lib/systemd/system/plymouth-kexec.service"
	);
}
static void svir_330(void) 
{
	svi_reg(&(tinfoil.validation_items[329]),
	        "d59f17605d143fb29c1e66d585441a6fb3ef1b55f8c990a721d0020d57e7e7d54569e5338f204592c76368928271d444b003059b824ecdb8d9b8bd866f678bfd",
	        "/usr/lib/systemd/system/plymouth-halt.service"
	);
}
static void svir_331(void) 
{
	svi_reg(&(tinfoil.validation_items[330]),
	        "b689b293d0666f51d8c71054c3de477dde534063d145da7aa3cceb84d7d803a30b9330320297e578fbae7f9fc9e22d3568c41a54e131db430b3e582e951cba10",
	        "/usr/lib/systemd/system/paths.target"
	);
}
static void svir_332(void) 
{
	svi_reg(&(tinfoil.validation_items[331]),
	        "deb436081f71b12a8db996f9f2cb31d1ed24dd86d4f04f49a964001252b158e31d39eeb54d9c3b981b69c8f590ae5cd900b0c0d734b7b1ba985f67bb6c6da640",
	        "/usr/lib/systemd/system/nss-user-lookup.target"
	);
}
static void svir_333(void) 
{
	svi_reg(&(tinfoil.validation_items[332]),
	        "007e81979310dedf551ad8d822186e82b504e0fef33312b0d7b5d1f9efd0e1b860885978821abdc7c25cdd195a6be5eeabdd44d3bcd8455f294ab89152fae722",
	        "/usr/lib/systemd/system/nss-lookup.target"
	);
}
static void svir_334(void) 
{
	svi_reg(&(tinfoil.validation_items[333]),
	        "a5d9959a98c5aaaefd8da0d61023e42df381d10d137e18d33cbb606f879b4c613288fe773644be37c576409378bb752a3866010a9831bbef67343d6422930ebb",
	        "/usr/lib/systemd/system/nm-wait-online-initrd.service"
	);
}
static void svir_335(void) 
{
	svi_reg(&(tinfoil.validation_items[334]),
	        "b8f04675d0c66498a28ed201c52db19b7d577b27fd211867e0781d17f19e0e16d88936a3de8b01c890bcff97ce5b766093b15d518f52c0352b9ce93b910e7543",
	        "/usr/lib/systemd/system/nm-initrd.service"
	);
}
static void svir_336(void) 
{
	svi_reg(&(tinfoil.validation_items[335]),
	        "2a879a0ff46b2a8b2a3a00f612fec4dc578131fce6b55a01881b6484b66ef6660b7077e871a8a6ac03eda785ead83f5eacbadca3e7282ef183ba0d6905652bc8",
	        "/usr/lib/systemd/system/network.target"
	);
}
static void svir_337(void) 
{
	svi_reg(&(tinfoil.validation_items[336]),
	        "ca7248d82d1eaf4608eba6236a94481cc9c3ca69c89904e35b427b36fe625a97d6182d2e95f23d8e3daef1f1bb6847bb83ddeca2cacf2f602445dbc8b4805797",
	        "/usr/lib/systemd/system/network-pre.target"
	);
}
static void svir_338(void) 
{
	svi_reg(&(tinfoil.validation_items[337]),
	        "1ddba06cc6b777d68ee20255fc6ddc251a62a0d1296edfed17838304f185ebcad4f6b54fd7c4acc334f54b563d83017f0dced2779c0f9c639b1f70deccd89ac4",
	        "/usr/lib/systemd/system/network-online.target"
	);
}
static void svir_339(void) 
{
	svi_reg(&(tinfoil.validation_items[338]),
	        "641528e6057adecd2f167e4f43212551c810663ee39dd5c9cdf0aa28655f6b73f0c4fbc594d6f5eb0d8f30e1b4b9dd1bc5d3d3009b28ac4723f46ec5ebbbecae",
	        "/usr/lib/systemd/system/multi-user.target"
	);
}
static void svir_340(void) 
{
	svi_reg(&(tinfoil.validation_items[339]),
	        "fc8eab203ea1cfa9734408adb806e9019f290de82fac8a288301827f7aeda58e44d7a3733142f314ffc5f75b7649fb0d4f777a0a2b2da2add57803894e39eb59",
	        "/usr/lib/systemd/system/memstrack.service"
	);
}
static void svir_341(void) 
{
	svi_reg(&(tinfoil.validation_items[340]),
	        "df3bef39d09658d38dd15a6b2ac249efad8962d5fb964dd903ffee35bad13f6baaaae635a0a05ea5bad92ea72980ddb9a164da108ff2ef954251aeadbbbc36df",
	        "/usr/lib/systemd/system/local-fs.target"
	);
}
static void svir_342(void) 
{
	svi_reg(&(tinfoil.validation_items[341]),
	        "4c02daae78333e0fc0b68d4506976418f3ab46de27a15f3d9dec1a10177210a4679e1e08230809a8dd756bb58a1b8403472e3aaa0b90ec6a3a69cbe2116dbf89",
	        "/usr/lib/systemd/system/local-fs-pre.target"
	);
}
static void svir_343(void) 
{
	svi_reg(&(tinfoil.validation_items[342]),
	        "a984e07fdd9ca176ae1107fc5790a32449256d64e85107b898ea2384a92f673801873644204130fde563ff771fcdc2c4bf9e93fee764431ff8c8e21a3ec81cea",
	        "/usr/lib/systemd/system/kmod-static-nodes.service"
	);
}
static void svir_344(void) 
{
	svi_reg(&(tinfoil.validation_items[343]),
	        "c1b8b3b6d72e3f7b3e4ff242409720ecad46a749fdaf7ec56f4a650869e56600077a91f8fdcc9021193e66221223f438a6880cd7026208a36fe3bce1bf39acbc",
	        "/usr/lib/systemd/system/kexec.target"
	);
}
static void svir_345(void) 
{
	svi_reg(&(tinfoil.validation_items[344]),
	        "e0d507000e98e675e3d71c628141c89a2f9c6bf15bf74cb1bd7f71b975ef481372e8c249d356e565e8cd9a950c22d12e47d008325521f83b86ab1e9313ae3280",
	        "/usr/lib/systemd/system/initrd.target"
	);
}
static void svir_346(void) 
{
	svi_reg(&(tinfoil.validation_items[345]),
	        "d746b529364042667716c64aa892da977c90c539b688528e6193ae0bc3590c8d73430b55aba0cbee3b46f8403387e543cd328bc1f1d968580625bd7a405fe52f",
	        "/usr/lib/systemd/system/initrd-usr-fs.target"
	);
}
static void svir_347(void) 
{
	svi_reg(&(tinfoil.validation_items[346]),
	        "2a32b66c80db105a93e65e2da391e771ca511029331cf8f6eaa74efeb111141be5b8e0fdb5e20ee20af0d4f788e0d169cf39798eb24e1fa9541655c90d4e0413",
	        "/usr/lib/systemd/system/initrd-udevadm-cleanup-db.service"
	);
}
static void svir_348(void) 
{
	svi_reg(&(tinfoil.validation_items[347]),
	        "8b9b8fbe92b5ec00aced9dc53621ab17297a5f3e1dd3e7da316ee65f13be6934a35a25554c731e5096961da4bc383154cd39027c2c4c61977e26c0af59d271e6",
	        "/usr/lib/systemd/system/initrd-switch-root.target"
	);
}
static void svir_349(void) 
{
	svi_reg(&(tinfoil.validation_items[348]),
	        "96fe5d3819cc642254ccf86a9a48d5858ed95eeb9eebcdfea1b9524e425ef96a4975145dbd84fada7a69c48dd141f9bcb12fe590207f656cd86fd12e8abe78e6",
	        "/usr/lib/systemd/system/initrd-switch-root.service"
	);
}
static void svir_350(void) 
{
	svi_reg(&(tinfoil.validation_items[349]),
	        "a67ddcee4ecf272f1386c1c46caaea8e6bea80d7574e416e51acc08fc54b4bd13987194ae8fe829919dab00defbec1ca996757bfac55a2dcb3e7704544da3cd6",
	        "/usr/lib/systemd/system/initrd-root-fs.target"
	);
}
static void svir_351(void) 
{
	svi_reg(&(tinfoil.validation_items[350]),
	        "510ac21b414407f407036e6d46864bfdafe11e18c932c8272fd4f46b1a5dcc0045979fc3bf736c4ef5326de74d17146d829d71a9f8ce0aba63bdcd8738ecc9ce",
	        "/usr/lib/systemd/system/initrd-root-device.target"
	);
}
static void svir_352(void) 
{
	svi_reg(&(tinfoil.validation_items[351]),
	        "d1b45b0d551e4d810c4cbff85f69699b0b46afcf02aa3f2389fbe17b6cc103229ae5cb3dfde4e00d1a7d84994a96a418c767218a1fdc686bde16285e21f945d8",
	        "/usr/lib/systemd/system/initrd-parse-etc.service"
	);
}
static void svir_353(void) 
{
	svi_reg(&(tinfoil.validation_items[352]),
	        "a3f3a9e0f619665e5fb2fcd8d37fa7254e81dfca92ebb51866d8196243ef49b4e3027f14246e9f89fa7eb492e74d3da6907d9be3745efa771be099149fd5f109",
	        "/usr/lib/systemd/system/initrd-fs.target"
	);
}
static void svir_354(void) 
{
	svi_reg(&(tinfoil.validation_items[353]),
	        "b75497365d21d11f5dc7950e739640e09de83fc00dbc6844fcae9558f5b675948f17616bdb9c91711b92ee70df974a098a5dab0d0182c5323bcfc639e0ccd98c",
	        "/usr/lib/systemd/system/initrd-cleanup.service"
	);
}
static void svir_355(void) 
{
	svi_reg(&(tinfoil.validation_items[354]),
	        "a1659ae20469e35498638e38f8bafea305b7465203d758250f95304419a7e64f5053567d25525cb9a5804004499e6e95749a3e69741284195a3d83891f4fd3fc",
	        "/usr/lib/systemd/system/halt.target"
	);
}
static void svir_356(void) 
{
	svi_reg(&(tinfoil.validation_items[355]),
	        "62bcc25dab6f8ddb25fe9939fd5a686ee21ec0ee7d7718a737bbadbbc19ed4a2123bef6b228bb2b860b8a2c24b0a7cd2377919ce7b7755508aff00a2a9c047cc",
	        "/usr/lib/systemd/system/final.target"
	);
}
static void svir_357(void) 
{
	svi_reg(&(tinfoil.validation_items[356]),
	        "95bcd01de762c576ce6d8717958c911fd6150326adba2c058a0b2fb794a90b1c1e43391ef3eda244e90f843c1257633cd9a16a69afad9cb99b9b45248bb2a261",
	        "/usr/lib/systemd/system/emergency.target"
	);
}
static void svir_358(void) 
{
	svi_reg(&(tinfoil.validation_items[357]),
	        "ac5a907287ff92712c38da765eeb4ac8755662b8c0ae76ab59768a27e1a92e98c9898ba5ee397b73fb6b468e40a409978b6dd72283a0f4ed1fbc0fcfd418f7bf",
	        "/usr/lib/systemd/system/dracut-pre-udev.service"
	);
}
static void svir_359(void) 
{
	svi_reg(&(tinfoil.validation_items[358]),
	        "8e77ebf9008ae0bb2efc2aaa2759bb3bc5549cb8e48e0133b4ec32542e7e13b8f6a030dcb53da6e8a2fa8dbcdff68f4daff5c9d5a6321b61a24addeb164e89a5",
	        "/usr/lib/systemd/system/dracut-pre-trigger.service"
	);
}
static void svir_360(void) 
{
	svi_reg(&(tinfoil.validation_items[359]),
	        "50c711b564984a4efa055ba907aa3eb8f880f44723f8229f95500adf52fe006e7f63d88adf155cd0714e13debbe4ae3919dc29716079cc638af456bf23dc2fa3",
	        "/usr/lib/systemd/system/dracut-pre-pivot.service"
	);
}
static void svir_361(void) 
{
	svi_reg(&(tinfoil.validation_items[360]),
	        "8433b73acb733cb43fd2840ab663c65fe7ea4b346581fdd11cf0f2f3fc5e8bb60a587b8f7a4255901246a8212f4af8a9c6560e65835b81a69808ac5e413d45fa",
	        "/usr/lib/systemd/system/dracut-pre-mount.service"
	);
}
static void svir_362(void) 
{
	svi_reg(&(tinfoil.validation_items[361]),
	        "cce013a6d12edad01c9ddecf1138329241080deaa3675cce864e349eca3c8d3ec01b6e3a8cd4adb789ee8c9833704e650fb2f1aa9f1652e3c0befbd6d4ece6e5",
	        "/usr/lib/systemd/system/dracut-mount.service"
	);
}
static void svir_363(void) 
{
	svi_reg(&(tinfoil.validation_items[362]),
	        "6e7ada9ac935a9a1e2a41c3b3665e537fcbb25b076469d7f01821412218adf179cec2fd6b544b6b8a9ec59676daa7e31f4501b454fa24f497d3341fd5629bb64",
	        "/usr/lib/systemd/system/dracut-initqueue.service"
	);
}
static void svir_364(void) 
{
	svi_reg(&(tinfoil.validation_items[363]),
	        "587c96f2e700033a8f44feaf064458fb16d087b37f0a82d5beb80e37910402362910ae551e503d99a0e94f2bff998ee9c5d4633b305a04a99e6db909e14aefd1",
	        "/usr/lib/systemd/system/dracut-emergency.service"
	);
}
static void svir_365(void) 
{
	svi_reg(&(tinfoil.validation_items[364]),
	        "3a7402885d6a5d31c51f2751c7cefe6be40cfbb26a38936d02f3a43c21889119a433b625b2582bd999581c795ce2045af0f61bf4342742a26b64ede1709e5782",
	        "/usr/lib/systemd/system/dracut-cmdline.service"
	);
}
static void svir_366(void) 
{
	svi_reg(&(tinfoil.validation_items[365]),
	        "2ed1b7c1c610f72a6ee8b37c26329cdc2a90167acf8887604f0ce462d32363d862d10cd77b6a30c6b82b2c860e7e8e71dc235940bd8d8d13c71ba719ef418cfd",
	        "/usr/lib/systemd/system/dracut-cmdline-ask.service"
	);
}
static void svir_367(void) 
{
	svi_reg(&(tinfoil.validation_items[366]),
	        "8f3f082ed85d8f5528105790788047d9e7d326fe831c29a9398de5dbd04526fb8cf8b4377656497666771d4cc46c34fcb46b69496d4f144267af02e5c36d2c17",
	        "/usr/lib/systemd/system/debug-shell.service"
	);
}
static void svir_368(void) 
{
	svi_reg(&(tinfoil.validation_items[367]),
	        "af3d7d1942e37bf49f4c83af659144f735dc38a864e98a856aec8833d9389362543ef821a9d20eecceca87999bef4997a9a855f4167b432c7f65250f5ed74f98",
	        "/usr/lib/systemd/system/dbus.socket"
	);
}
static void svir_369(void) 
{
	svi_reg(&(tinfoil.validation_items[368]),
	        "b852faee11d35d7540e4d5db1799821818089d00f7e553aba66e018a9fcd5c8929f21e8f167385d4b53bb954183b545e17d9ce207abb3f8d29589c2fbc307ffb",
	        "/usr/lib/systemd/system/dbus-broker.service"
	);
}
static void svir_370(void) 
{
	svi_reg(&(tinfoil.validation_items[369]),
	        "ae96266b961386b6fe3ceabf1f8ec82b084c10bd6ae7ad87d308327a30de4961b8c724a1fc6f08557e6f34eabf8c64e0a20e3babe09ae1b5e98005331b5c9c5f",
	        "/usr/lib/systemd/system/cryptsetup.target"
	);
}
static void svir_371(void) 
{
	svi_reg(&(tinfoil.validation_items[370]),
	        "2845b05e4d58690e02f31eddbee7e4d1f6ee5c08d8e30e44a9fa0e00c96745b20f2f47806aa35979933331a57984ff868942ef70d4ad1a575e61944dde0d44d8",
	        "/usr/lib/systemd/system/cryptsetup-pre.target"
	);
}
static void svir_372(void) 
{
	svi_reg(&(tinfoil.validation_items[371]),
	        "27e7dbe5b96a589861e6473f2e807a057079fd4f7dbc870fb9f64b3145a701c84c60deb86dfcbcab51015a7a808dc8839751cf1201b7a9bcd6c25057a1c5c9e2",
	        "/usr/lib/systemd/system/basic.target"
	);
}
static void svir_373(void) 
{
	svi_reg(&(tinfoil.validation_items[372]),
	        "4e18fdee549a7bbc0930c96eb6c083d6f5b42727ce60ff01acae613f486073fe79fcb208d4050f2bc63c318b3c495548a522ff8bb31f2972db5aaa43f5f64458",
	        "/usr/lib/systemd/network/99-default.link"
	);
}
static void svir_374(void) 
{
	svi_reg(&(tinfoil.validation_items[373]),
	        "8b44b6b41b2e57801c2ee6dc103542a58a8763f5938773cbdd16ae9d877b17c24d70f659f7a28eff8b65eec24e9c7295fa35dd1ced81e36ab659cc7989d032cc",
	        "/usr/lib/systemd/libsystemd-shared-249.so"
	);
}
static void svir_375(void) 
{
	svi_reg(&(tinfoil.validation_items[374]),
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        "/usr/lib/systemd/init2"
	);
}
static void svir_376(void) 
{
	svi_reg(&(tinfoil.validation_items[375]),
	        "aba0ddd691d4cfbc5410df56f049bdbbd6ea2407f182cd6859181f8e5eaa19273d5b09175d70e97778acd402f92165c5a0e903fd717dbce1f25d58c52f8618ac",
	        "/usr/lib/systemd/catalog/dbus-broker.catalog"
	);
}
static void svir_377(void) 
{
	svi_reg(&(tinfoil.validation_items[376]),
	        "984e5962516520deff584f3690d6390fce4df1af546b6d2c54b51907bd96c36e7121b9fbbe675d12d399e0ad0d1ad78671f73df7b291b78e6a3e68d0f3721537",
	        "/usr/lib/systemd/catalog/dbus-broker-launch.catalog"
	);
}
static void svir_378(void) 
{
	svi_reg(&(tinfoil.validation_items[377]),
	        "f5fb70900269e2235ade6754856473107bb7dca97d40ba191d43c48f966554721f86888073641fcef4e90621156e364c276e359415f2ab9337d9e81c7bf292f7",
	        "/usr/lib/sysctl.d/60-libvirtd.conf"
	);
}
static void svir_379(void) 
{
	svi_reg(&(tinfoil.validation_items[378]),
	        "ccc28b8a1766e085106d35fcfbbc25bd31f05ad02ed3bde0f2b19dbe229f947f5e0cfbf3d15ea7692f08b22a11c7c4f889d83b6a1b838a953ee72b79fdb3daa8",
	        "/usr/lib/sysctl.d/50-pid-max.conf"
	);
}
static void svir_380(void) 
{
	svi_reg(&(tinfoil.validation_items[379]),
	        "fb3020307d1a656577dc4d76c3b9f5294027a810dda082e2b45ff87647ee23be8fde333239b2911bd69ee3e247f50adc7bf09094c9918e2f100839253bede6d8",
	        "/usr/lib/sysctl.d/50-libkcapi-optmem_max.conf"
	);
}
static void svir_381(void) 
{
	svi_reg(&(tinfoil.validation_items[380]),
	        "6dd08aa3282400f379a84d160c8ee3a09b71112ed625c89bb606a37f303eae8635ad49e8f9bc6c6d19d6276bb275658a17adffdf9f2393b02c5cc414c5e5e8c3",
	        "/usr/lib/sysctl.d/50-default.conf"
	);
}
static void svir_382(void) 
{
	svi_reg(&(tinfoil.validation_items[381]),
	        "2743e00de2204bdfcb08f4838f49d5e38b0e4886b752aead356923236a5a11f44d5308f4d6672b01e5d9dd94bed18a8a5ae354b4caafd668d146990d6f5981eb",
	        "/usr/lib/sysctl.d/50-coredump.conf"
	);
}
static void svir_383(void) 
{
	svi_reg(&(tinfoil.validation_items[382]),
	        "c3f036310f4c9351c170d4439de0b47374a17b93c3f6d8156499171c20fd4e1a25870e6df39f1a3098d5ba90339d0d27358a544f065f0cb86a18a4582eeb29b6",
	        "/usr/lib/sysctl.d/10-default-yama-scope.conf"
	);
}
static void svir_384(void) 
{
	svi_reg(&(tinfoil.validation_items[383]),
	        "d52ef1164f2911876078255f7005b538caf230a200d7fba39a487c5953af7882490c1841f277495a218ba225ea3d023f46a219044473922bf46bc364d96c5bf4",
	        "/usr/lib/nm-lib.sh"
	);
}
static void svir_385(void) 
{
	svi_reg(&(tinfoil.validation_items[384]),
	        "d75a845dcaf23766ea127277f9feabb043fbdc8ce5bf8af51c5ca75a2221d85a1bd4cf3967205a65d1d41fa6991628da5dacecad757d8656990a07a69e703a89",
	        "/usr/lib/net-lib.sh"
	);
}
static void svir_386(void) 
{
	svi_reg(&(tinfoil.validation_items[385]),
	        "57d23d2778556eafc3035e6be575bf95b4032f123b35f2b1657eff5e7496de253173edc657f90531ee58e25673f4f27a5cd1cc76b14a038edb244f104a231771",
	        "/usr/lib/modules-load.d/open-vm-tools.conf"
	);
}
static void svir_387(void) 
{
	svi_reg(&(tinfoil.validation_items[386]),
	        "3a2d6939cc7e1d107a5b992965776ca27a3e4b79a81032a5ba31f93a00b8fbad473b40f5167cfbeb57cc81b0e6273b23e90ca5095ebb93f293a15bd5e5e0962c",
	        "/usr/lib/modules-load.d/fwupd-redfish.conf"
	);
}
static void svir_388(void) 
{
	svi_reg(&(tinfoil.validation_items[387]),
	        "3439580434862c6207887d23917e031d1efccc9e4b070599bd42f5f05e7a43780e504faec0b0fcfbd3d3c581f22d5c32a2f0da9e8068f8ee0fd3147f5df983e2",
	        "/usr/lib/modules-load.d/fwupd-msr.conf"
	);
}
static void svir_389(void) 
{
	svi_reg(&(tinfoil.validation_items[388]),
	        "57d23d2778556eafc3035e6be575bf95b4032f123b35f2b1657eff5e7496de253173edc657f90531ee58e25673f4f27a5cd1cc76b14a038edb244f104a231771",
	        "/usr/lib/modules-load.d/fuse-overlayfs.conf"
	);
}
static void svir_390(void) 
{
	svi_reg(&(tinfoil.validation_items[389]),
	        "54c48a9b236efe2e1b91bc62f5da01744a9c4a4304e9b9944dcefe4400472cedf2506ae180df03c6e2d1c3c2c828bba46a20f3b70f938b60599bed9190ad8c9c",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.symbols.bin"
	);
}
static void svir_391(void) 
{
	svi_reg(&(tinfoil.validation_items[390]),
	        "aad21b76c028284ada7799ab54bea21959f5cdcbc9d221ddc87d6c7afcdc74891afbc0c07ebcd92fbb592b500553fa4014e3d0e160efa37155c35ab094e48bc6",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.symbols"
	);
}
static void svir_392(void) 
{
	svi_reg(&(tinfoil.validation_items[391]),
	        "0aede37e5568ca16f6e7c774ef63aeea1bcd80af30067cd0ec2ea6ba71e5284c3a9052ec4bc9ce995c511d7ed8c0d1697227dd2fd142e679750727ffebf9e5a6",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.softdep"
	);
}
static void svir_393(void) 
{
	svi_reg(&(tinfoil.validation_items[392]),
	        "2ee6054c6345f19adeb77de82232001deeac4f4c3e5bfff336bd1fe340ba6de70939b8b55b9ba48ac23a3651ce6042e04d8cd6085cbd995fb9f07f94927409c5",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.order"
	);
}
static void svir_394(void) 
{
	svi_reg(&(tinfoil.validation_items[393]),
	        "4eb83ebd06ac0cc018a283e88845d2957efa35465035749cbb647a5b282c7a3b034f2a8bde96388684de59ff25a4d511a7addfee6881887467c4fd3a282ad907",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.devname"
	);
}
static void svir_395(void) 
{
	svi_reg(&(tinfoil.validation_items[394]),
	        "b641eee4b84348be2fdee1dc9489271e810c2743773da574e74541d0f41b409d7a822c00c5d5a3593a7a4d5512c94f7f545099bce395b270812e4488650d48a7",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.dep.bin"
	);
}
static void svir_396(void) 
{
	svi_reg(&(tinfoil.validation_items[395]),
	        "80e0311c8d8a0ca6b6a6474823c7e882dc0325b1af14d2dc28cd9124101dd8f3d96b1cf3815f02af7c2eb53dfee31d58f46e15cfef5fd1c422764ac291aa65ca",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.dep"
	);
}
static void svir_397(void) 
{
	svi_reg(&(tinfoil.validation_items[396]),
	        "3bc0e11866370babb3f8c3060d179eff93303d953a801ea786ed6f766d8b318a9809373ced50bf8c6881aff7dcac5b175146fdf141c302bacef34391f8f1df51",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.builtin.modinfo"
	);
}
static void svir_398(void) 
{
	svi_reg(&(tinfoil.validation_items[397]),
	        "5945516ea79e680f0cfa0705d20a2c9d9ea5b9518ad01575616a6b502a2a49835f3294ffaa9a4f5cf4152b1dd635df1f58c4b49be887f2068d3d57d15d005e34",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.builtin.bin"
	);
}
static void svir_399(void) 
{
	svi_reg(&(tinfoil.validation_items[398]),
	        "4673c2a14a6e3f64b67baaa433c6a6638dfd384e8428ad701d35a507f126b1a0d5c9282991f2f96354df3514039d1081117a5a1ca760a15b511d253d5ff9fb17",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.builtin.alias.bin"
	);
}
static void svir_400(void) 
{
	svi_reg(&(tinfoil.validation_items[399]),
	        "9d9fedf99e62a6845535862c5e40116d952cfa1dd8b9729bce1c9fc5ed0b4a44edd4032ec11c30222ffd526bfa7d48485bca1d37d9b33e5a01c68a407a5c5d6d",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.builtin"
	);
}
static void svir_401(void) 
{
	svi_reg(&(tinfoil.validation_items[400]),
	        "cb5ba403bdba85e6794de8671fcd679e99140b213127966e704a291cfb9656968e20a0f2fafdd4a628fece403c3e5fd592a31162544bc6a3ab9792c3c2eb0b90",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.alias.bin"
	);
}
static void svir_402(void) 
{
	svi_reg(&(tinfoil.validation_items[401]),
	        "fe03ddffb89d14450eab0c9608a8063545c49e50691dd1fbe7891214fc8a14a21e741b88cddd1fda30042a310ce30a1afd8a93284d570ce478fa65c5d74fe5f5",
	        "/usr/lib/modules/5.14.13-tinfoil+/modules.alias"
	);
}
static void svir_403(void) 
{
	svi_reg(&(tinfoil.validation_items[402]),
	        "0a9215bf8f97a43dd7579a76d76431429908a5663c03d9e2bd7a6ba4d55c1db284b4a4a1db5b36022aaa925b7c0fa0fc07ba9404547fdf83d6f29e0b366b4021",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/soundcore.ko"
	);
}
static void svir_404(void) 
{
	svi_reg(&(tinfoil.validation_items[403]),
	        "fea0bbd4ca911066b7fb3ad9caeb34cee87995d5fef88ff6442575feed004fd104d9f4a45b7d3ae15333ce996cc8308f9c0dcb672a5a7d8cc816b6b718b21567",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd.ko"
	);
}
static void svir_405(void) 
{
	svi_reg(&(tinfoil.validation_items[404]),
	        "619a0dc382a717ecc26d8d1f9dc6779cdfd0a56f13e2c3bce9808f6da6c9dedc34b61b3d86c82af2b7fdffd8ae69247d3d7a150ed471ccf8c676236067bd36ca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-seq-device.ko"
	);
}
static void svir_406(void) 
{
	svi_reg(&(tinfoil.validation_items[405]),
	        "aed5139a8efa758fe803fe53e5eacb59e4fce12da89c39325c205b0728b49f30b1f25146f3edfd767df07b4da6ab227b28abc870b82df2c33c8345a288612648",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-rawmidi.ko"
	);
}
static void svir_407(void) 
{
	svi_reg(&(tinfoil.validation_items[406]),
	        "74b94c165f4c3f9cb681544f04f9a081942f657b23c9d976197ad1566f41d098cb82f70ecfd52f39d92164cc12a8d767426260367009dab193b7b6729bcb8669",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/security/keys/trusted-keys/trusted.ko"
	);
}
static void svir_408(void) 
{
	svi_reg(&(tinfoil.validation_items[407]),
	        "d96651f4cec3207e89c757975e6f57fafe7ead7df5c305de2903e643ff814cdb3ae40cb5074001b66143302b2747a853634b59d4226fe8af6566e1baeb9dc8e3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/net/rfkill/rfkill.ko"
	);
}
static void svir_409(void) 
{
	svi_reg(&(tinfoil.validation_items[408]),
	        "aa8b775314df6beded7701792bbd75295929d15471acb4f0f30b2bff6c863c0a2107136a93b20b76271888520454609b94df069ff20235287ae9e8dee4845462",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/net/core/failover.ko"
	);
}
static void svir_410(void) 
{
	svi_reg(&(tinfoil.validation_items[409]),
	        "81596c055e40287573b4b581fc857e997e01b970428ca3fbb59974354f80e6e4d61196c216551612c659bc0d85a1444a5363794ea6e4d4a0c338b188df1a81be",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4hc_compress.ko"
	);
}
static void svir_411(void) 
{
	svi_reg(&(tinfoil.validation_items[410]),
	        "1748799064ec0c37e868a8d4469826e536f2ecbd18cf725afea351bdde46aa476c4b723ab1f35065a8aec4124408c2232a6efe92c5d36590c2f45fd2e417898a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4_compress.ko"
	);
}
static void svir_412(void) 
{
	svi_reg(&(tinfoil.validation_items[411]),
	        "0ec21dd78729818211f378c740d629879d0d388d77b5be6f75d83615c14be955396ca2357e51d3f6daf9c4fbe665d0ff50fad5459a6bd58cdbc75d6dd8712b74",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libdes.ko"
	);
}
static void svir_413(void) 
{
	svi_reg(&(tinfoil.validation_items[412]),
	        "d99a7f07499fdc956855264721e13fd1d669dd99818efe0cba71c703a395c319998927fb08bf769832fe09a052d5edb6e809b8fe56bd224093e12c052a2f3a59",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libcurve25519-generic.ko"
	);
}
static void svir_414(void) 
{
	svi_reg(&(tinfoil.validation_items[413]),
	        "e087c8799414827b06ca5bf3c12dd11364e713019682673793b37486d9a42193cd988a17c4adc6fb62b10ffde213d21a0bda11a3de93a26de571c11f63a35adb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libblake2s-generic.ko"
	);
}
static void svir_415(void) 
{
	svi_reg(&(tinfoil.validation_items[414]),
	        "44fdd0884e784b8309a2e98c76f2c639f9d9cdf55e0417dcafb3098bdccbf710a163041d3df32e39a4c35e5cbb08000a8f96aa6c6bb06ee2c520525f67b464c2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/asn1_encoder.ko"
	);
}
static void svir_416(void) 
{
	svi_reg(&(tinfoil.validation_items[415]),
	        "d6fbe0defcd3e061aaf0380cdcbad003f832be1a716499d1a1371b39f6784b8d472713638f890980ce428d36c79a7d2c3fad7852fac56ac49d9db421b252bf58",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fuse/fuse.ko"
	);
}
static void svir_417(void) 
{
	svi_reg(&(tinfoil.validation_items[416]),
	        "6b23b70f555f562a2dc9c454b50c3f089072a5929740a2a9abdeb5abe883d09763c2cb3b1509dfd29876ec628c76f99d03653fe9165e65d7b332d2b2fb6a5cf5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/vfat.ko"
	);
}
static void svir_418(void) 
{
	svi_reg(&(tinfoil.validation_items[417]),
	        "9240b974741fdbb5d5a4b97883e1a54c50897351792b0bded6c3b9d7c7343a535c6f065c381cbc780ff73bb3fb03a5fbf0966e20289ea436bde7a34a7c9cdfe9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/fat.ko"
	);
}
static void svir_419(void) 
{
	svi_reg(&(tinfoil.validation_items[418]),
	        "4602e774f0ad043a7473e819f635db02ad20df5a14c8a8d7073e6b92f6f75380e9e57dbd4542f048ebcbff93b7261dba2eaa596520817a80afe067aac0cd142d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/xen_wdt.ko"
	);
}
static void svir_420(void) 
{
	svi_reg(&(tinfoil.validation_items[419]),
	        "76be14e2c02fc17859d31ab4ff71e73b51c3c50accc749ca1e96b6b6515fe80133918f4a531d91584ed16827bbd72ffc5f87a624163e2cd309259bc37c6607ab",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdt_pci.ko"
	);
}
static void svir_421(void) 
{
	svi_reg(&(tinfoil.validation_items[420]),
	        "09bbbcdd92d2d981744734c8389dd265e07e25a727a8896973e9f67c4ab3a8cfeb2451b60c8989869e91b41958bcbc34069f4ff4d594101be4e4ac5ccfebbaf2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdat_wdt.ko"
	);
}
static void svir_422(void) 
{
	svi_reg(&(tinfoil.validation_items[421]),
	        "d8253e8f237042a91dda9aaea3ef3f19c54a65427dd7aee6a7da55eb407d5bf4faa660cf4ce7f61d4f0c44c7f85f13316a48c6682dfdeb2761a6fccd4955af83",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83977f_wdt.ko"
	);
}
static void svir_423(void) 
{
	svi_reg(&(tinfoil.validation_items[422]),
	        "8e5ef1ef94bf2898d99dc73e82f9ad9e4d6eadc8ca53381b4f53a63d418ebaf109a20a8b2f554e6b4c9d4b7a02c7f2217b2156987a257d8aa54034bd0ad147ef",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83877f_wdt.ko"
	);
}
static void svir_424(void) 
{
	svi_reg(&(tinfoil.validation_items[423]),
	        "1275e92f8225cd0370d12a620916bcc28e07fc6e74047dc42a26c770f4de397913e7b8bd09cbc38340359016b3294bdf9fadf8764d26dab5e1acd1ce8e263425",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83627hf_wdt.ko"
	);
}
static void svir_425(void) 
{
	svi_reg(&(tinfoil.validation_items[424]),
	        "87da8fa085d73693c4ec452308e1ccf100d905ed19e214b8d1094c3ab331419d38d8a13175bd49cc83409def842351bbed4cc4a214993e02789b3932c0fa0fc4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/via_wdt.ko"
	);
}
static void svir_426(void) 
{
	svi_reg(&(tinfoil.validation_items[425]),
	        "f9e2c2d8e5bccf6fe1359951ddf82ad6beb2b37ddee545b51a0062e063bc1110386f6cb7e569dddca89b09e63ec2b226cb68dcaf53e3e16703e94faf11b9844f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/tqmx86_wdt.ko"
	);
}
static void svir_427(void) 
{
	svi_reg(&(tinfoil.validation_items[426]),
	        "694baf1db15313d307898bb85dc2b09ee351d1f1a4c1eaee7b6628bc416ba47add22fd66eb87d45271d88654155cba0bc773b8625141e7ad33a589c810cc8ffc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sp5100_tco.ko"
	);
}
static void svir_428(void) 
{
	svi_reg(&(tinfoil.validation_items[427]),
	        "f8126733e76191d6111e574edf09701178e4bfe94593eccdffd48071bc6f7ce1851a36f9eec5d9bb8631c7aa08a4b0b701c716a71e7022a56e2f32e0036549bb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/softdog.ko"
	);
}
static void svir_429(void) 
{
	svi_reg(&(tinfoil.validation_items[428]),
	        "eb482dbd450fb3f3f8afcdea3d9f5f656f90e967e8b455847f5111675dfbf3eaebe8b8047f34cd25798bf4788624e47310e0f588d6e2733aade1536c41aab39c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sch311x_wdt.ko"
	);
}
static void svir_430(void) 
{
	svi_reg(&(tinfoil.validation_items[429]),
	        "ae042dcd0d0f6aac4c86bf4253e20b38eccc0f30f0a0be681bedd748bb41cf958b0957cffeff741e166dbf422808c8e19be8d4f1749b792881ef42694e010deb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sbc_fitpc2_wdt.ko"
	);
}
static void svir_431(void) 
{
	svi_reg(&(tinfoil.validation_items[430]),
	        "2fe453febc2006bc36c0cb59d26421c9974884607ce4d408c442742ddee837ec95bacb9d462fe7825be722b3da17624aeaac96b84e6bbeb4b407dd2b319d368e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_usb.ko"
	);
}
static void svir_432(void) 
{
	svi_reg(&(tinfoil.validation_items[431]),
	        "4a96fb97d942e3c16c3181f4b779940622ed894f5b934f3870122d162f3545f269a2cac44469719fe313af73db41539c08a17afef796cc6287353c3d916dddc8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_pci.ko"
	);
}
static void svir_433(void) 
{
	svi_reg(&(tinfoil.validation_items[432]),
	        "a1a06fd49419a23ef5670f2e1e31963dcf95b539cc679bd159678a292e72a2ecdfffb4fcf5ab2d208459a758418eaac80d498c88c9e606582690a010eb6c37b4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nv_tco.ko"
	);
}
static void svir_434(void) 
{
	svi_reg(&(tinfoil.validation_items[433]),
	        "f651c8898aff1dd8b67316c8aafa811ea07ede38977b020a535165a0a3a1041e7b2cf495bda694679e8fa2cb726af7bf8f551d55332c1b5189e6e8ce115c2675",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nic7018_wdt.ko"
	);
}
static void svir_435(void) 
{
	svi_reg(&(tinfoil.validation_items[434]),
	        "a5b840c5cd75a2e4f4f368013c2bd0cf1fc73704616e36a23adf5d7b4ef6b19953c6e1353f6cf6d5b708498c9c2bda53e5a21d54dc48b1a4ec921d40512dec3b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mlx_wdt.ko"
	);
}
static void svir_436(void) 
{
	svi_reg(&(tinfoil.validation_items[435]),
	        "89fe03e916de8ec333d560122dfe39ddae18f702849d2f0d42ed92120f3fb05589cf36eb727e1beeb7aa0307455fabf7f6b908aab740cd86f3c1f795a1fe2426",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mei_wdt.ko"
	);
}
static void svir_437(void) 
{
	svi_reg(&(tinfoil.validation_items[436]),
	        "e3d058b5fa8647f0b714569b0e583a16b99b7ebb2260f947a99c5096521943bf57231ec1c7ca0ae6d9f5649207d69fd9f83396aac8f1568033ac7dda6a8cd53d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/machzwd.ko"
	);
}
static void svir_438(void) 
{
	svi_reg(&(tinfoil.validation_items[437]),
	        "ed78ff05d58c28adb38edc8694a4a614c49ae450a242f18c62ed9f077edd9b42cb50e7bb8982b4c480dc05eca8e531a1e3e77ace1d0d48ddb021d7c3b4f6f3d3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it87_wdt.ko"
	);
}
static void svir_439(void) 
{
	svi_reg(&(tinfoil.validation_items[438]),
	        "96c12ee89d956d6944e67b4f5845459d8d2c6b17f50998ca55eadf74e9286c96b7dca286a76561117a93909d69a51568ff5d65771c6bd77689fd3bef9ad6f546",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it8712f_wdt.ko"
	);
}
static void svir_440(void) 
{
	svi_reg(&(tinfoil.validation_items[439]),
	        "f2eee377a41b9e051209360b7642a6767ad09fa8a2424bf91d6270dfb06f42845bf31dbf69526dc51860709788fe102258ff6a08797824efeb30887f32fb5990",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ie6xx_wdt.ko"
	);
}
static void svir_441(void) 
{
	svi_reg(&(tinfoil.validation_items[440]),
	        "1638d6c148473db5f0176b558ffebe83c80d694e11c7b4fcfdb313a5762f5796bd4aa4ff91b7e0ce964b471e744aee7c69da57c135ac3a71623be8f5f8d2d5db",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ibmasr.ko"
	);
}
static void svir_442(void) 
{
	svi_reg(&(tinfoil.validation_items[441]),
	        "1147cf0cfb613f22b17c8ec429d835ce24cb8cb92b555bfb0d3fa140913b2c81cf00fd1f98797f3f23aef618cacf0b679fb58d7f55f38a6aaee8eafe10a4117e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ib700wdt.ko"
	);
}
static void svir_443(void) 
{
	svi_reg(&(tinfoil.validation_items[442]),
	        "1541d4430080fbb1e684d8fbfb132ee4afb63424836f5177b6ea95c269120b3e272418d7050bf82d85ebbb8187afef5aa7085f144bf8ce282e170dd36db86cdb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_wdt.ko"
	);
}
static void svir_444(void) 
{
	svi_reg(&(tinfoil.validation_items[443]),
	        "e1b4ef9a2c0e89483febbcea687b0a647b5cc31a05b096e86513162b66239adb584c187b5b0792a1ef2c1377bc62d11f165a9703af5c0f673137f3ce403ae5e2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_vendor_support.ko"
	);
}
static void svir_445(void) 
{
	svi_reg(&(tinfoil.validation_items[444]),
	        "3ddef132a883a0e807ee3f3bd7548fde5ea9292511bd03b451c03bcbd89d6f845c0dc40aa5884b30497dd2b8ce67fa33c0dbe6ce5dbff78614b1de001985f413",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/i6300esb.ko"
	);
}
static void svir_446(void) 
{
	svi_reg(&(tinfoil.validation_items[445]),
	        "a893b37d81397dd55910b17115c72456de5233f0da3d25013f427b68537edbe7134694c8997c53e20d4de49005df15e5e8415b15c6c6b22d81d95a568fab9af1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/hpwdt.ko"
	);
}
static void svir_447(void) 
{
	svi_reg(&(tinfoil.validation_items[446]),
	        "d3fa6c44edc32c12b538d153b41dbac1110b454bf0cc6655537bf2c6bc920012dd0fd398ed25059bc10804969a36caee12a1f3d7540a2fdd4efaaee923c4a05f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/f71808e_wdt.ko"
	);
}
static void svir_448(void) 
{
	svi_reg(&(tinfoil.validation_items[447]),
	        "2eca831a8f19f6341a904a34fbab7d8ee0f89d30abfe957509649744ab6c841f910d9dc1b48cb8abbc0ae78ea45e7046bed9c7e90bc2c0506799433600e7ff00",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim7101_wdt.ko"
	);
}
static void svir_449(void) 
{
	svi_reg(&(tinfoil.validation_items[448]),
	        "1ceaaae26a3c033bc4e454f9c45e3f4e892684444108805442da8d54f36b981bdac981946f734f51b92bebd2a61d3e189d1283651fcf44f2b43fef173daea63b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim1535_wdt.ko"
	);
}
static void svir_450(void) 
{
	svi_reg(&(tinfoil.validation_items[449]),
	        "b1a633f8fdbd26597e621a9b1a18d74f0e6be3701c9318bcca76a5a769b2c88731f84ec9d0c9aaafe8e7dff7c0d6f9cb4ff07c1906a40d0c3289cbb3c6788fff",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/virtio/virtio_mem.ko"
	);
}
static void svir_451(void) 
{
	svi_reg(&(tinfoil.validation_items[450]),
	        "0506dd4c1d7c52b216e651c99510c952c8b03f02c1e842bc0b8afb3b32e0372db118909cc8e18fecd26a34b7e40161d97e9f0329a989b43e4b7d091c896a88e5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/video/backlight/lcd.ko"
	);
}
static void svir_452(void) 
{
	svi_reg(&(tinfoil.validation_items[451]),
	        "c30c19caea0d916578f42cb7d68c4cbb9ec4fee96e3af0c82a5fc426824250a774c555810c7d93df8c9d362131007d04a920ea575b7da27157b7e86506ca358b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_ccg.ko"
	);
}
static void svir_453(void) 
{
	svi_reg(&(tinfoil.validation_items[452]),
	        "685e54b4eced2bad86a740bc204a0f4c01377dd618e34ad6baa147fdd2effe2582325937848728dfc99a387cbd102c8aea282184400a07f1adddbbb5ea32dad0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_acpi.ko"
	);
}
static void svir_454(void) 
{
	svi_reg(&(tinfoil.validation_items[453]),
	        "88ab43eee5a2de4b8d0a1cfde42ca9dcb6f61420306bb08a7b273176b59b1570cf4fc5afaa98448553a22a88a9d4cff11d4a3bdd90d04332f5361df4e24e528b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/typec_ucsi.ko"
	);
}
static void svir_455(void) 
{
	svi_reg(&(tinfoil.validation_items[454]),
	        "6bb2289c4c765a23339b3e062445cb35676d751c449414e9ca791392fee15700226149d0d0e2b8162c0ad771a434f69e4bfaec21a323c90ffa032362684ca32d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/typec.ko"
	);
}
static void svir_456(void) 
{
	svi_reg(&(tinfoil.validation_items[455]),
	        "1860a3557677d9f5a33784cb64c83d031a317088ad506e672e64c2c2c7be6c493308f9399b3650acd5b8e7cbdd1075db10f66b3a38c2568ab46ec4e9cba5408b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tipd/tps6598x.ko"
	);
}
static void svir_457(void) 
{
	svi_reg(&(tinfoil.validation_items[456]),
	        "5c7191b8f1c2cf1ca3eb56f422b31f8bdff1f72fe4d7c19297a6445d19a478ba29df7f5701f2a0102bc3440abd85e2ad7391bcadbc83b6481ab27c88162555b5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/typec_wcove.ko"
	);
}
static void svir_458(void) 
{
	svi_reg(&(tinfoil.validation_items[457]),
	        "6340143addda57f96626858d5bf68588716efeb4a29b4f7c8b5321636442c4459d37cdf4322a20419c5749e1ea2b700d847bbcda8a81d06b74d064acb7748d96",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpm.ko"
	);
}
static void svir_459(void) 
{
	svi_reg(&(tinfoil.validation_items[458]),
	        "79ef6595057bde707c28ba75fe979a9e8a577d9d0e72862eca942651e701fa20ade034b3f9e86f6158b4b2a7e8fb08d679089bac0422e33380078376847fbe5c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci_maxim.ko"
	);
}
static void svir_460(void) 
{
	svi_reg(&(tinfoil.validation_items[459]),
	        "cd066da0c7c5c26c2562cf292597b8779ac2cd315b8a256e0435443ad922314d65795031880e63f7c490c293cd07c213d7d23176072b5c2298234984cfc26ad9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci.ko"
	);
}
static void svir_461(void) 
{
	svi_reg(&(tinfoil.validation_items[460]),
	        "d97cdabdd007def3f85e64cef7990260adb81b4189f959d5fe6828b4a22a9f6d8cfba14cfedf29c9a1050002bf26a1db2b04c7e9ce480c20eec4f70df9bc1e90",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/fusb302.ko"
	);
}
static void svir_462(void) 
{
	svi_reg(&(tinfoil.validation_items[461]),
	        "be812d77c365de0f4f168698a9b8564c249162d6e2abcf3127bc8ebff2e3e404cc1f9f1c1708a25ebc54645b39b9f8550fa381ed0a2fae41991d5d848da3d77d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/stusb160x.ko"
	);
}
static void svir_463(void) 
{
	svi_reg(&(tinfoil.validation_items[462]),
	        "1098b7095d9c849dc09a918bf6e06ba20fc7dec461573b25315c80ddc95b7d21ee97a2a446ee489e9f9ab46bfa89288ac5fa7171a36a26731aac57afd36c2f62",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/pi3usb30532.ko"
	);
}
static void svir_464(void) 
{
	svi_reg(&(tinfoil.validation_items[463]),
	        "5546491d1ce36ae1564d2dbe0bcb776d0f68946e4e8d040e0691b187d0b056b21bd4d9e243e3646cea2cbc7bbb8eca27d0b3d53e2bdb74387effa88cd21109da",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/intel_pmc_mux.ko"
	);
}
static void svir_465(void) 
{
	svi_reg(&(tinfoil.validation_items[464]),
	        "50d1e9fe01bd98e063af40e4b9fdb07b8661ed0a3a854b33fb4aeccd4f1d45c83af6e95f9b9dc4372bd85a42777d5a8ffd744706f48bf44b49726048add78826",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/hd3ss3220.ko"
	);
}
static void svir_466(void) 
{
	svi_reg(&(tinfoil.validation_items[465]),
	        "e6d2148795ba62768eedc9bc19f12bb39919217199ed1ef17bd0b53565fd1ce04b23db80258076122d61655aeeb0fc4691a96ca497855883b6ffead4d2e8ee55",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_nvidia.ko"
	);
}
static void svir_467(void) 
{
	svi_reg(&(tinfoil.validation_items[466]),
	        "965c09464e77e1c89dabe5349968cd29413706873d08e7088f5723c737c4a05e9e7629986eeddad28785591c5081a4318ae1c472b840838ed3200ae5db5197e5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_displayport.ko"
	);
}
static void svir_468(void) 
{
	svi_reg(&(tinfoil.validation_items[467]),
	        "73798e60ee7420e0eec1974216767571fc0a143b0745b56c8a0d94e1d2b55458e9f4481a17e5fc06db4e535be0d44379571b4c3fb9f28ad8e3db187973ea07dd",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/host/xhci-plat-hcd.ko"
	);
}
static void svir_469(void) 
{
	svi_reg(&(tinfoil.validation_items[468]),
	        "698787f230bf22f929cbabf608bb6ee3d5718aa680535c02f0e2cbbed5edc3f89c51f93476016fca3f7f709f1895eb5a6518f019b05ffa94ee5e27e1db29f89a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/sc16is7xx.ko"
	);
}
static void svir_470(void) 
{
	svi_reg(&(tinfoil.validation_items[469]),
	        "8e8886b8ed762304ed02488529a6bf7214804832810af5d1b71cd46ff0158490098354d84ff1dd4d9a81a514fba86cfcd8cee451ca146cf690d6f499fbbeeb09",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/jsm/jsm.ko"
	);
}
static void svir_471(void) 
{
	svi_reg(&(tinfoil.validation_items[470]),
	        "4c3ff5a355b4803bb582bf561b5bac6498be1709aa8828538713920f3a8d1876e4ec104544ca64b551cce60a85d133358f7a1900128de32ad847ce999014a1be",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/arc_uart.ko"
	);
}
static void svir_472(void) 
{
	svi_reg(&(tinfoil.validation_items[471]),
	        "566cccd862103d7d32dd6c23d1f4465b4326460fa9ce6f284ec877fc0b458d1d81a8b5488111ab594f9a7be78803bec069035350008ecddc2b55b87c657c94b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/serial_cs.ko"
	);
}
static void svir_473(void) 
{
	svi_reg(&(tinfoil.validation_items[472]),
	        "9583063240ff44de12e03b59c50b75177c9086ed625fd4312635909613f5cd3f88ccd1570994fa1e4c02b88485acd73994e2435e686f9dc9e535d49969914a9c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/8250_exar.ko"
	);
}
static void svir_474(void) 
{
	svi_reg(&(tinfoil.validation_items[473]),
	        "6ac402eec6aad82c9ab741f869fc62bb6d9dd3987afe5e8af9305b26959c31a0e3df16e668ed700669dc3b4056b5b2c444f716c03a187e8f986f24a4c999efec",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/scsi/virtio_scsi.ko"
	);
}
static void svir_475(void) 
{
	svi_reg(&(tinfoil.validation_items[474]),
	        "4c446f3133f4283320945fd65c8c5b3c8a92f77606d120545cc0e8aff4bd2e1ff2272a6cbc07fd9b603b051f8a52a2887fbee500f4076a01c07ec214def28df9",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/wmi.ko"
	);
}
static void svir_476(void) 
{
	svi_reg(&(tinfoil.validation_items[475]),
	        "b3e33278a9c9d91ad8f48c2288f6d009e2bf9acc5d0294457669950457d4f10c1c10f22c70e392b4bacf598786aa82fc091655ff08641796242a8d40ff9ccff8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/asus-wmi.ko"
	);
}
static void svir_477(void) 
{
	svi_reg(&(tinfoil.validation_items[476]),
	        "dd7fecc344134815dc80c31ef721d6b58bfde461a4d319ed1d6144c4ec26fde1e52a2089d97ed6003ef06ae5a6c322de4203b2e184e39d1cf5b51d64cd33c723",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/surface/aggregator/surface_aggregator.ko"
	);
}
static void svir_478(void) 
{
	svi_reg(&(tinfoil.validation_items[477]),
	        "4dd882334b7f75b9e1fd1ee38cb9392316f4fc35edbd749c36bb13062836198cb6a05a2e2b05832cd46e949ff2737e2a4e0c16bceb04177cae0a90d9612ba026",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-tigerlake.ko"
	);
}
static void svir_479(void) 
{
	svi_reg(&(tinfoil.validation_items[478]),
	        "32eafd0470bb890afa29ab737104282423c322d72c44f436d2ce17cb9ccaca4e92a71273144ef2234cdaef0c6b21e3d7d7db6128c19b238adb12f024795c2482",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-sunrisepoint.ko"
	);
}
static void svir_480(void) 
{
	svi_reg(&(tinfoil.validation_items[479]),
	        "9f4598cf86571cc254b025fafad040142eb6b92fd0a3a6c2b0f8d8b699323ec5777e032f1439952286ce4cffb2a495e7d0096a6c94f9f2309c382ad58eb1f5de",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lynxpoint.ko"
	);
}
static void svir_481(void) 
{
	svi_reg(&(tinfoil.validation_items[480]),
	        "15fe1c4a847bad74edc7042a4b4e0fcebdb2cb1a3948b3ce819f4fe07878ef5fac9334ac7aecfd858e593b5e3b5fb21e75f52b6787312bab3118d3a423795349",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lewisburg.ko"
	);
}
static void svir_482(void) 
{
	svi_reg(&(tinfoil.validation_items[481]),
	        "170b475d9a8d840fc43d2cf7683706638c3824bbb9024263b0a966fca0bcfcd4ef3633e81ebb8f149437fa4b5962e6a21f1c22448257ab3743911b7d3979ed59",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lakefield.ko"
	);
}
static void svir_483(void) 
{
	svi_reg(&(tinfoil.validation_items[482]),
	        "1cb4c62e693f09beedc17c1e8c4418c8ea8ca45ee8f7d1fe0a809bc0db1397cba79e61e3df471d6190e4c25d714ffc57594d71325ba961aeff3165d5a2c4cd50",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-jasperlake.ko"
	);
}
static void svir_484(void) 
{
	svi_reg(&(tinfoil.validation_items[483]),
	        "0c7d0034f2fd59de0db3dd067394157ed6c084a069987cc2e8a81e0040e4f8bcb617f3fbdb6df1f80721c463b1a2a980cf70c11b4567b53ad0ddf6eb10798adc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-icelake.ko"
	);
}
static void svir_485(void) 
{
	svi_reg(&(tinfoil.validation_items[484]),
	        "e5fe0e36da29be1bac8b0060068feacdb5fa5315ef608936e23f687d3bb9ccf74f795abe3a64968b0d5268313e1f4ab7891d7dbb75dbc20054753d8779494820",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-geminilake.ko"
	);
}
static void svir_486(void) 
{
	svi_reg(&(tinfoil.validation_items[485]),
	        "178bf72a0f29a296a7f518876fb8022218af62306b5d5679e0c30ce67538dd7af6ccd547387a3a19f3ecdaeacb6ae4b85e2e677baea89e756eb38f4bf1557746",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-emmitsburg.ko"
	);
}
static void svir_487(void) 
{
	svi_reg(&(tinfoil.validation_items[486]),
	        "377f75fa7227d5a4d94d3fb335e4cc13eaffaf146fbbb22fbaf782decfb98a2ee0ccd06559c9bfb33724a1c27b378a382ac450557ae3e3f103435995cc8be2ed",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-elkhartlake.ko"
	);
}
static void svir_488(void) 
{
	svi_reg(&(tinfoil.validation_items[487]),
	        "11b9ff77305c39230f212679ad4a9c30ce90551bc3c21396e81680188eb9dc9b06e905e1740391b223aae4e6b48893a09d607990f64a2b05a9745a4f34d3966c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-denverton.ko"
	);
}
static void svir_489(void) 
{
	svi_reg(&(tinfoil.validation_items[488]),
	        "6dad6fb4a2b851ef31986e1480249333e6156df7cd4f19d5b857559dd4c7c8b4dc75d3bf838dc3c2b64fc59d64c9c4229f6f0b7fbc8d26faa3784d4890def1b4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cedarfork.ko"
	);
}
static void svir_490(void) 
{
	svi_reg(&(tinfoil.validation_items[489]),
	        "abbb3e115a3421f3f6a9c1b6fc7c351fdfb210d242e72a95e8f91de2d7ddfc950c66b4457b8a29975b4fd28642bb4590c39ff997a5960e0d66203028c6234ea0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cannonlake.ko"
	);
}
static void svir_491(void) 
{
	svi_reg(&(tinfoil.validation_items[490]),
	        "b79402a95ad6fbcea60b77e7ef12335d2ec40aca8e1db1cab9fb01954aefb3f3bf63ef035f911c5ee55488344ae92f7dd5fc24b0c78a73e01893b78da3d467ca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-broxton.ko"
	);
}
static void svir_492(void) 
{
	svi_reg(&(tinfoil.validation_items[491]),
	        "9a51fec56f838926cc02a38c2f377bfd4711c9ecf7b1c681262bf46c1b3df390ace673dff813e0e1c837f6fa14e9e6fc0ac8f38bd61357e4bdda5a989e8e852f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-alderlake.ko"
	);
}
static void svir_493(void) 
{
	svi_reg(&(tinfoil.validation_items[492]),
	        "b57b83ab8a61dabafad9236d9086982e0171c04bca2fb819c5ac487be46ccc01722671fdc468c5408f89a8c41216de97f827523048811432135607902ece1cea",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/vmd.ko"
	);
}
static void svir_494(void) 
{
	svi_reg(&(tinfoil.validation_items[493]),
	        "2fd39f7db8f4dba6b08e41751725e1d5279f536aed635e6477e0d5b189173df848a28dee418b9d66e9e3a3bb4def1b791142ed21d1e4871c37c9e553c227b20a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv.ko"
	);
}
static void svir_495(void) 
{
	svi_reg(&(tinfoil.validation_items[494]),
	        "5b57e181171a57410824811cba46830fb410dc3c32f411374921d932ef1cf85d7a1075c2e6faced0638d695a66b65fc35a8a9bdf687cbccce1f39d07b32ee6a0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv-intf.ko"
	);
}
static void svir_496(void) 
{
	svi_reg(&(tinfoil.validation_items[495]),
	        "2da96de7ced196e82445eb9e84d4366b1620cd8ec1345532bd536cc0f8cbb2fa0f4660a083b7a90dce2027805d4775538ae1526b6cb004cdb7e9f93f32adfa18",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/nvdimm/libnvdimm.ko"
	);
}
static void svir_497(void) 
{
	svi_reg(&(tinfoil.validation_items[496]),
	        "f2f90a28e6289ec5399273f2ee8f04b7a421dbabd2acb91f83646ad3db95f1188074df9d80bdab647c37545d5b08f4af05503defbf5c9c4929a4ede9f500f497",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/virtio_net.ko"
	);
}
static void svir_498(void) 
{
	svi_reg(&(tinfoil.validation_items[497]),
	        "7fe125513365ffb6c557f3d13b910e02fcac2bc40db38d334dc90fc1077c3d8d560e7511834db231adc1e62a93c0c8f21803b09a22adea5a6a64c015f81c865f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/net_failover.ko"
	);
}
static void svir_499(void) 
{
	svi_reg(&(tinfoil.validation_items[498]),
	        "299d59d77fd1c9943f453c0fc5703a976864cf3f860e53c59096bdf6d55b6f3c3c9585de46fc4f4bd9853ec71fe4642e48f5c2ee9d1fbc3cb267f8b0db918591",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/mii.ko"
	);
}
static void svir_500(void) 
{
	svi_reg(&(tinfoil.validation_items[499]),
	        "f34d88274373cd61bf96b6d270f2dcc8e7cb2e2a03730265c96246be2cd0529b27104eee393d3422bc83014766590bb6288c99c32f2cd9054734d46a27663b00",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/realtek/8139cp.ko"
	);
}
static void svir_501(void) 
{
	svi_reg(&(tinfoil.validation_items[500]),
	        "ffee561e02421a58d89ac1b02be5aaf7a852af598b103f1d5ffe9c9ac6a575c22824f1413b26b9f765646796f4dca2ae2b01810afbbc6c45aafebe265669a501",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e1000/e1000.ko"
	);
}
static void svir_502(void) 
{
	svi_reg(&(tinfoil.validation_items[501]),
	        "ac944e6f79eef612013dbd1a24c2e451eb28d51a47f496ac2f34d0f9591890dd8d8f06bef2593726f30c6740debb3bdc937152c56cfad5181609e4c251519f38",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e100.ko"
	);
}
static void svir_503(void) 
{
	svi_reg(&(tinfoil.validation_items[502]),
	        "6a4a1b72bd402d316eb6119896ea863a88e1a73d09fb90dbef5626c0239ff36a1434127651bd8a2ed3cd6af11146def0730f43d8bb9e853573c627b05d82a441",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/amd/pcnet32.ko"
	);
}
static void svir_504(void) 
{
	svi_reg(&(tinfoil.validation_items[503]),
	        "be30d78ceadabc098965dfeb15c83dc65cb910e527a1498314f535b80e0a48d83985d99137a59452f3e6ff72673faffe74093f721c4010b185ed033ddcf3bf95",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/ne2k-pci.ko"
	);
}
static void svir_505(void) 
{
	svi_reg(&(tinfoil.validation_items[504]),
	        "323ca660f3591c0ccb9f5cb51c91329d9613354679da0da0d135495d5fce870442f86c46f183dc81b768c56c6521bad882281d82dba1760aec8cd4465ed1c677",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/8390.ko"
	);
}
static void svir_506(void) 
{
	svi_reg(&(tinfoil.validation_items[505]),
	        "f0c33ccb96590218341235e99b836afc62aa8722226dbb5c9737b3a4e42174804afed3604cc561af47a8cd7bc425fdfe33a026b5c0cc980242bb180d9b358f94",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/misc/mei/mei.ko"
	);
}
static void svir_507(void) 
{
	svi_reg(&(tinfoil.validation_items[506]),
	        "f00aa83a46a8b43c35c47f6839d0f21ae3a98c58ef4e65ae2fa5373222631915138c008d32aab037a3568ba49e1489f8f6e1a0cdffb7b4916d358c9497a15200",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/mfd/intel_pmc_bxt.ko"
	);
}
static void svir_508(void) 
{
	svi_reg(&(tinfoil.validation_items[507]),
	        "084bff3d4186497d4130708a79f0d3148c3b84f9990342fcb20131824e3112babeafd171856fdbf027c4817dea6d3a1997c5d710d7c2fa1548aa595525caf031",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/media/cec/core/cec.ko"
	);
}
static void svir_509(void) 
{
	svi_reg(&(tinfoil.validation_items[508]),
	        "bc7381ae0a351e4df970b76bfec053b9fb9a74dc01c2c8860af8120b182e6d1ba5095d0c1feced2d8fb652eb7ec09fc687554ae58deb882b0d5ab5498ca84537",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/sparse-keymap.ko"
	);
}
static void svir_510(void) 
{
	svi_reg(&(tinfoil.validation_items[509]),
	        "ee8b18a16a66f18bc5e7dceb5636c6e126b2085b509bd6087a958fefde6aba375241c8b8b1c9c8348c387bddde634d331ffe352882de6f1dfb6bbc2059f5a7ee",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serport.ko"
	);
}
static void svir_511(void) 
{
	svi_reg(&(tinfoil.validation_items[510]),
	        "8187892257cc8df4c33459ceedf4575ca9c34b99067c2c600466cce19ee1c311211d9ab59b520efe5bc990ce44e6a740c8c57c04201c67fdadd20fd3ed44d0ea",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serio_raw.ko"
	);
}
static void svir_512(void) 
{
	svi_reg(&(tinfoil.validation_items[511]),
	        "81dd8d69f6d0e37687988ae29a9e90b9675628727713e89db4e1d9645f643836d88640c5ddaf2b315dc4a28de223f74659c3f02042487e25ed634f163a2a8f23",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/hyperv-keyboard.ko"
	);
}
static void svir_513(void) 
{
	svi_reg(&(tinfoil.validation_items[512]),
	        "1bf3f82a2fa394e025e0aca790f8b6dc28463fe3f2d518333a2fc67373b747922839fa7ec326fca284b23fc09ce4e0adc0b534940b1c60a878e2975310f150a5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/arc_ps2.ko"
	);
}
static void svir_514(void) 
{
	svi_reg(&(tinfoil.validation_items[513]),
	        "68b42539a9b2564ab436f40fdd6bcf83505b773d02decc2f9eefe2d9587f90d40dad838c204164aca8d8a8d82de82b3e04a5216fde86658d172112e1cee21dbc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/altera_ps2.ko"
	);
}
static void svir_515(void) 
{
	svi_reg(&(tinfoil.validation_items[514]),
	        "b1e0e4e60fdeb61bbae122322131830d6a19f2fabfff912a04267041bc613abe76d379d81f2027367d8875ab06ef4b2f7d8d2930e4c053a8168313a1ff256a7f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/rmi4/rmi_core.ko"
	);
}
static void svir_516(void) 
{
	svi_reg(&(tinfoil.validation_items[515]),
	        "8d57e87eeb4ecebdfb1d54bd758fa6e222eab5e0cc09692fdc4e8a20b43dbe24dc2b6b28d8dd629897dff06faa2a76a4f3770f06841143d83079224bff847b9f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/tm2-touchkey.ko"
	);
}
static void svir_517(void) 
{
	svi_reg(&(tinfoil.validation_items[516]),
	        "d0005ff1a819819834c6a5ab7133ccd6203c1a1085e3b537f08d9dd67a8543a9d239220b74450437e7c4bde1560fc297bc25fb77ee371124fe8172797328d88c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1070.ko"
	);
}
static void svir_518(void) 
{
	svi_reg(&(tinfoil.validation_items[517]),
	        "beda3f8a767b177577834d4cdd3649251832047a2fdb967aae5a227bd595a898f3bef21e2b47ba871f2739c176afb2dc22435a64968a5ffb01f2093ee94cc1e4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1050.ko"
	);
}
static void svir_519(void) 
{
	svi_reg(&(tinfoil.validation_items[518]),
	        "1e5866af07578cf3afac2be06f31f31dd9b91bbf8458aace5c87bbd518f154c2fae4229366f02f66e9e08e6e7f7b194f8fa3350845584f4bf293120bf70fd954",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys_polled.ko"
	);
}
static void svir_520(void) 
{
	svi_reg(&(tinfoil.validation_items[519]),
	        "bcee38865e177213ddbda072a82cfd65ff84f8a4e64ae816fc28e74f89e444bd4889e722ca9d52d86af0516b0446a90460b707a5b349cfb05915c24d19e5c71f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys.ko"
	);
}
static void svir_521(void) 
{
	svi_reg(&(tinfoil.validation_items[520]),
	        "816dac25d1fe98501d69dd8530899d1c0b7d6e1128d405f163bf14ac8ffc2fa6066fae9a7e12161decbb3612c91f2a3184bab47954474c1798ff0133daaa57bf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/applespi.ko"
	);
}
static void svir_522(void) 
{
	svi_reg(&(tinfoil.validation_items[521]),
	        "c6ea2046722790fe274a94665f1bc30fc12b86028e8b6214c311571aee5c83d52b09e1470cef67ca9c701ce679be8ac8bd4c4ca576b9add17031be1427c8d4af",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/ff-memless.ko"
	);
}
static void svir_523(void) 
{
	svi_reg(&(tinfoil.validation_items[522]),
	        "70003bf5f8400a42c083ed7b37687ea23c51b14f7e4ee30c7079672f69469be8e64e8991674fea701fcbfae466a631b79cf55079c5eacad323e0dc36ef46a2d0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hv/hv_vmbus.ko"
	);
}
static void svir_524(void) 
{
	svi_reg(&(tinfoil.validation_items[523]),
	        "28093ff1b85a623f5b7685dd5a721a57f620c0551995c261f555d24efca219586bc4c47b0109f839f80c56212c200919a9f9ceaf6acb7ae14bd54489c3488cb8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/wacom.ko"
	);
}
static void svir_525(void) 
{
	svi_reg(&(tinfoil.validation_items[524]),
	        "a1fec6331146661bb16e3903d5bb89c9736ee8f4f839b39b23b70f8d9ea73efcdc8adcca59da9ee950705885a71217786edeccd96886830a7ca16d9148e069bc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/uhid.ko"
	);
}
static void svir_526(void) 
{
	svi_reg(&(tinfoil.validation_items[525]),
	        "cf42a19a2cac08a78af42b094c30e2032d761fb29ba2961a065b16d80d36e51259fef1dc1e1a6e48f86431e6e1fdfd57f7efd3f16b284c3f9d7ac5864558bfad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_kbd.ko"
	);
}
static void svir_527(void) 
{
	svi_reg(&(tinfoil.validation_items[526]),
	        "4e09b89ccbdc4baa1aca5c395e5ece33a013ebbb1014343f888f6cbd4a0dcfd2a762d9f48f2b2d52aeb017bcae816a223e27c9692dd4c2699a6830e2333f9d90",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid_core.ko"
	);
}
static void svir_528(void) 
{
	svi_reg(&(tinfoil.validation_items[527]),
	        "b7b4aeb70406eb3bad26dcd72cc9ea2753ae83e6aad75d2758d79e60f87b09036e621bf21a9ef78dd622b98c5bb20e2ec61e3a007e54e609baf0bd7d6b808849",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid.ko"
	);
}
static void svir_529(void) 
{
	svi_reg(&(tinfoil.validation_items[528]),
	        "e5203083397076358a904f608cac240924c0cf371ff6a0028874fae62cae847bef04e73833e56ca49560a98d03a5d407db63b9d10e04adb27bbfa8e0c3d8f03a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp.ko"
	);
}
static void svir_530(void) 
{
	svi_reg(&(tinfoil.validation_items[529]),
	        "2cd2cb68fd8b47244660b1b50c4c8f1a950e99e6e0781b478c04de2a6a58dc818168131fec74908bd8d37be828f8f0bfad30b021d0ec73fa98a4f236b387d1e5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-loader.ko"
	);
}
static void svir_531(void) 
{
	svi_reg(&(tinfoil.validation_items[530]),
	        "fb09755f96a05a5185ccefdfd3b0c29ef82330706c95789a4e395c6c308ace3bb0d48139c5d531e7ee22f4a0898629927807f86d8e442713fb6fc09fad120443",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-hid.ko"
	);
}
static void svir_532(void) 
{
	svi_reg(&(tinfoil.validation_items[531]),
	        "9aab5d7053156b929653f67ea2f00ccae918a1f4e5e98c1cb2a28d8a73104d1714530395ff8010c96d2f008b8e8af56922d936ed026e93455187e13806677884",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ish-ipc.ko"
	);
}
static void svir_533(void) 
{
	svi_reg(&(tinfoil.validation_items[532]),
	        "0e5f588978d78982e2a4917e809a5763b94b04606a5e08948b4ca6fd9cae2c8467925c9ee6af5bb8c7bdaaf8fff160c9d5135f775a6068f206c78671b8ac4e3f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid.ko"
	);
}
static void svir_534(void) 
{
	svi_reg(&(tinfoil.validation_items[533]),
	        "72fc058450c50d083c9887adfd4e49ebba4f1dd54ef6f7127eef1b26b29f658d888e6af93331f086333ac4d2dd752a237c1061ccdb434e1a28738148090b90ef",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid-acpi.ko"
	);
}
static void svir_535(void) 
{
	svi_reg(&(tinfoil.validation_items[534]),
	        "ee1d202c6e615f76d674ea518ae7b53b99886a37db56fbde4ea58174d5901dd5ac0d9bed845937aee498be5c4158daf33965dc4a779e23cda22e286e16fa06b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zydacron.ko"
	);
}
static void svir_536(void) 
{
	svi_reg(&(tinfoil.validation_items[535]),
	        "16b9a9790d323c6c0921baef13d90bd45654748420f2d406f8a05b086a14b4a953e5baebaa570ca6c7c513a0c13b4bf4015f5414623c6f08f13a02560fb60c2e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zpff.ko"
	);
}
static void svir_537(void) 
{
	svi_reg(&(tinfoil.validation_items[536]),
	        "94660d3b7b0e7e15dcb104edc96933edb7282c70a33224caacec9f1e0b9d65465bff3e034b6da02901eeecb9b09b43678b8a1cbd5bec79363a3712f06212a6bb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-xinmo.ko"
	);
}
static void svir_538(void) 
{
	svi_reg(&(tinfoil.validation_items[537]),
	        "fcad313c9467806c22a572981404b195d6ca69ba03ba446e22199b4c90f7603a445a2c8e0910005d989289038c06ef1b181c93e6c7ea151ea4f71c11f321c878",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-wiimote.ko"
	);
}
static void svir_539(void) 
{
	svi_reg(&(tinfoil.validation_items[538]),
	        "557fe243058a9f410fc827edb2d7b9680a292e2f96939fef8731c8b26f65bd0b21b25a9215751079e5d3084f420230093859075ece439bdb33f99ecb942f4584",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-waltop.ko"
	);
}
static void svir_540(void) 
{
	svi_reg(&(tinfoil.validation_items[539]),
	        "03d943f1d7775ed7246510d0f7502857249855f4ccb6fbe41f0e24f5833f7f2cd212dcaf4a619c04f8e562e9c703dc2848c9f4226c27e8cf612c2be2833aee39",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-vivaldi.ko"
	);
}
static void svir_541(void) 
{
	svi_reg(&(tinfoil.validation_items[540]),
	        "598303dc32b0117d9b6f608d5b663dcaa6f03770709aaed75c082ceef159d40e1455429b0700c6535df59711730b81c380f631bf5cd9ec6f8be5eba8f57969e2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-viewsonic.ko"
	);
}
static void svir_542(void) 
{
	svi_reg(&(tinfoil.validation_items[541]),
	        "643875b67a5c195b712b6c21d1900cc65ae550ec00ac08e5213d491c38c8d0c67ffe5bf45d2f43ddc7d8f9785b55f52432155461ff96385a3db63ece01d468ec",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-udraw-ps3.ko"
	);
}
static void svir_543(void) 
{
	svi_reg(&(tinfoil.validation_items[542]),
	        "7bd8630a148c33bc087933cbbfd871d197cfe9dacd4fa51af8ef1bd1012a99cfa9ffa5f2ffe62af2e3b2dccbce2736c329db6a6a347a8931f3ba4eb88b069858",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-uclogic.ko"
	);
}
static void svir_544(void) 
{
	svi_reg(&(tinfoil.validation_items[543]),
	        "7abebfc218dacbcbd0074bd1fd9741699b042d2d1ffd0be8e8b6b3d316a3128c55550b1b766bc2138ea003ce205da20eda67ab7ea2bb84eb619b8afdd6761c80",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-u2fzero.ko"
	);
}
static void svir_545(void) 
{
	svi_reg(&(tinfoil.validation_items[544]),
	        "5d42da7457f6e1135cb6e85320c8bf1da531570378a900af60a2329f4e45ba7132b5ea03e550a3953d8cb0e60c5e509b1cf2c22163a82a42957c9082e20efdb4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-twinhan.ko"
	);
}
static void svir_546(void) 
{
	svi_reg(&(tinfoil.validation_items[545]),
	        "03f0037f0705f50e6dc745a045672f8333df6bec03d2eef3564827f49a70951d39f8bc6d4366b24ee8aa0999fd11b6858412786061cbe0be4eb9fa4084c08ecf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-topseed.ko"
	);
}
static void svir_547(void) 
{
	svi_reg(&(tinfoil.validation_items[546]),
	        "39a444b08a5cd76b6c5307f6236d868ac025e1a63fe47309d63f5bb08b24c4e897a0313806cd6314922fbb0354fb20ed4e3593883a98ed9ad18c3626410baf84",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tmff.ko"
	);
}
static void svir_548(void) 
{
	svi_reg(&(tinfoil.validation_items[547]),
	        "6a49b64b57757d2be2719f8571dd51a571a30afa8ab88866d18e67d20fc31d492b97aa183749c08801172567a58bb5a8175207b3105a50c9ed0dfbdefcc6bd10",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tivo.ko"
	);
}
static void svir_549(void) 
{
	svi_reg(&(tinfoil.validation_items[548]),
	        "7a28510fa27295b28bdd857a0f743748a50be8f8b32d895a86027ec60f6c09ad91cf201cfa90dccf7b4e8b8579a2634e9481c9b767764e9643a25bad04d6ba29",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-thrustmaster.ko"
	);
}
static void svir_550(void) 
{
	svi_reg(&(tinfoil.validation_items[549]),
	        "50e77566b96f5987b7e5c1eada28d30794724f64ce40ff6c8d21aaa3147cdef59b6643e03412a0deea06dd6955d015f97d7f76455ea1a51bb9493d42867a47a8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sunplus.ko"
	);
}
static void svir_551(void) 
{
	svi_reg(&(tinfoil.validation_items[550]),
	        "787419720ac24508946ffc1fdc70170b3481eaf526719e88b6db05ae5df4048947b8414c6c52add06dec82e20c5e3d96a49d9a8168929dfdb04f8df5cf04eb45",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steelseries.ko"
	);
}
static void svir_552(void) 
{
	svi_reg(&(tinfoil.validation_items[551]),
	        "ad78aee3c06ce1ecae01f1e1fffd959cf04218b506afc6e66c6432e582ecb875ddfbd82153376b6d3f645841928ec40df0bc219905d6b291a062eff83d677dcc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steam.ko"
	);
}
static void svir_553(void) 
{
	svi_reg(&(tinfoil.validation_items[552]),
	        "ac459f5116e579292d43729b5e5d7189e1a883429e27628b71cf1d3bb469caaafb8838303f51dbdbca0d758c220b2c2f922003628d2d36fe4c4022e6c834ad91",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-speedlink.ko"
	);
}
static void svir_554(void) 
{
	svi_reg(&(tinfoil.validation_items[553]),
	        "340bea74be65ad646d7454db50d51a7c79745ec5d538ecf230d6b02c695cc46d97a7d5ce5fef7e9b59863c3bd09aa1a417d23a7bbafd4688e129b8fef01db51d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sony.ko"
	);
}
static void svir_555(void) 
{
	svi_reg(&(tinfoil.validation_items[554]),
	        "6441f4de6e36df1ad11bebb076e0c6debf6c9e45f44d3f370edb4560678cd48cb37117f84be42f5b22bf0d3906af452cfdbed8752fc5778a06c53ef9d8caf76d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sjoy.ko"
	);
}
static void svir_556(void) 
{
	svi_reg(&(tinfoil.validation_items[555]),
	        "7c6b5721eac52f16d721b3d4d3132f2fc827690a39dc6be7587c510beded3becbf5d110fb12fb696de5ff1630d14bc8551d6c665e5790a09085c20b1b91fdffa",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sensor-hub.ko"
	);
}
static void svir_557(void) 
{
	svi_reg(&(tinfoil.validation_items[556]),
	        "025a100785aa2c6d243b3e32082c403ec02529a25d0fb342ec85afedd992d171e6fec2e5deabae811763355dd6dd600fb4d558d12d46491c149dde19581f1271",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-semitek.ko"
	);
}
static void svir_558(void) 
{
	svi_reg(&(tinfoil.validation_items[557]),
	        "91486175d90f43df0712dd39c3c4592a080be9cd46dae254de0204099a79c34270d963e43162430a233595c4f53ed025c1b42270fae6b40067de27b2d2d991cd",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-samsung.ko"
	);
}
static void svir_559(void) 
{
	svi_reg(&(tinfoil.validation_items[558]),
	        "36705149abdec676fd7f6446eeb4cb022bc7e9f0639890b46ee1401e55f8593d72ba1549393f29642f870ddc2c50debfc88d8c96bbff22bc00cdf24415f086ab",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-saitek.ko"
	);
}
static void svir_560(void) 
{
	svi_reg(&(tinfoil.validation_items[559]),
	        "7eb48dc5dbcb45275fd8c31d3fff8fc6a151f10bb72ba237eb26da522ca296d0523a8419d3e17afa61cfc3b0f73024a2538ac5b4af76ddd04a514fa8582348b1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat.ko"
	);
}
static void svir_561(void) 
{
	svi_reg(&(tinfoil.validation_items[560]),
	        "de268da51bc8c36c65bebbda8b118c98905ab5ffd806cd83552bb0c6c0a6a07d2d2b461a687814447d98afb56ba6cc79a5e55423700521c676a45e6c2f2b8dc3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-savu.ko"
	);
}
static void svir_562(void) 
{
	svi_reg(&(tinfoil.validation_items[561]),
	        "a8948d1871cc3fd3cc09150d437b3094c1463810c46fd25b125ee1549dbfd59e47abda5b79e772482359aef431dac5dc3c630fa9d7b023dc3ca3f5813375c7b8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-ryos.ko"
	);
}
static void svir_563(void) 
{
	svi_reg(&(tinfoil.validation_items[562]),
	        "adc977b4e132476622763418ef2ad88ecda4b946d02d8b4b4ccfa646547c6ffc875e77273b3e9e5afcbeae3060e465290538a1c513a145b432dc9950aa77f54f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-pyra.ko"
	);
}
static void svir_564(void) 
{
	svi_reg(&(tinfoil.validation_items[563]),
	        "4e48f4c9219ee7d511c001fafd9c904288b8191d4bf90c42b4af2d0fee4b10d39cc2c07fd5cc09dd61ae2eee3fc6e650601f169a99d00d4e6bca8c079955e318",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-lua.ko"
	);
}
static void svir_565(void) 
{
	svi_reg(&(tinfoil.validation_items[564]),
	        "93e417e66e17c1314017ba6e372e260a4b9942a9436a4a31916c3a9c44b57523c4e58530f85265472ed20cab14918384b4c07dd5b6c7ac2ec1a1e14040d6927c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kovaplus.ko"
	);
}
static void svir_566(void) 
{
	svi_reg(&(tinfoil.validation_items[565]),
	        "87c1e5de98ea5e704274ce1b63a46e690bb0ac08b682a50b1b3156f6962be396e936284d015a6f1131d36b28fe3e8cf204d98ac2a6268e313855e07cc2cc5dd5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-konepure.ko"
	);
}
static void svir_567(void) 
{
	svi_reg(&(tinfoil.validation_items[566]),
	        "1d80d30912475f00b8aed0c03eceb254d9b7c3e0cd58b31861d26d53dfd22d515f5762a06e70c911b4fc5f0d49e464ab67ab1d54a34aaff5ed3da750697c921b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-koneplus.ko"
	);
}
static void svir_568(void) 
{
	svi_reg(&(tinfoil.validation_items[567]),
	        "912a9d257856a0c5d5ebfb4a4de95343fe95f0eaa6d67b329aaf6be3444e3f753f20bf84fe6b3104a7adfa569552a07e547c0be4d901e548e5c7b5e2ed1abf04",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kone.ko"
	);
}
static void svir_569(void) 
{
	svi_reg(&(tinfoil.validation_items[568]),
	        "f60b3b15c61a0b0d22aad962810ccf54555ec9ad787d48e598d734e6779595b970d45a47d17472cb1ee2a85b71d67c3943c8522745f235275eb979f4054d3860",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-isku.ko"
	);
}
static void svir_570(void) 
{
	svi_reg(&(tinfoil.validation_items[569]),
	        "3dc61679a3410fd17a344f1e55d2fba51b5a274e7a3a5f6611305ac6177aad63087075e4cceef5793dde26b33412f569d6908319f29c2b09c23a022408356cc3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-common.ko"
	);
}
static void svir_571(void) 
{
	svi_reg(&(tinfoil.validation_items[570]),
	        "45eb12d35436ed9e3099631495266b983faf1f3dc670e446de0bace8dbc38d58b8f53c3cedc655579770f79763bbc66da6e234813443edefe9208f91de9334cc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-arvo.ko"
	);
}
static void svir_572(void) 
{
	svi_reg(&(tinfoil.validation_items[571]),
	        "e745a0409e269a047f166dcf6064a141179c3d82ca58fdce51137bde0cf8f0efce3f415c1dd4779c744cfdfb9fcd1cad27c9d34b5c8064d635f8ec2236ed0cca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-rmi.ko"
	);
}
static void svir_573(void) 
{
	svi_reg(&(tinfoil.validation_items[572]),
	        "0d860a744ff6b0fb92203172997d6790fba53d947ff0ad2c7707a25749a5494608b9d50aa8a8dc46edc50869358a27faa9ce62721da9868f1ca16ce6bf3190d3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-retrode.ko"
	);
}
static void svir_574(void) 
{
	svi_reg(&(tinfoil.validation_items[573]),
	        "de45b87cb8a491d0ea595caa7295873f41f6f58a3093208d817976667f8bd3df157c8891aa0036955047b1ec010a20334bf61762a5dc742e98d476f1a1838872",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-prodikeys.ko"
	);
}
static void svir_575(void) 
{
	svi_reg(&(tinfoil.validation_items[574]),
	        "d21018077dacbd0e083d5a1e68303848f9d0b038e8f4a44d02e7f0497a8c790fcbeedd9f343c84ac35e349e8a2fbc928e9f0e655ff9537948e9b88c718e3670f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-primax.ko"
	);
}
static void svir_576(void) 
{
	svi_reg(&(tinfoil.validation_items[575]),
	        "cf59b406e190e59b5d046cfc9a5708e4aed53b1287f95ff437399df5ff3c36a57c18fdb247c1275d940da0275b312caf900d01ee593f1495f58ccc030fc8459b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-playstation.ko"
	);
}
static void svir_577(void) 
{
	svi_reg(&(tinfoil.validation_items[576]),
	        "da324ea77b9dcb4711a48cd302ccdf735a21421f0cbc8a6e2893dde0474063bd0e1211a47533e85e6faaa9767bd50433e72f3813ecf0a5c019eb53176766ab9b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-plantronics.ko"
	);
}
static void svir_578(void) 
{
	svi_reg(&(tinfoil.validation_items[577]),
	        "8134d2ecf6d59d6f0a6244b0f489c6e976ca4bfb26cad43dbae7bb958acc3fddd1812aed92672c391a5218a9eec800530c9854f7ece5cf4b78cb31cbd5a75148",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-pl.ko"
	);
}
static void svir_579(void) 
{
	svi_reg(&(tinfoil.validation_items[578]),
	        "5c543a34ecbab4b9c60e8ecb2061e33ee06692fa4b60fff9195f5a97a6fec3bb21b50cd3e2cf0ac61b2c1c87bd70aefaec1b592121bbd3cbae21007cb5899d1e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-picolcd.ko"
	);
}
static void svir_580(void) 
{
	svi_reg(&(tinfoil.validation_items[579]),
	        "a5f93e7bb38a9bc88b588f4c01512f299505749d53a1a90e64d7f588717278d6b3150d76ad45102684d867019f3275e18ba8adae264516597e695ca4afb9e2dc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-petalynx.ko"
	);
}
static void svir_581(void) 
{
	svi_reg(&(tinfoil.validation_items[580]),
	        "fd474c1ce5a2f8e8c94c732d37879593a6c18144eb5490aab3583acabef607df3a42b37423054cdd297079dac5e59299a302114db8a3180f5fdd02b256bf15af",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-penmount.ko"
	);
}
static void svir_582(void) 
{
	svi_reg(&(tinfoil.validation_items[581]),
	        "0f424fb56f3040d941db2ee5b2b6746c5ea40f3bf86b902442e8c4bb447c78aca98ea116086487a604bbee6c7efadfe96e4d0357ceb90a616b585ec2a1b4a739",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ortek.ko"
	);
}
static void svir_583(void) 
{
	svi_reg(&(tinfoil.validation_items[582]),
	        "68babd6db1eeb5de1f2c8dc8e5ba512c59ead91296dd142acf4cee8df36a238267dbc1be0219a8e96b3cbf60222fdbd972dc02c65f668e9fc2b3305dbb6e32cd",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-nti.ko"
	);
}
static void svir_584(void) 
{
	svi_reg(&(tinfoil.validation_items[583]),
	        "2d115d7aabac1d43c3ca3acf4346c7e458ac75ec58058179812a0eb396aa822838894c4d88b0f26f9173f9fa04b49e14cc5d296da6c713f58f6ed7a4d7883678",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-multitouch.ko"
	);
}
static void svir_585(void) 
{
	svi_reg(&(tinfoil.validation_items[584]),
	        "9e870aa3f95455c30b1b07b8065f9d8f5b0ac52708de09aaf796f97e98a2c38df24bedc8c61eda15b6ba28700038b2864271b89d4661dd0e3f196b72f11d49d1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-monterey.ko"
	);
}
static void svir_586(void) 
{
	svi_reg(&(tinfoil.validation_items[585]),
	        "354fd175e4b700ef8630a773893259b4ec166a5f7c1fd87f8c5a49be66f70a125e47238bc6ac225f0b1043f7e8c35116e33a033130936426736f1009b72f4bd1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-microsoft.ko"
	);
}
static void svir_587(void) 
{
	svi_reg(&(tinfoil.validation_items[586]),
	        "94cf75980e0fd0546ce78446712e3324841a2b35379bbf8e42e7a1b9cb5f625757f40911fc613afcac1cfe149e47e63629c87faf0032e9e7d6354c51b5e57acc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mf.ko"
	);
}
static void svir_588(void) 
{
	svi_reg(&(tinfoil.validation_items[587]),
	        "bf8bae673a3ce815fd457091b47a29c2ff175d8d6525de037102eacdd73f4aa2e276ae37be92ead5495cbe9a7a248d344df673ce56667ec2367e4561f88b95dc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mcp2221.ko"
	);
}
static void svir_589(void) 
{
	svi_reg(&(tinfoil.validation_items[588]),
	        "5c1db9bdd084cac9a78ec9d8cb89f82ab1b6e9a0534330dc8bc95c8e0554ce624bbf3652446b3d7b7f9bbd960b958f05fbf69d283ff9964b91ad5d95667095d6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-maltron.ko"
	);
}
static void svir_590(void) 
{
	svi_reg(&(tinfoil.validation_items[589]),
	        "e5427d5667cd52752497ff1128799c1672508b421fff35fcb7ff96b9d85f8b207bc3759aae7aecbf63bc0afb5cf9ca2623b4611c82d734fbb09564ffaf077474",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-macally.ko"
	);
}
static void svir_591(void) 
{
	svi_reg(&(tinfoil.validation_items[590]),
	        "0c114590a4073887dd56614b49527f448cf484c070a4dc9ff276a3cf95809ce822e76c327da7496f55e12ac17077fa1a7e1020be32141fdaad5d1a34f52362fd",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech.ko"
	);
}
static void svir_592(void) 
{
	svi_reg(&(tinfoil.validation_items[591]),
	        "7c9331a65d08ddaba25ed2585f2fac393c2f3708ec461cd88c3b9fe58a45c7e92f9cc4bceb347141422ddbad12d46eafbe04be6472058f32b1abee2ced435347",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-hidpp.ko"
	);
}
static void svir_593(void) 
{
	svi_reg(&(tinfoil.validation_items[592]),
	        "f5798412ebc7807210435d33d2f9d120e628e2682d3348f286b11ba5bc527bf94eacc2ab6e72c43686417e7246666fbc6303a5379a4e74583360a997ef2982f1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-dj.ko"
	);
}
static void svir_594(void) 
{
	svi_reg(&(tinfoil.validation_items[593]),
	        "70bbf85f29402c0d268b66961dcacd1482b85d665308e60471502700e416ec3fa54e2fb2de1e85a8f875793e81495390264de46484589013c79e73e9f5ad599d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lg-g15.ko"
	);
}
static void svir_595(void) 
{
	svi_reg(&(tinfoil.validation_items[594]),
	        "01adb2615bf2cbffab3e83c4ff49033caa328c378047a28b9d044b734f0327cbafe1d2cd5abc27d0f275266f9b851aae0821b51b9a2c266799f61cf43fff1e6c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lenovo.ko"
	);
}
static void svir_596(void) 
{
	svi_reg(&(tinfoil.validation_items[595]),
	        "424225cf65f6fb9cc54eaf4731dc6cb4d335e786f6f1aa872457f1d124bdce989a904823ae5204f50b56b661d841e47c5326e971fc4c36b14326ee2938f3e09f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-led.ko"
	);
}
static void svir_597(void) 
{
	svi_reg(&(tinfoil.validation_items[596]),
	        "406182d82566bcc276e68855963492d6ad2b000b483469d949bf50db9caead70c37135b387151f2e94cc7beb813d60d48ad5c15a9bf6491efbc6ead813516e43",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lcpower.ko"
	);
}
static void svir_598(void) 
{
	svi_reg(&(tinfoil.validation_items[597]),
	        "d4432990070769ebddc19911090e030649545aa47dd6b7f298e9754742ab3fce1c0ac11cfb00a38062ee1356870ed4765afb296986b679ccc61184caed0c6d4c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kye.ko"
	);
}
static void svir_599(void) 
{
	svi_reg(&(tinfoil.validation_items[598]),
	        "b39cf936e205a89c5bc660607a8af24e96498bac3e3d7d92c73e77f24654515da3e970145ec53b3638591758f6108badefd0424832e6c81564f96f397c8ff1e2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-keytouch.ko"
	);
}
static void svir_600(void) 
{
	svi_reg(&(tinfoil.validation_items[599]),
	        "c624d047d086d3f2e7ac2d4f8993af77a19c06b191cee7c917e9487432f7709ca0ced77a81adb670b947dcfa845ed702235901237570ac2bbdbbc774855fe1fe",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kensington.ko"
	);
}
static void svir_601(void) 
{
	svi_reg(&(tinfoil.validation_items[600]),
	        "8cbe8eac9dedeff1891d14677eec63af1cf6459f985d94b282642b13b237e774d0e3383d68e147d7f5556b3d203324af656ba5b1551fa757fe1893a2cb0a8ab8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-jabra.ko"
	);
}
static void svir_602(void) 
{
	svi_reg(&(tinfoil.validation_items[601]),
	        "c827327506aa4ebaf252f54247ba1178167d06696cd66834dcee7f56231756da4b8b5ab762aaa8c1819c62aaba21bb1ba3e5148e6f9fe4a53b7b182985e61ff0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ite.ko"
	);
}
static void svir_603(void) 
{
	svi_reg(&(tinfoil.validation_items[602]),
	        "4da261127a1ebe3ed6928b3e6b70c20a1ba88766e7f57f1e5f57d73b25d01a5087ff580a373e26f7d87171f8827f3a9149d434b84bd5d0e8c12550640b7b63d6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-icade.ko"
	);
}
static void svir_604(void) 
{
	svi_reg(&(tinfoil.validation_items[603]),
	        "8f5d20776716435934f7c5aa2e48fd715d15c1a90621fca019c075e7967b0a1a351a52c71bb0c26b64c9e1531428b272e54495932bfa78dc5ae59472681bd4e2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-hyperv.ko"
	);
}
static void svir_605(void) 
{
	svi_reg(&(tinfoil.validation_items[604]),
	        "799365fa27a4e518a23fc2ffb3d62b71ad317337438e0ef9a95e5badb6c6e9a6f9ca5b73c3adbacbb5a496cb4c3d19b3ccedb972fa117821fb9fb4c698cb3e0a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtekff.ko"
	);
}
static void svir_606(void) 
{
	svi_reg(&(tinfoil.validation_items[605]),
	        "28e24bedca95b55eaf9391ff70eeaff48c726650dd36b3bc6a32bb6ece12aadc43c674ee64bf1e1bd62b3b85368557e53a0bc36eb91745e88511ae77df4e3dd0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-mouse.ko"
	);
}
static void svir_607(void) 
{
	svi_reg(&(tinfoil.validation_items[606]),
	        "6c5ce1338a0df0d33eb330d8f6a17a6d2ce89e35d164140a26a15542345a91df7b1bd4ef1c7eff08b59233d6f0a6cfcb4b26e33f150dac747d03ca109a05678a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-kbd.ko"
	);
}
static void svir_608(void) 
{
	svi_reg(&(tinfoil.validation_items[607]),
	        "e2bb3cc147a3b27470cef38e81d0874c134f72f11d0d5fc13504afed33e815e62456e7a0c630270473a7933bb86887d5734aa42576535c0080e79dc1381e1256",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gyration.ko"
	);
}
static void svir_609(void) 
{
	svi_reg(&(tinfoil.validation_items[608]),
	        "3b0760242cdd41bbed363812a5c5c55b4116a70b569e515d0d5bdea956e1cf2db310ed55cf9ec817979c7f42c51118028ff01799d978e0829bab325b829b6e6d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gt683r.ko"
	);
}
static void svir_610(void) 
{
	svi_reg(&(tinfoil.validation_items[609]),
	        "b8f0dae0de0f7e2691bd28e6e1087080c641c32d1d427f652ad9dac34407b795d36a132a263b940e896f491cb59229d614601028807532c852e683a74c96f906",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-glorious.ko"
	);
}
static void svir_611(void) 
{
	svi_reg(&(tinfoil.validation_items[610]),
	        "73f6682e1147a6a4ae9a116aede30536849fc527e558731788d9b9f10e92d4f0a19fcb873f3914d4d6ad3c1b110db0ded03725675658fbea196d2aa2fa2ab749",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gfrm.ko"
	);
}
static void svir_612(void) 
{
	svi_reg(&(tinfoil.validation_items[611]),
	        "ebb5dcaf908f46098ee441f6b5149fbab527f8fa0db53248ceed4e0e600f385726bbcf13c0e305b27fcedf50b1ed34cb73b7c6bf5271eb2ae5e0c7bc2e85523a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gembird.ko"
	);
}
static void svir_613(void) 
{
	svi_reg(&(tinfoil.validation_items[612]),
	        "020cef149c8f4a0b8ab23ad185b48cc492fa61f380f6cc59091b17db33b23e8316e3669b3fc07af120e339c13a6ec4f7c00af6767eea4d24d9600de7a2ebf04f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gaff.ko"
	);
}
static void svir_614(void) 
{
	svi_reg(&(tinfoil.validation_items[613]),
	        "2195e8907a86bb39addf6ef410e27bea739d11d85bd65a69f554da15dad28fb71cf6a2f417f44925760f2fb4d186354b9df3fa49be9b360b69d87a05a5fa6707",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ft260.ko"
	);
}
static void svir_615(void) 
{
	svi_reg(&(tinfoil.validation_items[614]),
	        "87bc6ac52b7a690db7f2838d2f1eca834d8fbbd04f371e64dc2ed1bb692241896784cfc9fe3d6eb2ade960b08a681d51cc8761594d890db69b7118f6e220bd74",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ezkey.ko"
	);
}
static void svir_616(void) 
{
	svi_reg(&(tinfoil.validation_items[615]),
	        "850fef3cfac24a2664eab79f79cf96091cd4883fcf78d834c6fc60b4142cd0996389dc765b97688fb45bf6a903cfefab94aa5538e02ff6568c579e08d928d130",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-emsff.ko"
	);
}
static void svir_617(void) 
{
	svi_reg(&(tinfoil.validation_items[616]),
	        "b865e94eabba63a6e52654169e99bb5afad2601f58a40d87489326c9f6d0e18bb8f07724e269830756bc21a2a01da15c877f8ac2e3849e1f8d71c96a05733329",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elo.ko"
	);
}
static void svir_618(void) 
{
	svi_reg(&(tinfoil.validation_items[617]),
	        "131098d7c1c6943757db97edcb4b62a7b21da86b8471adb159ff956dc8c1ffab1a00ae4617e534a4dcae487431d0ea75720591da5d850ed781721b96dd346552",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elecom.ko"
	);
}
static void svir_619(void) 
{
	svi_reg(&(tinfoil.validation_items[618]),
	        "027dea5152b7798b3a7b2959b3470dd94421d58d7739d26e30465bfba9a0db3fbc66b598a134e019a862b6f350bdb0d215437f975c2c36e382fcfeccbc7bcc0a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elan.ko"
	);
}
static void svir_620(void) 
{
	svi_reg(&(tinfoil.validation_items[619]),
	        "8b8721078a9aeac88eef3e48029e55e12e49e2f5c89c9a30663c4291ac517601c6e1bbd38cfa449ec2b076f90ff9e052f8b330b4ae824af1e8711764b8402891",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-dr.ko"
	);
}
static void svir_621(void) 
{
	svi_reg(&(tinfoil.validation_items[620]),
	        "24325fc7f520e185b3565627f1f0b41990e47abb37b01c71dfbd7904c24847f15f58c89f5e9c62d9ab1deff801f6444210952d3cc67d481f7012946511066660",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cypress.ko"
	);
}
static void svir_622(void) 
{
	svi_reg(&(tinfoil.validation_items[621]),
	        "0c177a5f981acbb3c101476c274f10af9a55193aa5679c6028eee636bbb3a568eab5bbabc3162393dd9a6fd0b4c73df43c1da144467f90721d6ad9ac7fc3c2bc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-creative-sb0540.ko"
	);
}
static void svir_623(void) 
{
	svi_reg(&(tinfoil.validation_items[622]),
	        "ae7873e9731740cc7279c6867da3c13f38ed0ec622ff1ab38839117ea738de03ca9b7110ef37939c1fc19f870bd3ef06b998be19cbaffcdbc82e214029b66b90",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cp2112.ko"
	);
}
static void svir_624(void) 
{
	svi_reg(&(tinfoil.validation_items[623]),
	        "adf788f9741dd6a326eb7492670ffd7229c40e38e2461b8a8d01ab111e7953c1f265e33f330dc0a0e84f6540aecb65f2c9e47ea92792a416ddc7b1b60ef22cdf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cougar.ko"
	);
}
static void svir_625(void) 
{
	svi_reg(&(tinfoil.validation_items[624]),
	        "3ac880595fa8830c673e3528381847b3d3a56f209edc2952bd93df09b59a4092ce640b79ab802f9fbab389f1f7cb02f580610df16e9cbdb3ea547c75dd51d70e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-corsair.ko"
	);
}
static void svir_626(void) 
{
	svi_reg(&(tinfoil.validation_items[625]),
	        "caa2d10ca210878d2bd12c53b5ab0e4ba376e0f87311631ef4ce3ec178b369d0fa4ab1973cb8732b2fba18db5a6e53ae3c31a94fff41d53951cb599bd8127127",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cmedia.ko"
	);
}
static void svir_627(void) 
{
	svi_reg(&(tinfoil.validation_items[626]),
	        "54fc2dc7d626602d3cf6e0ab7873148b4030818671d85ec9a8f4dd5d53c3bcff7b0fbff6b845465f0586bb98d0262bd371936cd2f3234ff6679feece77e37f76",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-chicony.ko"
	);
}
static void svir_628(void) 
{
	svi_reg(&(tinfoil.validation_items[627]),
	        "ca286ca475bbc0d914cfb86241e5dde8fdf6e0f7ae208de6a7a857f002c8f426bdc7efa8ef8ad97a15932c3ca88872fb875fc13088c01fff9dc052ebf3a1f2fb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cherry.ko"
	);
}
static void svir_629(void) 
{
	svi_reg(&(tinfoil.validation_items[628]),
	        "046cb0554ee1f758685a21745943b059be51263f6f3a8ac8cd40b2eab2c28eeb978cb402ecd03aecac78c3c25fae14c81cc9df330f806d79ec4ceda74b15cb8c",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-bigbenff.ko"
	);
}
static void svir_630(void) 
{
	svi_reg(&(tinfoil.validation_items[629]),
	        "f3fb12f951f933abdbf383925a0b92a96c931a6d0d0da7ea1a3a5ed77ccf1e7f5d96786130af93dd62eb39398ac92979d1ed724e4db86541df25fdf8b456bffe",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-betopff.ko"
	);
}
static void svir_631(void) 
{
	svi_reg(&(tinfoil.validation_items[630]),
	        "81a76dc0843402492d9d0a784028ab7a34be15f06db4b12d3b5e2f3105f2f8d5a865d87b57bffd1a0ed12680a19e84407559d432ca0552b9b587759ca3733a6b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-belkin.ko"
	);
}
static void svir_632(void) 
{
	svi_reg(&(tinfoil.validation_items[631]),
	        "97c5d8b67627448eabd8e14b4fa80f3503a9628b877318614ecf0fbc708726dd9a4dc886023d9a994007d030591a99d2ba4fbc52ee771b572a03a9ce456b1b2f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-axff.ko"
	);
}
static void svir_633(void) 
{
	svi_reg(&(tinfoil.validation_items[632]),
	        "797ba0d6494901f8bfb189ced34b1cc48c83a03690dd3b2a4676e91c3153201567c5ee0907b2e80ca9a6831b9201e085a797fe255c73a027140d3802c495aebb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-aureal.ko"
	);
}
static void svir_634(void) 
{
	svi_reg(&(tinfoil.validation_items[633]),
	        "f5bc28d2ce92f53970547a0a0ef4d8b60980caa99cfc23a170104f94e7848e81547b3ef001928d2f3d0078bdfa1011952daf783e647eca3fd00b095df3ca5de7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-asus.ko"
	);
}
static void svir_635(void) 
{
	svi_reg(&(tinfoil.validation_items[634]),
	        "ec7122c85f8988f18efa03ae1c940b78c32926552e8e5e44ccc9d4f05595c5bc61aaecf5281e72be06fabdfebf40d73114273ca541f5aed0a3c6f4338a12051f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-appleir.ko"
	);
}
static void svir_636(void) 
{
	svi_reg(&(tinfoil.validation_items[635]),
	        "b4398413ffa6725e6cb9e90d453daad21558bf53c86aa1a43c7ba9290088dd997fad34a4499e7cfddfc891c7b8bf04b43ad642f460dd6157c37fc884ce9e8141",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-apple.ko"
	);
}
static void svir_637(void) 
{
	svi_reg(&(tinfoil.validation_items[636]),
	        "b52f24fedd61f64607d04b82c92246ecb6f7144a858cdfcd062d3eb7282497ea80acd10bdd67491ef83c2aefe7ed2b8011bc18188c4a3f72305d9d49d4f10987",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-alps.ko"
	);
}
static void svir_638(void) 
{
	svi_reg(&(tinfoil.validation_items[637]),
	        "27e0aa8ae0c34e99ca7042119536e775f640af21d4a63b6d879f9577fc7e82463a3b28b8cf2833cf6539397e31567a6a801a2780b3173b1fca1db0588e9b68b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-accutouch.ko"
	);
}
static void svir_639(void) 
{
	svi_reg(&(tinfoil.validation_items[638]),
	        "44faaca8e65e075124e2deac104f28418ddd8dfa92b875789460fb3a282bc5b07c7e3fe15698d8eab63a80fc77e6eaae8b48c4cbb837f25589acdf157bb7d5ec",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-a4tech.ko"
	);
}
static void svir_640(void) 
{
	svi_reg(&(tinfoil.validation_items[639]),
	        "dc1618255116c4f3a455e24dd776ca6fcbda2db1cd87ed42d0d21e3a802315e2d25ff248a220d39bd3fa3c22595939ef0ea9c313a250ae6d79fdc7cb680341ce",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/amd-sfh-hid/amd_sfh.ko"
	);
}
static void svir_641(void) 
{
	svi_reg(&(tinfoil.validation_items[640]),
	        "533f3dba9a57ca14958890d0897038ef6918f3297fa561d69be7b52d3dea5240686ab62eb3a47ab558f1a095bcb1ea32e49b0278e5c2c91acbd93661b16da4ed",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/ttm/ttm.ko"
	);
}
static void svir_642(void) 
{
	svi_reg(&(tinfoil.validation_items[641]),
	        "2558355f8830db2d9b7aa8d40829ef7bbfa10d5360aaf84422cd37d3d8db4179c5de49120ad94ad17fcbe7e44bb04907e291b59b02245a6e582f61abfbbe26f1",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/qxl/qxl.ko"
	);
}
static void svir_643(void) 
{
	svi_reg(&(tinfoil.validation_items[642]),
	        "f824550bb26b56a43d2ccd8638293129a7fe4fea92806b51c7a0fd0bc0b4b00118352c16a980f29da92708140a4b32f4ada1369d668a68b7582bfad4781abafc",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_ttm_helper.ko"
	);
}
static void svir_644(void) 
{
	svi_reg(&(tinfoil.validation_items[643]),
	        "4381374b5c31dd97fe2b9035ed6f2d734f010526f0d849829ba20d1abe1f05551bf21acc35163dbd3e3c95443e09bfdbe8f5bc2bdb1989a07001a22896870b45",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_kms_helper.ko"
	);
}
static void svir_645(void) 
{
	svi_reg(&(tinfoil.validation_items[644]),
	        "a9587aa496bbd5a7f2312040249a011367d43362689738c0dd9af76d5566acd91ee531118ecc36bb3a16555d1afda98dfdce9cf0d9293ac824da4cedafaeb6c5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm.ko"
	);
}
static void svir_646(void) 
{
	svi_reg(&(tinfoil.validation_items[645]),
	        "de93e944541713a8e5d3ff0d06b6e9abc8ad74b10ceed2cef909b706e90b030b6e7b231833eeadb55c98b87f581c06e2ab4fce90e2322ae95557907a29fc00f3",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/firmware/qemu_fw_cfg.ko"
	);
}
static void svir_647(void) 
{
	svi_reg(&(tinfoil.validation_items[646]),
	        "62b7886bc0d74c28ff254bae4f80fac213d35ece8f28a72ef149fb293fe14ecc30fe4213f913a51b56f4cf4c5759c1b361eb0fed91b5dc236007ea5813fc9f90",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/virtio_console.ko"
	);
}
static void svir_648(void) 
{
	svi_reg(&(tinfoil.validation_items[647]),
	        "7afb337b55d488e4b21171bd0ee8997ce50b087c532ac8679ada9b6bfddf0529def0a6e70184400416d0bee86c8efe474716246a042c4120fa4e4ae0a16a6dda",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_si.ko"
	);
}
static void svir_649(void) 
{
	svi_reg(&(tinfoil.validation_items[648]),
	        "634e6f24eb677fd9c26960c8830c6f7d2adceb982554faa7ac69ae34e8488651a16a3813da9a1b77a09d0e8ff895199fbd04796f9a527be422c65f9416b88c92",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_msghandler.ko"
	);
}
static void svir_650(void) 
{
	svi_reg(&(tinfoil.validation_items[649]),
	        "2b52b8bcc96b9cbd87aeef7fc2f8721d79c3936ffc0a96c2c3fa37ba7a5a74584e1c736b015addca75f1df51430ac381be9ea310be74e13da34c2e8a77d3ed5f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_devintf.ko"
	);
}
static void svir_651(void) 
{
	svi_reg(&(tinfoil.validation_items[650]),
	        "06c2c4a83301eff0d1fa3c8dfbaa2656516dbc60dd1a40c4803838cdb8bb3bfd14ab84253d05db0ae1f1df0d5cf39a7d500568c378bdb53296c094116bd90fd4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/block/virtio_blk.ko"
	);
}
static void svir_652(void) 
{
	svi_reg(&(tinfoil.validation_items[651]),
	        "0848e48ca22b2e6e8fe3d77a78fc65f70036b49a7b3f8cce6a28185021dfdc465eb85f72b9c738f8688a3e1300718504b687f4b76c14fd611fa4f99324ef37b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/base/regmap/regmap-spi.ko"
	);
}
static void svir_653(void) 
{
	svi_reg(&(tinfoil.validation_items[652]),
	        "3c432fbcea06c3f6b797f18e7ec3f4fd44dda46fe036740733b8d4bf431856cb57bdb96ded2f18c78bcd386781c9e50df28ec28c19d4eaec81672da63f492f8a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/pata_acpi.ko"
	);
}
static void svir_654(void) 
{
	svi_reg(&(tinfoil.validation_items[653]),
	        "c5d0581a8b5304620a65dad8418f395a4cb12c2e95caeafc444932dd3b5a0bf291c3eb496ae5abbec956c1c88df719abf53d50a79fec1bda5191edd86acff2a4",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/ata_generic.ko"
	);
}
static void svir_655(void) 
{
	svi_reg(&(tinfoil.validation_items[654]),
	        "630b592d39d3c1ee9c060c280aca55e1a0edf9d9ffefcc5a0d03ef30187e1e9397c9a4c48bbb3b7c62b366374bbc42bf6f357043903c2138cfad8e124f75f114",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/acpi/video.ko"
	);
}
static void svir_656(void) 
{
	svi_reg(&(tinfoil.validation_items[655]),
	        "b86f71dafc2746e6d235ecd38c4c6061e65428ded4401603462298433bab1512feadb921f8350fbfdcac48151ec4f7a7255583ab1eeae17489436f4529a901bf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/acpi/nfit/nfit.ko"
	);
}
static void svir_657(void) 
{
	svi_reg(&(tinfoil.validation_items[656]),
	        "154a90e0dde4225b4b74f849d8ece7d24ccfadac8848e936d9b6f5b475521c03546d71167d9999f939852e12ea7335755d3dde0b2e8c6a2230d72b96530883b5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/zstd.ko"
	);
}
static void svir_658(void) 
{
	svi_reg(&(tinfoil.validation_items[657]),
	        "cd99e57418a70cee4a0799802ad8d9a0b7f0a964b41c1a70acbaeb41d75b23e7198ee5aae69d0cf6d768c4d83b073d4c8de84d2e20b74c56fc7c1e91bb17e4d7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/xcbc.ko"
	);
}
static void svir_659(void) 
{
	svi_reg(&(tinfoil.validation_items[658]),
	        "b0dfa44f7d5e7d6df0f3a400d1911f6faff776dcd8f6c444392652fb82100676f5570f4b53106c2b0bc2a59658c3485137ab3cb399c43f1072025d10a7e5e980",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/wp512.ko"
	);
}
static void svir_660(void) 
{
	svi_reg(&(tinfoil.validation_items[659]),
	        "019f06c9f498ca0022d760058c6072b89a9b91451d59d5c4f3e75c3cdc3668ddb570c8b5dd1b9839236837d38e984a7150186e95aec460965948251d2b058965",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/vmac.ko"
	);
}
static void svir_661(void) 
{
	svi_reg(&(tinfoil.validation_items[660]),
	        "4c61bcb65634c710a169a34184c10d38d6ef474ef191a78de53d202400cce38b6310e21dedf35ef6022dc780abb20817bceb33434d06d8e73735a2eb608786c5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_generic.ko"
	);
}
static void svir_662(void) 
{
	svi_reg(&(tinfoil.validation_items[661]),
	        "de72a55def0746b338c44024159130ce7eb0dba807acd43cda9429f51daad978c1e516173eb516001ccd001df899e3b1746b7d01f961aa02b2f41375edc5b13f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_common.ko"
	);
}
static void svir_663(void) 
{
	svi_reg(&(tinfoil.validation_items[662]),
	        "6e0206cdc7ac104bdcf5ec7a5f4304a9b66a53d96c82b78914761e0a44b0f4c92b5fa2b47d6087e9f22b2d45cb4fa76525a7504ab8b3f03e9d218c04521e2658",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/tcrypt.ko"
	);
}
static void svir_664(void) 
{
	svi_reg(&(tinfoil.validation_items[663]),
	        "0548e2f3cde4edadef8ef53cebfaea76fe01fae4b46ef36c6d8ec71620275664b46470ef749baa25742773fc2abd6bb903690cc8c508050a45ef45e25232d136",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/streebog_generic.ko"
	);
}
static void svir_665(void) 
{
	svi_reg(&(tinfoil.validation_items[664]),
	        "c4414204ae9c876629e036905a0e8eca2bc245436a02731524a201865845825d52f5d00f57c60835d400d79c409638594333f7b909460382d0387814b546799d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/serpent_generic.ko"
	);
}
static void svir_666(void) 
{
	svi_reg(&(tinfoil.validation_items[665]),
	        "39cbef5b6ec912a3b690204eba0ede0d0aebdea62cb362b12668960df32684f9776eb16afac5a47ebce6f77e075a08e6a058cce3f965f7be650c2f528d4d9724",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/rmd160.ko"
	);
}
static void svir_667(void) 
{
	svi_reg(&(tinfoil.validation_items[666]),
	        "a26fe292d3d949ab50be3736292e867945fe66c9b1c2e34ecef86abf7a451bcf8ac47966181b38a1b2dfc436d49dd24cbccb08e750fb2470c54e5c9a95c19a00",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/poly1305_generic.ko"
	);
}
static void svir_668(void) 
{
	svi_reg(&(tinfoil.validation_items[667]),
	        "1826469b2a119a340ca549dfeeea8402b7e8108b05b91cba0b3da43753fbedc7590687ea49b9c4aee5db24fd4f8bc754c28c81ebf244267c7875a6ba5d3799f2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcrypt.ko"
	);
}
static void svir_669(void) 
{
	svi_reg(&(tinfoil.validation_items[668]),
	        "3f576f1775f041753ba368c6438db58bf36edc482e02e3bb24486a6d33230f876455851e5b3e6443385342dc9e25db5d38b09d07d65225f5bbee8aad806e4719",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcbc.ko"
	);
}
static void svir_670(void) 
{
	svi_reg(&(tinfoil.validation_items[669]),
	        "6c30f53296fe07c175d29bc3a89c045d7bf859a2af9ade950100a4e84cf997cf4f7ac2201fbe180a3730e5a8c87900f98af86b9464452b47a069d474260d09f7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/nhpoly1305.ko"
	);
}
static void svir_671(void) 
{
	svi_reg(&(tinfoil.validation_items[670]),
	        "0889529d853d28fe8501eeb81164973984d347a90b2793f02dc82d9bc6222d562d9b03864c5ba2131ae1ee2be412dc6436c9bda8007409fe554c0fa0b85de3c8",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/michael_mic.ko"
	);
}
static void svir_672(void) 
{
	svi_reg(&(tinfoil.validation_items[671]),
	        "718dc951ec43d2dbb3c6030d69470a48c2c24e6fa97c86d76a0933966699f69610b0b079c26b700d1462fb6a72ee74950eb538a697f282350f56c81360ff749b",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/md4.ko"
	);
}
static void svir_673(void) 
{
	svi_reg(&(tinfoil.validation_items[672]),
	        "84df30ed4e6b511c26fc3ce7186d2adf82670039bdfd952bde49c9823a0e3dedd5e383c389f7307058185775d651923ecad3b311a54f696ad826d7e186cfff96",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4hc.ko"
	);
}
static void svir_674(void) 
{
	svi_reg(&(tinfoil.validation_items[673]),
	        "6038262b2c5ca7b53aeb5a5a9fbc637e9bf7f88f517512baa2a7b24e84992116696adf19d0104e995cdd991ee3c2e9c832ff27af68a4bf3066256caf9dd30d54",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4.ko"
	);
}
static void svir_675(void) 
{
	svi_reg(&(tinfoil.validation_items[674]),
	        "ea2984b4832b628eaf46c5fe63b801763df635528017a86ad00d212648a19bd995cbb8a60f070ad094c9e327d3a976273c67dc9db167f0703b5df6db00e50854",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/keywrap.ko"
	);
}
static void svir_676(void) 
{
	svi_reg(&(tinfoil.validation_items[675]),
	        "982691ca57c082b02b6aa38cf9a503fb202bab0687bfe3922a222ba9441269dfa8435b9b149bd96fe2884b7283bf1088e21ba58d0f92438963433fd45df78a44",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/fcrypt.ko"
	);
}
static void svir_677(void) 
{
	svi_reg(&(tinfoil.validation_items[676]),
	        "42208e0d662ebe6cb0f2699d68e93377f0b7b399f6966f4fc3969fa23d98fc5977f795f2ece03b315444fa621791363fdad3c4ce1d6ce0a783d6caa4becd5d79",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/essiv.ko"
	);
}
static void svir_678(void) 
{
	svi_reg(&(tinfoil.validation_items[677]),
	        "c8692500bb34709f09a35a9883d893dba53cae5849a6dede117e902c95eecc43b125b8219d854839e553dc90e7e9748995c5b3dfa95d35c3c0c6d0e1a1577b4a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecrdsa_generic.ko"
	);
}
static void svir_679(void) 
{
	svi_reg(&(tinfoil.validation_items[678]),
	        "c3a2afb6a540c99e3781acff39421a0dadb3185c46f955a45eec9da5eb869566951189a570e8a61d18734d56e1d1606af186f2ced10f523b32545ca225f54ed7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/echainiv.ko"
	);
}
static void svir_680(void) 
{
	svi_reg(&(tinfoil.validation_items[679]),
	        "15a35cf194360ca5dbe0ff74771b5184ea41e654310a11691f424b884863490d54715723c230dc6dd4564628c7567b37bc35dd4abbb004461c449ae98743c572",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecdh_generic.ko"
	);
}
static void svir_681(void) 
{
	svi_reg(&(tinfoil.validation_items[680]),
	        "0a556bfc3a5b1ee0392333eeb4445967f0cd016a54881b74fc5b13ca5f4f85a09b510fb217f4d903477b42ddac35a8e6af70999acfff14046c5469db68268d34",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/des_generic.ko"
	);
}
static void svir_682(void) 
{
	svi_reg(&(tinfoil.validation_items[681]),
	        "1314b0066b8d497a79a4489bf203748b3fb1fce5a46a2d55bce577728308ead3cf80b9ec2123f0bf7e7619a667d90a9905a9a2707b3730b8559b3d844f5347ca",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/curve25519-generic.ko"
	);
}
static void svir_683(void) 
{
	svi_reg(&(tinfoil.validation_items[682]),
	        "4731b987c81ff0520e838ad13b283c39b8e4eedcd4540e88159ce3be872c1af20062cb41f81cbdafe1daf993113451ca6f3209c5317db2ef65fcbd4e7557324e",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_user.ko"
	);
}
static void svir_684(void) 
{
	svi_reg(&(tinfoil.validation_items[683]),
	        "64ce49176c9fc9986141093d65b510c145a537f2c31633b2d2bd7ccbf80bef409834cffb72995e07789b68b500bf926af577617bc1a2ff04db095901bbdc6b29",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_engine.ko"
	);
}
static void svir_685(void) 
{
	svi_reg(&(tinfoil.validation_items[684]),
	        "4d838cfc62967db76fa3758daea2e04e7be2d8bc18f8d290fc3085d41f33f5857f990cb639317fd6bc50f76ac3364f509cde487b073eef8987dac93b51f8750f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crc32_generic.ko"
	);
}
static void svir_686(void) 
{
	svi_reg(&(tinfoil.validation_items[685]),
	        "d3bdf0eb9b1a76e126d7e055b9f3bab200de84b0405b1422852275879c375c8cc2c342243762006b833cc45990695f71bc620b3532a13f8b7fe05622196dce67",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha_generic.ko"
	);
}
static void svir_687(void) 
{
	svi_reg(&(tinfoil.validation_items[686]),
	        "28dd53f3351895d4aeaffc6b8025dc84e16c074cb59bc9480c99585d9601d95a5916d371d7b768a9e6157349a0c4f3710a9e977d8631b05704558490b02b1232",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha20poly1305.ko"
	);
}
static void svir_688(void) 
{
	svi_reg(&(tinfoil.validation_items[687]),
	        "d0bad64fb642fee0daceebdae29ae52e0ff140d145b85338a000ea4d7915dbd4f42e31ba8962faaee2fc8bc396caa06ec724ca9a73ccd7d187e6f9a63f3da022",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast_common.ko"
	);
}
static void svir_689(void) 
{
	svi_reg(&(tinfoil.validation_items[688]),
	        "3878f18e2e5508621307bb558394bddf29bcb1a633ccdabea81b58c4ee6051e6ffbca1cd242cade8bfb413d01c631d11e5582859ded562ef4634989b1dd754be",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast6_generic.ko"
	);
}
static void svir_690(void) 
{
	svi_reg(&(tinfoil.validation_items[689]),
	        "e1d9a30583970e5336abfba175c670f9314dd3ff041e5d975708aa6d8de5889e68b1b64282051ede75d08355463a25711f4e142e4e0b8d7be4bb8913b73457ae",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast5_generic.ko"
	);
}
static void svir_691(void) 
{
	svi_reg(&(tinfoil.validation_items[690]),
	        "e21cb4908bdc0add250a8f1d78cdbad668bb206a112e1dc5aec4b57c24d57b3d84ea15d52f387c49886ad6cb3c8fe280119b6fc3871f37d31e728eeab2d400e6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/camellia_generic.ko"
	);
}
static void svir_692(void) 
{
	svi_reg(&(tinfoil.validation_items[691]),
	        "7cb6d32985152b6946db4cc072e2a18e01c7ea7e22cf1e69d37004db6f2b89cc7feaceb90ec0a9e180e7cc9b803752b5f3df107087fd4bfeb24852fd4000edcf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_generic.ko"
	);
}
static void svir_693(void) 
{
	svi_reg(&(tinfoil.validation_items[692]),
	        "287bc3c85f9e2cf9703c727f3fb57bb0d2500e30f460bb5e6a4cec3df6cc01b62a75ef5af7878e22222f9a6406b1bb8c21a003536c2684904b926baf6986b773",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_common.ko"
	);
}
static void svir_694(void) 
{
	svi_reg(&(tinfoil.validation_items[693]),
	        "bcd0363fefbda46bca8df6103883f125ec04a98597dace67906038c9570459c56a010d70ee584c8225e0b4b3aaf3ddfb3580d8130776e492617b87749d8973ad",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blake2s_generic.ko"
	);
}
static void svir_695(void) 
{
	svi_reg(&(tinfoil.validation_items[694]),
	        "6f88fe653bc5d20eeebc4bd2135c52f7c67b2aa8cdce04074ce126d34d37a8c1b05893b1343dacab80e61c1f30119cb692efcd0f1d1414f3b1932f8571ccf3fb",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/raid6test.ko"
	);
}
static void svir_696(void) 
{
	svi_reg(&(tinfoil.validation_items[695]),
	        "fddd303d4236424785b2de180ac431a9192606eff6279b12cbb470b5ce2454d1e1c9fa7f116a19d95e1cd461145aa5bf72f70f62ab5ada54132a70e2378b9256",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_xor.ko"
	);
}
static void svir_697(void) 
{
	svi_reg(&(tinfoil.validation_items[696]),
	        "a80ba695348bcef1a357e183ae30bda3eda9cab8f0b13f8b8322e8cb83889dabc5210fb03d63462353c1c1307f44caa5694059143cfce7be66463ae38bbb8ae0",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_tx.ko"
	);
}
static void svir_698(void) 
{
	svi_reg(&(tinfoil.validation_items[697]),
	        "b6296f46260d7d9605267a5af691293f4e76b4ae550eb0e7b1a0fb826182627f53c89d22ca214b0b89a50ae6800d3aafbc1f91d890b0729b5f7fbef231334635",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_raid6_recov.ko"
	);
}
static void svir_699(void) 
{
	svi_reg(&(tinfoil.validation_items[698]),
	        "a7cd647de693c418709a680310b060548b3296e1a8a74f1dce00e2ab4a2435af801b07c4cc39463152c712474aa1420526469b6ffa1accaffb8ce54d9f89fffe",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_pq.ko"
	);
}
static void svir_700(void) 
{
	svi_reg(&(tinfoil.validation_items[699]),
	        "6086323cbc17f304f0638f0f13b8e4588506bc5f24b3156c50fb493266160aaaae2ca9b74989cedf3da14464f4d954bfbc94b9088fff33832873c2a82d5f1127",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_memcpy.ko"
	);
}
static void svir_701(void) 
{
	svi_reg(&(tinfoil.validation_items[700]),
	        "1bb8dfb1329e4ad4dcae3de5053ccd826c8199c2ac858d8470e306010d801b30d5d2a5d8996f5cac7cd2c570b1535325054cc5f31cbe8eba3dd1bacbf4e41a8d",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/tpm_key_parser.ko"
	);
}
static void svir_702(void) 
{
	svi_reg(&(tinfoil.validation_items[701]),
	        "e8d0e5cdd6a6e5b506c15465766742d97d91c2f81a37ece777a2851a843cd7f6d554ca86c4cf39246f6d4dd5997a71af288f752a422ccc2304a02f3477ce5b79",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/pkcs8_key_parser.ko"
	);
}
static void svir_703(void) 
{
	svi_reg(&(tinfoil.validation_items[702]),
	        "471a88b91881baea6d627ddefd21a89c351872459a6262d1779eadcfb76d92bb9694f2d2779c84d4a69dfac338ec75e5b80b8472fc6670277ac0a4d53f8d9a17",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/asym_tpm.ko"
	);
}
static void svir_704(void) 
{
	svi_reg(&(tinfoil.validation_items[703]),
	        "d4b0b42768c78827588e24b20b26ec20e9572f8a1bd3c884bb5f0aa21e859566b587726c582d40d022f465cf98e2ed89331d1288c72ef32a6edafada2b3804b5",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ansi_cprng.ko"
	);
}
static void svir_705(void) 
{
	svi_reg(&(tinfoil.validation_items[704]),
	        "93f2731f98562827cb73d0dffde64662be02c35ad1ca76e77d673d64f2b0b7f6f08b7a2a5b49214ea0e996ee9eb80416b408e6085aa0382fcdc1338b6b990944",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aes_ti.ko"
	);
}
static void svir_706(void) 
{
	svi_reg(&(tinfoil.validation_items[705]),
	        "32681f6d69d20bafd70c05c89bfa45bc759e41b9fa030e32b7d902bf8270702d3c3714c5cb6da4bbcc4cffe979ca45ec8e0ffed5f156c2b0e48798bb11c9656f",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aegis128.ko"
	);
}
static void svir_707(void) 
{
	svi_reg(&(tinfoil.validation_items[706]),
	        "6fef1b0a63e54ac634cc04b36021d568e21f0dbbb37064e7b45373f9454cbd6c3fb0ae4cc1af077486cb214c2f2e7ff9ee97a7ecdc052c0431043cf919b920c2",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/adiantum.ko"
	);
}
static void svir_708(void) 
{
	svi_reg(&(tinfoil.validation_items[707]),
	        "3bc57bb0560020c480f6049a34bfdfd74ea68d842dba3bf1c3dfb3ed604592eee30a488b3d269266d14f6fe000d522a8b80d0e7ff562f2a58725e206e6690cb6",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/sha256-ssse3.ko"
	);
}
static void svir_709(void) 
{
	svi_reg(&(tinfoil.validation_items[708]),
	        "1402dfb82d4fd7b80d7112a326cabaec124d489cfd9bae868b3e7ebd261217aa8096d3a4fe00c71b583267f0a26cd9abe351a9216188eeea0301bef4cf8839b7",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/ghash-clmulni-intel.ko"
	);
}
static void svir_710(void) 
{
	svi_reg(&(tinfoil.validation_items[709]),
	        "9723fc97c165c767a384d17115e7aa4683c6cd2923b4153aff2d602138592b324efe1f9feea6118dd2bb18d043728244128a7e14e779265ea7f14f7112d5eb34",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crct10dif-pclmul.ko"
	);
}
static void svir_711(void) 
{
	svi_reg(&(tinfoil.validation_items[710]),
	        "c6d28c3863089d701486376a8fe8d284dba9eef6eb1c8ec98256a26819536d71108331fd6710ebf0b6343e73b8c86630cc85f24b85177200a2e06e813a96cddf",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32c-intel.ko"
	);
}
static void svir_712(void) 
{
	svi_reg(&(tinfoil.validation_items[711]),
	        "ac60757daf276d7454eb3019300b9acbe97cae68f132d943d83ade2a0b5e47d25cfec6e493bc5021c4a489fa1c1832ac6e7fa0f4e85466d1c2b0cca0854b792a",
	        "/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32-pclmul.ko"
	);
}
static void svir_713(void) 
{
	svi_reg(&(tinfoil.validation_items[712]),
	        "536c2ffb2e8d5152a58ce25038235f449fa7bc72e8e0d2c88845da4466e034fa08ecc9320fb25e22e631020e44c757164a9f227947d615d146405d209fc18bf6",
	        "/usr/lib/modprobe.d/systemd.conf"
	);
}
static void svir_714(void) 
{
	svi_reg(&(tinfoil.validation_items[713]),
	        "ff240d8e2b3949cf997b82c0e14e3a8cf2b491d060dceb3b8418cb4ae16eb758b8cee9826194bb79b0ecb725fda527f87d994bd6816a40e5205ced1cf1c1f333",
	        "/usr/lib/modprobe.d/openfwwf.conf"
	);
}
static void svir_715(void) 
{
	svi_reg(&(tinfoil.validation_items[714]),
	        "d7a8d232a43f5a32d2f8d0e3ad9a68abddf523cdda94b051ac5752d3b5ee5fb7d46ac5e043ad7d067f507f19e84d3e59572e1eb230622a8c9aadea0ddad1222b",
	        "/usr/lib/modprobe.d/dist-blacklist.conf"
	);
}
static void svir_716(void) 
{
	svi_reg(&(tinfoil.validation_items[715]),
	        "28b11aac0b723e9deeb4f569512cab6167498e557cf2f6c5d79ed76c675e924096a8a4eb7cf80618b92465ad4d5671e96ea9a54d2842aeb873231d0382d0e89e",
	        "/usr/lib/modprobe.d/dist-alsa.conf"
	);
}
static void svir_717(void) 
{
	svi_reg(&(tinfoil.validation_items[716]),
	        "9c9777d91486ea09c22f66ed86996af1015f17830670871016e62f07010bb96893607cb2ee0f52a33f09430a2413c74a504c7f34ee3e8897f270d2292e2c17b6",
	        "/usr/lib/kbd/unimaps/viscii.uni"
	);
}
static void svir_718(void) 
{
	svi_reg(&(tinfoil.validation_items[717]),
	        "0a9b6cf6e343955cc174c4b7d867edb7e5f9cd81005f666912e70722fc58c991a2f20bb4edf88b9f157145e6402b5b5417b2c2bafccdc0056aca1c75c143f824",
	        "/usr/lib/kbd/unimaps/tcvn.uni"
	);
}
static void svir_719(void) 
{
	svi_reg(&(tinfoil.validation_items[718]),
	        "de4e17dfaa7c756c276887e0cd0e83554e02e756ab925264511b25081ba535ef7a2a8f0f44a329eb1ffefdf48e89b4238da99699c9ece6c02436cebe076a8115",
	        "/usr/lib/kbd/unimaps/ruscii.uni"
	);
}
static void svir_720(void) 
{
	svi_reg(&(tinfoil.validation_items[719]),
	        "df8338e5575c0a804f915a671ed8563929cd7acec3c885af0dad895d67e132788de0069dff489d996ded8df3ecbd2c931735728fb26b39fc6c4df473575d7fff",
	        "/usr/lib/kbd/unimaps/lat9w.uni"
	);
}
static void svir_721(void) 
{
	svi_reg(&(tinfoil.validation_items[720]),
	        "baf3d83f392cb857c23e36ea017436ba175da68fd282a3c58fa2f9db865962344893dc6f0a7e942492fa47d9e7ef8f1875493e1f33b8f984fc6a6277a1280908",
	        "/usr/lib/kbd/unimaps/lat9v.uni"
	);
}
static void svir_722(void) 
{
	svi_reg(&(tinfoil.validation_items[721]),
	        "6bbbec21c57d74dcad62f2fcb016b6d0f2c2969dc755a19ac09d3582919e39f8a5d653a7931487743041219d90c5ec9addf34b0dc9342643b50513909d46e92e",
	        "/usr/lib/kbd/unimaps/lat9u.uni"
	);
}
static void svir_723(void) 
{
	svi_reg(&(tinfoil.validation_items[722]),
	        "ddded82ff9e746e0a24e4db18ea3de3be1db668182882c6aaf09f1a07ab39a226c151260b8f97f4163f3b21227c08ba7b4e799b9684c1424af16ec77af68d1fb",
	        "/usr/lib/kbd/unimaps/lat7.uni"
	);
}
static void svir_724(void) 
{
	svi_reg(&(tinfoil.validation_items[723]),
	        "01e3106139726c4fbd1f2e6691840800574c2ccc1771c952def68579b276b0e23cb07c205eda28af37a648dac7c01887ce6d3c05e4c685eac863935918eea295",
	        "/usr/lib/kbd/unimaps/lat4u.uni"
	);
}
static void svir_725(void) 
{
	svi_reg(&(tinfoil.validation_items[724]),
	        "fed25363dbd220b062849c528d8519c6f597e0e0d889d50347198eff08c82ed32ffcfbc7af79794940199fc2991617af7c8d7a9213e072c8b630ba202fe60e55",
	        "/usr/lib/kbd/unimaps/lat4.uni"
	);
}
static void svir_726(void) 
{
	svi_reg(&(tinfoil.validation_items[725]),
	        "549c2ee01e998096d0fa5529613a74e3dc482b39c2b9bc727fe3f1503178679d3a743a3fdb30c296032dd395414eb821b9f62365d82c8dcfef80ae1f4ba81938",
	        "/usr/lib/kbd/unimaps/lat2u.uni"
	);
}
static void svir_727(void) 
{
	svi_reg(&(tinfoil.validation_items[726]),
	        "f282a67b76accfad7aec1caad4540b0a7cfa700709931e667e5698b93b773ff5afac10a824e61305e3d076b6215715ff41c46ec590194c7aab8883406477df4b",
	        "/usr/lib/kbd/unimaps/lat2.uni"
	);
}
static void svir_728(void) 
{
	svi_reg(&(tinfoil.validation_items[727]),
	        "669731632d61a7b784d21abc61ca55619d187ba6eb2e4e66d3a2affb5365171ddf559bce103c50fb3b030f9b422cb172bb550932fdf14f4586238c5ed7c0b88e",
	        "/usr/lib/kbd/unimaps/lat1u.uni"
	);
}
static void svir_729(void) 
{
	svi_reg(&(tinfoil.validation_items[728]),
	        "003db33b95ad4bfcc80921c6512e82abaf29ecf5511305f9aeb50921b5bccdec0f5ea099d194d591d9cbfdd359fd2c2e84fecbb16d33399a5c7b34f685c9a6ec",
	        "/usr/lib/kbd/unimaps/lat1.uni"
	);
}
static void svir_730(void) 
{
	svi_reg(&(tinfoil.validation_items[729]),
	        "12acc724aa027d64d5ce2468284a81407a391193e785c529f65301f2d56b1a7e0698dd12c437775a3b8a712bc12fd62eb598e793c4fdd8d76d1ddfd8feab4555",
	        "/usr/lib/kbd/unimaps/koi8u.uni"
	);
}
static void svir_731(void) 
{
	svi_reg(&(tinfoil.validation_items[730]),
	        "f71b70cbefd4a03dbf40b843c6b1a8ee45c360e5af957e48495df0c63fc1a463972f97dcb295280f93c4c6d8733d5815c73f9d989935eea4e6ffd8a0a5c28827",
	        "/usr/lib/kbd/unimaps/koi8r.uni"
	);
}
static void svir_732(void) 
{
	svi_reg(&(tinfoil.validation_items[731]),
	        "0654b14633489cbc64b220ef76da0f7ade231858d1f7527ffda0cf54796fbeb207c651cc54497e5a78dab6f562bcc447d9df9c209402bad8e2b63ebc46b77080",
	        "/usr/lib/kbd/unimaps/iso15.uni"
	);
}
static void svir_733(void) 
{
	svi_reg(&(tinfoil.validation_items[732]),
	        "d2bf8d7ba201c2df06457993da0b786e841f57fe3862a6eeca8120a8fe8abf6ebafeee3364bcedea9ce5480ea341983be4b85e19f780f48a1ce99c942891ff19",
	        "/usr/lib/kbd/unimaps/iso10.uni"
	);
}
static void svir_734(void) 
{
	svi_reg(&(tinfoil.validation_items[733]),
	        "bf4b98d29f4e96eec6229cc1218b37afecc9cd6399a039fd8112a8e8801aa42076c59d063e2682de7de9279c7c2650a04e18a84c9976cd66569312002e2ca4ff",
	        "/usr/lib/kbd/unimaps/iso09.uni"
	);
}
static void svir_735(void) 
{
	svi_reg(&(tinfoil.validation_items[734]),
	        "375f2b8e667eb47962531c64e334701a3e7ac2701d13a226dfb1579c3c8af7112b234a383b0e1a1093dca7080c742bfc85824317e16416fb71953ac352bf6c66",
	        "/usr/lib/kbd/unimaps/iso08.uni"
	);
}
static void svir_736(void) 
{
	svi_reg(&(tinfoil.validation_items[735]),
	        "6576035ccea30fd440f61b889fce1fd96ece60b466baa9f6892c4d421fb9d6a9434bf35ceedc148006ebb13caa53a3b76c240a1659ff1919cb7bf1038c41211f",
	        "/usr/lib/kbd/unimaps/iso07u.uni"
	);
}
static void svir_737(void) 
{
	svi_reg(&(tinfoil.validation_items[736]),
	        "52fc846a7c6d2e3b01190e707d57a9b4469f36c850697a8f4dd29b1e4ded2aa83030288ed18a82f04d2481e2668d18eae11a943f98846f20a9d3f3d302dc9d2d",
	        "/usr/lib/kbd/unimaps/iso07.uni"
	);
}
static void svir_738(void) 
{
	svi_reg(&(tinfoil.validation_items[737]),
	        "5c204724ccb4262aec12bb386b4925976b3b46327597d5d90e1f3ec527611a868ff69c3648eb26a7b563dc74327f07c2e21383aa984117ed4bb4a7e5abac7ce0",
	        "/usr/lib/kbd/unimaps/iso06.uni"
	);
}
static void svir_739(void) 
{
	svi_reg(&(tinfoil.validation_items[738]),
	        "ea41e162380f3d06e61e99a5c4c389d7eeb0df0b03dd1bba2defbe5525276ce224c4180c4c7af65b322462944b62294d05428d2e1425fe1509813f37125d9caf",
	        "/usr/lib/kbd/unimaps/iso05.uni"
	);
}
static void svir_740(void) 
{
	svi_reg(&(tinfoil.validation_items[739]),
	        "bbbdd75caf1d325257fbbf4e86647a97cdada8a441940b07985b44e8f1ab041eaea9c35d22c21473c7ab804326c7eb50223d04809f07e89df00e4e18ac0281af",
	        "/usr/lib/kbd/unimaps/iso04.uni"
	);
}
static void svir_741(void) 
{
	svi_reg(&(tinfoil.validation_items[740]),
	        "1bb3250096d7d26cca3423f5eef73e362d61e39ff706eef12883e871af11d6ed56c8cdb29149c093a22c832b250bc429678798f7ab737a712e493130b0944aa4",
	        "/usr/lib/kbd/unimaps/iso03.uni"
	);
}
static void svir_742(void) 
{
	svi_reg(&(tinfoil.validation_items[741]),
	        "31ebc9b3faaf65bbd1e16ce6cf37437af7d9867a247946982ae90a0b57cdf4c6352cc6293c113f98244e1ae8eb6c55dc4eefbd2857a404159374177cb723c9d5",
	        "/usr/lib/kbd/unimaps/iso02.uni"
	);
}
static void svir_743(void) 
{
	svi_reg(&(tinfoil.validation_items[742]),
	        "01c9b6afadd3dcda1057283be85d0712b81cd82c86a0f8880735a8567108b75a1b6bd5c8ae03be70966d08a740500b11d6a3cd0b43f3761c07fcac9fec952736",
	        "/usr/lib/kbd/unimaps/iso01.uni"
	);
}
static void svir_744(void) 
{
	svi_reg(&(tinfoil.validation_items[743]),
	        "028c5a162955c4598b93a381a120960590f60d72de80ab4ad4c3fdff7fb7e0d91fbc52b2feb4e27749b821d7cf0b280ea42c17398275b37428cca5d13a9773e4",
	        "/usr/lib/kbd/unimaps/ethiopic.uni"
	);
}
static void svir_745(void) 
{
	svi_reg(&(tinfoil.validation_items[744]),
	        "507dc828ae8c377d33b42b55a803aec64b7b89110b58363152025e13da78351e388d6f12e9a469a396cc9ec3657a7f8f568a20507b4dad854389a21dcd3b3837",
	        "/usr/lib/kbd/unimaps/empty.uni"
	);
}
static void svir_746(void) 
{
	svi_reg(&(tinfoil.validation_items[745]),
	        "737a7835c7597c1c7f84f78a979e81dfd01a6c0633a825fa23493f887949ac37f31f206dee7552e7197068b3d2b0a65badf470ad3a56f8c0438221e936a2acbb",
	        "/usr/lib/kbd/unimaps/def.uni"
	);
}
static void svir_747(void) 
{
	svi_reg(&(tinfoil.validation_items[746]),
	        "3efaf173dec32e4272a321e9d845bc220e8791cba552dc1bb3db1e3e994a3134647e04b82708688d5e3f2508aa106cef9923b03697c1053889c2fdb4cb82b4d8",
	        "/usr/lib/kbd/unimaps/cyralt.uni"
	);
}
static void svir_748(void) 
{
	svi_reg(&(tinfoil.validation_items[747]),
	        "8538afdc49904bd3e289f3f5a6c2520e2310522026451d253b88ce81bf2894d2491fd2bf0dc01d882f8584b2df89c7fcb3d5ada49be5f79f682827b14eb23f48",
	        "/usr/lib/kbd/unimaps/cybercafe.uni"
	);
}
static void svir_749(void) 
{
	svi_reg(&(tinfoil.validation_items[748]),
	        "b7912529184585987524e8a87ab658b06a0d36ea71bd1910b866047600294d5affeb36dae972d6fe18a0904ea6c33ee497645652b954dd3136f301018b9d996b",
	        "/usr/lib/kbd/unimaps/cp866a.uni"
	);
}
static void svir_750(void) 
{
	svi_reg(&(tinfoil.validation_items[749]),
	        "6932da75e702a2eeb932f17885c264fbf35836c4c44ddf661701e2adb098059971231e6522213029a608318a4599041fd8a6e06e6856fa3072e668fc2883171a",
	        "/usr/lib/kbd/unimaps/cp866.uni"
	);
}
static void svir_751(void) 
{
	svi_reg(&(tinfoil.validation_items[750]),
	        "8287b8d2936065bcc5f98824e1d0935a0fcaa33ecab450652d742e75d629195d7eb7bcb034d1c3cf58929de420809d6f63d4a3296f5676a813c4554db3cf2dd8",
	        "/usr/lib/kbd/unimaps/cp865a.uni"
	);
}
static void svir_752(void) 
{
	svi_reg(&(tinfoil.validation_items[751]),
	        "a407d63ad24da7ebd2d2c041dc2548add174563d09ed5160fb774d02f2077066b766ab0cdf2ee61938a5ce4c6ffbba1c6780121fe6e38ef7ae98b80453b5b8b1",
	        "/usr/lib/kbd/unimaps/cp865.uni"
	);
}
static void svir_753(void) 
{
	svi_reg(&(tinfoil.validation_items[752]),
	        "6f4dd38eb807f0f2c2e26427cf24e2861d4e894e1b7f3f255cd07223638d0f372ced1244bb645dc192d3c41588a812bab282a74c4111c72ea6269362ed0d3b7d",
	        "/usr/lib/kbd/unimaps/cp850z.uni"
	);
}
static void svir_754(void) 
{
	svi_reg(&(tinfoil.validation_items[753]),
	        "52152dd29a0455593150be8c2da899536a113cdb5d1d293fa6fc61e51194b3830abc08701e9a44ca0df9c2de5e5b644eeaa3bbce4892625f871fa87bef122df3",
	        "/usr/lib/kbd/unimaps/cp850b.uni"
	);
}
static void svir_755(void) 
{
	svi_reg(&(tinfoil.validation_items[754]),
	        "b198cc30d5e1cc8be4dc8ca56d6db4ed3262633d7bca8516e3b1dde13f57d36a158fcbb3b74d51739c5ec4ea773b3d74b505876300cecd83d1ec5184321e2fd9",
	        "/usr/lib/kbd/unimaps/cp850a.uni"
	);
}
static void svir_756(void) 
{
	svi_reg(&(tinfoil.validation_items[755]),
	        "f4d8f08bdd789be3706b3d8d9a6c01e236c8f5689ac9f6bc21913412ce658cbadcf4683100cb855ca416f7b5bf928883898cc0c27dbaf7d2eec2a7a0cf4c4730",
	        "/usr/lib/kbd/unimaps/cp850.uni"
	);
}
static void svir_757(void) 
{
	svi_reg(&(tinfoil.validation_items[756]),
	        "4ab3ac770fb3c53720bf436d245efe045131076fdf43ba656a191cd58ea2a0b5307146d43c9b7a3da96d164913861b4c421231b73b6a5b86c3c42c4de00d00f6",
	        "/usr/lib/kbd/unimaps/cp737c.uni"
	);
}
static void svir_758(void) 
{
	svi_reg(&(tinfoil.validation_items[757]),
	        "f2a239e04d3f64bf0ddd7c9ef1aa4657be6981450235bb11e0c55073a69d7ddee333c9ee87392b25e4ce6bfa289020bf3e410c4e7e476e4d4bc53a72c8c1ef19",
	        "/usr/lib/kbd/unimaps/cp737b.uni"
	);
}
static void svir_759(void) 
{
	svi_reg(&(tinfoil.validation_items[758]),
	        "6fb77745745b877f664aa88ddc9ecc0c23a24d1ff33ee3b934271a88a1bddcb738e2f1a59422bd93fc2dcc4ec6bb1a0391cb0b42b22da7e61438ec758522b2d8",
	        "/usr/lib/kbd/unimaps/cp737a.uni"
	);
}
static void svir_760(void) 
{
	svi_reg(&(tinfoil.validation_items[759]),
	        "a64cf7085a3ab5a94c9e23733609343daadbce3dc36c7a0d0e6eebda9ea27e9d7f130e92d2f359f44462fca73cb5baac387fdd0ebb3589e083ba3b6e864aa6cc",
	        "/usr/lib/kbd/unimaps/cp737.uni"
	);
}
static void svir_761(void) 
{
	svi_reg(&(tinfoil.validation_items[760]),
	        "91d0102167f686a01eb6af5381af7d06a80eda1cafb969d62c28ac5af07536c49d8f1f66573f75db98caf81a62d2a2986e98d6451ef78839bfb20eb651042465",
	        "/usr/lib/kbd/unimaps/cp437.uni"
	);
}
static void svir_762(void) 
{
	svi_reg(&(tinfoil.validation_items[761]),
	        "c65979af7a70a41efbeeaf7533e5dbe8fd5d5bebffaebbfa9cdac049b157bb32a07f0413df773cf72b969143f98273340a90ae7cfc9d7a3fdc596cb23518d9e3",
	        "/usr/lib/kbd/unimaps/cp437.00-1f.uni"
	);
}
static void svir_763(void) 
{
	svi_reg(&(tinfoil.validation_items[762]),
	        "6f785fffb98db0bc7824a021758b599f82991d5736d736155d6a7db99ac2d277910caeafe7de35b49a69e42c214b02d77b8d03fae734da9b846083400b5c0332",
	        "/usr/lib/kbd/unimaps/cp1250.uni"
	);
}
static void svir_764(void) 
{
	svi_reg(&(tinfoil.validation_items[763]),
	        "6dfcc5ae0304039c7b7a865e54b6beef891302d94fcfb25536ba1e04cddc967cd170db11b6c8bfff745bf1375d3e55c108a07785d979ce1ea2febfdf8c91dfd1",
	        "/usr/lib/kbd/unimaps/ascii.20-7f.uni"
	);
}
static void svir_765(void) 
{
	svi_reg(&(tinfoil.validation_items[764]),
	        "2c9018c6f7820e6eaaa73cf9462a32c8cbdee71854c9a3b636c4fd41066fae9aac89d09969c965ef279aab8382703d7d25e04a70bce6791e82f375ce671cb3c7",
	        "/usr/lib/kbd/unimaps/armscii8.uni"
	);
}
static void svir_766(void) 
{
	svi_reg(&(tinfoil.validation_items[765]),
	        "fc0935fb673715150e0f2076b74c6d10c35bb98170ee503d33b9b593e52f86342287386023ae496896891523fb4f4214d44f07ff382647f226f6fa261b1ccf9e",
	        "/usr/lib/kbd/unimaps/ECMA144.uni"
	);
}
static void svir_767(void) 
{
	svi_reg(&(tinfoil.validation_items[766]),
	        "193373d95d6f1ce3c087d147efdd08ce3c0315d44382e8c2c9d193edafe572e4bf5696d3301de07183ae3515af1bffc27ba42d9ddbe53cfb8f2f64ec0d633f43",
	        "/usr/lib/kbd/unimaps/8859-9.a0-ff.uni"
	);
}
static void svir_768(void) 
{
	svi_reg(&(tinfoil.validation_items[767]),
	        "ecdb5c83fef936c72cff967d77c2c917a5a2cefb333102f48d00a6ff59afae0b6587002cbf774fc7ba03158ce85e3abaab108439a79bceff236f54bc7fb7a428",
	        "/usr/lib/kbd/unimaps/8859-8.a0-ff.uni"
	);
}
static void svir_769(void) 
{
	svi_reg(&(tinfoil.validation_items[768]),
	        "bcb8babc8f445f77b89f5fbb4c22d4e0d9f36e2d4860f9178a71101730ea9fb495210a8767083816fab52a75b99b885c5a8186560e7408f5481bb1b1149995c6",
	        "/usr/lib/kbd/unimaps/8859-7.a0-ff.uni"
	);
}
static void svir_770(void) 
{
	svi_reg(&(tinfoil.validation_items[769]),
	        "14d42d7cba6a4bd8514aadd431ed637aa0efbef4e4ec13d8aa008a7c02d63c3507dbeb17ada7c812f4f3e78dfaebd4d1a25501229aa83d83da9567b7a3c1b2f8",
	        "/usr/lib/kbd/unimaps/8859-6.a0-ff.uni"
	);
}
static void svir_771(void) 
{
	svi_reg(&(tinfoil.validation_items[770]),
	        "164407aee3103ccc603192fdb94fc8c3301e9c2f313bbfc32c202be636b788ca9429db9c5511dbfe4bbad7b01412b6cf0e31c4bc99e164d8539a6e67302c30b8",
	        "/usr/lib/kbd/unimaps/8859-5.a0-ff.uni"
	);
}
static void svir_772(void) 
{
	svi_reg(&(tinfoil.validation_items[771]),
	        "85b6e3a6a092e01b513420ddb1b0f547f07f32b27f5c2f9d5e09699e4fe66635262ef7dc77cd35d56bd1fc6e3782d36aac6e51fae852d3b67f83c6c16ae39dfb",
	        "/usr/lib/kbd/unimaps/8859-4.a0-ff.uni"
	);
}
static void svir_773(void) 
{
	svi_reg(&(tinfoil.validation_items[772]),
	        "804cca8a3b162ecf29c77a12b078ae865b0e6b308c6edfa83590a3964c6b29eba7e9396f1d181fea41e71c3e130cd0b77c94dec93fb328a61fd242282f7fbabe",
	        "/usr/lib/kbd/unimaps/8859-3.a0-ff.uni"
	);
}
static void svir_774(void) 
{
	svi_reg(&(tinfoil.validation_items[773]),
	        "2051e982f00017549c3121a6f2410376097a28239b73d40f0a16d8333b5ddba4a398689f7b45ffdf6222689ff0760f9f49800c41bab89976068b82d06f3f3de1",
	        "/usr/lib/kbd/unimaps/8859-2.a0-ff.uni"
	);
}
static void svir_775(void) 
{
	svi_reg(&(tinfoil.validation_items[774]),
	        "ec187c7518384e6ae157616934291e01ac2607875bde3f722124bd2af3d69ae810589ed94e9beccbe87862ea16a6c77f2b88f959940c3dcbebcfafd6353dc503",
	        "/usr/lib/kbd/unimaps/8859-15.a0-ff.uni"
	);
}
static void svir_776(void) 
{
	svi_reg(&(tinfoil.validation_items[775]),
	        "e409e3c55c92cb012fe0d5452e2246a0b6e19325cdb735526e177546fc9f6290cf1a8c1682d30a2b5d18b599593ff5efafe116ab0a097ae8e2cf019ab171d930",
	        "/usr/lib/kbd/unimaps/8859-14.a0-ff.uni"
	);
}
static void svir_777(void) 
{
	svi_reg(&(tinfoil.validation_items[776]),
	        "d9342bab12fd7b896660ccb80ed20930216d23cc127a1d3eafd02521c4ce357c56241621d3b7d129ed1317d09b7a4d2f68e02eff8357feed57126ef86e352075",
	        "/usr/lib/kbd/unimaps/8859-13.a0-ff.uni"
	);
}
static void svir_778(void) 
{
	svi_reg(&(tinfoil.validation_items[777]),
	        "4462e658cb488c4b3540de54b723626177ea4abfdc79ec040cf24fabf116df6ea98122dd36e7d8c013939face417d0eebee83405cf44a2400cfc704f985fe68e",
	        "/usr/lib/kbd/unimaps/8859-10.a0-ff.uni"
	);
}
static void svir_779(void) 
{
	svi_reg(&(tinfoil.validation_items[778]),
	        "62e3a2bde8cff0822cab9aed017fd8fa9c4c88983c420635a415c6e6b5ccd5ca77ac288f4f80c0e45f89f79c9ccbd5620e24e513c3de4827622eddc826d47630",
	        "/usr/lib/kbd/unimaps/8859-1.a0-ff.uni"
	);
}
static void svir_780(void) 
{
	svi_reg(&(tinfoil.validation_items[779]),
	        "74fcc62c06dc658628a3aac339e6d9152a990075dc80c32f5245dca937094794842758a1f42d5243a7791e79ab201ce0ad7a1c2b521492fc405a25c84e9d9698",
	        "/usr/lib/kbd/keymaps/xkb/vn.map.gz"
	);
}
static void svir_781(void) 
{
	svi_reg(&(tinfoil.validation_items[780]),
	        "c573f4c1c371fd2fd5804aec475473eaebfc6fd8de62293ebf8794bdc9ca868760c73ecaa5f90cc73501b1aa7db3a2c5577e3a085766645db320d21224702e78",
	        "/usr/lib/kbd/keymaps/xkb/vn-us.map.gz"
	);
}
static void svir_782(void) 
{
	svi_reg(&(tinfoil.validation_items[781]),
	        "9bdd800ac5af39d497bbef08442651b295c6af941a643e89996ae99e91090ec90a374709eaf57fd36bc266280749eba9f407ca6beff197c2a3c47d65ff86ebf5",
	        "/usr/lib/kbd/keymaps/xkb/vn-fr.map.gz"
	);
}
static void svir_783(void) 
{
	svi_reg(&(tinfoil.validation_items[782]),
	        "83b2df9f278ea7415b75830178803f4ed6e044a60b88914a1d14286a1b8a7b2929cae020616319ddba7ecc9a6984aee611f052e46f0f883019d175883d484241",
	        "/usr/lib/kbd/keymaps/xkb/uz-latin.map.gz"
	);
}
static void svir_784(void) 
{
	svi_reg(&(tinfoil.validation_items[783]),
	        "74c60b34b1d444c3d4e2cb2db157f264a15095bd5c4e5d78975937d3288a8fbeacddce97f3b90411d2e40f170bc54f394721c365fa8084a83ce4aa597e650ffe",
	        "/usr/lib/kbd/keymaps/xkb/us.map.gz"
	);
}
static void svir_785(void) 
{
	svi_reg(&(tinfoil.validation_items[784]),
	        "89518ad328febad789dec72102f99b4dfc817d886703944c386e8f5a06c6e2870eb16008ba2d084138de6f52025df3497d649962d27c2b4a2cb6b98fc024299a",
	        "/usr/lib/kbd/keymaps/xkb/us-workman.map.gz"
	);
}
static void svir_786(void) 
{
	svi_reg(&(tinfoil.validation_items[785]),
	        "9eeb2783fe7dc4ff6361c9633fb9bd00f2041b7ac00a350e64107acd49a328d8bb61e0e578cdd6ff267d99ef40f1361352d79397a92a7578c821ffef82076155",
	        "/usr/lib/kbd/keymaps/xkb/us-workman-intl.map.gz"
	);
}
static void svir_787(void) 
{
	svi_reg(&(tinfoil.validation_items[786]),
	        "500418535be363605b72c6491491f8fd7bbb038b0b342688a3e95c9bcc6cce7973f98c1f8e46ce8665f60c35dfbcdf819b6c98f80568465ce91cb834a19c27b9",
	        "/usr/lib/kbd/keymaps/xkb/us-symbolic.map.gz"
	);
}
static void svir_788(void) 
{
	svi_reg(&(tinfoil.validation_items[787]),
	        "96dbb6e7f413c8a56e5acd65f098449b7acd4750a6a2c26a62eff6bfda90a12952e7cde9d9928a3c98478e76619ee41e4d8d80bb695bdbde3983294f6a874979",
	        "/usr/lib/kbd/keymaps/xkb/us-olpc2.map.gz"
	);
}
static void svir_789(void) 
{
	svi_reg(&(tinfoil.validation_items[788]),
	        "566203d57390725775b3b1ffc6222403e10a4931a2a0940cc3508276c1726b418380f6cc612507146e7be2d29e312a26b58ab97228f426974441409f367a12ec",
	        "/usr/lib/kbd/keymaps/xkb/us-norman.map.gz"
	);
}
static void svir_790(void) 
{
	svi_reg(&(tinfoil.validation_items[789]),
	        "c3d1ffa972aceb931192854b68e690598f8101881330d07d0396e6ab3557527533e198c32b3daaf5576efa89978212cd88c80f0d72168cd352bf8f06814c50ca",
	        "/usr/lib/kbd/keymaps/xkb/us-mac.map.gz"
	);
}
static void svir_791(void) 
{
	svi_reg(&(tinfoil.validation_items[790]),
	        "7d1d48ccc54406979ff49e4b8e5cf54d1d17f501a333dd66c51c3c334b5c7dda8ea08766b349bfa21c581936090baf68f18b0f982ffac3a4399d2640c6245f5f",
	        "/usr/lib/kbd/keymaps/xkb/us-intl.map.gz"
	);
}
static void svir_792(void) 
{
	svi_reg(&(tinfoil.validation_items[791]),
	        "8fc3b8ce66fdf1210e5e1522ec2b0fac0903f0e0b6533776972b8a5bea35a5d31180e1ee15473b9ab56553e0958f1c4a5785124f414c266546c36c40a5e53ec8",
	        "/usr/lib/kbd/keymaps/xkb/us-hbs.map.gz"
	);
}
static void svir_793(void) 
{
	svi_reg(&(tinfoil.validation_items[792]),
	        "778eab4064034caefe81f481bab1938e36fdbcee25f89f901fddb73f8c366fafc93cae82cafaf88323f635f5d1d9c032905bad0bac270f2ad2e445f31a6f1471",
	        "/usr/lib/kbd/keymaps/xkb/us-haw.map.gz"
	);
}
static void svir_794(void) 
{
	svi_reg(&(tinfoil.validation_items[793]),
	        "2beb8af911f35922e157f0686d741fda743278dd57487a71f349db22daa9b41f2a2817950ccc86cbb7828ad5a9ee7e0b280c9af8a6437093887a07d4d128139c",
	        "/usr/lib/kbd/keymaps/xkb/us-euro.map.gz"
	);
}
static void svir_795(void) 
{
	svi_reg(&(tinfoil.validation_items[794]),
	        "a79f15e247c5db0bb8601f688d5ccf325c308e1ae82d6a0817923379fd6d0ea06363eb011e22f5818b928e8b7d3bece257309f6d4b4102e84ccbf8454e16a0d6",
	        "/usr/lib/kbd/keymaps/xkb/us-dvp.map.gz"
	);
}
static void svir_796(void) 
{
	svi_reg(&(tinfoil.validation_items[795]),
	        "c21f27de9146fdf49b41adb6a737a63672adfe69c1f0fb0a0d05d5ade600e76e60f8608b0daa0d16af38ec5e07f948a8b828fab6008ec780bf0de1eee8c0edb5",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak.map.gz"
	);
}
static void svir_797(void) 
{
	svi_reg(&(tinfoil.validation_items[796]),
	        "71710000feb2aa8e9656282db516f01ba2338db0cc4123dc30673d8da5f01a10be19bc80f7363e22da6c603e7e8a987d28d82804570209ead7954b350d7a2889",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak-r.map.gz"
	);
}
static void svir_798(void) 
{
	svi_reg(&(tinfoil.validation_items[797]),
	        "163bb0e2cb822246edbf10753af6f57c182196306f00e70bf7af5b4998bb2db828150a2b04b2cfd121d9e1c2ae87451da0f545567866a0e5b9611151f599365d",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak-l.map.gz"
	);
}
static void svir_799(void) 
{
	svi_reg(&(tinfoil.validation_items[798]),
	        "999ce4474617bf662efde33f584c8209ede4a596e6c546adc104ed27a7848c29ad37bd253eddd8c1a9717d8a4f6e7762e62a70d53de6fab4816c0c286a4c0b29",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak-intl.map.gz"
	);
}
static void svir_800(void) 
{
	svi_reg(&(tinfoil.validation_items[799]),
	        "4e5c7624be4f0bfaa9232b0a758e1df72292eec19e9c6de7547000b0231e8386f6d28f3f0f200b1b1967ed0485265de18031abf25cac5840e0f30acf4cad54aa",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak-classic.map.gz"
	);
}
static void svir_801(void) 
{
	svi_reg(&(tinfoil.validation_items[800]),
	        "6690fdbf420ac074c9c331f4e6b929616a4b2eaf3908be5eff52280fb5f9862119eabe4272805fe12bacee9cee94a49b6feee2bb67779fcfb588489c25a4c985",
	        "/usr/lib/kbd/keymaps/xkb/us-dvorak-alt-intl.map.gz"
	);
}
static void svir_802(void) 
{
	svi_reg(&(tinfoil.validation_items[801]),
	        "812097dc1b3b1376f669d8f7b755035cdeb033204e0727c9e9ed4653f398ded4969f1c958526b7a90ad2ef063a1875b02bd53c899ae96c918e3b801f5261df01",
	        "/usr/lib/kbd/keymaps/xkb/us-colemak_dh_iso.map.gz"
	);
}
static void svir_803(void) 
{
	svi_reg(&(tinfoil.validation_items[802]),
	        "951bee934e386e010e3517414b7f27f4770a6bae9cdbae0db8ffdf54cce68e9324e3fd19025ef5aaa41cbf71d90c83c33e10bbb9f8f8455f06d836fc94b7d189",
	        "/usr/lib/kbd/keymaps/xkb/us-colemak_dh.map.gz"
	);
}
static void svir_804(void) 
{
	svi_reg(&(tinfoil.validation_items[803]),
	        "a7e1f3915e758f859ea8412b58fb1f768f42040f066190f482bd52cbeab7d0851fb21a66271fd03cd5b652104d8201d2916c1e18bb6aa93ca6e0f2cdc332073c",
	        "/usr/lib/kbd/keymaps/xkb/us-colemak.map.gz"
	);
}
static void svir_805(void) 
{
	svi_reg(&(tinfoil.validation_items[804]),
	        "f91cc1d8b359c27a0cfd3303399eb6cf09f083ba10be0e9ebe93c9edf1b8e4de8db2911f1ab1f3985dca3574e6726934946eca0fbcdd205915c2ef9cf3bc5c4c",
	        "/usr/lib/kbd/keymaps/xkb/us-altgr-intl.map.gz"
	);
}
static void svir_806(void) 
{
	svi_reg(&(tinfoil.validation_items[805]),
	        "f6248524bddfa67317f39d39ffc066df1733b89ab3f36489dc6007085ca20a2d6ecb9f9c3a91bab0622f57f9baf5d8b63dac62394989b8fbd96891635f7b83b4",
	        "/usr/lib/kbd/keymaps/xkb/us-alt-intl.map.gz"
	);
}
static void svir_807(void) 
{
	svi_reg(&(tinfoil.validation_items[806]),
	        "852bd02e61532ec8c23e316183de8c2b73bf03e90b03b1125265a55f7d9694ea8db871bf9c83df6e81a76230222b0cf248b47b75176f8b4ef8679c590d83425a",
	        "/usr/lib/kbd/keymaps/xkb/tw.map.gz"
	);
}
static void svir_808(void) 
{
	svi_reg(&(tinfoil.validation_items[807]),
	        "df950cb24916200626445327cdd0c738be631635c1255c2ff620397ec3505769647082557e195ee2623738ce5537d92c79790868fb64ccb4fd056cbd0d408d15",
	        "/usr/lib/kbd/keymaps/xkb/tw-saisiyat.map.gz"
	);
}
static void svir_809(void) 
{
	svi_reg(&(tinfoil.validation_items[808]),
	        "61182d98cecadaa522eb8636f903775d16ad87e183d30bf1390647f4ae68939074ad3fb244e688a742175cad38beb10c4b7984a16fdc00203a4fc3f0321d2728",
	        "/usr/lib/kbd/keymaps/xkb/tw-indigenous.map.gz"
	);
}
static void svir_810(void) 
{
	svi_reg(&(tinfoil.validation_items[809]),
	        "31deb8ff831ee217b0bbc8ac9edc04635f25d40b3053701029200beeed55340b4474fc1de8c1120f1630add1b5b725eec419c7b7251006d92f2d085a2125bba3",
	        "/usr/lib/kbd/keymaps/xkb/tr.map.gz"
	);
}
static void svir_811(void) 
{
	svi_reg(&(tinfoil.validation_items[810]),
	        "be181abd70acd765049fadae777941290e1c3270e173010260d107714bcdf250dd6657d246c3c6d97786fde864cfd856b99c1df3c765d182b4da13d2e3482363",
	        "/usr/lib/kbd/keymaps/xkb/tr-ku_f.map.gz"
	);
}
static void svir_812(void) 
{
	svi_reg(&(tinfoil.validation_items[811]),
	        "5ba65cbf383933d3b3a09d232eb253d630f8fb5c3d27041d98d1ac035c9eeef0bcf3bbe821a0fff330288f7405f92c74cc294047733421b47575f25519733e5b",
	        "/usr/lib/kbd/keymaps/xkb/tr-ku_alt.map.gz"
	);
}
static void svir_813(void) 
{
	svi_reg(&(tinfoil.validation_items[812]),
	        "49a9083d4e9f766b27cc41fe8f3ef4b9542ee3339f02d835b283e7aaaf88e63bf3482a1f24fe6dea3fc626c272b5d82d1ee123cd42ce9d5ef773eaf59cf4ebd3",
	        "/usr/lib/kbd/keymaps/xkb/tr-ku.map.gz"
	);
}
static void svir_814(void) 
{
	svi_reg(&(tinfoil.validation_items[813]),
	        "47964356d22bd6050ee1ab8571c902bbfea8bcfa418a896fa110bf667194a5cd4988318b892724c408ac7e5f987cce22b9ab322a552f1dbc8e5a5dad2370fab4",
	        "/usr/lib/kbd/keymaps/xkb/tr-intl.map.gz"
	);
}
static void svir_815(void) 
{
	svi_reg(&(tinfoil.validation_items[814]),
	        "e6a56ba35e05f12d2276f79acc938a6abf3ab59efb6f0bad3517089b6648c83d03a70367acf3827b7bdfc4d4cef1dcb71b92f654a0de4d2a43205c5da371918c",
	        "/usr/lib/kbd/keymaps/xkb/tr-f.map.gz"
	);
}
static void svir_816(void) 
{
	svi_reg(&(tinfoil.validation_items[815]),
	        "919d87f73b73d5e14bc6b1220ebede918b4e408383c9b9b2ba6615aa54b99d7e779d7a96627489e9fde2351d1df1b73a8b3ee57a68629e4ff4f77292265eaef9",
	        "/usr/lib/kbd/keymaps/xkb/tr-crh_f.map.gz"
	);
}
static void svir_817(void) 
{
	svi_reg(&(tinfoil.validation_items[816]),
	        "6560f9b52ac4679bd73315ea1e34ce368d86fe15dad5d41169fd544e959d27d419cd4d304831513d2ed9c1877d41788e9769347373ddb4edc65dd6eb53fd10e0",
	        "/usr/lib/kbd/keymaps/xkb/tr-crh_alt.map.gz"
	);
}
static void svir_818(void) 
{
	svi_reg(&(tinfoil.validation_items[817]),
	        "8a1c5b01e7cbf137082701c94b97b52202fa4aad57222bc49af2f1ab0a6d02de8ec7fdaf77676eebe958de17a686128836af892899c610655712f899c9760014",
	        "/usr/lib/kbd/keymaps/xkb/tr-crh.map.gz"
	);
}
static void svir_819(void) 
{
	svi_reg(&(tinfoil.validation_items[818]),
	        "0454e91ede4138469d23bbcdbd941d50476bb05f7e21743f2206604534244106cecc1a7478a3ea45d1d134c8b0fea257894da9bd8fbf32282f73f82cbe38716b",
	        "/usr/lib/kbd/keymaps/xkb/tr-alt.map.gz"
	);
}
static void svir_820(void) 
{
	svi_reg(&(tinfoil.validation_items[819]),
	        "d19542e283ed68891e18322984396804d9c96375c93c5d9d73bf393d91b63c09f02df80d874b9fd005932aad849eec335fd9cf6d8573ada10067eae02d577d91",
	        "/usr/lib/kbd/keymaps/xkb/tm.map.gz"
	);
}
static void svir_821(void) 
{
	svi_reg(&(tinfoil.validation_items[820]),
	        "54d2ed5cf139d0191fd8c163c3fc2d6da9b21921b21c81f8f8b0c24a203ae27599a819fe8beb40bada169e2f1670cf1fe1bda50b4643febc665c5269e3307be7",
	        "/usr/lib/kbd/keymaps/xkb/tm-alt.map.gz"
	);
}
static void svir_822(void) 
{
	svi_reg(&(tinfoil.validation_items[821]),
	        "be181abd70acd765049fadae777941290e1c3270e173010260d107714bcdf250dd6657d246c3c6d97786fde864cfd856b99c1df3c765d182b4da13d2e3482363",
	        "/usr/lib/kbd/keymaps/xkb/sy-ku_f.map.gz"
	);
}
static void svir_823(void) 
{
	svi_reg(&(tinfoil.validation_items[822]),
	        "5ba65cbf383933d3b3a09d232eb253d630f8fb5c3d27041d98d1ac035c9eeef0bcf3bbe821a0fff330288f7405f92c74cc294047733421b47575f25519733e5b",
	        "/usr/lib/kbd/keymaps/xkb/sy-ku_alt.map.gz"
	);
}
static void svir_824(void) 
{
	svi_reg(&(tinfoil.validation_items[823]),
	        "49a9083d4e9f766b27cc41fe8f3ef4b9542ee3339f02d835b283e7aaaf88e63bf3482a1f24fe6dea3fc626c272b5d82d1ee123cd42ce9d5ef773eaf59cf4ebd3",
	        "/usr/lib/kbd/keymaps/xkb/sy-ku.map.gz"
	);
}
static void svir_825(void) 
{
	svi_reg(&(tinfoil.validation_items[824]),
	        "10ebd48b21f87122c041aa17a5e2af180f279e4fadb45017f1a111d6e555e7d252fe642ac9947c4d21df7c05a658a826fe3ff196c1162009520def9e937ce537",
	        "/usr/lib/kbd/keymaps/xkb/sk.map.gz"
	);
}
static void svir_826(void) 
{
	svi_reg(&(tinfoil.validation_items[825]),
	        "e040bd6b6828c3792f282de05ea5defc9c435733a0ea23e41b897f6dd489bcd92a2df17243137d5fbab61c98c3579201f1c06f710611ddc393486ebc0efeee5c",
	        "/usr/lib/kbd/keymaps/xkb/sk-qwerty_bksl.map.gz"
	);
}
static void svir_827(void) 
{
	svi_reg(&(tinfoil.validation_items[826]),
	        "3d40a159c0cc49b2f5ccf9f4dde107f2d2d346bba5084d9d14da09c047454052f3da2e13c91a6580a2ef766ae84d5c377f2a93d017fec1cc05f217d783d86229",
	        "/usr/lib/kbd/keymaps/xkb/sk-qwerty.map.gz"
	);
}
static void svir_828(void) 
{
	svi_reg(&(tinfoil.validation_items[827]),
	        "50fa83884f180554cf326a238b7f855b5ed09111d74519947081803b0748bc1d59ccaa45cd02a91546a314258b7fbacc9d242b3a29fae30d87d960963832db1e",
	        "/usr/lib/kbd/keymaps/xkb/sk-bksl.map.gz"
	);
}
static void svir_829(void) 
{
	svi_reg(&(tinfoil.validation_items[828]),
	        "d045a6cbbb0378a57e9606f9fe3a56c0265c30a97bd27eb7334be94ba1284bbe41c9feb53a49f18e62ffe4b2b6c5af4aceaf42e88e6aeab62f3244e26d858165",
	        "/usr/lib/kbd/keymaps/xkb/si.map.gz"
	);
}
static void svir_830(void) 
{
	svi_reg(&(tinfoil.validation_items[829]),
	        "cc5cf5531d2466112ff804b63954e897f0e33dbaa441e0f5158d363ebdcb9a998a5a6abed9e26504b47caaa7a76ae4d110d521fe6bb48c31206d8ef25676606d",
	        "/usr/lib/kbd/keymaps/xkb/si-us.map.gz"
	);
}
static void svir_831(void) 
{
	svi_reg(&(tinfoil.validation_items[830]),
	        "a2cbaf5b231033bd99f84f8a358579d34ee9d90d55f1c6509c07d9c9234c20bda945643744e5103f3d81e898c77998a0a6bd27b9002e6a2511767b5218672791",
	        "/usr/lib/kbd/keymaps/xkb/si-alternatequotes.map.gz"
	);
}
static void svir_832(void) 
{
	svi_reg(&(tinfoil.validation_items[831]),
	        "445f7c1341be2645db5eb4f5ce2e180d116f8aabebc7a1b4e0647d129899b31fe36337d49ae1a06a4a12848edaa44fa34a77e5f2e3efc8353c7925b4e244751c",
	        "/usr/lib/kbd/keymaps/xkb/se.map.gz"
	);
}
static void svir_833(void) 
{
	svi_reg(&(tinfoil.validation_items[832]),
	        "dbf0d44a2c82531a73c850db15c04f8d5a9acbdddc2629bd02e567970401b6f87b57b71c2adc0c70d9fd8f0220f4069c8539ff2d1fe6c009d1031ee18da07467",
	        "/usr/lib/kbd/keymaps/xkb/se-us_dvorak.map.gz"
	);
}
static void svir_834(void) 
{
	svi_reg(&(tinfoil.validation_items[833]),
	        "cdd88575d2d42e7a2d12e13cb425e0a62ea9e3608e6b51c4902c01ef04822710804a36b0911a4df60ba43f444082a04e27acbdea48915c54a4cefcef234a07e4",
	        "/usr/lib/kbd/keymaps/xkb/se-us.map.gz"
	);
}
static void svir_835(void) 
{
	svi_reg(&(tinfoil.validation_items[834]),
	        "416c0a75814da19db2d0152f16746642fa7d2d645d57c4aeb1e57adb573f278caa1c5cafc8ef47b006db980f90c32947f9ef330c166499ba4b7beb6adb47625e",
	        "/usr/lib/kbd/keymaps/xkb/se-svdvorak.map.gz"
	);
}
static void svir_836(void) 
{
	svi_reg(&(tinfoil.validation_items[835]),
	        "40c1e86f8eef179856145b8336c05458de21f0c1021f40a1bdc212a70741a732b7f5dbae1ecb460135e055e7362d578ca956a8d95d564a19d4f0b29ffa612bb8",
	        "/usr/lib/kbd/keymaps/xkb/se-smi.map.gz"
	);
}
static void svir_837(void) 
{
	svi_reg(&(tinfoil.validation_items[836]),
	        "887ec99210ef0f12408fad67ddea9b2fa9a627cd204e267d055bc7435c54a7c35846911e1bdfe847fccab2ef08cd94e1f59a6e8751f40eda8fd5025d64c4ed55",
	        "/usr/lib/kbd/keymaps/xkb/se-nodeadkeys.map.gz"
	);
}
static void svir_838(void) 
{
	svi_reg(&(tinfoil.validation_items[837]),
	        "2b69659c6147eee79bc64a4b8836d5e57f7d1739cd67726bafa7834b38df648ecf11fe94743b8440eb11649019eef6c235c2d4d95585e4bd9225462279cc2a12",
	        "/usr/lib/kbd/keymaps/xkb/se-mac.map.gz"
	);
}
static void svir_839(void) 
{
	svi_reg(&(tinfoil.validation_items[838]),
	        "898a4f1305ca6cebbfd68eae119d258f525a89617eeb1e1be8cb21db4088b4bdfc66c6dc92fb3353fa92902b7414829c3225afd08add1438b815d2e60cba5b79",
	        "/usr/lib/kbd/keymaps/xkb/se-dvorak.map.gz"
	);
}
static void svir_840(void) 
{
	svi_reg(&(tinfoil.validation_items[839]),
	        "f4ae3b9284613c3b0b9f2f99e9ff1d03d4abc9a83071efad9f8d75f3ebfd800eb973fbf940c833c09fd5bd65e66db51a6a1113348037535f39d673e395c32a05",
	        "/usr/lib/kbd/keymaps/xkb/ru-cv_latin.map.gz"
	);
}
static void svir_841(void) 
{
	svi_reg(&(tinfoil.validation_items[840]),
	        "ed849c4ae5de2d1991ab96672cc80aade89f694bab131e48c14542be413ec9da4d108f1d2b353c29995b90ce57850c9aa3a663348d4f86b70961d41c7a5996d3",
	        "/usr/lib/kbd/keymaps/xkb/rs-latinyz.map.gz"
	);
}
static void svir_842(void) 
{
	svi_reg(&(tinfoil.validation_items[841]),
	        "e13b30abf4a0fc45182dfe4cd81e66b9a5aacc2a2077159a7d82db5429ed9793e0fe744d1817119b9cbf9fd8fb6c3a5108c0b3742cb0c896238b4f936fdaeb6c",
	        "/usr/lib/kbd/keymaps/xkb/rs-latinunicodeyz.map.gz"
	);
}
static void svir_843(void) 
{
	svi_reg(&(tinfoil.validation_items[842]),
	        "9200e2cd009ad485e40af427ea8185c5ca58968323d5fd15fd6988492beab98dafd573df1a182bb09b79689456908d3bc5d3ee342f6c2ecf7548065d905ba882",
	        "/usr/lib/kbd/keymaps/xkb/rs-latinunicode.map.gz"
	);
}
static void svir_844(void) 
{
	svi_reg(&(tinfoil.validation_items[843]),
	        "61d4879ebaba728daa37dcf9378e1da79b33dc5401e03eebb9715209657788bb0053003a88efb123022068558c191696ad8c7e4e0becb30241467356cadb03ef",
	        "/usr/lib/kbd/keymaps/xkb/rs-latinalternatequotes.map.gz"
	);
}
static void svir_845(void) 
{
	svi_reg(&(tinfoil.validation_items[844]),
	        "c2f82cb910ce6b38400bbeb5640e7290a967a1cc5572ede843a1c2833cd090ca25af00ded30eea38aa42f2cb74acbf1f9b78d9e2248cd4cabe495790d408e666",
	        "/usr/lib/kbd/keymaps/xkb/rs-latin.map.gz"
	);
}
static void svir_846(void) 
{
	svi_reg(&(tinfoil.validation_items[845]),
	        "3ed327be647db2bc108beb216e2aec421f4903b67ca95b63cc21f8c16820ccdc3b7130809434c24c7a4725d96b341c9d9df3c95aa6ea8cc0de3f77326aaefdda",
	        "/usr/lib/kbd/keymaps/xkb/ro.map.gz"
	);
}
static void svir_847(void) 
{
	svi_reg(&(tinfoil.validation_items[846]),
	        "9142b0b64a5be5dfd42164a1a5644e51ad4267b2192978a546aba9f3a49c873fb47443b6b822991cedd9a04154eccdd36340fe44a84d5e15f7f808d93e9ef3bc",
	        "/usr/lib/kbd/keymaps/xkb/ro-winkeys.map.gz"
	);
}
static void svir_848(void) 
{
	svi_reg(&(tinfoil.validation_items[847]),
	        "e30d61da4601e24c41fa9869e01ed72c526ffd3bdba2bbcdc3e5b74bda0a966ddb05de97241732f3bc3eac3b2ae977e8a18c27cfaa5d9c652da3390d968c6b8c",
	        "/usr/lib/kbd/keymaps/xkb/ro-std.map.gz"
	);
}
static void svir_849(void) 
{
	svi_reg(&(tinfoil.validation_items[848]),
	        "2ca90ffc38f1f8933a72f9bfd3068f16191a201f2608d62c6ddb646993b9cfec77f6fa73221a54801e94bd8e30b1ac1cdb65f1313e288e2762cc4e01464e378e",
	        "/usr/lib/kbd/keymaps/xkb/pt.map.gz"
	);
}
static void svir_850(void) 
{
	svi_reg(&(tinfoil.validation_items[849]),
	        "73ad18e97a49516e0b7d1851e672900e24788b4ac9eaea0ac73b26f327f8c655c98e8d5b90d28df01f743ef25a7cf8f3b57fdd031ced7b54650928dc48aec3b0",
	        "/usr/lib/kbd/keymaps/xkb/pt-nodeadkeys.map.gz"
	);
}
static void svir_851(void) 
{
	svi_reg(&(tinfoil.validation_items[850]),
	        "d4f71a3faf2d898a6d950877c82c84d04d6d44dfd94cd1ba5300989387f32d1718b9e24378694ea388f421abd9ddda220df9699dd6355d170337f3e120f3eaba",
	        "/usr/lib/kbd/keymaps/xkb/pt-nativo.map.gz"
	);
}
static void svir_852(void) 
{
	svi_reg(&(tinfoil.validation_items[851]),
	        "9767efbf7e23991b873cab45ca9afa7ff7d5326668bc561fd5b0055b3d19155e83fcaf09ed72388a8d9eeb1cb1cea3acf0cf175243c7e59145efa076699d69fb",
	        "/usr/lib/kbd/keymaps/xkb/pt-nativo-us.map.gz"
	);
}
static void svir_853(void) 
{
	svi_reg(&(tinfoil.validation_items[852]),
	        "a7d4edd830874a63748f31745227dc192c430b4bc5d92ac50f2d81ae91514de3eef39b3cafbb9fce694d46dd5af284137a6a182eb328caaa01a2f9663b08eac1",
	        "/usr/lib/kbd/keymaps/xkb/pt-nativo-epo.map.gz"
	);
}
static void svir_854(void) 
{
	svi_reg(&(tinfoil.validation_items[853]),
	        "166db3cc7e95ee5e8739b3b772592b8b7a412cb9c0095e0e280c67a2affe0bd8e63cd6f4f7f19eb9755a5a1e6a423f1a81a704ca616afda852ccd7ebdf470caa",
	        "/usr/lib/kbd/keymaps/xkb/pt-mac_nodeadkeys.map.gz"
	);
}
static void svir_855(void) 
{
	svi_reg(&(tinfoil.validation_items[854]),
	        "a663a5db87850ff09752d26dbd2adcae28c9795ca1c124079551585c7899c22e669ea62de7d831e3e846430fa614ae05643eb69821e88f6906b1d71b62ef60db",
	        "/usr/lib/kbd/keymaps/xkb/pt-mac.map.gz"
	);
}
static void svir_856(void) 
{
	svi_reg(&(tinfoil.validation_items[855]),
	        "b68ea74d153012fd1fc9398db2c2c8cf41c9655a1f539b224ffdb704a63cee106f86fc0a9c3a8770cefd26386f25089551b9d44633dce2087d07de91141fe6f9",
	        "/usr/lib/kbd/keymaps/xkb/pl.map.gz"
	);
}
static void svir_857(void) 
{
	svi_reg(&(tinfoil.validation_items[856]),
	        "2138909d425621e2b1245a749373b3b54330dd8b15c21f196fd01ffd530415c3d1221316b650a0401f1f945372d7d0ac0b9e21b381e11c865f04a48ed87cb007",
	        "/usr/lib/kbd/keymaps/xkb/pl-szl.map.gz"
	);
}
static void svir_858(void) 
{
	svi_reg(&(tinfoil.validation_items[857]),
	        "c2bbf8c818f8628a7245cf88ce99efe7ae06fc9057bbef29c5b8a1d592a9d2ea2d6e60e4f23c97da2795ee5ae4d96adcf425f3e32143d9f5acb52f43dabfcc9e",
	        "/usr/lib/kbd/keymaps/xkb/pl-qwertz.map.gz"
	);
}
static void svir_859(void) 
{
	svi_reg(&(tinfoil.validation_items[858]),
	        "f56fb89a0134a4efa16395309b94b08083330406817ebf807045c27fbc09d1d1f0b452b12004327eea4f0443fad185a7d2e6b51d5d25aba468dbd361dcb8b22c",
	        "/usr/lib/kbd/keymaps/xkb/pl-legacy.map.gz"
	);
}
static void svir_860(void) 
{
	svi_reg(&(tinfoil.validation_items[859]),
	        "22ae1b657cd08df01bad05585b3f893fe95baf42183731371096939c3a213d35f240bab7dda4ef019a323ff28c9712d900d63b414fea8804e1e5b74b0d225362",
	        "/usr/lib/kbd/keymaps/xkb/pl-dvp.map.gz"
	);
}
static void svir_861(void) 
{
	svi_reg(&(tinfoil.validation_items[860]),
	        "03a883191fc80bed4d64acd5873c119e09d73db8f841b2680c5131a2febae2c589b93bff50e2ba5ca33a409696689c5665b5756f623379a1e339365d54c9d75a",
	        "/usr/lib/kbd/keymaps/xkb/pl-dvorak_quotes.map.gz"
	);
}
static void svir_862(void) 
{
	svi_reg(&(tinfoil.validation_items[861]),
	        "957eb318ae7954e1c0f81fdd04247ceeefbf53bb78bb36ef611e81ac5ed558122c815e7a9131971873bf548e8e0bf8fca90de783572a591c6578c653b7a8cd38",
	        "/usr/lib/kbd/keymaps/xkb/pl-dvorak_altquotes.map.gz"
	);
}
static void svir_863(void) 
{
	svi_reg(&(tinfoil.validation_items[862]),
	        "e85c3f2e24809fb8ec62881fc88fca51ccbd059ab9fef5e5b71a082b5af382bdb7a882a75736c0552828b2de8e35c7231d4a3a2800f6d335020b5ef5ca3a994b",
	        "/usr/lib/kbd/keymaps/xkb/pl-dvorak.map.gz"
	);
}
static void svir_864(void) 
{
	svi_reg(&(tinfoil.validation_items[863]),
	        "9457a60287bef442eabe37827ec7f864be86dfffc7a82bdce4f9baf3a83b2e25ccb684a778a49a7d4aab8bc54231f366eebd7386f5db3a37489bd1b6d627351c",
	        "/usr/lib/kbd/keymaps/xkb/pl-csb.map.gz"
	);
}
static void svir_865(void) 
{
	svi_reg(&(tinfoil.validation_items[864]),
	        "865ca0d854c51bc2267618ac312ede344ce9a834ae6dcbb551e61e56c817ab56299ea69f66734201db1a5af9e25f793b18d7a8a330125560991d1b9c80623709",
	        "/usr/lib/kbd/keymaps/xkb/ph.map.gz"
	);
}
static void svir_866(void) 
{
	svi_reg(&(tinfoil.validation_items[865]),
	        "46d3973901d6f9bcd1b4960c76c294830a8976ecf8c9c7e77b140fc6deb13c911b8765dfff11f6826ae1b0d3c42aae6a927ce8ecf0b91dca26d3edb09699bd4a",
	        "/usr/lib/kbd/keymaps/xkb/ph-dvorak.map.gz"
	);
}
static void svir_867(void) 
{
	svi_reg(&(tinfoil.validation_items[866]),
	        "ec495d1c3d2747d0f2abf2aa3360520a351a3831b30ee1e2f84c5093fc104282231eec2769e9ce16b8b6be2f87975da362067432c0c9742c95330c406f0e45ff",
	        "/usr/lib/kbd/keymaps/xkb/ph-colemak.map.gz"
	);
}
static void svir_868(void) 
{
	svi_reg(&(tinfoil.validation_items[867]),
	        "3e781b0f27cea70537b3fbad1f23c729fe5e3c5aa05c921b7733000427602eb60a3056372ce4ba7ca50db6bfac8772badfbea38b75e2266dbd6eaf858265638e",
	        "/usr/lib/kbd/keymaps/xkb/ph-capewell-qwerf2k6.map.gz"
	);
}
static void svir_869(void) 
{
	svi_reg(&(tinfoil.validation_items[868]),
	        "78cb4875d4e02f8bd5b56eb99d90e294db7a3f5b457bdd8a0e50315e904d3410b78374c363c4b1ca14aacae752064d2dbc48ef9c986b20c28bb40ff90ad1eccd",
	        "/usr/lib/kbd/keymaps/xkb/ph-capewell-dvorak.map.gz"
	);
}
static void svir_870(void) 
{
	svi_reg(&(tinfoil.validation_items[869]),
	        "0d15a6a4c7eebdb2420ab987ad45d7f17fa1404d27daa16ffc1c2476c11862bb8ccac0dc850a4ceb101a0bf37bb91924445eeb0d12795392ae6bdc0d4131b186",
	        "/usr/lib/kbd/keymaps/xkb/no.map.gz"
	);
}
static void svir_871(void) 
{
	svi_reg(&(tinfoil.validation_items[870]),
	        "e92e5d96eb0ada06fac5be1e5f7b7afb47b240fc109fb44a702aeee5e171fed79b46a3742f350d37436f8d8888868b33accefcae4ec0a21233cbdb5b3548cea4",
	        "/usr/lib/kbd/keymaps/xkb/no-winkeys.map.gz"
	);
}
static void svir_872(void) 
{
	svi_reg(&(tinfoil.validation_items[871]),
	        "639d7460fcce5357be6677050ecdbfce8d41b46a48ff5295e6777018db8c8e63b3f8984229c3887ad20d39487cdf24844abde4a5e1cd7c3197812d39e9d9f5e7",
	        "/usr/lib/kbd/keymaps/xkb/no-smi_nodeadkeys.map.gz"
	);
}
static void svir_873(void) 
{
	svi_reg(&(tinfoil.validation_items[872]),
	        "7f03ebdc3e0b1e023c13a073d0bde76a3a9ad717d763cf2d7930bfefa4d91be970029b10fa53a65d91b23769591687c91018a74c21e2fb15668efb3f5fa8db76",
	        "/usr/lib/kbd/keymaps/xkb/no-smi.map.gz"
	);
}
static void svir_874(void) 
{
	svi_reg(&(tinfoil.validation_items[873]),
	        "5008f7bf3083fe5f87ff30c808ab612c5d4249cc39b91b05cf475cb6c8d42f29f71cae727b83fa9adcbedbf73cac31502bc20f028890f8df45fe1ae48db50913",
	        "/usr/lib/kbd/keymaps/xkb/no-nodeadkeys.map.gz"
	);
}
static void svir_875(void) 
{
	svi_reg(&(tinfoil.validation_items[874]),
	        "e90d5585327ebef6756699efdc75754f8061bcbcacb7e8797f98fc09b67ec1eb6c98a6cf916849ca6f501e1e7de5d3996d02793e0cca48078ec27951b3785382",
	        "/usr/lib/kbd/keymaps/xkb/no-mac_nodeadkeys.map.gz"
	);
}
static void svir_876(void) 
{
	svi_reg(&(tinfoil.validation_items[875]),
	        "c26dd7906ad2a49c5beabf4b216958ff3782022ecc0646e08a1b44aeab72aee6e8ca0d7dc0ecafa312102a5125600abb34be73ecd396a05e4c1df44ec2092645",
	        "/usr/lib/kbd/keymaps/xkb/no-mac.map.gz"
	);
}
static void svir_877(void) 
{
	svi_reg(&(tinfoil.validation_items[876]),
	        "13a2676f4f92f2d719d8ae1d36dfeee5d977b1ffc46f5d548b4d758284354dc125215d57fab8f15693ed06ec1ba7bb4b532685ce993a0cfee46f4413a36054aa",
	        "/usr/lib/kbd/keymaps/xkb/no-dvorak.map.gz"
	);
}
static void svir_878(void) 
{
	svi_reg(&(tinfoil.validation_items[877]),
	        "61bb2d439d9b85868466c9c22e7dc7b6055ff3f49ddfa63602cf618c0ad027013a5f337bf147e6913f7c05d56463c2b06ae42d9aee8237c76b3e69f5f66cb754",
	        "/usr/lib/kbd/keymaps/xkb/no-colemak.map.gz"
	);
}
static void svir_879(void) 
{
	svi_reg(&(tinfoil.validation_items[878]),
	        "cac0b707390e91b7d40cd4e8bd04d65e95b66dc6f7c157412a73070e6444ea99b51aa21e6291ddf7016d2eccc0e236e37447224ace7c1336e2636360403f0784",
	        "/usr/lib/kbd/keymaps/xkb/nl.map.gz"
	);
}
static void svir_880(void) 
{
	svi_reg(&(tinfoil.validation_items[879]),
	        "2beb8af911f35922e157f0686d741fda743278dd57487a71f349db22daa9b41f2a2817950ccc86cbb7828ad5a9ee7e0b280c9af8a6437093887a07d4d128139c",
	        "/usr/lib/kbd/keymaps/xkb/nl-us.map.gz"
	);
}
static void svir_881(void) 
{
	svi_reg(&(tinfoil.validation_items[880]),
	        "fd811e7f7fc161fe94a1de3e03f2ce43300b5e1fe14718345a1200000b05dd43b629c8c900b57ec60b5058d9dcaf0cf02ff72aa8de8d225d2201404d9365959e",
	        "/usr/lib/kbd/keymaps/xkb/nl-std.map.gz"
	);
}
static void svir_882(void) 
{
	svi_reg(&(tinfoil.validation_items[881]),
	        "68317a1c1c5e0166e626bb40f000305747a2a131d1b399299a8a176ac30a4ad735b05c9a768d406c266341644e407c24e5ee39276c28cbb65e979670adb2ffad",
	        "/usr/lib/kbd/keymaps/xkb/nl-mac.map.gz"
	);
}
static void svir_883(void) 
{
	svi_reg(&(tinfoil.validation_items[882]),
	        "8cb0d2d937b5f7f6002b8f51909248a38f2e035139cf7ff65ea0b5a0b9ca5b552fc241153aa5ea84ece669e23b38082fe680e908630004ed1a77ddda9f489023",
	        "/usr/lib/kbd/keymaps/xkb/ng.map.gz"
	);
}
static void svir_884(void) 
{
	svi_reg(&(tinfoil.validation_items[883]),
	        "900876e8749e130e2ce1aad5747706b2ffb5742bc85b35b638980a047da749ced8a4152ae401cd859ae7c7fee3b58d49f69df80eef3f682fa471a14eb4568a49",
	        "/usr/lib/kbd/keymaps/xkb/ng-yoruba.map.gz"
	);
}
static void svir_885(void) 
{
	svi_reg(&(tinfoil.validation_items[884]),
	        "20a51f7c14d73f1f5171e6f2f477e36ef871d106774a0e5ccdf1e80ee8ecbb270936a86a9278a11d40c1e051742814fc5254d33f957750536ee602240825655d",
	        "/usr/lib/kbd/keymaps/xkb/ng-igbo.map.gz"
	);
}
static void svir_886(void) 
{
	svi_reg(&(tinfoil.validation_items[885]),
	        "f0681c6e3131dcbc786f445c10f7ba044a06f9a834826b7c0a75bd2fc8ff3a6f3aa2726563ba794209a1d9409bdfa6006596f365bcdc41e8201a7d2d12742111",
	        "/usr/lib/kbd/keymaps/xkb/ng-hausa.map.gz"
	);
}
static void svir_887(void) 
{
	svi_reg(&(tinfoil.validation_items[886]),
	        "6c6ee759f1b7e19aa486893e3288216178219e1e33b92eebdec861c7e40f4e4e32455b55615ff75a5edc258f7cfc07f13c3a93a3d50c8a39edc5a21f1faac04c",
	        "/usr/lib/kbd/keymaps/xkb/mt.map.gz"
	);
}
static void svir_888(void) 
{
	svi_reg(&(tinfoil.validation_items[887]),
	        "857be6e7c754dd506a1cf058663fa8c1e1083af1f11d8e686f1b6a6edcb1083e3408c132657c2297bbf4a6f4e82010cf1705b1650fb067a22574f446404d6fd8",
	        "/usr/lib/kbd/keymaps/xkb/mt-us.map.gz"
	);
}
static void svir_889(void) 
{
	svi_reg(&(tinfoil.validation_items[888]),
	        "b44b30a6168de9d52d768bcc2467360425d6b19ca6b6ade0c61c7df4d1dddde86b8c6f9b57fc2230fef33119e693b72970e84c49d627dbff228b38bddee56dcf",
	        "/usr/lib/kbd/keymaps/xkb/mt-alt-us.map.gz"
	);
}
static void svir_890(void) 
{
	svi_reg(&(tinfoil.validation_items[889]),
	        "756c32e410b702424a5d445f421287ff62f3ca4e8ec83daefbff0c57bf267fab7fd08fbce2a6cb2c48f6feba0a4e858927da08c4cdfe2d7c8934067165438fb2",
	        "/usr/lib/kbd/keymaps/xkb/mt-alt-gb.map.gz"
	);
}
static void svir_891(void) 
{
	svi_reg(&(tinfoil.validation_items[890]),
	        "67eb074f13998f388ede13e1b8eb058c747d9d9fb4a81d9a5dd9968f4a05ae6a888b0948111f587df5cc91c4cc396a295dbd6ad28d81d2d27da5acd59baeec17",
	        "/usr/lib/kbd/keymaps/xkb/mm.map.gz"
	);
}
static void svir_892(void) 
{
	svi_reg(&(tinfoil.validation_items[891]),
	        "46e8cb5e7ba1f558dccb9fc307deaaccc279b07804703583168ec3f50668379a5b89d266633aef776e0b822b900a8b3c671d3ec8f1b9a18b7eeadf35eeab84bb",
	        "/usr/lib/kbd/keymaps/xkb/ml.map.gz"
	);
}
static void svir_893(void) 
{
	svi_reg(&(tinfoil.validation_items[892]),
	        "7d270d002bfd1ba3d5cc694f38872b44bd8974f65c585b15965cb9a35b56710ff410075c8ceb8ce714e7eaaf669965fcc7e2d5fc3aa7b7788f24e0e01baa788d",
	        "/usr/lib/kbd/keymaps/xkb/ml-us-mac.map.gz"
	);
}
static void svir_894(void) 
{
	svi_reg(&(tinfoil.validation_items[893]),
	        "6a3a338d24cd1ab6d4d30e56c7f586550e8bd70bf9f05bb081c4a6321e51d1ee707eb6da81d558a59f5a5fde64b3e0523ea2060a4850811ba24e01e7b6abb2dd",
	        "/usr/lib/kbd/keymaps/xkb/ml-us-intl.map.gz"
	);
}
static void svir_895(void) 
{
	svi_reg(&(tinfoil.validation_items[894]),
	        "ee2d2d46a76e496b8b435135853349bccbc0db0621a68d1a9a7b520183a78734252f45d822f270aaf390f73d0b65b2aa99c1d869bd4481161e3f9d0f9c1fa58a",
	        "/usr/lib/kbd/keymaps/xkb/ml-fr-oss.map.gz"
	);
}
static void svir_896(void) 
{
	svi_reg(&(tinfoil.validation_items[895]),
	        "3b1f2a56a0640f54f99573247d8c64fef49f06c62eed150219861c89ce6bc07dc6e8134353f02f738128f7e9d04ea53269f2f4b7a13aacf6b0a752b4eed7e0ea",
	        "/usr/lib/kbd/keymaps/xkb/me.map.gz"
	);
}
static void svir_897(void) 
{
	svi_reg(&(tinfoil.validation_items[896]),
	        "1f3a8892c97a086515a81117460728b60f1f60ba854d30620f678cc755c32a59db0bd50830fb667594595d9ab1098ef1fd6a41cfc1b6fe53fa954c26262334c8",
	        "/usr/lib/kbd/keymaps/xkb/me-latinyz.map.gz"
	);
}
static void svir_898(void) 
{
	svi_reg(&(tinfoil.validation_items[897]),
	        "389f08809e0d59a609a0fc6d27b59c7f6875a93990a9ceb9b0d3493fbae92a1348cd24fa39b77feafd3b3ca730aebeeff074952db739b1dd9c9d784e2f0663d3",
	        "/usr/lib/kbd/keymaps/xkb/me-latinunicodeyz.map.gz"
	);
}
static void svir_899(void) 
{
	svi_reg(&(tinfoil.validation_items[898]),
	        "cde1b23c7012a024710fcee2b468a96866187c87316a433c88fa6c78c06303e47f386d4aecc0ab0fa204c212a96138d610e59b7b33c540b834aec3fd0fcbb60f",
	        "/usr/lib/kbd/keymaps/xkb/me-latinunicode.map.gz"
	);
}
static void svir_900(void) 
{
	svi_reg(&(tinfoil.validation_items[899]),
	        "e8639cd1abd3a5f0f0fdab59170ded3c8d66bcae1c7dc838efaa326b32ca6c26d6d3eac3c773ffb9b9e47049cfa26ed4203db4723466ce45546acfe7e3443712",
	        "/usr/lib/kbd/keymaps/xkb/me-latinalternatequotes.map.gz"
	);
}
static void svir_901(void) 
{
	svi_reg(&(tinfoil.validation_items[900]),
	        "3ed327be647db2bc108beb216e2aec421f4903b67ca95b63cc21f8c16820ccdc3b7130809434c24c7a4725d96b341c9d9df3c95aa6ea8cc0de3f77326aaefdda",
	        "/usr/lib/kbd/keymaps/xkb/md.map.gz"
	);
}
static void svir_902(void) 
{
	svi_reg(&(tinfoil.validation_items[901]),
	        "717f0d49d73a6f3d02e50c6ba264d82cec06626078ff24d9ac7e45adc692698ea51fb16157d719a35e754bff2fc102cafdc65b3634acf6c239aac58724fc4f6c",
	        "/usr/lib/kbd/keymaps/xkb/md-gag.map.gz"
	);
}
static void svir_903(void) 
{
	svi_reg(&(tinfoil.validation_items[902]),
	        "1e3e64f2c6a6bb0664b2151bd48f7b967944334293b19447909f63715d5116542593a110e2f48132c80027b6e2c91a4918854694fc72822afb3d12a3c823dcc4",
	        "/usr/lib/kbd/keymaps/xkb/ma-french.map.gz"
	);
}
static void svir_904(void) 
{
	svi_reg(&(tinfoil.validation_items[903]),
	        "375997084e60e07cc66daeed867ab04b1a393c73a8d5bdfbfca6ffa9f70c079b36c2a777f24f3d6c7ed94948108e1ceff2ff61bd3d7daf5ad5403cb496f27db9",
	        "/usr/lib/kbd/keymaps/xkb/lv.map.gz"
	);
}
static void svir_905(void) 
{
	svi_reg(&(tinfoil.validation_items[904]),
	        "87813b7b6a7ac31565583795c9ad04b0b4ac03b2d96b002c8d9a1a17d3a800904105a2a7e9573dd9626dea6f2f7cf8f98c5bbb3dcfc49cb27aacaa72e5a8a860",
	        "/usr/lib/kbd/keymaps/xkb/lv-tilde.map.gz"
	);
}
static void svir_906(void) 
{
	svi_reg(&(tinfoil.validation_items[905]),
	        "257c8cd743eb10dc4f895577c1afbff1c2ca5228b22d961d928d8bc0078d9ec7c5b05f2a6d75e42584da799c1d9fac907c4047ec98ecc397649f45a6b588e4ac",
	        "/usr/lib/kbd/keymaps/xkb/lv-modern.map.gz"
	);
}
static void svir_907(void) 
{
	svi_reg(&(tinfoil.validation_items[906]),
	        "4467eccad2bc643992a8f0313d9bb51c00778df77ce41eb589f6bf4e0bf605e7f986a2818c28c40b945fb46afb5de5702661d550272eb718c5f207fc05095e8e",
	        "/usr/lib/kbd/keymaps/xkb/lv-fkey.map.gz"
	);
}
static void svir_908(void) 
{
	svi_reg(&(tinfoil.validation_items[907]),
	        "c7138c7a523545db912e67e33f2de629890d507c17c12fefcfca26048b583321ab21f72db40befea272ba32904bd29f188e41a3dae93b09bdfffc624a6cf9ef6",
	        "/usr/lib/kbd/keymaps/xkb/lv-ergonomic.map.gz"
	);
}
static void svir_909(void) 
{
	svi_reg(&(tinfoil.validation_items[908]),
	        "c6758af2e33d2d27ba1e35b18103c00b261234b5f268cf0da2313e1cc88cbd7be198161e0b76cff8966460e132fc6235db8863c79540ddb7e2ae424c6886b25c",
	        "/usr/lib/kbd/keymaps/xkb/lv-apostrophe.map.gz"
	);
}
static void svir_910(void) 
{
	svi_reg(&(tinfoil.validation_items[909]),
	        "e44080cfef332f70ae887474462e3015d563b9d94f43b77f2425a9500253db8b2baa5eb88590ccf31b1de75daf36617e8d19f84f4b46fed4a6b28a42bdc219fc",
	        "/usr/lib/kbd/keymaps/xkb/lv-adapted.map.gz"
	);
}
static void svir_911(void) 
{
	svi_reg(&(tinfoil.validation_items[910]),
	        "8d70ea635b2e4ac0ea3f4c8bec7b15212dd651b91fc27b35eced58bbfca5b8e609bb6a16d8e65083962dec174f6ecb986d28b9d2d2d2701ea197340a16cc2936",
	        "/usr/lib/kbd/keymaps/xkb/lt.map.gz"
	);
}
static void svir_912(void) 
{
	svi_reg(&(tinfoil.validation_items[911]),
	        "c6433d16eae78fb3732c434671329d3f468833fc9884948fa795f68758ff66bc6b72cc2a3c6216885b28bc2d7c5c6de24a4dcc9d22cdb71aa47c1d81ff69b9d3",
	        "/usr/lib/kbd/keymaps/xkb/lt-us.map.gz"
	);
}
static void svir_913(void) 
{
	svi_reg(&(tinfoil.validation_items[912]),
	        "9c4b0e0cdd97cad49a67e642afae7d9ef20f93027635a8358e79d459eacd78c6504ed913396f7d5e55aba425ea8b886012e26c4750053e6a63f691a0a34836ca",
	        "/usr/lib/kbd/keymaps/xkb/lt-std.map.gz"
	);
}
static void svir_914(void) 
{
	svi_reg(&(tinfoil.validation_items[913]),
	        "61eb630b1c7e33e4f9cf107746e9715762d7696b39bed70cb4432d5a3c90e5b179e3a3461d30e64b06f3fee09789067ad5db8f79cd321e9147ddd31be548e700",
	        "/usr/lib/kbd/keymaps/xkb/lt-sgs.map.gz"
	);
}
static void svir_915(void) 
{
	svi_reg(&(tinfoil.validation_items[914]),
	        "189998bfe85c50d6b15199e3535d4ae49a61d79a224a82e8a57d58b73c25389279b993561a609dd263c370f07d9082be119184d6ab55d758e8b696085a822c95",
	        "/usr/lib/kbd/keymaps/xkb/lt-ratise.map.gz"
	);
}
static void svir_916(void) 
{
	svi_reg(&(tinfoil.validation_items[915]),
	        "80c512fb4094615fbe03988a3807eaba476ac0a7c109cf8af5499befc3d0e097fe4b3f1a0ff80accb124dc32a94afc54d955e99fa2b33c55c497cb7a07145d8f",
	        "/usr/lib/kbd/keymaps/xkb/lt-lekpa.map.gz"
	);
}
static void svir_917(void) 
{
	svi_reg(&(tinfoil.validation_items[916]),
	        "b480a9b9349a5383ae37a2c1dc9edc5e1a61c46565c52576208b9967e1c39a455cf76b9036c91c25a7e0a352e97cab06d67e3620778a3180cc10e576e89b1c29",
	        "/usr/lib/kbd/keymaps/xkb/lt-lekp.map.gz"
	);
}
static void svir_918(void) 
{
	svi_reg(&(tinfoil.validation_items[917]),
	        "431abb1381873a850a9bd4ae69165cc9a3d5f55946a14966d122f15fd74889ab8bf80f12a9df59e4aea784064d6c60065e2f1aafbad6f6140b55ec4cf35c49f6",
	        "/usr/lib/kbd/keymaps/xkb/lt-ibm.map.gz"
	);
}
static void svir_919(void) 
{
	svi_reg(&(tinfoil.validation_items[918]),
	        "f6774f76adee7092aca538743d8aeb83e4a4c1021d5a2c231950e3ae5775495109d9e6289d899a8fcb05a0990130c00177205844597ade0e11a1a16e6457b827",
	        "/usr/lib/kbd/keymaps/xkb/lk-us.map.gz"
	);
}
static void svir_920(void) 
{
	svi_reg(&(tinfoil.validation_items[919]),
	        "f6a5b64c81a54e9e3d322c6ae0bc9359e872102096131a0dcf708d1b156664dd454a2fc87b758ae2cf26a23d5387cb0eb1857ba31491b89c336a98c14c2e4a89",
	        "/usr/lib/kbd/keymaps/xkb/latam.map.gz"
	);
}
static void svir_921(void) 
{
	svi_reg(&(tinfoil.validation_items[920]),
	        "5594d78eecc4c8b98599b7a1bf7fa675db6cad97f22d845293dccdb896a5e692f612908810c16fd4faa19314373827d8a44def397f99e4f1a24ca1aa56075208",
	        "/usr/lib/kbd/keymaps/xkb/latam-nodeadkeys.map.gz"
	);
}
static void svir_922(void) 
{
	svi_reg(&(tinfoil.validation_items[921]),
	        "e8657a0c3b0f825366809965b9651d86789fc9a633cc73a8aa6bbab1b7a55e022f834c963da0071c89ae9b69bd9fca5feadd0da8cea9719ced2aac01ec40fa1e",
	        "/usr/lib/kbd/keymaps/xkb/latam-dvorak.map.gz"
	);
}
static void svir_923(void) 
{
	svi_reg(&(tinfoil.validation_items[922]),
	        "167f0e40502b1288c240c0502b96909ce1be12f53858a2ed32d5796215082d054f0f2ad4fb9129c06b3662844f3a4ad2fdf335d634f28afcd6408a99e7037e08",
	        "/usr/lib/kbd/keymaps/xkb/latam-deadtilde.map.gz"
	);
}
static void svir_924(void) 
{
	svi_reg(&(tinfoil.validation_items[923]),
	        "c807abff25fdfc837729fddd9be36f097337a2ca19810cc3a34a45a1465509464b6dad9d77dfcd7f7696e56bb9a45166c191d277d8a77dc1264ae39c0f246dd2",
	        "/usr/lib/kbd/keymaps/xkb/latam-colemak.map.gz"
	);
}
static void svir_925(void) 
{
	svi_reg(&(tinfoil.validation_items[924]),
	        "76153ec3bbbb2e92e1a0f7f477b909cb1a33202a3c19d02e13c56a6515377449924d58441db409732c9d7005ee3da1416a960c25b2363279e357c727a4c54ff0",
	        "/usr/lib/kbd/keymaps/xkb/latam-colemak-gaming.map.gz"
	);
}
static void svir_926(void) 
{
	svi_reg(&(tinfoil.validation_items[925]),
	        "cd8dadda5b52b0a28527f0247cc160f0557519313a1aac1a605f0d3b6f50bb92d8a3c63a8c3fd7115a40b8384ef0f67aac39c29a8e6af3cbd05cbbca11a7b9b8",
	        "/usr/lib/kbd/keymaps/xkb/kz-latin.map.gz"
	);
}
static void svir_927(void) 
{
	svi_reg(&(tinfoil.validation_items[926]),
	        "74c60b34b1d444c3d4e2cb2db157f264a15095bd5c4e5d78975937d3288a8fbeacddce97f3b90411d2e40f170bc54f394721c365fa8084a83ce4aa597e650ffe",
	        "/usr/lib/kbd/keymaps/xkb/kr.map.gz"
	);
}
static void svir_928(void) 
{
	svi_reg(&(tinfoil.validation_items[927]),
	        "fcb58db0c79b05bc9d7cc15db8ce5dd630166d5f4a1b93c0f128d0f1bca1f749d91de1fbad3eaa8a678e6894fa3b02feea89ede6a7ab760ca00caf5b334ae6ca",
	        "/usr/lib/kbd/keymaps/xkb/kr-kr104.map.gz"
	);
}
static void svir_929(void) 
{
	svi_reg(&(tinfoil.validation_items[928]),
	        "8c6f917374fa6d513ec15294edf0e658c285f25aef785b0d13d9dc1ed993af8c8a71381aaf4f2c1dba6f584c5fc5ae5d8f8f29523443348f88ff5da11e1c9f25",
	        "/usr/lib/kbd/keymaps/xkb/ke.map.gz"
	);
}
static void svir_930(void) 
{
	svi_reg(&(tinfoil.validation_items[929]),
	        "e7948d945826305030f5758916300a6524118939d15122e0c0ee834b3b7f0a504265a2b59cedc3246d72b935d4411deff458e8ef70acea4e1f97d3f07684995c",
	        "/usr/lib/kbd/keymaps/xkb/ke-kik.map.gz"
	);
}
static void svir_931(void) 
{
	svi_reg(&(tinfoil.validation_items[930]),
	        "6d3ca082fbf39d1e49441dcd1a577b986e25e4f4d8bda7a002cfc19aa712b311aa82fe426c925b6714cb07d4bfcd765950fb1cfc3afc7b0dcf730f8f48370f95",
	        "/usr/lib/kbd/keymaps/xkb/jp.map.gz"
	);
}
static void svir_932(void) 
{
	svi_reg(&(tinfoil.validation_items[931]),
	        "2422981d07f6e839b3c6153ba9558623ce3391ec740b791dcca4b3e65c1bb30b5220dbb3301ef1ec83c6148d029222868240f2fb13f136dd4f6a5f590915e3ed",
	        "/usr/lib/kbd/keymaps/xkb/jp-kana86.map.gz"
	);
}
static void svir_933(void) 
{
	svi_reg(&(tinfoil.validation_items[932]),
	        "650b5569f13937a5c3123821d41e100d48b19ec04678c078c8011bc1c1c4a6e3f2545654131d83d2cb65c0b41f60e7347a8d0a8d00b08f3c142a303b77457659",
	        "/usr/lib/kbd/keymaps/xkb/jp-dvorak.map.gz"
	);
}
static void svir_934(void) 
{
	svi_reg(&(tinfoil.validation_items[933]),
	        "adb8ce6cfee1b93d0b32992dc6414b5aa68d9712867b6f9255ad4fefb7393a1513696f3f9d39c3d768eb722cd34d4f4a6f4675cb91e8f7f242018a20a7ba44e8",
	        "/usr/lib/kbd/keymaps/xkb/jp-OADG109A.map.gz"
	);
}
static void svir_935(void) 
{
	svi_reg(&(tinfoil.validation_items[934]),
	        "50a45cc613cfbe71c53b4a3f8072869a70f5b3ad72ccbf4a5c9afc2c3d56cc9f3f25b663b9a56b7306856da94ef5cff132a1f46e9d35dea201fe8733c3f01ab3",
	        "/usr/lib/kbd/keymaps/xkb/it.map.gz"
	);
}
static void svir_936(void) 
{
	svi_reg(&(tinfoil.validation_items[935]),
	        "bb50389ee81c1c0eebba719d0208d15d999a85a72533de1f30736b76384fc8d0bd1a2a6938781922a56c11f70baf1bd0fc0009a4ad72d8665c2b178cff448e0b",
	        "/usr/lib/kbd/keymaps/xkb/it-winkeys.map.gz"
	);
}
static void svir_937(void) 
{
	svi_reg(&(tinfoil.validation_items[936]),
	        "e6099514d5ec993ebf0c1dc575dffb66fc53c0eb8a3cb65ec9c6d7a0167af24fecf7cd136e1e449605532da8288b2f59240e2228c22edd1695cb4293ee55ce48",
	        "/usr/lib/kbd/keymaps/xkb/it-us.map.gz"
	);
}
static void svir_938(void) 
{
	svi_reg(&(tinfoil.validation_items[937]),
	        "9a8e5fb0d307e646c9a1312cc730bb77381ca1c3837690f3834eb25f1758fa938f86f021288e30a776f1d3866f0005fa5a36d381c27a99c98a0a86bb8693b6c9",
	        "/usr/lib/kbd/keymaps/xkb/it-scn.map.gz"
	);
}
static void svir_939(void) 
{
	svi_reg(&(tinfoil.validation_items[938]),
	        "e44e66208c89379621aea03e8331b34ffabffad0e8cb5239b43cadf390bccb588fc17cdcfcf0b02983ab199fab2716d74978d261731a86e0bfaae45b0c516a0d",
	        "/usr/lib/kbd/keymaps/xkb/it-nodeadkeys.map.gz"
	);
}
static void svir_940(void) 
{
	svi_reg(&(tinfoil.validation_items[939]),
	        "77aed32c6899d36ffecd2ea9e997b404efe640cceb6f6d48f5d35b67c17f13298650da218dd3063613f399f18f7189fb869524121d7d38d2689eb45a255729dd",
	        "/usr/lib/kbd/keymaps/xkb/it-mac.map.gz"
	);
}
static void svir_941(void) 
{
	svi_reg(&(tinfoil.validation_items[940]),
	        "f647ff9c9ddefe78c61096ad788b82be209a5d2cfeed50fb5847b1525958844ba2427dda7106ba6df1df239459deef4b52b71e33252982b5662eeb7328ac70c9",
	        "/usr/lib/kbd/keymaps/xkb/it-intl.map.gz"
	);
}
static void svir_942(void) 
{
	svi_reg(&(tinfoil.validation_items[941]),
	        "d00179a650f431977b17ce2488757de3714bd1d449ef7b88cb505311287f7162a1dc469c0221d23a321e8926ddf9760eace94329ba8bb57db9583f25856cba95",
	        "/usr/lib/kbd/keymaps/xkb/it-ibm.map.gz"
	);
}
static void svir_943(void) 
{
	svi_reg(&(tinfoil.validation_items[942]),
	        "34e7bce1d0ba1d798a55a39ab48950cbeb7e2f69c088fd3e78a18d0a84f055f59a1cb473faedf77c21920029bf8ae8a1c4860f31fc064e46b945090153975905",
	        "/usr/lib/kbd/keymaps/xkb/it-geo.map.gz"
	);
}
static void svir_944(void) 
{
	svi_reg(&(tinfoil.validation_items[943]),
	        "4e179f751ba09ff13e92ba64dc5802620d10bf79287b2c41d21962b810b5b72a7ee079f888c7b7584aba66d973032f7e9bf383d3c761ab65c56baf925d4e9e2d",
	        "/usr/lib/kbd/keymaps/xkb/it-fur.map.gz"
	);
}
static void svir_945(void) 
{
	svi_reg(&(tinfoil.validation_items[944]),
	        "7239169385fd1534b6508148dc3e8c6d319f5b57f378b8f7276bb6d27644dc435baa83f71a4a6c9d678f22fa5a289fdc518750fc055be18646f7755f879fb06e",
	        "/usr/lib/kbd/keymaps/xkb/is.map.gz"
	);
}
static void svir_946(void) 
{
	svi_reg(&(tinfoil.validation_items[945]),
	        "4a225b10b5064d361a250f2cde145a0a061c0237ac3a48a658f21f86819b86ccf1d2213575e4c8890e8bb2c5123d60948d752ea3d4c681a659af0d4005cb7039",
	        "/usr/lib/kbd/keymaps/xkb/is-mac_legacy.map.gz"
	);
}
static void svir_947(void) 
{
	svi_reg(&(tinfoil.validation_items[946]),
	        "47133e67c8656cd04109b270a6af3aa84a8dd961e3b66f59ea6751ae5d81a34a9e6d3b3f4619a19857abc200fdb24caee15bea6d3212b7b2512ef48124ed1856",
	        "/usr/lib/kbd/keymaps/xkb/is-mac.map.gz"
	);
}
static void svir_948(void) 
{
	svi_reg(&(tinfoil.validation_items[947]),
	        "1c87e854d5bdc5032142f75cf4cfbeb5fa316a20a4cae0f272382ffdcb4d7856ffffee516d2dc314e60a1919ccbd02ae74bffe55a54043998c10fb9e60afb8a8",
	        "/usr/lib/kbd/keymaps/xkb/is-dvorak.map.gz"
	);
}
static void svir_949(void) 
{
	svi_reg(&(tinfoil.validation_items[948]),
	        "be181abd70acd765049fadae777941290e1c3270e173010260d107714bcdf250dd6657d246c3c6d97786fde864cfd856b99c1df3c765d182b4da13d2e3482363",
	        "/usr/lib/kbd/keymaps/xkb/ir-ku_f.map.gz"
	);
}
static void svir_950(void) 
{
	svi_reg(&(tinfoil.validation_items[949]),
	        "0a1219f0317687f6ea3bcc23e90752f02c00bf2875987dae9b666deff07f898e600cb239350fd1297e4171270ab50f38af1cdcb368f367a863163e2d3a1885ad",
	        "/usr/lib/kbd/keymaps/xkb/ir-ku_ara.map.gz"
	);
}
static void svir_951(void) 
{
	svi_reg(&(tinfoil.validation_items[950]),
	        "5ba65cbf383933d3b3a09d232eb253d630f8fb5c3d27041d98d1ac035c9eeef0bcf3bbe821a0fff330288f7405f92c74cc294047733421b47575f25519733e5b",
	        "/usr/lib/kbd/keymaps/xkb/ir-ku_alt.map.gz"
	);
}
static void svir_952(void) 
{
	svi_reg(&(tinfoil.validation_items[951]),
	        "49a9083d4e9f766b27cc41fe8f3ef4b9542ee3339f02d835b283e7aaaf88e63bf3482a1f24fe6dea3fc626c272b5d82d1ee123cd42ce9d5ef773eaf59cf4ebd3",
	        "/usr/lib/kbd/keymaps/xkb/ir-ku.map.gz"
	);
}
static void svir_953(void) 
{
	svi_reg(&(tinfoil.validation_items[952]),
	        "be181abd70acd765049fadae777941290e1c3270e173010260d107714bcdf250dd6657d246c3c6d97786fde864cfd856b99c1df3c765d182b4da13d2e3482363",
	        "/usr/lib/kbd/keymaps/xkb/iq-ku_f.map.gz"
	);
}
static void svir_954(void) 
{
	svi_reg(&(tinfoil.validation_items[953]),
	        "0a1219f0317687f6ea3bcc23e90752f02c00bf2875987dae9b666deff07f898e600cb239350fd1297e4171270ab50f38af1cdcb368f367a863163e2d3a1885ad",
	        "/usr/lib/kbd/keymaps/xkb/iq-ku_ara.map.gz"
	);
}
static void svir_955(void) 
{
	svi_reg(&(tinfoil.validation_items[954]),
	        "5ba65cbf383933d3b3a09d232eb253d630f8fb5c3d27041d98d1ac035c9eeef0bcf3bbe821a0fff330288f7405f92c74cc294047733421b47575f25519733e5b",
	        "/usr/lib/kbd/keymaps/xkb/iq-ku_alt.map.gz"
	);
}
static void svir_956(void) 
{
	svi_reg(&(tinfoil.validation_items[955]),
	        "49a9083d4e9f766b27cc41fe8f3ef4b9542ee3339f02d835b283e7aaaf88e63bf3482a1f24fe6dea3fc626c272b5d82d1ee123cd42ce9d5ef773eaf59cf4ebd3",
	        "/usr/lib/kbd/keymaps/xkb/iq-ku.map.gz"
	);
}
static void svir_957(void) 
{
	svi_reg(&(tinfoil.validation_items[956]),
	        "13db9c9b64c106eb2b7334ea8672b7bb6e482c0fff41cbf7606eeb193af5924b7715450bf5f4ffb361d3abfe5ff9bf259ff8463e8c9f99534834b55c9b2de92e",
	        "/usr/lib/kbd/keymaps/xkb/in-iipa.map.gz"
	);
}
static void svir_958(void) 
{
	svi_reg(&(tinfoil.validation_items[957]),
	        "d6ee60c9b7b6fede0e9fad0ae6a9481d735e011027eb0b4f8ce80326015be088943a61da45b0b8195b1436383ddc586a7b23abe6d7e065ca555e3f064c45744d",
	        "/usr/lib/kbd/keymaps/xkb/in-eng.map.gz"
	);
}
static void svir_959(void) 
{
	svi_reg(&(tinfoil.validation_items[958]),
	        "652abdd44d4da3c54e4ce4d43fc022601eef51ba2531e3e4ff5f9adbc616724fb0394647b429e51a226bf5a4dc6131a1bc0426dd6ad6c43c3a73c71f17bae5e3",
	        "/usr/lib/kbd/keymaps/xkb/il.map.gz"
	);
}
static void svir_960(void) 
{
	svi_reg(&(tinfoil.validation_items[959]),
	        "19bf62d88ff2fb5e1c095305a3afabed8b5576dd3283136664858158438eeef47335e65304eaf756a1cfede832b71989e78157fc20d12ec6eca77c7bb32e29b3",
	        "/usr/lib/kbd/keymaps/xkb/ie.map.gz"
	);
}
static void svir_961(void) 
{
	svi_reg(&(tinfoil.validation_items[960]),
	        "cc25055afc81bcac5c74533dcab17343e3a3866f9b8d4df8697f17999112252c2ce82559b12b99e3caca86a95b46527ac6b9e865b7d2968edec54198fc293154",
	        "/usr/lib/kbd/keymaps/xkb/ie-ogam_is434.map.gz"
	);
}
static void svir_962(void) 
{
	svi_reg(&(tinfoil.validation_items[961]),
	        "79088cdd6178878e69289fadbbf551e54b52758e420242d0a9c8b156fe65c27ceb0b78459d3de9ae56cc6ff25a0a07cb411a25d4ba2f79dc44141c007eb63e72",
	        "/usr/lib/kbd/keymaps/xkb/ie-UnicodeExpert.map.gz"
	);
}
static void svir_963(void) 
{
	svi_reg(&(tinfoil.validation_items[962]),
	        "b937c1b1f9dc1cad182f2b16662f2cfb3ebfef58f3d9bbabe1f75becef41ae30a6e44fafb09dad4c1f8714e2ad8bd4a79613a0523906b266dcb2cb68daaff2c9",
	        "/usr/lib/kbd/keymaps/xkb/ie-CloGaelach.map.gz"
	);
}
static void svir_964(void) 
{
	svi_reg(&(tinfoil.validation_items[963]),
	        "74c60b34b1d444c3d4e2cb2db157f264a15095bd5c4e5d78975937d3288a8fbeacddce97f3b90411d2e40f170bc54f394721c365fa8084a83ce4aa597e650ffe",
	        "/usr/lib/kbd/keymaps/xkb/id.map.gz"
	);
}
static void svir_965(void) 
{
	svi_reg(&(tinfoil.validation_items[964]),
	        "f83563f1af0d6938f0018eead635911b157a032572a924c6a5d1dfe8450632c9e05db4da9b4b935f925b025ddd5e9ff271ef8484e20652a73bbdca6db5490f3a",
	        "/usr/lib/kbd/keymaps/xkb/hu.map.gz"
	);
}
static void svir_966(void) 
{
	svi_reg(&(tinfoil.validation_items[965]),
	        "f83563f1af0d6938f0018eead635911b157a032572a924c6a5d1dfe8450632c9e05db4da9b4b935f925b025ddd5e9ff271ef8484e20652a73bbdca6db5490f3a",
	        "/usr/lib/kbd/keymaps/xkb/hu-standard.map.gz"
	);
}
static void svir_967(void) 
{
	svi_reg(&(tinfoil.validation_items[966]),
	        "4cab53bd3af965d4bba204c430f3a09bf9e32c9c30e88b708d4264d230d56af45361c7a3564644dd52a1559319d5285d26474a032948ba51c7154a4d4369267a",
	        "/usr/lib/kbd/keymaps/xkb/hu-qwerty.map.gz"
	);
}
static void svir_968(void) 
{
	svi_reg(&(tinfoil.validation_items[967]),
	        "70e3dc842280b7765e913c156127cf520c36dcab8c0132befa4dbca7f8639d3cfec064d9465db449f42105e08821b8cef118b6cfd0ab4b0598315e7c1fe7cd27",
	        "/usr/lib/kbd/keymaps/xkb/hu-nodeadkeys.map.gz"
	);
}
static void svir_969(void) 
{
	svi_reg(&(tinfoil.validation_items[968]),
	        "6a873d9511d7a29e4e92323de82eb31231a3d3cc6d338d1bc7333620528450430f591d8938aa73c056e27dd8840cb4b0b75b102c2a8daabc78aa7fc56a5bdf97",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwertz_dot_nodead.map.gz"
	);
}
static void svir_970(void) 
{
	svi_reg(&(tinfoil.validation_items[969]),
	        "19e8fe9d1cf6c4af3d0ac08fbdbc4d4c25984726b2e718ea061cadac0964e8682baefc408ff761d3a71e4d7397fb6940e0be4334a6d7c3f37687420b0172b25e",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwertz_dot_dead.map.gz"
	);
}
static void svir_971(void) 
{
	svi_reg(&(tinfoil.validation_items[970]),
	        "70e3dc842280b7765e913c156127cf520c36dcab8c0132befa4dbca7f8639d3cfec064d9465db449f42105e08821b8cef118b6cfd0ab4b0598315e7c1fe7cd27",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwertz_comma_nodead.map.gz"
	);
}
static void svir_972(void) 
{
	svi_reg(&(tinfoil.validation_items[971]),
	        "f83563f1af0d6938f0018eead635911b157a032572a924c6a5d1dfe8450632c9e05db4da9b4b935f925b025ddd5e9ff271ef8484e20652a73bbdca6db5490f3a",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwertz_comma_dead.map.gz"
	);
}
static void svir_973(void) 
{
	svi_reg(&(tinfoil.validation_items[972]),
	        "a87049c2660fbb78eb56c2b9bae958a19bda79adc733ffbc7bb6a1f437efc8be0f2918ce4e38c02376593eb8cd036c56aab9ac100d669ecbe2f2804dd0d38dbf",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwerty_dot_nodead.map.gz"
	);
}
static void svir_974(void) 
{
	svi_reg(&(tinfoil.validation_items[973]),
	        "94749c860ebdd273a9b36cf489a4c7d49ec343a8bfe66fb40ea73958eeddcfbb37dbf765a171ffb552642fd973a7ac2fd008b0d0b2c22a7415efaeb470bf86f0",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwerty_dot_dead.map.gz"
	);
}
static void svir_975(void) 
{
	svi_reg(&(tinfoil.validation_items[974]),
	        "88664816a18b8d6260e2bdee701f7af1c321ddf7ed807da0c2d8697b4d4d8e21134ee940905ac74fdda532db67615af805d5ee11c9c178cebd80b32790b123f8",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwerty_comma_nodead.map.gz"
	);
}
static void svir_976(void) 
{
	svi_reg(&(tinfoil.validation_items[975]),
	        "85de8890da952f281d413b2313bdff11e72f9a683043cb24bbc5f511e0977b093a13b38924fb2fc059230c5068c629edb69567c4cb154f84a3141cedce2b1ae2",
	        "/usr/lib/kbd/keymaps/xkb/hu-102_qwerty_comma_dead.map.gz"
	);
}
static void svir_977(void) 
{
	svi_reg(&(tinfoil.validation_items[976]),
	        "44faebff6e89e079c3737a90e03c7ed2ccd9691b0e220c0396e50e1be233fea1e0292f13623e5c47b4798246673dbc8ec05d165f8f7fb59e3890545f45cec56e",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwertz_dot_nodead.map.gz"
	);
}
static void svir_978(void) 
{
	svi_reg(&(tinfoil.validation_items[977]),
	        "0617d6760ac725745eb310225b9103f8972858ea08e2a5f6f59d4dc0ed39fca519d815924e020717d586c37d23828673ec825614398465ba3e76c0cdf415f7aa",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwertz_dot_dead.map.gz"
	);
}
static void svir_979(void) 
{
	svi_reg(&(tinfoil.validation_items[978]),
	        "c88bb3f3d0b329d3908ce19db76f53efa2bc166c01610b4b94b370bd934ee47789db6dc53941aba7115e2afeeb7f3b6bad234ef61ca1d16a9f3e169f6a4a3307",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwertz_comma_nodead.map.gz"
	);
}
static void svir_980(void) 
{
	svi_reg(&(tinfoil.validation_items[979]),
	        "a17f8885b16d453ea0501a3b806a734ca0af9671896db81968aeeadc4d836cf38a3c6fdb4655bf56fd3c0edde85ee175764b4b4e656ae74beed4d926533db2b2",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwertz_comma_dead.map.gz"
	);
}
static void svir_981(void) 
{
	svi_reg(&(tinfoil.validation_items[980]),
	        "76631a127c93a26baaf3f81ecfbcb42b3355e16403d1a919f60db4685c401b02052afbe427461bd60009e83f4df86840f34e5608345ec2993c48b611c386e3f6",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwerty_dot_nodead.map.gz"
	);
}
static void svir_982(void) 
{
	svi_reg(&(tinfoil.validation_items[981]),
	        "fe4f4c2b3db1d454b9ac64f5697305a369015f4caf682926d43aafa3966e055183e9e3e799f6ce8c1b020ff1d47722df6519ecf81e0f88b752e9a562df842e10",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwerty_dot_dead.map.gz"
	);
}
static void svir_983(void) 
{
	svi_reg(&(tinfoil.validation_items[982]),
	        "06122b7673fe074adb69efa798ad24e74ca89f58a41498e4966e6c09623317b24717d2eb047176ae9a1ef228397173cdc0ac06c0cc0344bc6e5856cae1ca09df",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwerty_comma_nodead.map.gz"
	);
}
static void svir_984(void) 
{
	svi_reg(&(tinfoil.validation_items[983]),
	        "4cab53bd3af965d4bba204c430f3a09bf9e32c9c30e88b708d4264d230d56af45361c7a3564644dd52a1559319d5285d26474a032948ba51c7154a4d4369267a",
	        "/usr/lib/kbd/keymaps/xkb/hu-101_qwerty_comma_dead.map.gz"
	);
}
static void svir_985(void) 
{
	svi_reg(&(tinfoil.validation_items[984]),
	        "a51863989bae597aeb5c0785590a2116994b277b993a27002e828cd8ab75727851697e2649eece3ab14383c3c5edd03fc74e219848bbf4b3ab293aeeca6dd5cc",
	        "/usr/lib/kbd/keymaps/xkb/hr.map.gz"
	);
}
static void svir_986(void) 
{
	svi_reg(&(tinfoil.validation_items[985]),
	        "38b0ca0d030bd1127a9faa9beb6f4e90593f90dff4addb3d82d3f9bea9963ac90dc83456ac3d79934276eecab67dea26206c9111ea32480e1458b8959b5b020c",
	        "/usr/lib/kbd/keymaps/xkb/hr-us.map.gz"
	);
}
static void svir_987(void) 
{
	svi_reg(&(tinfoil.validation_items[986]),
	        "e13b30abf4a0fc45182dfe4cd81e66b9a5aacc2a2077159a7d82db5429ed9793e0fe744d1817119b9cbf9fd8fb6c3a5108c0b3742cb0c896238b4f936fdaeb6c",
	        "/usr/lib/kbd/keymaps/xkb/hr-unicodeus.map.gz"
	);
}
static void svir_988(void) 
{
	svi_reg(&(tinfoil.validation_items[987]),
	        "9200e2cd009ad485e40af427ea8185c5ca58968323d5fd15fd6988492beab98dafd573df1a182bb09b79689456908d3bc5d3ee342f6c2ecf7548065d905ba882",
	        "/usr/lib/kbd/keymaps/xkb/hr-unicode.map.gz"
	);
}
static void svir_989(void) 
{
	svi_reg(&(tinfoil.validation_items[988]),
	        "61d4879ebaba728daa37dcf9378e1da79b33dc5401e03eebb9715209657788bb0053003a88efb123022068558c191696ad8c7e4e0becb30241467356cadb03ef",
	        "/usr/lib/kbd/keymaps/xkb/hr-alternatequotes.map.gz"
	);
}
static void svir_990(void) 
{
	svi_reg(&(tinfoil.validation_items[989]),
	        "e71d049640c0eec7700dedc3da643445c2d2212c21701fa3bf7c70a072ec9afe9de4d435e449460438909d2d3536d182d8eba05d095644c8c2b4053ce8ef701c",
	        "/usr/lib/kbd/keymaps/xkb/gh.map.gz"
	);
}
static void svir_991(void) 
{
	svi_reg(&(tinfoil.validation_items[990]),
	        "f0ed917767164205b1120325f7bc67080154b524048142ee79b6879d6bc670bafef3b9a663acff4f3dcdd729239e4cf01add374ac295263aba3d84c5b781cf55",
	        "/usr/lib/kbd/keymaps/xkb/gh-hausa.map.gz"
	);
}
static void svir_992(void) 
{
	svi_reg(&(tinfoil.validation_items[991]),
	        "96f84545333aece20fac7f1bf776b3d70cf3eada82b3d7418c49bdc767608f32ddcc64be3d73a5a5a04a0aa701b0518aacacfa69ec54df59feac083486a71391",
	        "/usr/lib/kbd/keymaps/xkb/gh-gillbt.map.gz"
	);
}
static void svir_993(void) 
{
	svi_reg(&(tinfoil.validation_items[992]),
	        "d8d2e3c2ee3fb57aaa80286bd2f9bc1c7d5688e8e4184e95d0b79eac5afe77d923f5510b4d138c8e99c153f89668e0f88b0216a8746cad97613ceb84db2dcc15",
	        "/usr/lib/kbd/keymaps/xkb/gh-generic.map.gz"
	);
}
static void svir_994(void) 
{
	svi_reg(&(tinfoil.validation_items[993]),
	        "0b3cc9726d78178aee4aa71f070f6a5f240484f22cc12f99f854984d396f145412abefa98fb6c9d173d34e41ba369372a5c56f126dd5aaa105550db8375d76a8",
	        "/usr/lib/kbd/keymaps/xkb/gh-ga.map.gz"
	);
}
static void svir_995(void) 
{
	svi_reg(&(tinfoil.validation_items[994]),
	        "f0ed917767164205b1120325f7bc67080154b524048142ee79b6879d6bc670bafef3b9a663acff4f3dcdd729239e4cf01add374ac295263aba3d84c5b781cf55",
	        "/usr/lib/kbd/keymaps/xkb/gh-fula.map.gz"
	);
}
static void svir_996(void) 
{
	svi_reg(&(tinfoil.validation_items[995]),
	        "caedaf6237a04784e3581644090e4263b9faa76e39ae04cb9e4a56a96178bedeb41abc45a32c9b96d440a6dccde773127d95408d6a596d7d87a0c03bc7f554d2",
	        "/usr/lib/kbd/keymaps/xkb/gh-ewe.map.gz"
	);
}
static void svir_997(void) 
{
	svi_reg(&(tinfoil.validation_items[996]),
	        "b5d1b0a6ec5b21e39ac408716cf77fb1dd0a4336b1aea4eff8d0f56d1c079ee73c773c4bc9af0c5d0d79a6c26160d5dd60b19d894b9b310c5d3bd617b98613cc",
	        "/usr/lib/kbd/keymaps/xkb/gh-avn.map.gz"
	);
}
static void svir_998(void) 
{
	svi_reg(&(tinfoil.validation_items[997]),
	        "3b21c45b2b14bf1ef5bbc8c39dcd066efdab3d1395f22e3aa5cf139e22e32c4b45433e20bb51b3883e59d926c5dfe07da1d0b3440f40c28cac062baf30ed5383",
	        "/usr/lib/kbd/keymaps/xkb/gh-akan.map.gz"
	);
}
static void svir_999(void) 
{
	svi_reg(&(tinfoil.validation_items[998]),
	        "b9bde06c7e8a3c4c1d3830679b07d57b1ee4fd7bdff145ee120fa72ea5f3fdce2e367d0a56d89affbe02fdb720c08672dea8882d19485eb493e450ca69bbcb07",
	        "/usr/lib/kbd/keymaps/xkb/ge.map.gz"
	);
}
static void svir_1000(void) 
{
	svi_reg(&(tinfoil.validation_items[999]),
	        "33ed7ad79d2f8ab45be18703ae0aec612a1fc6fa46530bb8a92b34a2e816801463e88330e4ed7ef06912f05f5a63e65bdcdc00d26acc92d5e97e561f315d807c",
	        "/usr/lib/kbd/keymaps/xkb/ge-ru.map.gz"
	);
}
static void svir_1001(void) 
{
	svi_reg(&(tinfoil.validation_items[1000]),
	        "5f8754c1e89c391312d0cbfef401e502539ffd2d8408c110ae4f7ae1114ca05bc6dd0c654f6524b7a480f50ecb629d62cdc67ce92fdb17de03f13406bfce5984",
	        "/usr/lib/kbd/keymaps/xkb/ge-mess.map.gz"
	);
}
static void svir_1002(void) 
{
	svi_reg(&(tinfoil.validation_items[1001]),
	        "053772b26d99d2dc191dd34048fa26f3ba60c8729232376a8be12973881fa53fac5bfbb026ea757e5bdf0383852669a3093cf9db6bc6cdc1fcdb7283235144a4",
	        "/usr/lib/kbd/keymaps/xkb/ge-ergonomic.map.gz"
	);
}
static void svir_1003(void) 
{
	svi_reg(&(tinfoil.validation_items[1002]),
	        "3873ed26a9c5354f1b821d64e771bdbe8ccff05a4f89ef24f071ce718111564f7026ce00ab93dcb46f6c8cef43c882fe3c5368cc2acdc10330db6aa8ec53d42a",
	        "/usr/lib/kbd/keymaps/xkb/gb.map.gz"
	);
}
static void svir_1004(void) 
{
	svi_reg(&(tinfoil.validation_items[1003]),
	        "6f71bd3ccea652dc994f03bd51f46135b0894911385e541f12a02ba9d801bbb7a9263d9a3c47a09ac686e0911f6e054edd0c91441f9b9991aca8d291aff448cc",
	        "/usr/lib/kbd/keymaps/xkb/gb-pl.map.gz"
	);
}
static void svir_1005(void) 
{
	svi_reg(&(tinfoil.validation_items[1004]),
	        "379ca6d8defb002356724292788238c066ae6e52aa0f181afdb8431a49fb46311e3ee48e66020a406c2ff2f2fc71b1036c1048a02e82f0ee7101ec3428b387d8",
	        "/usr/lib/kbd/keymaps/xkb/gb-mac_intl.map.gz"
	);
}
static void svir_1006(void) 
{
	svi_reg(&(tinfoil.validation_items[1005]),
	        "af77302beb7cb6933d02a39201720b75438d57bf3ad7c4f92fe6dd6491f3a7713f5ef3ea9dc72d35b70833c67fc7a2f38116d7685935866c85ea3f764d10ccbb",
	        "/usr/lib/kbd/keymaps/xkb/gb-mac.map.gz"
	);
}
static void svir_1007(void) 
{
	svi_reg(&(tinfoil.validation_items[1006]),
	        "f231f10972d9e0914853485da5364df5b3705a4034de0334593abdbb6bbcb7a2bb8033a61d03089e75260111ae39baa7f368160c6b28d4e3aab2144696510842",
	        "/usr/lib/kbd/keymaps/xkb/gb-intl.map.gz"
	);
}
static void svir_1008(void) 
{
	svi_reg(&(tinfoil.validation_items[1007]),
	        "1a125f288973814a57f75a819b0847c38e5805c8dfd1156f2a4e5269afac52e2b4db298710374951e5f114ef2b32048bfea2dfc13ec7e8ad15f6bbe3e0d85f8e",
	        "/usr/lib/kbd/keymaps/xkb/gb-extd.map.gz"
	);
}
static void svir_1009(void) 
{
	svi_reg(&(tinfoil.validation_items[1008]),
	        "85dbf41b957c5840d315eaa3a29c5317ea54dee5e5afc2a2f6df2eacf3816f5ac31b67392a9e62cbd04fa88e2ada4eb48e5cfd035a27b27267a4efb2d7bb9a05",
	        "/usr/lib/kbd/keymaps/xkb/gb-dvorakukp.map.gz"
	);
}
static void svir_1010(void) 
{
	svi_reg(&(tinfoil.validation_items[1009]),
	        "9446b4af4d6b21d248451a3dd216bd95ca238bab33a7012ce37d7b2182cd1153879406295176e94eb6c6bbbcd5f64948ff9cd9afba0720024156e611afb1bc63",
	        "/usr/lib/kbd/keymaps/xkb/gb-dvorak.map.gz"
	);
}
static void svir_1011(void) 
{
	svi_reg(&(tinfoil.validation_items[1010]),
	        "f02025763c703b35f4cc013f2ab97b9807cfab8631ba4a10731611101b2f3914bf14e050da78743941055f6707ca6c347263ea49e6904c0230d8d33aa63f430b",
	        "/usr/lib/kbd/keymaps/xkb/gb-colemak_dh.map.gz"
	);
}
static void svir_1012(void) 
{
	svi_reg(&(tinfoil.validation_items[1011]),
	        "34d1f9e947eb9cca8c7e6bd58fea2d4261d2eeedfd4dba39abd98352211b6d02fad4f2f4e36347b58af706a0caa0a545d0d5fc4bdddc8a9006620909dbeb42f4",
	        "/usr/lib/kbd/keymaps/xkb/gb-colemak.map.gz"
	);
}
static void svir_1013(void) 
{
	svi_reg(&(tinfoil.validation_items[1012]),
	        "1e3e64f2c6a6bb0664b2151bd48f7b967944334293b19447909f63715d5116542593a110e2f48132c80027b6e2c91a4918854694fc72822afb3d12a3c823dcc4",
	        "/usr/lib/kbd/keymaps/xkb/fr.map.gz"
	);
}
static void svir_1014(void) 
{
	svi_reg(&(tinfoil.validation_items[1013]),
	        "e0f31b0945f89f93b522c4f4993abf611a47789f0a848e18c38efa1cf8327b61fb6fae986ae56094d6d2ffe9a9e21991a884c6753a5e38d93938f4e46663d140",
	        "/usr/lib/kbd/keymaps/xkb/fr-us.map.gz"
	);
}
static void svir_1015(void) 
{
	svi_reg(&(tinfoil.validation_items[1014]),
	        "646b889a6f916f4ab395d20b6d25eafc62046c891635cf58111d29166d11c049b2543471c389fe1bdd49b0f48eda138230a850c96b3bb1e0dd47bccd5467f29e",
	        "/usr/lib/kbd/keymaps/xkb/fr-oss_nodeadkeys.map.gz"
	);
}
static void svir_1016(void) 
{
	svi_reg(&(tinfoil.validation_items[1015]),
	        "ff8ad2521e0038e164d746961dc0b69d670a909069cff5c75bdf19c7bdb526c41a3f74fb7ebcb3404f9905239dc224e2f60bfbc938c11796095ab967eab9d369",
	        "/usr/lib/kbd/keymaps/xkb/fr-oss_latin9.map.gz"
	);
}
static void svir_1017(void) 
{
	svi_reg(&(tinfoil.validation_items[1016]),
	        "70e25a49f9b75a28ef53642b5f6270cab6f842fab0cc4b1d0f3808d50ac9248a487827daf05327cd5bbe524fc8d3d921526ba013184ef81b9568d3edea7d7aae",
	        "/usr/lib/kbd/keymaps/xkb/fr-oss.map.gz"
	);
}
static void svir_1018(void) 
{
	svi_reg(&(tinfoil.validation_items[1017]),
	        "dfccea29a627593339ffccf23da2ecd3efbd832d9733f833cfa6eac5102dfe4c3b3a25d20d260c63b3cd76c74fc94b04e603a589ebdf82e9c5aa707f2b5c6c74",
	        "/usr/lib/kbd/keymaps/xkb/fr-oci.map.gz"
	);
}
static void svir_1019(void) 
{
	svi_reg(&(tinfoil.validation_items[1018]),
	        "1ad830453b3c490bc2b0f63b8bacea2708806838baeb5fb75d94ba5006e369894af8ed2e6e1a6a93e05ef36e5438f1a481b8e640f5734841114804963583a49b",
	        "/usr/lib/kbd/keymaps/xkb/fr-nodeadkeys.map.gz"
	);
}
static void svir_1020(void) 
{
	svi_reg(&(tinfoil.validation_items[1019]),
	        "a20a793c894068e4e1fcc9e6d6cf75827f604fe5c90fad42daf9293ef50ce96a6c0607f125145d82ec1f1ec3c0491e9ee89d760a06d88ce39eb8e9416f8b8330",
	        "/usr/lib/kbd/keymaps/xkb/fr-mac.map.gz"
	);
}
static void svir_1021(void) 
{
	svi_reg(&(tinfoil.validation_items[1020]),
	        "e546fd3d1a070503b5a133b5a1d59c8fd68cc78d60e79392c3301bf055df859bc038d24b0341c78761558694ee20dc14a265ae4349bbc06c99510dec7966d902",
	        "/usr/lib/kbd/keymaps/xkb/fr-latin9_nodeadkeys.map.gz"
	);
}
static void svir_1022(void) 
{
	svi_reg(&(tinfoil.validation_items[1021]),
	        "b8ed6fa9ae69df6b79251d1c766bdb41fa363e8ab14c985d62ae240cd258775bd58ec74c91336dcbd7a1dee4eaa802a6de28de8886a1c8a94cb842d633830c0d",
	        "/usr/lib/kbd/keymaps/xkb/fr-latin9.map.gz"
	);
}
static void svir_1023(void) 
{
	svi_reg(&(tinfoil.validation_items[1022]),
	        "123e4366ccc2f40dcc59508d9db669ffcbb677e5d9271702ca833a3f0d92cbb781eb3ca054ca3130d8f75f33e35fa449cae34367e2b58b29846e8241e9134768",
	        "/usr/lib/kbd/keymaps/xkb/fr-dvorak.map.gz"
	);
}
static void svir_1024(void) 
{
	svi_reg(&(tinfoil.validation_items[1023]),
	        "3537af0aac0b018d01925ba8cea2c813a691f0a66e11909bfdfd7368dee5f7848822fa1d0f943b4ef64a9455b331d0f8976c2988ea326b2da65a3191d6ef2f4b",
	        "/usr/lib/kbd/keymaps/xkb/fr-bre.map.gz"
	);
}
static void svir_1025(void) 
{
	svi_reg(&(tinfoil.validation_items[1024]),
	        "41d927bd9bd9173cf0f278fa6fe8986e4c140e0fb6f5cb850ab01db8ca30a50213aa4af4c0427cc63057466c988279e2510b47fa499561964675751555d1a74c",
	        "/usr/lib/kbd/keymaps/xkb/fr-bepo_latin9.map.gz"
	);
}
static void svir_1026(void) 
{
	svi_reg(&(tinfoil.validation_items[1025]),
	        "0316c673cdad75467702acd2a34f66cb929180ee1e4006ac03b93b5ee4c01bb6c3307f13d81741ef1176539661e5c9c8494d8cacce84d706ca5f6772be976b57",
	        "/usr/lib/kbd/keymaps/xkb/fr-bepo_afnor.map.gz"
	);
}
static void svir_1027(void) 
{
	svi_reg(&(tinfoil.validation_items[1026]),
	        "41fb83798a35b745b47ff8c28e5e7d0a5b7cdc116f8444ea106003ee85c2595cdee79983dd08dd61696e6b92bfea96e891864d943b3ba85fdc4cdb6d6025b7bb",
	        "/usr/lib/kbd/keymaps/xkb/fr-bepo.map.gz"
	);
}
static void svir_1028(void) 
{
	svi_reg(&(tinfoil.validation_items[1027]),
	        "23650ebdef883e0770ce9e20d8aff3ba7f90cedd1f0640731260ad03dd9b48a225c6c2e6fc450b50026176a9ab08e9fc55b628e172648f99c88eafd2ce289d8e",
	        "/usr/lib/kbd/keymaps/xkb/fr-azerty.map.gz"
	);
}
static void svir_1029(void) 
{
	svi_reg(&(tinfoil.validation_items[1028]),
	        "69d2abb6028e802d09d4039e686f7d1b8cc42f00a8fd98d79759f8972f69cf71cb0f698d4ac5e7a722c1d04d857f3016ccfd3c30cfffb918270be4bbcf459f50",
	        "/usr/lib/kbd/keymaps/xkb/fr-afnor.map.gz"
	);
}
static void svir_1030(void) 
{
	svi_reg(&(tinfoil.validation_items[1029]),
	        "761cb21ea61e9f81488555026ef3e359db0cc6e5e33bedead04c4f58d23dfaf129235b0af14676f18bd21917e7d6a71f21ca1b7c451bdc1422b95a90a6a366a3",
	        "/usr/lib/kbd/keymaps/xkb/fo.map.gz"
	);
}
static void svir_1031(void) 
{
	svi_reg(&(tinfoil.validation_items[1030]),
	        "7ab92865315f86cfa8c7fd2a3256b9e416626511d5743b59523b9210375e54e658de50aea0fe090f313dad20c0c03ca3f7c4ad23f90e4773b3ae85975410a7fb",
	        "/usr/lib/kbd/keymaps/xkb/fo-nodeadkeys.map.gz"
	);
}
static void svir_1032(void) 
{
	svi_reg(&(tinfoil.validation_items[1031]),
	        "582133765e66450655c26bb54d8d0a6488dac86ddbc619575a365f76e3a8e5febda359eab73ce7a6c397c11751e96d4f51a91814c4d3c0779252f0a60775370d",
	        "/usr/lib/kbd/keymaps/xkb/fi.map.gz"
	);
}
static void svir_1033(void) 
{
	svi_reg(&(tinfoil.validation_items[1032]),
	        "afe95fbdb95239e95d7dbd357edc8a6b328d07e17f475093ef0fc8c77e481f48386594ef850776a0c55bbd33bbeeaeba730abf3f8068622514d4dc13629c57a2",
	        "/usr/lib/kbd/keymaps/xkb/fi-winkeys.map.gz"
	);
}
static void svir_1034(void) 
{
	svi_reg(&(tinfoil.validation_items[1033]),
	        "40c1e86f8eef179856145b8336c05458de21f0c1021f40a1bdc212a70741a732b7f5dbae1ecb460135e055e7362d578ca956a8d95d564a19d4f0b29ffa612bb8",
	        "/usr/lib/kbd/keymaps/xkb/fi-smi.map.gz"
	);
}
static void svir_1035(void) 
{
	svi_reg(&(tinfoil.validation_items[1034]),
	        "8045fbec77c7f912dedef531044adf67e94ccdc2749338a89e8fceb0c4eacc075d3296bb261b86783856456a7cc64140cba6009bac26f159327a308411ac0086",
	        "/usr/lib/kbd/keymaps/xkb/fi-nodeadkeys.map.gz"
	);
}
static void svir_1036(void) 
{
	svi_reg(&(tinfoil.validation_items[1035]),
	        "2b69659c6147eee79bc64a4b8836d5e57f7d1739cd67726bafa7834b38df648ecf11fe94743b8440eb11649019eef6c235c2d4d95585e4bd9225462279cc2a12",
	        "/usr/lib/kbd/keymaps/xkb/fi-mac.map.gz"
	);
}
static void svir_1037(void) 
{
	svi_reg(&(tinfoil.validation_items[1036]),
	        "bb107d02b11fdc6c731fbead648907d8a6cc09000d5a0dee793e54f1c622c5c55c7b92b798bf713bf4ac5cf01148115bac52206eec03506563271f23b4cd4eb4",
	        "/usr/lib/kbd/keymaps/xkb/fi-classic.map.gz"
	);
}
static void svir_1038(void) 
{
	svi_reg(&(tinfoil.validation_items[1037]),
	        "7479343a3d6ce5bc6652475f91ced2aa7730ada855fb8c5af2e18ff8bc13949d4c4633694fd11c1fe7d75b211c7ba474ca02378c4a8bd1aa71e16ac75c208153",
	        "/usr/lib/kbd/keymaps/xkb/es.map.gz"
	);
}
static void svir_1039(void) 
{
	svi_reg(&(tinfoil.validation_items[1038]),
	        "feae9d0c89a77079239da6dd1f07b6ceb090047b4a5129bd9f7a1a8665efb4eb58e6925f566ef60a6adca923124b64426fd52264896036850128cafc34716f8a",
	        "/usr/lib/kbd/keymaps/xkb/es-winkeys.map.gz"
	);
}
static void svir_1040(void) 
{
	svi_reg(&(tinfoil.validation_items[1039]),
	        "b1aa950a5466655c54993e7b8dd41649204151c98c5c298ff64259122ce8b0ab79d626b6f745b43ea903fa642f134e4053f5e05ef017388a9850bff0d1c788fe",
	        "/usr/lib/kbd/keymaps/xkb/es-nodeadkeys.map.gz"
	);
}
static void svir_1041(void) 
{
	svi_reg(&(tinfoil.validation_items[1040]),
	        "7479343a3d6ce5bc6652475f91ced2aa7730ada855fb8c5af2e18ff8bc13949d4c4633694fd11c1fe7d75b211c7ba474ca02378c4a8bd1aa71e16ac75c208153",
	        "/usr/lib/kbd/keymaps/xkb/es-mac.map.gz"
	);
}
static void svir_1042(void) 
{
	svi_reg(&(tinfoil.validation_items[1041]),
	        "436f7a51fc5eba83ced8241428c11d9aad0e7ec1b6b4d46e14d683900670a30e7525c8ec88eba19ff2877447514f997c1b3cfbd11790562469c6e10b9d37368d",
	        "/usr/lib/kbd/keymaps/xkb/es-dvorak.map.gz"
	);
}
static void svir_1043(void) 
{
	svi_reg(&(tinfoil.validation_items[1042]),
	        "f17b2f22ebc5e709e8ddc2a080dbbee7d4449c6c91cad3d7a70b9f44786154d986687120aacfd620c201d296a658466cc78579d3e3fc1426673554e7c1621902",
	        "/usr/lib/kbd/keymaps/xkb/es-deadtilde.map.gz"
	);
}
static void svir_1044(void) 
{
	svi_reg(&(tinfoil.validation_items[1043]),
	        "f3ee3225d11c7f66b6c5a2703b2ad73ceebf3559cf71229e0c70ad986a32041bf1b50f15d99a037b96e997ace56df9333339a5820e7c0693b8672916b0f9034e",
	        "/usr/lib/kbd/keymaps/xkb/es-cat.map.gz"
	);
}
static void svir_1045(void) 
{
	svi_reg(&(tinfoil.validation_items[1044]),
	        "1fcd485efc5f14057a09ea641c212c3835cc8671398f1b38f609d37efaee400fd8833b187ca6b089356e75095ea269e1cd503caaf82c9d3b94ccfc982289c3be",
	        "/usr/lib/kbd/keymaps/xkb/es-ast.map.gz"
	);
}
static void svir_1046(void) 
{
	svi_reg(&(tinfoil.validation_items[1045]),
	        "34c4d539622e1bc8ae610d4a6bd1037f01c9b1b99edbdbe23b031a7b4bf582127c4d79312af399dfdf73a4dfc55f0fdff92ab823870398a7da8e025af98973a6",
	        "/usr/lib/kbd/keymaps/xkb/epo.map.gz"
	);
}
static void svir_1047(void) 
{
	svi_reg(&(tinfoil.validation_items[1046]),
	        "1438cba0e6eab5b841a148f7ffa42593986202f9867ca04491c21cee751673359c569e72fb5f46f81b426339120325a93eea422b780a8322b5bf6a8ce52e8f54",
	        "/usr/lib/kbd/keymaps/xkb/epo-legacy.map.gz"
	);
}
static void svir_1048(void) 
{
	svi_reg(&(tinfoil.validation_items[1047]),
	        "4c8a1e58ddd3c20377864d2869487c344f090167f65d565a74b62c4e7aa502fc456a3ff3c460d10b35e3dd87c50bc4d0b024581fb01ea0533c9398c51f3dd514",
	        "/usr/lib/kbd/keymaps/xkb/ee.map.gz"
	);
}
static void svir_1049(void) 
{
	svi_reg(&(tinfoil.validation_items[1048]),
	        "f4b4bbe269ad5c8d6d5af7aef6391426a7c2f7d30be41e71ed4e64ff566110607d6b62439999613ae2d8c5f0ee3bebdc9b9551964bf987f0d233c7661c04a4c2",
	        "/usr/lib/kbd/keymaps/xkb/ee-us.map.gz"
	);
}
static void svir_1050(void) 
{
	svi_reg(&(tinfoil.validation_items[1049]),
	        "05f465b7761aef06780222df2170f15b6ed48d6d5489c719092ec2f9a164585cbc520ee009fee5c27c2c96c3777062aad167cf890d6636cb57acb0b9ec631bd9",
	        "/usr/lib/kbd/keymaps/xkb/ee-nodeadkeys.map.gz"
	);
}
static void svir_1051(void) 
{
	svi_reg(&(tinfoil.validation_items[1050]),
	        "9682517e576e39b14f3ff8c7f31e0e908ca0dd5389ad516a9e8a9c672d0e2424cd45b5f06f00989a8cc4f3a2da9c5b0ff8f1db5da29815b7859eb81fa5102ef5",
	        "/usr/lib/kbd/keymaps/xkb/ee-dvorak.map.gz"
	);
}
static void svir_1052(void) 
{
	svi_reg(&(tinfoil.validation_items[1051]),
	        "56b2d9754331e0b7161c4a850c462de503f4b71bb314194b0ef697e92b4ce46b159d93fdb6ba4c8389f2d954a048d623e97734cbafeb736d9394cd048a2d87eb",
	        "/usr/lib/kbd/keymaps/xkb/dz.map.gz"
	);
}
static void svir_1053(void) 
{
	svi_reg(&(tinfoil.validation_items[1052]),
	        "0f4aeaa729ba6e684c5842a8e727702025cf723b26bb6bc8165e70ef606de426d9f1ca0d1e3fb35d2ecbea282b61043cd13590d03c54e441eb3af9d6157849f4",
	        "/usr/lib/kbd/keymaps/xkb/dz-qwerty-us-deadkeys.map.gz"
	);
}
static void svir_1054(void) 
{
	svi_reg(&(tinfoil.validation_items[1053]),
	        "1a644d0770e3ef13f61f324b4d3c4515cba96de1b509822faa242d0648a8ca1c6a4530f02f6256574c3d790a4ced1db1aac122ff754275c05f4f9ac1eaece5f7",
	        "/usr/lib/kbd/keymaps/xkb/dz-qwerty-gb-deadkeys.map.gz"
	);
}
static void svir_1055(void) 
{
	svi_reg(&(tinfoil.validation_items[1054]),
	        "46f8016b4ef947ec0327c623d22be570261038782ad1e35926d7ba9aa293e29b9454f3dd312aef5caae63f9a56d89f9a9c391291838c7c956d4f93de0808b76a",
	        "/usr/lib/kbd/keymaps/xkb/dz-azerty-deadkeys.map.gz"
	);
}
static void svir_1056(void) 
{
	svi_reg(&(tinfoil.validation_items[1055]),
	        "6a4faadff5642dbb634f24e05cb11fae25b1de674c03e72d9e9192c781dcaec9e1e320d95b91dcff1ae856bfb722267c076c8f5e76cc662fdc7cac780563c5b6",
	        "/usr/lib/kbd/keymaps/xkb/dk.map.gz"
	);
}
static void svir_1057(void) 
{
	svi_reg(&(tinfoil.validation_items[1056]),
	        "29759f21c8ac92e48fea4737d96c5cf80bba9300b78ac749d628cd1ace06c0466ebc28bcebbcc5e1421dd1eccc9289f2c8d9f2de7d464cb286bad3276b31f600",
	        "/usr/lib/kbd/keymaps/xkb/dk-winkeys.map.gz"
	);
}
static void svir_1058(void) 
{
	svi_reg(&(tinfoil.validation_items[1057]),
	        "aecf4d54ff4f34959249ce0ef882458443a639195d45fdca4ce3c5fb469306c3393fcd9dbf36071c20e7dc02a61495bea84bff1fb143d860f144085a33e4a4af",
	        "/usr/lib/kbd/keymaps/xkb/dk-nodeadkeys.map.gz"
	);
}
static void svir_1059(void) 
{
	svi_reg(&(tinfoil.validation_items[1058]),
	        "e86a6f54e20669f185f09d06f4e3e5802503eae0ef1d82d9cbcbc9c522a3bedf150427e40f4ae462474cfd11bfb85b107240c03c005913a43c3d80db763b6c6f",
	        "/usr/lib/kbd/keymaps/xkb/dk-mac_nodeadkeys.map.gz"
	);
}
static void svir_1060(void) 
{
	svi_reg(&(tinfoil.validation_items[1059]),
	        "e1640a3d960d1dcf7f23cdb0588bde14252ac6467f3e2f398e3d003baa817e0016a615f60109b1dda4fa506c78ea41f4019f6979357394da64ce617576dfc7d6",
	        "/usr/lib/kbd/keymaps/xkb/dk-mac.map.gz"
	);
}
static void svir_1061(void) 
{
	svi_reg(&(tinfoil.validation_items[1060]),
	        "a7034f437ceeaa2d4c312c6743cdf05f4f77c4ff638bf4a367252562ad4349a3a7f6b4b2afc2e0293c5c583803c0b5b834f692d9eae41e582669dcfe6e5cc213",
	        "/usr/lib/kbd/keymaps/xkb/dk-dvorak.map.gz"
	);
}
static void svir_1062(void) 
{
	svi_reg(&(tinfoil.validation_items[1061]),
	        "bd67bf2aedfd1ab99b939738b574622356115939edf2d84588385a46da62a5cf60b47b10b2264e9284f8daeaa84ed446d57c551dfe85732bebff95cb82d3ed9a",
	        "/usr/lib/kbd/keymaps/xkb/de.map.gz"
	);
}
static void svir_1063(void) 
{
	svi_reg(&(tinfoil.validation_items[1062]),
	        "a9a68bae1f36d6d5b76b5d5648f2bb1cd005073c7e5f0a05e4357291268158413a98a54d2801a9aa242a0feffcc5064c5e494d5d966e3145ab90e38ff2fd685b",
	        "/usr/lib/kbd/keymaps/xkb/de-us.map.gz"
	);
}
static void svir_1064(void) 
{
	svi_reg(&(tinfoil.validation_items[1063]),
	        "912cf33d2e208ab37d7599455c11784964af74bf9d4886941ffc970760cdd8fe1fe49d62a1080b3c161e6ec98ed2bf7e2e728c2a2d35b242c3aa6ce98d268571",
	        "/usr/lib/kbd/keymaps/xkb/de-tr.map.gz"
	);
}
static void svir_1065(void) 
{
	svi_reg(&(tinfoil.validation_items[1064]),
	        "29378ca498986cebcd17cf7be7904ed72cebc78b69b770242d1bc23467a80ae858cd1c255dc456d942c024069b9fed8cd3a7aa4d2fea4c9707b654b4ea1d37c8",
	        "/usr/lib/kbd/keymaps/xkb/de-ro_nodeadkeys.map.gz"
	);
}
static void svir_1066(void) 
{
	svi_reg(&(tinfoil.validation_items[1065]),
	        "737eb2bc3a58848f5172f34d00814db6788228e349e522a39709820866030af6a37754e4bd43fbc52d25a85c25df8c4f90a04e53d252448f35cb2d03628268ec",
	        "/usr/lib/kbd/keymaps/xkb/de-ro.map.gz"
	);
}
static void svir_1067(void) 
{
	svi_reg(&(tinfoil.validation_items[1066]),
	        "4ff8cc1707a0d4e69233acda29a6d7b66605884111cd35d9e7f7286ed1c6c8dda7935a1a875b772d96daef5da1786d1c09eb0e1dd2300998c22e8b39f79b1759",
	        "/usr/lib/kbd/keymaps/xkb/de-qwerty.map.gz"
	);
}
static void svir_1068(void) 
{
	svi_reg(&(tinfoil.validation_items[1067]),
	        "843e408eddf49e6d1856d409d9e34865421b19512ad4981807889ab0f2ebb73bca1ccc29d7c662cd0481556d6c75e2624bb8f75655e9b885c961b8101aea2dd0",
	        "/usr/lib/kbd/keymaps/xkb/de-nodeadkeys.map.gz"
	);
}
static void svir_1069(void) 
{
	svi_reg(&(tinfoil.validation_items[1068]),
	        "4e1caf682b5f9be1b280df8ddc78c339a0041a65a8278ca30380e136a488bbf3e61328eb65a93a0eeb5ebf1fdb7a28b69cb8fed216253d52cbf2ed3b4e360806",
	        "/usr/lib/kbd/keymaps/xkb/de-neo.map.gz"
	);
}
static void svir_1070(void) 
{
	svi_reg(&(tinfoil.validation_items[1069]),
	        "317f5b8cbe52e21d2eddd1ef39254cd2f6e1c1fb7efa6fd24683eba3a76e22d58602a592a1e6b6952d769fddc22dc2ca855371b1103d09791feed7b70b02379a",
	        "/usr/lib/kbd/keymaps/xkb/de-mac_nodeadkeys.map.gz"
	);
}
static void svir_1071(void) 
{
	svi_reg(&(tinfoil.validation_items[1070]),
	        "cdd7644f245c226e0b17b6ef55e7307c20419a727b65780ee287bcca8aa608a178c7cbbe1ee606ff59926f988bfd182c795e2460e193fd4bda5ca7671f39761d",
	        "/usr/lib/kbd/keymaps/xkb/de-mac.map.gz"
	);
}
static void svir_1072(void) 
{
	svi_reg(&(tinfoil.validation_items[1071]),
	        "8c1ad8c44ec43598fbdaca710bf63904ad9bede3fd160a6cc35a26f9c1330a436eee46743b029cf778ce989baca4b84ece424b7e07c4a3c40e8d39cf453468e9",
	        "/usr/lib/kbd/keymaps/xkb/de-e2.map.gz"
	);
}
static void svir_1073(void) 
{
	svi_reg(&(tinfoil.validation_items[1072]),
	        "59656c27d69ac90f6e53935056ecfa7dafdeed04e05d39c0a23057a73fbd0c857b9f068128b5afe8a9f7ffa9f3edcf2997d051fda9802535c799ac3dcb26bdea",
	        "/usr/lib/kbd/keymaps/xkb/de-e1.map.gz"
	);
}
static void svir_1074(void) 
{
	svi_reg(&(tinfoil.validation_items[1073]),
	        "8719e526b775f4589b197b2857d5af28d9992296e1ff3976b0400bb2c9240ece666670ecfbc0923418794d05f8ee33f2f7d28a4e278da3e911a13cd3376bc905",
	        "/usr/lib/kbd/keymaps/xkb/de-dvorak.map.gz"
	);
}
static void svir_1075(void) 
{
	svi_reg(&(tinfoil.validation_items[1074]),
	        "b99231362c9737404e6e089ff86cf4f829c2e938249ccafd2b9698c3e622c3e38c630b94fd7968c34510b360e4adc24ac1345b5cc6ca2e9923e1efad00f0f359",
	        "/usr/lib/kbd/keymaps/xkb/de-dsb_qwertz.map.gz"
	);
}
static void svir_1076(void) 
{
	svi_reg(&(tinfoil.validation_items[1075]),
	        "6ed0079dcc15c29352c0a56b6839393870c962042e5abad61d9003ca4ab169baa4f73b913984c70dda05f49b0c4cd72ff64004bc8f56a176ec35412696e68ace",
	        "/usr/lib/kbd/keymaps/xkb/de-dsb.map.gz"
	);
}
static void svir_1077(void) 
{
	svi_reg(&(tinfoil.validation_items[1076]),
	        "6c714dad4af3cfcf579e5fb6bfe9991a5a69ada22cb5362092aaa6166c0ff827abe32c9637ffb7b50c2f3591a41c3de1e262e09e745fb5bb69b6eef0f5d0ba12",
	        "/usr/lib/kbd/keymaps/xkb/de-deadtilde.map.gz"
	);
}
static void svir_1078(void) 
{
	svi_reg(&(tinfoil.validation_items[1077]),
	        "4af18fa83e7b6d9b5bb9a6cf6950681abe2819c749bc3c0575fd038e4f0b1ff7620c36b3bf9573775253b7267287689ffd6729c2ecfc8471f846de6d286c6ca6",
	        "/usr/lib/kbd/keymaps/xkb/de-deadgraveacute.map.gz"
	);
}
static void svir_1079(void) 
{
	svi_reg(&(tinfoil.validation_items[1078]),
	        "53740dda8a61c5072aab8d078985998937d272ee095e05084e1c4f25db52c70658f23f7f05c6a79e048a00802bef069a91aa581820661f5319e40c58389a4cf5",
	        "/usr/lib/kbd/keymaps/xkb/de-deadacute.map.gz"
	);
}
static void svir_1080(void) 
{
	svi_reg(&(tinfoil.validation_items[1079]),
	        "857816e1f75b8051821e649b25492a49e83d30bf20c0381f27ce335dbf71f0814a608f0566ac8f5819a3d5cf33ad94efbf31d732694499ed5c9f9af63c381c80",
	        "/usr/lib/kbd/keymaps/xkb/de-T3.map.gz"
	);
}
static void svir_1081(void) 
{
	svi_reg(&(tinfoil.validation_items[1080]),
	        "91614030435db8fa967e2289daa1b3ae2deb24e4fdc9699bbeeeab2051a6f94df266fb1730d7d9c1dff5e6997d6529ca60ca8383577cdf23bea2e8dda9c613b9",
	        "/usr/lib/kbd/keymaps/xkb/cz.map.gz"
	);
}
static void svir_1082(void) 
{
	svi_reg(&(tinfoil.validation_items[1081]),
	        "02dde47541da824e794bb71e99936a72ea4a98785478c8d3ffef2b03b0eaa851fef6090492630331c6b7fe0e54c6418ba4d3510af9e7751085008a8b82ed58be",
	        "/usr/lib/kbd/keymaps/xkb/cz-rus.map.gz"
	);
}
static void svir_1083(void) 
{
	svi_reg(&(tinfoil.validation_items[1082]),
	        "5e85f315ee2f4259bfb47b02c564fe0ad8d4d4be06b20255b6dc51fa73677920f3034b387eaaedc9f1ba41812c24a5a8d7ceae25f6f9731728e057792eb0245a",
	        "/usr/lib/kbd/keymaps/xkb/cz-qwerty_bksl.map.gz"
	);
}
static void svir_1084(void) 
{
	svi_reg(&(tinfoil.validation_items[1083]),
	        "3e060ec491f728fc58087f35867fb3b6392413185984f9db64a28dee9aa223d9bbc9d22d686a730a5437dd7b19275bbafb9c962b5a89b7b7b8e180b0c7f24278",
	        "/usr/lib/kbd/keymaps/xkb/cz-qwerty.map.gz"
	);
}
static void svir_1085(void) 
{
	svi_reg(&(tinfoil.validation_items[1084]),
	        "62dfd5efc188e6d2ea6af38f7c522a8808f702df2e23cec9552f9f72e00ef0852642c3190878e6a94c080ed315e35848f3ee56828fcf3cca297052454b81a011",
	        "/usr/lib/kbd/keymaps/xkb/cz-qwerty-mac.map.gz"
	);
}
static void svir_1086(void) 
{
	svi_reg(&(tinfoil.validation_items[1085]),
	        "f8bcea334d10918f5f1f07ad6ed8f5c0bfa0e2de6734f9e3b977e527ebce918372a5af52e45bd4e2610dc387b25aef8f17871db809c90a32a49cf90305bf44c5",
	        "/usr/lib/kbd/keymaps/xkb/cz-dvorak-ucw.map.gz"
	);
}
static void svir_1087(void) 
{
	svi_reg(&(tinfoil.validation_items[1086]),
	        "7cc9bd50dbca43f9ff7d1470f68d28821b6080a37592b88f034efc5c668ab69db5d5b2390e1e580384d6d14575dd6a299e49736b5f6999c6f53f8341bab0a019",
	        "/usr/lib/kbd/keymaps/xkb/cz-bksl.map.gz"
	);
}
static void svir_1088(void) 
{
	svi_reg(&(tinfoil.validation_items[1087]),
	        "74c60b34b1d444c3d4e2cb2db157f264a15095bd5c4e5d78975937d3288a8fbeacddce97f3b90411d2e40f170bc54f394721c365fa8084a83ce4aa597e650ffe",
	        "/usr/lib/kbd/keymaps/xkb/cm.map.gz"
	);
}
static void svir_1089(void) 
{
	svi_reg(&(tinfoil.validation_items[1088]),
	        "74c60b34b1d444c3d4e2cb2db157f264a15095bd5c4e5d78975937d3288a8fbeacddce97f3b90411d2e40f170bc54f394721c365fa8084a83ce4aa597e650ffe",
	        "/usr/lib/kbd/keymaps/xkb/cn.map.gz"
	);
}
static void svir_1090(void) 
{
	svi_reg(&(tinfoil.validation_items[1089]),
	        "418812a72ecf421b46f537046e1491ad41fffbe5ba33f586e009aa11e1266ed5a7689a1cd560114a12614a586d17f4fbee2cc20faeb28a114759fd5080ac49bd",
	        "/usr/lib/kbd/keymaps/xkb/cn-altgr-pinyin.map.gz"
	);
}
static void svir_1091(void) 
{
	svi_reg(&(tinfoil.validation_items[1090]),
	        "bfd579ea83b74d1b5abf135b29ad1d34728e93359fe35ee73f5322a91f32c77c9b8a6c6b84728e3dec6452acca69319b1b6e39d4f41f180caf88bf384db14a54",
	        "/usr/lib/kbd/keymaps/xkb/cm-qwerty.map.gz"
	);
}
static void svir_1092(void) 
{
	svi_reg(&(tinfoil.validation_items[1091]),
	        "8ec69e38d81154a287622751844293fa6f0c15f427f85dfefc69c3d96f43bde8380d6aaf753a46903295f2cbd4984d8d7770f143b6edd9b8375c706af0f62219",
	        "/usr/lib/kbd/keymaps/xkb/cm-mmuock.map.gz"
	);
}
static void svir_1093(void) 
{
	svi_reg(&(tinfoil.validation_items[1092]),
	        "1e3e64f2c6a6bb0664b2151bd48f7b967944334293b19447909f63715d5116542593a110e2f48132c80027b6e2c91a4918854694fc72822afb3d12a3c823dcc4",
	        "/usr/lib/kbd/keymaps/xkb/cm-french.map.gz"
	);
}
static void svir_1094(void) 
{
	svi_reg(&(tinfoil.validation_items[1093]),
	        "e40dacaf469b746346e5a8aff49c38f13c5cc4cd3a1d1b45d05319941617f2cdec810cdb0df2acccd1fef5683dd5ffb8f6b1fa7d1913b21c5d976cb14606c279",
	        "/usr/lib/kbd/keymaps/xkb/cm-dvorak.map.gz"
	);
}
static void svir_1095(void) 
{
	svi_reg(&(tinfoil.validation_items[1094]),
	        "9ffef995ec1706955617414939fbdb74b721b430c38db333ec1a0a7955de0aab23c01fa303c4309ef608cd500decf9e92f023f12498e55d7dc72f8bc7afe9bf3",
	        "/usr/lib/kbd/keymaps/xkb/cm-azerty.map.gz"
	);
}
static void svir_1096(void) 
{
	svi_reg(&(tinfoil.validation_items[1095]),
	        "91f71107f9e1d3042b182cd92a6f4f534c1ced8bbba2cd87ca976d4614ba984f509b856a94b1a6d9e48462caf75620c4b5133dfb716a478cda62160ac37bff27",
	        "/usr/lib/kbd/keymaps/xkb/ch.map.gz"
	);
}
static void svir_1097(void) 
{
	svi_reg(&(tinfoil.validation_items[1096]),
	        "56a9221547cafffb3795969b7ced055d9f2895f9be1c204b8a9475c27623d6db4be1752d3c06c613eb19f586774cb203cae3049575cffdeccd1d9efd0448a6fb",
	        "/usr/lib/kbd/keymaps/xkb/ch-legacy.map.gz"
	);
}
static void svir_1098(void) 
{
	svi_reg(&(tinfoil.validation_items[1097]),
	        "ce232358a5f0651e51d0a1048ba7947a64d9fbbffd9f50c1234ee8027bb5cda93ab194a7779b5f85bc2fd3a342aec081968ab39e638e82ff1a6a713997ee75e6",
	        "/usr/lib/kbd/keymaps/xkb/ch-fr_nodeadkeys.map.gz"
	);
}
static void svir_1099(void) 
{
	svi_reg(&(tinfoil.validation_items[1098]),
	        "e8b4551709feb336eee036e3133da8fb631d3d71416f60fd140279240f7c7865ed39892cd03fae3b64a062a002194b098fb888602a75ffc8f2ec7c195eeb1326",
	        "/usr/lib/kbd/keymaps/xkb/ch-fr_mac.map.gz"
	);
}
static void svir_1100(void) 
{
	svi_reg(&(tinfoil.validation_items[1099]),
	        "dee55eef16c6cc51da98c55873d65f7166d5ce2039df5cf04b0e1de42c242b8e7069e74f5b7c3c48a42fa3b7d718864d6ff74a62004e37081bc9130bf1b3695b",
	        "/usr/lib/kbd/keymaps/xkb/ch-fr.map.gz"
	);
}
static void svir_1101(void) 
{
	svi_reg(&(tinfoil.validation_items[1100]),
	        "0cfd2258f1eb3a2e5e9195a43df87be2158cf102236d432aceb006b6e0bb62b2225d81a7e0b26d9e9854114c3cedfd55d9eb731bd218a11b5fcd6a2e838d6467",
	        "/usr/lib/kbd/keymaps/xkb/ch-de_nodeadkeys.map.gz"
	);
}
static void svir_1102(void) 
{
	svi_reg(&(tinfoil.validation_items[1101]),
	        "cc7486e51c00c3e436256e53a5f3ef217db368929a3167dc32b2b4856797ddcbcc3bdcb1d5a3d8398358fa1a5459d7daebd0ebff33097ef0807943f2435592f1",
	        "/usr/lib/kbd/keymaps/xkb/ch-de_mac.map.gz"
	);
}
static void svir_1103(void) 
{
	svi_reg(&(tinfoil.validation_items[1102]),
	        "fcfe21651eb4c9d209a2212490e51394d1acfd81285a0706e341a2067ef486996eabe97aed096c3a8733afa7e850cae99ebcfd057f421a2acb2a8c59e96766b4",
	        "/usr/lib/kbd/keymaps/xkb/ca.map.gz"
	);
}
static void svir_1104(void) 
{
	svi_reg(&(tinfoil.validation_items[1103]),
	        "33641ef1e7cf93a41feae805e79e5e432e6de8cc9d9e41e4ea26fa9c5afedd0a1a2174ef9a9c03bd380d006b842432ecf87f9ddd5d69246a84af508275a3ffcc",
	        "/usr/lib/kbd/keymaps/xkb/ca-multix.map.gz"
	);
}
static void svir_1105(void) 
{
	svi_reg(&(tinfoil.validation_items[1104]),
	        "d4d8fb0cf75c4aaaf18a598b51ae017630d439f20f54920cf2edfde1cc54883b6c54c65d630206d086f0d4836d9382d514fa09194cbb5c3e0fbf0487e18d65fa",
	        "/usr/lib/kbd/keymaps/xkb/ca-multi.map.gz"
	);
}
static void svir_1106(void) 
{
	svi_reg(&(tinfoil.validation_items[1105]),
	        "92c8f6d25941dff63ea69ec60212a360a9cf35480df17bd4ae2f6bb5d5e46b9be9d107e033e77962006dd6731c34efdf2a562db159cb1d65d06aaa9a3b8c80c1",
	        "/usr/lib/kbd/keymaps/xkb/ca-fr-legacy.map.gz"
	);
}
static void svir_1107(void) 
{
	svi_reg(&(tinfoil.validation_items[1106]),
	        "007a9893279893d7a91107d779d86c8f699eac186ab5ea4a318b45d6cf22cb7abf9628e7a16efbc5cc9b29113dd439b6ffd82da6341dc6f42c9506d45b2406f7",
	        "/usr/lib/kbd/keymaps/xkb/ca-fr-dvorak.map.gz"
	);
}
static void svir_1108(void) 
{
	svi_reg(&(tinfoil.validation_items[1107]),
	        "040620a728ac77a39d4519f1998ca70b24c8b5cebc3d316e7bf143b1201922b10e066aaf6f31878173d21b9367a02ec94939986108ce9363b932571a1fad2a41",
	        "/usr/lib/kbd/keymaps/xkb/ca-eng.map.gz"
	);
}
static void svir_1109(void) 
{
	svi_reg(&(tinfoil.validation_items[1108]),
	        "bbe782d3b6bf681208fb811e37c30d022a773b755b8690ba5e679b341d6b759f7ecf5769e8e2154b609a22d96d6c307c8ef96145e35e5ef16369dcdc03054e5f",
	        "/usr/lib/kbd/keymaps/xkb/by-latin.map.gz"
	);
}
static void svir_1110(void) 
{
	svi_reg(&(tinfoil.validation_items[1109]),
	        "3d1a399c4985f55c75973ba548ee812f6dcbaa1b2ce62a77e8b8604f730c8dd307583340593ec4458b05c55dca7d7f14401e46672721cc066fb5e812e7044f96",
	        "/usr/lib/kbd/keymaps/xkb/br.map.gz"
	);
}
static void svir_1111(void) 
{
	svi_reg(&(tinfoil.validation_items[1110]),
	        "b55d98e4477fa622e2887cd6fda2a29e73b852bf58c6d439fac333981e083f0c345f3c25c5c122b226e0cb27ecfd3b3b6bf7640083881cfda0668a0e2e67e714",
	        "/usr/lib/kbd/keymaps/xkb/br-thinkpad.map.gz"
	);
}
static void svir_1112(void) 
{
	svi_reg(&(tinfoil.validation_items[1111]),
	        "44c657d28edb1c91bed6b6b5b0e6857e6d86a826a9556e40b58de39227910b7eda63085dd9516922af3a6b0b749b536fce196dcdf9f88d05ba6e5b65f045bb17",
	        "/usr/lib/kbd/keymaps/xkb/br-nodeadkeys.map.gz"
	);
}
static void svir_1113(void) 
{
	svi_reg(&(tinfoil.validation_items[1112]),
	        "c5a337c31b495786d677ccf677bf998e646b0adc25054d626422f163b9a7e916b1b118ce5902ca41a628cf4d9d2f5d289e872bd455dc1805b8d67c32ca85fec8",
	        "/usr/lib/kbd/keymaps/xkb/br-nativo.map.gz"
	);
}
static void svir_1114(void) 
{
	svi_reg(&(tinfoil.validation_items[1113]),
	        "699b4930b154dfe2bc8123369ccb865de069e3277635c7ca1045b1b496eb89b5834acd598f4da42332668d73c3294cc7e22d9c0f3086152fa660330fe19e5f6f",
	        "/usr/lib/kbd/keymaps/xkb/br-nativo-us.map.gz"
	);
}
static void svir_1115(void) 
{
	svi_reg(&(tinfoil.validation_items[1114]),
	        "84804f4c66a730c61b854dee7c23e76da8291a47e31b2c9b0c429d4091c95b967c9ade0ce27ece1dd3a8e392e421077d8eb39f69bdc2af8737b35ca992fd4fab",
	        "/usr/lib/kbd/keymaps/xkb/br-nativo-epo.map.gz"
	);
}
static void svir_1116(void) 
{
	svi_reg(&(tinfoil.validation_items[1115]),
	        "251ff3194dd204e4e8249129879c634ab9e4c06909877ec20c583a94f073ec5c6d79e9cb4e6525af17a7ddf1b324540ee61a4a10df2bf0b38adfaf096b9eec55",
	        "/usr/lib/kbd/keymaps/xkb/br-dvorak.map.gz"
	);
}
static void svir_1117(void) 
{
	svi_reg(&(tinfoil.validation_items[1116]),
	        "814ba1d2c35cbe4a58fecc2624b28fc8014e2e31616ec52ec3115f643f30be8fdeb08a5e56bc18179dfc8149f45d6cacd5ba8a3baef792f13519a049479a010e",
	        "/usr/lib/kbd/keymaps/xkb/be.map.gz"
	);
}
static void svir_1118(void) 
{
	svi_reg(&(tinfoil.validation_items[1117]),
	        "d07c067b301d0d85bd9191e5611cc84837d388392f48d7e4a98c5af8f9c358352a297df8206a2d7d77a749563e0d8ea51603c2cad47d61b586eabffa160df9e0",
	        "/usr/lib/kbd/keymaps/xkb/be-wang.map.gz"
	);
}
static void svir_1119(void) 
{
	svi_reg(&(tinfoil.validation_items[1118]),
	        "da737fac367fdbecc60a3454df465c7d8fa693963b6a8fb3f322a1342d5d68abd354fde7e3ef847358cc9afee9915460cd52f0f35f625a1270ba84f97a89abcf",
	        "/usr/lib/kbd/keymaps/xkb/be-oss_latin9.map.gz"
	);
}
static void svir_1120(void) 
{
	svi_reg(&(tinfoil.validation_items[1119]),
	        "c8a2fb2bf78419ef88bc6bc00dc1f77eb477c7015640fc3cb240189e698ddd3df73a38007d7d0f0bb9160da546b6e2548e03b33dd5788b6738cd8c410a61b4b9",
	        "/usr/lib/kbd/keymaps/xkb/be-oss.map.gz"
	);
}
static void svir_1121(void) 
{
	svi_reg(&(tinfoil.validation_items[1120]),
	        "136eb7ba4cf331a0699446eb2217d85de00740440fe4b04cea9290ab1f0f3c7e31ada456ade14e485151043c0fff7fbb952dfbb473543400f2f8360b283e5fd5",
	        "/usr/lib/kbd/keymaps/xkb/be-nodeadkeys.map.gz"
	);
}
static void svir_1122(void) 
{
	svi_reg(&(tinfoil.validation_items[1121]),
	        "7f7fb5b404c3765731b6e1e7d7c59e97d033c32c43c0c4648f25ce4f6b24b510d84cd82283ce94258c1e1797a454e277288b6fdf353e5c173c34ebcb145dc85a",
	        "/usr/lib/kbd/keymaps/xkb/be-iso-alternate.map.gz"
	);
}
static void svir_1123(void) 
{
	svi_reg(&(tinfoil.validation_items[1122]),
	        "c2f82cb910ce6b38400bbeb5640e7290a967a1cc5572ede843a1c2833cd090ca25af00ded30eea38aa42f2cb74acbf1f9b78d9e2248cd4cabe495790d408e666",
	        "/usr/lib/kbd/keymaps/xkb/ba.map.gz"
	);
}
static void svir_1124(void) 
{
	svi_reg(&(tinfoil.validation_items[1123]),
	        "ed849c4ae5de2d1991ab96672cc80aade89f694bab131e48c14542be413ec9da4d108f1d2b353c29995b90ce57850c9aa3a663348d4f86b70961d41c7a5996d3",
	        "/usr/lib/kbd/keymaps/xkb/ba-us.map.gz"
	);
}
static void svir_1125(void) 
{
	svi_reg(&(tinfoil.validation_items[1124]),
	        "e13b30abf4a0fc45182dfe4cd81e66b9a5aacc2a2077159a7d82db5429ed9793e0fe744d1817119b9cbf9fd8fb6c3a5108c0b3742cb0c896238b4f936fdaeb6c",
	        "/usr/lib/kbd/keymaps/xkb/ba-unicodeus.map.gz"
	);
}
static void svir_1126(void) 
{
	svi_reg(&(tinfoil.validation_items[1125]),
	        "9200e2cd009ad485e40af427ea8185c5ca58968323d5fd15fd6988492beab98dafd573df1a182bb09b79689456908d3bc5d3ee342f6c2ecf7548065d905ba882",
	        "/usr/lib/kbd/keymaps/xkb/ba-unicode.map.gz"
	);
}
static void svir_1127(void) 
{
	svi_reg(&(tinfoil.validation_items[1126]),
	        "61d4879ebaba728daa37dcf9378e1da79b33dc5401e03eebb9715209657788bb0053003a88efb123022068558c191696ad8c7e4e0becb30241467356cadb03ef",
	        "/usr/lib/kbd/keymaps/xkb/ba-alternatequotes.map.gz"
	);
}
static void svir_1128(void) 
{
	svi_reg(&(tinfoil.validation_items[1127]),
	        "7c7a5ddf9d372029c1199d9d60aca7eee2452959af692a78163e30db184228e63f37ee86a7e14084c625b444922ae1e4bd2a2efc2b8921604db2e799673806b7",
	        "/usr/lib/kbd/keymaps/xkb/az.map.gz"
	);
}
static void svir_1129(void) 
{
	svi_reg(&(tinfoil.validation_items[1128]),
	        "bd67bf2aedfd1ab99b939738b574622356115939edf2d84588385a46da62a5cf60b47b10b2264e9284f8daeaa84ed446d57c551dfe85732bebff95cb82d3ed9a",
	        "/usr/lib/kbd/keymaps/xkb/at.map.gz"
	);
}
static void svir_1130(void) 
{
	svi_reg(&(tinfoil.validation_items[1129]),
	        "843e408eddf49e6d1856d409d9e34865421b19512ad4981807889ab0f2ebb73bca1ccc29d7c662cd0481556d6c75e2624bb8f75655e9b885c961b8101aea2dd0",
	        "/usr/lib/kbd/keymaps/xkb/at-nodeadkeys.map.gz"
	);
}
static void svir_1131(void) 
{
	svi_reg(&(tinfoil.validation_items[1130]),
	        "cdd7644f245c226e0b17b6ef55e7307c20419a727b65780ee287bcca8aa608a178c7cbbe1ee606ff59926f988bfd182c795e2460e193fd4bda5ca7671f39761d",
	        "/usr/lib/kbd/keymaps/xkb/at-mac.map.gz"
	);
}
static void svir_1132(void) 
{
	svi_reg(&(tinfoil.validation_items[1131]),
	        "3be4f60158229012c8237b550ce8b999de0bc8e3bf19194d409586835ab0421ee16a60b8bb90df53a62082cb1c836e871d5126b15aec3701a6d05a60552d3a88",
	        "/usr/lib/kbd/keymaps/xkb/al.map.gz"
	);
}
static void svir_1133(void) 
{
	svi_reg(&(tinfoil.validation_items[1132]),
	        "27b2977897054639ebd9ee308457dfa524ce01ee577130e61c6305af81a345667d805ac71864a03e9cdbaf00528f927ae02267bdced54209811261cd293f202d",
	        "/usr/lib/kbd/keymaps/xkb/al-plisi.map.gz"
	);
}
static void svir_1134(void) 
{
	svi_reg(&(tinfoil.validation_items[1133]),
	        "509f82b454c987b7ef53babc627e8ba943154514047b36fbe61856d2d5aef6ce5da2137809693a85af4e3d70ccbef28f093082d9241c4c846bc4a4a9a87949fb",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt6-uk.map.gz"
	);
}
static void svir_1135(void) 
{
	svi_reg(&(tinfoil.validation_items[1134]),
	        "03cae081b7f4000a67081c010f51e57fb0becb38195cd527838d4ca360671c8403204c592e9f4ce11e36158c908aaecb63524f79ffcc37c97948948fa32a48d9",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-us-cz.map.gz"
	);
}
static void svir_1136(void) 
{
	svi_reg(&(tinfoil.validation_items[1135]),
	        "e2faec494938269309b0fc6909f47e05f5054bc24c49a9b36021093b2937a8370af67743291f9b3252b526b400a51ef7c6e2e171ec12a415b34116fbbe1f642d",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-uk.map.gz"
	);
}
static void svir_1137(void) 
{
	svi_reg(&(tinfoil.validation_items[1136]),
	        "db966daf0082f3d578f156491f4b77faad6f97bc2d6106301420ca1c5564e956f7337d16577d676a791a1054233a0d66baec66291f3d6e532c28f0d2c1f2d714",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-ru.map.gz"
	);
}
static void svir_1138(void) 
{
	svi_reg(&(tinfoil.validation_items[1137]),
	        "0154e5ce036f7adab566c4b189d666a59cbdf0c54a41bd31a9dcf4ec0b7330467d27b67d44494316cd81efb16cf6b5f1f4c44578181d2674fe46454e31fccdc9",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-fr-latin1.map.gz"
	);
}
static void svir_1139(void) 
{
	svi_reg(&(tinfoil.validation_items[1138]),
	        "856f0dd65e007cdf32c372054151562e0209f412196fa647e84b8100cf5f74928ff70d1a959a7318fec3f4983a7d9587f7e7741686044dd20b5673b7395ae542",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-fi-latin1.map.gz"
	);
}
static void svir_1140(void) 
{
	svi_reg(&(tinfoil.validation_items[1139]),
	        "84007d2bf268c8fcfe5d435e27698dc8bfba6335a218ea016201fcc6d91dc79dd078386a371514b06fb9731e02cc3a02b08cc8e5ba3c2897710c14e288e34b1f",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-es.map.gz"
	);
}
static void svir_1141(void) 
{
	svi_reg(&(tinfoil.validation_items[1140]),
	        "0108012d8f1b370c1fa61f5a8be4d05651566d1833b9ee1c42ef7e0d8d46adadfc3d9b59afd413cfbe283ecb199336813b520ded357cd34bae24e7b733323c54",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-de-latin1.map.gz"
	);
}
static void svir_1142(void) 
{
	svi_reg(&(tinfoil.validation_items[1141]),
	        "b6e1e09984d32821d64da12d72be397aa2dca7c30c7ff0d0448eb43483c7f8603e9619e857363e12df55d0fe02a1e78b65dd7e0f2df94a5fcd4c9b719478544e",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt5-cz-us.map.gz"
	);
}
static void svir_1143(void) 
{
	svi_reg(&(tinfoil.validation_items[1142]),
	        "44536e72bd270dc212b770a1eecfea4a24fc1a9d76ca9380ea6f8ccb02008fa9f2506c49cc88ae317a81eb86c9910cfdede6e58a1b971ee75611c69c881e573a",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt4-no-latin1.map.gz"
	);
}
static void svir_1144(void) 
{
	svi_reg(&(tinfoil.validation_items[1143]),
	        "fa0c490528660f45585215f5edb51fde21e05c9967ddc3fa60bd555d39c0dc2a19946c8be364ad1666517afa71dee54374e03cf94de574466eea221ffad58d1b",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt4-fi-latin1.map.gz"
	);
}
static void svir_1145(void) 
{
	svi_reg(&(tinfoil.validation_items[1144]),
	        "d13cec16c795f722f9dcdad6a9eb82854109d82b03a2e6c1907a1ed20c0aa06f9a173c96d3dcb20fbb8af37bdeb5a6b3934ad34c96eaae3d85027838abd55383",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunt4-es.map.gz"
	);
}
static void svir_1146(void) 
{
	svi_reg(&(tinfoil.validation_items[1145]),
	        "89fad46965c5925b9e399648d777c3bdbfde9a0efd6ee25cb0bbac6972e87fc141b9f343ba88902f76619f7cb54cc8a6f942183913721cf729c16f69bbf28162",
	        "/usr/lib/kbd/keymaps/legacy/sun/sunkeymap.map.gz"
	);
}
static void svir_1147(void) 
{
	svi_reg(&(tinfoil.validation_items[1146]),
	        "d67d47aa1ab637ec67ab48152d56309b78e238ffb2c44a130d43a3a509f78ae099d3f6a4683b7b2e600422ce2fab8d7a8eeabe0260928f1a6ebc5402bf978c8a",
	        "/usr/lib/kbd/keymaps/legacy/sun/sundvorak.map.gz"
	);
}
static void svir_1148(void) 
{
	svi_reg(&(tinfoil.validation_items[1147]),
	        "19e72ea26d6b68e019b94b8ccee4fc33274560addc6b9ecddb2575e631498093e02f507c903c2bfb9d0d0bcf6010039d3c79b8fc71aa1ddadd2cef5417bfd60d",
	        "/usr/lib/kbd/keymaps/legacy/sun/sun-pl.map.gz"
	);
}
static void svir_1149(void) 
{
	svi_reg(&(tinfoil.validation_items[1148]),
	        "24fcb99c9ed9f16e1f5969135c5883059828638f2c60d39da2891b0fb8226a2c8ed3a1f97e35ec8f3456dcceefa83dd9099bb62c4595ac641d1046e0e97bdb46",
	        "/usr/lib/kbd/keymaps/legacy/sun/sun-pl-altgraph.map.gz"
	);
}
static void svir_1150(void) 
{
	svi_reg(&(tinfoil.validation_items[1149]),
	        "a8e62fd5de3b81e090556c5ab6c06f50d96ceb135d8b405af892b134eed6f93ac13f53007c51ee6afb476954d8f3929c164cca98e8cb0405217b3eddc3438bf4",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-qwertz-layout.inc"
	);
}
static void svir_1151(void) 
{
	svi_reg(&(tinfoil.validation_items[1150]),
	        "bc0828abec38a49b9c61dfcf9b18026c12c563ce50edb1309e62933ea05d4e5871676b922ed662501389ca62b846502d1c9e55b4e8f68359848bc97620838319",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-qwerty-layout.inc"
	);
}
static void svir_1152(void) 
{
	svi_reg(&(tinfoil.validation_items[1151]),
	        "30e622c060bc7424046cd818cfe7aa158842dd45e2e47ee476ac8daee5bd2a2ab6e357d40436254a46aee75e956b1f5ccd36bdc428f21afcfa0476e83cedcf14",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-linux-keys-bare.inc"
	);
}
static void svir_1153(void) 
{
	svi_reg(&(tinfoil.validation_items[1152]),
	        "e68519a333a2c7f8a1d1d46c674675ae9e3665815cc1cbbd236822c97967e1fd7bfc676420643579df2a0b47bbcfadf9b54417c97bcf116fde301a32da448ae5",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-euro2.map.gz"
	);
}
static void svir_1154(void) 
{
	svi_reg(&(tinfoil.validation_items[1153]),
	        "bb0b3f9121fd2eb3c609448cb6e126ca3777ff402c014146f429f2d30728eb8acb5e82de7df7da1a3ffb33df5c97be46f253ea730a74d1073db998a6815e60c8",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-euro.map.gz"
	);
}
static void svir_1155(void) 
{
	svi_reg(&(tinfoil.validation_items[1154]),
	        "a91d1649bc6c7c840ea912c01ecf6059b93eea67915b61e710910b44eb8785f323dd460265e1b9aa42f095e697e5c6888d857bf4727f452269f0f62e4fd0a637",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/mac-azerty-layout.inc"
	);
}
static void svir_1156(void) 
{
	svi_reg(&(tinfoil.validation_items[1155]),
	        "46762f4e2edaaf8c776c8508359b480e7c1a5388b753ad46ea2d96ee2fb1f4bdf6af7bdba9a02c628a68033d0c5d756418d5546894f18d9772740fd838eabf9d",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/apple-a1243-fn.inc"
	);
}
static void svir_1157(void) 
{
	svi_reg(&(tinfoil.validation_items[1156]),
	        "fec000ca5967a01deb02f52354fd9f05c41b9162d4deddaf32ecc5288eeaaaa54361f92b02ca5bdfcc400f611f357aa506d09ee93877b08749c6a76b70f16e9b",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/apple-a1243-fn-reverse.inc"
	);
}
static void svir_1158(void) 
{
	svi_reg(&(tinfoil.validation_items[1157]),
	        "5822f4e095f3f9a440eb491ced71cb9f1e583c0031620450b4fbe8feee6bde8d51573ad04f90577cd686e4748e8edbb91d34dac99fb5ea1803210eab5a86e153",
	        "/usr/lib/kbd/keymaps/legacy/ppc/include/apple-a1048-base.inc"
	);
}
static void svir_1159(void) 
{
	svi_reg(&(tinfoil.validation_items[1158]),
	        "c6380d3929c1375c9c3e880a3f5ce678a30e84a21e162730e068c3808634695e639a62740936c9c398efb9577e52a3cccf22ca4c44d1e018a76799b08e68f8ec",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-us.map.gz"
	);
}
static void svir_1160(void) 
{
	svi_reg(&(tinfoil.validation_items[1159]),
	        "3b2d8ae0863ddb11e0a1ffe7bde6327b55dde718cd04d7999e658ef6e290e6367395e9083eeacfe3b42d4a22457d834a434f5ca3babf8e8dedb65f2ae9c3a9ce",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-uk.map.gz"
	);
}
static void svir_1161(void) 
{
	svi_reg(&(tinfoil.validation_items[1160]),
	        "d666d315c623e58d80c51794a1c8af16baf0256f025dc9a4eb05e6d5211977bf30caf0ebf45ebe06c51d10a38c6923b040ccf6cf56d3f8f18edcb1e2e3764823",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-template.map.gz"
	);
}
static void svir_1162(void) 
{
	svi_reg(&(tinfoil.validation_items[1161]),
	        "ebc31af67ae9fa2034464b73c53ef321c8b9eb2121820f4f314c0aecafb2790c1467a4bba14e8ad21ef19216de8a46400bba235de0299e49e843be4f77552168",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-se.map.gz"
	);
}
static void svir_1163(void) 
{
	svi_reg(&(tinfoil.validation_items[1162]),
	        "1e8bf7e0f277301a11f8456c1fad6ffb629c0b2a708dade5a50b5108d8ce22922ac82b313864e9238c5e0bab98a74089d617eefac84af335298c0ed2189f3f5d",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-pt-latin1.map.gz"
	);
}
static void svir_1164(void) 
{
	svi_reg(&(tinfoil.validation_items[1163]),
	        "6df0bdf3268c108afed27f53b508bbf6b99d8cd92957c7f0e2d77c7fac44b14e9b35964e116ceab744fea0b0328b43d53fa0bb724fe6dbec512dab049c1bacbf",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-pl.map.gz"
	);
}
static void svir_1165(void) 
{
	svi_reg(&(tinfoil.validation_items[1164]),
	        "34cd911feda963011087ae00f70df61306eccd953c3ed670dd54164e31d57e3f8fa80c24cc1d7a481e1bd960cfe8e78ebdffdad23410fd4beb8590e6b71193c3",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-no-latin1.map.gz"
	);
}
static void svir_1166(void) 
{
	svi_reg(&(tinfoil.validation_items[1165]),
	        "1f199f865a5c3b624832d795787a68b23abb47d164929b843ef328489b74e29128a9ea0268f5f95b0b1bde215d92ac7b49039df1356a7a176f33c73adcb436d5",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-it.map.gz"
	);
}
static void svir_1167(void) 
{
	svi_reg(&(tinfoil.validation_items[1166]),
	        "42326e9148a20ccca371ec3bc5396dfb876a4b577b9db27a18f8577b872b5086050a1369dd873be8ba2e196c0a836a87a6b42538e1b95b3d235155743a71ed56",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-fr_CH-latin1.map.gz"
	);
}
static void svir_1168(void) 
{
	svi_reg(&(tinfoil.validation_items[1167]),
	        "115fdf098b98b7498772fac21e01ad9ff18d8ae19a9c8df4f98fe2e4213eb591431abc30d71079728bd3e19b4357f9817178f4bd613011de0d91041e5092ff4d",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-fr.map.gz"
	);
}
static void svir_1169(void) 
{
	svi_reg(&(tinfoil.validation_items[1168]),
	        "678cf6ea9da4000555a27f50b9479d81b59d7d3488e380bbbee53bb99889e5304c1cff9652e9dd9ec3aada7fb6497c2728612b1e3237f5abf80fbd98b3b01bde",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-fi-latin1.map.gz"
	);
}
static void svir_1170(void) 
{
	svi_reg(&(tinfoil.validation_items[1169]),
	        "627fa8384834d7decd712e7888d94e77a56759ec13df57299473f571a85a7f6e4f9717d7818002cb3874fd0b0d1f2fac64893859a170f26f6cc572009556bd15",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-es.map.gz"
	);
}
static void svir_1171(void) 
{
	svi_reg(&(tinfoil.validation_items[1170]),
	        "443a97851c4696eed295c669a18a70a8b0b7f669755e12dc7b96aceb388ea4fa1fe535dca917739140006cd5a21dd09fef0f19535afa99b1ad1a9cd53c302464",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-dvorak.map.gz"
	);
}
static void svir_1172(void) 
{
	svi_reg(&(tinfoil.validation_items[1171]),
	        "c926362b0a5c871b86f9250a162202b6957c7a054f456ef4dc233df9e15c2464f616cf3c54bac7b3ba984c8184d694327d59459f45734e85727c3d0e251642bd",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-dk-latin1.map.gz"
	);
}
static void svir_1173(void) 
{
	svi_reg(&(tinfoil.validation_items[1172]),
	        "b8adc3f319905449f8a6c0a645672dce3e5a6846905c5a4877aef11d32e737220428b91b9ad266e80578b60dffe58d0ca36717c0bc712176878e1df92520652d",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-de_CH.map.gz"
	);
}
static void svir_1174(void) 
{
	svi_reg(&(tinfoil.validation_items[1173]),
	        "8dffd123286fde92420208f7d5e0510ca3fd2372be78c663829b7c6fabdccc5f597fa4d8c1b148d4f277113a5b5f3bbd4f69a1ca3dde95468be6f0491c202f57",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-de-latin1.map.gz"
	);
}
static void svir_1175(void) 
{
	svi_reg(&(tinfoil.validation_items[1174]),
	        "99175827c1d6ee16200a8b2675eb53a9a5b81bf2c8933da788d39027777868a2c5852c1972c9dd8592276d5c01cfb2808ee169f4d3d9b5e4b1330cb25c26e21b",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-de-latin1-nodeadkeys.map.gz"
	);
}
static void svir_1176(void) 
{
	svi_reg(&(tinfoil.validation_items[1175]),
	        "88e588b98b6f45dff8b9277a390760e36051ca8030018116c2191f188766df26d9b74b940f20c8381418c04a441d766b6f77848b891995e8edb462f84b3b596b",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/mac-be.map.gz"
	);
}
static void svir_1177(void) 
{
	svi_reg(&(tinfoil.validation_items[1176]),
	        "60755ad88aace3e6e8f3d8ff91c2a9a4ba6d32bcd7b6e8f9cc827b212e1c5f8c3eb5b846943b4ef41097e16cb61b2426afc8240618a0e3514443379b23d9075f",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/apple-internal-0x0253-sv.map.gz"
	);
}
static void svir_1178(void) 
{
	svi_reg(&(tinfoil.validation_items[1177]),
	        "bf67fda9eec64f24abb9c810a2af4d75092f73735f7569c5b20fe018f7e78f56e6d1d827e23ca98180d0d884dc5b4224a387db08aaf8328e8d90013e1a8030d0",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/apple-internal-0x0253-sv-fn-reverse.map.gz"
	);
}
static void svir_1179(void) 
{
	svi_reg(&(tinfoil.validation_items[1178]),
	        "8b7a2d3fa18f7a906725cb89ebea02a07aed5113cc56fd3a097f627cae601fdee96a4301f197307fcf0df1cc3c4ea6df654b0e301042f5ec3acc18d7718e6a81",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/apple-a1243-sv.map.gz"
	);
}
static void svir_1180(void) 
{
	svi_reg(&(tinfoil.validation_items[1179]),
	        "b5ec777095da9d30740b6843c779f2faf32d8d744b550dbb0ab3b25ed01f6be43a0ff8cb885bd4817f94a05641a809313aac1bcfa0fcd5b6fcb1f2b2218fcdc4",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/apple-a1243-sv-fn-reverse.map.gz"
	);
}
static void svir_1181(void) 
{
	svi_reg(&(tinfoil.validation_items[1180]),
	        "3429335893094393f7508e32af4725efe17d0fcffb834aef4f3ed0acbfced96e93cbf6798431882fa92d7e87a73e8f31f226d81878090160367f41e34d9c02a8",
	        "/usr/lib/kbd/keymaps/legacy/ppc/all/apple-a1048-sv.map.gz"
	);
}
static void svir_1182(void) 
{
	svi_reg(&(tinfoil.validation_items[1181]),
	        "a8e62fd5de3b81e090556c5ab6c06f50d96ceb135d8b405af892b134eed6f93ac13f53007c51ee6afb476954d8f3929c164cca98e8cb0405217b3eddc3438bf4",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-qwertz-layout.inc"
	);
}
static void svir_1183(void) 
{
	svi_reg(&(tinfoil.validation_items[1182]),
	        "bc0828abec38a49b9c61dfcf9b18026c12c563ce50edb1309e62933ea05d4e5871676b922ed662501389ca62b846502d1c9e55b4e8f68359848bc97620838319",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-qwerty-layout.inc"
	);
}
static void svir_1184(void) 
{
	svi_reg(&(tinfoil.validation_items[1183]),
	        "30e622c060bc7424046cd818cfe7aa158842dd45e2e47ee476ac8daee5bd2a2ab6e357d40436254a46aee75e956b1f5ccd36bdc428f21afcfa0476e83cedcf14",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-linux-keys-bare.inc"
	);
}
static void svir_1185(void) 
{
	svi_reg(&(tinfoil.validation_items[1184]),
	        "e68519a333a2c7f8a1d1d46c674675ae9e3665815cc1cbbd236822c97967e1fd7bfc676420643579df2a0b47bbcfadf9b54417c97bcf116fde301a32da448ae5",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-euro2.map.gz"
	);
}
static void svir_1186(void) 
{
	svi_reg(&(tinfoil.validation_items[1185]),
	        "bb0b3f9121fd2eb3c609448cb6e126ca3777ff402c014146f429f2d30728eb8acb5e82de7df7da1a3ffb33df5c97be46f253ea730a74d1073db998a6815e60c8",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-euro.map.gz"
	);
}
static void svir_1187(void) 
{
	svi_reg(&(tinfoil.validation_items[1186]),
	        "a91d1649bc6c7c840ea912c01ecf6059b93eea67915b61e710910b44eb8785f323dd460265e1b9aa42f095e697e5c6888d857bf4727f452269f0f62e4fd0a637",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/mac-azerty-layout.inc"
	);
}
static void svir_1188(void) 
{
	svi_reg(&(tinfoil.validation_items[1187]),
	        "46762f4e2edaaf8c776c8508359b480e7c1a5388b753ad46ea2d96ee2fb1f4bdf6af7bdba9a02c628a68033d0c5d756418d5546894f18d9772740fd838eabf9d",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/apple-a1243-fn.inc"
	);
}
static void svir_1189(void) 
{
	svi_reg(&(tinfoil.validation_items[1188]),
	        "fec000ca5967a01deb02f52354fd9f05c41b9162d4deddaf32ecc5288eeaaaa54361f92b02ca5bdfcc400f611f357aa506d09ee93877b08749c6a76b70f16e9b",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/apple-a1243-fn-reverse.inc"
	);
}
static void svir_1190(void) 
{
	svi_reg(&(tinfoil.validation_items[1189]),
	        "5822f4e095f3f9a440eb491ced71cb9f1e583c0031620450b4fbe8feee6bde8d51573ad04f90577cd686e4748e8edbb91d34dac99fb5ea1803210eab5a86e153",
	        "/usr/lib/kbd/keymaps/legacy/mac/include/apple-a1048-base.inc"
	);
}
static void svir_1191(void) 
{
	svi_reg(&(tinfoil.validation_items[1190]),
	        "c6380d3929c1375c9c3e880a3f5ce678a30e84a21e162730e068c3808634695e639a62740936c9c398efb9577e52a3cccf22ca4c44d1e018a76799b08e68f8ec",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-us.map.gz"
	);
}
static void svir_1192(void) 
{
	svi_reg(&(tinfoil.validation_items[1191]),
	        "3b2d8ae0863ddb11e0a1ffe7bde6327b55dde718cd04d7999e658ef6e290e6367395e9083eeacfe3b42d4a22457d834a434f5ca3babf8e8dedb65f2ae9c3a9ce",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-uk.map.gz"
	);
}
static void svir_1193(void) 
{
	svi_reg(&(tinfoil.validation_items[1192]),
	        "d666d315c623e58d80c51794a1c8af16baf0256f025dc9a4eb05e6d5211977bf30caf0ebf45ebe06c51d10a38c6923b040ccf6cf56d3f8f18edcb1e2e3764823",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-template.map.gz"
	);
}
static void svir_1194(void) 
{
	svi_reg(&(tinfoil.validation_items[1193]),
	        "ebc31af67ae9fa2034464b73c53ef321c8b9eb2121820f4f314c0aecafb2790c1467a4bba14e8ad21ef19216de8a46400bba235de0299e49e843be4f77552168",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-se.map.gz"
	);
}
static void svir_1195(void) 
{
	svi_reg(&(tinfoil.validation_items[1194]),
	        "1e8bf7e0f277301a11f8456c1fad6ffb629c0b2a708dade5a50b5108d8ce22922ac82b313864e9238c5e0bab98a74089d617eefac84af335298c0ed2189f3f5d",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-pt-latin1.map.gz"
	);
}
static void svir_1196(void) 
{
	svi_reg(&(tinfoil.validation_items[1195]),
	        "6df0bdf3268c108afed27f53b508bbf6b99d8cd92957c7f0e2d77c7fac44b14e9b35964e116ceab744fea0b0328b43d53fa0bb724fe6dbec512dab049c1bacbf",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-pl.map.gz"
	);
}
static void svir_1197(void) 
{
	svi_reg(&(tinfoil.validation_items[1196]),
	        "34cd911feda963011087ae00f70df61306eccd953c3ed670dd54164e31d57e3f8fa80c24cc1d7a481e1bd960cfe8e78ebdffdad23410fd4beb8590e6b71193c3",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-no-latin1.map.gz"
	);
}
static void svir_1198(void) 
{
	svi_reg(&(tinfoil.validation_items[1197]),
	        "1f199f865a5c3b624832d795787a68b23abb47d164929b843ef328489b74e29128a9ea0268f5f95b0b1bde215d92ac7b49039df1356a7a176f33c73adcb436d5",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-it.map.gz"
	);
}
static void svir_1199(void) 
{
	svi_reg(&(tinfoil.validation_items[1198]),
	        "42326e9148a20ccca371ec3bc5396dfb876a4b577b9db27a18f8577b872b5086050a1369dd873be8ba2e196c0a836a87a6b42538e1b95b3d235155743a71ed56",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-fr_CH-latin1.map.gz"
	);
}
static void svir_1200(void) 
{
	svi_reg(&(tinfoil.validation_items[1199]),
	        "115fdf098b98b7498772fac21e01ad9ff18d8ae19a9c8df4f98fe2e4213eb591431abc30d71079728bd3e19b4357f9817178f4bd613011de0d91041e5092ff4d",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-fr.map.gz"
	);
}
static void svir_1201(void) 
{
	svi_reg(&(tinfoil.validation_items[1200]),
	        "678cf6ea9da4000555a27f50b9479d81b59d7d3488e380bbbee53bb99889e5304c1cff9652e9dd9ec3aada7fb6497c2728612b1e3237f5abf80fbd98b3b01bde",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-fi-latin1.map.gz"
	);
}
static void svir_1202(void) 
{
	svi_reg(&(tinfoil.validation_items[1201]),
	        "627fa8384834d7decd712e7888d94e77a56759ec13df57299473f571a85a7f6e4f9717d7818002cb3874fd0b0d1f2fac64893859a170f26f6cc572009556bd15",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-es.map.gz"
	);
}
static void svir_1203(void) 
{
	svi_reg(&(tinfoil.validation_items[1202]),
	        "443a97851c4696eed295c669a18a70a8b0b7f669755e12dc7b96aceb388ea4fa1fe535dca917739140006cd5a21dd09fef0f19535afa99b1ad1a9cd53c302464",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-dvorak.map.gz"
	);
}
static void svir_1204(void) 
{
	svi_reg(&(tinfoil.validation_items[1203]),
	        "c926362b0a5c871b86f9250a162202b6957c7a054f456ef4dc233df9e15c2464f616cf3c54bac7b3ba984c8184d694327d59459f45734e85727c3d0e251642bd",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-dk-latin1.map.gz"
	);
}
static void svir_1205(void) 
{
	svi_reg(&(tinfoil.validation_items[1204]),
	        "b8adc3f319905449f8a6c0a645672dce3e5a6846905c5a4877aef11d32e737220428b91b9ad266e80578b60dffe58d0ca36717c0bc712176878e1df92520652d",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-de_CH.map.gz"
	);
}
static void svir_1206(void) 
{
	svi_reg(&(tinfoil.validation_items[1205]),
	        "8dffd123286fde92420208f7d5e0510ca3fd2372be78c663829b7c6fabdccc5f597fa4d8c1b148d4f277113a5b5f3bbd4f69a1ca3dde95468be6f0491c202f57",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-de-latin1.map.gz"
	);
}
static void svir_1207(void) 
{
	svi_reg(&(tinfoil.validation_items[1206]),
	        "99175827c1d6ee16200a8b2675eb53a9a5b81bf2c8933da788d39027777868a2c5852c1972c9dd8592276d5c01cfb2808ee169f4d3d9b5e4b1330cb25c26e21b",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-de-latin1-nodeadkeys.map.gz"
	);
}
static void svir_1208(void) 
{
	svi_reg(&(tinfoil.validation_items[1207]),
	        "88e588b98b6f45dff8b9277a390760e36051ca8030018116c2191f188766df26d9b74b940f20c8381418c04a441d766b6f77848b891995e8edb462f84b3b596b",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/mac-be.map.gz"
	);
}
static void svir_1209(void) 
{
	svi_reg(&(tinfoil.validation_items[1208]),
	        "60755ad88aace3e6e8f3d8ff91c2a9a4ba6d32bcd7b6e8f9cc827b212e1c5f8c3eb5b846943b4ef41097e16cb61b2426afc8240618a0e3514443379b23d9075f",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/apple-internal-0x0253-sv.map.gz"
	);
}
static void svir_1210(void) 
{
	svi_reg(&(tinfoil.validation_items[1209]),
	        "bf67fda9eec64f24abb9c810a2af4d75092f73735f7569c5b20fe018f7e78f56e6d1d827e23ca98180d0d884dc5b4224a387db08aaf8328e8d90013e1a8030d0",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/apple-internal-0x0253-sv-fn-reverse.map.gz"
	);
}
static void svir_1211(void) 
{
	svi_reg(&(tinfoil.validation_items[1210]),
	        "8b7a2d3fa18f7a906725cb89ebea02a07aed5113cc56fd3a097f627cae601fdee96a4301f197307fcf0df1cc3c4ea6df654b0e301042f5ec3acc18d7718e6a81",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/apple-a1243-sv.map.gz"
	);
}
static void svir_1212(void) 
{
	svi_reg(&(tinfoil.validation_items[1211]),
	        "b5ec777095da9d30740b6843c779f2faf32d8d744b550dbb0ab3b25ed01f6be43a0ff8cb885bd4817f94a05641a809313aac1bcfa0fcd5b6fcb1f2b2218fcdc4",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/apple-a1243-sv-fn-reverse.map.gz"
	);
}
static void svir_1213(void) 
{
	svi_reg(&(tinfoil.validation_items[1212]),
	        "3429335893094393f7508e32af4725efe17d0fcffb834aef4f3ed0acbfced96e93cbf6798431882fa92d7e87a73e8f31f226d81878090160367f41e34d9c02a8",
	        "/usr/lib/kbd/keymaps/legacy/mac/all/apple-a1048-sv.map.gz"
	);
}
static void svir_1214(void) 
{
	svi_reg(&(tinfoil.validation_items[1213]),
	        "c740f69c11398294b7c27522ae1931736d1a0633a994d4084c54766c070ff2340f5e3f07884c0791279f540c09becfd255f15249d383feb21bce9a884aebc7d9",
	        "/usr/lib/kbd/keymaps/legacy/include/vim-compose.latin1"
	);
}
static void svir_1215(void) 
{
	svi_reg(&(tinfoil.validation_items[1214]),
	        "0a51c422b3073998ba3c7b50df7b4088e7dee93d855ef91668395dbd7a1e2e6b8d06ac9bb6a3fb7c8e80d945b9bdc92465e18bee04e6b1e3312c324db9c0666e",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.latin4"
	);
}
static void svir_1216(void) 
{
	svi_reg(&(tinfoil.validation_items[1215]),
	        "0ad3ade713fb9cb3831b6d785652afa379ddad546093f75e16cc1da5b85f518b92ed64b9088c7a6dd12854eff1926c64e9731be388d65b897740f20beb1ef793",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.latin3"
	);
}
static void svir_1217(void) 
{
	svi_reg(&(tinfoil.validation_items[1216]),
	        "32aaf2dfe9575be63dff64f7aca8b8fa7bdccb871849ce00c87c175a6380bc9dcb15cd1389babc3f1f987fbfe5ce3c4357c73cb0f5ac56ae6885fe27b1cc3155",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.latin2"
	);
}
static void svir_1218(void) 
{
	svi_reg(&(tinfoil.validation_items[1217]),
	        "8fc7a2831db729c846918efb6e42f70860aa12b054a6d783ae357e850a60e9ff09276bf629f0e59b4066daa38e8fcab7d7cc613102b97b053cbc378f5f4af788",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.latin1"
	);
}
static void svir_1219(void) 
{
	svi_reg(&(tinfoil.validation_items[1218]),
	        "ae52ad7d7383a8bfb19d4a8c57d3045db0d03251da0c075ee96c23f368aa87d3e65da622e04114ce069cd276e232ec72843075e8175dce279375c577817c8d3a",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.latin"
	);
}
static void svir_1220(void) 
{
	svi_reg(&(tinfoil.validation_items[1219]),
	        "e46589592ee8a6db1187aa07a0ab5297ee956cd58f7435daca9346051819468603bea96235c53e622411dedaa659f8039ae1b5de2b5a5ad71e2a9bf74d55f1c0",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.8859_8"
	);
}
static void svir_1221(void) 
{
	svi_reg(&(tinfoil.validation_items[1220]),
	        "b30abf2f182d5ae0daf50df0ff4e6e3281a0852f65a21793e78942ea3fcc80ded91fc208154fb22f22c9b3db3bfa6bdab0f23317db68579b2958ac10c8b13404",
	        "/usr/lib/kbd/keymaps/legacy/include/compose.8859_7"
	);
}
static void svir_1222(void) 
{
	svi_reg(&(tinfoil.validation_items[1221]),
	        "dd87cc0238619813b511b8a402077f95be7268edd0d8c17b66a2a69734bd85f79953bfe7b3a898b61d850925a9594ff537daf1ca2a7047974a537157a4a89cfa",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/slovene.map.gz"
	);
}
static void svir_1223(void) 
{
	svi_reg(&(tinfoil.validation_items[1222]),
	        "dd87cc0238619813b511b8a402077f95be7268edd0d8c17b66a2a69734bd85f79953bfe7b3a898b61d850925a9594ff537daf1ca2a7047974a537157a4a89cfa",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sr-latin.map.gz"
	);
}
static void svir_1224(void) 
{
	svi_reg(&(tinfoil.validation_items[1223]),
	        "c13ba5ae9d54ec93a3d61ba4db17d988e27b71cb2b13fbb65fec6ecb2fbdfd1066a1306a6135299c0befe587b3b4c9de423c3443f2aebbe559dd4e230716517f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sk-qwertz.map.gz"
	);
}
static void svir_1225(void) 
{
	svi_reg(&(tinfoil.validation_items[1224]),
	        "2dd09974db8746389cbeb1e7bf231c806c65322800d9ac140ec297cb3c0243c18eed5c1834675c298a8b3d814dbb34f85b86146c257267d5252076d0bd6e2d9c",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sk-prog-qwertz.map.gz"
	);
}
static void svir_1226(void) 
{
	svi_reg(&(tinfoil.validation_items[1225]),
	        "d93a82465886c601982e4b6c68ebdb98f055d8297405bd576c269050cd6189b74e1388884c39230bb8ce956fa83f33b874208daf77c5b110b88c9fd516e67cba",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sg.map.sg-decimal-separator"
	);
}
static void svir_1227(void) 
{
	svi_reg(&(tinfoil.validation_items[1226]),
	        "52cce2c8d7380cf3cd65f3056c2622d7f99a3faefee75e6bf753539d7d9d7acc6010c19c11406f206e971d93dc2e9c06f791600889ec07dd6a5e11c72400506b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sg.map.gz"
	);
}
static void svir_1228(void) 
{
	svi_reg(&(tinfoil.validation_items[1227]),
	        "3a1279ab496cf1b6fcfb6425f7f06a2fc48fbb9b7c030f8c221d1c11feee0aae5d9560bf2504a7d288c9af57a03e9c00002131088d775bb21ff402749729599c",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sg-latin1.map.gz"
	);
}
static void svir_1229(void) 
{
	svi_reg(&(tinfoil.validation_items[1228]),
	        "d3be72a5695d83b61c8404132015cc19294cb28dcf32af8a3d341f542ba0e0f8b9c19e4983bad8b5ddbcffcd394ecc837336c95287a63bf305b9e6196cc4114b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/sg-latin1-lk450.map.gz"
	);
}
static void svir_1230(void) 
{
	svi_reg(&(tinfoil.validation_items[1229]),
	        "26ed6b026bd7ea2e2b0fe8a873d75f97d31101ea60707c7781d4f610d32495e8cd53a6e6a195b1b7653809d984917af4c8e94c9f632fa1b4e04ee95cd29f738c",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/hu.map.gz"
	);
}
static void svir_1231(void) 
{
	svi_reg(&(tinfoil.validation_items[1230]),
	        "7db6227cd32efafd0d5d58c2953cbf6078d01ca6e9368668de4921cf44bf8d6ffac066624967ddbb843f89471416c89b2b0b99dfb6c3c4a3c499e78ad316f76f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/fr_CH.map.gz"
	);
}
static void svir_1232(void) 
{
	svi_reg(&(tinfoil.validation_items[1231]),
	        "1cd09d147e9e3eea14d876ff27b8abdab033520d6fa692cb9cdbcb984b9d9c60b75d69e56eae5cb07a353ffaa9c78952184d334abac448ba62251546c194b9d1",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/fr_CH-latin1.map.gz"
	);
}
static void svir_1233(void) 
{
	svi_reg(&(tinfoil.validation_items[1232]),
	        "1e938e25d9606f9455504182003c13bbe2fa1395821d84d152e2eca1ef7c2ab10abe01487b43c0bb72490b2b5558cca78f4585468ec63fb2cf48396d9c8a4d8a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de_alt_UTF-8.map.gz"
	);
}
static void svir_1234(void) 
{
	svi_reg(&(tinfoil.validation_items[1233]),
	        "fba09d97b9e20946f9bf089fda8827b8a2ff1f2d32752758e43d0089a726619af6fc09cca652519d2a25947b9e29e6ff452ae3a338a8b90825f0ded3f4943392",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de_CH-latin1.map.gz"
	);
}
static void svir_1235(void) 
{
	svi_reg(&(tinfoil.validation_items[1234]),
	        "1facb1ab34e7c3ba7a1d66bf1bae30f6949da805e4d61a2d7112c0dd180df96d6151f7e23424cabfbd61e50769b1a6389e066919f9e9a709ab055a237fd00edd",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de.map.gz"
	);
}
static void svir_1236(void) 
{
	svi_reg(&(tinfoil.validation_items[1235]),
	        "12e154fb22062410ec106c3ed439151d5f1a4d51d20bc9f577f350304201d7321de929ad49df9e3a3b18b8a774cfbbaef4c612d6dc0abdca0df0ef7184f8a9e7",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de-mobii.map.gz"
	);
}
static void svir_1237(void) 
{
	svi_reg(&(tinfoil.validation_items[1236]),
	        "50d3e98281b563c53a51246f133ae8632849fba841ea37a26afaf108e3270be4657390fc3a59be8240c2c1af7aa9551433f1e149d38fa681c9d19dc0ad7ceede",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de-latin1.map.gz"
	);
}
static void svir_1238(void) 
{
	svi_reg(&(tinfoil.validation_items[1237]),
	        "86a19e6594b341d208ca61e4960c98d24d707dec73440e6995a9b14fe57ed53939062b2cde7833d34c15490e9fe528a3c6e1250338ea771e5f10f9af123af749",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/de-latin1-nodeadkeys.map.gz"
	);
}
static void svir_1239(void) 
{
	svi_reg(&(tinfoil.validation_items[1238]),
	        "d1969b232975f7e0e503bcfb878f35eeeb05ac921ab9f66c21fb250ae7d9f4a46e1486c433b6e7f2dfffcc4bc5647545fe52d4dd031dd2d9133259d8fdfe93ee",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/cz.map.gz"
	);
}
static void svir_1240(void) 
{
	svi_reg(&(tinfoil.validation_items[1239]),
	        "47ff47a5c8af91ce3ed02b25175ce2d63ed520ee92ddefbc5af5115841e6b882e75f01e64138d3da742977f014d68afe8845070b025b366219c106a17ac1eaf4",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/cz-us-qwertz.map.gz"
	);
}
static void svir_1241(void) 
{
	svi_reg(&(tinfoil.validation_items[1240]),
	        "eb0f7886dc81392d18f2fd4a93869f2ff4ff03538d27de7b884b4d0db8c01d775b069fea4a3e2c144311b6f1f8d3cb8f962b9c523495b85afaa88ac823f671ba",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwertz/croat.map.gz"
	);
}
static void svir_1242(void) 
{
	svi_reg(&(tinfoil.validation_items[1241]),
	        "914bacff065018f3848a5ccbf5f04f4620281282d680ab31e8a1206745e90623ad7a5fce218aaacf57cf7bdcf2dc080ebabe358dd4b9e90da5f0edb140d12efb",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/us1.map.gz"
	);
}
static void svir_1243(void) 
{
	svi_reg(&(tinfoil.validation_items[1242]),
	        "cb79d7b3e681daf4381e29dfb7455b2bcea5c64b2c785eba97c954d9b286a1133eb54d9950e6193fb7d1edb50df0085cfd4c6c5452fc3c0a6044f08ceff0081a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ko.map.gz"
	);
}
static void svir_1244(void) 
{
	svi_reg(&(tinfoil.validation_items[1243]),
	        "cb79d7b3e681daf4381e29dfb7455b2bcea5c64b2c785eba97c954d9b286a1133eb54d9950e6193fb7d1edb50df0085cfd4c6c5452fc3c0a6044f08ceff0081a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/us.map.gz"
	);
}
static void svir_1245(void) 
{
	svi_reg(&(tinfoil.validation_items[1244]),
	        "c2a14c8a64a61ef0cb3127ea3266d121aa34fda024610c8f7662576dc2b9866463dffc611d6d1ed1b07b7e289e108eb340a7bce7e716ee97481a7c02a212a9e4",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/us-acentos.map.gz"
	);
}
static void svir_1246(void) 
{
	svi_reg(&(tinfoil.validation_items[1245]),
	        "a3a3b0a50a18185f49aacc519f56b5de072dd4e350fa79e29bc46f8566d12aa7fd5b64119e23e9dbd593a9196eb4a75947e25c0866c4e8bb7138095b61f003a8",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/uk.map.gz"
	);
}
static void svir_1247(void) 
{
	svi_reg(&(tinfoil.validation_items[1246]),
	        "ab4106eeb92dbd02b5da179f11bd0c7115f675e1c5bcb05a8a21657619935b86274736f585ad9e7ec47856e9069798c40aae85ed9fc40becb6b7a9c498772f15",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ua.map.gz"
	);
}
static void svir_1248(void) 
{
	svi_reg(&(tinfoil.validation_items[1247]),
	        "d1f812c2479377ef28c2a9e0a24bdae69fd7c433f6c35dc233a063e119f37e495203fb9f24e698ba3aa481b3fb7c717a721833eb252df23a6087bf1c8d2ee562",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ua-ws.map.gz"
	);
}
static void svir_1249(void) 
{
	svi_reg(&(tinfoil.validation_items[1248]),
	        "7b741b5f1b240b79b84b838e01838d9ab9e75dd25aaf0e31061378cc15f0fc089be3a9c0a78965166f4f5089dba091a60d510cb68958bee0e23c596515bf997a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ua-utf.map.gz"
	);
}
static void svir_1250(void) 
{
	svi_reg(&(tinfoil.validation_items[1249]),
	        "ce888dec6447f75cc7460b92b63ac34eb63a4d85dc5777a1c0f515dd137f673e198ca0774c0b078831ea17daf8f7d92be4f9aa286053e05fe7f9fa3817155699",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ua-utf-ws.map.gz"
	);
}
static void svir_1251(void) 
{
	svi_reg(&(tinfoil.validation_items[1250]),
	        "354b2b63ec2a7569d51e1c347b3e5ecf13ec68eada4ac7f68d1fb21d05ac2e9018ce856a6e2dcdd329a384ae59b965daa6495ea949f670455a1aeb608b789a72",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ua-cp1251.map.gz"
	);
}
static void svir_1252(void) 
{
	svi_reg(&(tinfoil.validation_items[1251]),
	        "da9ff3f7c06f055db0d7bf2be0e2d1b7a08837fd535597a30ae77f868c8cdee90e87b287bb96f69e21fbdb41ccdae8225e2d99e48a83635151caab34eca8d54a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ttwin_ctrl-UTF-8.map.gz"
	);
}
static void svir_1253(void) 
{
	svi_reg(&(tinfoil.validation_items[1252]),
	        "d276721f2c186a41b228629db735459fa26bf3186b393b3e88e26ea9f6d1d1222676239a785b6fda915af35ae0f4157e6636324c404a2eac675601689d3c3fb8",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ttwin_ct_sh-UTF-8.map.gz"
	);
}
static void svir_1254(void) 
{
	svi_reg(&(tinfoil.validation_items[1253]),
	        "ca9b239d85f7e1000eed6eacbe2916a56bfc72b1caaac5f28b1381356e252e74d02406f70e27aac2b523231886bef361142b269588c285ebe395293a86857b32",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ttwin_cplk-UTF-8.map.gz"
	);
}
static void svir_1255(void) 
{
	svi_reg(&(tinfoil.validation_items[1254]),
	        "1273b8d0f36fba928ba91559562330e5fae248571e855e0e56216be5554ca6cd9d6632b24d08ce950a8089ac2235b9bc9554297b135cabc98cd9a4914a157e9f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ttwin_alt-UTF-8.map.gz"
	);
}
static void svir_1256(void) 
{
	svi_reg(&(tinfoil.validation_items[1255]),
	        "ebf13d0a351ba2fcf63978fe2ed4b5825928855651339039a5f80f22614c22075391e726a1c8405d333c2adca986f6c6d496ddf47d604090c95101c3c3d86adb",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/trq.map.gz"
	);
}
static void svir_1257(void) 
{
	svi_reg(&(tinfoil.validation_items[1256]),
	        "0dde1f0df37715896c6bdad1319cde6263c1433f3ed7e9e35d115213d2919abcb5dd4c8cf437a44044d82b0e56ffadd9b4d21a9507ee38e2ba552ff07a0cb311",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/trf.map.gz"
	);
}
static void svir_1258(void) 
{
	svi_reg(&(tinfoil.validation_items[1257]),
	        "d668de2b47aff4edb22a36dc2982298c697a33387e2976ec527e7342120892d64f8123c9d1c7c48fe9feadec955a8d24c5f63f589621a28241914a9dfcda2936",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/tralt.map.gz"
	);
}
static void svir_1259(void) 
{
	svi_reg(&(tinfoil.validation_items[1258]),
	        "6b606b60b7cd2ac5ad39f519a177196f663ce27cb724e1705ca1f4453e4bbda67219f6ced6af2f52ac4b12c955b69e474d5f8366f82db7e092321b5f9083dddc",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/tr_q-latin5.map.gz"
	);
}
static void svir_1260(void) 
{
	svi_reg(&(tinfoil.validation_items[1259]),
	        "9b8728cb67ab5157623f905c5dfb928a800c013776d4e79bafb8de4ad11d2d9cb66e4a4ce03debb13d1add5c1fe7256530b659b26275aed0047f0a94827a8b6b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/tj_alt-UTF8.map.gz"
	);
}
static void svir_1261(void) 
{
	svi_reg(&(tinfoil.validation_items[1260]),
	        "537d436cb770e89c85c06922e285e539c28140559cdaf12b03dc14cbd88e72a138d52c1a52081efbdc9096e459103dceadbf933858057142dc4df4c5b8fb764f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/se-latin1.map.gz"
	);
}
static void svir_1262(void) 
{
	svi_reg(&(tinfoil.validation_items[1261]),
	        "537d436cb770e89c85c06922e285e539c28140559cdaf12b03dc14cbd88e72a138d52c1a52081efbdc9096e459103dceadbf933858057142dc4df4c5b8fb764f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/sv-latin1.map.gz"
	);
}
static void svir_1263(void) 
{
	svi_reg(&(tinfoil.validation_items[1262]),
	        "a06a8db44b45e9f77a1ae832d0b062b34092abcbcff7e52402ae50b5112b05eeb608015e68bc619f20163a3c50fb1a1e9be40d58d3403e1017c3071ab04520a2",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/sr-cy.map.gz"
	);
}
static void svir_1264(void) 
{
	svi_reg(&(tinfoil.validation_items[1263]),
	        "a06a8db44b45e9f77a1ae832d0b062b34092abcbcff7e52402ae50b5112b05eeb608015e68bc619f20163a3c50fb1a1e9be40d58d3403e1017c3071ab04520a2",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/sr-latin.map.gz"
	);
}
static void svir_1265(void) 
{
	svi_reg(&(tinfoil.validation_items[1264]),
	        "3427ee6ba24c262aa9449ae45cda9d3787d34c0943f2d7ea72b36f30eb91eec3f48930d01cec4da1cd90d5367156efe01d3acdbcb57ee1ac26fbaf8533ef6b6f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/sk-qwerty.map.gz"
	);
}
static void svir_1266(void) 
{
	svi_reg(&(tinfoil.validation_items[1265]),
	        "f3b5e0b4c4864b098e9da806f24e8e9d9f0ad612d36af2638bc9399de7b754db842ea5c5c242ff12ed3a37eb800a4683bff5bf7d79f36b3f44efc0fd71b19646",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/sk-prog-qwerty.map.gz"
	);
}
static void svir_1267(void) 
{
	svi_reg(&(tinfoil.validation_items[1266]),
	        "07df3831785c0d45503280aba1b7c4376880387479838bd76de364a5f9ebc7cad0413acf90612a6e9d47a73e47c2d1d745781cb409f8ecd143e7b046fc4c1e39",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/se-lat6.map.gz"
	);
}
static void svir_1268(void) 
{
	svi_reg(&(tinfoil.validation_items[1267]),
	        "22aad3195ad4d12d72cab8e17e3ef9da1015018cf7069d89fea32a1f8844e5673846b01dc39a768d7d60881188ac8d7cd19fd4dc3dd760ac0f57c40b8e43d3c8",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/se-ir209.map.gz"
	);
}
static void svir_1269(void) 
{
	svi_reg(&(tinfoil.validation_items[1268]),
	        "168d180d967624906fd266ef25e946cc8a9346b5368e67c1b1ba7b602c7bcfd414780d6c0be16e3df34f946aa6a61b7f8fd736c28d4827ab8708e8f36163f104",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/se-fi-lat6.map.gz"
	);
}
static void svir_1270(void) 
{
	svi_reg(&(tinfoil.validation_items[1269]),
	        "09fc354c6872010378b91499e351f9dd559d5b22e4857b30a40dec8c8ac423d72e7a7d3f436e47a797d47216b0377f9c289309ab5fb10c0c1684b1e6c15a5825",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/se-fi-ir209.map.gz"
	);
}
static void svir_1271(void) 
{
	svi_reg(&(tinfoil.validation_items[1270]),
	        "2a74ba681f88dac1dfe043b5dadb663461d3fefc64e5691d27b32fddf11553858dfe910d631a327a9203dab52d7fed42dee50c7673d68671149ac41fabc505f5",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ctrl-UTF-8.map.gz"
	);
}
static void svir_1272(void) 
{
	svi_reg(&(tinfoil.validation_items[1271]),
	        "c7c5d9e7b43e3bc7110c2e7d6a544eb18b8994c4fa5863d415a9d909dfbb11cbf116c17b6ec1a36282d41014f2f56f71f65cbf4436598e053e92436069ef7534",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ctrl-KOI8-R.map.gz"
	);
}
static void svir_1273(void) 
{
	svi_reg(&(tinfoil.validation_items[1272]),
	        "22d4dc1be7d63e6be09679a077fc1089fb06b14475c82c5507bd139cc888f61abf86d0cd8294a4f12fb2d308c3c0957b3a807c03e7ed6129cd909cd2994ad7ee",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ctrl-CP1251.map.gz"
	);
}
static void svir_1274(void) 
{
	svi_reg(&(tinfoil.validation_items[1273]),
	        "70946e630b2d65633d8d282b1bdb26606637102dbc11f4db62384134b5ce25db0762c343926cf1410210d0c87a1d4f7a60359548b77782caa458800ee05db4b5",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ct_sh-UTF-8.map.gz"
	);
}
static void svir_1275(void) 
{
	svi_reg(&(tinfoil.validation_items[1274]),
	        "b01dc5500164f54cc3c40a23877fc3ddb698fd851efccc9879c9c77103290d5d5198a2032e8a4c7e2c2b1f067b723bb6266ca2925bda5d0cc8d90d9fdefbda62",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ct_sh-KOI8-R.map.gz"
	);
}
static void svir_1276(void) 
{
	svi_reg(&(tinfoil.validation_items[1275]),
	        "c4b7331c6f76167dd6e6e8241e8bfc561e8801e86ee625d83bf7a3b861b72f1a6c02479ba38449c7aba83db90a55654a793e24b47be96015651e793b4333898c",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_ct_sh-CP1251.map.gz"
	);
}
static void svir_1277(void) 
{
	svi_reg(&(tinfoil.validation_items[1276]),
	        "bb700d174eac61a8aa1be05e809e3970d6a9a01a0103f6dacd66ecb2fa75debf02c491d94210db9e5e07bb93d5f9ecf70a5a501b0a324b11c176e99da057f402",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_cplk-UTF-8.map.gz"
	);
}
static void svir_1278(void) 
{
	svi_reg(&(tinfoil.validation_items[1277]),
	        "da7b41e87cb8db72a378a5e3c5e770cf4ba701dc55ea2506aa86c96cd881503073c71a3fc361d25674daef4cfd78abe81eab1bcabda8f67e28746d417e67a80b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_cplk-KOI8-R.map.gz"
	);
}
static void svir_1279(void) 
{
	svi_reg(&(tinfoil.validation_items[1278]),
	        "fbd4f4ee9c0cde0dc83128c51df7d66eb60c0ec1577513ae7583342e70466201bb74ce5055cea5312a50f491de3b52c7d3da1023b6c048c594eaf35d86e60a6f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_cplk-CP1251.map.gz"
	);
}
static void svir_1280(void) 
{
	svi_reg(&(tinfoil.validation_items[1279]),
	        "86524ad71b9c4dc762aa6f93a7a3d11a221a95fb32e17c15fce9629674f2176db0ae974333d0db0991d785ee57c6b955035f02538e20e082f7b3b3221a9ca4fe",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_alt_sh-UTF-8.map.gz"
	);
}
static void svir_1281(void) 
{
	svi_reg(&(tinfoil.validation_items[1280]),
	        "b803b76f3598d3ae1f030b5d1668c78addbeb5d3bcd8305144978570bf1c28d2a7554effb4bd32ea161e9f897c76592598ee8ffe2f357be83f5e402a60056c04",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_alt-UTF-8.map.gz"
	);
}
static void svir_1282(void) 
{
	svi_reg(&(tinfoil.validation_items[1281]),
	        "a9ea8d86031525a9f2107ddf05f712aecf7a1c518ef0bf9cc675aabf7f548e3267e3f127de6bf3efb6c5edbcb8e1d5afb9c889456b4fdba93f18c1655032a906",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_alt-KOI8-R.map.gz"
	);
}
static void svir_1283(void) 
{
	svi_reg(&(tinfoil.validation_items[1282]),
	        "ccb369c87131f80533d5d185f964176997ce671703510d4bee03c2ab357656ebdf5e32ee1059633f3715db4741c3fb44904bf21b07d53e94a0300582c062ee22",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ruwin_alt-CP1251.map.gz"
	);
}
static void svir_1284(void) 
{
	svi_reg(&(tinfoil.validation_items[1283]),
	        "d06419959d43db3d54efeef965f1e264684f138f70d0cada798acc67e66be736a4e60bab646daf2d5e94f4b065177f74491e2cb58ae2230e7027441b886b4e03",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru_win.map.gz"
	);
}
static void svir_1285(void) 
{
	svi_reg(&(tinfoil.validation_items[1284]),
	        "cb2b63c43c7ed69494599857e9f9c44bb9da26693ec30acf03bad651b7633bbe43833380f303b4b15131218434ffcb81b781a7475571a5752d833492b7cf9b83",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru4.map.gz"
	);
}
static void svir_1286(void) 
{
	svi_reg(&(tinfoil.validation_items[1285]),
	        "56de4e96418684023ae60cbffb8f0adc3a32df72ed93e5083f97d64c11bec80309f35df7a9a8dfd7e33bfd713363173de4e9253b3ff2802aaefc8a233ecde020",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru3.map.gz"
	);
}
static void svir_1287(void) 
{
	svi_reg(&(tinfoil.validation_items[1286]),
	        "91d88c02dc82b287d5d83e0ffb28b5192e635cdcf99ab207253b17dcb17e0419b8c47962c6c8546768d24ba6643de02bc694053ebfe658f6867d92262c1545d5",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru2.map.gz"
	);
}
static void svir_1288(void) 
{
	svi_reg(&(tinfoil.validation_items[1287]),
	        "ebde78408247d02927860efbbb7c970cfc2614473ceda2ecfb5fda726b5601ab9631da03439c1efa353cfe75d72c67a2bceaa533a64e656baa843a951667626e",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru1.map.gz"
	);
}
static void svir_1289(void) 
{
	svi_reg(&(tinfoil.validation_items[1288]),
	        "ecb8ba861d4908baf37d9fd0c43e85d4e49353b7b3c894adabcf38fd69a1caa457256ba316e79b43395484a87b9ff0a5629414b2bf54e58af0bfff70315e206a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru.map.gz"
	);
}
static void svir_1290(void) 
{
	svi_reg(&(tinfoil.validation_items[1289]),
	        "da720187f939277789ee45edf1dc647412cae9af36c126dfae035a80214cb3087700f906e8f140b4de2bcb139a355d635a6a1408e631c23d1be0e83cfcb83648",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru-yawerty.map.gz"
	);
}
static void svir_1291(void) 
{
	svi_reg(&(tinfoil.validation_items[1290]),
	        "bf08453f1d77047fc99104e9750bdc2a2b396801d448fc9e6aa7c620500d46d063a58507e1154f8693b4af90889882eb7a07e088a98646ce4463f60851eeba26",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru-ms.map.gz"
	);
}
static void svir_1292(void) 
{
	svi_reg(&(tinfoil.validation_items[1291]),
	        "5d233a97929781f0ceabb92a8d0bc14a407268dca6577ccf937d380849b52ae08eb225833780043cd86a265ba502caccfe4948f6e5970ecd1f5f54e1d04f1f2b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ru-cp1251.map.gz"
	);
}
static void svir_1293(void) 
{
	svi_reg(&(tinfoil.validation_items[1292]),
	        "9b0d5457945fe203c43a43ef4734ca32d5ec86c403a7fc917e2cd37405e07bd2ab8b9d433d8a92f267683e3bceff3610073ed27e9d7a105003956232dbf35d11",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ro_std.map.gz"
	);
}
static void svir_1294(void) 
{
	svi_reg(&(tinfoil.validation_items[1293]),
	        "f4350497f7af8a74fa3c611e3426b802602f8db4e78996bd99ac62b731b0ed437333f0e4cc50b5be2f877cabce80ec8373705dfc92df5921e2b6e403109cbdec",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ro.map.gz"
	);
}
static void svir_1295(void) 
{
	svi_reg(&(tinfoil.validation_items[1294]),
	        "0a30e2f19159bd43fba8513142d2a389f717a6b9039b77f12181428dbf4bcf0310612d5771dcb4af1a73b4b37cacfaa69a4ebd7e7d0b9556c21ff8872ae36867",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pt-latin9.map.gz"
	);
}
static void svir_1296(void) 
{
	svi_reg(&(tinfoil.validation_items[1295]),
	        "0a30e2f19159bd43fba8513142d2a389f717a6b9039b77f12181428dbf4bcf0310612d5771dcb4af1a73b4b37cacfaa69a4ebd7e7d0b9556c21ff8872ae36867",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pt.map.gz"
	);
}
static void svir_1297(void) 
{
	svi_reg(&(tinfoil.validation_items[1296]),
	        "22e249afb3f35cd45a9b41cbc06329ede10ea9f25e2eefc1f366880f5234f39233a406597dc85219e142fc24ee4f188fb211ca144e8da020c8ce6981dc37baad",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pt-latin1.map.gz"
	);
}
static void svir_1298(void) 
{
	svi_reg(&(tinfoil.validation_items[1297]),
	        "d7d8fd555902967cd18f9aef5c85bd1f2cea67f8e5ce8a82dd6d8c787e3ae8f68c236ccdf7e9b30dfb27aa8e28851ece3cd3661cc0f30a95e8701e8d7538a569",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pl4.map.gz"
	);
}
static void svir_1299(void) 
{
	svi_reg(&(tinfoil.validation_items[1298]),
	        "978c711395e5aee58ad51144d860c39e5f454790a5feb4ea9f323d98d1e0a7b24c090950412793c924510f18e1d5bda4447bd779fdfb63b238fde54a2696822b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pl3.map.gz"
	);
}
static void svir_1300(void) 
{
	svi_reg(&(tinfoil.validation_items[1299]),
	        "8d77b90650cb1f2e5493bdc28c340ec4645382ecaf0ea29bb6877297a6c37a2362bc001aa562be5fda865b53c80859131f767b4e5ac365d4563f54a755061389",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pl2.map.gz"
	);
}
static void svir_1301(void) 
{
	svi_reg(&(tinfoil.validation_items[1300]),
	        "02eb5098353cf0833193b2ec06fb247166bed7899c4589a11f5d8dea222c3433cf319f4d7ed28aedcc3b8810062366683d00b1a62bdfbc625cfee7595bb8ac14",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pl1.map.gz"
	);
}
static void svir_1302(void) 
{
	svi_reg(&(tinfoil.validation_items[1301]),
	        "41645d8a60a4ae376c4d11421ae318348fc6b791dca3f715da683937369a128399b54f1f6c4d722972405f08289b72a33ef7194d714c5740f95a0cac697f0cd6",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pl.map.gz"
	);
}
static void svir_1303(void) 
{
	svi_reg(&(tinfoil.validation_items[1302]),
	        "c20af0d2ea55a56289e5c8c10e4d9d61b2a9fe9da350a13743c4cc56a240c5d368ceac64d447eca70113565920fcd5b64dcbafbf560f5853cf0e1ddf8d6f0570",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/pc110.map.gz"
	);
}
static void svir_1304(void) 
{
	svi_reg(&(tinfoil.validation_items[1303]),
	        "12fbc5e370308ffcb78a930289542771a89ca5c7b16621de970f582c14a79df778f24545ccbfecc09ef962311c6312e07d27657e205a39155dc37a354ad27db2",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/no.map.gz"
	);
}
static void svir_1305(void) 
{
	svi_reg(&(tinfoil.validation_items[1304]),
	        "f998e35fa3ec41c03de9e2a30a7498182855f08b476059509f74c215d8a0fc7ac5c3815453102e7c4bcfdeb0288e0528759dc920d67d08035dffc0604c982b04",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/no-latin1.map.gz"
	);
}
static void svir_1306(void) 
{
	svi_reg(&(tinfoil.validation_items[1305]),
	        "750fc6b5ac8f53068fb4ee06b69e7a9f31beefacb40e21a36de030bee4cca7f3bb07bbf253fa7bf3ca000442c49171cbb94a2cd57e061d745fcd9a1c58e7e2a2",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/no-latin1.doc"
	);
}
static void svir_1307(void) 
{
	svi_reg(&(tinfoil.validation_items[1306]),
	        "73a98e62f5809d52d7051991a5398e9258ab65b5a649e8e795ee88da544e5cc2d5e32b15e2660ae9efb540416ca4ee3041b064638a7eb9f2c658d34b02f02b6f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/nl2.map.gz"
	);
}
static void svir_1308(void) 
{
	svi_reg(&(tinfoil.validation_items[1307]),
	        "39f2148db6869718e85c47da407831d9c854fbcb07e40ab190b4bd813c52968fb1ecc10aeedcf2e78aa1466beb0cec205165a33e3a579e3575bb3bd423526f9e",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/nl.map.gz"
	);
}
static void svir_1309(void) 
{
	svi_reg(&(tinfoil.validation_items[1308]),
	        "7f2b56a4e57551a452673f597a1f99ed89f8a2ca027b75aa68f5ee37a373bade0e8aa6e8a5437272b56f5ab8a86b0809245dd4f14e6c05c686a09ee66f74bc87",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/mk0.map.gz"
	);
}
static void svir_1310(void) 
{
	svi_reg(&(tinfoil.validation_items[1309]),
	        "370aa6a208618b0ddc35332e0f2d71f811d05e616617cbaa7d40ce88d4ef897bee8c300df3fda13aaa4c0fe020049a11762450116ff9f845a46e297a4ef3876a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/mk.map.gz"
	);
}
static void svir_1311(void) 
{
	svi_reg(&(tinfoil.validation_items[1310]),
	        "fd047ddc2f1a32621c295f5598ff74bb4767399843989196899a128a7e11f6659d4d03d8d7d036ef4c8ac75b3cc30e9447e88dda04587fa55e0edb8518e8b9d0",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/mk-utf.map.gz"
	);
}
static void svir_1312(void) 
{
	svi_reg(&(tinfoil.validation_items[1311]),
	        "ee1d6221c21f8255baae77c596af1a771c16a03bdbaaebf6dc3ea7ed02b7aac215362801987b24a3cea59c214138bcfae91f6bba6fda5063c5a76c116ce484e9",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/mk-cp1251.map.gz"
	);
}
static void svir_1313(void) 
{
	svi_reg(&(tinfoil.validation_items[1312]),
	        "86a4c0db9e534c6dcfbaff29314e581e96192d6a2ec106f511510ea5a56491cbe86dde59e0b6a9b24ecdd394931e0332c24d6e65a6ada9e9a9622d4edbb5950f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/lv.map.gz"
	);
}
static void svir_1314(void) 
{
	svi_reg(&(tinfoil.validation_items[1313]),
	        "25ace43c409b190e698cc7c511dd91550b70317d87abc5745c328b6bd2145ad3d83e845720260535d71fb452628785c9a169fdd0ef39cace7a1a3e732a17b00b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/lv-tilde.map.gz"
	);
}
static void svir_1315(void) 
{
	svi_reg(&(tinfoil.validation_items[1314]),
	        "08947dfc1e116eeecafc190d18f6a9c1fe2a28d44148255840bb01b1dfcbc0b43d4ba35dac06a2457ac54c016f87008beddc212dd95ff8d49b9055d3ee2c1c9d",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/lt.map.gz"
	);
}
static void svir_1316(void) 
{
	svi_reg(&(tinfoil.validation_items[1315]),
	        "16a82b7e77702c6af90eb3a32f9a57e437b962d6dcd3f5bf5691bbcd6f568ea47b9631a94c98ca7580dfe414f96ed8288beb4072465cdff4ee7daa79dd55afe1",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/lt.l4.map.gz"
	);
}
static void svir_1317(void) 
{
	svi_reg(&(tinfoil.validation_items[1316]),
	        "7b7d12155d9c5ff270db747335688a6a01c410c9ba054f6b68306af1e662c628255280a2c12cf8cd0f9cf06f2fb3b741ce20aefcce15f9d30497df8f6741ec72",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/lt.baltic.map.gz"
	);
}
static void svir_1318(void) 
{
	svi_reg(&(tinfoil.validation_items[1317]),
	        "9ad2a696def6abd7c9c814a5e1321357a45a91db09074d36e90f44cd2b3d2b617e1fb325ba6bd36246001e79d3cf2d85365b315ff53bdcceb48671f00d5a194c",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/la-latin1.map.gz"
	);
}
static void svir_1319(void) 
{
	svi_reg(&(tinfoil.validation_items[1318]),
	        "209aaba0eb0eaee964cbfbcf5c99b7c6de00674e97c27242074eba8a48e40d8e0f832dc1e6fc7202a4662334f63d353209a6ccd3784258b682b49365d5442176",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/kyrgyz.map.gz"
	);
}
static void svir_1320(void) 
{
	svi_reg(&(tinfoil.validation_items[1319]),
	        "f535f8c8830cf1c008c16d14fe687f0af7b3202ad13dd222e3f64d0f8195b06923b199d7376a5965b836fc920172a6158742c421b2b133eb92461094d67e6331",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ky_alt_sh-UTF-8.map.gz"
	);
}
static void svir_1321(void) 
{
	svi_reg(&(tinfoil.validation_items[1320]),
	        "2e4a458859f4bb3311c20372bc87b55ed6ab9c148af2b174b36e2755ccfa80e28146de275ba2879e79ba57749a7b04c0402c29fd7eb71f34bfd7dd06a9cb17be",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/kazakh.map.gz"
	);
}
static void svir_1322(void) 
{
	svi_reg(&(tinfoil.validation_items[1321]),
	        "0f22769ba364769df8a9c3b085cc4cf4f30ed0fb1b701c92b515bcdbad6dd01a418898c7d67c446003cf2dc4b53963497570290f192e3fde62989ac28e31f9ad",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/jp106.map.gz"
	);
}
static void svir_1323(void) 
{
	svi_reg(&(tinfoil.validation_items[1322]),
	        "73986c301e59f292cf00b790ca9056d1000f8874aed368344193fdcd125b4d418a168ba267aec9903ca4a8893b89f6352a9c3eebd157febbfebe642092464293",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/it2.map.gz"
	);
}
static void svir_1324(void) 
{
	svi_reg(&(tinfoil.validation_items[1323]),
	        "f83a79d94611f4f2c58610cd0d17c858c213dbc2e466c60a8c26d92c492a5e3594a6af1c4b166bf226443fd3cdeb6f88e975a6ba501b58e5142a6918fab9f343",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/it.map.gz"
	);
}
static void svir_1325(void) 
{
	svi_reg(&(tinfoil.validation_items[1324]),
	        "5de5b2ba1d202cc45f6c6e89e346db866913080d5e5af054467e5d9fd8b2920498660bcc13b7e4fcb9cf57a26545b850123774bbe163105adb266358eb5a8fe4",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/it-ibm.map.gz"
	);
}
static void svir_1326(void) 
{
	svi_reg(&(tinfoil.validation_items[1325]),
	        "c410a0b9f86598b867ad2ac0b36875d611206f993476796f67c60208b7d877c392094163dfa5717a23801b54667b6032baa8076caec7313ce22196b1b52097b7",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/is-latin1.map.gz"
	);
}
static void svir_1327(void) 
{
	svi_reg(&(tinfoil.validation_items[1326]),
	        "f02b0c252bffdae15594dfc10c0ab49d9f4ef7b15fb5c3ff0cd763fc78c7879790c2110ca28f5447a78dfc8f3a9ccbf8e4c6b5b33c17500765ef9b0a35ae048b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/is-latin1-us.map.gz"
	);
}
static void svir_1328(void) 
{
	svi_reg(&(tinfoil.validation_items[1327]),
	        "fa4019704fe3209127a0faa098a96febe26f7413ad84d8b984a40f48a42ffcda7fc81c219dad3bddab65d1dd4674f76fd9ad3c217872fe69e96f8eeae32d56fe",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/il.map.gz"
	);
}
static void svir_1329(void) 
{
	svi_reg(&(tinfoil.validation_items[1328]),
	        "e2ef2fb0e8b31ebd8c30201a9c371446fb844bf3244d428324472e94c8293ae84815da411200e8e68a20504640f69e41003e9d4cf64e035d2ac8ec178c5dc6c6",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/il-phonetic.map.gz"
	);
}
static void svir_1330(void) 
{
	svi_reg(&(tinfoil.validation_items[1329]),
	        "57ba3675db068cfd6315acf3071d032a793004da6a22a20412803e1e23d9301e744c9c7eff896cc8610d6643d3109a35ddc1b39e025986133584456fae9bdcec",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/il-heb.map.gz"
	);
}
static void svir_1331(void) 
{
	svi_reg(&(tinfoil.validation_items[1330]),
	        "8efdfbf55cd6cb16a63d6d02f91e776eff56b11e2b6bd6de83be53aa6d6152b299d12bd5028146b5fa7dc979c976b78e1211ab56a38ef67bb519d991bf22bcb8",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/hypermap.m4"
	);
}
static void svir_1332(void) 
{
	svi_reg(&(tinfoil.validation_items[1331]),
	        "13a45c6d1113c0f9fd3ba2f4c8105ecfd33afaac6b155ee6f25e5506cb57aa6ab3f94556b71ff38a1ea29ea5b22e0219e17b0521200d34167fdd6b61dfc2e2e0",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/hu101.map.gz"
	);
}
static void svir_1333(void) 
{
	svi_reg(&(tinfoil.validation_items[1332]),
	        "56d04b940fbed482eb3115dfd6b85fc4a2f7cf1a8b8a2177ad6ed74647976a6e1172d3b4bcdedeac195b17e0d3252efe0492e26359c20e207fc84ebd2b324778",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/gr.map.gz"
	);
}
static void svir_1334(void) 
{
	svi_reg(&(tinfoil.validation_items[1333]),
	        "9f0e3663cfab0b2ba5c955b44ab1c033e05887f97e0842c1262b69a93ced29e908c3e9e53ff12e3e32c9c4043f6e07a0d474d42a64bb563f14a8c387166ea2a2",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/gr-pc.map.gz"
	);
}
static void svir_1335(void) 
{
	svi_reg(&(tinfoil.validation_items[1334]),
	        "45be7f0310d90fa13e094c9e549f9c1766c395c9530d10468b0bbac2aaeb139732ea86ebbe683c6e67fd5fd86926d511d6b39ed2df9f8b8c58ca535a09d98a5e",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/fi.map.gz"
	);
}
static void svir_1336(void) 
{
	svi_reg(&(tinfoil.validation_items[1335]),
	        "3d750e72251062740bb4a2c2b2c06adbe288d49001d07e5af922d6e115c04c802bde697b93fa35b951c13740c29815fe921c731dc41cda08df7dce6f9b5c1f74",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/fa.map.gz"
	);
}
static void svir_1337(void) 
{
	svi_reg(&(tinfoil.validation_items[1336]),
	        "7c1d51e38b7de77bb7929985ea8196719f3f72af9291d80a3610ba9479ac906fa11b74fd4c379f425c15ceb2118a5bb02af291a357294d2937c37ebe604526aa",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/et.map.gz"
	);
}
static void svir_1338(void) 
{
	svi_reg(&(tinfoil.validation_items[1337]),
	        "6e319fb45df6f0a9b9da04a5aaed9ea4fbb8f646100d5ad1c8adedbbe78762207d7eb98ca3952d1dc3c114cd561ce53a541306145189ec0340c1a53c79b59280",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/et-nodeadkeys.map.gz"
	);
}
static void svir_1339(void) 
{
	svi_reg(&(tinfoil.validation_items[1338]),
	        "569e2ec255eaa7132d78cc3a20f0ca9702712eaccb034e76044b9777f02b19a1cedb13d087258ff2852f56fa97466d29d0dc61a082a5ad22c679c3591a9e35cc",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/es.map.gz"
	);
}
static void svir_1340(void) 
{
	svi_reg(&(tinfoil.validation_items[1339]),
	        "59bc56094b49bf4bc2976b3711040e0458d022d5c13b8d654fa212068098fa8195c7777123c02197a632acbe1b6ac5fadcec7fcdc78793933e2a6e446344e621",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/es-cp850.map.gz"
	);
}
static void svir_1341(void) 
{
	svi_reg(&(tinfoil.validation_items[1340]),
	        "6a62ccb563fde3cc1edf77778ed3a44121c76647b28c9f758c467ad3c1e00e9a5d7bc43471b82ce46e112e8b8eaa7ee4d08dddd4a8871f80dbb271ea541e578f",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/emacs2.map.gz"
	);
}
static void svir_1342(void) 
{
	svi_reg(&(tinfoil.validation_items[1341]),
	        "7377cabb3298c20fe6241bc6e4a56c695e1a71355c5f63b94f3222304a9479e0522d2a27f7db23a8184c3b1ff368289e3ef2f499ae17ed78835e14a11bb423ba",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/emacs.map.gz"
	);
}
static void svir_1343(void) 
{
	svi_reg(&(tinfoil.validation_items[1342]),
	        "5cfcc493faafe3a55af2ce0641757767e991b222d5faf5c8b440359976c5951de37c808263c31b67f6b10bd3b77fac32c4693d02e93043870c9db1da337219ef",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/dk.map.gz"
	);
}
static void svir_1344(void) 
{
	svi_reg(&(tinfoil.validation_items[1343]),
	        "4a81ea7f26fdfc9a6b011f52513dea4853981391d3340ac2b4eb5dca20b7faec4b7dd05b9d3cd9aa60586b172b16a3f668610f3d517e87672cf0e241c408c0b0",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/dk-latin1.map.gz"
	);
}
static void svir_1345(void) 
{
	svi_reg(&(tinfoil.validation_items[1344]),
	        "30a8fa144bb11bd339e68dca98a277154996a391d14315d5b9e782444a7cf3d93f84e481115c39a2ebe7de7435376cc6ddae0051e1036fdb95ea5ff7eaeef4b3",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/defkeymap_V1.0.map.gz"
	);
}
static void svir_1346(void) 
{
	svi_reg(&(tinfoil.validation_items[1345]),
	        "1f707e323fb09a597f3f98be3f003be39ccc3af90f100042b671442253f19a91e760e62add081a4bea822b59ab838e9623a6cb26b1d28ed7ad1e60cdf9652c60",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/defkeymap.map.gz"
	);
}
static void svir_1347(void) 
{
	svi_reg(&(tinfoil.validation_items[1346]),
	        "45abbf85f08e2a8e04d495813413d5ff3b42d7e0e7461c9b1cc5499ef75ddfd4d4bc0254501fe5a03079ca404de9d0abbdecbbfab699647e0936c58f3af80f79",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/cz-qwerty.map.gz"
	);
}
static void svir_1348(void) 
{
	svi_reg(&(tinfoil.validation_items[1347]),
	        "b4ec6c18d6348c05e2ad52e0666cd301e0cd131fc99f791f2af75b5a332b441732a6c3380b77e64b6184fe0ffe7b1f1200e1a526060a1a29b779a61a77bf3984",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/cz-lat2.map.gz"
	);
}
static void svir_1349(void) 
{
	svi_reg(&(tinfoil.validation_items[1348]),
	        "f3bbf718947f994682d23d01a06cc19487744d2f7ee55e99c4c4ad31861ed6c881085797944a5c5742364a0bd04964d69e83f08bc26194ccfbc81eff6a2a443d",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/cz-lat2-prog.map.gz"
	);
}
static void svir_1350(void) 
{
	svi_reg(&(tinfoil.validation_items[1349]),
	        "631943ab8e92d7bc3bf2b10381f2e36342b5bf701d5793f16266db3f79386f1dbef1c8b5345a9a1a3b93691130d26fd40b2bbedb4cc98cd528e5742e4787aa64",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/cz-cp1250.map.gz"
	);
}
static void svir_1351(void) 
{
	svi_reg(&(tinfoil.validation_items[1350]),
	        "173c1595321812bc5ec4d73e41fd412594721d4324a9598d7f56e65c6eaf6acb08a476576fb1937a62e39ed1778f59d343c5c29352ef1c985fbb6ce324d7e391",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/cf.map.gz"
	);
}
static void svir_1352(void) 
{
	svi_reg(&(tinfoil.validation_items[1351]),
	        "46c9d58738f8c2e8643bb50099346c5a2e02b0bc082933e34e42876bfaef79288eb6126d2728f3c699b1fd6ed78eb01bed28723586060e02493503d621fc912e",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/ca.map.gz"
	);
}
static void svir_1353(void) 
{
	svi_reg(&(tinfoil.validation_items[1352]),
	        "fb2b13b45110c7bca2ddcecb160c677064bf6961520a968aae23136e2f69421faa46937c37e91630a0174d3ac28f76f649673f0f13e125cf07ab678ce7fe877d",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bywin-cp1251.map.gz"
	);
}
static void svir_1354(void) 
{
	svi_reg(&(tinfoil.validation_items[1353]),
	        "6c43c731e15924586b536350c4c2bd57380a4b12c9e571c7faf1cd43b92f48100b0af8d5aa6ad11dd5896b7071c87ea89889738487dd64decf5160f8a4797a8b",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/by.map.gz"
	);
}
static void svir_1355(void) 
{
	svi_reg(&(tinfoil.validation_items[1354]),
	        "181e9fb54c08c2e888af1dc5b3d750c76a87ef82e11f2f8a634f4a0118bec8345f71026ed27491ebeb23cf958b6b18aca0d9f832bd57ceaf8842456d6ec63581",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/by-cp1251.map.gz"
	);
}
static void svir_1356(void) 
{
	svi_reg(&(tinfoil.validation_items[1355]),
	        "10a508a81fcba5e8ec1509fb66301a5e423c3712fa4b29b4582248a1ca6d2e545ccf5fbf7ed59b51d6142b61b182a5be0426ac0b5444d885cc4276564c4dcdd7",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/br-latin1-us.map.gz"
	);
}
static void svir_1357(void) 
{
	svi_reg(&(tinfoil.validation_items[1356]),
	        "cf22526c17e2736eaf810ca46640c5ff7de5c62859f40f75e40841d72eafe893ba87b4347dfd1b5708fe97b368508d258e890203f44f5b7d313165490d7a8f62",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/br-latin1-abnt2.map.gz"
	);
}
static void svir_1358(void) 
{
	svi_reg(&(tinfoil.validation_items[1357]),
	        "2655d6727c608fec59c0fb935ef4bd17cbc82fb87bc4807774addc9ddf5ee0cf3669d5fe96f36f8a8566605dfcc7353f31b9e89b084b9fcfd503c6e390452f22",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/br-abnt2.map.gz"
	);
}
static void svir_1359(void) 
{
	svi_reg(&(tinfoil.validation_items[1358]),
	        "eeae9b577f29d3a3f9345ace62f139ea9c17511e32978e26e8cdb3e18395d8360b9ace95aabaa1a4742189b558117b3fd45d7b553f9312a741372d200cc69407",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/br-abnt.map.gz"
	);
}
static void svir_1360(void) 
{
	svi_reg(&(tinfoil.validation_items[1359]),
	        "b6474ec0db62640c368afadd28f3cb09f8f0c09d461202144d4b275aa8e15e54b225a34d757546c06765bd930ee5fd733ff4aae348d398aceb5e49919b9f7e20",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg_pho-utf8.map.gz"
	);
}
static void svir_1361(void) 
{
	svi_reg(&(tinfoil.validation_items[1360]),
	        "208b20239c36d52ae7ef8c6db7e47f8949a2ce5acce9ae4ebca252b00b8fcbe67da374c05946536ce19b5b704b4dafbbced28d11bb5c334b353ce9ceaef92fcb",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg_pho-cp1251.map.gz"
	);
}
static void svir_1362(void) 
{
	svi_reg(&(tinfoil.validation_items[1361]),
	        "59f500b1545d857650b664b644a7facc05aa9b2ef5082642dd7bca58ff5f81471ef22023ad7bf11c91d7a3b9e1858399f904c6e91ed8defe16ca9d53abb84b57",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg_bds-utf8.map.gz"
	);
}
static void svir_1363(void) 
{
	svi_reg(&(tinfoil.validation_items[1362]),
	        "f917b11af6d3c617ab8b3b5bb27e05d84f8e8b1204d1135271a9697f20110417627f04f2bb2476d623bcf5af11e9686681722ba8ec1b42882e4f5c4038a00ae8",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg_bds-cp1251.map.gz"
	);
}
static void svir_1364(void) 
{
	svi_reg(&(tinfoil.validation_items[1363]),
	        "b9bfa9a023252f7dfa62466651b3cd73efaa18978637e46be31ff3c4a5f10e1d568a6b4bfa098a4b3ca380975c891dcf70565344f9cead034b0230022befc658",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg-cp855.map.gz"
	);
}
static void svir_1365(void) 
{
	svi_reg(&(tinfoil.validation_items[1364]),
	        "40f80c919257803d9cf447249a71b03c6b3a7cd3a4afb655c48a49d56821c518a3c5d7f8181ff2138def54710055b0dc35dc918a8cfd1eaa1a4c0e62482c4104",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bg-cp1251.map.gz"
	);
}
static void svir_1366(void) 
{
	svi_reg(&(tinfoil.validation_items[1365]),
	        "1c7cfc691d8d6af4936b13dc8a1273784f98eb8b7ffb9828cf104d120689974b377411e1812c4408cba75a50179fa96a12328d221f5f3c8916b210176aaca28a",
	        "/usr/lib/kbd/keymaps/legacy/i386/qwerty/bashkir.map.gz"
	);
}
static void svir_1367(void) 
{
	svi_reg(&(tinfoil.validation_items[1366]),
	        "70757ed0ef35ead4b516f7a6f1258c45e7346d878fb2e0087a454bc5cd47551d458fb57a7f24b609f04a08d1fd923016bf684471b2dc8dcb4f2d991c119f06be",
	        "/usr/lib/kbd/keymaps/legacy/i386/olpc/pt-olpc.map.gz"
	);
}
static void svir_1368(void) 
{
	svi_reg(&(tinfoil.validation_items[1367]),
	        "de42a7290508d70d08a28234d55f581a5761dd93b92704260344c93da1fed70c5c0e545a93f4b7c1f7f5e566ba094dec9764982ebf869a3a9f1619b20c306d24",
	        "/usr/lib/kbd/keymaps/legacy/i386/olpc/es-olpc.map.gz"
	);
}
static void svir_1369(void) 
{
	svi_reg(&(tinfoil.validation_items[1368]),
	        "7ed772de6de0a837c553fd32dd399efad5acfd41f40b74d6ff78bd478734126994835140a5c50679f071ee13fa823c6471ac4724d287b88d671cac668a533b2f",
	        "/usr/lib/kbd/keymaps/legacy/i386/neo/neoqwertz.map.gz"
	);
}
static void svir_1370(void) 
{
	svi_reg(&(tinfoil.validation_items[1369]),
	        "d723e9e13ede4eaa6eb2461965ef129c18e221f2501e051b6cba622bacaabf2c215c5feecc2a251eaeccad67085416b2eecce11531dfbdf7c1875b39d472b14b",
	        "/usr/lib/kbd/keymaps/legacy/i386/neo/neo.map.gz"
	);
}
static void svir_1371(void) 
{
	svi_reg(&(tinfoil.validation_items[1370]),
	        "29bcad06ccac1d6f0c87de98407dd92e8c83c18e6b2a053155ef1fe2b680586ef2abdca1477035f3a990b2994073362694c7f471ff91555c7863b8dc939ac371",
	        "/usr/lib/kbd/keymaps/legacy/i386/neo/koy.map.gz"
	);
}
static void svir_1372(void) 
{
	svi_reg(&(tinfoil.validation_items[1371]),
	        "9e1742634e6566488b4c39a63227211af1fefa9a0bd32a8c30b02e360714b6c43192f7363046a8a4527c431fbd0561ecd886cf8fa88f5764bd4c6794faa9108b",
	        "/usr/lib/kbd/keymaps/legacy/i386/neo/bone.map.gz"
	);
}
static void svir_1373(void) 
{
	svi_reg(&(tinfoil.validation_items[1372]),
	        "2bfd5f6b5a0267dbc862ab443d62dad8e1e2e3f3d0fb04404ba39495778256e2e512c159a169da71ca1469dc253962edc05e66b867be808995df1c7bfa782671",
	        "/usr/lib/kbd/keymaps/legacy/i386/neo/adnw.map.gz"
	);
}
static void svir_1374(void) 
{
	svi_reg(&(tinfoil.validation_items[1373]),
	        "05315682f25cd9f95d9c963b72274e7fc72600a9288aca618af9c8ddbcbd6458cb81cc19fabc64db4be02ab324ad053f1be3c08284a37a31bcb5be880c8da1ea",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/windowkeys.map.gz"
	);
}
static void svir_1375(void) 
{
	svi_reg(&(tinfoil.validation_items[1374]),
	        "59928ba1f9b3b9b8cac348b792b5ce9f1b8dd8411e255c017b2b28bf9ca9f14521b7a1ec95751d647ffbe8fb84244c76172728634f88bceea68b75839a195644",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/unicode.map.gz"
	);
}
static void svir_1376(void) 
{
	svi_reg(&(tinfoil.validation_items[1375]),
	        "b684e38bc52d672c3af47114227992f7bbfa24757752b9e44ef5aff7d4c79053e227e4416bcd9c3c416ec30d5b7934b648d5dd50c19d19b638710188694186a9",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/qwertz-layout.inc"
	);
}
static void svir_1377(void) 
{
	svi_reg(&(tinfoil.validation_items[1376]),
	        "f79da7572dbab265fac847143d745791b4826997e199d3ee1a09ffcb388a1deeb53f884de00c265c9f4ff7e3cf9afb867c064d45c3ff9492ad749a448bdf426d",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/qwerty-layout.inc"
	);
}
static void svir_1378(void) 
{
	svi_reg(&(tinfoil.validation_items[1377]),
	        "d03c3ac4d0a05063cbc3a4f8cefa33f9baf1554dab40f9b3267f6cc2f990e9eeb20048dcd52ea1a3ab3652be248c4e87f71f3480f73a4b01255eae8a68814bd4",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/linux-with-two-alt-keys.inc"
	);
}
static void svir_1379(void) 
{
	svi_reg(&(tinfoil.validation_items[1378]),
	        "948bc6740424add53555099ed70a8db53ff7e4e6e581199349387f5178d0817c9631cb82c755d78433a21195c8ab564903288b1d5e7265cf56e43e4b3baeb2cc",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/linux-with-modeshift-altgr.inc"
	);
}
static void svir_1380(void) 
{
	svi_reg(&(tinfoil.validation_items[1379]),
	        "f8c68456567e6dd5be978a3998ae714010602ea203a4afb2b72e4c605e104282ccf5918572cd15a9ecea350fc44260ea8a91e17816905260287ad7be263e537c",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/linux-with-alt-and-altgr.inc"
	);
}
static void svir_1381(void) 
{
	svi_reg(&(tinfoil.validation_items[1380]),
	        "07f49336af934fd58c0c49fe600afe8ed86f1d04f0b2dcfebea0b8e3e50a9cf9dbd92f1879207be32ddf2ef2ae434ea1642eb8691fdaab4222ae25a91c5ae688",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/linux-keys-extd.inc"
	);
}
static void svir_1382(void) 
{
	svi_reg(&(tinfoil.validation_items[1381]),
	        "77bebeee53ab326a8d07e201d6eb77431fc0896e9dea562eeb5934dcd1e1fa3c6242d816d5403f56e9e175d90ea315f301e2aabbbf3b947d42a452e8afd835f9",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/linux-keys-bare.inc"
	);
}
static void svir_1383(void) 
{
	svi_reg(&(tinfoil.validation_items[1382]),
	        "2ebbde2ea4c26bf46754c9163fee3f4677d5cc6a2adff20678b684277b14fe1ee58d3eb825d16d877be59a5be3a230d88685fefaebcb4fb265227167887e5bca",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/keypad.map.gz"
	);
}
static void svir_1384(void) 
{
	svi_reg(&(tinfoil.validation_items[1383]),
	        "098cb07a8a1ded28be16bbacc66fee05f01f22e87cce0f74ad09a81c2c7801beb79e5b5dfaea2d6e96dbd96210601cbeeaacc6080fde695259039e0627ccad8c",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/euro2.map.gz"
	);
}
static void svir_1385(void) 
{
	svi_reg(&(tinfoil.validation_items[1384]),
	        "03b8bac913ed7a7960811542b6b8f72ebb234b241e7513cdd089aeef1acae4e397daaba9e1d5119eb1b6b96df7d66f5f362ce0da765e68ba71bc39e2e1dff6d9",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/euro1.map.gz"
	);
}
static void svir_1386(void) 
{
	svi_reg(&(tinfoil.validation_items[1385]),
	        "d660800a1c00c023c8e880006f3f830e79c9e7673f63184c9a3d98f2bb4e315f7b81ba873b5a6107e4a38ab51b72865068723646e02710079703e14decef16ad",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/euro1.inc"
	);
}
static void svir_1387(void) 
{
	svi_reg(&(tinfoil.validation_items[1386]),
	        "c75b09f70ef123621b0715ffb0b65facc9fc24a93e2ad500627db1015b45a1c1d423a916aa92127dbb710baef3b24d9aa7e43fcf4de6755f478e14c26370cace",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/euro.map.gz"
	);
}
static void svir_1388(void) 
{
	svi_reg(&(tinfoil.validation_items[1387]),
	        "4076deba05a170286e37adf4969f6fb1be149774d6306b0c9f01b4fcb3e2efb80631b4aed5a6b405fbfffc86abb1697ff55a56a22174653e025a52eeec44f5a0",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/ctrl.map.gz"
	);
}
static void svir_1389(void) 
{
	svi_reg(&(tinfoil.validation_items[1388]),
	        "ca923ced81a482bb7ea253aab0d29c25d1de1c5a0b7db28229a15cf3cbf428cd21188a1c64c36d086c32a81e7b875c0b70c3f3ef59b034efdabe7fea8c0b6dab",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/compose.inc"
	);
}
static void svir_1390(void) 
{
	svi_reg(&(tinfoil.validation_items[1389]),
	        "ec6b9da3c8924141b9762b96f495ac7a6e56104e06b6e0cdbe149d568af9c97fa0e48c56bafae1f4dd6349c65a7d0df54fbadb3d230fc7a9d3b27acb0f624172",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/backspace.map.gz"
	);
}
static void svir_1391(void) 
{
	svi_reg(&(tinfoil.validation_items[1390]),
	        "2fc7f9cbc196e2d6d3c3e9105fa2d888568eac698e78cde5255515f26ec0983bddf042ba05f1f9a1779edb62e4c7eb112b901429b49419735e49e3d317686bc0",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/azerty-layout.inc"
	);
}
static void svir_1392(void) 
{
	svi_reg(&(tinfoil.validation_items[1391]),
	        "b9b7bc5b915dcf91534eb94714348d191bfb8cf94eb56ac424706138c4d01d840037dae4200d6fe4fd89de8b3bdd2e1c57fa0dfe76df3d55e40e8ec342b44896",
	        "/usr/lib/kbd/keymaps/legacy/i386/include/applkey.map.gz"
	);
}
static void svir_1393(void) 
{
	svi_reg(&(tinfoil.validation_items[1392]),
	        "547a11efb803b60c429cf3fe32dd1a6010fdcf5185d9acbce775e05bfa293b558e5dd8839fc28b7778c9b59c1ed38505f3bb079f58081d538de78b3b45c01ce6",
	        "/usr/lib/kbd/keymaps/legacy/i386/fgGIod/trf-fgGIod.map.gz"
	);
}
static void svir_1394(void) 
{
	svi_reg(&(tinfoil.validation_items[1393]),
	        "5526cdd59e43174b0692e5527ddacce40b57cd4ad36d085e916308b4e093c52a36f202e88763c73ed89358762d95ff612d213eb21fd1bbcd6cd7f84e782fa30b",
	        "/usr/lib/kbd/keymaps/legacy/i386/fgGIod/tr_f-latin5.map.gz"
	);
}
static void svir_1395(void) 
{
	svi_reg(&(tinfoil.validation_items[1394]),
	        "54d18497d1309051dc7e8ef1ef4c6cb519185bc93a6f9b2e2ce38ae8e39d98311813ebb4823682d25f79c772c7ea39cee2a63da9aac071970ca7722f5e79d0fe",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak.map.gz"
	);
}
static void svir_1396(void) 
{
	svi_reg(&(tinfoil.validation_items[1395]),
	        "962fb312e438015c41171c4c994fe520ec9211ffb7b20f8b5d12909ce538f7c5587960e95cc172bec7e564df74b7abddb52f7645366b5e07a6236d69fd8f4964",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-ukp.map.gz"
	);
}
static void svir_1397(void) 
{
	svi_reg(&(tinfoil.validation_items[1396]),
	        "d5308874ed930083c9fd5166dee0dcd500731da045c76441bacf1cbe4a6b6850865e8cb1941b39a3c2bfcbcfe2bcba4a89586cd6ba3ec6d5b1e46dd86a77f490",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-uk.map.gz"
	);
}
static void svir_1398(void) 
{
	svi_reg(&(tinfoil.validation_items[1397]),
	        "7410adf13b2bb14d22ab8a37a8aef49b66b03028776bb959d20df28ad99823024b5be8a9bf11c683945df4a5299668a17655a6c887b47f96ac2a962bd5c546bc",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-sv-a5.map.gz"
	);
}
static void svir_1399(void) 
{
	svi_reg(&(tinfoil.validation_items[1398]),
	        "66dd5148f8b030116d440a51611ece2d1f4084ad5f24625ca1d9dd8730061971d8da9d405dbc8c2f0099c06a9126c69827ed3cb183dae0ac48ffb75f8df03541",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-sv-a1.map.gz"
	);
}
static void svir_1400(void) 
{
	svi_reg(&(tinfoil.validation_items[1399]),
	        "de9b2aa6f7da03faccf5893d185428d9638c1956c85b6fcc2f3eb27b25b7f99d972035a6ea4db4dbf7578dd28f8c14af677a8545815d545d8a0cd6aabbd1e702",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-ru.map.gz"
	);
}
static void svir_1401(void) 
{
	svi_reg(&(tinfoil.validation_items[1400]),
	        "d7e6bc64309b0856e590ce45f054aaea5e2a9f482fc999ec271c624daf76f4c8faf0a7ffa14aac7c49711ad4c9c7321a7f9bff6bc38a12d1a4b66fd6bdda7c79",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-r.map.gz"
	);
}
static void svir_1402(void) 
{
	svi_reg(&(tinfoil.validation_items[1401]),
	        "b395671871c9a75e45d85a649026df4a67e72ef76b59a22c827506a5bbe5a51fb6f47755e7d3e4336cf053a58b721b338756110637be1be9a455655beba5d4a7",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-programmer.map.gz"
	);
}
static void svir_1403(void) 
{
	svi_reg(&(tinfoil.validation_items[1402]),
	        "c151efee97d6e1e57de67a0d6ae37eb2ccbdb3d83493d76020f9890125b94553bf5580cab2984ca71cf62a2b5d049e80756c24ca18bdb2ab2bcad98018908e4b",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-no.map.gz"
	);
}
static void svir_1404(void) 
{
	svi_reg(&(tinfoil.validation_items[1403]),
	        "c3b55b446d9d6ba0aeeb8eca76741f66a54f75cba6337aff3b5cf0129a7dfe10b54f3e6c96672fe3e6670cc71cb98d3c0f8091a978dacf433f9b72179a740e83",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-la.map.gz"
	);
}
static void svir_1405(void) 
{
	svi_reg(&(tinfoil.validation_items[1404]),
	        "a04c64ee5b765c673f6d160613551f4160449ac9f5930ecf993ec8db52d7383fa05e28a933cfd9eefcc9744a8a2ff772b76e137c045a805940df346e478aab29",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-l.map.gz"
	);
}
static void svir_1406(void) 
{
	svi_reg(&(tinfoil.validation_items[1405]),
	        "736eb33edbc623d0a13d19198d325485fc24ec6086e052b25c33af3fe52d747a4f750f4d05cd13984449d9c12e75180eaba56b305bb02705628e6427bb34fad3",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-fr.map.gz"
	);
}
static void svir_1407(void) 
{
	svi_reg(&(tinfoil.validation_items[1406]),
	        "d1b7ff72f360c06625a986eb2edeb971be7382411551204fb54b243533955379bfc7231b1f8162352488d763d3622b0a381b8513f1565b7d1c9e629b1ba20f9e",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-es.map.gz"
	);
}
static void svir_1408(void) 
{
	svi_reg(&(tinfoil.validation_items[1407]),
	        "d03eed6aea7f539de272ab2cb87a87d50f40abb0397f49798c8a2de368d241f66eea0b0ad93969c9d16b8d33b9bc3e69552312f2ee0e3ce45774bcf68a3fb365",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/dvorak-ca-fr.map.gz"
	);
}
static void svir_1409(void) 
{
	svi_reg(&(tinfoil.validation_items[1408]),
	        "91b946aca41577b1652ab417781040bab9e48a8d847582e28fbf4bcf3ab0400030dafb9ec4891a854953f04c08eaca6f5bc5cd03ecdcb9352bfee25660ae6286",
	        "/usr/lib/kbd/keymaps/legacy/i386/dvorak/ANSI-dvorak.map.gz"
	);
}
static void svir_1410(void) 
{
	svi_reg(&(tinfoil.validation_items[1409]),
	        "dfc0fbda36f486a294e6349df3676a7263e9515b458675071e5edee77e6a5698c251b0b81f652ed34b2f43a3598181f0cadbd052046c1876fca9f1c6e9770257",
	        "/usr/lib/kbd/keymaps/legacy/i386/colemak/en-latin9.map.gz"
	);
}
static void svir_1411(void) 
{
	svi_reg(&(tinfoil.validation_items[1410]),
	        "01178e0acbc3dbfc4233d77c508977dd0f292645528d6d65881751ff697c297b19c387b533dd40312e20f07c180fd7e97cb62c5c6d531ed188535425038c558a",
	        "/usr/lib/kbd/keymaps/legacy/i386/carpalx/carpalx.map.gz"
	);
}
static void svir_1412(void) 
{
	svi_reg(&(tinfoil.validation_items[1411]),
	        "16f6bf5cd8e41eeccd28234ec578bc948c8118d0f47ff087a4545387cda23e050033d377df0b3ddca957e0dcb696aff1068fa2552bb17f280e89525a915dc074",
	        "/usr/lib/kbd/keymaps/legacy/i386/carpalx/carpalx-full.map.gz"
	);
}
static void svir_1413(void) 
{
	svi_reg(&(tinfoil.validation_items[1412]),
	        "9739387eab945d223d70eeab2289bb2259519a00c02e2c9bb4f15fc0bf5488a378dd760351b077f119af101f09f2db7df41a7087266376e9b8e9501a1d66dc66",
	        "/usr/lib/kbd/keymaps/legacy/i386/bepo/fr-bepo.map.gz"
	);
}
static void svir_1414(void) 
{
	svi_reg(&(tinfoil.validation_items[1413]),
	        "bfc414487933653181e637a090686280771923e18cbfa473707310ae8f0302f3c07950958107d3ddb98b9db6cd56f54e1376af056d91065f05d9e010e606601d",
	        "/usr/lib/kbd/keymaps/legacy/i386/bepo/fr-bepo-latin9.map.gz"
	);
}
static void svir_1415(void) 
{
	svi_reg(&(tinfoil.validation_items[1414]),
	        "a5fd8c425367738b7856d729de970bf89d3d6f02d1aa07e5dd21de7c3dea7c7f2e9ddd881072c4975242d107b3d1b480dc6e82784137de403b7a9621301117d4",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/wangbe2.map.gz"
	);
}
static void svir_1416(void) 
{
	svi_reg(&(tinfoil.validation_items[1415]),
	        "1e4e928bb472121bf05234dd8665c8fa84de1451d8812ff73b062e3d303d2c81c1435dc66b723ea62efe4286a2a81bad23fce80614c2164b549bfdc7a951b495",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/wangbe.map.gz"
	);
}
static void svir_1417(void) 
{
	svi_reg(&(tinfoil.validation_items[1416]),
	        "3604d00794b6e229565cd39e326f5604b12e5757df9d2fc3d39dfe8e3b75a7a74f0d47938461f2ef565969ecb3b40dc652d546ceead68446674a83e4871e8109",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr-latin9.map.gz"
	);
}
static void svir_1418(void) 
{
	svi_reg(&(tinfoil.validation_items[1417]),
	        "3604d00794b6e229565cd39e326f5604b12e5757df9d2fc3d39dfe8e3b75a7a74f0d47938461f2ef565969ecb3b40dc652d546ceead68446674a83e4871e8109",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr-latin0.map.gz"
	);
}
static void svir_1419(void) 
{
	svi_reg(&(tinfoil.validation_items[1418]),
	        "3604d00794b6e229565cd39e326f5604b12e5757df9d2fc3d39dfe8e3b75a7a74f0d47938461f2ef565969ecb3b40dc652d546ceead68446674a83e4871e8109",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr.map.gz"
	);
}
static void svir_1420(void) 
{
	svi_reg(&(tinfoil.validation_items[1419]),
	        "37ac16723ec8a30021933ca1f843e5366d81c401967780f1a5ad49490e9367a512904b1e6f2ee9fb414abffcf2a8a8955b99780c53f997554e43eb389fb7cef9",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr-pc.map.gz"
	);
}
static void svir_1421(void) 
{
	svi_reg(&(tinfoil.validation_items[1420]),
	        "b529222cc75e68f26cbc563883fc28dea2067cd14e683f8916837634270602d53efef0c888fc074f1ea26e95c1ac702043b8baa9497585879ee3dfe8131c8bce",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr-old.map.gz"
	);
}
static void svir_1422(void) 
{
	svi_reg(&(tinfoil.validation_items[1421]),
	        "2149ceac4aeb0136da915a495429306e1889031672f406833cab5de1652cbc3bbdaf797be8c656ad63ed513fdbdd949f3984578669a07eded5749aa061b2274f",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/fr-latin1.map.gz"
	);
}
static void svir_1423(void) 
{
	svi_reg(&(tinfoil.validation_items[1422]),
	        "78e1108d7b2d7f495e9652ad390b9764043bf81e49580d3f677d7600b7efe64c01dc0737b5455dad2b17b3af61895bf29c029193c08c34d88b992f42fd4e8021",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/be-latin1.map.gz"
	);
}
static void svir_1424(void) 
{
	svi_reg(&(tinfoil.validation_items[1423]),
	        "d4d789d69625648c16afc3df9f40af126e392de435d1cbdb693b8f09bbeceb6ff56ea647e0945b6c9abd1b6b6b61b81a9df934568d032a718370f469645aa552",
	        "/usr/lib/kbd/keymaps/legacy/i386/azerty/azerty.map.gz"
	);
}
static void svir_1425(void) 
{
	svi_reg(&(tinfoil.validation_items[1424]),
	        "264135fbc10308bd3f2106aae94613f5ff110bf55834a87ae964877bac538f65e352a0414c98e54f00120f1d9acfc84ea2c04b4acf42cb9640943272b5c440b6",
	        "/usr/lib/kbd/keymaps/legacy/atari/atari-us.map.gz"
	);
}
static void svir_1426(void) 
{
	svi_reg(&(tinfoil.validation_items[1425]),
	        "d77495daa20cc71d99e32bd3196f9c21fe9bd289ae4fbcd643dd84a0f606d575df69b5501ab5a3a639cf1c67ab227237d0448264ca095e626f18c0f2adc7bd04",
	        "/usr/lib/kbd/keymaps/legacy/atari/atari-uk-falcon.map.gz"
	);
}
static void svir_1427(void) 
{
	svi_reg(&(tinfoil.validation_items[1426]),
	        "fcde6edde6643c734237e4dccad176af042ef71507abe5abf8c6f77f324b10769583b2cfb7afd052ade680cad71db744c6246c78c7f8736ff6112209e805f425",
	        "/usr/lib/kbd/keymaps/legacy/atari/atari-se.map.gz"
	);
}
static void svir_1428(void) 
{
	svi_reg(&(tinfoil.validation_items[1427]),
	        "9c0aedc1ed57a823e46678b39b3163a26b2a2be182ae118dfca17ac83becb799a08929a66a5a150d259c6f1d80a168ef0462c1c955af36fd479c6b0be16da6ad",
	        "/usr/lib/kbd/keymaps/legacy/atari/atari-de.map.gz"
	);
}
static void svir_1429(void) 
{
	svi_reg(&(tinfoil.validation_items[1428]),
	        "245a948e35ba1b0c58c9a7cdb8cdf2b6ef34419c6b311e6394e61ff26dc5110e54e7669148191591ef659ef4852c9072677594e21a1d7c47ee0cb2c69f5f04e5",
	        "/usr/lib/kbd/keymaps/legacy/amiga/amiga-us.map.gz"
	);
}
static void svir_1430(void) 
{
	svi_reg(&(tinfoil.validation_items[1429]),
	        "5383ddd81fe9f49e35fadac8ff19c87b7b5c6ab5e76f8f9f5d411e4b02526069b2db7677c6ec2f4e5baa961bedf0d96eb9d0ae5dbbc441690a6aa71c4d4dd4ad",
	        "/usr/lib/kbd/keymaps/legacy/amiga/amiga-de.map.gz"
	);
}
static void svir_1431(void) 
{
	svi_reg(&(tinfoil.validation_items[1430]),
	        "2165dfcd09be7c315a9306ef3dd6cefb74bb54ef1eb6ba367c16e5056c32faf243ebdda4fa9293751a36c6af214f8510a5abb3a83cd0ab1daac08353ccbaa0f6",
	        "/usr/lib/kbd/consoletrans/zero"
	);
}
static void svir_1432(void) 
{
	svi_reg(&(tinfoil.validation_items[1431]),
	        "102614df8f54b2b98abdd0d9edde7725b881b4bee7f5683ec28b005ee86a60464b3916615ad0b236f34f865676e0e73516b4f98dd5e583165f96769cd2aebd2d",
	        "/usr/lib/kbd/consoletrans/viscii1.0_to_viscii1.1.trans"
	);
}
static void svir_1433(void) 
{
	svi_reg(&(tinfoil.validation_items[1432]),
	        "824196385cf1182a924d31d16565cc677ac5815ff9462e09be3c1931e86369dfde2c035bcff950a9009c3fd41de4d96b05702305cfcd8fb34e6dee291740ea16",
	        "/usr/lib/kbd/consoletrans/viscii1.0_to_tcvn.trans"
	);
}
static void svir_1434(void) 
{
	svi_reg(&(tinfoil.validation_items[1433]),
	        "78e8f18743830ddda30cc64a5475229f12ec10e9c558456a7285447039f4e10a24be04f65ad6786f892618135f9d6aa5d45698ed2158c0c785fdc0d4ecdccb5d",
	        "/usr/lib/kbd/consoletrans/vga2iso"
	);
}
static void svir_1435(void) 
{
	svi_reg(&(tinfoil.validation_items[1434]),
	        "0be8f0ba3f667194898e0d972862d5e42c425666fa54bb5e44e8b6f00998a820cf2b94226359bbd7d58d1295f85fc4dbe55b7c24b699a4d56f0633c568de5512",
	        "/usr/lib/kbd/consoletrans/trivial"
	);
}
static void svir_1436(void) 
{
	svi_reg(&(tinfoil.validation_items[1435]),
	        "20be28e46266df4c1663b5661e5a6f0c0d567b50092e305901edfd476d7a2fb4f20e943ca74c165c3c262ed59332a0ddf31d52fbcef880d7d6067f4c1a26204b",
	        "/usr/lib/kbd/consoletrans/space"
	);
}
static void svir_1437(void) 
{
	svi_reg(&(tinfoil.validation_items[1436]),
	        "0c437b2b6d4a8118fb6339a430b4b3799a00f415d723f27af381d621f0bc3562487258df845ab7a59f977a21d578bfeced519f6afe876712becfb180fff31f69",
	        "/usr/lib/kbd/consoletrans/null"
	);
}
static void svir_1438(void) 
{
	svi_reg(&(tinfoil.validation_items[1437]),
	        "debd74f04f3d0406bad042db56bb5e44279f14a11c245b4cdcc7ab060df40c42dedfdc2b151d39d09a6c717eebd41641cd86fa505a9be2e3c2b0422757db921a",
	        "/usr/lib/kbd/consoletrans/latin2u.trans"
	);
}
static void svir_1439(void) 
{
	svi_reg(&(tinfoil.validation_items[1438]),
	        "d2f12bc0fe20d8691bb16c1e49735c6fa411fc1260b3395909d12681910a90e85c9541f54252c2f10729e84fcc9544f80064d8bdc82c4e9601a0abc64e1fb3d6",
	        "/usr/lib/kbd/consoletrans/koi8u2ruscii"
	);
}
static void svir_1440(void) 
{
	svi_reg(&(tinfoil.validation_items[1439]),
	        "dadbaff719ad0f80531198dadf7fd97500d05ea5d2cd2a4f13b73426f91973aaaac42e75d9906e961feab364c8fe586bec2d9ef0837d10308a74435ea5f34b63",
	        "/usr/lib/kbd/consoletrans/koi8-u_to_uni.trans"
	);
}
static void svir_1441(void) 
{
	svi_reg(&(tinfoil.validation_items[1440]),
	        "b9302dc362bf96c6fbff3f496d8234c546db84993504df4b13b168311f6664a34ac486b580a44af4802b18c052c2cc9f209bca26fa0c42298a40a27087a57b07",
	        "/usr/lib/kbd/consoletrans/koi8-r_to_uni.trans"
	);
}
static void svir_1442(void) 
{
	svi_reg(&(tinfoil.validation_items[1441]),
	        "84fd45901623450342335b5b31e23eac394b2dde0da62a06b91322b9d776a210ceffa09f6656160ce2d24db4ec400dc5a0129dee26b83eed132e7f187ac2b7da",
	        "/usr/lib/kbd/consoletrans/koi2alt"
	);
}
static void svir_1443(void) 
{
	svi_reg(&(tinfoil.validation_items[1442]),
	        "00a383c27b3e8dd8923f830e8198bddf19ed467431bf874c990d906afa4156c9e5210c79ab3ddd3face08fb0ff44c70bac777407411eb35b33997324bf5fbdef",
	        "/usr/lib/kbd/consoletrans/iso02_to_cp1250.trans"
	);
}
static void svir_1444(void) 
{
	svi_reg(&(tinfoil.validation_items[1443]),
	        "0f046699b80455e68c96f7c041ef5181f28f1f9fc150cf8fe82b555853f45da54feee2e9df61cf7b729b7e12263423ea49bb308202e43d9c30deb01855d71140",
	        "/usr/lib/kbd/consoletrans/cp874_to_uni.trans"
	);
}
static void svir_1445(void) 
{
	svi_reg(&(tinfoil.validation_items[1444]),
	        "7294bb42655b568d7a14eb79bfe5572b5b337c8bb520c4b5958a44e1d7c7b3810a6dc839f6c85fe811b088122ae86337d00f5e58b94ea4d96c61d84ed47f9629",
	        "/usr/lib/kbd/consoletrans/cp869_to_uni.trans"
	);
}
static void svir_1446(void) 
{
	svi_reg(&(tinfoil.validation_items[1445]),
	        "668ae6f5cc1fb9fa933ef0da9139ccd56f1aa1d62529d60f580ef79619fe2dd152f74c5d423f2fe6263b58b37faa559395c23c0fead2c0ccb53df97e73d90931",
	        "/usr/lib/kbd/consoletrans/cp866_to_uni.trans"
	);
}
static void svir_1447(void) 
{
	svi_reg(&(tinfoil.validation_items[1446]),
	        "2e9db8907110abdc4fd8faba14fc4eef6c465d1dd64913d536182bd76cddbf34270dc67cbb5930d9680adb68961fbb2a232b0f0bc36a3820527b3241158a67ca",
	        "/usr/lib/kbd/consoletrans/cp865_to_uni.trans"
	);
}
static void svir_1448(void) 
{
	svi_reg(&(tinfoil.validation_items[1447]),
	        "56923384f021f3835f6cee0cf20918d896e53cbfde43d384e55e46789cc5d90d3ad17d4a4df7fc2f9222f13666e7df944f4bfe52946fc3c2b057bceb79560f88",
	        "/usr/lib/kbd/consoletrans/cp864_to_uni.trans"
	);
}
static void svir_1449(void) 
{
	svi_reg(&(tinfoil.validation_items[1448]),
	        "8696f9ca6a3599456683b9e4f5298b6691d88be16a57222a5c516a48aa02a556f76de06b99261a5985ac7d32e6400e4c100ac24ee0b1e461fed46cacc9296ed1",
	        "/usr/lib/kbd/consoletrans/cp863_to_uni.trans"
	);
}
static void svir_1450(void) 
{
	svi_reg(&(tinfoil.validation_items[1449]),
	        "f93a544d5c99aa80afa8c18bfc3721fa783a96de0e79a302755c801735d011d8aa3daf5ac25c9446d0265bd405f86bad4c2e19c5d7219293853b877aef54bc0d",
	        "/usr/lib/kbd/consoletrans/cp862_to_uni.trans"
	);
}
static void svir_1451(void) 
{
	svi_reg(&(tinfoil.validation_items[1450]),
	        "639f58e960317a555dfd05354e9fcded3406bc763760eb2e0c23b713a2ab38e0a378478d239b4e6985fa00858b253a5490fa2e494d7d4e8445c17e87d62b972f",
	        "/usr/lib/kbd/consoletrans/cp861_to_uni.trans"
	);
}
static void svir_1452(void) 
{
	svi_reg(&(tinfoil.validation_items[1451]),
	        "7e5cfdffb510731726a08e0bf474974cf06c90a4d4cc63d965d833252ba88523c3d522fec288dd27e78c94ca39f62e0459bae648f5ffe1b6dee5dc35b4a55ca2",
	        "/usr/lib/kbd/consoletrans/cp860_to_uni.trans"
	);
}
static void svir_1453(void) 
{
	svi_reg(&(tinfoil.validation_items[1452]),
	        "559cace07eaf6709e5bdcec4fc629456f718bb925da7e72fd93661b316558c7a06fd5344bf67e577dd0aaaf4ca1e229697ca8f0197fa55e85a24f6338962bc4b",
	        "/usr/lib/kbd/consoletrans/cp857_to_uni.trans"
	);
}
static void svir_1454(void) 
{
	svi_reg(&(tinfoil.validation_items[1453]),
	        "874a2e60f00858ea10ab75e25594ee784e07c9bb3420d7074a2c065c54599d43405c201cf820d635d535b75c85fe2e96dd21207fe12fa65c8640c77d4f8af97e",
	        "/usr/lib/kbd/consoletrans/cp855_to_uni.trans"
	);
}
static void svir_1455(void) 
{
	svi_reg(&(tinfoil.validation_items[1454]),
	        "7b77407aff7b45074df1d6ffe843d29f471874ec9df93f2cd40fd94b1b66d0393fbd633106a553ca513c19aa988bd868b1a69b8282287b437a5aa5c861341e39",
	        "/usr/lib/kbd/consoletrans/cp853_to_uni.trans"
	);
}
static void svir_1456(void) 
{
	svi_reg(&(tinfoil.validation_items[1455]),
	        "48ef339990cc3e4f3797a3ee3030e73a800add486561969dbb8f2f2483eda1422a06161ecba4986edf8ba912266048a63b68a92e3d4827e2db7953a762a13ad2",
	        "/usr/lib/kbd/consoletrans/cp852_to_uni.trans"
	);
}
static void svir_1457(void) 
{
	svi_reg(&(tinfoil.validation_items[1456]),
	        "c3c831671bef285ce8a8b3e46f64fff27dcac6f1710e8cf8a1e8fb8769fee900b664dea27de235164e279bd4e509c6a3e1ec9c10447251e2d9eabe87e0652c61",
	        "/usr/lib/kbd/consoletrans/cp850_to_uni.trans"
	);
}
static void svir_1458(void) 
{
	svi_reg(&(tinfoil.validation_items[1457]),
	        "e66456fc3cce5b9d38e524f7021fea83b71a851ab0ff2dc5dc8176ca89440273ce100d6dde8196824bf291b199059ddc209f901a8a36e624f08fa10d1fc21158",
	        "/usr/lib/kbd/consoletrans/cp850_to_iso01.trans"
	);
}
static void svir_1459(void) 
{
	svi_reg(&(tinfoil.validation_items[1458]),
	        "0f6a3ddaaf4f05e41f71b071e9055422140d09e0aae19026a1c15a22c1e2f63d0952a8097fd7cd7f3194f43eb67695ad2fa50981ada6636741561ba6c56fdb71",
	        "/usr/lib/kbd/consoletrans/cp775_to_uni.trans"
	);
}
static void svir_1460(void) 
{
	svi_reg(&(tinfoil.validation_items[1459]),
	        "b111d372c22dbf32058baae19da949613e13f49bbbed6b3d93195b3b47549eae7a1c25226efee4e15f03bea2e4d53e47fc50e1f9ae3aa901cb508c82c4c6af5a",
	        "/usr/lib/kbd/consoletrans/cp737_to_uni.trans"
	);
}
static void svir_1461(void) 
{
	svi_reg(&(tinfoil.validation_items[1460]),
	        "9dabd06c709042350aceebfa98c57c4e68dbcc57dc59af99d3fd07040c7bfa5ffb4ad37b21b2ef4a0e5281104f44750858d7683f51c1da209d6c880aa7e3a1c5",
	        "/usr/lib/kbd/consoletrans/cp437_to_uni.trans"
	);
}
static void svir_1462(void) 
{
	svi_reg(&(tinfoil.validation_items[1461]),
	        "dcee4904107788d9f14b37cbf428a8106bee69e2a6865afc99dd59a7113c585107a1398e01fa6c231a82f87abc9ee11922a1a40fd9ac6646fbfdaf6b9ca04452",
	        "/usr/lib/kbd/consoletrans/cp437_to_iso01.trans"
	);
}
static void svir_1463(void) 
{
	svi_reg(&(tinfoil.validation_items[1462]),
	        "2d0a98627f434dd720361c98da4714bb95854d74d9fa5447c2f888af67b49e5191339c75d6789d855b7ab75e60632a2f4d03e29f72de03c97291feb5d584172e",
	        "/usr/lib/kbd/consoletrans/cp1251_to_uni.trans"
	);
}
static void svir_1464(void) 
{
	svi_reg(&(tinfoil.validation_items[1463]),
	        "c5259a0c6aa13bf2423d71e2eef582ba545ac8f2840d57147a412356a4558577e03ddbaed023c2860a8170b3b1d755c0a0ef059e70defc58739e2d1b2b2704b8",
	        "/usr/lib/kbd/consoletrans/cp1250_to_uni.trans"
	);
}
static void svir_1465(void) 
{
	svi_reg(&(tinfoil.validation_items[1464]),
	        "62bf3e2d60ad7e40d3b529a109a72b69e383291d12749b8f01acb99c1156d043bea22664183400d581b810b0cefe5717679d34b45c2d7c9752762e737687f2db",
	        "/usr/lib/kbd/consoletrans/baltic.trans"
	);
}
static void svir_1466(void) 
{
	svi_reg(&(tinfoil.validation_items[1465]),
	        "1260da5c191ff05d2e8c8580163d64eb3ba91dca1ac5491971b9113caff28ecd8e00353f6c9911a7e7df3e9ece17807b05fef1ed66d3e2fff5c40f5ffec75f63",
	        "/usr/lib/kbd/consoletrans/8859-9_to_uni.trans"
	);
}
static void svir_1467(void) 
{
	svi_reg(&(tinfoil.validation_items[1466]),
	        "fa81466351f2babd7aa99814a117e97766c66a71bdf7d8f5f4a1bbc33d500d3bf95666eb29f24870f027129e15ba7f9b411bd3c700bb73c6511fa45673e81326",
	        "/usr/lib/kbd/consoletrans/8859-8_to_uni.trans"
	);
}
static void svir_1468(void) 
{
	svi_reg(&(tinfoil.validation_items[1467]),
	        "bb21a5e57751117d58cea76c32712c8d64f91b60e198e287ba2deb73b3dacb9381d9b4a5ca0b232025a79fc7265b38393e117c3ae72574bf32fb13803294ae6c",
	        "/usr/lib/kbd/consoletrans/8859-7_to_uni.trans"
	);
}
static void svir_1469(void) 
{
	svi_reg(&(tinfoil.validation_items[1468]),
	        "7fa2cf2b86b50e098fc6c6100af071b204329c92629084ec65ed55909dea89eaf14ee87342a7d18d67d59f0e509261cd0262eda1224454064a645fa3a3a020b2",
	        "/usr/lib/kbd/consoletrans/8859-6_to_uni.trans"
	);
}
static void svir_1470(void) 
{
	svi_reg(&(tinfoil.validation_items[1469]),
	        "c695702900f59e89bd60b89631a4230ecd7f010b3a138af261484051b343d4d844076af07ecdf67168a13a71354d173e99c96f9f6bec743cb771eb83784fc4bd",
	        "/usr/lib/kbd/consoletrans/8859-5_to_uni.trans"
	);
}
static void svir_1471(void) 
{
	svi_reg(&(tinfoil.validation_items[1470]),
	        "7e71fe326fcfa412976432685db480ba47e0766deb2f35870b3208aafb05ec7407c7ebe5362e3dff15961605735dd1f068edb57e4429b0c119deab3b901566e6",
	        "/usr/lib/kbd/consoletrans/8859-4_to_uni.trans"
	);
}
static void svir_1472(void) 
{
	svi_reg(&(tinfoil.validation_items[1471]),
	        "4f5b5424b26ecd0e596827eff5eeb3f79a6ad379c3a412fed44345be996fd1e4b7c6490b467b94855f40fe9c5306d04473a4e8b0785ca475b692e7e35a03fd7a",
	        "/usr/lib/kbd/consoletrans/8859-3_to_uni.trans"
	);
}
static void svir_1473(void) 
{
	svi_reg(&(tinfoil.validation_items[1472]),
	        "0eb71bfd122488d427c1ce88b0e99f6f84334f4af01b025a7886e45867656096472c5a879ebd371ec2c484e8a6cd8b2decc9f3b94595e8ebc14c2ad121509288",
	        "/usr/lib/kbd/consoletrans/8859-2_to_uni.trans"
	);
}
static void svir_1474(void) 
{
	svi_reg(&(tinfoil.validation_items[1473]),
	        "76c9b6f79c7b265ca5e18c93c8ea14dab907a194ea51023cc7b9482bb4cdd99788d4e43900a3adf847d07890d82a11038d3a695ac2c57fa24152a53f42658d8d",
	        "/usr/lib/kbd/consoletrans/8859-1_to_uni.trans"
	);
}
static void svir_1475(void) 
{
	svi_reg(&(tinfoil.validation_items[1474]),
	        "f760fa06de261faa873787ecf5df3267bb5498ec1fa529568b0d28429bfedb94821cdcef1398664341516c2807081e8f31b97d9f31bbc43fea455918fc04d2bf",
	        "/usr/lib/kbd/consoletrans/8859-15_to_uni.trans"
	);
}
static void svir_1476(void) 
{
	svi_reg(&(tinfoil.validation_items[1475]),
	        "28638c64d56bc33c66f183879f9396dbc13f7b751a8861f0e94dd2dad8fb0934aa8564333cc3fd58195a664e249f47c3370a61e5c1f89b399825f3d6c792278d",
	        "/usr/lib/kbd/consoletrans/8859-14_to_uni.trans"
	);
}
static void svir_1477(void) 
{
	svi_reg(&(tinfoil.validation_items[1476]),
	        "09abca69962e2aff710962c21f325213203305b5bd833a37503251a3175cdb9e7ea06ba8e6897a967a75cd7e1cb2b34d439dfc435a48b2d6a708510add85a148",
	        "/usr/lib/kbd/consoletrans/8859-13_to_uni.trans"
	);
}
static void svir_1478(void) 
{
	svi_reg(&(tinfoil.validation_items[1477]),
	        "d9e61fcd1bd0e6de8dceb24f8ae4db7b87b3b577707a99979a1b9301c000dda6b5599a7fa95b0678a74f9d86f58cb7f0e5142a5967f8aea55f86a1d0a2b37a77",
	        "/usr/lib/kbd/consoletrans/8859-10_to_uni.trans"
	);
}
static void svir_1479(void) 
{
	svi_reg(&(tinfoil.validation_items[1478]),
	        "0ea2f716ed774f5c0f846067f273d42f198d31d0e602e68fdae299b3ff094c88bc6d5ead8e4e24720dc01d89b93f2d15aeccc37ecd1106a0f3bebe826707aa98",
	        "/usr/lib/kbd/consolefonts/viscii10-8x16.psfu.gz"
	);
}
static void svir_1480(void) 
{
	svi_reg(&(tinfoil.validation_items[1479]),
	        "f3b2b4f99aeeb61bd54200677048835abf09f007f252a1cd17751670f687243bc50cc832245875736b4e9ce391d3e1fbf425c253dae98dc512a456882f3f7d56",
	        "/usr/lib/kbd/consolefonts/tcvn8x16.psf.gz"
	);
}
static void svir_1481(void) 
{
	svi_reg(&(tinfoil.validation_items[1480]),
	        "1f887d69a6340ef6c7a4cadadd3c2227471c6c75a9c9d8aae8f449f2263d09803969cf3abe9abc309c63b4b8c0cb8aef07433e5d1691e820c19d769ef6c392fc",
	        "/usr/lib/kbd/consolefonts/t850b.fnt.gz"
	);
}
static void svir_1482(void) 
{
	svi_reg(&(tinfoil.validation_items[1481]),
	        "fec44c42790e823fe83a5d564c56af8542aecf192ae9aa0cf9867b4438522a8f62b0e02ca9b5ba80ec6e013f898eca37bc8dfdded5ef1e25739a7eb137fa50a3",
	        "/usr/lib/kbd/consolefonts/t.fnt.gz"
	);
}
static void svir_1483(void) 
{
	svi_reg(&(tinfoil.validation_items[1482]),
	        "29a6616d058b249de9bf48fe615e9f368fd502ff4200541e1f3b9591c5fb4b07cd1eac6e8fa42eecd2b359b409da5c3751252f9e9ec2909400003ca3d160fbd8",
	        "/usr/lib/kbd/consolefonts/sun12x22.psfu.gz"
	);
}
static void svir_1484(void) 
{
	svi_reg(&(tinfoil.validation_items[1483]),
	        "6c60ea69f968d1178e0cb6aeed4344a7d9f259ed1da1e7a5e4149facde5eb57933354a1275f49180a9339f325bba5a736bc9e23c58d2ae5e957088a1b05675f2",
	        "/usr/lib/kbd/consolefonts/solar24x32.psfu.gz"
	);
}
static void svir_1485(void) 
{
	svi_reg(&(tinfoil.validation_items[1484]),
	        "13b13ea124cb0cba88bd1ec6cc00fc27c7be65a51cc9d4a369e1eb8cab0ccc69583fe34a5f6d6a857d3ccca49bdadaa7192ccb1bfaab4f59b9139e1bf5e18e11",
	        "/usr/lib/kbd/consolefonts/ruscii_8x8.psfu.gz"
	);
}
static void svir_1486(void) 
{
	svi_reg(&(tinfoil.validation_items[1485]),
	        "0c498e1526ffda501310e1b53d0a88288b5a8dd4a0f2c9c4efc520dab32d80aa3eb46113572b4fd6f2b4ccb44b5008a8a7cfb99b160beb32747eb2db0c641d4e",
	        "/usr/lib/kbd/consolefonts/ruscii_8x16.psfu.gz"
	);
}
static void svir_1487(void) 
{
	svi_reg(&(tinfoil.validation_items[1486]),
	        "050d9822af3a44ff2439521dbab9ed4d4dee011b39553b447c4a2429554b65d8c9c97c69ad9247e89b71c980db66f5f18d843a0093ae091ffeb0410f6ebd9486",
	        "/usr/lib/kbd/consolefonts/partialfonts/none.00-17.16.gz"
	);
}
static void svir_1488(void) 
{
	svi_reg(&(tinfoil.validation_items[1487]),
	        "0a2d768e84f03e3ef8488c3b6780e75262c59818a3245d273605f6ad220ecbf9950d7cb902ec9dfe3cb828730b3fc1e97ee0b92b3c95aae2418a7984ff6dc86d",
	        "/usr/lib/kbd/consolefonts/partialfonts/none.00-17.14.gz"
	);
}
static void svir_1489(void) 
{
	svi_reg(&(tinfoil.validation_items[1488]),
	        "444f259cee24396140fd7f2c843e1642faa2010ef60eab81a9e756ec5d65aad8ab43cd55f751eb1731f6373c0cd7c725d6a74bf9028564ac65cf85755f2d1421",
	        "/usr/lib/kbd/consolefonts/partialfonts/none.00-17.08.gz"
	);
}
static void svir_1490(void) 
{
	svi_reg(&(tinfoil.validation_items[1489]),
	        "e1f968379058bcfa84cfeba14ebe73363ef17abf35614c4f6107e944ab64e908e969a2b1c1853ffe782ce0ce52c9a23d8dfcee09becdaaf742faf5a2962a636e",
	        "/usr/lib/kbd/consolefonts/partialfonts/cp437.00-1f.16.gz"
	);
}
static void svir_1491(void) 
{
	svi_reg(&(tinfoil.validation_items[1490]),
	        "9df95312f8d75a263f383d9918e6537622fd278f17adf2877db80bff11e5935dd7e3687fed053740b175292a722afe57c45a5b559f3eaa4746f45b5e61818fc2",
	        "/usr/lib/kbd/consolefonts/partialfonts/cp437.00-1f.14.gz"
	);
}
static void svir_1492(void) 
{
	svi_reg(&(tinfoil.validation_items[1491]),
	        "1e56167ec437c50946e2e80304c2f469930fb3d1941b2458c2bedb9412d87ac744d73c3eee66b04034b485f734e1451846ff3647ee0ace61418c6ec2f5ffe3ab",
	        "/usr/lib/kbd/consolefonts/partialfonts/cp437.00-1f.08.gz"
	);
}
static void svir_1493(void) 
{
	svi_reg(&(tinfoil.validation_items[1492]),
	        "bffdc66910aec5fba9c1f32853a3b00e9af447b4284e236016bbf3b19bd1b0a5ece1eedb53b537287b5bc106ff1d7021695e54fdfebb41ec2d32b435acb3bb3d",
	        "/usr/lib/kbd/consolefonts/partialfonts/ascii.20-7f.16.gz"
	);
}
static void svir_1494(void) 
{
	svi_reg(&(tinfoil.validation_items[1493]),
	        "73845b8c3178b586d435bb844d0a257747601fa4c9ba9bbecc75daa1fbfa9db32141e2a53a2dba778ff68990928841705095d4ec07e04712d59bba2962ec1f52",
	        "/usr/lib/kbd/consolefonts/partialfonts/ascii.20-7f.14.gz"
	);
}
static void svir_1495(void) 
{
	svi_reg(&(tinfoil.validation_items[1494]),
	        "bf27015881295790e80b8ea2b9508848b46a92490bb1b02268d1b375d9b22ee26fad0e670edee51a84e87d6596886fd03d0d340a04224b9408dbfd7b083c722b",
	        "/usr/lib/kbd/consolefonts/partialfonts/ascii.20-7f.08.gz"
	);
}
static void svir_1496(void) 
{
	svi_reg(&(tinfoil.validation_items[1495]),
	        "e91d1064a3b904f3889c7bdd5a1c11b8ede83e9da936914009a9a54f86f80d1234debe672fde8ff5b378ebd6c167962b8dabd38d926ea928397db63bbb288002",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-9.a0-ff.16.gz"
	);
}
static void svir_1497(void) 
{
	svi_reg(&(tinfoil.validation_items[1496]),
	        "46b790cedbc5d84fdc74a356a257ca70dcd646a67d360391a77e810d97dbf232ee3650ed3c68f1c22e1260e074c559c218236b8cca049522e49beb35e969c019",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-9.a0-ff.14.gz"
	);
}
static void svir_1498(void) 
{
	svi_reg(&(tinfoil.validation_items[1497]),
	        "36ec9da44ecbb59c114ad33646ca0cca09b982f631552fe196872521de580d8062aefd8c89dd4cac08ca0f0e76d05b6a9df595046597c0ce379f0c438424ef85",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-9.a0-ff.08.gz"
	);
}
static void svir_1499(void) 
{
	svi_reg(&(tinfoil.validation_items[1498]),
	        "01dc140d98fdd12e802454d83827e3056257319f437edc7d7d28761f33efc47ce73ec30c8e8bd32c0bbf4db51a286d19a09e3663e90f2431758aef424de2c56c",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-8.a0-ff.16.gz"
	);
}
static void svir_1500(void) 
{
	svi_reg(&(tinfoil.validation_items[1499]),
	        "d26ab388ef761d240038b31b230d503a9eda83d12ebaf42cef21b33041eff9c9037a9844d6e1adddc4fffa92667290e1cb9c199bace9f7c47adb6029b78991d7",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-8.a0-ff.14.gz"
	);
}
static void svir_1501(void) 
{
	svi_reg(&(tinfoil.validation_items[1500]),
	        "3a1c28fafdadb8aacec121cbfe073eb41a602785629df187807bd459e44e10bdf75b1e9f2d329dd503541e92591709599762a249e19aed43343d74be87a0a001",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-8.a0-ff.08.gz"
	);
}
static void svir_1502(void) 
{
	svi_reg(&(tinfoil.validation_items[1501]),
	        "d07b0a9428cb9ecff85b38b3988f23e2c6b257a880782add5a89cda0ad57702798402dfddc3dd16e9637711db54265870da95602423caaedfdf4c71be6bda1d4",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-7.a0-ff.16.gz"
	);
}
static void svir_1503(void) 
{
	svi_reg(&(tinfoil.validation_items[1502]),
	        "f1a78022c67b2412450e92d01f3ca152873653178d52effa19fe9270bec382291a8db0075d98472831722168f4607d8c70300e62ebcafdda3995e2592c0a0554",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-7.a0-ff.14.gz"
	);
}
static void svir_1504(void) 
{
	svi_reg(&(tinfoil.validation_items[1503]),
	        "d57e3cd0201303fbfd79b71966a23ac4afb4bcaea1f82d2eb352baad8ce22e6632dfd0c07f4c90692a484189f3ba7fff00f3a951cbddb7912eadab30a699deb4",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-7.a0-ff.08.gz"
	);
}
static void svir_1505(void) 
{
	svi_reg(&(tinfoil.validation_items[1504]),
	        "a09b86fb55c79cc06241cc51d6c5b0716bea3946b45a068e31e397e589fb1ddf1e2a0f14dd0179e29b8b403b622e4cf9ac3c8f98e522bcb3906dcd5200cf154d",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-6.a0-ff.16.gz"
	);
}
static void svir_1506(void) 
{
	svi_reg(&(tinfoil.validation_items[1505]),
	        "b9aa2d88ab109ff04ab2fdb353e566a037fb89725fe1fbadd207507d866e6a750e4402007192ffea5f5bda8af58640edf7f72b54b712fff84d787b3a176cbdb6",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-6.a0-ff.14.gz"
	);
}
static void svir_1507(void) 
{
	svi_reg(&(tinfoil.validation_items[1506]),
	        "ff0a2d36db9c98e815bb21936b83bd5dae18d3df4954e18937e058ddd202c6f902f656302e0ad2fb1d3e2f060782bf40243e5f97064b448e8ff904e3e6990b11",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-6.a0-ff.08.gz"
	);
}
static void svir_1508(void) 
{
	svi_reg(&(tinfoil.validation_items[1507]),
	        "e9702aea7aae27218f1dbdcf44dec52cb23736c8b9a6ada4beecdd767f813ed23ef6a612e08d397a1453df4c03ac88b42eb97d650dbb3b514871dcdb83176291",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-5.a0-ff.16.gz"
	);
}
static void svir_1509(void) 
{
	svi_reg(&(tinfoil.validation_items[1508]),
	        "0610ad39c85ec673d7fb9d3b7e05939424d7a162883365a90ec1a35bc396f82dcba2a41e6c1a4bdbd2fec5dee776271820c3a8d85b3d5b239d5021fb0637b1bc",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-5.a0-ff.14.gz"
	);
}
static void svir_1510(void) 
{
	svi_reg(&(tinfoil.validation_items[1509]),
	        "f46b21cabda22953c3bada7050238c8d27f0c43ace53040bc0e82ebf1ad00fe031731121b9adc5aa24a845b9942bfea4b4b9b738ea00edd4640a91dd71b165b7",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-5.a0-ff.08.gz"
	);
}
static void svir_1511(void) 
{
	svi_reg(&(tinfoil.validation_items[1510]),
	        "70ceb77ef3eda4d5fee9be94e91b7c3d7cb095934d1e42baf3c7e4b82d910aea5046efcf6cc2268082059af61fe1264be3859a1537980659c5166365b12efd5a",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-4.a0-ff.16.gz"
	);
}
static void svir_1512(void) 
{
	svi_reg(&(tinfoil.validation_items[1511]),
	        "d0af5b625f04ed9ca346d0f495486e1d707c021aac080e17308280a4d2eeaa202e1f71940716806e9aa247971580ae1e67f2f237aa236dc4ebaf5dd143c35cd7",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-4.a0-ff.14.gz"
	);
}
static void svir_1513(void) 
{
	svi_reg(&(tinfoil.validation_items[1512]),
	        "e53b11dbafe366fa03e40e24071d2c2da5fbf1eed4a3a7b4454a6fa966129e0cbc96f9eff44c5a86c72ab5e18ef6052f1dca6d555a8d2956f0b835633cf2bcb1",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-4.a0-ff.08.gz"
	);
}
static void svir_1514(void) 
{
	svi_reg(&(tinfoil.validation_items[1513]),
	        "b1542b2cc44bdb72883296c55c81f71810bf21dc1137b0d030e21afe8da21aba3892ade9015f89a76ba0b1a0bae4033f257f698823482edbceb228775f32d658",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-3.a0-ff.16.gz"
	);
}
static void svir_1515(void) 
{
	svi_reg(&(tinfoil.validation_items[1514]),
	        "4100b8d56690a49add11eb79c5920338364ed217cb688e7da89a511c5b54859aa6f0454571e8ae6c683606ca450745200b99862abd11d94db45b733d0c81946d",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-3.a0-ff.14.gz"
	);
}
static void svir_1516(void) 
{
	svi_reg(&(tinfoil.validation_items[1515]),
	        "c47b249a7f221f967c20336653debd1e054b7df43bc8040150516631d75dc41751bbf0945f0ff588cd1970fc5583aa20f6612d8514b6e2bc40a1426035fb98bd",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-3.a0-ff.08.gz"
	);
}
static void svir_1517(void) 
{
	svi_reg(&(tinfoil.validation_items[1516]),
	        "e29ea7c34322754b33db2f718865075a9fa497e2d047a5805ce8db02be8c2a7910825e97a7a78f95f0f85c7b541ec9d46994c77b094e2eee0f936dbbe81d186e",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-2.a0-ff.16.gz"
	);
}
static void svir_1518(void) 
{
	svi_reg(&(tinfoil.validation_items[1517]),
	        "04d7bfc4dff9487d9e736aea8d8430d59272b66bd1b5b646a85a3f97d255b50bcc6ccefad06500ce1bea25377e472336ea974385f31db31f388f1c8ce1fcefc4",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-2.a0-ff.14.gz"
	);
}
static void svir_1519(void) 
{
	svi_reg(&(tinfoil.validation_items[1518]),
	        "ab2e5448e51ec2ad5f9b674cdd8598eb76f33f106eb43d48bacc3284c99748e2ac9b174b5cdd8ebbdcf76c3b9c230be9472a161beaf9e380dace0f15ccc3df8f",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-2.a0-ff.08.gz"
	);
}
static void svir_1520(void) 
{
	svi_reg(&(tinfoil.validation_items[1519]),
	        "7bec3465fd61da22a581871ae4bcb672f7edcab936f440664938faab859a96b623b13e43df588acaa0c40b891e8c89f97045c417386e3832f2981674cc782168",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-10.a0-ff.16.gz"
	);
}
static void svir_1521(void) 
{
	svi_reg(&(tinfoil.validation_items[1520]),
	        "e72d001a669cd0a813c64eaac74566c55259c9bea89b59b10849025295ceeb7e7060b382bb2de63193188dce2f3b6b39bade54cb26c57425855e1cd45fa96788",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-10.a0-ff.14.gz"
	);
}
static void svir_1522(void) 
{
	svi_reg(&(tinfoil.validation_items[1521]),
	        "2cc1edb88c5295f65a62c220ae69aabc6ed9932b2ee1e6fcc6666e4ba9a075822291127a2e2da9a36c82924325c27afcb5513fcfe1ce1643ba628bc40bacfe8f",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-10.a0-ff.08.gz"
	);
}
static void svir_1523(void) 
{
	svi_reg(&(tinfoil.validation_items[1522]),
	        "35b1b2b28c186db372e7a1561914dd87e4bcaf05fb3a3eba064469c485d5c9bf4a288f934c5d3932f509c80c1375a5dfa621af66905a3ea997dbb24f0f9df8d2",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-1.a0-ff.16.gz"
	);
}
static void svir_1524(void) 
{
	svi_reg(&(tinfoil.validation_items[1523]),
	        "f0331724956890645aa2fc3863023f20872aed5e8b6f2db4d581db2d7209e0439fc5e39ed549ce9abb30925dd07b47fc59cd936b6183359e85d0da57cfca1251",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-1.a0-ff.14.gz"
	);
}
static void svir_1525(void) 
{
	svi_reg(&(tinfoil.validation_items[1524]),
	        "a4c79bb0ecf4dc1982dad849afd539e3724446ba1c8ece65dec6d2759409df19939516f4fab6a8e1718d6897d6fb37402d34cc0f44257bcfd36094aa2a38bd08",
	        "/usr/lib/kbd/consolefonts/partialfonts/8859-1.a0-ff.08.gz"
	);
}
static void svir_1526(void) 
{
	svi_reg(&(tinfoil.validation_items[1525]),
	        "8203d39daacc8d33e6c871d6c675692be947c0f266e0a5770d52a44a78259d2944f0e4ef19f3f53bc66125d1f703ac17ebe779828bbda22f97dcf66881f06f0e",
	        "/usr/lib/kbd/consolefonts/pancyrillic.f16.psfu.gz"
	);
}
static void svir_1527(void) 
{
	svi_reg(&(tinfoil.validation_items[1526]),
	        "e25806494615a5a816db35dd1ebcdcc789e7f9fd913bf93a0362a19d6d524f2ba606fc67327fc1ab14ee5153888a63c445346ea013cf9b6c22d53bd231238b15",
	        "/usr/lib/kbd/consolefonts/latarcyrheb-sun32.psfu.gz"
	);
}
static void svir_1528(void) 
{
	svi_reg(&(tinfoil.validation_items[1527]),
	        "6e23b6e4761e97a83faeb41050ac857ec79262913f551761927cce5ddadcfbcc3803e9696794b9c789742159b54feaa994c7ca4399f9e63326aaf21ee84fafd6",
	        "/usr/lib/kbd/consolefonts/latarcyrheb-sun16.psfu.gz"
	);
}
static void svir_1529(void) 
{
	svi_reg(&(tinfoil.validation_items[1528]),
	        "dc338b1842961ec76f0494eb2aa2578296cac9b0e3c7872fc6b6983349e9e6fd56ffc2915536a70a2db3eb13baa5477fb2fb7b44478489bbbc7e094b2fa8ab3a",
	        "/usr/lib/kbd/consolefonts/lat9w-16.psfu.gz"
	);
}
static void svir_1530(void) 
{
	svi_reg(&(tinfoil.validation_items[1529]),
	        "b70831c07721dbf6cd3995e6861ba2317a4faf48add043ed6961cf44ecaf07a5454cd7b5e04e84795b69d52079ec845362acab8747d9c5413603a11d65c846a6",
	        "/usr/lib/kbd/consolefonts/lat9w-14.psfu.gz"
	);
}
static void svir_1531(void) 
{
	svi_reg(&(tinfoil.validation_items[1530]),
	        "47b978a47d09d0c9b6f09dd677bad2c2b1eed443f0f30310e6e6231c53d4590cfd504f7113a0bacafc3a3d1bfb7485c8592274bd8144913c5615f9351e5ac56a",
	        "/usr/lib/kbd/consolefonts/lat9w-12.psfu.gz"
	);
}
static void svir_1532(void) 
{
	svi_reg(&(tinfoil.validation_items[1531]),
	        "f810da93953b9e0d1df0c2cc6b16da9ed0a23546363016f49479b29f975e2a76a189885faf84e82bc77bb14b170cd7c42e6bcd81abc42b593b790eb572599d03",
	        "/usr/lib/kbd/consolefonts/lat9w-10.psfu.gz"
	);
}
static void svir_1533(void) 
{
	svi_reg(&(tinfoil.validation_items[1532]),
	        "6c476417315fa8672a1f03a7798b327a77077ee5c0420bfa3d0d07bf2e7beb187327d9ab2fe24449db3fa6f9256b6b8240b0091eb3679b56ee792a8d65813c5e",
	        "/usr/lib/kbd/consolefonts/lat9w-08.psfu.gz"
	);
}
static void svir_1534(void) 
{
	svi_reg(&(tinfoil.validation_items[1533]),
	        "03bd8f42b03b2fa1edea6718a55de1747097924cd5bb4c5627afce32e19db626a88f8ddd92076dacb1c08d6c24275a35629ad15f4cd7618e00a87505fb13faee",
	        "/usr/lib/kbd/consolefonts/lat9v-16.psfu.gz"
	);
}
static void svir_1535(void) 
{
	svi_reg(&(tinfoil.validation_items[1534]),
	        "87cbc4cbd513ec0b5307cc1451d17de1ec3ee384a872b629e187910117a493091260e6497ddc8b35e8989062bf5c6ff8eb7f3a8a13f978fbbe134b4a0dc117bb",
	        "/usr/lib/kbd/consolefonts/lat9v-14.psfu.gz"
	);
}
static void svir_1536(void) 
{
	svi_reg(&(tinfoil.validation_items[1535]),
	        "9d8493be576eabd11731c98697081fe4aa27d07eb7b8ff0b525dea456664e5cb319b48465e1b1def3be2bbc1de8c3965b7cfe133fb1c4933e272a1ff343a308c",
	        "/usr/lib/kbd/consolefonts/lat9v-12.psfu.gz"
	);
}
static void svir_1537(void) 
{
	svi_reg(&(tinfoil.validation_items[1536]),
	        "36e23cdcd713b2aa6fae7f63849490c46f50fb026e10c32f87582badaaf7d14b4bd8b06defc8c176c053d19df23ae9d5c434e151adb639ad6917d5748f6b63a3",
	        "/usr/lib/kbd/consolefonts/lat9v-10.psfu.gz"
	);
}
static void svir_1538(void) 
{
	svi_reg(&(tinfoil.validation_items[1537]),
	        "e48759b59dfa59b46829453a2ce9d4a043c6bbc3e28ebe59988ad1bb81c30fb66c71385258d3ea89df24f8817b00f9b6f0508df12f20e49d3f5265f7d3783389",
	        "/usr/lib/kbd/consolefonts/lat9v-08.psfu.gz"
	);
}
static void svir_1539(void) 
{
	svi_reg(&(tinfoil.validation_items[1538]),
	        "1b32c8d661975f510d144027aa4e8ca7abf63d55623ef83d632ebc6b5256dcc9735aa2b17e15263de70905e9d64acea8a6f75b281cb825a61ba0392817e8a8ca",
	        "/usr/lib/kbd/consolefonts/lat9u-16.psfu.gz"
	);
}
static void svir_1540(void) 
{
	svi_reg(&(tinfoil.validation_items[1539]),
	        "ccb9081fbd3c6b0a8a2bd2e2576e36c747e1103b2ffa927d23db111594e12654c3ea97012bd0d9a0741f021b65713c0274a69aa3aa6843d8ec9b6c62d605545c",
	        "/usr/lib/kbd/consolefonts/lat9u-14.psfu.gz"
	);
}
static void svir_1541(void) 
{
	svi_reg(&(tinfoil.validation_items[1540]),
	        "83d3f9e775b67f28254c66d1960c700b0f504a51fa4341fa3f3b0460688d0960ceb859389eb5d99594454ae378d1aebc23d268a46b9555dc2d36365f35104f85",
	        "/usr/lib/kbd/consolefonts/lat9u-12.psfu.gz"
	);
}
static void svir_1542(void) 
{
	svi_reg(&(tinfoil.validation_items[1541]),
	        "71fc7a8dffa2c2ac28105629cb0836079b6181f92660c255d57e22918a2388c2d26aa378edbbd58fea3929ef6a44c5fd0197a84942fa0d11a755b4eee743a125",
	        "/usr/lib/kbd/consolefonts/lat9u-10.psfu.gz"
	);
}
static void svir_1543(void) 
{
	svi_reg(&(tinfoil.validation_items[1542]),
	        "b7c58ce54db23905ba03aa41d1c0c4d77bc3799208b66e3b3ca091fa1716dfd472f4350a6e09dc7b8acc623a975d1b9458909423c57cf734d91cc4ab82c42616",
	        "/usr/lib/kbd/consolefonts/lat9u-08.psfu.gz"
	);
}
static void svir_1544(void) 
{
	svi_reg(&(tinfoil.validation_items[1543]),
	        "6f6e52e2ddb5ec00aff2faed88bed31151bae3f37ed6365da6038f47161273d079d2541a7c62a150824bfea9039ae737afdbba6136c5c213fedc1d0ea2dcb489",
	        "/usr/lib/kbd/consolefonts/lat9-16.psf.gz"
	);
}
static void svir_1545(void) 
{
	svi_reg(&(tinfoil.validation_items[1544]),
	        "99ee8a2f69df6ea4a69c977ba9d0809e003d7ad7466880d89aa17e49fa26c08008b8fe81e616ac2431668de46168984c2c4ed12866c626e23e082c16391f9074",
	        "/usr/lib/kbd/consolefonts/lat9-14.psf.gz"
	);
}
static void svir_1546(void) 
{
	svi_reg(&(tinfoil.validation_items[1545]),
	        "3a5c2aa6ba7433c3dc03f38273ce62a36fbc5af200de5c6bfc4ab113ebd950d9015219592b921eea4fa9ec5685aee6139ccbb3b090c62cd84ea6b1bdc2a8e69f",
	        "/usr/lib/kbd/consolefonts/lat9-12.psf.gz"
	);
}
static void svir_1547(void) 
{
	svi_reg(&(tinfoil.validation_items[1546]),
	        "769508f809288a7f97f913a0d5f67be24a7467f5c5d3759979d27a4fd2c15c4d06b2cb39c2ba0e9d19d6890f47f5c5d3a7ff0cb9310514b0c164c055d6636f60",
	        "/usr/lib/kbd/consolefonts/lat9-10.psf.gz"
	);
}
static void svir_1548(void) 
{
	svi_reg(&(tinfoil.validation_items[1547]),
	        "5f52f4c9d2a3960c7e0e3cd98e93ca518fa5c96cd59eb6b803cb41ad3055934687503d5337a4c59997fa31d2c838097949a2ee05235dbe96777160ca71774103",
	        "/usr/lib/kbd/consolefonts/lat9-08.psf.gz"
	);
}
static void svir_1549(void) 
{
	svi_reg(&(tinfoil.validation_items[1548]),
	        "61c11df5a98f73d9c0e40e9be1e68c6ec94bfac28f93b1e0aab16e2b65273b0d35740defdff281bcf5c16b54b26f973d8bf90cd7473915b453bd54de96494d1d",
	        "/usr/lib/kbd/consolefonts/lat7a-16.psf.gz"
	);
}
static void svir_1550(void) 
{
	svi_reg(&(tinfoil.validation_items[1549]),
	        "e437147ce779d4679cf19d31fc191673cc4510597c82507d95b4fce5cb835f732a3e49a3f9aa41828cc1064d52eb8ddbaede1845dc8f242b7f3e4a3ff8340deb",
	        "/usr/lib/kbd/consolefonts/lat7a-14.psfu.gz"
	);
}
static void svir_1551(void) 
{
	svi_reg(&(tinfoil.validation_items[1550]),
	        "e4f6ff1784a7af555f992c2e2db873c6ab2b5f73b8499404fcaac6a8053bb1f13c6d7fec27df311a7f3eb86f4fb5bfacf9a366776e6350558ab1d5559f0e93eb",
	        "/usr/lib/kbd/consolefonts/lat7-14.psfu.gz"
	);
}
static void svir_1552(void) 
{
	svi_reg(&(tinfoil.validation_items[1551]),
	        "39b352fbd3bb41644d4935edc11699f0178dd3b642984168d9cd2a99a8acfcda45da330486e34d1800f1ff948568a9bf1903f162a525cb55dae5a9e7f396cd3b",
	        "/usr/lib/kbd/consolefonts/lat5-16.psfu.gz"
	);
}
static void svir_1553(void) 
{
	svi_reg(&(tinfoil.validation_items[1552]),
	        "60e57ad6e2bc82698aeb248472a407880304bb9545e740c314e0acc7371bbe0c687cd66a28518ed83ed0460ce557d9a237ec07a2cb8b68801f0d03bbd6c76491",
	        "/usr/lib/kbd/consolefonts/lat5-14.psfu.gz"
	);
}
static void svir_1554(void) 
{
	svi_reg(&(tinfoil.validation_items[1553]),
	        "205f8cb6518f6598b16a26b2cae1061efa34a1b3fbc9fc3aeafa045bde9060d576df3d915a5c5da41a2501432461884df92cf6ae6780ced3935dd70bbe9cd22d",
	        "/usr/lib/kbd/consolefonts/lat5-12.psfu.gz"
	);
}
static void svir_1555(void) 
{
	svi_reg(&(tinfoil.validation_items[1554]),
	        "bd3504f355a7e6e0d2c12a2119e74ab560e649fd470e3a9375b45363de77183a13bd5726e3d3bf4715e53307cfd76c049bdac4b767df705711cf592bc935a93c",
	        "/usr/lib/kbd/consolefonts/lat4a-19.psfu.gz"
	);
}
static void svir_1556(void) 
{
	svi_reg(&(tinfoil.validation_items[1555]),
	        "e10cca67a1f1dcf2a89fcfc9e09409d67a400c168b07df45dded9962c4115cce13e6da2ad965e68d4afd7f810a74cb6da6caa2f61fcb59ae9d719aba1e420f06",
	        "/usr/lib/kbd/consolefonts/lat4a-16.psfu.gz"
	);
}
static void svir_1557(void) 
{
	svi_reg(&(tinfoil.validation_items[1556]),
	        "df419e4140c4d830c8367ec85ddb988bae029ab715ca736f599af5f95e44c54ad49947c681e7e0b2601ba96d498ebb4a3b811f868540256b0e9c11e50d8ce2cc",
	        "/usr/lib/kbd/consolefonts/lat4a-16+.psfu.gz"
	);
}
static void svir_1558(void) 
{
	svi_reg(&(tinfoil.validation_items[1557]),
	        "d7a08a27518280f1aff7fe134939bd3b2e1d7445b19c2aa1230b893a3484c485697c940ba9d36cc4bdcbf2282b6463fed147ccf32f0e8df6159c5851433764e0",
	        "/usr/lib/kbd/consolefonts/lat4a-14.psfu.gz"
	);
}
static void svir_1559(void) 
{
	svi_reg(&(tinfoil.validation_items[1558]),
	        "a693c48822526957026643826294393b9f1728523f2fb727afe8b2edbef3d31a12c30142ff5d61eb000eae20e8202d7e83501dbb16654a8a19da9e56dbce2ad5",
	        "/usr/lib/kbd/consolefonts/lat4a-12.psfu.gz"
	);
}
static void svir_1560(void) 
{
	svi_reg(&(tinfoil.validation_items[1559]),
	        "e70d5f9283d3d97fed034f8416cf5748c7e2685ee04bac3cf55b2c450b718f8123db46d859b9692235b16674b08c8c35d6b855cad72915aa9937ed2b1f6b0119",
	        "/usr/lib/kbd/consolefonts/lat4a-10.psfu.gz"
	);
}
static void svir_1561(void) 
{
	svi_reg(&(tinfoil.validation_items[1560]),
	        "9f74f96ee84b22d1542559b3cae233dd9e5ce5e273ba6a6c62c276db434a429a38dcc89a25b0183c892c47b86e0b1de0538580c9b3e984095457ea64e319f74f",
	        "/usr/lib/kbd/consolefonts/lat4a-08.psfu.gz"
	);
}
static void svir_1562(void) 
{
	svi_reg(&(tinfoil.validation_items[1561]),
	        "0a4f25b0a261b5b5bd951da2b9187ed63dcaab09f8903cc0675741793047be415db47a27fa3b50061c05a14a2f99e5dd167135568afc7bf53cb87b15bc25700f",
	        "/usr/lib/kbd/consolefonts/lat4-19.psfu.gz"
	);
}
static void svir_1563(void) 
{
	svi_reg(&(tinfoil.validation_items[1562]),
	        "02e44bbd8eab6432ae82b40d8eaa258c2fd088b3eaf9d933b13734d384f7b9339b0fa9a3bb2f931839df4b8e1163111da1df9cc7d4319da0b90a4799df57e4c6",
	        "/usr/lib/kbd/consolefonts/lat4-16.psfu.gz"
	);
}
static void svir_1564(void) 
{
	svi_reg(&(tinfoil.validation_items[1563]),
	        "2d575d441580eba4af2402a5c852a6c557a7a8a1a4eeab46771c0062bbc3a4724d0d45ffd55f475e0d869e6a628e0a53eebb7bdf963e69da7fa9364dd7d6706a",
	        "/usr/lib/kbd/consolefonts/lat4-16+.psfu.gz"
	);
}
static void svir_1565(void) 
{
	svi_reg(&(tinfoil.validation_items[1564]),
	        "ca6b4a741fe2ac74a036a35563af83d92a29324a8e483a538c71fba1d67bea3a7489c88e3dc3ca05da06a60614c9a3ee93c1af50b556d3bf988e752f8d4046ee",
	        "/usr/lib/kbd/consolefonts/lat4-14.psfu.gz"
	);
}
static void svir_1566(void) 
{
	svi_reg(&(tinfoil.validation_items[1565]),
	        "478aec91dd0c8f747e8d0648d7359fa29123ca0deae4a92a6fb54d05a346c520168276c6cf82b256d8c203ec93b84811186281ce5962ed11a0ba0a0a2614b5f8",
	        "/usr/lib/kbd/consolefonts/lat4-12.psfu.gz"
	);
}
static void svir_1567(void) 
{
	svi_reg(&(tinfoil.validation_items[1566]),
	        "5f000134ee7ae95505cf2a785708be5c221a9165640a04c775cb90b87d0217e7519cb08241abe0a3781e85b689ab0932ab3c0489e1908b3f3756b93fe19df151",
	        "/usr/lib/kbd/consolefonts/lat4-10.psfu.gz"
	);
}
static void svir_1568(void) 
{
	svi_reg(&(tinfoil.validation_items[1567]),
	        "9eccee7e9762d0087d3fbd2b62bd7068b84ab1f8f05cc9991be7c617cde19e3e8bb86bca5b7420e3c4f6dd9227aab96ff0b635da66624c34b6fbea494a474ee6",
	        "/usr/lib/kbd/consolefonts/lat4-08.psfu.gz"
	);
}
static void svir_1569(void) 
{
	svi_reg(&(tinfoil.validation_items[1568]),
	        "571a2b26104d9892315f88a8688fc15eb5ad1d847df126cb4429ea963cb16fb51bd2c5efcb1e7cd1ae7bbf6824e8cfa14923993b77c3449393cf4724a71dbe4c",
	        "/usr/lib/kbd/consolefonts/lat2a-16.psfu.gz"
	);
}
static void svir_1570(void) 
{
	svi_reg(&(tinfoil.validation_items[1569]),
	        "15b4d856dc5348c2ece0e6cbd8083b102e5384512b86b129ade6eb58135006e69525e4b609d133bde221c1189e15a3a73d2c851b612df906021cc9f38afb01cd",
	        "/usr/lib/kbd/consolefonts/lat2-sun16.psfu.gz"
	);
}
static void svir_1571(void) 
{
	svi_reg(&(tinfoil.validation_items[1570]),
	        "71f8e8d47bd8a0339476998540c5a6a177cce3593f176df938177782c3d769ef395d586a1e4595e638fd6c3aca0f2b324a16d3ee9afe523e2303e5d8eca78e3c",
	        "/usr/lib/kbd/consolefonts/lat2-16.psfu.gz"
	);
}
static void svir_1572(void) 
{
	svi_reg(&(tinfoil.validation_items[1571]),
	        "e7524e46c1653bdc87d294c64190065b5525a085008169d0eaab98acb4a11d126e283f3565fa474f730c135914f656a9d5b26cc85e83c5499d2435e969b29a8f",
	        "/usr/lib/kbd/consolefonts/lat2-14.psfu.gz"
	);
}
static void svir_1573(void) 
{
	svi_reg(&(tinfoil.validation_items[1572]),
	        "d276e68dc3f0aa0dc00c929f9ffb77f0820742fcc733737917b99dc33828c038552a4f4266675b8a2f723dec2e0020fd8907fb84ee88ed64bbf6fd79d4b80712",
	        "/usr/lib/kbd/consolefonts/lat2-12.psfu.gz"
	);
}
static void svir_1574(void) 
{
	svi_reg(&(tinfoil.validation_items[1573]),
	        "29c83b3502d7c36f38685a1b1f50e679faf53e0e2d8b3bbbcf7e689e68ed3b66cc0a10c85695acf518d11a9ee87524c5f3e7ceda7a392d0aae39ed18df91dcc0",
	        "/usr/lib/kbd/consolefonts/lat2-10.psfu.gz"
	);
}
static void svir_1575(void) 
{
	svi_reg(&(tinfoil.validation_items[1574]),
	        "7eadc9320d4bdc4d07c1a52ee11553e1f4ae5dafcf081f568d6f4fca4a9c4866ecca7ad187ceeb6269acac8dd53638b78bd79ce526383af798b10af39497c9c9",
	        "/usr/lib/kbd/consolefonts/lat2-08.psfu.gz"
	);
}
static void svir_1576(void) 
{
	svi_reg(&(tinfoil.validation_items[1575]),
	        "6b6434fd7d7957d0967ba9011f744aa925e829de81f3a01222c255e6e056a1abf4c8627dca01aac4ab9e8e69241cdb37d9b6a0e00954c5fa1a037f5a8eb3f7d0",
	        "/usr/lib/kbd/consolefonts/lat1-16.psfu.gz"
	);
}
static void svir_1577(void) 
{
	svi_reg(&(tinfoil.validation_items[1576]),
	        "20e5b773b793e0f88abe7e29edcb704bcea05df306fe5d804b5c357b1beb294aa56c3050b8ca580fe5a3fd511087c777373a9548d2851167aaeebd43829ad290",
	        "/usr/lib/kbd/consolefonts/lat1-14.psfu.gz"
	);
}
static void svir_1578(void) 
{
	svi_reg(&(tinfoil.validation_items[1577]),
	        "3c90f7ea3e7fc85fd0e448bb610a17341f32f17ac26b2edc007e5a878ac34f3871a6a07038f96d8cb978d313e366aaab0ffac4b296177a86c9d12e4992761775",
	        "/usr/lib/kbd/consolefonts/lat1-12.psfu.gz"
	);
}
static void svir_1579(void) 
{
	svi_reg(&(tinfoil.validation_items[1578]),
	        "93731ab7697811e861ea01e8d450be6f9bd1c32a2ad4f9d427cd1dd80354f7a7daa38922cbf77a69c1882cd189fc71d36614f743238d913b61dcd368441555b0",
	        "/usr/lib/kbd/consolefonts/lat1-10.psfu.gz"
	);
}
static void svir_1580(void) 
{
	svi_reg(&(tinfoil.validation_items[1579]),
	        "ace97ff2391f6fbd282a12ba79ba249912ea8c30a3f0f98ea2508ad9ec512fef91be35e3b4c2ebc8676c53f4b59c9be9d686c94aa73f46ed03b7968d4e60d07d",
	        "/usr/lib/kbd/consolefonts/lat1-08.psfu.gz"
	);
}
static void svir_1581(void) 
{
	svi_reg(&(tinfoil.validation_items[1580]),
	        "6822eeb8c711eb5f7e6db726de0612202f47e1a3ab5714a72087ec94e766616137e769462ebf2be8efd1ece2dce30f8cb92a2d3d034cd134b96302a7277ec2c3",
	        "/usr/lib/kbd/consolefonts/lat0-sun16.psfu.gz"
	);
}
static void svir_1582(void) 
{
	svi_reg(&(tinfoil.validation_items[1581]),
	        "1a2ca1841484324cd935d37fc36596b7c9322a6b88051d595e100f62a580ffc9d2103ca0d86794452d6dd6c66d986701806914edee04220847251400d7a1ba55",
	        "/usr/lib/kbd/consolefonts/lat0-16.psfu.gz"
	);
}
static void svir_1583(void) 
{
	svi_reg(&(tinfoil.validation_items[1582]),
	        "5c6008fadfcca7d16591fec7ae7da1de528f419a9d03bceb6bd49d8b83b6004013b92c69419fb90a484ac5ee22479de7bfd2856da52f98628166d19f638d2e4e",
	        "/usr/lib/kbd/consolefonts/lat0-14.psfu.gz"
	);
}
static void svir_1584(void) 
{
	svi_reg(&(tinfoil.validation_items[1583]),
	        "d670d65216ef184df50931aa6975fb7f95a8ff1806ac58973e983af9b9ec05d2611a9479fd04ae339eb35322910c1919a46fc4a8d7e34dec8d7311d793780d20",
	        "/usr/lib/kbd/consolefonts/lat0-12.psfu.gz"
	);
}
static void svir_1585(void) 
{
	svi_reg(&(tinfoil.validation_items[1584]),
	        "f0eb52908383d8f76b53a6434c99a1fa586ffc1701918aeaea91216060960c02fe857bfd69802ce968be33fef372af7a202694d52bd791b9d2d92220cd5bffc0",
	        "/usr/lib/kbd/consolefonts/lat0-10.psfu.gz"
	);
}
static void svir_1586(void) 
{
	svi_reg(&(tinfoil.validation_items[1585]),
	        "5a1d936c8e841cdd8daec230bf59892fc6a2da5b59e8b56130cad905273a379da52a6bc2134e2ee737a587b1ab9f52a5bd69641b0745c50724675cac2e8644cf",
	        "/usr/lib/kbd/consolefonts/lat0-08.psfu.gz"
	);
}
static void svir_1587(void) 
{
	svi_reg(&(tinfoil.validation_items[1586]),
	        "e93a6e52ce6a4cb05d4ee994b75eb223e9e36f68e73b0610f9e6cde3b88d6c9e56f2cbbf86c9ad6fd509f6e5c66f22d9fe72d84b09f77dacd1e8d975c65a246a",
	        "/usr/lib/kbd/consolefonts/koi8u_8x8.psfu.gz"
	);
}
static void svir_1588(void) 
{
	svi_reg(&(tinfoil.validation_items[1587]),
	        "a76f16e10e06132157b79aca10c592901bd5f46e118503bf0ec774b06f99494ad001cb6c8d4d099e33e10835ad87126beb164ab534783f3a2d3d81979934e5f6",
	        "/usr/lib/kbd/consolefonts/koi8u_8x16.psfu.gz"
	);
}
static void svir_1589(void) 
{
	svi_reg(&(tinfoil.validation_items[1588]),
	        "840d8d6d925437dfeb0c1edee6423caef9b8a6750d78fcc0804f55353fbae4ae4ad32576e679d4495827188dbe3b3fc25fc02275e7ddc2443999d0d9423ea035",
	        "/usr/lib/kbd/consolefonts/koi8u_8x14.psfu.gz"
	);
}
static void svir_1590(void) 
{
	svi_reg(&(tinfoil.validation_items[1589]),
	        "58fd683d00d4787f9023cf3c0539d4ebd26c5498aa296e4513305774a02f2e537bae44b6c83f29077d958c0eef423acfac1583656da3fe866d768aff03af9037",
	        "/usr/lib/kbd/consolefonts/koi8r.8x8.psfu.gz"
	);
}
static void svir_1591(void) 
{
	svi_reg(&(tinfoil.validation_items[1590]),
	        "2274b3c26023c5e3e6d8312a83ab7d882b523b053b5cd59f5654161f3c7725aa737ad12fa5377f7874e903578a73c9fb78478caa24a2f18e6afff04e33cfcb96",
	        "/usr/lib/kbd/consolefonts/koi8r-8x8.gz"
	);
}
static void svir_1592(void) 
{
	svi_reg(&(tinfoil.validation_items[1591]),
	        "85eb5b3dd15ee1f7fa451035aead9225d63cf9dbc0c3b6ea01209bb41aabb05fc9a51570b61d6a4e798e25e73490f6533f4f12bf47f5931d5726953cb0c62b71",
	        "/usr/lib/kbd/consolefonts/koi8r-8x16.gz"
	);
}
static void svir_1593(void) 
{
	svi_reg(&(tinfoil.validation_items[1592]),
	        "cbc3098d580c70b974e97d852158e56d8457ca1a0966cf1b07dbbf309ed6764cbcb329d09cf8993b05157941a38fbe5396a120251f3822dacdb7f8d12474f4ba",
	        "/usr/lib/kbd/consolefonts/koi8r-8x14.gz"
	);
}
static void svir_1594(void) 
{
	svi_reg(&(tinfoil.validation_items[1593]),
	        "b39e39f90e09099b71a6c0b24eb1636df5abf2ab6935dcac60780aed7db7f06e5b426f333104a576db34baebe401fc65e9bfdd799bb48967947350d7ec7a557a",
	        "/usr/lib/kbd/consolefonts/koi8c-8x16.gz"
	);
}
static void svir_1595(void) 
{
	svi_reg(&(tinfoil.validation_items[1594]),
	        "2a3dff7ef4479c5fb4251018b6de74855fe13bf5316274df2df016b7ea273b3c6bdc09d517f43054d26912a0392b19a8a1adf0bf510604a713dd16b8274ae155",
	        "/usr/lib/kbd/consolefonts/koi8-14.psf.gz"
	);
}
static void svir_1596(void) 
{
	svi_reg(&(tinfoil.validation_items[1595]),
	        "701944e853f89c451111b4ae36b527d7d61915cceabfa6b22b9a9c56aeb8aec3f956099f84887b5a6095885e1c0c180502bb21e7aaca6d6b1c0df3de4c87014a",
	        "/usr/lib/kbd/consolefonts/iso10.16.gz"
	);
}
static void svir_1597(void) 
{
	svi_reg(&(tinfoil.validation_items[1596]),
	        "832bf42483c5efb8dadab4d35b73a13437e68e89bfb25f15fe663a4b0c4eae04885226ee6510cf5ec89710f5b7bdb93d0240a7c8ea8b960a0ee028ab38863609",
	        "/usr/lib/kbd/consolefonts/iso10.14.gz"
	);
}
static void svir_1598(void) 
{
	svi_reg(&(tinfoil.validation_items[1597]),
	        "b1c510b35f882426f1142be441f64405bf6331fdcbd366e430b39a23654d86903e84d475f6e5040e74236a77abdb02862c313d33a5fdc90e824939cf42adb327",
	        "/usr/lib/kbd/consolefonts/iso10.08.gz"
	);
}
static void svir_1599(void) 
{
	svi_reg(&(tinfoil.validation_items[1598]),
	        "a53f1cd1cb8ac6658dca1c1d174aa85fcd5b9dd59b6431e09c1bceeca2ae38a61d1b1fd9d9c4520bee3fa0594cb704082cbea4d14bf7e5c4fc5913105c9ba3e4",
	        "/usr/lib/kbd/consolefonts/iso09.16.gz"
	);
}
static void svir_1600(void) 
{
	svi_reg(&(tinfoil.validation_items[1599]),
	        "18b5ad78b87c0a56665f17446e0606934efd3e46f765689dc69e13222a37e68aaa4e77e61553c55e081cacffac7c1cca70a8914fbadfe590de8a3312286db772",
	        "/usr/lib/kbd/consolefonts/iso09.14.gz"
	);
}
static void svir_1601(void) 
{
	svi_reg(&(tinfoil.validation_items[1600]),
	        "51e9587cc038328392a403322f12f72a36eb296c4558dacdd2bcc4fac137bf4017678b835434ae458dfaa1a223469198cd5a480e40bdd468a1f8ac8b5e2e462e",
	        "/usr/lib/kbd/consolefonts/iso09.08.gz"
	);
}
static void svir_1602(void) 
{
	svi_reg(&(tinfoil.validation_items[1601]),
	        "28f7de89f882957685626d7777645bf7f843f84675a42bd213612924c3dccae75666632f630e0c18a36151b1c208fc6b88e53d74fe2955ef9b9b73b53db144b7",
	        "/usr/lib/kbd/consolefonts/iso08.16.gz"
	);
}
static void svir_1603(void) 
{
	svi_reg(&(tinfoil.validation_items[1602]),
	        "6901b73d7b719313704971ffc3c47df76171d81d5472b67ae5a337213295e2129db7a531b2369236abdc02424378d26e4bdc90b2f69197d59b3b0e9af13420f1",
	        "/usr/lib/kbd/consolefonts/iso08.14.gz"
	);
}
static void svir_1604(void) 
{
	svi_reg(&(tinfoil.validation_items[1603]),
	        "25bb4be52a3c41d70963f6c123714b4d5b7664cdec4e2c1de76e15ba14590f7c3cbe667bd9a6dab9701a263d8d3edbd418bded298b9d8be7ad6187bd0c3519c6",
	        "/usr/lib/kbd/consolefonts/iso08.08.gz"
	);
}
static void svir_1605(void) 
{
	svi_reg(&(tinfoil.validation_items[1604]),
	        "73668fcbc38c10fade122f782e14410e70cd4549361edda9ab5365590cb0b0af9b51abf808810ddf7ca7166bede4458dae597697fcbba96a40529d11f3af1f4b",
	        "/usr/lib/kbd/consolefonts/iso07u-16.psfu.gz"
	);
}
static void svir_1606(void) 
{
	svi_reg(&(tinfoil.validation_items[1605]),
	        "f6e4b756bcdc1474920958f6cfdf6d88e4ad0c4a765de400fe0456774fde6e60ecaaca22d222162ef1560a742cbcae610cdb69347d9fd14179d15bb49d791615",
	        "/usr/lib/kbd/consolefonts/iso07.16.gz"
	);
}
static void svir_1607(void) 
{
	svi_reg(&(tinfoil.validation_items[1606]),
	        "56643129d69ba6e22cc8315587a9e1198e2b3a7df640d9157656d8f6f595b21ab1a4e764189aa0d57fc29280139f26ce16de3d2116fe169806e562c3bfe49dc5",
	        "/usr/lib/kbd/consolefonts/iso07.14.gz"
	);
}
static void svir_1608(void) 
{
	svi_reg(&(tinfoil.validation_items[1607]),
	        "2325d1e59d135c3806be969eff04d678cb8556f95527fd551203aab849af712bd5c658479cf5beacf4606aca0cdb60dfd04eb2ab94f4f027d603e184e48d5ca2",
	        "/usr/lib/kbd/consolefonts/iso06.16.gz"
	);
}
static void svir_1609(void) 
{
	svi_reg(&(tinfoil.validation_items[1608]),
	        "68f99261fce0683b312e23ea5931444bd7983695e208e03734b1977a160d24ce15eda45b66d303db640b7e9f1101a3c97320f46f2f55d7515022b2d175b23872",
	        "/usr/lib/kbd/consolefonts/iso06.14.gz"
	);
}
static void svir_1610(void) 
{
	svi_reg(&(tinfoil.validation_items[1609]),
	        "5f68e20d4be12f07e4169b9ba0322db10f47bfaa4e2101853ca3ef1d3b589aac69931bbc690f19aa82ecd03041846047634cbb8a7d26cf0a2ccacaf47d17b65f",
	        "/usr/lib/kbd/consolefonts/iso06.08.gz"
	);
}
static void svir_1611(void) 
{
	svi_reg(&(tinfoil.validation_items[1610]),
	        "dee7cef29e9bf8bb6615cc3d08823b13827e12960c432b79c6966a1698b6c08037f1bd06f495ef6b5b758636411b15b00f50c6a210b66aa7dc287b85aa338b41",
	        "/usr/lib/kbd/consolefonts/iso05.16.gz"
	);
}
static void svir_1612(void) 
{
	svi_reg(&(tinfoil.validation_items[1611]),
	        "04db74b99ec423cdbdcd40e9493247cb7644398debb68d571ee26eff2242c73cbfd1a96e12d944be5dc9531892675477887939e0ac4182d74a54719bf0cfc235",
	        "/usr/lib/kbd/consolefonts/iso05.14.gz"
	);
}
static void svir_1613(void) 
{
	svi_reg(&(tinfoil.validation_items[1612]),
	        "ebb753f6c9025b78d4751edb12911b286b332b423c970d89d4eaf0e1f53571e0315e7339630b83dd0fad09eecbbed2b9c070119eadb661707c259b05045b9715",
	        "/usr/lib/kbd/consolefonts/iso05.08.gz"
	);
}
static void svir_1614(void) 
{
	svi_reg(&(tinfoil.validation_items[1613]),
	        "0956a8f89bf71b8b15c57f383d9e9f81fc4cef9e5f1edf744dd2557fedb2f9b8dd7b53db01d347fef6a15c57e7a13f61957df7f80458a8b435870b1bc5319240",
	        "/usr/lib/kbd/consolefonts/iso04.16.gz"
	);
}
static void svir_1615(void) 
{
	svi_reg(&(tinfoil.validation_items[1614]),
	        "c09164abf7659fe876ab4c366eba09aef0e23b755317dd3511b55dce1f661ede20c4d3cc762e61a3962ca2b7085d9f74d1df0f07ad4cb2eb295a5c928109e651",
	        "/usr/lib/kbd/consolefonts/iso04.14.gz"
	);
}
static void svir_1616(void) 
{
	svi_reg(&(tinfoil.validation_items[1615]),
	        "b5c8d1ec70b783b16d382633ad4c916b67f548ce8642cee577a058d39f080b686f1588ec61f4b3e966a760d85ce496b5f95e5f131b8a52253f953c5c49c94861",
	        "/usr/lib/kbd/consolefonts/iso04.08.gz"
	);
}
static void svir_1617(void) 
{
	svi_reg(&(tinfoil.validation_items[1616]),
	        "765157d11e6c2129a5f6b2f6c6e7a447d7c7af60655639893bfe3010890072b3bf335b9c3eadc718056b29c9a2e9fe1e3bd7f8ac9c57591d691af5a6abedbc6b",
	        "/usr/lib/kbd/consolefonts/iso03.16.gz"
	);
}
static void svir_1618(void) 
{
	svi_reg(&(tinfoil.validation_items[1617]),
	        "3e6db8dff5ece5c10078c99bcd21e4f282fe4ea0147b801058a83e49cabff5661ad58e1579148e415ed41f0fb30a0ae456fe95d301090b265d2b6659488dc9da",
	        "/usr/lib/kbd/consolefonts/iso03.14.gz"
	);
}
static void svir_1619(void) 
{
	svi_reg(&(tinfoil.validation_items[1618]),
	        "33d31611ee94a1414bb67d89b99b7dcdff87e1a083f7ac604ad88c5748b0934dea7628fca186e6df49930a0dcbe0988227f0638db383e3d0f2146a988a6a7acb",
	        "/usr/lib/kbd/consolefonts/iso03.08.gz"
	);
}
static void svir_1620(void) 
{
	svi_reg(&(tinfoil.validation_items[1619]),
	        "07768ef37ab255b8ac3d8bf5218b1c68075c179dba852a4cd2eb6bec8ed91bc1a00f22fb6b7c702ca05b5352c3ab329e574e25759d58e7436a39890cc5dea959",
	        "/usr/lib/kbd/consolefonts/iso02.16.gz"
	);
}
static void svir_1621(void) 
{
	svi_reg(&(tinfoil.validation_items[1620]),
	        "47cd1acad4b9dda2a2752a27d5fb187c75c03ed0c732ef707899dc3eb8b41ba8e8339119349db075c839f6663462b3ca0d564958ea5226db9628a198802ac3a4",
	        "/usr/lib/kbd/consolefonts/iso02.14.gz"
	);
}
static void svir_1622(void) 
{
	svi_reg(&(tinfoil.validation_items[1621]),
	        "bbd231015da89cadbc3f1feff9716020c91fbeb4c7d32f85ae6f01cb19750de10857b8b9b0a621fda3a3787443aecd29e9e60f4bff6d901a01af0059fbc710aa",
	        "/usr/lib/kbd/consolefonts/iso02.08.gz"
	);
}
static void svir_1623(void) 
{
	svi_reg(&(tinfoil.validation_items[1622]),
	        "7c9a9195ab3c388f20de8b98e36c4bc9d6d18b39956900b5ff152782db2dc9e90e2459c1eb5047aeab89e1cd91257dd05bfc161de43fb46f46b020c3d932a960",
	        "/usr/lib/kbd/consolefonts/iso01-12x22.psfu.gz"
	);
}
static void svir_1624(void) 
{
	svi_reg(&(tinfoil.validation_items[1623]),
	        "7c9a9195ab3c388f20de8b98e36c4bc9d6d18b39956900b5ff152782db2dc9e90e2459c1eb5047aeab89e1cd91257dd05bfc161de43fb46f46b020c3d932a960",
	        "/usr/lib/kbd/consolefonts/iso02-12x22.psfu.gz"
	);
}
static void svir_1625(void) 
{
	svi_reg(&(tinfoil.validation_items[1624]),
	        "15e7fe0b9d46fa58b26f79b9cae290f3bc09d3b714413052686e6ac774512b2be25986824e779ea283363b9f6162995316d045d2aecd667f4f87c50201d53221",
	        "/usr/lib/kbd/consolefonts/iso01.16.gz"
	);
}
static void svir_1626(void) 
{
	svi_reg(&(tinfoil.validation_items[1625]),
	        "ec0045ef006795870cf1de3e0743f74cb4e003dc74570c47f1c71bfb331762fc18c464188b0e32a95217d2358cd081d39bcac4c13074cb59fc1f6483a18639d3",
	        "/usr/lib/kbd/consolefonts/iso01.14.gz"
	);
}
static void svir_1627(void) 
{
	svi_reg(&(tinfoil.validation_items[1626]),
	        "2509d775c59c71bf47558d9140c7915e61d6cf1590fe505872fd1050e7b6748a473fc02d11d25799e07486c3c12cff33a351bfcea2f1d36bfa55e211d8eecad8",
	        "/usr/lib/kbd/consolefonts/iso01.08.gz"
	);
}
static void svir_1628(void) 
{
	svi_reg(&(tinfoil.validation_items[1627]),
	        "d41bf34d9a83781c98c55e676de308ba1d936aa353ea4bdee487ac581f17467e509b7902370bfe15a91b03677674e2626d481c63cc3133a03c4ce1c7cc50a813",
	        "/usr/lib/kbd/consolefonts/greek-polytonic.psfu.gz"
	);
}
static void svir_1629(void) 
{
	svi_reg(&(tinfoil.validation_items[1628]),
	        "5e23621fa816834862909f27c67019d14f8ea9b5a5cabbd54f57f411497535112fe23c0b7177ad38fb7601587894f58a96040fbf01f39ec9701bef40e5166896",
	        "/usr/lib/kbd/consolefonts/gr928b-8x16.psfu.gz"
	);
}
static void svir_1630(void) 
{
	svi_reg(&(tinfoil.validation_items[1629]),
	        "630d1d09102bdef16868d9e65ca1d32b1b7d93b12bdd9d65c441cca993c1f53dee5dcb90430e8efae5d96f456fc2e840cd0ca287f6dabe2f69f77a4a7b0fdae4",
	        "/usr/lib/kbd/consolefonts/gr928b-8x14.psfu.gz"
	);
}
static void svir_1631(void) 
{
	svi_reg(&(tinfoil.validation_items[1630]),
	        "7cec5ef92f40af11cf3e822adeda76e8ca3480fbd6e3c528a2f9ced7a93af4a9666be860e8583806983573e2a90ffe0090286c6fc416b952a2af0a8b26546f05",
	        "/usr/lib/kbd/consolefonts/gr928a-8x16.psfu.gz"
	);
}
static void svir_1632(void) 
{
	svi_reg(&(tinfoil.validation_items[1631]),
	        "ef0d30c1ef69901d3a3ae8b1153b930f181213275515dfe4e26205640a9d16bcb4b56ac9b9e2763f3dd21c37152f155b26ccba9984cc2313cbb10787626fad02",
	        "/usr/lib/kbd/consolefonts/gr928a-8x14.psfu.gz"
	);
}
static void svir_1633(void) 
{
	svi_reg(&(tinfoil.validation_items[1632]),
	        "adddefac4a171d6ae425f264480c874130b13fd9c4b7f81cdba5da1fd82ee09a4766ac33299e3968baeeb8f2997a3e1d5d8ff56a2fa3e5ed17a6beeb700e37f8",
	        "/usr/lib/kbd/consolefonts/gr928-9x16.psfu.gz"
	);
}
static void svir_1634(void) 
{
	svi_reg(&(tinfoil.validation_items[1633]),
	        "6eee0afebe5777d2f9354a8f4fb2ec82409890e4d8c29da9fe66e0bd0e2de8ed06f3c9d37c29472dd6ae18505448ae7ebc7e37d38e6b35316938ff98463aa496",
	        "/usr/lib/kbd/consolefonts/gr928-9x14.psfu.gz"
	);
}
static void svir_1635(void) 
{
	svi_reg(&(tinfoil.validation_items[1634]),
	        "0e37d496a540ebe2534af56ab2fdc9f3f0001e5a704369e67810bbdd7f94682623ef466e35a096c87c5984d292b8f4ee21a926216d458135bb4b345f638d861f",
	        "/usr/lib/kbd/consolefonts/gr928-8x16-thin.psfu.gz"
	);
}
static void svir_1636(void) 
{
	svi_reg(&(tinfoil.validation_items[1635]),
	        "86a90abac62efabe4a98d6a67ad90db426f7ddf15cd42e9534f521ea0b72177fcef08ef594cc0dd8beae5d623f553faf513f4ba3c78cef044414bb8aa3d5b3b7",
	        "/usr/lib/kbd/consolefonts/gr737c-8x16.psfu.gz"
	);
}
static void svir_1637(void) 
{
	svi_reg(&(tinfoil.validation_items[1636]),
	        "86a90abac62efabe4a98d6a67ad90db426f7ddf15cd42e9534f521ea0b72177fcef08ef594cc0dd8beae5d623f553faf513f4ba3c78cef044414bb8aa3d5b3b7",
	        "/usr/lib/kbd/consolefonts/gr737d-8x16.psfu.gz"
	);
}
static void svir_1638(void) 
{
	svi_reg(&(tinfoil.validation_items[1637]),
	        "204fee7e5fd2399009b5bfa5d792783b8381bc6a60e25d585f220d3b602b32aa029eeb99290d150b8a62459d4b764315fe1641ebdcb27f8a61ff0fa8a4340cc6",
	        "/usr/lib/kbd/consolefonts/gr737c-8x8.psfu.gz"
	);
}
static void svir_1639(void) 
{
	svi_reg(&(tinfoil.validation_items[1638]),
	        "33edc9965f1648c2d7fa0f63de72120695113eedfdc683e1361640bd9e700c402e125d2f84d3d9df667b2bc30b3d03e169110381357b2b27b675cfc8c1eecab9",
	        "/usr/lib/kbd/consolefonts/gr737c-8x7.psfu.gz"
	);
}
static void svir_1640(void) 
{
	svi_reg(&(tinfoil.validation_items[1639]),
	        "c33cb0b73333046cfaf6e2c9e904cf439295dea3c7dfaa10961ac763063ed9b538e1fe32a4d81f0079af4b16b10a1b136cbfd41fd7c0513192df0ab634497b5b",
	        "/usr/lib/kbd/consolefonts/gr737c-8x6.psfu.gz"
	);
}
static void svir_1641(void) 
{
	svi_reg(&(tinfoil.validation_items[1640]),
	        "c404ad9c8e97eecf503f07a950e1d11861497ccdf62dc31bd073b0615e87c87803a60d62e674c44a0ebe17e60fba44bf7627255c0f73f0b7e77d63951e3eb7f2",
	        "/usr/lib/kbd/consolefonts/gr737c-8x14.psfu.gz"
	);
}
static void svir_1642(void) 
{
	svi_reg(&(tinfoil.validation_items[1641]),
	        "0190c624dda83c89070c63305d4ad5ce7aca6b5fe7555c0d082554ae70bc88a886a6406440f23423cfc5939e592bbe6f9f67c948ff7506a862521c5f262c78eb",
	        "/usr/lib/kbd/consolefonts/gr737b-9x16-medieval.psfu.gz"
	);
}
static void svir_1643(void) 
{
	svi_reg(&(tinfoil.validation_items[1642]),
	        "a76104274b23f58472b0d8a50a105647dc00d153c52087c0b33ed2050d8eb6d52649de5da7496e48ca6487736ec4671dbdccd749da0fe671fb0c963dd60b8579",
	        "/usr/lib/kbd/consolefonts/gr737b-8x11.psfu.gz"
	);
}
static void svir_1644(void) 
{
	svi_reg(&(tinfoil.validation_items[1643]),
	        "8f0fc62b1c288845e20bd86a3b0b18a45724b53b6926013bcc55ea26dcd1c09f11779d014750c20dc5127e32c563bd50ca1b0e55fe6180387052f99c819e069a",
	        "/usr/lib/kbd/consolefonts/gr737a-9x16.psfu.gz"
	);
}
static void svir_1645(void) 
{
	svi_reg(&(tinfoil.validation_items[1644]),
	        "4fd7a34c454618aa8c08c09ab6b451809892fcd02ce710a7b217a12bdaa07488c907d562a8fca5c9d6e5d5fb740c32feed5a4059d5ff8b2231113aaf0c18d8c6",
	        "/usr/lib/kbd/consolefonts/gr737a-9x14.psfu.gz"
	);
}
static void svir_1646(void) 
{
	svi_reg(&(tinfoil.validation_items[1645]),
	        "bdab5ef81fa48c3e1b7d1a1756121f2eaa91183ca7d49d17a2478c1bdcb7b4e318391832906bf5160df848e205347a077c43adc041e4ab6f770a93e3d4d4ac6e",
	        "/usr/lib/kbd/consolefonts/gr737a-8x8.psfu.gz"
	);
}
static void svir_1647(void) 
{
	svi_reg(&(tinfoil.validation_items[1646]),
	        "211948e113fd2265d4ce4f41d2e0e2ebf6097d2cf45d6f8d39d59d2ea2193c713c9b9d8707e8a65b026392d45dd03eaaad5a6df8dcbaf4ac5c872106045c8bff",
	        "/usr/lib/kbd/consolefonts/eurlatgr.psfu.gz"
	);
}
static void svir_1648(void) 
{
	svi_reg(&(tinfoil.validation_items[1647]),
	        "51769f0041d71586a9f34ed5f2cd029cbf95f93124e6bcc5e67f04601638541fca4a4b35fcf50b3604b065297db826cb53cc7be93a1eedc0909adaac0317a485",
	        "/usr/lib/kbd/consolefonts/drdos8x8.psfu.gz"
	);
}
static void svir_1649(void) 
{
	svi_reg(&(tinfoil.validation_items[1648]),
	        "337dd21a14a65f086a8c243d082bc929760bc31f50a3b4cdd05a4e27b38f827450d1da43ca4b0cb75ebdc04d2b0baeb036cb08974c854dd7c1e589efae62246e",
	        "/usr/lib/kbd/consolefonts/drdos8x6.psfu.gz"
	);
}
static void svir_1650(void) 
{
	svi_reg(&(tinfoil.validation_items[1649]),
	        "4564cdd66dd4c090d08065e241d300cbac83cd06316ff56f6bc5873ab7836bcad2e0e9b2fe6faad4c65983a1b9639b9ed768fb6ce13a1ef4901a01a9a67fbc1b",
	        "/usr/lib/kbd/consolefonts/drdos8x16.psfu.gz"
	);
}
static void svir_1651(void) 
{
	svi_reg(&(tinfoil.validation_items[1650]),
	        "9bd2856f92fc2bbfaa768dd7251010b35d22bb5b20b2b7c67fa40b858c062405490df87754586866ef77ee778f8c1de062340123c5fc812ab7e08da3d637be20",
	        "/usr/lib/kbd/consolefonts/drdos8x14.psfu.gz"
	);
}
static void svir_1652(void) 
{
	svi_reg(&(tinfoil.validation_items[1651]),
	        "c4272bcc903502bc5e325529ed44d975769749f4cafbaa271bc285d58088b350a8d3d0c4a74fc6f46900580b323235008830a91bdd4f24a211c21a554a5f5fde",
	        "/usr/lib/kbd/consolefonts/default8x9.psfu.gz"
	);
}
static void svir_1653(void) 
{
	svi_reg(&(tinfoil.validation_items[1652]),
	        "a1ef12a607d014f64781b138d59145caecb55924305b874551eb2e05ab2b1309834903dab4976d74ab2ff3d3363cf45865f02b9cc8677a72a0774e2ae85da399",
	        "/usr/lib/kbd/consolefonts/default8x16.psfu.gz"
	);
}
static void svir_1654(void) 
{
	svi_reg(&(tinfoil.validation_items[1653]),
	        "ca1db23e77b173d0804f7b5c4bb4474047ab0db5ff4960f9077806f6ce3803bb1ae57844f32f7ca8b327d9558a0085960e58c4510b315ef833e8b9daf86618d8",
	        "/usr/lib/kbd/consolefonts/cyr-sun16.psfu.gz"
	);
}
static void svir_1655(void) 
{
	svi_reg(&(tinfoil.validation_items[1654]),
	        "fd77d791747172717b3a7ee41b6558f36fbec08a35aa69a9ca43903011ec4b287c2c1731c7e012ef406c605a9ef24ce2d5fb40d18b4c069dcbc8679c2e8ecbd7",
	        "/usr/lib/kbd/consolefonts/cybercafe.fnt.gz"
	);
}
static void svir_1656(void) 
{
	svi_reg(&(tinfoil.validation_items[1655]),
	        "3459f70537717a53ab19ecdef2b29158a2a2949c4556bd5c7ffddeb1c3ced9251799a24a50245904c6987eac860f3e62d3659cc814bba229c7d0c0d3b0a0c93f",
	        "/usr/lib/kbd/consolefonts/cp866-8x8.psf.gz"
	);
}
static void svir_1657(void) 
{
	svi_reg(&(tinfoil.validation_items[1656]),
	        "8940163892a16be681715d6e372abfb319accff8aaa20e475ddaa7330fd8611e0ca2a9e2cf3f218bae58ff2d1f2dff04e43bf4c4219edd906f42836b19ea00fa",
	        "/usr/lib/kbd/consolefonts/cp866-8x16.psf.gz"
	);
}
static void svir_1658(void) 
{
	svi_reg(&(tinfoil.validation_items[1657]),
	        "3ea60e88ea2460aa6e0474e050630291b1d7c5709a7728133cc1a386e4fc4e53be1e4f983d924eab746725d7d7656daf6f7b76943656cee0194f0815239a3675",
	        "/usr/lib/kbd/consolefonts/cp866-8x14.psf.gz"
	);
}
static void svir_1659(void) 
{
	svi_reg(&(tinfoil.validation_items[1658]),
	        "bd67e35d5b95ba95bc0fb8045fdf7e8dba4577434947d2aea946ad5042d0897d755e7a0f500685554b8fe59970ad361f3cd1cb165764f561dc11ef6acbea776a",
	        "/usr/lib/kbd/consolefonts/cp865-8x8.psfu.gz"
	);
}
static void svir_1660(void) 
{
	svi_reg(&(tinfoil.validation_items[1659]),
	        "fa8870aad2e2659e0ea76bed501356d47f00df302d784f302924d2ee45e2aecae0a661aedaaff9c29d1cfd03d715cae28f496ff5ac9d68888c29b0f883e2a1c4",
	        "/usr/lib/kbd/consolefonts/cp865-8x16.psfu.gz"
	);
}
static void svir_1661(void) 
{
	svi_reg(&(tinfoil.validation_items[1660]),
	        "e1ea9c1d2cd0034a77f73685323d0d243b225db583b3f502583e67a875c714f8d5f5867946cc0bfd61b4aaf6c4a2b6fea1d845a53302dc2d220184855de5b24c",
	        "/usr/lib/kbd/consolefonts/cp865-8x14.psfu.gz"
	);
}
static void svir_1662(void) 
{
	svi_reg(&(tinfoil.validation_items[1661]),
	        "5a655ab25871f9ae3f4d3a0d055efc89ca48b361de6d655b490cf84f1cee498ddd560ec6f83b19a80d689907a7e863ba0d7aa1845c307a3336fc3a637427879f",
	        "/usr/lib/kbd/consolefonts/cp857.16.gz"
	);
}
static void svir_1663(void) 
{
	svi_reg(&(tinfoil.validation_items[1662]),
	        "e538f66a221b0b7f76ec8369a34eb06b7803e0ca48782670f87d22c5d6ad6a3e6e2200e6daa4f221502a749529282e56f466e30755d827c558ba3a567bc4cc8c",
	        "/usr/lib/kbd/consolefonts/cp857.14.gz"
	);
}
static void svir_1664(void) 
{
	svi_reg(&(tinfoil.validation_items[1663]),
	        "f0b1a3acb53b038f3b136e97a685918c1ce88264478cd1ecbedb0c2069129abee2b33358ebf7ce1a940d024268a59a11f616c809490bedb29d14d275ba3a9f28",
	        "/usr/lib/kbd/consolefonts/cp857.08.gz"
	);
}
static void svir_1665(void) 
{
	svi_reg(&(tinfoil.validation_items[1664]),
	        "6f5ca37948ef30ffe9644fed16e088de201cfe949e5944f7ebaf0d45185bce874ab85d70b0e60f2854034ab05aee0de09a2763b068abef2bcb8b6ef02847800f",
	        "/usr/lib/kbd/consolefonts/cp850-8x8.psfu.gz"
	);
}
static void svir_1666(void) 
{
	svi_reg(&(tinfoil.validation_items[1665]),
	        "fbaad356c815a42dc89968c2d990f7b4b28316b9752dc69ca0c48b3d4e410423e47b8be38670c4e25304f3a82eb284c94084d462d6ec8a76cb7b93561edc4b79",
	        "/usr/lib/kbd/consolefonts/cp850-8x16.psfu.gz"
	);
}
static void svir_1667(void) 
{
	svi_reg(&(tinfoil.validation_items[1666]),
	        "6063ae75d72ed4b2ae124e3cee3563f5626c0dff47d088f8f30b8d536ccfeecd2dcd984b27b158c53d2e171aa034bf4f2c4228ec8a17b72fb85082f130fd0c98",
	        "/usr/lib/kbd/consolefonts/cp850-8x14.psfu.gz"
	);
}
static void svir_1668(void) 
{
	svi_reg(&(tinfoil.validation_items[1667]),
	        "b823d6eaace499c7fe3e3f8900a5be2c76778d18c5464339ed97162808d6708b621e4d65a5b2cfe551907a8bcb0aaaaa8a4fa38aff0ea715c4038c4d9787f72d",
	        "/usr/lib/kbd/consolefonts/cp1250.psfu.gz"
	);
}
static void svir_1669(void) 
{
	svi_reg(&(tinfoil.validation_items[1668]),
	        "6e5a5f79ec76c9c883c247c316caf8f6b3a805a32ab28e4e3938363de25589aa2a2a5f5f7897ff8443fd42cb348d0cf4fd3f8e67e383a29af87661e93d1b9468",
	        "/usr/lib/kbd/consolefonts/arm8.fnt.gz"
	);
}
static void svir_1670(void) 
{
	svi_reg(&(tinfoil.validation_items[1669]),
	        "40553f87e7e23bb7c5c1b11a927ace10ca9428d53181aedd7d505dde0c4f026d361f2a0017fddaf69b390d8138222342af4cfec117841d2cf6e60ce66e37aa19",
	        "/usr/lib/kbd/consolefonts/aply16.psf.gz"
	);
}
static void svir_1671(void) 
{
	svi_reg(&(tinfoil.validation_items[1670]),
	        "dfa47df17f40bda75ebdc4c381cb98c2900995ecd67b1ff7ed4aa44585153c43e59a9ba64355b3674d63065afabd9b23fadda49d0f06c185a087b8adbe34b218",
	        "/usr/lib/kbd/consolefonts/altc-8x16.gz"
	);
}
static void svir_1672(void) 
{
	svi_reg(&(tinfoil.validation_items[1671]),
	        "fb3e66265ff5cbe3f7a4b30d6eb60a6e1f57d0f01f952254c83b17800e11039e6d95097f4f4f19ce38fdd46659894fba3fbff07c3faf644da3653623b154e8ab",
	        "/usr/lib/kbd/consolefonts/alt-8x8.gz"
	);
}
static void svir_1673(void) 
{
	svi_reg(&(tinfoil.validation_items[1672]),
	        "abda0e3fa47748338dd11878f8e59398ef6ade0a307d3b96858832680e45ba8c45976f56102d7b34d213c954ca5898a23a097df4a966e21fbaf29fd75f559b0a",
	        "/usr/lib/kbd/consolefonts/alt-8x16.gz"
	);
}
static void svir_1674(void) 
{
	svi_reg(&(tinfoil.validation_items[1673]),
	        "b31b588ddc22fb57e8007d914164fbd4e344fc1be5bd9c48f2cd842353cbf5f2cfea604fc1718754ff681c1f8172904a3541ade8441724c81fb16b86e0a3fadd",
	        "/usr/lib/kbd/consolefonts/alt-8x14.gz"
	);
}
static void svir_1675(void) 
{
	svi_reg(&(tinfoil.validation_items[1674]),
	        "9ea76f43634d5aeba0a3f6fee58c6c15897398bec505089a1d9e4aba23df7010d3e83efca2a0eca9cbb840511b1c84fd001e908c6aebb4a11c9b58705b39f66f",
	        "/usr/lib/kbd/consolefonts/UniCyr_8x8.psf.gz"
	);
}
static void svir_1676(void) 
{
	svi_reg(&(tinfoil.validation_items[1675]),
	        "1f0608de43909b427bcdf9719a28ce16fa23ffbd52a73605b3227fbacef17b5b9dbf4f9a3d69e536de0b573fb0fd6a60ae58bdf0c81599ebab89e92ccbae8e54",
	        "/usr/lib/kbd/consolefonts/UniCyr_8x16.psf.gz"
	);
}
static void svir_1677(void) 
{
	svi_reg(&(tinfoil.validation_items[1676]),
	        "b81ef2416581c3e80c192e0a252e88b4936ce6bfa4c3693d9765600c2586a0988c2e00e5f8602b9c753230873b2ea257d65c900c53a05bd58a4268bda7eff8e7",
	        "/usr/lib/kbd/consolefonts/UniCyr_8x14.psf.gz"
	);
}
static void svir_1678(void) 
{
	svi_reg(&(tinfoil.validation_items[1677]),
	        "4aa1d11c64668ba0dc18dd1075b6d05203f6ecdf32d2e4baefa7f5bd224ac3990fb8f0a8de2c44c131031ed6bd6cb3964b51a09f9c70cd4e881eb81467f39d76",
	        "/usr/lib/kbd/consolefonts/UniCyrExt_8x16.psf.gz"
	);
}
static void svir_1679(void) 
{
	svi_reg(&(tinfoil.validation_items[1678]),
	        "a703c19ab61c80d6a396a290edc378d411156b13aef6e3dd5d6c776e4f675222fd63879f6bd53d7c23472fa13b7536292e1d81f6efeddc0f6ddf1a3d674345ac",
	        "/usr/lib/kbd/consolefonts/Mik_8x16.gz"
	);
}
static void svir_1680(void) 
{
	svi_reg(&(tinfoil.validation_items[1679]),
	        "a6058c375c7a91dccbc6ef98c18792014221b58be1159e123554bb4142b8d59cd056c6427fef90e15a2d2cb73166b4fd0cbbea7f6e7e6f6091cf9b22317aa9b9",
	        "/usr/lib/kbd/consolefonts/LatKaCyrHeb-14.psfu.gz"
	);
}
static void svir_1681(void) 
{
	svi_reg(&(tinfoil.validation_items[1680]),
	        "c27e7d8a8f7c6c7f3d1c6db7475dabdc374d00ac8633f938713b401269ef2406f658d8c0448fcf752db341fcb65a6153d7de337926194cec883734274fb22e40",
	        "/usr/lib/kbd/consolefonts/LatGrkCyr-8x16.psfu.gz"
	);
}
static void svir_1682(void) 
{
	svi_reg(&(tinfoil.validation_items[1681]),
	        "47160ece62c06e6a8209534fc85a6ef2e20670edf3c22abb9c1a8b87c7047fe11784765e2f89d3165777dfc7de0edf01be45b5647b4e8a4e7b198876aa9c78de",
	        "/usr/lib/kbd/consolefonts/LatGrkCyr-12x22.psfu.gz"
	);
}
static void svir_1683(void) 
{
	svi_reg(&(tinfoil.validation_items[1682]),
	        "29428758b0ffa43dac751ad9a986350c72bca28f935f57e7575fda5402f74afbe48a9198b0384c11cc7cbce18ab68bb4576321ab5c8af6dbb720d4545d87e3cd",
	        "/usr/lib/kbd/consolefonts/LatArCyrHeb-19.psfu.gz"
	);
}
static void svir_1684(void) 
{
	svi_reg(&(tinfoil.validation_items[1683]),
	        "5002d854455c1af5905270d409965edd43e1f62b67ed07bae19a933d47b69e426b8ca753eba1be968cef2a4f7ed4066aa850bd57cff58e053d3e7ef8fbb64006",
	        "/usr/lib/kbd/consolefonts/LatArCyrHeb-16.psfu.gz"
	);
}
static void svir_1685(void) 
{
	svi_reg(&(tinfoil.validation_items[1684]),
	        "8a11b88d944a41f050b3cd4520e686b2f6f6be36dcfccffc23ef62877a9e8979d099b0f1b5fa390a671bf81c1dc491d5a16f00f2304f66651a5e41ff4f67d830",
	        "/usr/lib/kbd/consolefonts/LatArCyrHeb-16+.psfu.gz"
	);
}
static void svir_1686(void) 
{
	svi_reg(&(tinfoil.validation_items[1685]),
	        "7b100df045a6fcbee740f2f48239d666193400282a932e00f8aa168bec11227c47326dcddc2ea15a317bdd3418ca49f1f2e3fd5dfc56cd3d0228eb576fdb74e4",
	        "/usr/lib/kbd/consolefonts/LatArCyrHeb-14.psfu.gz"
	);
}
static void svir_1687(void) 
{
	svi_reg(&(tinfoil.validation_items[1686]),
	        "31be7e5f98416e4e6f21e7a0dae0dfc5709ed6c9abe4b980703538111014473ffab25ffef9afdefc035257c52da73e93f035a4763721bc410d4259ffbd3052f7",
	        "/usr/lib/kbd/consolefonts/LatArCyrHeb-08.psfu.gz"
	);
}
static void svir_1688(void) 
{
	svi_reg(&(tinfoil.validation_items[1687]),
	        "0cc864311430b92a987be59c5dc7af7a51450283c810e556b8d30cfe47d9d9b2863ccda1beb2c6429bab188c6b5cb9473355e6111debd835d272985db10d6b56",
	        "/usr/lib/kbd/consolefonts/Lat2-Terminus16.psfu.gz"
	);
}
static void svir_1689(void) 
{
	svi_reg(&(tinfoil.validation_items[1688]),
	        "10aff3824f894256948df6ff6d4a5a6aafaefd1036ce0056c2ca1406a244e60e8b9ff4e39c9a51acd9437b8a075bac537dea266b38a80d8b2ca852b6d9c69aa9",
	        "/usr/lib/kbd/consolefonts/GohaClassic-16.psfu.gz"
	);
}
static void svir_1690(void) 
{
	svi_reg(&(tinfoil.validation_items[1689]),
	        "48ffff4ab90fb6c1d3bc0bd69bebd0036c468c65289472dc9a9eea01be1af05e7c66f40826d8ecfdf718f6fcf8c8a2e5e24fbb5510b24f1263bab19510738ecd",
	        "/usr/lib/kbd/consolefonts/GohaClassic-14.psfu.gz"
	);
}
static void svir_1691(void) 
{
	svi_reg(&(tinfoil.validation_items[1690]),
	        "e33ef531674f4c1dcdaeef82137d8910ab9b0588cf3394d94f22a0e0e7ccae507b06bfc225623fbb38b810964a3f011e2ad3a76ea4cc310f95c2a980a385a07a",
	        "/usr/lib/kbd/consolefonts/GohaClassic-12.psfu.gz"
	);
}
static void svir_1692(void) 
{
	svi_reg(&(tinfoil.validation_items[1691]),
	        "080fa41f687e33f384128e78ed28462b3f6747099557c07d365e4274a8f0646cbfa0a187084c568f2523af37da782e1d17e0f80e29e9e87ab3e303c34360d535",
	        "/usr/lib/kbd/consolefonts/Goha-16.psfu.gz"
	);
}
static void svir_1693(void) 
{
	svi_reg(&(tinfoil.validation_items[1692]),
	        "d21751185d78120a934397f9b6b6a5a05485a681259f1bc6f4c1c81150a82e9ddff5ad3ad850d964b75b14b3ebdcfedd46d89847eab24aa2f440cfeebc7cd9cc",
	        "/usr/lib/kbd/consolefonts/Goha-14.psfu.gz"
	);
}
static void svir_1694(void) 
{
	svi_reg(&(tinfoil.validation_items[1693]),
	        "fd1d530b030f617a7365d0cca215da14a9c2c69f8b739b2ebd6ad103b7a41d5aefe00b2186c8dc0fba7866bbf04d7d3a9c0ef426f80bc7d5e5d6fea5194c6683",
	        "/usr/lib/kbd/consolefonts/Goha-12.psfu.gz"
	);
}
static void svir_1695(void) 
{
	svi_reg(&(tinfoil.validation_items[1694]),
	        "b5448db67d719bb87c738c04f5060a1bae4b4499a9dce8a69d1d103ae363c1db88daf78b5418702fcaf429df920d93d3ee2931d0f18cbbde1a7744d241ccef11",
	        "/usr/lib/kbd/consolefonts/ERRORS"
	);
}
static void svir_1696(void) 
{
	svi_reg(&(tinfoil.validation_items[1695]),
	        "1a32298d57d78d6cd19a07da92a9ac18287bffd42bdef930b5c72a09dc1c14f9eda8f98615ef57ff5b9c82b79b7ed91ee31a70683fe5fa637dcd3470cd286f29",
	        "/usr/lib/kbd/consolefonts/Cyr_a8x8.psfu.gz"
	);
}
static void svir_1697(void) 
{
	svi_reg(&(tinfoil.validation_items[1696]),
	        "109261b53a3c3727f476c3c101eab34508cf2a2e6e4f9eb68bdf3b11c2f0ea723fee3390ea6cbe2f40b1fdb3764afdbc3fe42712717235a41127403e8be32064",
	        "/usr/lib/kbd/consolefonts/Cyr_a8x16.psfu.gz"
	);
}
static void svir_1698(void) 
{
	svi_reg(&(tinfoil.validation_items[1697]),
	        "46b74ee304847150f491a6841be6f54238fb5e3e701f3e88ac9fcd1d765a0cab735b9951a7d46fafc922170f03dcd72ea758e14ddf7357d1abc3104b1a33ce60",
	        "/usr/lib/kbd/consolefonts/Cyr_a8x14.psfu.gz"
	);
}
static void svir_1699(void) 
{
	svi_reg(&(tinfoil.validation_items[1698]),
	        "0fc1aaa2e9922046959be7794ed45bdb80d4d330e9646882e2fd667255d25328be21aef1f8f4baca8703a2c619ca0af0b7a7b1376146b188e4b068d4b1c8b36f",
	        "/usr/lib/kbd/consolefonts/Agafari-16.psfu.gz"
	);
}
static void svir_1700(void) 
{
	svi_reg(&(tinfoil.validation_items[1699]),
	        "51ab4ff98818171f2282fd5fbef88cad8313c4a723ed6310145ab322518308c413f7d51afab99655398f5f7fac5321c3c79e096d658347e3d9d5864632ad69a2",
	        "/usr/lib/kbd/consolefonts/Agafari-14.psfu.gz"
	);
}
static void svir_1701(void) 
{
	svi_reg(&(tinfoil.validation_items[1700]),
	        "7bdf0d1cd37f7140505efde8c072bfa92153310d2cdd589681afcf1884954b54522b0078d8c80c364e200d2f5e82cde3ba0b3cc93370e434d74ecd95e793c68f",
	        "/usr/lib/kbd/consolefonts/Agafari-12.psfu.gz"
	);
}
static void svir_1702(void) 
{
	svi_reg(&(tinfoil.validation_items[1701]),
	        "ce6f44d3bcc856af11f02c7d0b89e0920bdc869c0fed0c24710640c69b0ac1e836e0b4618d435dc40cbfa52e537a044da509ada359637877b43e7663278839d9",
	        "/usr/lib/kbd/consolefonts/972.cp.gz"
	);
}
static void svir_1703(void) 
{
	svi_reg(&(tinfoil.validation_items[1702]),
	        "20d41731fde276d42f728d1c54d10d0c69da702f4e81da6169d8a2bc6ef26f63ec538ad9b7c09a00d65dd8131eddbe728bc50f9d27a30ad1b18dea1dba351b19",
	        "/usr/lib/kbd/consolefonts/928.cp.gz"
	);
}
static void svir_1704(void) 
{
	svi_reg(&(tinfoil.validation_items[1703]),
	        "04b3c9faa22d2836ca703be125743e5cb19cc2bec219b2332cecb237218138c8ee9905c95a930d2334f2302a39558eb6a5101892f8588d7d9958cab0659ad69c",
	        "/usr/lib/kbd/consolefonts/880.cp.gz"
	);
}
static void svir_1705(void) 
{
	svi_reg(&(tinfoil.validation_items[1704]),
	        "14a5e7a66e09c00cbf30c5dbf5c16728bfaa4fd048834955cd1452b7a6b68c215e6687e99b5731cba5eaa9d7a80aa5781e3e8f8116f3c6fd555258bc18cb7312",
	        "/usr/lib/kbd/consolefonts/737.cp.gz"
	);
}
static void svir_1706(void) 
{
	svi_reg(&(tinfoil.validation_items[1705]),
	        "9c226c2882d7047eeedf1112af1af90fc7e0135c7f06c662e9d5ee55bc46b12a3e56d7838f6c15858b02302ef823cb0437a0b7483a3f0f4466089dcc980d3575",
	        "/usr/lib/kbd/consolefonts/165.cp.gz"
	);
}
static void svir_1707(void) 
{
	svi_reg(&(tinfoil.validation_items[1706]),
	        "dd4c8d28ef99f97ae880ec6d73f11be95c5d7e81ecd5c5e2f1dc4743a84e5c9827f5868dcd629d84a86d0fe22b5aa46e2d46f0df5e295902b4fd22bf9e5f2f17",
	        "/usr/lib/kbd/consolefonts/164.cp.gz"
	);
}
static void svir_1708(void) 
{
	svi_reg(&(tinfoil.validation_items[1707]),
	        "c6aae8a8aa5c26a52b656f67776f7518c145c762b8ff6dfd58d4a32fc1fa7c99abe0fe4ff50731422236e6ad6071c44cfb810867f0a9218c47afcc91492c3f6e",
	        "/usr/lib/kbd/consolefonts/163.cp.gz"
	);
}
static void svir_1709(void) 
{
	svi_reg(&(tinfoil.validation_items[1708]),
	        "2c6cb8ee10781cff98ff9036e99236263c73e3be555a944861fa6e58b69eaa7cd50a05081003819f8431624550130ff531f0de3b0997e7018b1c6b22b7fd0ccd",
	        "/usr/lib/kbd/consolefonts/162.cp.gz"
	);
}
static void svir_1710(void) 
{
	svi_reg(&(tinfoil.validation_items[1709]),
	        "857b4c8e111edea5029c859a04ce35ea50e74aa23f6d962eb4843ad08695003d926d43944017d3c39c50aa77084d00042c783111a0ccf7ce28c153e2b9aa04ee",
	        "/usr/lib/kbd/consolefonts/161.cp.gz"
	);
}
static void svir_1711(void) 
{
	svi_reg(&(tinfoil.validation_items[1710]),
	        "94565a3d6743735c4e0fb19d39439cc2b67140c6a07cea78c0750024ab00bd22340d532f4e3c44db34ec77f62852a3e5961de2403a20704caa00f39b24bb7303",
	        "/usr/lib/initrd-release"
	);
}
static void svir_1712(void) 
{
	svi_reg(&(tinfoil.validation_items[1711]),
	        "6d4ed45554e2a2c665b4d38621956ffca5546aebd797a0bf28250c0a38a667512d93eb7f37262c2e28c80d9682a645626862c1661ee45e4beb88253d6b8cdeec",
	        "/usr/lib/fs-lib.sh"
	);
}
static void svir_1713(void) 
{
	svi_reg(&(tinfoil.validation_items[1712]),
	        "730b034b6d25431e651e41cbf449df0598c0acd56c767b4ec3843a0bff3a18c340eeaf95cb2e84f1cc653385ae6797e5e151a4e4bddf78725dd476f2d06667fc",
	        "/usr/lib/firmware/e100/d102e_ucode.bin.xz"
	);
}
static void svir_1714(void) 
{
	svi_reg(&(tinfoil.validation_items[1713]),
	        "406524637c5aa7f548340ee0c2951f2eee567f002e39a65214b7d47e584e5b48c7a72d6ff0c0d42a3369487f76e0b691b185cc6d3eb1011a66eea41f297dff65",
	        "/usr/lib/firmware/e100/d101s_ucode.bin.xz"
	);
}
static void svir_1715(void) 
{
	svi_reg(&(tinfoil.validation_items[1714]),
	        "d9ea46afe41bedc356622ab15f4442e9b7d94153e60dbe3a83757bbaa0db4d432b55007112a6c8a482a722e21f08f0816dba7880fde25e8559b73c63dc7fc4ed",
	        "/usr/lib/firmware/e100/d101m_ucode.bin.xz"
	);
}
static void svir_1716(void) 
{
	svi_reg(&(tinfoil.validation_items[1715]),
	        "1e2a2e7c61d1c7e3f9846b8779cbc807b08bd23bd80e97b956694a12d31ded953dd83faf248b429731a94007aa6ad67bc571704158f17d08d283f72c42d1e77d",
	        "/usr/lib/firmware/cis/SW_8xx_SER.cis.xz"
	);
}
static void svir_1717(void) 
{
	svi_reg(&(tinfoil.validation_items[1716]),
	        "3fc371ab44295fc0c90c9e7afacc23d3932d03e569b59302ea76d8c4383991e54ede14e6d1adf1bb38ca49f70cc3100d99fc582deb19b96f33df9a2459046b2f",
	        "/usr/lib/firmware/cis/SW_7xx_SER.cis.xz"
	);
}
static void svir_1718(void) 
{
	svi_reg(&(tinfoil.validation_items[1717]),
	        "380343b7aee5ad47acfef6873699d16cebfcf89cf210630b1cf881a8abd01eadd68710a1a88b8f09f67e2c60225712af6550c055831a28ca4d54e73f3bc1ea30",
	        "/usr/lib/firmware/cis/SW_555_SER.cis.xz"
	);
}
static void svir_1719(void) 
{
	svi_reg(&(tinfoil.validation_items[1718]),
	        "c85aba44b9832a98b7882fa4f30fbf7d8810740065193cd991b8287e65c1a4c8588e01179983577e0636f04ffa5317ffb99dc0b9e4220f71c4b473b4cad1460c",
	        "/usr/lib/firmware/cis/RS-COM-2P.cis.xz"
	);
}
static void svir_1720(void) 
{
	svi_reg(&(tinfoil.validation_items[1719]),
	        "bc4fe1175fab973b1d7a6836556a0e37c773c9e111ce77b23f6f391aa9957361a32b813d3c1cdace0f2ae9cc502691acd6f2b5737fe1754744839f699ec946a8",
	        "/usr/lib/firmware/cis/PCMLM28.cis.xz"
	);
}
static void svir_1721(void) 
{
	svi_reg(&(tinfoil.validation_items[1720]),
	        "e109a57ba7091d3cbb3ffe78d87b1a5448b4755e5ce08076254701f454e54d98c11647d954006d43fb2b52bc16954aeeaab2242f995eacbfccd3f8c0a08abe5b",
	        "/usr/lib/firmware/cis/MT5634ZLX.cis.xz"
	);
}
static void svir_1722(void) 
{
	svi_reg(&(tinfoil.validation_items[1721]),
	        "21aa5ba76229f7657850eb6b1e311184109562cbb9f4ad1c07121fdfc4e9832ba9b38e142cdbae5ba929bef1cfaa58eece712a48e9129a8a6064845b910b1609",
	        "/usr/lib/firmware/cis/DP83903.cis.xz"
	);
}
static void svir_1723(void) 
{
	svi_reg(&(tinfoil.validation_items[1722]),
	        "48c0d305191806da5b8c18ed2db7a10cea0bfb37d6dd8694a28a35405412a0787452d13bf8119e0d7154119cce1444e29e975c51bc15d140ceebe4eae5f7162e",
	        "/usr/lib/firmware/cis/COMpad4.cis.xz"
	);
}
static void svir_1724(void) 
{
	svi_reg(&(tinfoil.validation_items[1723]),
	        "3e5e95208f1b3feb27b1945c6ff88c4040ff6769274ce00e0bd1cda5a5fc684818b291ebd39199305da2ce771565855fde7decb4fa1d240c9ef85ba24e18544a",
	        "/usr/lib/firmware/cis/COMpad2.cis.xz"
	);
}
static void svir_1725(void) 
{
	svi_reg(&(tinfoil.validation_items[1724]),
	        "22feb5999ab412645c9af1fa906fef6717240f49d460597c962c5247de22ab610543448922ccf194c7ae3be453fe0b2eff9760eef362bf7583b6c75e3db13d10",
	        "/usr/lib/firmware/cis/3CXEM556.cis.xz"
	);
}
static void svir_1726(void) 
{
	svi_reg(&(tinfoil.validation_items[1725]),
	        "ab2f83bbb0048a3676ad9062e46d4f6beafe451460654ef77f26a318c6aebbd806acc5d5e8f48fd9629cf2d8e4e18996bcfa34322a4e17caa14d8392a7664737",
	        "/usr/lib/firmware/cis/3CCFEM556.cis.xz"
	);
}
static void svir_1727(void) 
{
	svi_reg(&(tinfoil.validation_items[1726]),
	        "8b8873b958e1e1ec2d5537edff75c89be7e73fee1bc642e95ead8cf80ec9ec83c9c5ff47a830f1ff4f0c40a052e356bb391676d01505e77da8b6e40d343d701c",
	        "/usr/lib/fedora-release"
	);
}
static void svir_1728(void) 
{
	svi_reg(&(tinfoil.validation_items[1727]),
	        "1eb77c7e3117e9200ea97d4f7f5117d3c96e5ca335214e3bbb4851d964350485f4d8fd5c011933fd22d0a8b42e343c8ad09488cc8c66832aa2a82e2a456b790a",
	        "/usr/lib/dracut-lib.sh"
	);
}
static void svir_1729(void) 
{
	svi_reg(&(tinfoil.validation_items[1728]),
	        "fbc0fc6724fa6bf645434e17ee9dff4e4e188e0f3a076c322746230c8d2fd99395f448bc987632a59aac463dfb9377d05dbc33c5d0575e6074374e3eb8b5936c",
	        "/usr/lib/dracut-dev-lib.sh"
	);
}
static void svir_1730(void) 
{
	svi_reg(&(tinfoil.validation_items[1729]),
	        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	        "/usr/lib/dracut/need-initqueue"
	);
}
static void svir_1731(void) 
{
	svi_reg(&(tinfoil.validation_items[1730]),
	        "69645d5c11ffdb63605f5602320ff903bf59320c64f83a3775c048cc673baa4d29aadfd009b9605f2b242e7a7ac6046736e2913dc782815591a92184a3d49c91",
	        "/usr/lib/dracut/modules.txt"
	);
}
static void svir_1732(void) 
{
	svi_reg(&(tinfoil.validation_items[1731]),
	        "dbcb6d1caf08d3f7296b3c5634229a859ee68f1ab79314c35a99921b5388431b76d9c08d854b7164428dd8d512d24bb7312c6ad56893e68e7b8ee9a898e46335",
	        "/usr/lib/dracut/hostonly-files"
	);
}
static void svir_1733(void) 
{
	svi_reg(&(tinfoil.validation_items[1732]),
	        "31acd0039a78d5beefb924e8337321bd2b8016c959cf9f71d51d563d4cd1151446ad4671a4cdefb4fd77a20c4e943c2dd5a19857bb7df51e8e0dfaddd0312df9",
	        "/usr/lib/dracut/hooks/pre-udev/50-ifname-genrules.sh"
	);
}
static void svir_1734(void) 
{
	svi_reg(&(tinfoil.validation_items[1733]),
	        "21c1189591d0484c8f50b75f050c52ef9059207f15fd2d816b4ef13f8c98636074323bdbfc3817bb22a75e1de78332b1f49e37819136504d9a7349b937ffe683",
	        "/usr/lib/dracut/hooks/pre-pivot/85-write-ifcfg.sh"
	);
}
static void svir_1735(void) 
{
	svi_reg(&(tinfoil.validation_items[1734]),
	        "a8c81fe64e37400871d1694f523bb73a398ed8eedc23c960f3f0d7f113d0bdbc04fdae21b84e49189c041e823c241df1cd0dfcbae0c251deb493461d2205477c",
	        "/usr/lib/dracut/hooks/initqueue/timeout/99-rootfallback.sh"
	);
}
static void svir_1736(void) 
{
	svi_reg(&(tinfoil.validation_items[1735]),
	        "5e0e45f576ba4a83363450fc1d99858f9d3749fa701338834968916a3d9c6d98bcd31bc76c7b724239d0841a537c99665a4dbf0823cb88bd91fe23f8bf52f647",
	        "/usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh"
	);
}
static void svir_1737(void) 
{
	svi_reg(&(tinfoil.validation_items[1736]),
	        "83b0026310c8956d9fddeeb9dc0d11a62704517426594616fa4c3ae377b6fe3c7cf44e3ca3d1389559efe6b373427a58f1d978f997a52aa866e9c3fd7ee1f601",
	        "/usr/lib/dracut/hooks/emergency/50-plymouth-emergency.sh"
	);
}
static void svir_1738(void) 
{
	svi_reg(&(tinfoil.validation_items[1737]),
	        "e58335ed810a8e0f4a261b57cf2e5f650a37bb62e94075709a847f921e1a6b287ca2463d38eb40cbaf4809847c0be1dc8fbd29192e8be04048ea7aa57aa84b81",
	        "/usr/lib/dracut/hooks/cmdline/99-nm-config.sh"
	);
}
static void svir_1739(void) 
{
	svi_reg(&(tinfoil.validation_items[1738]),
	        "01b72229c9867e297f44768f2ebf2fa07929a980f46b2c9931cc38b6fb3998b73dd7f246f50a383a892a08e2f6b8a5d5a6074c4918e57c71f91285788b8d4356",
	        "/usr/lib/dracut/hooks/cmdline/91-dhcp-root.sh"
	);
}
static void svir_1740(void) 
{
	svi_reg(&(tinfoil.validation_items[1739]),
	        "7a886225ee1e7a2993c0e3b0d04b43e2eec75428040981b540ce311d56600240b24bf3d1dfaa6d80dcdb7c2eedbca5c37b4ae22270f3b60b139d6a7555bf2c12",
	        "/usr/lib/dracut/hooks/cleanup/99-memstrack-report.sh"
	);
}
static void svir_1741(void) 
{
	svi_reg(&(tinfoil.validation_items[1740]),
	        "7a33348b0d9274f99123285a6444d5168a19448e1a939dc71be05cea56560f143a02bb583b520b55b0d246160ace759003875418f70a293c01212d7757217550",
	        "/usr/lib/dracut/dracut-055-4.fc35"
	);
}
static void svir_1742(void) 
{
	svi_reg(&(tinfoil.validation_items[1741]),
	        "101f35a98a28df91f41449b90edf11a0d332714176b77fac50bb95e22e1a794cde6c292b3af25623f3fbc60667e31dbb5c1cc49cadbd4efb9955e3537b3d42c2",
	        "/usr/lib/dracut/build-parameter.txt"
	);
}
static void svir_1743(void) 
{
	svi_reg(&(tinfoil.validation_items[1742]),
	        "dbdcd79a302bbd9a52070665b39359cd66b265a0feee847aad7cd37cd057f81524483c57ea8883277b8684413165209c4599e2957fff0e29a989b63763c34d9c",
	        "/usr/lib/NetworkManager/conf.d/initrd-no-auto-default.conf"
	);
}
static void svir_1744(void) 
{
	svi_reg(&(tinfoil.validation_items[1743]),
	        "5b52441eb3e8e4d5902cee4e6563cae0b8d0b141d5a24a2ae343e88cf31620052570ce42b35c8e69f9a0db325e914b3f7727b55c64557383e79e352cd38985f4",
	        "/usr/bin/vi"
	);
}
static void svir_1745(void) 
{
	svi_reg(&(tinfoil.validation_items[1744]),
	        "6551fae1285ed55387ebf00a35ed2c9d95e16ca7eecc56d1f6917d3113acdb9ce00f60d8b978207a2598ff4c74bb6bf808741026c0d2ca60bb9aaa8d34d9caf2",
	        "/usr/bin/uname"
	);
}
static void svir_1746(void) 
{
	svi_reg(&(tinfoil.validation_items[1745]),
	        "e9940eab81542676e1e8598d60e01ee847bfde04a0c2f1c8206ebef6b2584f775a9c222f5a42e9a57cfc75f3d3e3cf02df0695d33fe8ae450e94a6b45f122924",
	        "/usr/bin/umount"
	);
}
static void svir_1747(void) 
{
	svi_reg(&(tinfoil.validation_items[1746]),
	        "787ef7ae71688145275bdfe91c7bb046509a76de9c3da37895db3048f6951e7fb6970e300b17a8f29bb001f8d8ed51064eb9bc4dda6a88af9f140c8fb266cc07",
	        "/usr/bin/udevadm"
	);
}
static void svir_1748(void) 
{
	svi_reg(&(tinfoil.validation_items[1747]),
	        "398d389040f0f89ece06e2c224c4a37beaeabb8e3f7a1bef2d7fa691180e7d72232b30b1d0db10dbc50ad168d64e0db7d77b534d3d3e5cbbfc61d2f9dc8756f9",
	        "/usr/bin/true"
	);
}
static void svir_1749(void) 
{
	svi_reg(&(tinfoil.validation_items[1748]),
	        "f183e6d58da884c3b9408346b9492818d512f21510014cf8999b3a38cc408ecb2a966dd39b7f7dc8597485a56b4dc31830b8f68f0fda2e6baff11f245830aad7",
	        "/usr/bin/tr"
	);
}
static void svir_1750(void) 
{
	svi_reg(&(tinfoil.validation_items[1749]),
	        "11c71e4990f01314b9e0b91e266e018f6d07642af909a588bd6e48352a289cb0935a4a63421d9d0de5eb894b38a49ae3c40b7825bc62acb42faa0f71e102ffe3",
	        "/usr/bin/timeout"
	);
}
static void svir_1751(void) 
{
	svi_reg(&(tinfoil.validation_items[1750]),
	        "a1b87180235c7482313b32dee67e54d7f9c449368454526bb93441796708788a54602857e2f95e2dab55404e1311cca42cec9d2add09b5bd24cd6c0ec8dbad4e",
	        "/usr/bin/teamd"
	);
}
static void svir_1752(void) 
{
	svi_reg(&(tinfoil.validation_items[1751]),
	        "0424bb9173ef9d94e8029a5ff9196c0ecfdd4afe0bfa8ce796dd1c0c52dbbc47e956675ac48caf3fa8cc2225823db7af6b1da501c3c1bf80f255f61dbfc97944",
	        "/usr/bin/systemd-tty-ask-password-agent"
	);
}
static void svir_1753(void) 
{
	svi_reg(&(tinfoil.validation_items[1752]),
	        "a659683f56a931b44f1ce69c24c1ac62ab53ea5cf600e9992a08054b5933d4b0464ff71c8f941ed7f84038895b6b9ee2c6c9081fd36f9fa3c004f026d1cb9278",
	        "/usr/bin/systemd-tmpfiles"
	);
}
static void svir_1754(void) 
{
	svi_reg(&(tinfoil.validation_items[1753]),
	        "6a2ba96d14b32e582033d0fde3653741e127fc8409b50cb6fabd83853fccb73f5af648543c75a53c1a33ef8beaaff00bb3cdc6ef0ff7c7e9efbdf8c135a7b096",
	        "/usr/bin/systemd-sysusers"
	);
}
static void svir_1755(void) 
{
	svi_reg(&(tinfoil.validation_items[1754]),
	        "c2071697f9d757dede31afa1b52dffca53a51558589e753a81c0689484f36a2aea67cb0b30cddefaaed122ea9afb7aec66194c7946f4e03ac0e3448f0724b19c",
	        "/usr/bin/systemd-run"
	);
}
static void svir_1756(void) 
{
	svi_reg(&(tinfoil.validation_items[1755]),
	        "07839f0cd2617582079184a6fc3933678ed6250c4f11c52893be0980df20cbff3d72d1d680470aee5600e482dfee0f6792a875b82c28e3edd58a67119c1f24b9",
	        "/usr/bin/systemd-escape"
	);
}
static void svir_1757(void) 
{
	svi_reg(&(tinfoil.validation_items[1756]),
	        "bfb8f883dcb07944ac03a8a6824b492166bd21c52d48c27a1776b96241766d2c8036519db249a147072caffa046ceaae80e207af8e044e78d5ff2ec6e06201e5",
	        "/usr/bin/systemd-cgls"
	);
}
static void svir_1758(void) 
{
	svi_reg(&(tinfoil.validation_items[1757]),
	        "f5d688dff7ffbb5f7eb6af7939f7fc76266631dec04ba9048c5883c6f22fd4474518d30465b5cc4fd90d62ce8bd8b2e5a87bca3153355def16080a7694541fac",
	        "/usr/bin/systemd-ask-password"
	);
}
static void svir_1759(void) 
{
	svi_reg(&(tinfoil.validation_items[1758]),
	        "280cb95b0ba73dc5c8ae9bc12ef9a42a809de1503fb67efffb29d64aac4427967378da7bdc6e9d0e5a4d0c0f60e64725cb485cedd41e40bfa1c427c227a5cab9",
	        "/usr/bin/systemctl"
	);
}
static void svir_1760(void) 
{
	svi_reg(&(tinfoil.validation_items[1759]),
	        "f971695f0bc14fd45d16bab545f3f2eb22e407dc7a11c20a4994525290c0bf773f594efb3dd3178c4e4eb73e1c5210cb92902c483c731bfc4854c2b1b551914a",
	        "/usr/bin/stty"
	);
}
static void svir_1761(void) 
{
	svi_reg(&(tinfoil.validation_items[1760]),
	        "7d6eecc8ae453e2e056b125ef3f629aa32779d741f5aa23f842fa2799d82688948d70806e87e492d53e7fa5468c89fe1ff4868255ced18ca1da928867b635f9e",
	        "/usr/bin/stat"
	);
}
static void svir_1762(void) 
{
	svi_reg(&(tinfoil.validation_items[1761]),
	        "0088658666d99ed3629061aa4de4fc51d91850aaf3f34fa0a2819a5afc15bc5101e234e0c841c3b35102535e351ff556a667e8dc4e33caf772fcb8d170fb81a5",
	        "/usr/bin/sleep"
	);
}
static void svir_1763(void) 
{
	svi_reg(&(tinfoil.validation_items[1762]),
	        "1735ef84e210e64ebf522db6fe623f9d5824a276b5d26e84778ddf7ee55bd623e924149c52ab47587e33cd0948206020b66ef18c76940b0a6cb4937ebc7723e9",
	        "/usr/bin/setsid"
	);
}
static void svir_1764(void) 
{
	svi_reg(&(tinfoil.validation_items[1763]),
	        "171565123bc95c0c7df7472e9523899fd34b4be6cf0780e8ddb5e96bc4bad0a2f986a3ca0ddbc322ce189f664628138f34de9668f6431773c344ab4c353626f1",
	        "/usr/bin/setfont"
	);
}
static void svir_1765(void) 
{
	svi_reg(&(tinfoil.validation_items[1764]),
	        "3fb39e9fe5d09450453c0979886f797b28c51f0a48ecc9a5fb95adc28746acf893828f9b0e9a6c094df1bb53b410c2c1f7e2e45c4ffd1625dbdb9680971babce",
	        "/usr/bin/sed"
	);
}
static void svir_1766(void) 
{
	svi_reg(&(tinfoil.validation_items[1765]),
	        "3a063967b0de98fa5dcf582214f6dfddfd11b3b14d4ec90271efdadf5b6046799dd46dff3011c3679a3fa6a2f179824ee2e525d6aba0ac9643c1ec1542e6b41b",
	        "/usr/bin/rm"
	);
}
static void svir_1767(void) 
{
	svi_reg(&(tinfoil.validation_items[1766]),
	        "ec2ce4e917a0fc222979d4a46e83699a66e6b859d7ad12c7d2c71c6e89e3415ff7fba34ae406ebda9a654b4ba3d14f0a0b39004c70d419c388fab15eb8da475a",
	        "/usr/bin/readlink"
	);
}
static void svir_1768(void) 
{
	svi_reg(&(tinfoil.validation_items[1767]),
	        "b270ac5b8a9ad028da7a11e0f53fc40fc3ee01af35244a4b5d92f50beaf0ca65640fa946bf61872602a7a344a74f2ad5852ec51c2be6d2ded77b3883a0dc3f1e",
	        "/usr/bin/ps"
	);
}
static void svir_1769(void) 
{
	svi_reg(&(tinfoil.validation_items[1768]),
	        "7c62fe53825b5e04196121af87c4e9abbd894d0966905eb17c2a9b3d5cb35ce6e023b010fc7e8e83f7f423c001a42e646b12ee285b8fd11bfafcf95c4888f39d",
	        "/usr/bin/plymouth"
	);
}
static void svir_1770(void) 
{
	svi_reg(&(tinfoil.validation_items[1769]),
	        "e4b1aff49609d3982ab9f38ee098533ba2ea4c63eb1b2b2f93b52055135bec47b218c629bc25d1cdd38f8e56c1cd1018880c08621f6f54e6bf2e478ad1d22335",
	        "/usr/bin/pkill"
	);
}
static void svir_1771(void) 
{
	svi_reg(&(tinfoil.validation_items[1770]),
	        "c5467e9733162e5c3d7f9a07dcf5a7092c10d9ba7b7020e89244794449ac93bb129ae0d87d9f90c858b5d62f14ea61fee44cc59c0ebb1c10a0bff0ed3966d11a",
	        "/usr/bin/pgrep"
	);
}
static void svir_1772(void) 
{
	svi_reg(&(tinfoil.validation_items[1771]),
	        "87bca35a4738b2fcce96cb5e76b4daed3c1c43ffdc4be9de130115ce6af9f6b693745e209b513ed4914f1f0a7c98dd47cd9620e64f9838ef1d9a82d85fcb1e18",
	        "/usr/bin/nmcli"
	);
}
static void svir_1773(void) 
{
	svi_reg(&(tinfoil.validation_items[1772]),
	        "6a71af07fcb232664dff91f4ea8f40fec056d236bead127a21ced0c6cd82da1637523796cd8db74cfcb12471f0d7221694cf48d46df395381cf7213ea6339d3e",
	        "/usr/bin/nm-online"
	);
}
static void svir_1774(void) 
{
	svi_reg(&(tinfoil.validation_items[1773]),
	        "6d6901cac5d85d735c430c068bc3b598c5c11a5bc3a4bd5bd441df9477a1b3557a83b00d2e241a118bd894a1fac222fa3b43be4dd8dccdcbf4ae4a759671b4f7",
	        "/usr/bin/ndctl"
	);
}
static void svir_1775(void) 
{
	svi_reg(&(tinfoil.validation_items[1774]),
	        "485fe074af48a7743a960cc8890aca402de0c48e677dd6dabb40c861a5c43444dad0b4b57a76c61a065316eb5cbd0669319e613a0f991d55cc0a52b4996b0124",
	        "/usr/bin/mv"
	);
}
static void svir_1776(void) 
{
	svi_reg(&(tinfoil.validation_items[1775]),
	        "d2385caade1cd9d90e6ab7a265d6f9fdd459fd9b05eee2703006ba6e6eebd50be2c1c8464c739e363c4fd867af3df3e5987644507c1725fa6ab0588152b526dc",
	        "/usr/bin/mount"
	);
}
static void svir_1777(void) 
{
	svi_reg(&(tinfoil.validation_items[1776]),
	        "15743d75ae57d66b05f68d70ffa49dba2faee4330cc86d0c76f0f4d4db72b9082ccbd2e5d7793e52e9f22a1fb43fa58eb60b9ca5d282af698a425aeb4329fcd7",
	        "/usr/bin/mknod"
	);
}
static void svir_1778(void) 
{
	svi_reg(&(tinfoil.validation_items[1777]),
	        "95d524dc11f134f3c9d8c4977fc9663e8e72ab40b4f2470ed536acc01381e2d75a0cc8076cf509c5f959e46240f2bb5fa2c377cf63d4cbb06f7bd2f66b24322d",
	        "/usr/bin/mkfifo"
	);
}
static void svir_1779(void) 
{
	svi_reg(&(tinfoil.validation_items[1778]),
	        "543d844d92c2b1720cf97625633d0514961388d9817ab2ba6e268044ecb4174859403949acc83072e8aee16fa66aa84b6c9a30a40279138e5d7806fc5e6af3b5",
	        "/usr/bin/mkdir"
	);
}
static void svir_1780(void) 
{
	svi_reg(&(tinfoil.validation_items[1779]),
	        "07a158662b98498e627f8485aa1a2318c39def7cb0edf1daa48fc2ca4043afadb39d258ef8a42ba3895ba84e14664c25162bd8390abc3ab8887167820e0bd1dc",
	        "/usr/bin/memstrack-start"
	);
}
static void svir_1781(void) 
{
	svi_reg(&(tinfoil.validation_items[1780]),
	        "b9ddc84089a8718d85a27bc3b5f07df9f8f9d8a441cabe9090b5f30b8c8c9561c808c3c406a5f38ffc3e0f5bbcbcb72a0b72408d7313dc076ff47f9e061ef7dc",
	        "/usr/bin/memstrack"
	);
}
static void svir_1782(void) 
{
	svi_reg(&(tinfoil.validation_items[1781]),
	        "db63e32135f087504df7fc34e9085c411195b99f3fef8df68178761481a3da7dd944a0791bfb5097a7dd82249bb2acb0b0daea1d1f4107a840452da1296001bf",
	        "/usr/bin/ls"
	);
}
static void svir_1783(void) 
{
	svi_reg(&(tinfoil.validation_items[1782]),
	        "3b27b970a3246a45ad6589c0ea55fbec33a3a51227bb0b703f3e52a971ccc0d6cb4aa1a1ff5d06469ee97156320af9caad7085de22f9e501bd7bc7272d17632b",
	        "/usr/bin/loadkeys"
	);
}
static void svir_1784(void) 
{
	svi_reg(&(tinfoil.validation_items[1783]),
	        "20d57ff970272a7404d14e6f7d063994c278681682c73a8ab8683d6d2536e44625e0a8703380ad7536616eeb4d996abdbb05b19011dd3a5b356e86859d33e238",
	        "/usr/bin/ln"
	);
}
static void svir_1785(void) 
{
	svi_reg(&(tinfoil.validation_items[1784]),
	        "126aa131057fad2702f04275465a0b16055219784ead65475a62cbc7c10fcd2c4f2ef0fb5939b4ecb2636d9caf91a3d1256dca4323ebe143c56b19acd622ed81",
	        "/usr/bin/less"
	);
}
static void svir_1786(void) 
{
	svi_reg(&(tinfoil.validation_items[1785]),
	        "e2a4098377a4c4000421a1084b8f61b677502b7a060bf4252b8c3e6b6bd58b29921f0f4d8bd06bfb1bc5806cfb0493b1698c208762f0aa0942c31da53ab7d32f",
	        "/usr/bin/kmod"
	);
}
static void svir_1787(void) 
{
	svi_reg(&(tinfoil.validation_items[1786]),
	        "a47512d76105e8e28fe5e09ad3be776c4cd130de224dca4ea60a70f37c139bc750e5045734da3391bd392731a26842f5944db46326a4b189eb7ca210c6a3ceb2",
	        "/usr/bin/kbd_mode"
	);
}
static void svir_1788(void) 
{
	svi_reg(&(tinfoil.validation_items[1787]),
	        "a033ac3a647cbf490f45b7ebe3c50be0529d99671da0fedc14067c1a6975f2be08f25d029fbef668463ef67fd4d80fa32d7fecc0d6b57790f902d55424b2b714",
	        "/usr/bin/journalctl"
	);
}
static void svir_1789(void) 
{
	svi_reg(&(tinfoil.validation_items[1788]),
	        "a17bee1441eefc983fd212be611cbf5f942af4410fec37400e8340e2dbef0d19f273c7fe6f7c698513943857864a3c605d8010cd6ccafd833bdb96a7683314e7",
	        "/usr/bin/gzip"
	);
}
static void svir_1790(void) 
{
	svi_reg(&(tinfoil.validation_items[1789]),
	        "da489e66efb8dd8a452a79302ce753f0dc5a51f021c6d1b2fb1ebcf6effdefbaf037d8a43733b6be2d6714a56b07985ae322bbab2e834c94f0c76f8e8d569331",
	        "/usr/bin/grep"
	);
}
static void svir_1791(void) 
{
	svi_reg(&(tinfoil.validation_items[1790]),
	        "1a5c986509df98c100487a5b6440204543e20000b5c93bfff252997ecb4856c62c16dba7a77a33af5f8da4f9df950a9366f4f92c0da021b229a4781d8b8aa4ef",
	        "/usr/bin/gawk"
	);
}
static void svir_1792(void) 
{
	svi_reg(&(tinfoil.validation_items[1791]),
	        "9d203693c61bce0f06cca6f6ead4b29a58010fa9f2474e0d2e5af0e1de91cd62987a935ec1cf3b26c052edcc6b041c370fcffe455d9af11339fa65330821e2f2",
	        "/usr/bin/flock"
	);
}
static void svir_1793(void) 
{
	svi_reg(&(tinfoil.validation_items[1792]),
	        "334854271683430c2c32a4055ff4cd5b53f43fae1fccdb71880059b3228aba8f722389501319108b3c9da8a233d82e181c1a7191b17bf25a07ad06fbc53f1956",
	        "/usr/bin/findmnt"
	);
}
static void svir_1794(void) 
{
	svi_reg(&(tinfoil.validation_items[1793]),
	        "7f62b6ba6f87e8e3a0fae9b5daf27b55be8979c7ce272293acd99a37a856e36e4ecf3ec625e42b749bb000a89444a86e9c6dde63484318a23d63ed013acec211",
	        "/usr/bin/echo"
	);
}
static void svir_1795(void) 
{
	svi_reg(&(tinfoil.validation_items[1794]),
	        "25f5b8678e4155e3008ef4053f10ad1c169488fa57a1536316a22eee9df970a1ea80c2029f1c22ebb04645582a77cd2c1aaedda0a50bfeb1c9258465750dd711",
	        "/usr/bin/dracut-util"
	);
}
static void svir_1796(void) 
{
	svi_reg(&(tinfoil.validation_items[1795]),
	        "de0a515d47806fc8f8a5200a8d236de4394dd92ea6fa6b8a1b21756445408c7ef6e133b70b0ff7ee52e35da3c81e1d38833767aa7b9a2c56d1feab5b4ebe7bd9",
	        "/usr/bin/dracut-pre-udev"
	);
}
static void svir_1797(void) 
{
	svi_reg(&(tinfoil.validation_items[1796]),
	        "525ef470fe178560424560818ae6f764a2be5c2ec9710ceb9fb9bba2f38c30d25ab29fa645c705db6f00bace9b6de65e8966fe891c59e85343f2a12a495a6f67",
	        "/usr/bin/dracut-pre-trigger"
	);
}
static void svir_1798(void) 
{
	svi_reg(&(tinfoil.validation_items[1797]),
	        "62616f3f0a29b617605e5ad796b0074e60c21dc98d90e85be6b616b380c366d3140031bfef673b4a0d70f5dd1bc7e99bfce01e3a817557c042dcee7ca7ae2f1e",
	        "/usr/bin/dracut-pre-pivot"
	);
}
static void svir_1799(void) 
{
	svi_reg(&(tinfoil.validation_items[1798]),
	        "ae71bd75f29773b64dbbe9902755dee241f93f8516e54bdfc5c689f3174d11e96d5d6f8f41bbe675a40c0c3940fe578084bb8a00e0b3470410f445968dc84f92",
	        "/usr/bin/dracut-pre-mount"
	);
}
static void svir_1800(void) 
{
	svi_reg(&(tinfoil.validation_items[1799]),
	        "002cafe9aa8e6cdb3579a5c36a408ca911ecb3246ae364e088d49365347af227c6884245910ce0e13aad7ca163f568af2e9c4b90ab144d7fc33e8341ac01fed6",
	        "/usr/bin/dracut-mount"
	);
}
static void svir_1801(void) 
{
	svi_reg(&(tinfoil.validation_items[1800]),
	        "ad56deb30e2ee425e153b81ef90b6e1e46e9c813d395c7ba85cb3671d6f34237b5732ac24ff8e8825fc9c3f4e84b5c7d45c9925f7af24b292577656267c8894b",
	        "/usr/bin/dracut-initqueue"
	);
}
static void svir_1802(void) 
{
	svi_reg(&(tinfoil.validation_items[1801]),
	        "8734e2ac401f8e6a2feb1c5f4590a17fb9e8761e239c346096a1c206f1e2c6fb1b7a7cee3d5830991ddc9fd985dadae34d63795e5146215fae618ff40ea53d13",
	        "/usr/bin/dracut-emergency"
	);
}
static void svir_1803(void) 
{
	svi_reg(&(tinfoil.validation_items[1802]),
	        "3a20bc69f74ced6c0d251ba3b8244c0c6d71ff407abe2171c937ae23ad88f1c21f8b4dc92bb3282a8887cfe71e8d021ffe874b734ae3b60781ec76d1469051af",
	        "/usr/bin/dracut-cmdline-ask"
	);
}
static void svir_1804(void) 
{
	svi_reg(&(tinfoil.validation_items[1803]),
	        "a75c88e4c77efd29df71b166a7405406a20ad6df26da520345454c316dfd4b74cbbb265d6eb1cc83c4d364977e1335870d15db67841ccaea2745a4bf7f2a6942",
	        "/usr/bin/dracut-cmdline"
	);
}
static void svir_1805(void) 
{
	svi_reg(&(tinfoil.validation_items[1804]),
	        "e0844dbe6a3b4923c6a8fb7cfafa19c11befc000fe865e187280cdef4ec49a000622887424382e817abb5f45a71e6c6f0363ca779ec8fd27f9b307454219d1a2",
	        "/usr/bin/dmesg"
	);
}
static void svir_1806(void) 
{
	svi_reg(&(tinfoil.validation_items[1805]),
	        "b3af0eaf4c9c5bf91401437d68d960c4b5027488a306a96de3364c12682cd62b8685ab552588c9d398bb48b802a3a630fe7523a760c76950ca61eb3e370244e0",
	        "/usr/bin/dbus-broker-launch"
	);
}
static void svir_1807(void) 
{
	svi_reg(&(tinfoil.validation_items[1806]),
	        "c884aa66cc49792352b6ba8dcddf7570805ff546614bd80e3246ffa045ea17791d6aa099c438a4ba4c26da6006ff513a87fbf00beafee31e6252ac0837dcf32b",
	        "/usr/bin/dbus-broker"
	);
}
static void svir_1808(void) 
{
	svi_reg(&(tinfoil.validation_items[1807]),
	        "3ec49238c55786c2f371032a38aa7926695197c9e1f28248e7a045102c22bf8600d9d793d4ed165e617904b603597754802f217070b73c197dfd37f9a7f740cd",
	        "/usr/bin/cp"
	);
}
static void svir_1809(void) 
{
	svi_reg(&(tinfoil.validation_items[1808]),
	        "b46b1a8194f781f2870ee8bc73af29e7119b6f08373d6f746aa877b6ef8056f4f53fb705ece653c6b0d7972d5a136430356985f95e67029a2267140aa22956eb",
	        "/usr/bin/chown"
	);
}
static void svir_1810(void) 
{
	svi_reg(&(tinfoil.validation_items[1809]),
	        "fee55ec5d985699ec18db0154383925921b7b18f9db99c404c3eb9b809833434c8ac147a34ce59eeb3522ddb65e3302557779a1e8f33a4fc733fd23c4a0b8397",
	        "/usr/bin/chmod"
	);
}
static void svir_1811(void) 
{
	svi_reg(&(tinfoil.validation_items[1810]),
	        "775a5f04e1382bc36c5ba3a6555b62347de39c11aafdbb30ac086c3e40acff04370e07465d3e4ba2d865b2888c66e4184fd560fdcffb0ef4277560f0d057e52b",
	        "/usr/bin/cat"
	);
}
static void svir_1812(void) 
{
	svi_reg(&(tinfoil.validation_items[1811]),
	        "4bf67ee5d0d9b1ac89eebc3b2861693c2454f7ea2c2304703be01982e290fb03710a4261afd20dbe8d859a7d8529a6013a77c661dbfa32464aedf620c04d1575",
	        "/usr/bin/busctl"
	);
}
static void svir_1813(void) 
{
	svi_reg(&(tinfoil.validation_items[1812]),
	        "80a20a3ae25c67f0d450e7684477f2ed862c709d6a84245bf39d3488b80e035c7b6ace048038e76c7f2e9022a3bbcaafc2580e67e35812571019986b9abbaf65",
	        "/usr/bin/bash"
	);
}
static void svir_1814(void) 
{
	svi_reg(&(tinfoil.validation_items[1813]),
	        "1e46c6fabb7bfe425359a5bebc136ab0232ca7d97b1da27face335a02a7f2e726501369bea71ed168380c0f85654f240eaccffa1eb92b01f2aa737a85bad0d4e",
	        "/usr/bin/arping"
	);
}
static void svir_1815(void) 
{
	svi_reg(&(tinfoil.validation_items[1814]),
	        "3fd78329be9db1bf7dcdc74f589182bcbd6a5c098391a65ae05103b586e7a7b8dbdbd32301c0278c814d19a73d687c7c7d19f90174d8ae92a50a850d5c372185",
	        "/shutdown"
	);
}
static void svir_1816(void) 
{
	svi_reg(&(tinfoil.validation_items[1815]),
	        "bbcc8a9903c7a600dcbdd65bc7f6aceac318f37584f34a6f0ebde4ac914b0c435402ec390061b8b97c72b9422ae3bfceee805670f9c75eed9b2ac9fe85ac8bf3",
	        "/etc/virc"
	);
}
static void svir_1817(void) 
{
	svi_reg(&(tinfoil.validation_items[1816]),
	        "4eb1be561a6723501d9103e883e66292123d22a4e0470af30ac5dfe9be3bf71a91f398776b7015c7d9d2cd456cebad29978664169a7bfa229487651e1558b10c",
	        "/etc/vconsole.conf"
	);
}
static void svir_1818(void) 
{
	svi_reg(&(tinfoil.validation_items[1817]),
	        "6dc7d60933afe1aecc2f8dd917586be3de59045237db9d0c550d9354b26ea6848c33f6b64718f0a460838784cc7078748c16e66aa2d51314f9414eb3cc981084",
	        "/etc/udev/udev.conf"
	);
}
static void svir_1819(void) 
{
	svi_reg(&(tinfoil.validation_items[1818]),
	        "830836d4cbd04575c72720c75292c857056edf0716aefdecdd30b58b60b5c63ce3d58a83614836380bbe8d16731cd09fe610ea16c85e5b57d8d7fcc53bc81534",
	        "/etc/udev/rules.d/61-persistent-storage.rules"
	);
}
static void svir_1820(void) 
{
	svi_reg(&(tinfoil.validation_items[1819]),
	        "e9de7c3415723bb1031b78766866c72c1231084699e0cd6c6c1ef493e413ca449653e103e52c1487cd3df53e01084b7ddb706c1ae42d53e46f785b75674b2432",
	        "/etc/udev/rules.d/59-persistent-storage.rules"
	);
}
static void svir_1821(void) 
{
	svi_reg(&(tinfoil.validation_items[1820]),
	        "9625b94aec37520ec29e627bef19bcdf6adfd1a6b69213c3d802d582740642715f6bd4a93839071720e96518f10b6310033f7b70873119cc18fde0d31dc41b49",
	        "/etc/systemd/system.conf"
	);
}
static void svir_1822(void) 
{
	svi_reg(&(tinfoil.validation_items[1821]),
	        "48d9b132b7dfab6b45fce405292614b14a9e3247696eec3cf413d6dab6654b44524604bcfe05fd3e3c697ebbaaae1dc52b394834ffc6a8f705fe7c2ce638f3f2",
	        "/etc/systemd/journald.conf"
	);
}
static void svir_1823(void) 
{
	svi_reg(&(tinfoil.validation_items[1822]),
	        "348f0899cabf170e317d61e1f217f4a8ac93b03ceb69e7e1ebb54eb12b4c5f8fc23ba10a926265495ce3d100fb0f6fa30d925d21c34d57f08f542a174574bcef",
	        "/etc/sysctl.conf"
	);
}
static void svir_1824(void) 
{
	svi_reg(&(tinfoil.validation_items[1823]),
	        "ae3f5c7baeb6d6e20badb550337093dd24d6d0a5d0d946cb0637960a0a8beb93641459e400e618277d497fd0519dff3bab188fd985dd131ea04705bda664a95c",
	        "/etc/shadow"
	);
}
static void svir_1825(void) 
{
	svi_reg(&(tinfoil.validation_items[1824]),
	        "50338e4b3204c0796f85c832762e00af27aa0d5698325b041455a0c6175c63097137544ba2d3c7f42fb695ea34d357ee61d4e49b7aec6ddd78c7305f621b9248",
	        "/etc/plymouth/plymouthd.conf"
	);
}
static void svir_1826(void) 
{
	svi_reg(&(tinfoil.validation_items[1825]),
	        "23d457e590e96382c3b79ff896d7d73b0d0dab8e61deb55650b0d684c00ea55d46e7346e9eb07253afb72ac4b51f93547d75b0dec1b0cf64e1c650b85a033dfb",
	        "/etc/passwd"
	);
}
static void svir_1827(void) 
{
	svi_reg(&(tinfoil.validation_items[1826]),
	        "434abb3e67a4f8dc1c114d58a53314684f493cbedc2b806fe7e311e414eb69b0fc2e229f26c87c0d43bcdd7c2a15129a0ae2fa5efbbde059d47648bdc360f549",
	        "/etc/modprobe.d/vhost.conf"
	);
}
static void svir_1828(void) 
{
	svi_reg(&(tinfoil.validation_items[1827]),
	        "7dd2c52ddf8313e8fe2f557fc0f0d8248035300d1c3d3d65eea38246de14e8669809e1c4f2422ebebab3272bafcb1f7707176f483e7521c07da167a208cff28f",
	        "/etc/modprobe.d/sctp-blacklist.conf"
	);
}
static void svir_1829(void) 
{
	svi_reg(&(tinfoil.validation_items[1828]),
	        "70836364735b983732ca0d9fbaf374107649366829b94afe00d5ac9aacf535d64dffe56ecb3c8d47537aac837f6257108965c19fb0647a818ff5b2fa5c11106e",
	        "/etc/modprobe.d/rose-blacklist.conf"
	);
}
static void svir_1830(void) 
{
	svi_reg(&(tinfoil.validation_items[1829]),
	        "01ab6980694a57ab17629a5fdfcd0da4cd047507455b7729fa72af28281a68425cc0a8ddccaa62644a01c96d822206457d99c320fd40999a9b3926f684fb9840",
	        "/etc/modprobe.d/rds-blacklist.conf"
	);
}
static void svir_1831(void) 
{
	svi_reg(&(tinfoil.validation_items[1830]),
	        "a6e1352f266c7f996b08249dc267ade11251ffe7de5d1be843ae190881c6ffebcc8b18f1b64423a61d2d2de060d2ff8cb8c3076eb86da2f71ebfedfe6057d74a",
	        "/etc/modprobe.d/nvdimm-security.conf"
	);
}
static void svir_1832(void) 
{
	svi_reg(&(tinfoil.validation_items[1831]),
	        "b557918a778454d3d74148b5ea8ecc47785e2b6a426d450528cbe6f752b0f9f03485c9f1c2e1f394e67605e522101a47877298522be4d91c4754c05c9c3e8393",
	        "/etc/modprobe.d/nfc-blacklist.conf"
	);
}
static void svir_1833(void) 
{
	svi_reg(&(tinfoil.validation_items[1832]),
	        "099583f0368617089138a9e5fc32c9ddca990bb1f02539b0036853cf5a2f5e35ceb4f5695bba71d2fbff5966e0f93f5365cd0014e5b02c2a4f31fa2e3be2f8ec",
	        "/etc/modprobe.d/netrom-blacklist.conf"
	);
}
static void svir_1834(void) 
{
	svi_reg(&(tinfoil.validation_items[1833]),
	        "55b4f1a02a3b76b27a9743c28c6f24e993719a5461f956e2f4b58e4cce883b48b6fcf41f9f88929fc19dcb515fb42783fb371fea27b8c37a22f4d245e57d4ecf",
	        "/etc/modprobe.d/lockd.conf"
	);
}
static void svir_1835(void) 
{
	svi_reg(&(tinfoil.validation_items[1834]),
	        "a52a2d09a751a6ef682a9d41ae514785f0b17b40fe84e98163cc61929b02fa86adbf54f2765d30339db7f5e5877f13b6d91f8b38ea6a180545b617d5d97efe58",
	        "/etc/modprobe.d/l2tp_ppp-blacklist.conf"
	);
}
static void svir_1836(void) 
{
	svi_reg(&(tinfoil.validation_items[1835]),
	        "ef62ea9f8af7e5d217e2bd409bbfedb82a8db378f9965efc7aaead952d97da3256f27b4e8c573fa61b96b231c342c85ecdb7f5d76da9378490992a258811faa5",
	        "/etc/modprobe.d/l2tp_netlink-blacklist.conf"
	);
}
static void svir_1837(void) 
{
	svi_reg(&(tinfoil.validation_items[1836]),
	        "1e93345f6323504948a7594f491741f5df035076b5566030f63243056c6a817484e9a3d9182c746b73c8e4c842ff01aecd0448dfedb639198defa8ac6b0560e8",
	        "/etc/modprobe.d/l2tp_ip-blacklist.conf"
	);
}
static void svir_1838(void) 
{
	svi_reg(&(tinfoil.validation_items[1837]),
	        "0ed61dc258ba990b7abf95ca4ff992427c9a720e55290bf6b2b94a621237e4eae99c7f9d5b6cd4d878bbe04e8955f45bde4f712a43f8be3ddee9ac806bd7ed4d",
	        "/etc/modprobe.d/l2tp_eth-blacklist.conf"
	);
}
static void svir_1839(void) 
{
	svi_reg(&(tinfoil.validation_items[1838]),
	        "d73e9bd57beafd555d8de5b03049504ee24d34d385a7db3f89c2ddac2eb7825e5a16e310733a388de0131dcc608a8696298cd780487a0cd6ffc191604b2574c6",
	        "/etc/modprobe.d/kvm.conf"
	);
}
static void svir_1840(void) 
{
	svi_reg(&(tinfoil.validation_items[1839]),
	        "821d8c3f847cfaf5e83b6149cc7c00e969f6ffbf9bb9f85d370ab4f66f2f1bd83d113a76b16bd6cc833304b68ffb6a0002adc94c009c577d2034f8ef8031fa6c",
	        "/etc/modprobe.d/floppy-blacklist.conf"
	);
}
static void svir_1841(void) 
{
	svi_reg(&(tinfoil.validation_items[1840]),
	        "3f367af407fdcaa08be428b9cc79b189f9cda0b22e8f3c5ed0d1f49419ad24c93a67300b824b77fe03a3e49ae2f66147a119b647eebcbc57fb38bc99a6c61dc4",
	        "/etc/modprobe.d/firewalld-sysctls.conf"
	);
}
static void svir_1842(void) 
{
	svi_reg(&(tinfoil.validation_items[1841]),
	        "5578aac6fc2cfb5bab9855aabc9039b0451351b28f8454ac7e12b86df03ab2ba5060c9778874bbcd396afa9c6117634f1826be629a9258a16839a841b0897f4a",
	        "/etc/modprobe.d/batman-adv-blacklist.conf"
	);
}
static void svir_1843(void) 
{
	svi_reg(&(tinfoil.validation_items[1842]),
	        "016025079425db6bd46253425b30efafe2a187bf0b6321d866069402dd5b8fdab6ab327ec2dab892c93b1a5aaf674c1ad18460e844380bf3bf1aaedff3bb1ac4",
	        "/etc/modprobe.d/ax25-blacklist.conf"
	);
}
static void svir_1844(void) 
{
	svi_reg(&(tinfoil.validation_items[1843]),
	        "0288561ce71f325e4568c6afc41a098b8c8cfd5edacb0df21c8a53b08716b5956d4cc2f6b86d18f14aff3f25e8f183720a7fef334ad31ebe8dc38c7cf64c5162",
	        "/etc/modprobe.d/atm-blacklist.conf"
	);
}
static void svir_1845(void) 
{
	svi_reg(&(tinfoil.validation_items[1844]),
	        "696ca74598908c32880fcc51263ee83004a162fd1616c398ca47c92c52df8b870299df77032b88b4034d94bc09c668afce46c520f861492a9c5dc360379f6502",
	        "/etc/modprobe.d/appletalk-blacklist.conf"
	);
}
static void svir_1846(void) 
{
	svi_reg(&(tinfoil.validation_items[1845]),
	        "f1bca615e8fdb8aa91ccc31723ada432efdfffd2c2f1fba63753f061e6a819a1b679b102e40f4908ff42f2c557118f78fbfb1fe9fb60c045d10e2c7844a10e34",
	        "/etc/machine-id"
	);
}
static void svir_1847(void) 
{
	svi_reg(&(tinfoil.validation_items[1846]),
	        "7284c9d025de14476e64ec5ab5d541466350b08e57735813c2e55b61f0bd362cc58e088d0bb93cb4ac7c3c66dfb3d1ba52b398aeb4f46071bf6e51b8194c643c",
	        "/etc/locale.conf"
	);
}
static void svir_1848(void) 
{
	svi_reg(&(tinfoil.validation_items[1847]),
	        "7a597cb449ef5cf8fd6e71e14cb353df05777b59af726766e939f5f542ac3924f845f3b141a70b8a7e0bf01f764b431c60b7b390d9e1c106d77ea3e670493ecb",
	        "/etc/ld.so.conf.d/qt-x86_64.conf"
	);
}
static void svir_1849(void) 
{
	svi_reg(&(tinfoil.validation_items[1848]),
	        "5625c68969e894fbcda65e226c223d8f1f478928af0147429263499b1d0ddac4a07f44e0c263070b12f06d2b9f5b6a8745c3d7253829d52920158bbbc10ee120",
	        "/etc/ld.so.conf.d/pipewire-jack-x86_64.conf"
	);
}
static void svir_1850(void) 
{
	svi_reg(&(tinfoil.validation_items[1849]),
	        "5f4c191f3e37a58e45432b5f2a5dd1e9b3ac4f06846b2d84905fb3b5a01b98be2418bb595a1c82989d150536ad39476a31d2082913dc442f86b5e91b31e06eff",
	        "/etc/ld.so.conf.d/libiscsi-x86_64.conf"
	);
}
static void svir_1851(void) 
{
	svi_reg(&(tinfoil.validation_items[1850]),
	        "69f4ba5d2c4ee30cc15daf2794c0faee3df92e31a22431a5e401785077ad4733648b11b7a8cc00ab2ba4ae2e5b17a4d3fc8611ccf9eafebc77bf8696cb857d04",
	        "/etc/ld.so.conf.d/dyninst-x86_64.conf"
	);
}
static void svir_1852(void) 
{
	svi_reg(&(tinfoil.validation_items[1851]),
	        "1852d09cf0b43eceb0947cbf47cd814052313b2e9e35781e44112b34b7a6f483dc931b2d1102fd7d81f5bb658ce3864111f3df71e3ee98d227c56f214d58e593",
	        "/etc/ld.so.conf"
	);
}
static void svir_1853(void) 
{
	svi_reg(&(tinfoil.validation_items[1852]),
	        "21ecefdeeb15e28b4e0f1fd0f98ce1f7c7a63f069b9583a1235d7c71effa2f485491b19364df80ff149060f5ab7eb9a3d7fecc902051e4cbb9bcb91ee2cb8e4f",
	        "/etc/ld.so.cache"
	);
}
static void svir_1854(void) 
{
	svi_reg(&(tinfoil.validation_items[1853]),
	        "6286e0a5cbc030f7b2d105f594ae0afb9105c92175c6b07ff454734c23cd0bddfed77639fe59b68a70b8c78af27657f611cbe89c27f7a47b978fa9449808c19f",
	        "/etc/hosts"
	);
}
static void svir_1855(void) 
{
	svi_reg(&(tinfoil.validation_items[1854]),
	        "be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09",
	        "/etc/hostname"
	);
}
static void svir_1856(void) 
{
	svi_reg(&(tinfoil.validation_items[1855]),
	        "27169f8c6e606172d2128ba69dc871abfb265bb4a0421fcea9c1b3b009bbc504b0c90c968d35d208bf164b8931b39ef1696c9216bec2b266752c788879ad921c",
	        "/etc/group"
	);
}
static void svir_1857(void) 
{
	svi_reg(&(tinfoil.validation_items[1856]),
	        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	        "/etc/fstab.empty"
	);
}
static void svir_1858(void) 
{
	svi_reg(&(tinfoil.validation_items[1857]),
	        "74539a951f33e2a5e3af3e4652a9554dc6c80aa58d334cc50dafa2ee45f4695103f26c1385b200903ad4b66c3d360dc9ce237a9e9c2a31205b7117752d969949",
	        "/etc/dbus-1/system.d/teamd.conf"
	);
}
static void svir_1859(void) 
{
	svi_reg(&(tinfoil.validation_items[1858]),
	        "380c00dc26cd58b9a153df3bb477446be979984d8416169379cb63fe0744887a4cb8662b8d371af99c80559108120c91276bbb25a10dd6b0504df14c2a3bdd5b",
	        "/etc/dbus-1/system.conf"
	);
}
static void svir_1860(void) 
{
	svi_reg(&(tinfoil.validation_items[1859]),
	        "6072682bd8904a6e561e0cc6e3851810c1bb78ee1e98d137183d0c3c0d531abea87bec7e8c7f56decf76450f646fb27711f3a920bfed7e0adbacd6d04e3f5a05",
	        "/etc/dbus-1/session.conf"
	);
}
static void svir_1861(void) 
{
	svi_reg(&(tinfoil.validation_items[1860]),
	        "451160697d564c406ee7cc11a1b6ef6e6c267f0d48bb2799bfd6df793d94d27b98a96182120b4f49e95e49941e7a1e3aad5418d584c0bd94514eeece1e074424",
	        "/etc/conf.d/systemd.conf"
	);
}
static void svir_1862(void) 
{
	svi_reg(&(tinfoil.validation_items[1861]),
	        "5345e1b889aed4376faf668f90e0b97dda3c1dc6c8907e898cd2f1e6d731b06d990d5c4dc01aa5c2093da366cb88ea454d49145c0e1357f4b08a7a7ee87745ea",
	        "/etc/cmdline.d/00-btrfs.conf"
	);
}
static void svir_1863(void) 
{
	svi_reg(&(tinfoil.validation_items[1862]),
	        "7f50cd82bfb0b70bf514e06edacbbd379951aba51f63c8c0f6398b3e95a9d4948a19119a0496867b188f11b2347e8cb77c2ac8aaa8961728c95a14ed8d62e8ac",
	        "/etc/authselect/nsswitch.conf"
	);
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;


//##########TEMPLATE_PARM_SP##################################################=>	
	int validation_count = 1863;
	svir_1();
	svir_2();
	svir_3();
	svir_4();
	svir_5();
	svir_6();
	svir_7();
	svir_8();
	svir_9();
	svir_10();
	svir_11();
	svir_12();
	svir_13();
	svir_14();
	svir_15();
	svir_16();
	svir_17();
	svir_18();
	svir_19();
	svir_20();
	svir_21();
	svir_22();
	svir_23();
	svir_24();
	svir_25();
	svir_26();
	svir_27();
	svir_28();
	svir_29();
	svir_30();
	svir_31();
	svir_32();
	svir_33();
	svir_34();
	svir_35();
	svir_36();
	svir_37();
	svir_38();
	svir_39();
	svir_40();
	svir_41();
	svir_42();
	svir_43();
	svir_44();
	svir_45();
	svir_46();
	svir_47();
	svir_48();
	svir_49();
	svir_50();
	svir_51();
	svir_52();
	svir_53();
	svir_54();
	svir_55();
	svir_56();
	svir_57();
	svir_58();
	svir_59();
	svir_60();
	svir_61();
	svir_62();
	svir_63();
	svir_64();
	svir_65();
	svir_66();
	svir_67();
	svir_68();
	svir_69();
	svir_70();
	svir_71();
	svir_72();
	svir_73();
	svir_74();
	svir_75();
	svir_76();
	svir_77();
	svir_78();
	svir_79();
	svir_80();
	svir_81();
	svir_82();
	svir_83();
	svir_84();
	svir_85();
	svir_86();
	svir_87();
	svir_88();
	svir_89();
	svir_90();
	svir_91();
	svir_92();
	svir_93();
	svir_94();
	svir_95();
	svir_96();
	svir_97();
	svir_98();
	svir_99();
	svir_100();
	svir_101();
	svir_102();
	svir_103();
	svir_104();
	svir_105();
	svir_106();
	svir_107();
	svir_108();
	svir_109();
	svir_110();
	svir_111();
	svir_112();
	svir_113();
	svir_114();
	svir_115();
	svir_116();
	svir_117();
	svir_118();
	svir_119();
	svir_120();
	svir_121();
	svir_122();
	svir_123();
	svir_124();
	svir_125();
	svir_126();
	svir_127();
	svir_128();
	svir_129();
	svir_130();
	svir_131();
	svir_132();
	svir_133();
	svir_134();
	svir_135();
	svir_136();
	svir_137();
	svir_138();
	svir_139();
	svir_140();
	svir_141();
	svir_142();
	svir_143();
	svir_144();
	svir_145();
	svir_146();
	svir_147();
	svir_148();
	svir_149();
	svir_150();
	svir_151();
	svir_152();
	svir_153();
	svir_154();
	svir_155();
	svir_156();
	svir_157();
	svir_158();
	svir_159();
	svir_160();
	svir_161();
	svir_162();
	svir_163();
	svir_164();
	svir_165();
	svir_166();
	svir_167();
	svir_168();
	svir_169();
	svir_170();
	svir_171();
	svir_172();
	svir_173();
	svir_174();
	svir_175();
	svir_176();
	svir_177();
	svir_178();
	svir_179();
	svir_180();
	svir_181();
	svir_182();
	svir_183();
	svir_184();
	svir_185();
	svir_186();
	svir_187();
	svir_188();
	svir_189();
	svir_190();
	svir_191();
	svir_192();
	svir_193();
	svir_194();
	svir_195();
	svir_196();
	svir_197();
	svir_198();
	svir_199();
	svir_200();
	svir_201();
	svir_202();
	svir_203();
	svir_204();
	svir_205();
	svir_206();
	svir_207();
	svir_208();
	svir_209();
	svir_210();
	svir_211();
	svir_212();
	svir_213();
	svir_214();
	svir_215();
	svir_216();
	svir_217();
	svir_218();
	svir_219();
	svir_220();
	svir_221();
	svir_222();
	svir_223();
	svir_224();
	svir_225();
	svir_226();
	svir_227();
	svir_228();
	svir_229();
	svir_230();
	svir_231();
	svir_232();
	svir_233();
	svir_234();
	svir_235();
	svir_236();
	svir_237();
	svir_238();
	svir_239();
	svir_240();
	svir_241();
	svir_242();
	svir_243();
	svir_244();
	svir_245();
	svir_246();
	svir_247();
	svir_248();
	svir_249();
	svir_250();
	svir_251();
	svir_252();
	svir_253();
	svir_254();
	svir_255();
	svir_256();
	svir_257();
	svir_258();
	svir_259();
	svir_260();
	svir_261();
	svir_262();
	svir_263();
	svir_264();
	svir_265();
	svir_266();
	svir_267();
	svir_268();
	svir_269();
	svir_270();
	svir_271();
	svir_272();
	svir_273();
	svir_274();
	svir_275();
	svir_276();
	svir_277();
	svir_278();
	svir_279();
	svir_280();
	svir_281();
	svir_282();
	svir_283();
	svir_284();
	svir_285();
	svir_286();
	svir_287();
	svir_288();
	svir_289();
	svir_290();
	svir_291();
	svir_292();
	svir_293();
	svir_294();
	svir_295();
	svir_296();
	svir_297();
	svir_298();
	svir_299();
	svir_300();
	svir_301();
	svir_302();
	svir_303();
	svir_304();
	svir_305();
	svir_306();
	svir_307();
	svir_308();
	svir_309();
	svir_310();
	svir_311();
	svir_312();
	svir_313();
	svir_314();
	svir_315();
	svir_316();
	svir_317();
	svir_318();
	svir_319();
	svir_320();
	svir_321();
	svir_322();
	svir_323();
	svir_324();
	svir_325();
	svir_326();
	svir_327();
	svir_328();
	svir_329();
	svir_330();
	svir_331();
	svir_332();
	svir_333();
	svir_334();
	svir_335();
	svir_336();
	svir_337();
	svir_338();
	svir_339();
	svir_340();
	svir_341();
	svir_342();
	svir_343();
	svir_344();
	svir_345();
	svir_346();
	svir_347();
	svir_348();
	svir_349();
	svir_350();
	svir_351();
	svir_352();
	svir_353();
	svir_354();
	svir_355();
	svir_356();
	svir_357();
	svir_358();
	svir_359();
	svir_360();
	svir_361();
	svir_362();
	svir_363();
	svir_364();
	svir_365();
	svir_366();
	svir_367();
	svir_368();
	svir_369();
	svir_370();
	svir_371();
	svir_372();
	svir_373();
	svir_374();
	svir_375();
	svir_376();
	svir_377();
	svir_378();
	svir_379();
	svir_380();
	svir_381();
	svir_382();
	svir_383();
	svir_384();
	svir_385();
	svir_386();
	svir_387();
	svir_388();
	svir_389();
	svir_390();
	svir_391();
	svir_392();
	svir_393();
	svir_394();
	svir_395();
	svir_396();
	svir_397();
	svir_398();
	svir_399();
	svir_400();
	svir_401();
	svir_402();
	svir_403();
	svir_404();
	svir_405();
	svir_406();
	svir_407();
	svir_408();
	svir_409();
	svir_410();
	svir_411();
	svir_412();
	svir_413();
	svir_414();
	svir_415();
	svir_416();
	svir_417();
	svir_418();
	svir_419();
	svir_420();
	svir_421();
	svir_422();
	svir_423();
	svir_424();
	svir_425();
	svir_426();
	svir_427();
	svir_428();
	svir_429();
	svir_430();
	svir_431();
	svir_432();
	svir_433();
	svir_434();
	svir_435();
	svir_436();
	svir_437();
	svir_438();
	svir_439();
	svir_440();
	svir_441();
	svir_442();
	svir_443();
	svir_444();
	svir_445();
	svir_446();
	svir_447();
	svir_448();
	svir_449();
	svir_450();
	svir_451();
	svir_452();
	svir_453();
	svir_454();
	svir_455();
	svir_456();
	svir_457();
	svir_458();
	svir_459();
	svir_460();
	svir_461();
	svir_462();
	svir_463();
	svir_464();
	svir_465();
	svir_466();
	svir_467();
	svir_468();
	svir_469();
	svir_470();
	svir_471();
	svir_472();
	svir_473();
	svir_474();
	svir_475();
	svir_476();
	svir_477();
	svir_478();
	svir_479();
	svir_480();
	svir_481();
	svir_482();
	svir_483();
	svir_484();
	svir_485();
	svir_486();
	svir_487();
	svir_488();
	svir_489();
	svir_490();
	svir_491();
	svir_492();
	svir_493();
	svir_494();
	svir_495();
	svir_496();
	svir_497();
	svir_498();
	svir_499();
	svir_500();
	svir_501();
	svir_502();
	svir_503();
	svir_504();
	svir_505();
	svir_506();
	svir_507();
	svir_508();
	svir_509();
	svir_510();
	svir_511();
	svir_512();
	svir_513();
	svir_514();
	svir_515();
	svir_516();
	svir_517();
	svir_518();
	svir_519();
	svir_520();
	svir_521();
	svir_522();
	svir_523();
	svir_524();
	svir_525();
	svir_526();
	svir_527();
	svir_528();
	svir_529();
	svir_530();
	svir_531();
	svir_532();
	svir_533();
	svir_534();
	svir_535();
	svir_536();
	svir_537();
	svir_538();
	svir_539();
	svir_540();
	svir_541();
	svir_542();
	svir_543();
	svir_544();
	svir_545();
	svir_546();
	svir_547();
	svir_548();
	svir_549();
	svir_550();
	svir_551();
	svir_552();
	svir_553();
	svir_554();
	svir_555();
	svir_556();
	svir_557();
	svir_558();
	svir_559();
	svir_560();
	svir_561();
	svir_562();
	svir_563();
	svir_564();
	svir_565();
	svir_566();
	svir_567();
	svir_568();
	svir_569();
	svir_570();
	svir_571();
	svir_572();
	svir_573();
	svir_574();
	svir_575();
	svir_576();
	svir_577();
	svir_578();
	svir_579();
	svir_580();
	svir_581();
	svir_582();
	svir_583();
	svir_584();
	svir_585();
	svir_586();
	svir_587();
	svir_588();
	svir_589();
	svir_590();
	svir_591();
	svir_592();
	svir_593();
	svir_594();
	svir_595();
	svir_596();
	svir_597();
	svir_598();
	svir_599();
	svir_600();
	svir_601();
	svir_602();
	svir_603();
	svir_604();
	svir_605();
	svir_606();
	svir_607();
	svir_608();
	svir_609();
	svir_610();
	svir_611();
	svir_612();
	svir_613();
	svir_614();
	svir_615();
	svir_616();
	svir_617();
	svir_618();
	svir_619();
	svir_620();
	svir_621();
	svir_622();
	svir_623();
	svir_624();
	svir_625();
	svir_626();
	svir_627();
	svir_628();
	svir_629();
	svir_630();
	svir_631();
	svir_632();
	svir_633();
	svir_634();
	svir_635();
	svir_636();
	svir_637();
	svir_638();
	svir_639();
	svir_640();
	svir_641();
	svir_642();
	svir_643();
	svir_644();
	svir_645();
	svir_646();
	svir_647();
	svir_648();
	svir_649();
	svir_650();
	svir_651();
	svir_652();
	svir_653();
	svir_654();
	svir_655();
	svir_656();
	svir_657();
	svir_658();
	svir_659();
	svir_660();
	svir_661();
	svir_662();
	svir_663();
	svir_664();
	svir_665();
	svir_666();
	svir_667();
	svir_668();
	svir_669();
	svir_670();
	svir_671();
	svir_672();
	svir_673();
	svir_674();
	svir_675();
	svir_676();
	svir_677();
	svir_678();
	svir_679();
	svir_680();
	svir_681();
	svir_682();
	svir_683();
	svir_684();
	svir_685();
	svir_686();
	svir_687();
	svir_688();
	svir_689();
	svir_690();
	svir_691();
	svir_692();
	svir_693();
	svir_694();
	svir_695();
	svir_696();
	svir_697();
	svir_698();
	svir_699();
	svir_700();
	svir_701();
	svir_702();
	svir_703();
	svir_704();
	svir_705();
	svir_706();
	svir_707();
	svir_708();
	svir_709();
	svir_710();
	svir_711();
	svir_712();
	svir_713();
	svir_714();
	svir_715();
	svir_716();
	svir_717();
	svir_718();
	svir_719();
	svir_720();
	svir_721();
	svir_722();
	svir_723();
	svir_724();
	svir_725();
	svir_726();
	svir_727();
	svir_728();
	svir_729();
	svir_730();
	svir_731();
	svir_732();
	svir_733();
	svir_734();
	svir_735();
	svir_736();
	svir_737();
	svir_738();
	svir_739();
	svir_740();
	svir_741();
	svir_742();
	svir_743();
	svir_744();
	svir_745();
	svir_746();
	svir_747();
	svir_748();
	svir_749();
	svir_750();
	svir_751();
	svir_752();
	svir_753();
	svir_754();
	svir_755();
	svir_756();
	svir_757();
	svir_758();
	svir_759();
	svir_760();
	svir_761();
	svir_762();
	svir_763();
	svir_764();
	svir_765();
	svir_766();
	svir_767();
	svir_768();
	svir_769();
	svir_770();
	svir_771();
	svir_772();
	svir_773();
	svir_774();
	svir_775();
	svir_776();
	svir_777();
	svir_778();
	svir_779();
	svir_780();
	svir_781();
	svir_782();
	svir_783();
	svir_784();
	svir_785();
	svir_786();
	svir_787();
	svir_788();
	svir_789();
	svir_790();
	svir_791();
	svir_792();
	svir_793();
	svir_794();
	svir_795();
	svir_796();
	svir_797();
	svir_798();
	svir_799();
	svir_800();
	svir_801();
	svir_802();
	svir_803();
	svir_804();
	svir_805();
	svir_806();
	svir_807();
	svir_808();
	svir_809();
	svir_810();
	svir_811();
	svir_812();
	svir_813();
	svir_814();
	svir_815();
	svir_816();
	svir_817();
	svir_818();
	svir_819();
	svir_820();
	svir_821();
	svir_822();
	svir_823();
	svir_824();
	svir_825();
	svir_826();
	svir_827();
	svir_828();
	svir_829();
	svir_830();
	svir_831();
	svir_832();
	svir_833();
	svir_834();
	svir_835();
	svir_836();
	svir_837();
	svir_838();
	svir_839();
	svir_840();
	svir_841();
	svir_842();
	svir_843();
	svir_844();
	svir_845();
	svir_846();
	svir_847();
	svir_848();
	svir_849();
	svir_850();
	svir_851();
	svir_852();
	svir_853();
	svir_854();
	svir_855();
	svir_856();
	svir_857();
	svir_858();
	svir_859();
	svir_860();
	svir_861();
	svir_862();
	svir_863();
	svir_864();
	svir_865();
	svir_866();
	svir_867();
	svir_868();
	svir_869();
	svir_870();
	svir_871();
	svir_872();
	svir_873();
	svir_874();
	svir_875();
	svir_876();
	svir_877();
	svir_878();
	svir_879();
	svir_880();
	svir_881();
	svir_882();
	svir_883();
	svir_884();
	svir_885();
	svir_886();
	svir_887();
	svir_888();
	svir_889();
	svir_890();
	svir_891();
	svir_892();
	svir_893();
	svir_894();
	svir_895();
	svir_896();
	svir_897();
	svir_898();
	svir_899();
	svir_900();
	svir_901();
	svir_902();
	svir_903();
	svir_904();
	svir_905();
	svir_906();
	svir_907();
	svir_908();
	svir_909();
	svir_910();
	svir_911();
	svir_912();
	svir_913();
	svir_914();
	svir_915();
	svir_916();
	svir_917();
	svir_918();
	svir_919();
	svir_920();
	svir_921();
	svir_922();
	svir_923();
	svir_924();
	svir_925();
	svir_926();
	svir_927();
	svir_928();
	svir_929();
	svir_930();
	svir_931();
	svir_932();
	svir_933();
	svir_934();
	svir_935();
	svir_936();
	svir_937();
	svir_938();
	svir_939();
	svir_940();
	svir_941();
	svir_942();
	svir_943();
	svir_944();
	svir_945();
	svir_946();
	svir_947();
	svir_948();
	svir_949();
	svir_950();
	svir_951();
	svir_952();
	svir_953();
	svir_954();
	svir_955();
	svir_956();
	svir_957();
	svir_958();
	svir_959();
	svir_960();
	svir_961();
	svir_962();
	svir_963();
	svir_964();
	svir_965();
	svir_966();
	svir_967();
	svir_968();
	svir_969();
	svir_970();
	svir_971();
	svir_972();
	svir_973();
	svir_974();
	svir_975();
	svir_976();
	svir_977();
	svir_978();
	svir_979();
	svir_980();
	svir_981();
	svir_982();
	svir_983();
	svir_984();
	svir_985();
	svir_986();
	svir_987();
	svir_988();
	svir_989();
	svir_990();
	svir_991();
	svir_992();
	svir_993();
	svir_994();
	svir_995();
	svir_996();
	svir_997();
	svir_998();
	svir_999();
	svir_1000();
	svir_1001();
	svir_1002();
	svir_1003();
	svir_1004();
	svir_1005();
	svir_1006();
	svir_1007();
	svir_1008();
	svir_1009();
	svir_1010();
	svir_1011();
	svir_1012();
	svir_1013();
	svir_1014();
	svir_1015();
	svir_1016();
	svir_1017();
	svir_1018();
	svir_1019();
	svir_1020();
	svir_1021();
	svir_1022();
	svir_1023();
	svir_1024();
	svir_1025();
	svir_1026();
	svir_1027();
	svir_1028();
	svir_1029();
	svir_1030();
	svir_1031();
	svir_1032();
	svir_1033();
	svir_1034();
	svir_1035();
	svir_1036();
	svir_1037();
	svir_1038();
	svir_1039();
	svir_1040();
	svir_1041();
	svir_1042();
	svir_1043();
	svir_1044();
	svir_1045();
	svir_1046();
	svir_1047();
	svir_1048();
	svir_1049();
	svir_1050();
	svir_1051();
	svir_1052();
	svir_1053();
	svir_1054();
	svir_1055();
	svir_1056();
	svir_1057();
	svir_1058();
	svir_1059();
	svir_1060();
	svir_1061();
	svir_1062();
	svir_1063();
	svir_1064();
	svir_1065();
	svir_1066();
	svir_1067();
	svir_1068();
	svir_1069();
	svir_1070();
	svir_1071();
	svir_1072();
	svir_1073();
	svir_1074();
	svir_1075();
	svir_1076();
	svir_1077();
	svir_1078();
	svir_1079();
	svir_1080();
	svir_1081();
	svir_1082();
	svir_1083();
	svir_1084();
	svir_1085();
	svir_1086();
	svir_1087();
	svir_1088();
	svir_1089();
	svir_1090();
	svir_1091();
	svir_1092();
	svir_1093();
	svir_1094();
	svir_1095();
	svir_1096();
	svir_1097();
	svir_1098();
	svir_1099();
	svir_1100();
	svir_1101();
	svir_1102();
	svir_1103();
	svir_1104();
	svir_1105();
	svir_1106();
	svir_1107();
	svir_1108();
	svir_1109();
	svir_1110();
	svir_1111();
	svir_1112();
	svir_1113();
	svir_1114();
	svir_1115();
	svir_1116();
	svir_1117();
	svir_1118();
	svir_1119();
	svir_1120();
	svir_1121();
	svir_1122();
	svir_1123();
	svir_1124();
	svir_1125();
	svir_1126();
	svir_1127();
	svir_1128();
	svir_1129();
	svir_1130();
	svir_1131();
	svir_1132();
	svir_1133();
	svir_1134();
	svir_1135();
	svir_1136();
	svir_1137();
	svir_1138();
	svir_1139();
	svir_1140();
	svir_1141();
	svir_1142();
	svir_1143();
	svir_1144();
	svir_1145();
	svir_1146();
	svir_1147();
	svir_1148();
	svir_1149();
	svir_1150();
	svir_1151();
	svir_1152();
	svir_1153();
	svir_1154();
	svir_1155();
	svir_1156();
	svir_1157();
	svir_1158();
	svir_1159();
	svir_1160();
	svir_1161();
	svir_1162();
	svir_1163();
	svir_1164();
	svir_1165();
	svir_1166();
	svir_1167();
	svir_1168();
	svir_1169();
	svir_1170();
	svir_1171();
	svir_1172();
	svir_1173();
	svir_1174();
	svir_1175();
	svir_1176();
	svir_1177();
	svir_1178();
	svir_1179();
	svir_1180();
	svir_1181();
	svir_1182();
	svir_1183();
	svir_1184();
	svir_1185();
	svir_1186();
	svir_1187();
	svir_1188();
	svir_1189();
	svir_1190();
	svir_1191();
	svir_1192();
	svir_1193();
	svir_1194();
	svir_1195();
	svir_1196();
	svir_1197();
	svir_1198();
	svir_1199();
	svir_1200();
	svir_1201();
	svir_1202();
	svir_1203();
	svir_1204();
	svir_1205();
	svir_1206();
	svir_1207();
	svir_1208();
	svir_1209();
	svir_1210();
	svir_1211();
	svir_1212();
	svir_1213();
	svir_1214();
	svir_1215();
	svir_1216();
	svir_1217();
	svir_1218();
	svir_1219();
	svir_1220();
	svir_1221();
	svir_1222();
	svir_1223();
	svir_1224();
	svir_1225();
	svir_1226();
	svir_1227();
	svir_1228();
	svir_1229();
	svir_1230();
	svir_1231();
	svir_1232();
	svir_1233();
	svir_1234();
	svir_1235();
	svir_1236();
	svir_1237();
	svir_1238();
	svir_1239();
	svir_1240();
	svir_1241();
	svir_1242();
	svir_1243();
	svir_1244();
	svir_1245();
	svir_1246();
	svir_1247();
	svir_1248();
	svir_1249();
	svir_1250();
	svir_1251();
	svir_1252();
	svir_1253();
	svir_1254();
	svir_1255();
	svir_1256();
	svir_1257();
	svir_1258();
	svir_1259();
	svir_1260();
	svir_1261();
	svir_1262();
	svir_1263();
	svir_1264();
	svir_1265();
	svir_1266();
	svir_1267();
	svir_1268();
	svir_1269();
	svir_1270();
	svir_1271();
	svir_1272();
	svir_1273();
	svir_1274();
	svir_1275();
	svir_1276();
	svir_1277();
	svir_1278();
	svir_1279();
	svir_1280();
	svir_1281();
	svir_1282();
	svir_1283();
	svir_1284();
	svir_1285();
	svir_1286();
	svir_1287();
	svir_1288();
	svir_1289();
	svir_1290();
	svir_1291();
	svir_1292();
	svir_1293();
	svir_1294();
	svir_1295();
	svir_1296();
	svir_1297();
	svir_1298();
	svir_1299();
	svir_1300();
	svir_1301();
	svir_1302();
	svir_1303();
	svir_1304();
	svir_1305();
	svir_1306();
	svir_1307();
	svir_1308();
	svir_1309();
	svir_1310();
	svir_1311();
	svir_1312();
	svir_1313();
	svir_1314();
	svir_1315();
	svir_1316();
	svir_1317();
	svir_1318();
	svir_1319();
	svir_1320();
	svir_1321();
	svir_1322();
	svir_1323();
	svir_1324();
	svir_1325();
	svir_1326();
	svir_1327();
	svir_1328();
	svir_1329();
	svir_1330();
	svir_1331();
	svir_1332();
	svir_1333();
	svir_1334();
	svir_1335();
	svir_1336();
	svir_1337();
	svir_1338();
	svir_1339();
	svir_1340();
	svir_1341();
	svir_1342();
	svir_1343();
	svir_1344();
	svir_1345();
	svir_1346();
	svir_1347();
	svir_1348();
	svir_1349();
	svir_1350();
	svir_1351();
	svir_1352();
	svir_1353();
	svir_1354();
	svir_1355();
	svir_1356();
	svir_1357();
	svir_1358();
	svir_1359();
	svir_1360();
	svir_1361();
	svir_1362();
	svir_1363();
	svir_1364();
	svir_1365();
	svir_1366();
	svir_1367();
	svir_1368();
	svir_1369();
	svir_1370();
	svir_1371();
	svir_1372();
	svir_1373();
	svir_1374();
	svir_1375();
	svir_1376();
	svir_1377();
	svir_1378();
	svir_1379();
	svir_1380();
	svir_1381();
	svir_1382();
	svir_1383();
	svir_1384();
	svir_1385();
	svir_1386();
	svir_1387();
	svir_1388();
	svir_1389();
	svir_1390();
	svir_1391();
	svir_1392();
	svir_1393();
	svir_1394();
	svir_1395();
	svir_1396();
	svir_1397();
	svir_1398();
	svir_1399();
	svir_1400();
	svir_1401();
	svir_1402();
	svir_1403();
	svir_1404();
	svir_1405();
	svir_1406();
	svir_1407();
	svir_1408();
	svir_1409();
	svir_1410();
	svir_1411();
	svir_1412();
	svir_1413();
	svir_1414();
	svir_1415();
	svir_1416();
	svir_1417();
	svir_1418();
	svir_1419();
	svir_1420();
	svir_1421();
	svir_1422();
	svir_1423();
	svir_1424();
	svir_1425();
	svir_1426();
	svir_1427();
	svir_1428();
	svir_1429();
	svir_1430();
	svir_1431();
	svir_1432();
	svir_1433();
	svir_1434();
	svir_1435();
	svir_1436();
	svir_1437();
	svir_1438();
	svir_1439();
	svir_1440();
	svir_1441();
	svir_1442();
	svir_1443();
	svir_1444();
	svir_1445();
	svir_1446();
	svir_1447();
	svir_1448();
	svir_1449();
	svir_1450();
	svir_1451();
	svir_1452();
	svir_1453();
	svir_1454();
	svir_1455();
	svir_1456();
	svir_1457();
	svir_1458();
	svir_1459();
	svir_1460();
	svir_1461();
	svir_1462();
	svir_1463();
	svir_1464();
	svir_1465();
	svir_1466();
	svir_1467();
	svir_1468();
	svir_1469();
	svir_1470();
	svir_1471();
	svir_1472();
	svir_1473();
	svir_1474();
	svir_1475();
	svir_1476();
	svir_1477();
	svir_1478();
	svir_1479();
	svir_1480();
	svir_1481();
	svir_1482();
	svir_1483();
	svir_1484();
	svir_1485();
	svir_1486();
	svir_1487();
	svir_1488();
	svir_1489();
	svir_1490();
	svir_1491();
	svir_1492();
	svir_1493();
	svir_1494();
	svir_1495();
	svir_1496();
	svir_1497();
	svir_1498();
	svir_1499();
	svir_1500();
	svir_1501();
	svir_1502();
	svir_1503();
	svir_1504();
	svir_1505();
	svir_1506();
	svir_1507();
	svir_1508();
	svir_1509();
	svir_1510();
	svir_1511();
	svir_1512();
	svir_1513();
	svir_1514();
	svir_1515();
	svir_1516();
	svir_1517();
	svir_1518();
	svir_1519();
	svir_1520();
	svir_1521();
	svir_1522();
	svir_1523();
	svir_1524();
	svir_1525();
	svir_1526();
	svir_1527();
	svir_1528();
	svir_1529();
	svir_1530();
	svir_1531();
	svir_1532();
	svir_1533();
	svir_1534();
	svir_1535();
	svir_1536();
	svir_1537();
	svir_1538();
	svir_1539();
	svir_1540();
	svir_1541();
	svir_1542();
	svir_1543();
	svir_1544();
	svir_1545();
	svir_1546();
	svir_1547();
	svir_1548();
	svir_1549();
	svir_1550();
	svir_1551();
	svir_1552();
	svir_1553();
	svir_1554();
	svir_1555();
	svir_1556();
	svir_1557();
	svir_1558();
	svir_1559();
	svir_1560();
	svir_1561();
	svir_1562();
	svir_1563();
	svir_1564();
	svir_1565();
	svir_1566();
	svir_1567();
	svir_1568();
	svir_1569();
	svir_1570();
	svir_1571();
	svir_1572();
	svir_1573();
	svir_1574();
	svir_1575();
	svir_1576();
	svir_1577();
	svir_1578();
	svir_1579();
	svir_1580();
	svir_1581();
	svir_1582();
	svir_1583();
	svir_1584();
	svir_1585();
	svir_1586();
	svir_1587();
	svir_1588();
	svir_1589();
	svir_1590();
	svir_1591();
	svir_1592();
	svir_1593();
	svir_1594();
	svir_1595();
	svir_1596();
	svir_1597();
	svir_1598();
	svir_1599();
	svir_1600();
	svir_1601();
	svir_1602();
	svir_1603();
	svir_1604();
	svir_1605();
	svir_1606();
	svir_1607();
	svir_1608();
	svir_1609();
	svir_1610();
	svir_1611();
	svir_1612();
	svir_1613();
	svir_1614();
	svir_1615();
	svir_1616();
	svir_1617();
	svir_1618();
	svir_1619();
	svir_1620();
	svir_1621();
	svir_1622();
	svir_1623();
	svir_1624();
	svir_1625();
	svir_1626();
	svir_1627();
	svir_1628();
	svir_1629();
	svir_1630();
	svir_1631();
	svir_1632();
	svir_1633();
	svir_1634();
	svir_1635();
	svir_1636();
	svir_1637();
	svir_1638();
	svir_1639();
	svir_1640();
	svir_1641();
	svir_1642();
	svir_1643();
	svir_1644();
	svir_1645();
	svir_1646();
	svir_1647();
	svir_1648();
	svir_1649();
	svir_1650();
	svir_1651();
	svir_1652();
	svir_1653();
	svir_1654();
	svir_1655();
	svir_1656();
	svir_1657();
	svir_1658();
	svir_1659();
	svir_1660();
	svir_1661();
	svir_1662();
	svir_1663();
	svir_1664();
	svir_1665();
	svir_1666();
	svir_1667();
	svir_1668();
	svir_1669();
	svir_1670();
	svir_1671();
	svir_1672();
	svir_1673();
	svir_1674();
	svir_1675();
	svir_1676();
	svir_1677();
	svir_1678();
	svir_1679();
	svir_1680();
	svir_1681();
	svir_1682();
	svir_1683();
	svir_1684();
	svir_1685();
	svir_1686();
	svir_1687();
	svir_1688();
	svir_1689();
	svir_1690();
	svir_1691();
	svir_1692();
	svir_1693();
	svir_1694();
	svir_1695();
	svir_1696();
	svir_1697();
	svir_1698();
	svir_1699();
	svir_1700();
	svir_1701();
	svir_1702();
	svir_1703();
	svir_1704();
	svir_1705();
	svir_1706();
	svir_1707();
	svir_1708();
	svir_1709();
	svir_1710();
	svir_1711();
	svir_1712();
	svir_1713();
	svir_1714();
	svir_1715();
	svir_1716();
	svir_1717();
	svir_1718();
	svir_1719();
	svir_1720();
	svir_1721();
	svir_1722();
	svir_1723();
	svir_1724();
	svir_1725();
	svir_1726();
	svir_1727();
	svir_1728();
	svir_1729();
	svir_1730();
	svir_1731();
	svir_1732();
	svir_1733();
	svir_1734();
	svir_1735();
	svir_1736();
	svir_1737();
	svir_1738();
	svir_1739();
	svir_1740();
	svir_1741();
	svir_1742();
	svir_1743();
	svir_1744();
	svir_1745();
	svir_1746();
	svir_1747();
	svir_1748();
	svir_1749();
	svir_1750();
	svir_1751();
	svir_1752();
	svir_1753();
	svir_1754();
	svir_1755();
	svir_1756();
	svir_1757();
	svir_1758();
	svir_1759();
	svir_1760();
	svir_1761();
	svir_1762();
	svir_1763();
	svir_1764();
	svir_1765();
	svir_1766();
	svir_1767();
	svir_1768();
	svir_1769();
	svir_1770();
	svir_1771();
	svir_1772();
	svir_1773();
	svir_1774();
	svir_1775();
	svir_1776();
	svir_1777();
	svir_1778();
	svir_1779();
	svir_1780();
	svir_1781();
	svir_1782();
	svir_1783();
	svir_1784();
	svir_1785();
	svir_1786();
	svir_1787();
	svir_1788();
	svir_1789();
	svir_1790();
	svir_1791();
	svir_1792();
	svir_1793();
	svir_1794();
	svir_1795();
	svir_1796();
	svir_1797();
	svir_1798();
	svir_1799();
	svir_1800();
	svir_1801();
	svir_1802();
	svir_1803();
	svir_1804();
	svir_1805();
	svir_1806();
	svir_1807();
	svir_1808();
	svir_1809();
	svir_1810();
	svir_1811();
	svir_1812();
	svir_1813();
	svir_1814();
	svir_1815();
	svir_1816();
	svir_1817();
	svir_1818();
	svir_1819();
	svir_1820();
	svir_1821();
	svir_1822();
	svir_1823();
	svir_1824();
	svir_1825();
	svir_1826();
	svir_1827();
	svir_1828();
	svir_1829();
	svir_1830();
	svir_1831();
	svir_1832();
	svir_1833();
	svir_1834();
	svir_1835();
	svir_1836();
	svir_1837();
	svir_1838();
	svir_1839();
	svir_1840();
	svir_1841();
	svir_1842();
	svir_1843();
	svir_1844();
	svir_1845();
	svir_1846();
	svir_1847();
	svir_1848();
	svir_1849();
	svir_1850();
	svir_1851();
	svir_1852();
	svir_1853();
	svir_1854();
	svir_1855();
	svir_1856();
	svir_1857();
	svir_1858();
	svir_1859();
	svir_1860();
	svir_1861();
	svir_1862();
	svir_1863();
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	for (j = 0; j < validation_count; j++) {
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
	if (tinfoil.failures > 0) {
		GLOW
	}
}

// init
static int slowboot_mod_init(void)
{
	if (mode == 0)
		mode = SLWBT_MODE_REG;
		
	printk(KERN_INFO "Beginning SlowBoot with mode=%u\n", mode);
	
	tinfoil.failures = 0;
	tinfoil.st = NULL;
	tinfoil.st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil.st)
		return -ENOMEM; // CHECK
	
	switch (mode) {
	case SLWBT_MODE_REG:
		slowboot_run_test();
		break;
	default:
		break;
	}
	kfree(tinfoil.st);
	return 0;
}

// exit

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
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
	struct file *file = filp_open("/dev/console", O_RDWR, 0);

	if (IS_ERR(file)) {
		pr_err("Warning: unable to open an initial console.\n");
		return;
	}
	init_dup(file);
	init_dup(file);
	init_dup(file);
	fput(file);
}

static noinline void __init kernel_init_freeable(void)
{
	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = get_pid(task_pid(current));

	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

	rcu_init_tasks_generic();
	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	padata_init();
	page_alloc_init_late();
	/* Initialize page ext after all struct pages are initialized. */
	page_ext_init();

	do_basic_setup();

	kunit_run_all_tests();

	wait_for_initramfs();
	console_on_rootfs();

	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	if (init_eaccess(ramdisk_execute_command) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 */

	integrity_load_keys();
}
