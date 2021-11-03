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

//DING DONG
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

#define SLWBT_CT 555

#ifndef SLWBT_CT
#define SLWBT_CT 0
#endif

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

typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item *validation_items;
	int failures;
} slowboot_tinfoil;



static u32 mode;
static slowboot_tinfoil tinfoil;
static slowboot_validation_item tinfoil_items[] = {
{
	.path="/usr/sbin/swapoff",
	.hash="0bfb28fbeacce74902a92234b6ce38e911923986a76468d0a7ebaaa66b6f144e43b143819c46b467b97383768c8e15ea1e09a305ae9d347c0f14936327de9815"
},
{
	.path="/usr/sbin/sulogin",
	.hash="727123f197e62f4397c928cf3f7feea2cad47515a6a73e1af965a7166a4529c02e8588f985db59b4cbfcebec1b87897840e287da4b520f60c870cd678da8a62d"
},
{
	.path="/usr/sbin/rdsosreport",
	.hash="1dbf433d6b5ea6250e085f2ce22a44eae9f9de24234867a5885e148fbf1899d88f94635dbd807d43e3cd7fcf978aae33d1f666e922867229087a35ef31b36166"
},
{
	.path="/usr/sbin/plymouthd",
	.hash="cc7d3ea6bff118e4f781e7cc98160323a81d96f06fe0501cb0425e7d7d1e9c2fde18dcc61f6775685be5ec5680ca5988fb81f51c30abe6ffe42bc4e6ed1735eb"
},
{
	.path="/usr/sbin/plymouth-set-default-theme",
	.hash="b637db5ca66c2b80427d5fdc73ee276fc811bcee3033124163487e606c5d72590e7d53a8f0d88d154a3cb77fdd2bba077e3dc69045e72de9ca53ddf53b5105f0"
},
{
	.path="/usr/sbin/nologin",
	.hash="86e7877f8065db1e3e85ecad559ccf7dc15c00006fd27f9eb30e0a892f7401be7bbe4113452e3e5bbe912fcd4e15fc4e6c2d564f1625a967497179da1453c6d6"
},
{
	.path="/usr/sbin/netroot",
	.hash="2e6608d88c1c457a636a8e74e000e90699ebb2b4dcf86a2d31b8c36c3f47e7e761c49f42328bdbe7747a779d4728edacb4f0c6d64e7f1dbccbca4f669bd5019d"
},
{
	.path="/usr/sbin/losetup",
	.hash="ff4f5364ac4a67de88d3988675eef8c35d7a6199a68a76e84e6e1b7a1d16f94822216f7ce5b088555537186fcbf549022a293f8dbd4401a745b9c913f0c93d3d"
},
{
	.path="/usr/sbin/loginit",
	.hash="eef9b1a8ee72c4094d8575aaba8c7cab58b31f08839615268446dd4b8b9edf3b51c12800bbfe6d8c00d8296264dda12d3946075fe3f3f1463845eaa70ff1e926"
},
{
	.path="/usr/sbin/kexec",
	.hash="fe59361e7ee38ec831c1878e73cd2f5e1f172a4f19c543e6f337d31934753189b91ce37852c385bc10c7adf19125aff65744f061f3acb5f9f4321563aceb1039"
},
{
	.path="/usr/sbin/ip",
	.hash="0aaa85942f9d493d00b6066678a068839f79d445bca57f821c88e90cb9569cea0f2bbd58f4af5eebf211ea6cd26bdceb8ee978b4251632342c93faa73e3dfc0f"
},
{
	.path="/usr/sbin/insmodpost.sh",
	.hash="b2084eec74016bb1edac98ca78d9ee99255d9d95d3f860d702a929d9651ac4388af4107f44520cff757c153dae774219b8a43a2db271d8fbe8a6e1492bc9922b"
},
{
	.path="/usr/sbin/initqueue",
	.hash="23f60be049539c63a5b008f5f6b1572d3176c4d5c61b8cc43cd34d38f2567e7593c07a638c2b618d26868606e8314504a8e03f1a53a3e6ecf04fc8a904f0dddb"
},
{
	.path="/usr/sbin/fsck.fat",
	.hash="26b1c82026591a4737afbcf9057c5976344b89356b5bb6285da4cb72e4c62472e19e188e1c6e7a71fb40c081428752008b31883528e1b4056d7c53d2e72b093b"
},
{
	.path="/usr/sbin/e2fsck",
	.hash="7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63"
},
{
	.path="/usr/sbin/fsck.ext4",
	.hash="7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63"
},
{
	.path="/usr/sbin/fsck.btrfs",
	.hash="c4ae2fd25c6619cc5c2f63ee5e9b94cd1ff8a3fe239f1df7fc84e4ede6b506fde673eb8c3fb7c287e8c2775f7ed1806f4984ac54a71187c8d66c72f3304e2404"
},
{
	.path="/usr/sbin/fsck",
	.hash="c3ea684a8031727c58d5de6b99d460848df480b2e823351d124e7775f0ffa87ceac3970e835064d2a764b37e0e6f59614b240287e4a22dd1930c53e1c0fa0d05"
},
{
	.path="/usr/sbin/dhclient",
	.hash="a1ad5646e9a645dcbbbd9d214a513c8f91a34a828f2c1b0fed756673ddce71a20f236838b0362e6b7b2100bf46470aaa7ab4b662341d663b22387e9d18ed8f54"
},
{
	.path="/usr/sbin/chroot",
	.hash="abe8d08a84d0487bf202006042f4ff706637e499d7b0f0bf6f06a20347607ae45be5f871fe1e561c522e98a97fc7fbdd599f7a595225cedc4cec94682b1603b3"
},
{
	.path="/usr/sbin/btrfs",
	.hash="bade5883b38d9340eec437adf5450e5f867c4ffc0cdb21a04ec200a46ef1b26ae746e6b954ebde4d063b91de5ba84bdd79bbb2f1aa2cce2dcd20b492965461fb"
},
{
	.path="/usr/sbin/blkid",
	.hash="1c5f9b600d70e169ddb59fa47886ec40f320faa7ef6e919b689af408c925067dc94fa7c77deedc89eda95d8cd5e1e2e744fb09968f6cd156faa627e3bb8b7580"
},
{
	.path="/usr/sbin/NetworkManager",
	.hash="1b455ef04b9e5264e70bb7bb1dd44d4a67404af48ac7ae8b6550e2fc6053de2c331a0a720aad06d0753dccae1709f100ac888eaa6902354d39aa520abc2bd557"
},
{
	.path="/usr/libexec/plymouth/plymouthd-drm-escrow",
	.hash="45714246af66f045609dc5f71d0f7e1aa7b2f693d02680b09903ad115b77771702c47cc8d4da63f68de92dcb79f04c3ac78dd8265c034a5fc4961474915a1bd5"
},
{
	.path="/usr/libexec/nm-initrd-generator",
	.hash="3dd8b7283e0afde105a740434a46cf5816223c05d35431e369a0829ace1faf23a694a356ca833c0bfad0d1ec4f5cfb2dae0c8079d8d385c21463ee393563888e"
},
{
	.path="/usr/libexec/nm-dhcp-helper",
	.hash="72c3000d1e2b614451aaab0f9942ea621692fc26566ed799906a47417206999d24709508858d6be01f58f3fd66fa224528db32450088f68514f6a37d14b0391e"
},
{
	.path="/usr/lib64/plymouth/two-step.so",
	.hash="30d79069725451b9af646080da1ed08e40cb9b2be6c13d14610470bce52eeb382ac0fc8c6891ebe0d70064d7e07caedf7cdc3760f6df56d781a2f061b88cd548"
},
{
	.path="/usr/lib64/plymouth/text.so",
	.hash="02b8131594e00680e089a50b38ce803a1736f0a475cea767f2d75d90354e5b156d853c5d9b90c3dc6dd155fdc5eb1f3264f3a71694ed99960c3d5aafb19a124f"
},
{
	.path="/usr/lib64/plymouth/renderers/frame-buffer.so",
	.hash="9445de829d05ecebbd8c5cf2a03e3f62afc22803a5585bd7121122bcfcab3f0a17e2d6b59e915d0fe8a215c575d79f3736de995e977b20c7a148317264450cab"
},
{
	.path="/usr/lib64/plymouth/renderers/drm.so",
	.hash="e63bc9ff0036c47eed2f72124731eeb674d94017218db672d2bc15969d23e68adabdb171744ae39c6c206f078c6a197063afa8261c9e4b70389a4f2e74097c6c"
},
{
	.path="/usr/lib64/plymouth/details.so",
	.hash="17da7b1a5b28d4c715c2af45d1cd7714696324b09805da3d3a9fda8193db01daee2b1e6d84686e9541d01fc2da89920d3b213988a466a5a98d3085a7297127fb"
},
{
	.path="/usr/lib64/libzstd.so.1.5.0",
	.hash="1a855666ab3870a403e379c2b24da4eca16a762b756517ec5fc2a8694866929ef43644a876150e210acb24e2f25d1608e620d4be67824dd8e967354dedfc96d6"
},
{
	.path="/usr/lib64/libz.so.1.2.11",
	.hash="654598d4f149484e1ce0e3150729a8d4da81ab1cb2f83e2c13d87e352352854aa6830ac98e86dd42e61474f03d97ab4feee6e97f1ed6877f517b2a1934a37322"
},
{
	.path="/usr/lib64/libuuid.so.1.3.0",
	.hash="c2e5dacc12909bbc594738da3701f156ea0732d61698c92ddc0a2d4683dc27e14b1c1a7bf8ee4e6905d9da203307eeccfd1063d2aad56f74c1051696ca883bdc"
},
{
	.path="/usr/lib64/libunistring.so.2.1.0",
	.hash="28728238eb9e4c35bdaafa2b2cbac0c65aec1c4f4cb5a0655259e605440cfe7df5c395761ddcc80fd3ca69bbf7823cca8db2eada388bf7a95992b8eddd2612ea"
},
{
	.path="/usr/lib64/libudev.so.1.7.2",
	.hash="7eb017c3497752fed653cb52eddc2e52ef7344046fca99e9fc6223dbd684db0eb66a0367a8bb4ede69fa1d82bebc216ace5635f52bd87dbc168bed246b06ddcc"
},
{
	.path="/usr/lib64/libtinfo.so.6.2",
	.hash="754687f380d5b0e3359e19705b3913ad1a948bf0963d86730f86a0736030a6f3398c7a9826e100ab95876d890ada6374e2ff0ed74a0999342835c0a72a8c3d95"
},
{
	.path="/usr/lib64/libteamdctl.so.0.1.5",
	.hash="8b3db40ecc40a18e729e476734564c15b2fc371a27511a4360021c10e0c6a7c01140148857c3cc3fb0241685ced8980dd771d1645f87483b3acab14ee2d496f4"
},
{
	.path="/usr/lib64/libteam.so.5.6.1",
	.hash="b4112d10e5c92c3420c93f5abee2fd7dc928cccf029ff3a53211b6a6a6558d1acf0df5fb76ebb42c196956503bc6ce03f51fd2f2e8da432fbbdbd6a4d7614e57"
},
{
	.path="/usr/lib64/libtasn1.so.6.6.0",
	.hash="879848ab7e7aaf185082a007d343012ed23edfa9ce098f4ee8e8c290eb054040c6a1bf7e9875b1074134ef1528cf0fd069057a33eaac239194512b30edb07911"
},
{
	.path="/usr/lib64/libsystemd.so.0.32.0",
	.hash="d8881687eeb716e069674939760f09e620ee42aedce2cec5183930e37d266629ca704167d901a0e98771f65b00448c252b3436a90e8b29a59318cc5a56716e4b"
},
{
	.path="/usr/lib64/libssl.so.1.1.1l",
	.hash="7a96433c45ae21580fe8ee379cf1cb5634052c335d044f75d7313d2df5bb47b3dd9e6a31ea9c994b42023d2d6fc91d96ee966abd3da7d647c6e6ea3fdcb3efde"
},
{
	.path="/usr/lib64/libssh.so.4.8.7",
	.hash="c7075ff4878557d2b79017a6302cd9d1637fdd6f9217dfe3ed51dfe4036dfc42879feeec2135b89dc41fb06383a9684e1595daf944510a24f2a3603a7518cd90"
},
{
	.path="/usr/lib64/libsmartcols.so.1.1.0",
	.hash="501796a22f522767c67bbde455b4eefda3b74e5dec13104e5cac8682eb030683374c41f237b22b54e9ffa4a285a0e22603abb7eecd72b8a77bff1b363368bb66"
},
{
	.path="/usr/lib64/libsigsegv.so.2.0.6",
	.hash="32bb5738e1b3d125fdfb913b3328067b25cf01f1b09a97ba13f9822a7e87c95398fc6ce09378a72b9acccaf6c3e25d9e7c84928e80e77f84d108a392de13f655"
},
{
	.path="/usr/lib64/libselinux.so.1",
	.hash="db703ccb059f65706fa1e945ed82f04c3882e8121b1a52c438cd9892bd54b8a7580f278b60ba777ec72d88945b679839d414a0e487878c1f161fe1fa0e8e0a5b"
},
{
	.path="/usr/lib64/libseccomp.so.2.5.0",
	.hash="94afe835d287d18588374a28d34b7b7adf7c21eda3c6c2b55668571d7008e8b6ece1fe86554f0e179516d5ea9fcc103e878a52d5fb3d93901384cf9841823e29"
},
{
	.path="/usr/lib64/libsasl2.so.3.0.0",
	.hash="8cf6c8b968077b8bf4dc8598eb26e0b4b800f4bdfdf197dee5b4614097a03a235b1e26421925d057cd25e22f3367fb6f638f94c01d9594723b768937fa63bff7"
},
{
	.path="/usr/lib64/libresolv.so.2",
	.hash="d0cda4b11c76effaae73e7dfa3ca3e8bb84e88ed66e59c4fbb68e05496952e8c500f02b7572bf662b2cf2a3bf0467bd47813ff44a18373c93fdfee3d5f65ebc0"
},
{
	.path="/usr/lib64/libreadline.so.8.1",
	.hash="3b64b048b69983499e3b6121194f6078b4eb4111b420e1dec0547fc210c156372a948bee0f3e4279a9d837a5e2ae66ed575a6fa39b655c96c7fd907df38692e9"
},
{
	.path="/usr/lib64/libpsl.so.5.3.3",
	.hash="e26c44b812a99ff6be237edad3a57f4cc03e20b73090f6d39852997a97f694712cf081be2f6f8f4860178d094fb58b1cc0a8efd13f5ea9b5ccc38a648f3de59c"
},
{
	.path="/usr/lib64/libprocps.so.8.0.3",
	.hash="1d44fcd0b4b140a7997ef92951b1a9b42b71a342e84ba1401b89985ba6789c7eddaaab6218dfe2de5c38559193f7680ffae0df2147f927e533044355cac23844"
},
{
	.path="/usr/lib64/libpng16.so.16.37.0",
	.hash="9b7855dfb84c67350968649813bfe1261c0544c9511417700e3826a32b31a3454b7414ee5d1d2d284f3c2aa776d3bb8527b20012f72d4bf8429ff26677a63340"
},
{
	.path="/usr/lib64/libply.so.4.0.0",
	.hash="4ed11e46e4a46a71487c5fc5ee811dfa520118ac776058c79c52814a5d5872a66861e81a859ebf1a3d4700e10282b35eb326b3ff2dcdf39195415a49d7dbfe20"
},
{
	.path="/usr/lib64/libply-splash-graphics.so.4.0.0",
	.hash="a6986fb1646e5c324141ccbc9a9b1f6d13662dd7107c2f6f199a5cecb5685e5242806740f82409bcbc8c0401992b66ca6b0e74ddc6fbf03afe5d47639a5450d3"
},
{
	.path="/usr/lib64/libply-splash-core.so.4.0.0",
	.hash="59436ac843a2aebd33d6a3dcd8f48f3f9fd60c34bd3a4d6ff66d5c43a22cc8108edcaacf0a0fc393cb389b14627cc010541eea1cb6fbd2242c187c189e75f720"
},
{
	.path="/usr/lib64/libpcre2-8.so.0.10.2",
	.hash="8e9d327785083b4aa245cb7e57983de404a3b7602d122cda03e8da0be1153bfa5f36daa5617df0631225346d817a5146412ba750feee458fd2880857a84cdbd1"
},
{
	.path="/usr/lib64/libpcre.so.1.2.13",
	.hash="bd8183ff468a3666e7a981dc0c03466fbc29f8f7644a66a036e106ab040790aedb14d7553808ac772600f7658c7a94ca7fc109ce5cdd39671d1dfbf6063ed9d1"
},
{
	.path="/usr/lib64/libpcap.so.1.10.1",
	.hash="2553045a006713ec27966f9b414b46781246da63b83901f5780a4d103f81699aea94e2f5ead300ef6dfe31745c1167c6370b4ead866967f57e8b084b4fc40f2f"
},
{
	.path="/usr/lib64/libpam.so.0.85.1",
	.hash="0e2928eb1bd2376b9239333deffe4d0b1e7fb6b31fdaeef908eed9d01a6784487ced335d8bc694f630fdee6aa02c8c1f1db387d1545ac16dc35c72e06719846e"
},
{
	.path="/usr/lib64/libp11-kit.so.0.3.0",
	.hash="8e31e0700c2486bc29ab190d3d5ed6962ae2195368f1f918d3ef39839e724bd0a6af7d182d30fc7119ca06a5953191a2dc254490a3713ed4c5718cd8bc14165e"
},
{
	.path="/usr/lib64/libnss_systemd.so.2",
	.hash="89409d76df5541d6cd45facef906c11d88b6d3364d960c9ed4d5f3225baf0c3e9aacceb9278e0298e697cda1786a04b68f6f58093caa2c76b04b18cfa578bfde"
},
{
	.path="/usr/lib64/libnss_sss.so.2",
	.hash="455d8c2d34af34fb919a4c0048d836b18b6959792e398b24c15c633ae4837984a9a210de25857d61c9503416f6ad23d07fe6c1ba535a5e2a0d0e2cf43e672563"
},
{
	.path="/usr/lib64/libnss_resolve.so.2",
	.hash="ef8cb82b7b21e61529f971f2a5c1c40fa835392cf1b963b2f6767917940157f41d9527d26758f4d46efac7ae6e20e1b53b7224c6fdee9dfd3a0683479c1c75f2"
},
{
	.path="/usr/lib64/libnss_mymachines.so.2",
	.hash="45e16342b691084d19c83d2b0a77682be560509f904a6a2a192a03ef0b6b8c2600ad0ebb263ec83b1969183f6683f778675f4421cb1cab43336ee9d4d73143e9"
},
{
	.path="/usr/lib64/libnss_myhostname.so.2",
	.hash="4247be62f5968ac514a96f3f2ca71a619040477997c9c87517e4a37602dbd8c817236c17fba60070bff99e0c6dd63313da5f8da2534484f32a6cfb1fcb024e25"
},
{
	.path="/usr/lib64/libnss_mdns_minimal.so.2",
	.hash="5eaf062405830c7be4e0b8e66bd8b7cba00f80af2586ab3609f84cd9f818ddbb1b9f155a2354d9f4963b3331519f1fde6ba1675d9acdf809045e149e59df2c79"
},
{
	.path="/usr/lib64/libnss_mdns6_minimal.so.2",
	.hash="0f15bd67fadfcc903c180d2968bf9833eace38fe6917f137dc80c31addc271759c5814aa116f12cd25c3b2d81fbb1b8ebcf8f168fb0eeaa7fc8518938716b247"
},
{
	.path="/usr/lib64/libnss_mdns6.so.2",
	.hash="4c1efd4ce089f715c1906a1e01ac6dfe782409920c3228959ccf8811771f02bc7ab08a1d6524ada685f6ea6976a3d4b2ef00b76b06ea79f67929c7449a2f1a9b"
},
{
	.path="/usr/lib64/libnss_mdns4_minimal.so.2",
	.hash="578405e3f0a6e23baca23a2b2f0f9cd81ed18b55c44d16e451e577f0d6021f3dedd20946e4dd3cb7cf06b2d2b4a84cd5686a8cd9c6885120ca43594d7bd901cf"
},
{
	.path="/usr/lib64/libnss_mdns4.so.2",
	.hash="d3e58e309fdcc1d5b965136ff0f4287fb96ddcd5099a720bc654935a874e24a54b80612be4bcc6ef28c92ded5a2ce7a1fe16619b28743ae49eaebab5aee67c7d"
},
{
	.path="/usr/lib64/libnss_mdns.so.2",
	.hash="04fae3dc6bd851bfcaf6e6867c475687f85e804edaa1b5fe5153b2b7b620c845a63cb4cb9d6988729cfdf2f72371bb56372d852c6619377aedfb6a1189b57c6e"
},
{
	.path="/usr/lib64/libnss_files.so.2",
	.hash="9005c536dd4abbdbfbd0abec7e46ebd2c2ac6397d41082a58a359abdd4b6039ebf082fead63a525b3c854657f8ba567265212e37dc910e2472815bb7ae58a012"
},
{
	.path="/usr/lib64/libnss_dns.so.2",
	.hash="87e4d0e14081f8a8485dd5645b3b36f8e54a7d2cf4dc6fd4383f82e9d62ec5e7b11b3eec5bfc7aa4b118f1bcc02d2c92901250312041bd4b79b9fd6bad88b585"
},
{
	.path="/usr/lib64/libnss_compat.so.2",
	.hash="befc7cb10690edf4add8b69e086c8fd4ba07c8d15db482d0e1b069b8074d159e8f82c398c4ee3797fe2d8f0adef7e493082ac8994503e62bf6a3c49d343e39ec"
},
{
	.path="/usr/lib64/libnm.so.0.1.0",
	.hash="93d22c5bd06527d2cbbd857206ec670dc20ec369efbdac975b101041926061abfa3c8b0b3542660cddf974c8892c08e9a44d4073ce4b4968bae8b364aaca6f1b"
},
{
	.path="/usr/lib64/libnl-route-3.so.200.26.0",
	.hash="232505f482d1a65c81cac3f4997627e75f59e4e0ea673fcdeae68edfb32c77d90ce26ebc4742e683b3e8afdec28dde0b2158925378ccc263370d44cc6690a5ce"
},
{
	.path="/usr/lib64/libnl-nf-3.so.200.26.0",
	.hash="87038a874f2f40b67b03ef8d9137f3eca51be6629344cef350196778408f85e6cf5a130a54d34be286f925fd9e6f48983c87f5391872065362c606ffffd3ea05"
},
{
	.path="/usr/lib64/libnl-genl-3.so.200.26.0",
	.hash="846b26bcbe4f2c3506ef6e26264d7448562de1e563e3347c706fc67013b6a7a755a946ed15f3f3da423ffcc5c0668b3f9d68218dca1ba495eb90ee369ff57a0d"
},
{
	.path="/usr/lib64/libnl-cli-3.so.200.26.0",
	.hash="8079f10be4f43a77b4269acd65f3e6ce792c16e25116483fa94f9ff618919a98d03bcda42887cff624183c291e733669e6d4c698b5d3d600be7eeaabd668cfd3"
},
{
	.path="/usr/lib64/libnl-3.so.200.26.0",
	.hash="62e5b936290ee2119e399093f449ad8ab5d8adf09952717e8eae93a4f77b1d22cbd8630b830c94cdad0d9d005b5acd8d0eb1e8ddf08e00f50131af7c6d255b95"
},
{
	.path="/usr/lib64/libnghttp2.so.14.21.0",
	.hash="280c8fd3166112ab1f97ec8ef9a949c60fee6c856d3dc9c97754b86f2df8c46ab9f5b60d53ba7a75999742baf0a9e819500e7c2ebc57df4f1cc49515850af9a2"
},
{
	.path="/usr/lib64/libnettle.so.8.4",
	.hash="faa9a77e1215cbc42f222ce488071f00ca5fe3fffbb5073d408acb36d25432a9add1c411157350af94ab6c026b4e258fdfc75434933ed44a3fb19fa72c144c52"
},
{
	.path="/usr/lib64/libndp.so.0.2.0",
	.hash="91bb7ad9d2885bbc0e441a222d19dd3efce2924c98a4d5f5c967b2b1fdc2fbf5054b5e499268cbc103857bdc710037829659b89e38bf25042f609c32f5585c2a"
},
{
	.path="/usr/lib64/libncurses.so.6.2",
	.hash="96db756f2f2db17ae5ca977454b2abc5e1c837b96846061df1555fa2874174f589c2b3ef2dc06248de47316e340069ae0d0eff52bd82668730b86f0d2262e302"
},
{
	.path="/usr/lib64/libmpfr.so.6.1.0",
	.hash="98314c4261cdc8b7ae5f4abdad5a497693f8477b6afe95cc22a50cb264d44d5fbcdcbfce12b5ea390e670be94ccd54591d2885806f073a4dcecfc6bac2967d6d"
},
{
	.path="/usr/lib64/libmount.so.1.1.0",
	.hash="227a70f0a149d71281d1a23b05ef73dc578a65e77398b28e44b4bbb6606cb290a310bc0612017c4a0466a0edd997d4f7a49f5db4d71ced5fde7eb6204fcd345e"
},
{
	.path="/usr/lib64/libmnl.so.0.2.0",
	.hash="49067d3308a9168815e4836fc6b30a004adcfec87177bb5b84cd963bbe5979e28411c988a2085434ad396c7137c89820d7c06ba0535218e6f20cc79abd045e7e"
},
{
	.path="/usr/lib64/libm.so.6",
	.hash="5324a28c9361f0cb04517a1bc9ce4832a51509e74132b6521a38bf6f5012fa03dfbd29ed376031289299e154bcee3762edb69a47b99b1e7844eb9cd29002f943"
},
{
	.path="/usr/lib64/liblzo2.so.2.0.0",
	.hash="c41288490686d598df4f663360551b9ae70e789d967e775bbcd1657abb0878084bb45ed5429673c5e530ca9e603d6025c2c631d2dc5314e9abe0d1f97a7d6d2e"
},
{
	.path="/usr/lib64/liblzma.so.5.2.5",
	.hash="271869d919db1a74fd2995a91af88c753dcfddb73b0b550983d6998fda7d5a1b1f45aa4fb8d3381e27823a8d3c49faf6ecdffd2cc0daee37b58106fc8e3a1d1f"
},
{
	.path="/usr/lib64/liblz4.so.1.9.3",
	.hash="1a08045bd5a6312d4400cde34fff9aea64b151fc7113db8d7bd60319522ece9f544f48fe6c62ca8962c076d24a65687c147c9d2452d5a132ae805635b126682c"
},
{
	.path="/usr/lib64/libldap_r-2.4.so.2.11.7",
	.hash="707b28f9fd7a1db23468cba0fffeb7a47695dd2f93f29ac9fa033b27d5da8a5dee4fa2b42ead5f8b6ab887000122242cee852991e50a36513b0167101d41863b"
},
{
	.path="/usr/lib64/liblber-2.4.so.2.11.7",
	.hash="d8d514e53c59da939af489043f958c036feed075d11c3a554f6a0e322d73c17b2e564f6fba4590f5bc7c891489e322c20347c8c9df2ed474f4924a37f558b172"
},
{
	.path="/usr/lib64/libkrb5support.so.0.1",
	.hash="aaecc0ffc94ae9cbf83ef7f3f0f232095407eee30d728f736f1f76bee1f9a314d623caa75d035349a26b06894274e80309998cbea0727d1344804245e6f0d45b"
},
{
	.path="/usr/lib64/libkrb5.so.3.3",
	.hash="76fe643a5678209eca467cb4eab612dff876ec806b7b8e235d854680acae4e2981d82da7108e77c65b7004caacab2997228df8a272f2e31eeb7b4c383d8bccff"
},
{
	.path="/usr/lib64/libkmod.so.2.3.7",
	.hash="8c8759d2ef2fc039653d9657e3117efa76a9051d1069d14c410c41ac75e7bf65cb18a731acb2e06b27777e02422ecadd394e603a11aea92beffc8bff30b12b9a"
},
{
	.path="/usr/lib64/libkeyutils.so.1.9",
	.hash="bf36c453b33848dda1f01726f21101fdd26d462ec610020647abd6fc965c2d75dc4050e39abd153db6e668ce0f4c28a9c2fcb36eef5ea04f4e02787b5c086fb0"
},
{
	.path="/usr/lib64/libk5crypto.so.3.1",
	.hash="247ba720c4e44aeccd4e757ba709d8643906733a34213020f2301550d6bba06bd338df341090d208828499ccc2031411e257a751034378c64b07233085bb598e"
},
{
	.path="/usr/lib64/libjansson.so.4.13.0",
	.hash="d2a2b6183c4c852b525f60a1feca8758ad61c0e6b40defa1356da9a75ee3ca6423f2366fee7ea49ddf463578f8e0c9bc71458aa46950dd9ff0989168adb879c0"
},
{
	.path="/usr/lib64/libip4tc.so.2.0.0",
	.hash="a89cd174c3d537ab8adf96a86aadc768906bd94770cdec136aa63f2fd755b691c55c9dfa0d9908f9491963dd34483a459e9d3ad3bcd89dfc4ca2737af93cf51f"
},
{
	.path="/usr/lib64/libidn2.so.0.3.7",
	.hash="bae4ebd990c2bcead7de5ec7faac6a625520ae3e2e2c3424390d5239c6b7b73138a470b15b9329b047791177df9b0c3e4b641a2303e9db0acb0da04bfb059d2f"
},
{
	.path="/usr/lib64/libibverbs.so.1.14.37.0",
	.hash="2595edec4ec363be3406a5028bb5ee5485074ce1e1d3b1f1c731ae6ffbd768663981d88c5875bd50a632214c4c69b65f5c0034d8913fb7d6521265c624fc7a79"
},
{
	.path="/usr/lib64/libhogweed.so.6.4",
	.hash="2f5207be549b700f3adcd49834a5e16ee8ea139f0ffe0bf4a86c1573f7aa490f9f66a5e67d68ee038c79eb2ed0392faa90ffbd0379dfe5c65aebd1db88b83d51"
},
{
	.path="/usr/lib64/libgssapi_krb5.so.2.2",
	.hash="2cf6c05c502644b798643507dae5bbc8894ca2f0d43922ee7185de1160c118ef2a618cf3e4a665b27105efaf2095f1f3b1dfb96ca244a447b85417010b8a96a7"
},
{
	.path="/usr/lib64/libgpg-error.so.0.32.0",
	.hash="a9c0fbf6dc3b3c3ca2be034d99652240824dae7a5155232ea805cc20504406feadb3daa733b28ed1e250f3b2ad6bbc0bd7728c372a41e1ba615525a3e1578eee"
},
{
	.path="/usr/lib64/libgobject-2.0.so.0.7000.0",
	.hash="47f7dbee84418bf218805a8e2f3f258a632b692e803a1665a01000691f292f6f6dd350fa43e5fcff98fd3db57185c3e593c425fa54131e43ba14901afd710f67"
},
{
	.path="/usr/lib64/libgnutls.so.30.30.0",
	.hash="00806ea9e81bf01632c00dfbfa2719581ef7b54141025716a143991d21a2ae659927b14b6f571f0d52f1e7e99b26e31d0190909cfb61605b2d3aac11a7efaa55"
},
{
	.path="/usr/lib64/libgmp.so.10.4.0",
	.hash="756b547d064c171ffb10d64a4636ae5ccb89740d56744a244ccf50ae87956f7348d77c5f236a448886f52cd605323da1512dd5e7a575d78bbaa74b186cd8945d"
},
{
	.path="/usr/lib64/libgmodule-2.0.so.0.7000.0",
	.hash="21c3d642cdf291f3e0ef38981981f58b6c595e8f4c78679b4007725bd2d1d65d1552c68604660f6e23793f2ed487510b0b1b31a624129833bb24888b7f28317a"
},
{
	.path="/usr/lib64/libglib-2.0.so.0.7000.0",
	.hash="6ac69b79138d4aa03cbe71bbb307e928b02569155da5195bc91ffcc585dec0da207257c0d89136adf1a80dbaa734b42d687eaae2afab4628d68755a5f48b2743"
},
{
	.path="/usr/lib64/libgio-2.0.so.0.7000.0",
	.hash="af3ce92f28a00f206b628fd4520f776325373667eb43d67c8fac6df03b113cbdcecfe5c928b66132ce1b35ebd1aa721866b9aedfcbb6281bf8344cdd4726ceee"
},
{
	.path="/usr/lib64/libgcrypt.so.20.3.4",
	.hash="d460bcc4990a3f4ff430f61f945696adc18f5bccf892477a3b25ec587f1e9b396c3b43a7d7f09f3dc08398ec7b2454af7ac8de78c0715420a4b92abb6529f60e"
},
{
	.path="/usr/lib64/libgcc_s-11-20210728.so.1",
	.hash="9b71e8d9f91bcab7d805a530aaca58636c5609edf64e4cef17f2c15db60a07650706c7344c611fcc17d663fd7a0ee6f2ced5abb8964df243c9a72c479f68a4cf"
},
{
	.path="/usr/lib64/libfreeblpriv3.so",
	.hash="97ea6ee5e96fe61ef7a99dfe34383d0233ae2a9d542084de3d7f99f0d0cf08cec7bbcf5f2ae835d61bc0764dd42d29517a25f1f67a4dea3d254d90c4fff90819"
},
{
	.path="/usr/lib64/libfreebl3.so",
	.hash="682f8ea49648538b78f2c818b1cbe2bef98fdf26a77cbd4581c3b669a4ced7079b432982be7ad07654c8c94d67e45b5085ecbf5714146a0611eee538a136567e"
},
{
	.path="/usr/lib64/libffi.so.6.0.2",
	.hash="75817ba2d0306e10ff63fec8e676b14088de65fe5b5e8a48ea883e3478768e1ae119b3f964a2ae56afb6fc8946d5ddac76036b432d39499296e92a44bbbe93a0"
},
{
	.path="/usr/lib64/libext2fs.so.2.4",
	.hash="b6393be5eb9ed065a1666d63297a36adcc7d743c108a17caaea67012661b47c7a9a270aa15045ef32c496d096529d301c7dd5571d205f9d4fc671afb8553cc06"
},
{
	.path="/usr/lib64/libexpat.so.1.8.1",
	.hash="76bb06cb41893090d0711adbdcbfa62f2cc01f5559d3ad0c8d1b803d616c6affa655867d0cdab9d647d59f1c39e182818117407da5ed1f22cc49b42a2be5cdec"
},
{
	.path="/usr/lib64/libelf-0.185.so",
	.hash="1ada711750e714f95f55e5e833827811c2adcd0e8014906f990ce838438da2e6195af593f4ef8589aa35666a6e2fe9535548f2bbac6f5d07ff6a1720c0f28176"
},
{
	.path="/usr/lib64/libeconf.so.0.4.0",
	.hash="f91a9d5e8cfd48a8a03d8d0b5e48c8693bcc63783028d2eb0f88578412c2bfc0fa5169cb3c9b153f3bff53f1236248fd57e58cc34e2ffb1b6e95e4d05fddb54a"
},
{
	.path="/usr/lib64/libe2p.so.2.3",
	.hash="af85657241f1bf3e358569403847eda4586e5b47658fc7af6bd82d5d206018c0b3bf19c25c76520ac9e4230e4116d1b9ed3d115e7dcbc0c5d23af00d953317f6"
},
{
	.path="/usr/lib64/libdw-0.185.so",
	.hash="d539858e3d6966babbfbb42809cb4e4ac511764929cbe5a508d0d6ecd0629b35bc2da00760d90106a98cdc03be413015ffef497e19e364274697dea896288566"
},
{
	.path="/usr/lib64/libdrm.so.2.4.0",
	.hash="f313629b13f675ddee06acea3af22bbd3623762e5169381c4a06d344e560f9282e8acb10a365ea130f68ed03d61887746abab8d1b31b290d4a81c82c16e00e64"
},
{
	.path="/usr/lib64/libdbus-1.so.3.19.13",
	.hash="a4de6a0db0dcbcc6f896628c6d35e974e314fdbba6dab78ea7ce363af3d6d49d7fe5b1ff54726412aae1d6afd72fd97e4a9e6fc7038da9aeaf2b1353b0eede61"
},
{
	.path="/usr/lib64/libdaemon.so.0.5.0",
	.hash="5e354b633eb08b5c877b326f91eb6e05fbb9da492d38e25bf99c5ddfdd305d7a0761f861ba392938265e0e9952ccce5d8c4ba5abc73e3fe7e7e17925bebc09f4"
},
{
	.path="/usr/lib64/libcurl.so.4.7.0",
	.hash="607b17c757706e82345b8ba4efebe88ed5ef94d944b87caa1703347f5ecd511db1f27998fe09048c852e45cf1073f7bdac496be24439914fa1ba12888ba26b23"
},
{
	.path="/usr/lib64/libcrypto.so.1.1.1l",
	.hash="3e7b11446bc7ff2db8d3179ba976d4e6d98e13ca3f4a60d8bcd1b9dff8d69f6dac2ee85838a20dbb78a6e09d5407cceaa9130b48ed54904140ea1e74edabaa4a"
},
{
	.path="/usr/lib64/libcrypt.so.2.0.0",
	.hash="dbbe916f63a49ea6983f3e02bb28963330885eb49756411e5ee7dc1dafd9f846a71cdc9f07a0e206b553f06acb25d76e817849d0eeb0c13de8baaa4f67226f4b"
},
{
	.path="/usr/lib64/libcom_err.so.2.1",
	.hash="4335e7ea3c7139cad4840bf6cf9d4557519f76b383c3b68cc537f0be7bb69a041f147f4e8eef8fa63c5b8f67d5b394eeff3a7cfadcc3eb5608eace87a94c6e2b"
},
{
	.path="/usr/lib64/libcap.so.2.48",
	.hash="5e253856c0b19a2b8629965fb8845b80fdc6c8ff78ed3b95ed12d7819dd43166b8f5de0266d342ae886628924c71919bf5a134cb9d50eeae9cf32c33fa26c508"
},
{
	.path="/usr/lib64/libcap-ng.so.0.0.0",
	.hash="56da592866a38b1f901ed4b60076cb2a12ede05a4eef20a6cfeb2a32263a65645fb9a2e37340ca09ba41308596364ea3826d309711c6f06063be98690aa2686b"
},
{
	.path="/usr/lib64/libc.so.6",
	.hash="5b4effdba4bfd29bd6cb22ec2dc89e533448b83b565edede005acce93d49e51467eb2a7e21fa840c061f76bbe9a4c45b87317d94e0236c889209c48a4eb1999f"
},
{
	.path="/usr/lib64/libbz2.so.1.0.8",
	.hash="4d4cc38dcc631829d9caae30d57e3c02bcce36dcb10afc0bd033b9df2bed992fc9005339770f06174528b5721f9b5d8f14c70b78b0f838db3cf1f1c2c0f2724e"
},
{
	.path="/usr/lib64/libbrotlidec.so.1.0.9",
	.hash="e6a46215f5c0a9d1ef45178c4601e242b441fdc9d7821eccea200ae02a43af22d1ebdebd7d00b79e563608b9db1b140247e7bf69e3f8f552274f069a5332a9d1"
},
{
	.path="/usr/lib64/libbrotlicommon.so.1.0.9",
	.hash="6678b15e924d06ad0deacfbf118f625ec3d84d669635e30d9167dd12ba30ca07c7279899fcce5f55f781906774b23729c4923a4f1b5b9b3cb2b5225c1c56963a"
},
{
	.path="/usr/lib64/libblkid.so.1.1.0",
	.hash="204ac666854364c803adbd083e51eef1e59500770bf07c6d2be38b9a1ca2ab0644dca1a3ad67b23e3fa8a0d7c8f4942a42b3cbe54ca46ee6ef8c40c53f049956"
},
{
	.path="/usr/lib64/libaudit.so.1.0.0",
	.hash="ce3e7af9680ca4462f5b4ed4b2e820e30370bc0008a50673ac558208883ee13dad636c3c083a8895486da4e12699255bfcb1ec3e12b2be4c9e91c42d8751be4c"
},
{
	.path="/usr/lib64/libattr.so.1.1.2501",
	.hash="f69a1989768d0104474bb7ca825b2b9a7fe14275309263b49b820498ef7b45f8735f809332ccdd7f298cb0bbdc3ec32fd78e7248ebbbd535402f39e1acfc93c8"
},
{
	.path="/usr/lib64/libacl.so.1.1.2301",
	.hash="270d7f8629d6efa9f285590f3fa7f2f4c22c781a3452bd874170b0c5e6c5c9fee95cb915efdc6ea561f28681eab77350dce91460e499b69a860b2369bf9348bc"
},
{
	.path="/usr/lib64/ld-linux-x86-64.so.2",
	.hash="b7d7e4b9ca4849dec0565a9902c50293f9c79422a03115dedbd426402db1d772efd3cbd173c6b13a422eeb30d34f35b7a33b57ecf84902888fcc04c28fa0684d"
},
{
	.path="/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-settings-plugin-ifcfg-rh.so",
	.hash="796e457be98b71e5971fb42a2ad9aaea89c7ff056a6122f1a492db5c26021caa2b99d7e9475ed2d456517f55608fd5492f6c4f4a2dcf9df4c4ed5e702e59be16"
},
{
	.path="/usr/lib64/NetworkManager/1.32.12-1.fc35/libnm-device-plugin-team.so",
	.hash="cd8259d561a9f267dab3866c0b5cbbc854e082cd04811289e44d411373406b1237ea2c47f6b953c5123bccfeac2587b9b17eba204b4ff5a6f476ddbde78642d2"
},
{
	.path="/usr/lib/udev/scsi_id",
	.hash="1193d70e966151c1255f981f1557889cae4abb94282c2868b032c3a23d360c4d675857d14f0ad3ab61bfc8c76f6b349ddb8336c768612b8afb7e7a814cdeb9e9"
},
{
	.path="/usr/lib/udev/cdrom_id",
	.hash="b0838ae1932a04c9d4906f7793ba9aa7d3738ee1262308c5c414e0ca098babaacd8ef20b0d9aac25ed286d745122fd23dfb45fe1992a19a1739b9b88ca23881f"
},
{
	.path="/usr/lib/udev/ata_id",
	.hash="35ef1626a3d310fe169b11cc55194c72f9cfbfd76d89c01e59a4ddf9c7605bb758f2bbe994ccfaddbdfd5fe0fb887f8dff843ed310131d23f0a2d9aaea49f474"
},
{
	.path="/usr/lib/systemd/systemd-volatile-root",
	.hash="a4ae0e06989b79d443de78b1797183878aef58184ab6bb411300b3f12fd440b77b08bba7ee9035010664febd31bc6bac6ea6d46fc47a40b4d10cbaa45d33b4b1"
},
{
	.path="/usr/lib/systemd/systemd-vconsole-setup",
	.hash="97c183ab876e1b3fdb534363893789f7919e4ff7bdfa0e27807361e187b7f25b0a0f8ff842534331424ec1c954c09ce4cf665bb5c223687ad3e202cbcad8fb28"
},
{
	.path="/usr/lib/systemd/systemd-sysctl",
	.hash="058f5e542ee0c57db34544a61aa31e15abdffcfcd7e2fac788794ad8858aba38ad72555647e6178a9c58e99da0b5b3dc4408c87a251bdcbd6079a0918211433b"
},
{
	.path="/usr/lib/systemd/systemd-shutdown",
	.hash="cba3fffe157f1b370b4edab1e674dec9fc5413e471eedf6f12b2b69fd327e5337e2f7a97647e8fd6b37ffb37fedac400e1075a9dd5863cae454efb0aaf036657"
},
{
	.path="/usr/lib/systemd/systemd-reply-password",
	.hash="f53660d38790af7701b3fe48c9f771214042a3df822b1446f2d0d6d2c7c21a0c4d145f74ba4e032e91c6738fb49e177777cac31c123117d1de170879d2b56275"
},
{
	.path="/usr/lib/systemd/systemd-modules-load",
	.hash="5c0fa5054f06e2641d72d4ac64a56ed7deffa5ba095e1232a14d23f4d29dff801972cba1c71893af326b5983d2948e49181617d941ebe1b15aadaa5cbc3dc6ce"
},
{
	.path="/usr/lib/systemd/systemd-journald",
	.hash="67076789b802f54ef6be5d9d86a975efd02eb483c25e4dc3385964ee46b9644da85ea3977dc18387b32b6076ab6b1b778fc9c42e60f591e6f83a33ca1209b68b"
},
{
	.path="/usr/lib/systemd/systemd-fsck",
	.hash="7f94a6095df9780245f797123b835713352b288214b40cb938fad004f2fa700a1de61b00af02c2e959dc46497506347c21fcf46a54e4ec6fcf82389bd753054d"
},
{
	.path="/usr/lib/systemd/systemd-coredump",
	.hash="d7e0640f3098403ddc039d778b88b2209ee4d28c5c76f48ca2b6fc908eba16960f17346737e679ff52da04884d580bc22d36028e8c11ae7f9330487cbc9c0277"
},
{
	.path="/usr/lib/systemd/systemd-cgroups-agent",
	.hash="4d115c6ba06df4517d05449957ae8dfd5f040658322ecec9840dab6c9de27685d00a90a91451d7a4b79953d3fc181c2a1c17d2221e61b8247fa6a7f28b4212af"
},
{
	.path="/usr/lib/systemd/systemd",
	.hash="affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021"
},
{
	.path="/usr/lib/systemd/system-generators/systemd-gpt-auto-generator",
	.hash="c3562221328b407e6c65125b5dfbef23f7bf646bcb3f43909bdab2d1f43f47089e64fd11ebcee487ce9bb26704afcb00c642ee3abd296348145134ffaadb7c40"
},
{
	.path="/usr/lib/systemd/system-generators/systemd-fstab-generator",
	.hash="cba9690c6bd6636c831343aa15e51212022ce61eb17b056440a8d1581fcb11433f76e2cd665c1ad530634182f1321c077061c716900f49f9a904e60e6039f58c"
},
{
	.path="/usr/lib/systemd/system-generators/systemd-debug-generator",
	.hash="d28760bfb13fae9081426b839ae97e9ff15b95f88286a3beebcba1cf8831f45a25c411e8b4210c4e3fa317913528367524da64f328afa7a3677e193dcd30fdf1"
},
{
	.path="/usr/lib/systemd/system-generators/dracut-rootfs-generator",
	.hash="eb5b83d61e201ff9b9b19f212d85e7ba1b27087bc89caef72c889328da3784f3520052938b34b3827655fe0f32e0b0322651405d106f0f7eca7cd18f9eab0caa"
},
{
	.path="/usr/lib/systemd/libsystemd-shared-249.so",
	.hash="8b44b6b41b2e57801c2ee6dc103542a58a8763f5938773cbdd16ae9d877b17c24d70f659f7a28eff8b65eec24e9c7295fa35dd1ced81e36ab659cc7989d032cc"
},
{
	.path="/usr/lib/net-lib.sh",
	.hash="d75a845dcaf23766ea127277f9feabb043fbdc8ce5bf8af51c5ca75a2221d85a1bd4cf3967205a65d1d41fa6991628da5dacecad757d8656990a07a69e703a89"
},
{
	.path="/usr/lib/fs-lib.sh",
	.hash="6d4ed45554e2a2c665b4d38621956ffca5546aebd797a0bf28250c0a38a667512d93eb7f37262c2e28c80d9682a645626862c1661ee45e4beb88253d6b8cdeec"
},
{
	.path="/usr/lib/dracut-lib.sh",
	.hash="1eb77c7e3117e9200ea97d4f7f5117d3c96e5ca335214e3bbb4851d964350485f4d8fd5c011933fd22d0a8b42e343c8ad09488cc8c66832aa2a82e2a456b790a"
},
{
	.path="/usr/lib/dracut-dev-lib.sh",
	.hash="fbc0fc6724fa6bf645434e17ee9dff4e4e188e0f3a076c322746230c8d2fd99395f448bc987632a59aac463dfb9377d05dbc33c5d0575e6074374e3eb8b5936c"
},
{
	.path="/usr/lib/dracut/hooks/pre-udev/50-ifname-genrules.sh",
	.hash="31acd0039a78d5beefb924e8337321bd2b8016c959cf9f71d51d563d4cd1151446ad4671a4cdefb4fd77a20c4e943c2dd5a19857bb7df51e8e0dfaddd0312df9"
},
{
	.path="/usr/lib/dracut/hooks/pre-pivot/85-write-ifcfg.sh",
	.hash="21c1189591d0484c8f50b75f050c52ef9059207f15fd2d816b4ef13f8c98636074323bdbfc3817bb22a75e1de78332b1f49e37819136504d9a7349b937ffe683"
},
{
	.path="/usr/lib/dracut/hooks/initqueue/timeout/99-rootfallback.sh",
	.hash="a8c81fe64e37400871d1694f523bb73a398ed8eedc23c960f3f0d7f113d0bdbc04fdae21b84e49189c041e823c241df1cd0dfcbae0c251deb493461d2205477c"
},
{
	.path="/usr/lib/dracut/hooks/initqueue/settled/99-nm-run.sh",
	.hash="5e0e45f576ba4a83363450fc1d99858f9d3749fa701338834968916a3d9c6d98bcd31bc76c7b724239d0841a537c99665a4dbf0823cb88bd91fe23f8bf52f647"
},
{
	.path="/usr/lib/dracut/hooks/emergency/50-plymouth-emergency.sh",
	.hash="83b0026310c8956d9fddeeb9dc0d11a62704517426594616fa4c3ae377b6fe3c7cf44e3ca3d1389559efe6b373427a58f1d978f997a52aa866e9c3fd7ee1f601"
},
{
	.path="/usr/lib/dracut/hooks/cmdline/99-nm-config.sh",
	.hash="e58335ed810a8e0f4a261b57cf2e5f650a37bb62e94075709a847f921e1a6b287ca2463d38eb40cbaf4809847c0be1dc8fbd29192e8be04048ea7aa57aa84b81"
},
{
	.path="/usr/lib/dracut/hooks/cmdline/91-dhcp-root.sh",
	.hash="01b72229c9867e297f44768f2ebf2fa07929a980f46b2c9931cc38b6fb3998b73dd7f246f50a383a892a08e2f6b8a5d5a6074c4918e57c71f91285788b8d4356"
},
{
	.path="/usr/lib/dracut/hooks/cleanup/99-memstrack-report.sh",
	.hash="7a886225ee1e7a2993c0e3b0d04b43e2eec75428040981b540ce311d56600240b24bf3d1dfaa6d80dcdb7c2eedbca5c37b4ae22270f3b60b139d6a7555bf2c12"
},
{
	.path="/usr/bin/vi",
	.hash="5b52441eb3e8e4d5902cee4e6563cae0b8d0b141d5a24a2ae343e88cf31620052570ce42b35c8e69f9a0db325e914b3f7727b55c64557383e79e352cd38985f4"
},
{
	.path="/usr/bin/uname",
	.hash="6551fae1285ed55387ebf00a35ed2c9d95e16ca7eecc56d1f6917d3113acdb9ce00f60d8b978207a2598ff4c74bb6bf808741026c0d2ca60bb9aaa8d34d9caf2"
},
{
	.path="/usr/bin/umount",
	.hash="e9940eab81542676e1e8598d60e01ee847bfde04a0c2f1c8206ebef6b2584f775a9c222f5a42e9a57cfc75f3d3e3cf02df0695d33fe8ae450e94a6b45f122924"
},
{
	.path="/usr/bin/udevadm",
	.hash="787ef7ae71688145275bdfe91c7bb046509a76de9c3da37895db3048f6951e7fb6970e300b17a8f29bb001f8d8ed51064eb9bc4dda6a88af9f140c8fb266cc07"
},
{
	.path="/usr/bin/true",
	.hash="398d389040f0f89ece06e2c224c4a37beaeabb8e3f7a1bef2d7fa691180e7d72232b30b1d0db10dbc50ad168d64e0db7d77b534d3d3e5cbbfc61d2f9dc8756f9"
},
{
	.path="/usr/bin/tr",
	.hash="f183e6d58da884c3b9408346b9492818d512f21510014cf8999b3a38cc408ecb2a966dd39b7f7dc8597485a56b4dc31830b8f68f0fda2e6baff11f245830aad7"
},
{
	.path="/usr/bin/timeout",
	.hash="11c71e4990f01314b9e0b91e266e018f6d07642af909a588bd6e48352a289cb0935a4a63421d9d0de5eb894b38a49ae3c40b7825bc62acb42faa0f71e102ffe3"
},
{
	.path="/usr/bin/teamd",
	.hash="a1b87180235c7482313b32dee67e54d7f9c449368454526bb93441796708788a54602857e2f95e2dab55404e1311cca42cec9d2add09b5bd24cd6c0ec8dbad4e"
},
{
	.path="/usr/bin/systemd-tty-ask-password-agent",
	.hash="0424bb9173ef9d94e8029a5ff9196c0ecfdd4afe0bfa8ce796dd1c0c52dbbc47e956675ac48caf3fa8cc2225823db7af6b1da501c3c1bf80f255f61dbfc97944"
},
{
	.path="/usr/bin/systemd-tmpfiles",
	.hash="a659683f56a931b44f1ce69c24c1ac62ab53ea5cf600e9992a08054b5933d4b0464ff71c8f941ed7f84038895b6b9ee2c6c9081fd36f9fa3c004f026d1cb9278"
},
{
	.path="/usr/bin/systemd-sysusers",
	.hash="6a2ba96d14b32e582033d0fde3653741e127fc8409b50cb6fabd83853fccb73f5af648543c75a53c1a33ef8beaaff00bb3cdc6ef0ff7c7e9efbdf8c135a7b096"
},
{
	.path="/usr/bin/systemd-run",
	.hash="c2071697f9d757dede31afa1b52dffca53a51558589e753a81c0689484f36a2aea67cb0b30cddefaaed122ea9afb7aec66194c7946f4e03ac0e3448f0724b19c"
},
{
	.path="/usr/bin/systemd-escape",
	.hash="07839f0cd2617582079184a6fc3933678ed6250c4f11c52893be0980df20cbff3d72d1d680470aee5600e482dfee0f6792a875b82c28e3edd58a67119c1f24b9"
},
{
	.path="/usr/bin/systemd-cgls",
	.hash="bfb8f883dcb07944ac03a8a6824b492166bd21c52d48c27a1776b96241766d2c8036519db249a147072caffa046ceaae80e207af8e044e78d5ff2ec6e06201e5"
},
{
	.path="/usr/bin/systemd-ask-password",
	.hash="f5d688dff7ffbb5f7eb6af7939f7fc76266631dec04ba9048c5883c6f22fd4474518d30465b5cc4fd90d62ce8bd8b2e5a87bca3153355def16080a7694541fac"
},
{
	.path="/usr/bin/systemctl",
	.hash="280cb95b0ba73dc5c8ae9bc12ef9a42a809de1503fb67efffb29d64aac4427967378da7bdc6e9d0e5a4d0c0f60e64725cb485cedd41e40bfa1c427c227a5cab9"
},
{
	.path="/usr/bin/stty",
	.hash="f971695f0bc14fd45d16bab545f3f2eb22e407dc7a11c20a4994525290c0bf773f594efb3dd3178c4e4eb73e1c5210cb92902c483c731bfc4854c2b1b551914a"
},
{
	.path="/usr/bin/stat",
	.hash="7d6eecc8ae453e2e056b125ef3f629aa32779d741f5aa23f842fa2799d82688948d70806e87e492d53e7fa5468c89fe1ff4868255ced18ca1da928867b635f9e"
},
{
	.path="/usr/bin/sleep",
	.hash="0088658666d99ed3629061aa4de4fc51d91850aaf3f34fa0a2819a5afc15bc5101e234e0c841c3b35102535e351ff556a667e8dc4e33caf772fcb8d170fb81a5"
},
{
	.path="/usr/bin/setsid",
	.hash="1735ef84e210e64ebf522db6fe623f9d5824a276b5d26e84778ddf7ee55bd623e924149c52ab47587e33cd0948206020b66ef18c76940b0a6cb4937ebc7723e9"
},
{
	.path="/usr/bin/setfont",
	.hash="171565123bc95c0c7df7472e9523899fd34b4be6cf0780e8ddb5e96bc4bad0a2f986a3ca0ddbc322ce189f664628138f34de9668f6431773c344ab4c353626f1"
},
{
	.path="/usr/bin/sed",
	.hash="3fb39e9fe5d09450453c0979886f797b28c51f0a48ecc9a5fb95adc28746acf893828f9b0e9a6c094df1bb53b410c2c1f7e2e45c4ffd1625dbdb9680971babce"
},
{
	.path="/usr/bin/rm",
	.hash="3a063967b0de98fa5dcf582214f6dfddfd11b3b14d4ec90271efdadf5b6046799dd46dff3011c3679a3fa6a2f179824ee2e525d6aba0ac9643c1ec1542e6b41b"
},
{
	.path="/usr/bin/readlink",
	.hash="ec2ce4e917a0fc222979d4a46e83699a66e6b859d7ad12c7d2c71c6e89e3415ff7fba34ae406ebda9a654b4ba3d14f0a0b39004c70d419c388fab15eb8da475a"
},
{
	.path="/usr/bin/ps",
	.hash="b270ac5b8a9ad028da7a11e0f53fc40fc3ee01af35244a4b5d92f50beaf0ca65640fa946bf61872602a7a344a74f2ad5852ec51c2be6d2ded77b3883a0dc3f1e"
},
{
	.path="/usr/bin/plymouth",
	.hash="7c62fe53825b5e04196121af87c4e9abbd894d0966905eb17c2a9b3d5cb35ce6e023b010fc7e8e83f7f423c001a42e646b12ee285b8fd11bfafcf95c4888f39d"
},
{
	.path="/usr/bin/pkill",
	.hash="e4b1aff49609d3982ab9f38ee098533ba2ea4c63eb1b2b2f93b52055135bec47b218c629bc25d1cdd38f8e56c1cd1018880c08621f6f54e6bf2e478ad1d22335"
},
{
	.path="/usr/bin/pgrep",
	.hash="c5467e9733162e5c3d7f9a07dcf5a7092c10d9ba7b7020e89244794449ac93bb129ae0d87d9f90c858b5d62f14ea61fee44cc59c0ebb1c10a0bff0ed3966d11a"
},
{
	.path="/usr/bin/nmcli",
	.hash="87bca35a4738b2fcce96cb5e76b4daed3c1c43ffdc4be9de130115ce6af9f6b693745e209b513ed4914f1f0a7c98dd47cd9620e64f9838ef1d9a82d85fcb1e18"
},
{
	.path="/usr/bin/nm-online",
	.hash="6a71af07fcb232664dff91f4ea8f40fec056d236bead127a21ced0c6cd82da1637523796cd8db74cfcb12471f0d7221694cf48d46df395381cf7213ea6339d3e"
},
{
	.path="/usr/bin/mv",
	.hash="485fe074af48a7743a960cc8890aca402de0c48e677dd6dabb40c861a5c43444dad0b4b57a76c61a065316eb5cbd0669319e613a0f991d55cc0a52b4996b0124"
},
{
	.path="/usr/bin/mount",
	.hash="d2385caade1cd9d90e6ab7a265d6f9fdd459fd9b05eee2703006ba6e6eebd50be2c1c8464c739e363c4fd867af3df3e5987644507c1725fa6ab0588152b526dc"
},
{
	.path="/usr/bin/mknod",
	.hash="15743d75ae57d66b05f68d70ffa49dba2faee4330cc86d0c76f0f4d4db72b9082ccbd2e5d7793e52e9f22a1fb43fa58eb60b9ca5d282af698a425aeb4329fcd7"
},
{
	.path="/usr/bin/mkfifo",
	.hash="95d524dc11f134f3c9d8c4977fc9663e8e72ab40b4f2470ed536acc01381e2d75a0cc8076cf509c5f959e46240f2bb5fa2c377cf63d4cbb06f7bd2f66b24322d"
},
{
	.path="/usr/bin/mkdir",
	.hash="543d844d92c2b1720cf97625633d0514961388d9817ab2ba6e268044ecb4174859403949acc83072e8aee16fa66aa84b6c9a30a40279138e5d7806fc5e6af3b5"
},
{
	.path="/usr/bin/memstrack-start",
	.hash="07a158662b98498e627f8485aa1a2318c39def7cb0edf1daa48fc2ca4043afadb39d258ef8a42ba3895ba84e14664c25162bd8390abc3ab8887167820e0bd1dc"
},
{
	.path="/usr/bin/memstrack",
	.hash="b9ddc84089a8718d85a27bc3b5f07df9f8f9d8a441cabe9090b5f30b8c8c9561c808c3c406a5f38ffc3e0f5bbcbcb72a0b72408d7313dc076ff47f9e061ef7dc"
},
{
	.path="/usr/bin/ls",
	.hash="db63e32135f087504df7fc34e9085c411195b99f3fef8df68178761481a3da7dd944a0791bfb5097a7dd82249bb2acb0b0daea1d1f4107a840452da1296001bf"
},
{
	.path="/usr/bin/loadkeys",
	.hash="3b27b970a3246a45ad6589c0ea55fbec33a3a51227bb0b703f3e52a971ccc0d6cb4aa1a1ff5d06469ee97156320af9caad7085de22f9e501bd7bc7272d17632b"
},
{
	.path="/usr/bin/ln",
	.hash="20d57ff970272a7404d14e6f7d063994c278681682c73a8ab8683d6d2536e44625e0a8703380ad7536616eeb4d996abdbb05b19011dd3a5b356e86859d33e238"
},
{
	.path="/usr/bin/less",
	.hash="126aa131057fad2702f04275465a0b16055219784ead65475a62cbc7c10fcd2c4f2ef0fb5939b4ecb2636d9caf91a3d1256dca4323ebe143c56b19acd622ed81"
},
{
	.path="/usr/bin/kmod",
	.hash="e2a4098377a4c4000421a1084b8f61b677502b7a060bf4252b8c3e6b6bd58b29921f0f4d8bd06bfb1bc5806cfb0493b1698c208762f0aa0942c31da53ab7d32f"
},
{
	.path="/usr/bin/kbd_mode",
	.hash="a47512d76105e8e28fe5e09ad3be776c4cd130de224dca4ea60a70f37c139bc750e5045734da3391bd392731a26842f5944db46326a4b189eb7ca210c6a3ceb2"
},
{
	.path="/usr/bin/journalctl",
	.hash="a033ac3a647cbf490f45b7ebe3c50be0529d99671da0fedc14067c1a6975f2be08f25d029fbef668463ef67fd4d80fa32d7fecc0d6b57790f902d55424b2b714"
},
{
	.path="/usr/bin/gzip",
	.hash="a17bee1441eefc983fd212be611cbf5f942af4410fec37400e8340e2dbef0d19f273c7fe6f7c698513943857864a3c605d8010cd6ccafd833bdb96a7683314e7"
},
{
	.path="/usr/bin/grep",
	.hash="da489e66efb8dd8a452a79302ce753f0dc5a51f021c6d1b2fb1ebcf6effdefbaf037d8a43733b6be2d6714a56b07985ae322bbab2e834c94f0c76f8e8d569331"
},
{
	.path="/usr/bin/gawk",
	.hash="1a5c986509df98c100487a5b6440204543e20000b5c93bfff252997ecb4856c62c16dba7a77a33af5f8da4f9df950a9366f4f92c0da021b229a4781d8b8aa4ef"
},
{
	.path="/usr/bin/flock",
	.hash="9d203693c61bce0f06cca6f6ead4b29a58010fa9f2474e0d2e5af0e1de91cd62987a935ec1cf3b26c052edcc6b041c370fcffe455d9af11339fa65330821e2f2"
},
{
	.path="/usr/bin/findmnt",
	.hash="334854271683430c2c32a4055ff4cd5b53f43fae1fccdb71880059b3228aba8f722389501319108b3c9da8a233d82e181c1a7191b17bf25a07ad06fbc53f1956"
},
{
	.path="/usr/bin/echo",
	.hash="7f62b6ba6f87e8e3a0fae9b5daf27b55be8979c7ce272293acd99a37a856e36e4ecf3ec625e42b749bb000a89444a86e9c6dde63484318a23d63ed013acec211"
},
{
	.path="/usr/bin/dracut-util",
	.hash="409cd5c6f06f968d41481fa68824abcc0e24175a6376bf0a2c3b2461ac172b8771cc7193c0c0669e072357bd4ecced56b64be0ee6c0facb2422394cc13469ade"
},
{
	.path="/usr/bin/dracut-pre-udev",
	.hash="de0a515d47806fc8f8a5200a8d236de4394dd92ea6fa6b8a1b21756445408c7ef6e133b70b0ff7ee52e35da3c81e1d38833767aa7b9a2c56d1feab5b4ebe7bd9"
},
{
	.path="/usr/bin/dracut-pre-trigger",
	.hash="525ef470fe178560424560818ae6f764a2be5c2ec9710ceb9fb9bba2f38c30d25ab29fa645c705db6f00bace9b6de65e8966fe891c59e85343f2a12a495a6f67"
},
{
	.path="/usr/bin/dracut-pre-pivot",
	.hash="62616f3f0a29b617605e5ad796b0074e60c21dc98d90e85be6b616b380c366d3140031bfef673b4a0d70f5dd1bc7e99bfce01e3a817557c042dcee7ca7ae2f1e"
},
{
	.path="/usr/bin/dracut-pre-mount",
	.hash="ae71bd75f29773b64dbbe9902755dee241f93f8516e54bdfc5c689f3174d11e96d5d6f8f41bbe675a40c0c3940fe578084bb8a00e0b3470410f445968dc84f92"
},
{
	.path="/usr/bin/dracut-mount",
	.hash="002cafe9aa8e6cdb3579a5c36a408ca911ecb3246ae364e088d49365347af227c6884245910ce0e13aad7ca163f568af2e9c4b90ab144d7fc33e8341ac01fed6"
},
{
	.path="/usr/bin/dracut-initqueue",
	.hash="ad56deb30e2ee425e153b81ef90b6e1e46e9c813d395c7ba85cb3671d6f34237b5732ac24ff8e8825fc9c3f4e84b5c7d45c9925f7af24b292577656267c8894b"
},
{
	.path="/usr/bin/dracut-emergency",
	.hash="8734e2ac401f8e6a2feb1c5f4590a17fb9e8761e239c346096a1c206f1e2c6fb1b7a7cee3d5830991ddc9fd985dadae34d63795e5146215fae618ff40ea53d13"
},
{
	.path="/usr/bin/dracut-cmdline-ask",
	.hash="3a20bc69f74ced6c0d251ba3b8244c0c6d71ff407abe2171c937ae23ad88f1c21f8b4dc92bb3282a8887cfe71e8d021ffe874b734ae3b60781ec76d1469051af"
},
{
	.path="/usr/bin/dracut-cmdline",
	.hash="a75c88e4c77efd29df71b166a7405406a20ad6df26da520345454c316dfd4b74cbbb265d6eb1cc83c4d364977e1335870d15db67841ccaea2745a4bf7f2a6942"
},
{
	.path="/usr/bin/dmesg",
	.hash="e0844dbe6a3b4923c6a8fb7cfafa19c11befc000fe865e187280cdef4ec49a000622887424382e817abb5f45a71e6c6f0363ca779ec8fd27f9b307454219d1a2"
},
{
	.path="/usr/bin/dbus-broker-launch",
	.hash="b3af0eaf4c9c5bf91401437d68d960c4b5027488a306a96de3364c12682cd62b8685ab552588c9d398bb48b802a3a630fe7523a760c76950ca61eb3e370244e0"
},
{
	.path="/usr/bin/dbus-broker",
	.hash="c884aa66cc49792352b6ba8dcddf7570805ff546614bd80e3246ffa045ea17791d6aa099c438a4ba4c26da6006ff513a87fbf00beafee31e6252ac0837dcf32b"
},
{
	.path="/usr/bin/cp",
	.hash="3ec49238c55786c2f371032a38aa7926695197c9e1f28248e7a045102c22bf8600d9d793d4ed165e617904b603597754802f217070b73c197dfd37f9a7f740cd"
},
{
	.path="/usr/bin/chown",
	.hash="b46b1a8194f781f2870ee8bc73af29e7119b6f08373d6f746aa877b6ef8056f4f53fb705ece653c6b0d7972d5a136430356985f95e67029a2267140aa22956eb"
},
{
	.path="/usr/bin/chmod",
	.hash="fee55ec5d985699ec18db0154383925921b7b18f9db99c404c3eb9b809833434c8ac147a34ce59eeb3522ddb65e3302557779a1e8f33a4fc733fd23c4a0b8397"
},
{
	.path="/usr/bin/cat",
	.hash="775a5f04e1382bc36c5ba3a6555b62347de39c11aafdbb30ac086c3e40acff04370e07465d3e4ba2d865b2888c66e4184fd560fdcffb0ef4277560f0d057e52b"
},
{
	.path="/usr/bin/busctl",
	.hash="4bf67ee5d0d9b1ac89eebc3b2861693c2454f7ea2c2304703be01982e290fb03710a4261afd20dbe8d859a7d8529a6013a77c661dbfa32464aedf620c04d1575"
},
{
	.path="/usr/bin/bash",
	.hash="80a20a3ae25c67f0d450e7684477f2ed862c709d6a84245bf39d3488b80e035c7b6ace048038e76c7f2e9022a3bbcaafc2580e67e35812571019986b9abbaf65"
},
{
	.path="/usr/bin/arping",
	.hash="1e46c6fabb7bfe425359a5bebc136ab0232ca7d97b1da27face335a02a7f2e726501369bea71ed168380c0f85654f240eaccffa1eb92b01f2aa737a85bad0d4e"
},
{
	.path="/shutdown",
	.hash="3fd78329be9db1bf7dcdc74f589182bcbd6a5c098391a65ae05103b586e7a7b8dbdbd32301c0278c814d19a73d687c7c7d19f90174d8ae92a50a850d5c372185"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/soundcore.ko",
	.hash="d34a63f8244ab70f9af7304f142b041110403e3c4d378d0f827461926b1a9a91cfe8e76d58793768463122b7249f9d501eccd69af88c34db9fa55e96b0c2d2ef"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd.ko",
	.hash="13b0d058536592b1ac54a3dd300179b934c95096fbb487aa514c4e180de6f809268aadf000c17d511a196cb3e48ace3e05354f124de3a18ffcb0999a77050ece"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-seq-device.ko",
	.hash="5b7656cdbc12c86c8a3c571c664f88864105f1ee1b3879b7b407cf6029abe613f3d0dcdc6115545b6f28421f701c781324d9363ff067cdfb40192ded84fbc15b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/sound/core/snd-rawmidi.ko",
	.hash="523bda067b1729ed1cd8104d46d394b8d40ed996a2666ec449a0992b9a2028aeca1d95ff03de088ba7304e5ae86c0378cd6638d702b0cf4314923021b42c8ecd"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/security/keys/trusted-keys/trusted.ko",
	.hash="e8084b0b85c904d9a70baf12452ec1d7b78f868c5a427e13618db3da0a3b588fcca0be3ae4f3ec3eb882a66cd23439277759b3e74a2c1eca9acf4997344882d8"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/net/rfkill/rfkill.ko",
	.hash="4202a2402313fa414c348e1b79a639c9ca1a9f590d26d79c6386b168c4252201c40320f9bd0edbbd7a7c45e236774e9e92a1167184c5e37fd528076fc917ba8e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/net/core/failover.ko",
	.hash="68c4aca78a25bcc8d67907c1c47c087ddd09b6abedeb2c2a5cf8304131e0e078f38920489153a0f5c7c86ea59020b58ca15079d7307fb3d31b38d98a581927e8"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4hc_compress.ko",
	.hash="e522489a427e38130417a91c049bd778e399a56935fcfbff41fae085024b7a35cce08e32bb972abe418d0148093a458d88a0e0a196043b7d712679b8393ec758"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/lz4/lz4_compress.ko",
	.hash="13bc6d8c965c6238a2ae46230e161eb91fe363184ffdb1931da7a46d109b3480d9d107f08fd07b9694cbf4816647ca289d7ae9a4016a17ed63196f5ed4c141d5"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libdes.ko",
	.hash="a8785097c4eb7c889faaee85f9a77e7bfd9097c3f49a6a2b2c5a2f2015ccae5ec394997d45c6fe7fcdae98e35208e11a7ced64b02680b1dfd2ad992f1b1bfdb0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libcurve25519-generic.ko",
	.hash="c8ab61be2b148e7ef4672a8d58498dd363f57c76414b5b0f9fe038e55e6ac6246950287e7ccfa3e6c5aa5a8876d1e618c023e5ff8a701a8f977039f7b998c42e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/crypto/libblake2s-generic.ko",
	.hash="f6f9c8c7f9fda6dc4663b0fa7c6bf7ea7f4a10dece60360367eaa30ada08f77c11e17d1645d1596b5e8b0717de97f6276d217de0712f2521ce63ea7d95019856"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/lib/asn1_encoder.ko",
	.hash="39ea8f72902e285f45c7e196c1e879a2c379dae177d698566d7487d79afed6be1acb9bdf5afb718f2af949cb259a1ebcfeb3e1fa55d851ecda400bac0220da16"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fuse/fuse.ko",
	.hash="ee41d9a2b3dcf7d8856eda1f0787313b7189aecf958bda628c6368a4ac10eba77ada2b79365775695f78a80c5551ebe77bfb0149a4f2c46a9853b3c45b234f26"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/vfat.ko",
	.hash="2288dfc3a9bc8adc580071fa858a742c98b3457057985dc940c44e7b496e3dc80c4e5d938919f9aa46821c46ce1c279b3cade07cbffabe0de2c92a5934d9611d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/fs/fat/fat.ko",
	.hash="cc1afae27f9879cb2dc5d98c118a179cb188a39448dff3dfb92e5c008093799edb9cb8090f49916ffb0114a69409c4900eae313100b90aa1efeee9ae5fe41d16"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/xen_wdt.ko",
	.hash="4bd28558e8edfe9723d8f47bf28746a2aebea308d28a9f85f7258ff8f1b734dfb5216e9daa6ec76730d0d71867b39a792d664ecf3c53523815ba31e0349daa7c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdt_pci.ko",
	.hash="f75d495c82f73b22e0e56613416d2b105f2f4d5e32363aab29bb16e30648152d2008fc282766da9a59249f08210778dab8b71277741a7346ef211da16fe853d4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/wdat_wdt.ko",
	.hash="5fa59a33281ce62f1bc55125fb9e94c9c1c92ec9b8934d619c7dce77c6a1ee7c066f41dede95b58168afe84f75cf11c9afebb30f18604c2f238c06d396faa868"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83977f_wdt.ko",
	.hash="5918e4065b17e2a55e4c666a9941e23dde2db184f7a59f31d00daf004dfe080f5cfae36a38df9b088799fd08fb05159a8eb88123c59ddf1cc322c731dbcd6b9d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83877f_wdt.ko",
	.hash="48fff15b532cb8394a113238ad5d7f00066346d5090e04e33c68787fb7399222ed1f8b04f3e442cdedc8ed173c5870e1ed0912a9798d5af803e576435074eb59"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/w83627hf_wdt.ko",
	.hash="f74102b7dcf398cb14e0a0bdcd90ee086a23be2afd6b7a82b31991b0bef71954004478f3903ff0665d9f272105ec9a29110325fcea7019b71e27a739d59cf836"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/via_wdt.ko",
	.hash="eb9dcfeda395e6a79ec5654f37ffc2b1a05c3ae940da52bc69fc0ed00a23e6e1196fb2d63eaaa9439876a44696a61d69b37bace5fce49e4a6546b59145ac3b55"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/tqmx86_wdt.ko",
	.hash="1dacd22594450d1b72a18bd33c84fbc163baf84bf45c51a8f5a240dbe1e983adba36a43867cf63ca20246ed71806ceed66048c3d5e3fcd2bd64cbaaae67cbc32"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sp5100_tco.ko",
	.hash="c9875be535e1b1c455fcd065234abcdb51457c6428398d7d478323545a49ba116199d3f7ad3253982fb4ff834832ef4d788c13875d831f603375269ac03de9eb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/softdog.ko",
	.hash="f0c25e5d659eadc806864b5e9560a6207229d7f9818ecb88a39524a1f7cd69ce51ee349bb31934a63b558a805c7bb1471d5487f0459c20170a0b3b09f595a0eb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sch311x_wdt.ko",
	.hash="ae9cea8beefe22fc56b5ee7be823ac136062c2218194ac008f082f5d9b753fc2f8830ff90c938cb6ea3bc58d56d2cf120f3c3901b17b3b7398502087d72665db"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/sbc_fitpc2_wdt.ko",
	.hash="63d1ca6b6d87f326399d56bd5f3ab7beaa0aaade29239dea77ba5d6ec4b4f7b99d8d363f40a01146038d9a4221dc5e1817d44de52475665bccdd08fa3032596b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_usb.ko",
	.hash="9080b974afb30c293cb610f3c85b18f5c249dbc9c57cdd3dac09f0076aae4c003bf4fac73f6242c0af63730c2d52a41c97dc35b8df26c25173dcf8bb08744d1e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/pcwd_pci.ko",
	.hash="3ee2e57abfe1ad4b05475e38da91e3a819eeb2ca4cbfb5d8af55d844ce0c49a48a6b75cd0ac415d05598558c3aeafa1360f88deb92ffbf157bf42f65700f2908"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nv_tco.ko",
	.hash="9ead5804cf6985e7da6c153f3ecd4e0298937e2cdf9c9b3c82812ad3fb27f8cae94eca1da5d43d056e6cae54bd3d087ddec2f46594905271f6715fe1c95bbb43"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/nic7018_wdt.ko",
	.hash="d00e9c8eab7f7ab7dc2e0e61e8233ff1007d73d29fae12d548ef274e45753055019aed5cfe49f262ed2d9fd97feab1a4922b73b8a70c98d0f3f33b683d2d3842"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mlx_wdt.ko",
	.hash="f18266e3dedcfa0258e877b872c3169fe2add82b3bf1e1ebd7d39cd52d87cb7ed33865227ac41901a9d3e38a5c9eca7e3e50fa5420a6d12b1772ce20e02eb692"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/mei_wdt.ko",
	.hash="9f66ad105ad7b7ae4dcc66bd51fdf006e87446dbf66eb79b6baa67d235c4b3b34a586aff2c3fefcd46a441612c2efa76fcf43c5d802a86f3fe61071a4d32127b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/machzwd.ko",
	.hash="ab50fcecebae2b4a44059095fc36f13d031295f51a2b2a550d94f3a402d7d102d383a2fcf3734144582f9cc01da1e526bd84edb4c2eb7619b039300c065d52d0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it87_wdt.ko",
	.hash="197f12fe0e56e3bf0ae3dff150784243450335f83a9676fcff75c69df9099f0e48f01f3861ba9b2878196251f0eff8493d429b09d4019911251956b8a51a480d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/it8712f_wdt.ko",
	.hash="c195a1f42c449fa44f7a33f33fe59136bcf7e6708a8faab8bd6275474d0b081d332dc67a9e73a48384df946c42cebe44015a0f90d7067d2863e9a5365f77a928"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ie6xx_wdt.ko",
	.hash="b6a22bca761bfc8cd3966228bcfdc66f9961416de9c5c3990308456c48a375354ccf862b325b8abee80fc0bb4178c0bab79b1d93a177cfa8854cb535aa573a69"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ibmasr.ko",
	.hash="3a34f89995158679f7389c60f9327cc910d19817bab0c6c07a469e79bf429e05151c0c7898544cff96983034a955333c675d8846c44b7ba3db138b7156ba58e5"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/ib700wdt.ko",
	.hash="5d72e2eb924a6570b786afa6bf571aa1c2796fd507f5e67be6431b162dffedce6d21a1f4369baf8cf2c017289bb85393a00a539568fdc9e976ee8e607bb29d6a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_wdt.ko",
	.hash="97ae324ba613849d0227a529bdab80067014ce003bf77c251f6ef97cf27395f9976ddddb35af04cfec5adca24d1981c30002272c214843cee7e32e2c6796eb04"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/iTCO_vendor_support.ko",
	.hash="6fd2f4a8b20b25dd1c1d56fa3cfa66a70ea1c9832ad474a06bfe5f022bc559d75e58c2de4486aea7fab8502e4374ce94ab65937628bbadcb64822150ec81bbdc"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/i6300esb.ko",
	.hash="5a19d680ed18bec9ff25d935b423f8d39aaeffc39775548bb26cc595c7db7dd67cb4f7348654edfd752a4c556e83e33bed7bcbbd2ca5fbc60390cea00d720c7b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/hpwdt.ko",
	.hash="3142ce3687cb271f238b266643bd03076bfc106c789c72415bb3b89f6e4c0cc20b0d0c3c8657255b8922bb695b079fd22729084d81c771f0542f6a9342413653"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/f71808e_wdt.ko",
	.hash="01428ae7547401dac9e9f5beb23a797911fe39ba34f949268fe2f0553ece5c44b5c1214367c71ee7426fff287b24dd81b23bc7b0d7965089fdc25b60124e6e59"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim7101_wdt.ko",
	.hash="f8bd5a3905df1a3535b2d2061fbc8a7bd0d6648d7eea57d0959b29b310cc9aaac616b0fc28ffb42799e709e5c33fe21e309841f1ff54013bb2bf7572eb39aec7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/watchdog/alim1535_wdt.ko",
	.hash="0ef54892e564f4edd5c84799dad991979217824c4764fc29ca15b4ea18c0a4d369373e775e7678b191cb08826de757da1fb4bc8f892667ee680b59f7fca67587"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/virtio/virtio_mem.ko",
	.hash="8ccdd309a44a6934539c6f6b43853d9234a886cfebdd858119fb4ae3e798db87afd2674d1a815b7538cbbc24e90b2bf7919e6fed88b6d980876b5d6d2f4fc5c6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/video/backlight/lcd.ko",
	.hash="b8fb2da85a6666bfd2e6a6ea45f69dfc02136f751b2a850f53358de9c09adcbfdb02f23c868bc5bead15b8d7eac5db88eee2129a6b9e1dac482683507de2e3a9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_ccg.ko",
	.hash="fa6b1df23e4247e61d482f96feb8bd7c86405d4bc8d7da3fd4d5c02edede691bfba00f3c99c7e07e9c8db5844083fa21d7e83f5b2dd57ef63ae3b9281019cd0d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/ucsi_acpi.ko",
	.hash="ffb2868dbe72ab45c63951b4ccc1f28d6209bf03376e31280ed1959f9deac808981c4a84c4b3985d718a33bdd2e9e5d8da91f5c2a81c39d94be16cf3ce52c910"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/ucsi/typec_ucsi.ko",
	.hash="e3029e1f0893e640d37452bae1e21dec7a7c6ab6e71a2781b22b42cbe50c89f3e877a0106e27de8e39ca1ab439d4cdb7293f482fdeb463bb8913fcf7dce94309"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/typec.ko",
	.hash="ed31583db4f06275d394b9d6df3cfe65d004f64f417039dc60f94f3e40c1928c1216fc756fb435d358d5e7b3611d8b52c499450b25814ae14e305938bf27e569"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tipd/tps6598x.ko",
	.hash="8cf9bae5261e473a73d162e9faf03f5e839a97340c6598775e3291720299decbb4c98a3b6f44735f6a2de6faaf61b9b6b3c8036da4f87591e6619984683cf15e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/typec_wcove.ko",
	.hash="c0cada096df73a2c2db4c1fea922166ddb935900c7c84c8bad5ef5244cde0f3236c8d18c27007e7cfdbd141d564ad0e4af0e4fce03375b4000c7d9008df68c1f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpm.ko",
	.hash="9a0ee7d9a25efbb3ad03b26cc41045e207699bf8f61fd21565e37bbcf8b615a211a5c8012b6b6d9bc84cdf969968931aefd9fe54e7949c703068de2cb42943ce"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci_maxim.ko",
	.hash="07f8930c198db5e510248a23490e4b1240cda66ce90cef7cd32793cb4ab371276d1cebb13ffca861f39842d47e40f6b671f29a37309b80c27ddeef36be353dc7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/tcpci.ko",
	.hash="b8f255f4bc13e392cbf220ecf6d885123150bdc825556d38dffe31cd81687519b5026e333efd3644204a82dfe7f104b219e027b4af609be6ceb4690d0a66e90c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/tcpm/fusb302.ko",
	.hash="4043170196d23e797de4e80b4987cabb2dde6f7e4925703732291740e25844da43da9575be51ad6392d1672495072f57ebe7a304ea9189c09a99e11851117d8e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/stusb160x.ko",
	.hash="aeeec72e5bffeee6387012a781e9954edffeaa3021ce602b737c5d7a6c89f9dbe96fe3dd962852903eef1a42986622d378bf6459345b3c70e54db21e0c173aec"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/pi3usb30532.ko",
	.hash="ee771f4fd76b81850fd15c647538a71160fd1b32028dc78f0d43ba5fd4e288fc917969ac3af11fe5a273cd9d0ab4b1187ffeff83acb6e12ebfdff887c125b356"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/mux/intel_pmc_mux.ko",
	.hash="40126cc88959a78f339837aa5c2ac8ded40615e193701ce3113df848258887ea3b216bc8d1131535701ba5d9b6773f95573cba5106391e85d052a0c37d2161a7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/hd3ss3220.ko",
	.hash="e14d7d6d81209ddb2963cd120e7a224b83670cfa5f9c8e97b99e33ca9a706bfd17a69aa3a7be3ce725518fdfe04392ef76841fbce0cac77ef08b21b7a5817d34"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_nvidia.ko",
	.hash="8a3dcdf70831614f1f6ff9588ff4e20c6829c7b5fdb13e3c1ccc91439cdd42aa0b5e3b319855dd7ebcfd8dbe74e02dac3dfa09022dda3e4b3a9c5aa854bea248"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/typec/altmodes/typec_displayport.ko",
	.hash="8a525c9ec7345905ac284c92c8eb5edeb66bf53d73c08e3a7b0402a500dce415c706688a5592fb6ffbdfb04bccdb4d3728f48606022401160745bf93e14b183a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/usb/host/xhci-plat-hcd.ko",
	.hash="d49cb2a5e321f91f0a50d811ac80fcfc38fb34c308db44d4dbb4de69f0bb486a756e32761b6a8e3fac1f415b08a4136fa65aca6f0ce7ce770ad0ce37d9a4e7cf"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/sc16is7xx.ko",
	.hash="892f3d4d928fb3470bfb2910f62c806e63606f2026aaddd61838d339ae4ad2065a052ea38b79e404d9fdf7dcae2e05d2122b290375edb5dd6c16a363a2b5c554"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/jsm/jsm.ko",
	.hash="3907775d3c031a3ae36e67cb2db16d78dac69607cdf51db64930217c74269476c07e3eff3b4f40f254415d3858bf3d459505e68227076d47b1a2ee0b1cd310ee"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/arc_uart.ko",
	.hash="d928105e40981e75d0c0cd1fbab5c778f896a65573feebdec683342e074a0f65941341ba221e3022e93e4fd94980473456f28dde633d556029d6dd76adbb08d3"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/serial_cs.ko",
	.hash="b4ebe0f01d46fb43b0371b2fd100100c10c8c6030837731477c290254943da41b959e4cae1d92526a9949dad2d5a63387cecc0f4c6d303d7d402f5e057e25754"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/tty/serial/8250/8250_exar.ko",
	.hash="7588792bac75793b500af54ba107508ea5a039a94c0537fd668624d52074522717f302177fcfa08bef3af621dd1e9892283f84ad574fa3556f8b904dd951d415"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/scsi/virtio_scsi.ko",
	.hash="9506744ca7bee43e76b229512a82fa247537e7428be4251d7d0d721f2bf70a1a56bd5d88a5d17610b5af864cdfaf0233b9cb31947fe80fd770e1efbc0fbbf11d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/wmi.ko",
	.hash="08ab5d51ebd9e46617b9764bba9647ddf964d7576817de6ba1303a157a89402dc93db18a554e4aa50efa1486f77f81b3e18ce80edb1b69ec48d5a106ed4ab7a4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/x86/asus-wmi.ko",
	.hash="d3bc4b8ae78911ee6cde0fa181557213b47cb5edb523d36bedfb88d03cfe0ffc6b9ccb9eb989d75021c2bec1c57a1190c62e19391397dc47952a16143d485d03"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/platform/surface/aggregator/surface_aggregator.ko",
	.hash="9ee1cc191257ff5cc746946aa6f5e556b9f35b528a380b45a155c9fc521da2fc8727235f915ebabff085a57105e59fe95c94de01ccfac702efdc41c907546ac9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-tigerlake.ko",
	.hash="d7281d5f3c9cd590fe7ec35d14eb08a87b567cb5a75bcd18d6d3b4ce5f233def71709ca77e1fc0414b25036a1258bf20ecdd32a345a2cadf2a00ab5efe5205ff"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-sunrisepoint.ko",
	.hash="1a8105e618542de5d7d50879951a961b4d2c6ef0bd2c8a0ba9d0c216671ffc997e8a66cfbbe61f81013fe173a229f8c77e4a42a5d163c4c6cb1dc34d60810ca4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lynxpoint.ko",
	.hash="cb18901edacc582c1b731c8f92991863c56bb6fcb7850a8d57333d4a2e01debbb0085b2d5217bf2e20c1777540b29942e554bbfbba668de7538f41b0186f2896"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lewisburg.ko",
	.hash="233a5e8c47bb4f7e7e290aef642191acabb39713378e77c9a7a229444f693a8430a111a7329472ca3ac473255d868e10be31aa852368bf60129caf4ad87d5a77"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-lakefield.ko",
	.hash="5565b9ddcfa9bf1e5e16403cd341c8fd7fcb39e5a5d2bbdeec58187866bcb981bd28ca8063406e994433598148ec12f34b046643e52ba14f6ca5d797efdce73d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-jasperlake.ko",
	.hash="bca1cf8cc099f69ebe28edeea5d667bddec2b18e513de16b9c763003c44e3facd82477d69be6ae923288c6e1994c2423e55be98a09cf1e5aadebcaa57792798a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-icelake.ko",
	.hash="e88546d4ccd4d450c8db85acbe350347d644f1490ab7d021032b31a9eadc0bff79eaf656570ab680294d643b45818295cb947a44560a40d62dedcb64d35e5b8f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-geminilake.ko",
	.hash="5c2b9ca4061ea89736dc950b9bb65f04af4a379c3fa1566029aba86777a103826d19ea325d20636bac425cd9d597dc7c49d8bd888564de0f96b57cb6a96c20de"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-emmitsburg.ko",
	.hash="b1343ab8f78aa9e9f85f261fac8b6f435d96928998c80834e4c2a33c2f8415c61bb4d118b4c893e20832625cae69cf72fedc493de0751a3d3632d74a12b1269f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-elkhartlake.ko",
	.hash="9b8d893388d16783f12b29611054585f7090fc0e2aa0cb2bb443540a9da7a622eba7edf7078cc50a8ed6d641ec540fcb834459f171d21c0dba048eefd518247b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-denverton.ko",
	.hash="8deac601d31d5a87bea8877eb7c8031ddeaf98f20500d552ffd71c0a3715536efc470741398252534f6cda08ddb578a0bb221b6f4c244072aa63d3b63ffb91e9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cedarfork.ko",
	.hash="02fb69ca44500e0a8335428559e803cc4a14148e9fbee106507109bf14c51e138baef06e78975f8f180d07e1f6f76e9095c0dea487830d68b1a9461c4018d2eb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-cannonlake.ko",
	.hash="e9b5c034b04c856a1ece72cedd32e56bf33a01aaf8b5c0cae3766fbf86a6f62a785691cfd057e47831a6eeaab2effcdbd469a5bbd90a39bc43d4ff8d505c98df"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-broxton.ko",
	.hash="b4f4ba2a965709af73637577bab9c526f1b79202332190505c20309c1e58c6f820c3802adb7527403137f2927510f44d3c4a507651eb3eb8e241859f012ec22e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pinctrl/intel/pinctrl-alderlake.ko",
	.hash="131616658ef5563f40b5e45de9962237753f61e4b20a256fb4431853ceed228079ba4427190c4bef0d13592995a2e1cfa6ca6f00df6a3f3b9a5af95a5d30cff6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/vmd.ko",
	.hash="fb703014a5e9c5f45e907a8f9f2f02a88b89fc8a381ac4f501063ad35e211e8e72d14a4d70e9bf08d6c7fb38dca96c05d69eb34c75247626411c9f5059f0c7c7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv.ko",
	.hash="30027a739d4eaf5da584866fe929230ce1d09f0d8ed77c083655edb1881c9939b178209c37d7ae2c06fc42637020a79e4bfe2758ad1ba47b3cdfe9edf910af9c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/pci/controller/pci-hyperv-intf.ko",
	.hash="b8dbd88c80722e6eec114d3627f7ed19176f325f9ce3231ff818709a39a97433d50d9ee4ef3e8c3020ee9cfdc5c22f873578c12ca7d7fcaad84fbde89ae22385"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/virtio_net.ko",
	.hash="85e79623d6761f4011a47f758d9f4bcfed14024f9626578cca87dee1f1cf5d51ee17ff00487a68d15c33e544f06ccfbb260f38808872af6b0f89f1275851b086"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/net_failover.ko",
	.hash="0bb95ba73ff1c54833a9ff347a4d42d067e15e2c284190610c58a7fc069886fa3e0bfb59530fb8e43e8d39b07d6fe3195dc349e5fab2fd80a761cb19cee8c071"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/mii.ko",
	.hash="e20b07365848223f1910669069c7a421159458e17a9eb5dc702e2b186310b70ebc0e670ddac080860850b896195f776de9d6f13bb2e09384fe5e87baed7d971a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/realtek/8139cp.ko",
	.hash="1ce57a10a9e462b2337e4280fef39ffd697cfa2580c3cf7479e9c9a15990a2ff68c58b6738524a1550461c59f46c18088d21d5c5aa7c8a8bcfb392addf4a2795"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e1000/e1000.ko",
	.hash="442ea6c77432aa44a86e7703362e29c45d8bba1a09c9329c07c0b757dc9fabcbd0645ea73092e96623730c051c9bc09d1bc4cde4685e4bd0aa34d6f1960bd048"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/intel/e100.ko",
	.hash="deca83349e8ca596b11d3831516065863846a3bb9317e88f898d7b885a1d09249d16eae343b31d5c5852a4653a18635029fc8cde3683f337a765b95ecaea169a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/amd/pcnet32.ko",
	.hash="ff067fc9eae79170761b8f3301c22572785da5d810af510668f45619fac83a9a0b271d3a150d68c8067a2a71dc45d8cd6c008a92d587f9f408a6474b419e23e4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/ne2k-pci.ko",
	.hash="965e55edaa9dd10a92e6f16858ebf638f08cb63caf745f9c21062e94ff31617ff48da5a01199abdfa1c705fec16d680d6121027f9cf6b483a69cb9304e7d9bdc"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/net/ethernet/8390/8390.ko",
	.hash="32c279ebf4857f870fd0c740773e2efc6c53a77f5334f434bc3eecc6c6935f034ef5e830a7961fe3e0a108c67f10271bfa7b6623d5e082c30adf41668afa5994"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/misc/mei/mei.ko",
	.hash="2b92b2116e02243e8fa75e2ab03018fbd5d903790d51e71f05ae63c2b6508bd99f4568ba5a4ab75472639d2d24a7a67a974642e527e95d9beef448e7ee983280"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/mfd/intel_pmc_bxt.ko",
	.hash="46b04f2e027702ade56ad11f6339a9054a04a256e6fd893919eba00fd9eda11fadeaaaaf9bd283abe2e49e40bae841c26c31e91ae570ea2e923f01133d373492"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/media/cec/core/cec.ko",
	.hash="1a3c4da9c969d1541a0a3990a91828f7b853e253fb25dc24719b0403d3fc42652df7d801032657467b6f21bc0b915d0405c8d068f895fdd2a3764e76a4f95775"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/sparse-keymap.ko",
	.hash="ed20196ba6d3ae86c2c4bb82673c679c42f79c4902dcbaca0051066fb4388b970e3934993fdca3792fb91a891c116dda81ddc7640b2b72dc7cdc7c8e49fa79ac"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serport.ko",
	.hash="4d8b6a81378ad312e95d5fa2c35183498aaaed1029fbb0db62b9ae73d778894aee7cf9de7f2dced1de376d5df3acece6f3565e533699087057ea5dd167f7c435"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/serio_raw.ko",
	.hash="95b38b6cbb379a7c6ab3ed60f6f4924abe904b26d85aa3ab300a974a248ee82dd1541cc5cca8add0624b5c8e541315bfee41d8a3a7a4a7d66194d3838b6c87a7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/hyperv-keyboard.ko",
	.hash="9e66b767cf37cb1ee5f777ce0552ef79115fe16775a47df3579ceab15661e597c496ab15562ab829ac9278ba4789a78d6c71afb1eef308d2d030f932baa7a986"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/arc_ps2.ko",
	.hash="3a12b2c4874757b2b3e9b7702cf7b01ea026f5472df1ac29dab2d7179d30c144a6e951d478c0ae30b6a605654418c645e0dc393947b5e51dfe427046bd5bbb54"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/serio/altera_ps2.ko",
	.hash="fa2f54bf4c73efc65a1d3a8f1073c48b24cc24e5dcccd0653cc67610b64bb7ad88107a2da259801c9205b5dc6c2ce460262f22aa80d74cf1c1a8081f8cfc8c69"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/rmi4/rmi_core.ko",
	.hash="e542a7011e26c9ae2032c40dcc4638a8969b2b69c08a4c304079fe589e310bc7f087f20ffb5e9267bf9e63a6c05b70aaab62c879f8f0b517759ee22e940d636c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/tm2-touchkey.ko",
	.hash="a14793e5c180d74490658c5c18dfee4bdfb426616aec52b14cfb92d746c3c51f830985933ca0311f658b26d728c47152df8dd794b34629cece31d5b5dc1e4c96"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1070.ko",
	.hash="a8f1b97fd91031f740eae84b705890fc9a4901ef1c14208eef2232310d08dc684f790e8466dc81d462e4d0726f774cfa7104f6f52b7aa045257fe66afc449f2e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/qt1050.ko",
	.hash="87d8e92877be3ff60d695a84c8c83d3f58031ca64f2e4b7d29a981163ae3522bc64e73fbaed2be188016af8fbe406545a56582f622ae98350b78da1078c02bc5"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys_polled.ko",
	.hash="d4e21175f8e54a4c4afe202da5e4f34aca8c6621c89918feb9f073ecc064d5c8ae7bcf18430e0e3877f0ba5e52304704aba15a7af2866af4a81a90c15ef1b30c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/gpio_keys.ko",
	.hash="ae96cf0a997595b092b51d1c19d9d5a02b1e62b1238839a06b30570687db08f1f9147ed4e28ad952905617f90b07176a85a370e88693b7be25e9b83ba1975b25"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/keyboard/applespi.ko",
	.hash="9e5c6e9d462b1739a2d91c4fbf9bab7838450bc8f7c574c04f84a9bc7cf3805955deec3f5708353e688342f642cdcfe9dd618c9b0ba6fc9cf35cf1087f0f821f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/input/ff-memless.ko",
	.hash="61997f9c9d3432666b362ac9a13b8284a6bb247365080897aeb295bdcd090a041c7572bfbd3e04b14fd6caf87184dfbdcdd4916d5b330e1cea210799ca1b4884"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hv/hv_vmbus.ko",
	.hash="cd4173427234b23ba88ad097466992f8f1b298873c3451ea3695855705ddf3faac317a7404c7cb00be9ec16b54302b9331cb7f6c7c268c6a3c3a9b71d5f6424e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/wacom.ko",
	.hash="4ccf9e4082bcda5825f32007801af13042e7b1224c5e6daf53918c7d23f0522c441e3196c9b31f62718c51ca9a137be31b7b9896463f58b945b0f46e3e2e0f5c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/uhid.ko",
	.hash="83d86d6717268dd4d5f09ad801020e33187c76dff6a0e14e7cdf4437eb28e04404992cd41bfe8410773888c81a95cb4a745547f3dcb27d29697c70595e3ec2de"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_kbd.ko",
	.hash="6f8e52cdab375b12bf0ced5e3e650366c1e0afd4e262895d095f62317ccb0fe0cce14728353c1615013997471c25e04103a1a533cab0fe4452b331fba4ad5a19"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid_core.ko",
	.hash="a3c11fd737e16c64e01cb50187f8f22360910b22934f8a982652c2d0fb1cb873209c3bcc4d16539fe90873db4d4383c2663d9b5a8a3430a9f942455b9ccc2327"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/surface-hid/surface_hid.ko",
	.hash="ec5c4635a4802c45d6349c670006d5c844cddce7476abd2404195bf63ca328400eb7d9c6d7239768a39a0147635ffd593d2e4740ccab2cbcb50c25469a0714d4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp.ko",
	.hash="da51068a4dcb61ea8a0ecbd0fa52fcc0ec373f4bd4a4fef6a6689a128ec9b91988aa487cac8f9e0dd0702aee945df07d14f98c26d1bd4816af2977fe82a7920f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-loader.ko",
	.hash="5c48e535bfe37a017401efe02d238258e52f132cd70a36c0325045ce7a6f454fd87f95e8828bb66bc93917ab1fb4c14d9c894a861ca623715a2d7b21a2438ad9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ishtp-hid.ko",
	.hash="8a6400b245cd32ce4872f706e2669a9868bfc555deec76f8c1ab7f485bd0eee3c4036d7ba3ca538ff7cec7187fb9dc89c0bb03bba57a7bc8935f2190fd837477"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/intel-ish-hid/intel-ish-ipc.ko",
	.hash="7812ecc460dd88cf1b24bf4746b04356e93f37007c384f54e9f122da9f741a72e213fa5cce159d9ae99fe21fa9d0226977c3393878eca1e0263e1b4c9d2213fe"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid.ko",
	.hash="47cd3e479869da62460c4825be9994f3cf87e8a096e5ac9adb0fd20567f2a00a48808a43273a356e93fea5bc0a1acbcd4cf46865608f2fa38ad68b560a3a5402"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/i2c-hid/i2c-hid-acpi.ko",
	.hash="773a06a0db036446b75f57d5c214a740b38fb5176cca6aa77f7b62b46d18b5fac270034eb90f730c4d68c7ee19f4d6261bc1c0d0330babedafe2fc5ea1afc461"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zydacron.ko",
	.hash="78119c0181e3bed8de0252885bf9bf44103b5cc162eec1b23537ef7b211ea36f5e35d0a32a3b9e2f636dd69a1e9ec3aa1a2c7b4841cd12a4f10e9d03f4f50b24"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-zpff.ko",
	.hash="fc95f065f077332bd944b983b1e4e1551c98222cc7faa782debbeb08280cb4d2c50452457bfd1972e49c5c4199dc87f3c532afaf09e93f79fe320d81edb8b733"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-xinmo.ko",
	.hash="2f10ba4c2127b7f667ca9a5634347a55a05a9f72c3d5a6a113b94d450328ab189472c0dfec31b949a44700954117b9217e343cd7ad1ff775a44bdb88fe0e02c7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-wiimote.ko",
	.hash="4e7ebc1c90a643d8e83c38dae9ac7bc8c7595b08d710dc8a971f640b9bc48fbcc852676a0b7769afbcb80a938d63bdff168f4276e255828dd766d51f2fd4844c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-waltop.ko",
	.hash="c37dc341490e8a13b1684db59e4bcba3a0a378a6de4a401ece6c205fc60f2c6aecd1007a62dfa273c40d7219ab898065545045b1d4e62881b51067dc44c83814"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-vivaldi.ko",
	.hash="f00361a735a7a63145e3b5844b2409f0a591840b8a2f1b81378ea05faf7e0add0fd4dcafe4ba73ddac937c96c7faf7be21ad6c69147d0e189a6e16808b6f3471"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-viewsonic.ko",
	.hash="e1c309f3e643f0c24f15f1e499baeb3bcae838970557155a0aaf04d256fa5042fa103044adf2777d640f9794c7d200b32136caaf80ea2ecc85ce4991f6d80fd0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-udraw-ps3.ko",
	.hash="1fac83949cfb70b40a07229db8bf24272a563f4da7ecc552ab9c23a4ab09036ddeac5022c899393434bf370a855713c7cb4970bfee79ec6f7e711f0e7aa4f31c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-uclogic.ko",
	.hash="5ae27feb31dd31a5ae398cfbf20101ffb8ca86b96f52ce5dce3e1f056dcc9524d5ceee35f79ef7a33d9f97fd9653df5dbcc549d3dedb08e6e26589e4afdddd72"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-u2fzero.ko",
	.hash="18f09865ab2b1f1d8c1111ca9b8d2abbb13aceb0559059823324834d18223e73054b8424d50d3093bac777bc3af48ddabee636b7f3f373c81f5f15c70c59b6d3"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-twinhan.ko",
	.hash="031f9e6f092bdafcdf4fd4dab1ea1c4735becca3d8c682e7ec9716a56da966f5ddbe9ee89cf81fbd7a4df3d13d8854c0f1cea96a0b27bdf7fedf081106ea0d0a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-topseed.ko",
	.hash="80518de158ad22408664abc3adf2e9f235d45c65adaee18365e65d8731a2b8cd014e4d2140b9f2d272cc3e4a6200ecf10e7768738040ad01cef96502048baaba"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tmff.ko",
	.hash="7ff437c36c4a40fbd53e7827155748352909ad92821df462c645bb3f5fc80d5ac0c4ff24527507bbbcdf9206fac959b5a79bef0a2ea34df55f46a7f0fa6c63f7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-tivo.ko",
	.hash="b8e81720039bb86639eb2794ebc2a0c1e005048af6a66a035289bd69102c5bfab684cf82970d62685e0affdd1627aa00c606a4d3e3051ebc1e8cc9420dc97c3c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-thrustmaster.ko",
	.hash="86181742d29436f315c0c44734f85715603ed8da10a744adff51e2dbcac19916b7758e6227d96093fc37de89ba5645533a1bfbcc0211f69b5282f1fe24c6b89d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sunplus.ko",
	.hash="8373740c018d27e6a1bc7b00e7f3fe650a872bdd1172ee093af600073bea036556bd1ebd20b22f3cdf427062401864ed6597125bb2e71ff835253a4226d4e4d6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steelseries.ko",
	.hash="fdad7408fa927f0b7a89e1697a5b9af34d17b19fcd3c0a5f27f8f0fca47d285342da9e110b8baf89479860ecf47ecff284cd8594bde54084c0b61adf02c42035"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-steam.ko",
	.hash="9f706f35794adb057f25de6a7ee55892223da229a22ae5412809b2036e7fe8c58802b299321cee53cfbd902e6b101f9b8bed343e2112a3bcb5c2c7ff003b6e92"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-speedlink.ko",
	.hash="c2c19d1a4675d22324b85a49162d2c758d6755d0acbff91c793673e01ab0a2694a9ee84066a672999da581e50b49b6418e52157a8d4fe1c3884983d333b35ee9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sony.ko",
	.hash="b906182d341e77398b188c6b9d76a6d7f8794650304c08dac3f8fefb854371c7b2fb574c836ffd8c2fa900b9f20d72bfbcb401933d0ca91257f8a5f118b64fe4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sjoy.ko",
	.hash="2cd22ccfc3b72287f7c9acd27c922e4c0ccbf6c758c2a85718c5c805b18ebfd72cacce6604ee0f5911e5a7612f1572c47a46c98284bdc679cec0ff3d81df16f6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-sensor-hub.ko",
	.hash="97fcbe80a20203abe24d26c150fe44fc332a894b47484eecc9478e5cdc81071731f19069aeeee813039fe1f18518a0e533e3cb1f36a788a94fdda31a959495cd"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-semitek.ko",
	.hash="73703692eca956743a12a8accaa7f1609cf60de8183c9e88a9ae385895c742688c3195d6670de3e527b23ee212444675affdcec5c63d69d149013c5ea87d6a7c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-samsung.ko",
	.hash="aca9df61ca76b7f3fe525265e24534a697edcff3fc224333dd5c8354fdfbe3ac0e0fae3d27708ae7a0bb1c190bcd3e851068901cbddf479ed5954c469b0d7e3f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-saitek.ko",
	.hash="f615d4155be0bfe65504fdf895ef00f5fa70739af773b09aee574fd1210a89a0cdb98191755f60219a9a08cfae586e36691f26e03b9fea93a9c982ebee5861b5"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat.ko",
	.hash="d29e271fed4b9c71b57c85063b398a6c0e2c31efe6e686f3fc44501c51f4eb78b41c9528a9254529e92195751142108abcd90496556030ab4fc817c24f2466cf"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-savu.ko",
	.hash="79a5fe04299dbda57112443a73748fd031e32300cbff0736684fbc1e3a206222dade69f46b244c947a6ed7f48281d48a19c8d0260f2ef4ebb238855f970f2c5c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-ryos.ko",
	.hash="35103f7edd069d947735231bcb56d06db2fb49a9c69325ac9602118c19def4f4ec8213375c7d16f6d4cf5afa894090cd219814e1b60c5622372343670af58398"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-pyra.ko",
	.hash="3d1329875e74340b2487652ec7a69d87f8f83175f5585f4ca58fae4de46669151e9d2ed709017e2c69ae6018b98082ba3526bd82cf663a46769b34174f909d7e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-lua.ko",
	.hash="85025e1a9bd1bf5e1fde3bffea3414f6c2c06627afc541cf2b313ce5ca0c70e9aaf2ae3675ed3013204e47ced01f43132994f5dbbf233147cef6657df033d4eb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kovaplus.ko",
	.hash="a7f579ffe3fb9f617994599c627445969f2e7a021537fcbd2153331df38428ec740bb3da2390285525f58e36adf6f78b2512f83b671648a7f9c26c74f6ca463b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-konepure.ko",
	.hash="4192bc63a1ec47b12d3514ae0159f4add54532218b634a52927159a7c458a6d533b1bae2fe68d4df94117b6d5bf160da7726f8613d08f4223132fdc4841ad80e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-koneplus.ko",
	.hash="b774124acce5c48deb489fd830aeb6b321b34c680d6ad9ca5f273d52d2dc1fa7f6c29a20a22627b85e40776de9edcb2a530b8c9cfb0814ab4df83387b50458cc"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-kone.ko",
	.hash="3f7effd2ef4dcb63a0a77990dbc1e152b2298545e20668de72ff1a551f4f453b4481657231923d358a829800e6931ca5b3323c856c868388e0cc738c6102bdc7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-isku.ko",
	.hash="2f837412de99f8a962fe4a2f1de9baf2b7bfaa632eb7d48b3ca6f905defd5dc1328acd8d90ede444465625afebb33c9921face6d847c0f8fc705bcb0c99e7253"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-common.ko",
	.hash="4d1f227f6f8769977eb8fdd1c7673f478931761f0d7b8ddf5b094e48bee0570ffc2337ed13b01fda2b876199bde40abaa5e2521bba012898c5a1fd29be000955"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-roccat-arvo.ko",
	.hash="64cacb49e5bc64e2302d305580ebb0b71218f9a85bcbee45046af0d364da9f7c3fdba7c609f26eb77954d984edb447e34afa3494608ad86f87d41e38972bf24e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-rmi.ko",
	.hash="dfffff0addc4cdaf9e5cae92de39aebfe7143905344d50f06357abbfa53d2402745f221d5d449d506aaf854c3f279e6f5446aab6736841401389a31b4ba1b008"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-retrode.ko",
	.hash="242706df83012c868074d29a846ac6006123375aa8a75659814fa2da97411b48b1b344e35f58aec231a75fdb1f714ec35b77efd808d8f5e2642626028032dbf2"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-prodikeys.ko",
	.hash="a1bad28f053416be9b46a88aec57d7cc17ceb2aa166d82713464fb91bc9d2094882d0b79ea479534f3e2150b4b1de11a58e0e14362899b482c1f1986169382a0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-primax.ko",
	.hash="3c2d1cb6ed7d9744e9f8fcecc9c1073a13c397b039bea3ad1e175fbe697386be736db6c16b0c8ecbd4e771d11eb7e8ac2c92c8c1ca6667abef25e10f386e8fb3"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-playstation.ko",
	.hash="4919f5a3c5b891cd5e2546a13f043fd570d642cceb4e90ee8dd516c2b841ae931ba355cd563741d6eb5cac43b9e8c7a41191cf31509d3ef8189331bf9e8c362d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-plantronics.ko",
	.hash="50d912e3f5428091d7a1c6011882a1c4aee92c6b607602b62cda41b6dbf7e49b2ad3b41fe569cee882e371bfc89e28062278fdc4cba54e6e96b5a93d22132c69"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-pl.ko",
	.hash="5df5a51419d2259a8e17380e9851943218b2cc0a207574563e44574f171583f8f3d5489c91cc310b2b8cff9c0876cb2a899477491fed1bb0f327acd9b9dc4811"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-picolcd.ko",
	.hash="f998a892780b5a9bdfaa55228ef4b0615d87f6d5dd250bc062b211ee8ab091b36fe1212f256aa916eecc0db1ba8a364615e4b389ac2ddc1a387651986ae871b6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-petalynx.ko",
	.hash="e786100656522a4cebbfde78a90d19dec122a312e9cb3b4af0fc29d814b6881561435e59d0c5fb4e69418cc98f598dfbd0395f686167c607d3ac404cbc57008d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-penmount.ko",
	.hash="8c64a95d4b7d1eaf56141f8ba28ee3f8b67315bb6cbc1d4b8718723b453d4d6c3551657b81eafa8248d788ea57ab172c1d3a983dacc36ad3f5e77412536bc933"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ortek.ko",
	.hash="290c8436e78c200bac9e1fd7f6a5cb637f22cb0b1446cc9f21d8fb7985181affdd79bdc22e8fe8f96486bf1fff9a27c363a7091da77f2f67783a4331d54de129"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-nti.ko",
	.hash="65a4fc16337febdb5e43d655dab3f0480d60d64ff99de3abfd1357cf616c78a0bdb124810df9972d3fced2d48d286779547b24a6ad6a7578aa4c8141ecc01e96"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-multitouch.ko",
	.hash="e9fe1663a1b890712dfddfe4fdb34aea8b8544c4ab76b6780bcec4a33359bf38a71f90855c690bd68d5d13b1abc429fe1128c9b29e6f7d5e1687950089afe305"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-monterey.ko",
	.hash="ce8f43cd701ff457c9b204db47f6ab0cb2f0456d9a6938ebb50d1ac4ca4a589dd67e7c0fb4f830f7fdf78eb8e5e2abdf62d098ca79acedf3ba2b571f12f6fa1b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-microsoft.ko",
	.hash="c88db8b7178bcadf3c54d06076d77fe53c1805429a25d982a8a39adfd891cddaf21f0e77c8031f84dce9272156ddf5874b9dd22c7119332a5b26b3728f39f031"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mf.ko",
	.hash="907ccf9b4ef06c3f5a2b6e86a4bd3f614e8b12cf91a0882bfa12208a7c0367ee15f3f542a3952922405d11a9453f7013f243cf4e9059e9a86e6fee23dfbb4ffa"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-mcp2221.ko",
	.hash="54d3732f679e02016e0b0d7db86d83e5a284b4449fbb7b23b7621b7db1401d3f8d8ecb0def90dfbe43399b1b2747d8113e39eb52392d2cb600ca9fc76195f15c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-maltron.ko",
	.hash="985794d9874e2d8b7ce5bdf3a94250e0d915bf590afccfe4df5a1cb9da4ea5c06193f8a42e92cd891ad54808dabd0efb90772c774b724f7909955cf56447b5fe"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-macally.ko",
	.hash="c12cbd48031e5a0c3f6afbe40ab063a4ddd0383823b69f5a817c6beb441f59ae5044625ab895ef26dcc9311039f20e6dfaa2f8e07283051bfa3ee9d73d9983a0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech.ko",
	.hash="3bd80b55b90cada09c369e3aaca80011620e45f802a6eb5a58b6f27cd824ab4888869f52b2ae26a8f6cb934d7d62aa8535a47a870630c3d98775789e4a8b461a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-hidpp.ko",
	.hash="8186da569fa08b518c7def7d8093085e851ef8c78824a36705583b78e8c144f3ab936001ada0d4c6ade08b07332d9fea5d75d4d33cfef55b1ae1536bb5adae74"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-logitech-dj.ko",
	.hash="7e1c68310a57328bcd5c2af384e95ae9c57fd9cb3f6220ea20ddce2f24e779185d12c726daaf87079077dd532bf7d5ff76a9a17eccccd5580f53fa5acd04ff4a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lg-g15.ko",
	.hash="25632f30ac37448ac7d3dcb0c80e3b7c481d20a33fbe4386be61e388ae8e50a3d2acf216aaea632146e9695c2ca0ba265b411fdb143381404690a91d39fa1dfc"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lenovo.ko",
	.hash="ccb77c32bf937fcae0d285090f05c534a34fed0dc25c31638525a26d005b811365c40b3f56b709d2d44e72efc2518244e4802a79c182d0d27bbbcc880447cd90"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-led.ko",
	.hash="c56d63d6158741474bd1d26f5dfeb04f2cfa387b10c5a5ae4f9a2956f1088be71fc96b0602123e14e7b2d07311a525981859a359647497af0517bc41cd636fd7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-lcpower.ko",
	.hash="069bbb3d2a32de4f3f8c1759b328459ab85c91a3215b6a721b65439a308aeeaa7c1543015301a9917f1bf8f5fbfab6529032cec7db8ab6e2be97c51b380e3e86"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kye.ko",
	.hash="515dceb5ce255d57f1b9058e514e433a2e5b8f5cb072fecf3fecfa52fd89628a743105d85a67543c26c763ee1eeaf1c115a91af64866ca4c56e2752aecfccb08"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-keytouch.ko",
	.hash="b31c50cf1f4d40f66a21522ad19aa573effc7dd60c07341e8c92f3d567c858e055426704a9d0829372eb0e3220ddd61d63b98d535d42c481143cc98ac6c42ce2"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-kensington.ko",
	.hash="40b3fb914ad9aa106fd99b135eb0d6123c19d91361323debcbf53ea60ad95c4eec85fad93ab7c2c16a362a2753fd3bc913e861b3fd5f4e36f84502c71840322a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-jabra.ko",
	.hash="26eb5ee9e3ff9ccff179c43dd1bf964db1b04b2876838ecd13d6ba26944bc1caa77df72f24ee597bc4c2f9e18635c244c347a751b51df6f17c36cad41e2aebfb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ite.ko",
	.hash="0d62e76f04298c1533076b3f092856f37ad10833802696b8af0cd06680052eedd61120d18dc93e6f598c70ce7c8ec32c980a4a32f09afeb4a53c32f5a53cf268"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-icade.ko",
	.hash="3e5083d2ec64ec4a628c29a6b3aeebd8faf1354f6b44fc15e78ec7f174d24b212f39c8a8d0c70412573da1375529ad672204b149973f03ed995bcea5a61107b4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-hyperv.ko",
	.hash="8f4d8e1bab2facef101911876422f8c97deacfee8d90ce35b6da11c52853bb2d14c9e1ae5c1d86cb130088c45bfd0c9b1944296a0c6c284c57dd9699312412cd"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtekff.ko",
	.hash="f8881499cc2b80f0fe2a1efe4062597202119868d3f7e60d1bab6e2a3404482f31d1e0d056e1198d9461326a52f4117cd47d3e8e13bb9992ce749efffca46c32"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-mouse.ko",
	.hash="e2f37c40e2e921bdc2541cbbf39a029364eab8ae3b0e0fea9428ef2e4b9cf4f88ce102f15e8ed6f1d35ed0d1ff89b69395c0139bfeff11278ac6b3d58f0cde1f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-holtek-kbd.ko",
	.hash="1838c009304dbfcbc65d9f4867f428de819a671501c072bd4a198c619ab2f69cf8500c25b2f2d8978c939a7850c0ffcf4c21dda5a5ff312988bb81ad975b1c9f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gyration.ko",
	.hash="33c359c50b652970f11f1edf447028cf9e05b02d0292ba3cb88de8b33fe298f7477a66b888e01425377b1ce5f1410ed402beb5b515ffe4c69a1e5b1ac30010ba"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gt683r.ko",
	.hash="7a06127e8a5c2981b27d84a1235b9fddc634dc343cbd0cddf2c90729220c721bba1f772679b00988d288ecb317c988751be94f62ec08e301b77973a1824a1b89"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-glorious.ko",
	.hash="ac58dbfd5723089295c1e901cf863fe700830acd5f1d305d2e4a66a270516992255f52575587e355acc9a0b744cbb555e9ce7544e29a398d8d741090a64c6d56"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gfrm.ko",
	.hash="cd1a4d4f451417643e26b78e18eba086a8e58206b5d971ee040910b29256a5881886abae251cbfec81385638af4564042be10da435c46b74188f804b8fde03fc"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gembird.ko",
	.hash="55f7b61bbf998958a5d9bf70b8a4cd718eacb4df66a157f179a69a8f74ab8abb6e3bfcccd41f895b12a4738da1c451b96a6af7f35e13b2dbccfa0030d963d437"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-gaff.ko",
	.hash="ab0395c1c06466674be29e778caa661a3c7f629d2e49d3e5675a057f7d5ea655ffbcba4b01ed2c05e7d4bf7def5eabf09a91c602a8f624349743fd5fa75dc168"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ft260.ko",
	.hash="cedb959a025d6a9eac84355fae0a5c409602fc8e6c41c260edccf2245313a7d5e5a295f88aacf1902b2ca24da9402ec07418953b7029645340e1e0900b6771d1"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-ezkey.ko",
	.hash="0105c514297ed391cabd370aa350f7c7644c8635e06648c1eeea84923369670b06048f3422db8e3a83f89fc25f245c4236b4f3faea5f81712f475d54d5e1b747"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-emsff.ko",
	.hash="3174a253553096a65779cfa545e0550e2273ac089dc99b6c22b19b1bd8b634a559fd00ddfca690e03c94b8698857d7114e4ea4504e18325c538cfc9053376cbf"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elo.ko",
	.hash="fe11cda376f0c97c5db255db2c11c05458b30388164b90e7b7d1570cd6be5a8570d4f9d73ae5bdabe4efeca8db43276d7d0bb61b618cfb66c76c1dab4f230ca9"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elecom.ko",
	.hash="7ca6ab1df7b643ebc26cb118cc5b7230b3c3aaf5d31f65bac3af5c52f3c77472859c67a16fa2543dc6320a2ead0514b1d070c2cffa426e121aa40f2bd05f11f7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-elan.ko",
	.hash="6ad212af15cdba783c154cb38f991a60107ed84456c8edabea9b7f309c129eb968ad2ed984ab6453915fa493cb135b4926cfedcc89a0e2b9461901ef177416c5"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-dr.ko",
	.hash="fe70df40e89a7c11dcbca2d7d471510450cf20174b0a9f685b3991d229a21042dd47a809f40ad0f6c7687d330b0d04a9b0d6b1950fa05fefacdc281a75b755ad"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cypress.ko",
	.hash="546c7d6998e38533abe9b70414511166d67ddeffe9b8e7478bdb54d65ae757d986fc3e04d74d0adda6953cf2651eeeaf2b60c54d6fe1e67266356f3b17809a5d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-creative-sb0540.ko",
	.hash="9095393613437ebf021c071e66c90d3fa93e2e2045425a2985ade27e1e08e136030b76e35c5b114bf3ab0d8c24802ea151827f54747a56cfd7d8508ca550068a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cp2112.ko",
	.hash="2c6ba9fd0ea98205010257e6507b86c201534b5bbc90bed6e06e483d66626a5c67e18263258e2b904f23cded833f4a504238e2ffc1a62908b54aa2f9a586292d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cougar.ko",
	.hash="bbad3d3c7dfe6ad006e8accc2f492cd25cec4e37c489a8e92e7f7cfea7df2743ffacd757cfdc939fa76ee24b28f1f18621838deb1b8d9519d75ee9847a1e5114"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-corsair.ko",
	.hash="54c039791af4ae4cd78c9b16c0a614ed27bc74d580eb8b6ffbf983aba6e739a2c377ce8052dee2409d84363ba744777343c279eee4b86c649a154956d399ddeb"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cmedia.ko",
	.hash="fc8803f4f04a3addac007779e29fdf74efb519c059824910a6e485d405735f75fceaefa83db24dafd5e5b003613b0e1f9270273ce84f808de2293ee3cf0c0bb3"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-chicony.ko",
	.hash="44262de88271428d808228b42e128d32fab38874de5509de651892b1456830fc0b5b850ef3cb5c2ac481936c96568b946ab58564691a196b4bed67e9c26e935b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-cherry.ko",
	.hash="05d27381085c7ad5a74d75f417d9c63335e6aaf56d5cdf9cfaa16ecf34f11a4d3f8dc72c358d1f386bd02f9c671e3a3a4d8f692daf072119cbeb67effa3ca816"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-bigbenff.ko",
	.hash="5351e76837ee28a77f1f832c3e21f8651b9f93b422c60c118d862c44cdbee768d7fed4d83135b05212ec004e2b93e8d6ed08ff55de82eab39435020f66849dd8"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-betopff.ko",
	.hash="b542074c79a324a0b7851064c22c3f19e94935b8497d39e5911402223f09d360e3f7f6880024619eb0a5133f6cf750ec539bcabee5ccf10de4b0fa23d9d161a3"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-belkin.ko",
	.hash="5248d2bf3418d543aa13fb08091af13dafff89638cab643b57a6faee7f86f118e54024129e2408f6c735b20994edfcb609eacd90ebf556b925a77cfca6fd1bc7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-axff.ko",
	.hash="099d283dbef0223a17b1067d34f3b4f865e5a28797765489f65a78b92f4f135b84ce4a3d55ca4d2999ceb06790ba029436eb92e2a423ef9d9451f28bb6bfbc9e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-aureal.ko",
	.hash="01f3c4e32875128aeb8050d8c5df5f35c9954cbbee965187d7d4a1b579431868dcc01dc34b1caf1196cba57f6597f9d4be533fdbf6c02cec4791cd91304c4caf"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-asus.ko",
	.hash="62c3716b93e73c9ad65e872bd28b47262b9e79999ddaaf4dfaba583aa2d256a18d2a96a46a132ef22a98ab37303059b924bc728ce141ad3f48097b2462e5d455"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-appleir.ko",
	.hash="2861af8c2d446ff768d6c1a730e7cac8b4b03a216e283dd93e321102a8eb400edb3f25655b6d545b7f4a6939484c5fda8383c1c70bbf8dff4da0704a228ed1cf"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-apple.ko",
	.hash="9d4c6bad087fbc959dcd621b26f7e177ad935d5e8e2049a2bad656ee1133b2940efdf53f7268a05f3aa50637416e14496f2c667b473e734d9a95b225e425ab0c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-alps.ko",
	.hash="bb94973bbe2030a5414108db58221609002e8b480c739bc0fac2f74dc9a8e7a3cd8150f360456bebafe568c9933f9452abe947582660691262f9739a0d822f83"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-accutouch.ko",
	.hash="82b5bf013522683af95de215eff76a1a6afc0d61cec7c51114bf7ba0e64b4af44b00388e6a9b1698bb1dda7fa942d21a0c5caaa880f81f5532ac7955a82b04e1"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/hid-a4tech.ko",
	.hash="2afa1289a9cea583c1cc77667b9c3dbbdf6dbea6b2b2f93301985cb27add1b6eec32fbb84581b59cfdc125b667e2aba16d02b4587de48e168034c62812132679"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/hid/amd-sfh-hid/amd_sfh.ko",
	.hash="1046d0a13267f54e900327c311838a7ee83b4274a7411bf224d65acc5de052b000bea53997c3ee14cc93e5c4780ac6e6e09234e1928f07d2ca31b30ca694826f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/ttm/ttm.ko",
	.hash="81a0e469f56c7ef08b5beaba1130b1f4a7188536badfa1ed4598c3faf6475f95e04b8660af6d80f9568cd8d3287c078a6243214f1147f941d496dc9311569360"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/qxl/qxl.ko",
	.hash="c945b0eb34921c8a912d763c3448fdd8d7d24502f0a15965e1645e4306c5361d3a2019e44a889c51c5fed6f577b83a6aab2f8dbab43e007feb60f027866e6726"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_ttm_helper.ko",
	.hash="491a95c58c898c2170725c9bd302520337401e2b2c904a965cd70f439748018b6aadd21be113b172f5b83900cacc982ea0735a4c115ea0ee1a82ca1eae1b0e8b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm_kms_helper.ko",
	.hash="adb7b2117b3e2ed2376f70c0ca4300f6a84ce66eb33d00d943c2eeca755da235e6d34fe1d4d959be93615bf5dd3846aacf38449b084f47f3d49f4d2afc005553"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/gpu/drm/drm.ko",
	.hash="80e764a0693007f60eaaecef7dd7c334e6ccb18e129f4026dc50b61ef4c40d51ce875ff02bb3801b732d17b1745c77a6565ab0cd20c20e59e9728b7b854fc456"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/firmware/qemu_fw_cfg.ko",
	.hash="3760343a7e0606d75c3756b64f8c0daafee91b9cdec296741048d14ebbf4d9bba6d92633165e984b5bac2a2d9c73e1eceb0776f090c615372488ff26b10041c0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/virtio_console.ko",
	.hash="99b60b497f1aa321962942a52faf70b3a1a6fc77352fff55190f4a10a84a4c0bc8a2b9bdde36423ad27dce8b785dac96599d015b2c237ecdc0a6a2b699be6ffd"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_si.ko",
	.hash="569642b65ec6b181c7df011c3ac0974f0f29dec278a8afefce26525d9ee347875a6e5f14b32d7b58c585969603132a9dfa3ba312130c3476c7fa948d334fbd2c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_msghandler.ko",
	.hash="187421a1c3cc2e2e0eb939e1501e692c9925d16cd621dcce91214c98f693063407318e191175fe6bb7d5c048bb391e173901cb9783dee62de945b38ce22ac111"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/char/ipmi/ipmi_devintf.ko",
	.hash="6393f98422aeab7e2d635d5c85a036123892f76efb666f49458847a0e4b68d522b697d2bc9c9c623ead4a40cec836d3c54dbbb62f3f2fb033fcf6e06c5765420"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/block/zram/zram.ko",
	.hash="892aadb6b23964b8fd9503f78bcbc4176e53c661e3787b7169430c05005a22e99d33a2652c4071f43f2006ac4ec18349245cd58b5610c309e5d705e529a63481"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/block/virtio_blk.ko",
	.hash="48db0b88983981d9552432c4d1c0bedb463a7d114b5be06a164d58ca359563b3da0d14b8c7e9a8d20905fc4b8eaf02508479bbe4b82934620ab2b4931c3ea6ce"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/base/regmap/regmap-spi.ko",
	.hash="e4b13a331b89b2eb115fa9b0f82f4974a6fae017e236e6a474d8c8bf3930d29a5cb612ba887688bb0ed142b9c967345a8bbdcdaae2da631c6262eed9cb4fd1e7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/pata_acpi.ko",
	.hash="08f0cd2a4366bdc5aece28eb9fadca459b33dae4966d40304b3f381c01955987c71359c03a2a6877d22c16eff356ebf972a9dc8d67b89c710323858041f44d1c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/ata/ata_generic.ko",
	.hash="48877cb1d3c526ff90900639f1771b513ac8cc6410461d7ea9a4d55ddc397205dd3bcdbd7006ee6b9df1635b2ba7ea3c77536993cd1201e059abe95d06c40807"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/drivers/acpi/video.ko",
	.hash="4964b5030104e342e0a9d2c5f0d4cece76b37d6bac1470bf6c4c8e349354cd2084b17849248ea57745ffb5424cd2a032cb9b4098d7153beb07b0f6fb28f176ed"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/zstd.ko",
	.hash="bccee29200be7e7e4763059a7bf2cfd33250d0abb59262a64a966442987667834b52dcf227f463d4eb79140144f509a826dda8890dab8db52ac96ad6ac274aa8"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/xcbc.ko",
	.hash="fd28d5d38b9b82481c2e995aced9a927ac30af00be1db328f06c03917eed3502d3f990e95bab55a3d464946c65e7a7985fc8e4616e63696fe115272712bed909"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/wp512.ko",
	.hash="f548e213ee20695071c6e65688d8afbb6fd2832562ddd8e6b2f15be07aa4ae1d5806a6842d64cf7c5845bbf5eb3c6e6681b21b3b19e56a1b866ee10db0c25776"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/vmac.ko",
	.hash="13ceaee2932b7d5db493f1147de81c3d0984eb7955edf61ac31887b2a64648feb9c068c56dcb4c57346ce444e024021b7b7d45208a99ba10b42429fe67812f99"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_generic.ko",
	.hash="470c87208e374cd608c0701b4c3cb8030765df64bef1e267b5e7a38082dd6da92fd71fc303e2dcd08c885dca46dd032af202f71a059a4e8581e09e56302cf89d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/twofish_common.ko",
	.hash="e2b50752ec580214300d278a5aa1cb4c20875d8a00642dd4065085d5af890335ff7d4778e969c0ecf31bf352c4767c1dfc0dad14d6ce914af753ae4234c5b8fa"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/tcrypt.ko",
	.hash="49afc4d1a2af8ed374bfabb2e23d8c88b33e31e15a5e816b0c560239930f597326ea523e511e0676898097e92b4b48d6ca0c235cd2e82d5994c841394797f5a1"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/streebog_generic.ko",
	.hash="eead36f9a8dbb3f4600860aec3be8467cabf86b2aafc255bc1262ed9d3729bbaf4411b12e510d1591027e69e3428ecd6c1fd53bc6e4e5cee7fe3141433b9458a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/serpent_generic.ko",
	.hash="c6cdb9acdc80aa0bb8306d6577ca125e1a9fa467ec63617e18b23cf6db17ab165604047e53a2a23299d2996ff160e5a07169bd5ee4f1f20e228c42a461f07ae7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/rmd160.ko",
	.hash="e96fadd43067f9729b38933624797a5da2b762161841086e38803ee358abe8052507e8fe5aa5f3bef10306c22a6656672304fb56cc11e2d88cf53581aacd992d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/poly1305_generic.ko",
	.hash="fbb13f1a00e70df210b029310af7528689ab5cb1b0c3012c104bfce8a6def546734832610ad40621b0dbbf9cb5a0b1365b5dd7bc25df01a29ef2e59c49aa3f7d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcrypt.ko",
	.hash="3751e89ef14acc195131eb1673b7dac5b230bb0da32624371ef9dd45476be8523c9e98197811c7951a07b04a3cf7f1d6e9ebef21f0506eec37ece6cca6511476"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/pcbc.ko",
	.hash="62daa18b8df91d1ff77809220c31b6feda5f58e37f8cd11782879f08d20a8541e190e1fd69db3306ca03ec0d24ffa3240ad6dbdf1dcd32eaa68e9009ec01b753"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/nhpoly1305.ko",
	.hash="66aaec1786ce7f4504638ca65c712b2e5a8766ff550af482252498c3032db8d4c0d726870c6d415fa8409e414ba2e85ae152ed5628231388a39105a5926df2a8"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/michael_mic.ko",
	.hash="07c73808ffc8ab3d6cc577bca70870575b004a1c054932e0a78a313f3dd3814103edf66cf304b22703eb117bfc219ac5478f851d187050ba510d2c343354ad62"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/md4.ko",
	.hash="34bfaae3fbbbde36f134e780425c9e76909fd7d349d02d8c63f7506b066ce3772ff3b1ec38f9a1e558667d53a237ed453f7dbde2e87e0788830f9220d5dc7b5e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4hc.ko",
	.hash="821344098d7ab72bcde62296520bf190d95c975623a583a205331f3341091dbd328f0d4ce04b63566bb15cc2623e5058906eeb53ab34bed5a86d360c7a4e1cc0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/lz4.ko",
	.hash="f3768cb6381afaaa3b5218dad8718ac683b37eec62019186cc70b2d8af60f1f0f05cc194f469e7a478268d6da30bf8a08be986324c69c1f94c3ec807fbf7b869"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/keywrap.ko",
	.hash="272190ec76ac1fdecb588a491fb82f99c816ce3acb0b2f1cc62652f91ac42ad2d9a5126b31d09b51743cbd8bfd1e9b5066de3a603afa19e362b6d3e094b5b647"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/fcrypt.ko",
	.hash="d81f9004c5185c79e6ececc9820241d5a6d0ffad867a37653f1e08ebc3ccd3861f73f1ae94764e39df755317d5e3dca4d3441322821a97e56a260dd1a6195235"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/essiv.ko",
	.hash="9644a4ae8dbee85bc868279d515c4b3aea686662838969dd395e747dfc1e06f5407380d590ca67e37094c70385909864769c9b35d8dcc7878b5ec70ffacd5200"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecrdsa_generic.ko",
	.hash="930c7dcbf758e84e8006b7b8cff48e13672840557afb7c15c634640d51bd17d7b7cf88b4efb457eae796a6d42697426bf815ab3475268f2326f941ca08cc6599"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/echainiv.ko",
	.hash="f221f0a9218c5317f5a9f1d797852f9168575770e0e34c6662a87fc354e0264f90226e24e365be6719d8c8a358c263319ea6f6f78b6dccc36bf4810e2d5d587c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ecdh_generic.ko",
	.hash="43ecc1c9c1615c29f5636d4b9e4c2916dc01e3d8775e7efe38629fcc440c079d4c21d61806dc9e34454e02f3e20599c397d1237a4d36931604df10a9b157b362"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/des_generic.ko",
	.hash="26a0b8cf4b036b2ca7bc63c67fc18337619ceadbd7a83c30ed945fd17b7cb57a78390db10e7244c7cfbbd47051eca3dc382196344496b2ec03c9ae07535d69c1"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/curve25519-generic.ko",
	.hash="a456de7366d4259c79d2d8f8716d6d9a98bacd706baf5b6bb34f95a8e737b507b0645cebb03748a4a4d71d273b6d6e338cb843c83129e7856ed0e3f1d500063f"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_user.ko",
	.hash="74c1ca706a6fdec69ca4f9854a85ceb2332a264798365d4b9ef9714f22b732301435281311a0dcaba7891f4639a240653445caae638d26511234b3798e7b544a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crypto_engine.ko",
	.hash="14f38ce9e43fac259e5dccb69f0561a7ecf638ae443da41d09a715ae64873d50ead377f07bae3d18886f18910e83dae34e4b04ca9e0245a0b53a89e1ce5ad740"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/crc32_generic.ko",
	.hash="09c9497f466a42c80064af183ac79156412f5d492cc964e13c85d140a984826b18c370c27a143b1f44f551f08070e88d58bef8a68fd97e050d982f1f18b982fd"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha_generic.ko",
	.hash="160e079c85131d1afe76dd0c6c21e13afee6d9264d78223498531a20fb51997efd0cba7063a95335f39a1e0b51f8f4eef998aff8421a1c1d228d8800d8f93553"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/chacha20poly1305.ko",
	.hash="a34b66464cfa272a86aab9520f8355d2df9ee8dabecc4098005b38d8988f0706b5cc03267652bc655cff996683705f58f17a981d7062b80e2bb8ce0f5d2b0d2b"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast_common.ko",
	.hash="daa686b440f91985f59f82e90d9bebf539ce562536fcb3e1a569f4ad0bfd2be236e999d059d15dd85ef531be1578baaf217733f1b9c087ad5e57b6635ff40a40"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast6_generic.ko",
	.hash="3df646d2d9c16f11aa9cf0332382817c0157ff5d0682dd43068f130954c83f1566923ff422559ba88cf4caa5cf31b9a244e290ba56c2f9b9ac129fe2f2f477a7"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/cast5_generic.ko",
	.hash="200d62cad062771a92f4a9e22c2197c53f0cae197c1837a01f0409ba60db96680230aa53c69dacd3ed9e03c60ad38970a6defa0c744428202b6c8fa7d9ece1f0"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/camellia_generic.ko",
	.hash="435a6c76b3e75baeaa6f961d92be18b64ad889e0ef1982ed38cb7289bad365c128024d2414839af95b63620e5fad5432639d29f8503cfe72a321c916999db47e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_generic.ko",
	.hash="1d11eedb984e4bee42a2a701c0c1a9d103a6a8cd6e03568a55be55ef00ffaf15a919899de24d563c8ff445a67c500fda47455a317eba588058eb436f3d5c4988"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blowfish_common.ko",
	.hash="ff780936e77ec1214c0eb11f06e80e527b41a833971b26b4240b10cc674635131739da24ef081a8fb871b5b4edbbd18f19ed5d67a610b68cbd96bd7349c8e8c6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/blake2s_generic.ko",
	.hash="f4a953c011b7d0d0112d9a01a64a7f2f1a75c913f39b6c14abb0949d0e3e51c8ae00bc4c616f2430e1aa255e2d2734639eceda0e1b2226ad2a054c40f087dce6"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/raid6test.ko",
	.hash="2e0f427cb7fee1ce729fdd64f64b7f0fa04b7505f2d477730a555860d06efb2c7f3f7895ba7bf8c3d0ac15ba43221d433c9d9f743f4a5958360287a1ee3036b2"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_xor.ko",
	.hash="bc0c6926824a0fd5db336bfaeeb4a11c858a91f28f521312eab0c1dbf84ca348c12999ab93d514edda585acdfe11dab83b9df308178764d87d0f7905ca3f98aa"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_tx.ko",
	.hash="629190469591c4fae3fbba65000b093580eae9ce6480dd5af4d0ddee76bb5128f6778a74888ba6c5832b32250e191ce8fffed8524ab40ec8acdaa9cf5ce255ba"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_raid6_recov.ko",
	.hash="008b833b7bbd9cb23b9a2bbeec6a32da233a48d6d96bef327aa1f47fd4e1fab09962c712954188a18de22cde5e9a661ca683c3e565f260687e4e039040bd4d22"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_pq.ko",
	.hash="c1d80f30ec86e748e4d10f18a3b7de75564cd809de1aaf8bd00ee70d28fe85dc6618f0f4d3f81d2335320658524ba67c3ec4ee29a96fb303cc7929521bcb6a49"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/async_tx/async_memcpy.ko",
	.hash="e14bc27f3a97fa619c4f44b9e2b4a548316c72476214d4ad4a4e1cb6c2732893578c6c109de3513598b794c5f3606972474f514922213b39a8cef8d3f51fb850"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/tpm_key_parser.ko",
	.hash="0618024ed9577a5b0dbbba12cba9402ea72cf3af257df4e5744e63c35099a0384c8248978f0618f94ad40d601d52764c7a66ae732961b8f5f735b872efcee7a2"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/pkcs8_key_parser.ko",
	.hash="8f49d4f2857f90a26db528117099823ac7e660e6fb303ff7127cf6452c5ccd1d36ed9a9d412d37a90286d3acca7a6d9d60bfe037e159aea8beeb9b7361f78616"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/asymmetric_keys/asym_tpm.ko",
	.hash="9e1dfb67ffafc03ad835aeccbe44da04e761a9b768c4e2e1a7b5cc08fdbcf59d054136df909c5ba6ce2eed01f497c8e89344a1ce1bde3f4d9dfa7e4a8943345a"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/ansi_cprng.ko",
	.hash="ea9b1b595829bfdee50712f01392ad8e05fc148417e9df0c4d4efd83c6d5ec309cf105b21a1bb0665c340691745ee37106577e0a01c68c1e6a802b1e657acb3e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aes_ti.ko",
	.hash="f2e82445dc4111c3277bd957060488c2b61ff0990f18a5a3156ad432513ce504ee438bff4c6b0a7e532af771eefa8a1b28bcdf588a299d1920ca8e42a2955990"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/aegis128.ko",
	.hash="fd996460a7ab848a8f451129cf831a963a8ed868008bd71d8ac9b4fd637686d8ce7fea04b0531c38d88313a10d151f04f16a9be76a3c985c240499ebe847b13d"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/crypto/adiantum.ko",
	.hash="05f54e9b930267523f5f358c9a3fd695af6bd9339267d913fca6541ef2da5e98c14c7e06675c5e3199d23ed6fbb2192fd0f483f5bc23a107d69e5fc8bea1f502"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/sha256-ssse3.ko",
	.hash="8b5b70998579eb0a923f5ea7bba9413c7c1f7c7697ee5c476f6e6562c8b0d3219ebfeed0f47e6734072f30c58a8552d51c8509ce71d8cd037eb7f3476ecb9bb2"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/ghash-clmulni-intel.ko",
	.hash="2a99557f9a7a0bd51ff79dbdb60a076ddf7356f6d5edea183d015c6775cff50d5b748d8d2503f0f42c878e1347ae4ff0c693d21d1d132655d722d16fb79cbdb4"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crct10dif-pclmul.ko",
	.hash="1a49f747cca5f40264d66bc6c4c15aca6538bf764aaec9793b83930509fef43dd58e18881e2bbc288d1b7c3cfbad691842cbbf3f3e68fd008cc974650fa0f03c"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32c-intel.ko",
	.hash="8a7c138ffb71c94cf8021c554fe5078be7299fae961fe24c7ed78e1a13437af3816d1e07664c3439e0075382d656955c21b18dbf589e6d9ba733ab01e799743e"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/kernel/arch/x86/crypto/crc32-pclmul.ko",
	.hash="ccf60f53c9a9fa77999f400870ed89f6a41677ae69c2d5b16a2eb4fbfec80761f4ae4b29baf6ffce96eaf3e7ce1c52c230c7d754cfd29c3aea205564764cb7ce"
},
{
	.path="/usr/lib/modules/5.14.13-tinfoil+/extra/slowboot.ko",
	.hash="9f4fef034c07d4d10632cd9bb3607221e83d3a23f9e0459bfa475e3eaefc464d7212db9af2a296c86bb578c3f8a971dab430e8e5a10952886158d8423b745c4a"
}

		//{.hash="", .path=""},
};
//static struct kstat *st;



/*******************************************************************************
* Register data in array                                                       *
*******************************************************************************/
/*static void svi_reg(slowboot_validation_item *item,
		const char *hash,
		const char *path)
{
	strncpy(item->hash, hash, SHA512_HASH_LEN);
	strncpy(item->path, path, PATH_MAX);
}*/


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
	

	item->buf = vmalloc(item->buf_len+1);
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
		vfree(item->buf);
		return -1;
	}
	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "StoredHashFail:%s\n", item->path);
	}
	
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
		return NULL;
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
	if (!sd) {
	  printk(KERN_ERR "Can't allocate alg\n");
	  vfree(item->buf);
	  item->is_ok=1;
	  return;
	}
	
	crypto_shash_digest(&(sd->shash), item->buf, item->buf_len, digest);
	vfree(item->buf);
	kfree(sd);
	for(j=0;j<64;j++){
		if(item->b_hash[j]!=digest[j]) {
			item->is_ok = 1;
		}
	}
	kfree(digest);
	crypto_free_shash(alg);
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
	if (item->is_ok != 0) {
		printk(KERN_ERR "File:%s:%s\n", 
		       item->path, 
		       (item->is_ok == 0 ? "PASS" : "FAIL"));
	}
	tinfoil_close(item);
	return item->is_ok;
}

/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;

	tinfoil.validation_items = tinfoil_items;

	for (j = 0; j < SLWBT_CT; j++) {
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
	printk(KERN_INFO "Beginning SlowBoot\n");
	
	tinfoil.failures = 0;
	tinfoil.st = NULL;
	tinfoil.st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil.st)
		return -ENOMEM; // CHECK
	
	slowboot_run_test();
	kfree(tinfoil.st);
	return 0;
}




//DING DONG
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
