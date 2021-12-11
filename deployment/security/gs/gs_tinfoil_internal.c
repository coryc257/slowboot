// SPDX-License-Identifier: GPL-2.0
/*
 * GS Tinfoil Pre Init Integrity Check
 * Copyright (C) 2021 Cory Craig
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/public_key.h>
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
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/random.h>
#include <linux/lsm_hooks.h>
#include <linux/gs_pbit.h>
#include <linux/gs_tinfoil_slowboot.h>

#ifndef CONFIG_TINFOIL_NEW_LINE
#define CONFIG_TINFOIL_NEW_LINE '\n'
#endif

#ifndef CONFIG_TINFOIL_VERSION
#define CONFIG_TINFOIL_VERSION 1
#endif

DEFINE_SPINLOCK(gs_irq_killer);
static int __gs_is_enabled = 1;

int __gs_tinfoil_verify(void)
{
	struct pbit pc;
	PBIT_Y(pc, __gs_tfsb_go(CONFIG_TINFOIL_CF,
				CONFIG_TINFOIL_CFS,
				CONFIG_TINFOIL_PK,
				CONFIG_TINFOIL_PKLEN,
				CONFIG_TINFOIL_DGLEN,
				CONFIG_TINFOIL_HSLEN,
				CONFIG_TINFOIL_PKALGO,
				CONFIG_TINFOIL_PKALGOPD,
				CONFIG_TINFOIL_HSALGO,
				CONFIG_TINFOIL_IDTYPE,
				&gs_irq_killer,
				CONFIG_TINFOIL_NEW_LINE,
				CONFIG_TINFOIL_VERSION,
				NULL,
				NULL));
	pr_err("GS TFSB tinfoil verify finished with status: %d\n",
		PBIT_GET(pc));
	return PBIT_RET(pc);
}

static int gs_tinfoil_init_hook(const char *init_program, const char **arg_i,
				const char **env_i)
{
	return __gs_tinfoil_verify();
}

static struct security_hook_list lsm_gs_hooks[] = {
	LSM_HOOK_INIT(pre_init_kexecve, gs_tinfoil_init_hook)
};

static __init int gs_tinfoil_init(void)
{
	security_add_hooks(lsm_gs_hooks, ARRAY_SIZE(lsm_gs_hooks),
			   "GlowSlayer");
	return 0;
}

DEFINE_LSM(GlowSlayer) = {
	.name = "GlowSlayer",
	.flags = 0,
	.enabled = &__gs_is_enabled,
	.init = gs_tinfoil_init
};
