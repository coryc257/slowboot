// SPDX-License-Identifier: GPL-2.0
/*
 * GS Slowboot PostInit Integrity Check
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
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/random.h>
#include <linux/gs_pbit.h>
#include <linux/gs_tinfoil_slowboot.h>

DEFINE_SPINLOCK(gs_s_irq_killer);

#ifndef CONFIG_SLOWBOOT_NEW_LINE
#define CONFIG_SLOWBOOT_NEW_LINE '\n'
#endif

#ifndef CONFIG_SLOWBOOT_OVERRIDE
#define CONFIG_SLOWBOOT_OVERRIDE "not_applicable_no_gssb_override"
#endif

#ifndef CONFIG_SLOWBOOT_VERSION
#define CONFIG_SLOWBOOT_VERSION 1
#endif

#ifndef CONFIG_SLOWBOOT_BUG
#define CONFIG_SLOWBOOT_BUG 0
#endif

/*
 * Main function for validation
 */
static int __init slowboot_mod_init(void)
{
	return __gs_tfsb_go(CONFIG_SLOWBOOT_CF,
			    CONFIG_SLOWBOOT_CFS,
			    CONFIG_SLOWBOOT_PK,
			    CONFIG_SLOWBOOT_PKLEN,
			    CONFIG_SLOWBOOT_DGLEN,
			    CONFIG_SLOWBOOT_HSLEN,
			    CONFIG_SLOWBOOT_PKALGO,
			    CONFIG_SLOWBOOT_PKALGOPD,
			    CONFIG_SLOWBOOT_HSALGO,
			    CONFIG_SLOWBOOT_IDTYPE,
			    &gs_s_irq_killer,
			    CONFIG_SLOWBOOT_NEW_LINE,
			    CONFIG_SLOWBOOT_OVERRIDE,
			    CONFIG_SLOWBOOT_VERSION,
			    NULL,
			    NULL,
			    CONFIG_SLOWBOOT_BUG);
	
}

static void __exit slowboot_mod_exit(void) { }

module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GS Slowboot");
MODULE_AUTHOR("Cory Craig <gs.cory.craig@gmail.com>");
MODULE_VERSION("1.0");
