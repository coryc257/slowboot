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
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/random.h>
#include <linux/gs_pbit.h>
#include <linux/gs_tinfoil_slowboot.h>
#include <linux/gs_tinfoil.h>

DEFINE_SPINLOCK(gs_irq_killer);

/*
 * Verify boot files chaining off a trusted kernel
 * There should be an LSM hook for this to avoid
 * conditional compilation
 */
void tinfoil_verify(void)
{
	printk(KERN_ERR "GS TFSB tinfoil_verify finished with status: %d\n",
			__gs_tfsb_go(CONFIG_TINFOIL_CF,
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
				     CONFIG_TINFOIL_OVERRIDE,
				     CONFIG_TINFOIL_VERSION,
				     NULL,
				     NULL,
				     CONFIG_TINFOIL_BUG));
}
