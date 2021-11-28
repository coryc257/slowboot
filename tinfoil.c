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
#include "linux/pbit.h"
#include "linux/gs_tinfoil_slowboot.h"

/*
 *
 * Don't assume that this will be used but if this is to work it should be
 * nearly impossible to disable (eg recompile kernel)
 */
#ifndef CONFIG_TINFOIL
#define CONFIG_TINFOIL 0
#endif

/* File that holds the hash(space)path(newline)... data */
#ifndef CONFIG_TINFOIL_CF
#define CONFIG_TINFOIL_CF "/etc/gs/tinfoil"
#endif

/* Signature digest file made from openssl */
#ifndef CONFIG_TINFOIL_CFS
#define CONFIG_TINFOIL_CFS "/etc/gs/tinfoil.sig"
#endif

/* Primary key in hex */
/* this is hard-coded because the idea is you cannot trust the system because
 * everything can be hacked so you remove the ability for uncontained root
 * from breaking the system in a way that may prove fatal on reboot
 * openssl asn1parse -inform PEM -in key.pem -strparse 19 -out kernel.key
 * xxd -ps -c 999999 kernel.key
 */
#ifndef CONFIG_TINFOIL_PK
#define CONFIG_TINFOIL_PK \
                 "3082020a02820201009af1624ec932c82d57d296ebddf3d8c1cdc03a6c5c"\
                 "709cb3658b33797dd8a94b4183146224a63f8dbf04032690f04c4b05138c"\
                 "f9b0955057e4acf4721c84eb3073eeb1ccc5c6e9bec3d36b1b3bd274c13a"\
                 "fb42f33c5c057121debaa622f8f2c0e75bbc99cbcf78767d4225025ece95"\
                 "61ca6022b650ab9c9a68763e7e461164bdfdd07b72e4c623e07b38a7767a"\
                 "c2671c06ea899d6291fddb1eb3d8a6d03fbd78719adec4b92f8881562d73"\
                 "923fcf8f2bd41f324993ecf42c40cd9c596c3b58850aa96a7d28a767b0be"\
                 "8e919fb247897cdc557391753db766991f197217b96e430c8e9bfc3f84a9"\
                 "c45b4aad9e6284e87041eb1709e99fd01e8f23f1f97aa86e255eb8d4bfb1"\
                 "3ce6f14264347e40372bb79e17a87e1c541077e8e874092f475b9dbfb4fc"\
                 "a981c1358971004421454069c3868cd4fe8fd1ea6d46d9daac7dc00d6b60"\
                 "d998bebbe0121126e3f29acfc3ccc2f24e6eb6c4ab9c0f2e7670e920f33d"\
                 "69eb1f0ca7be630098fe220c1f8ef87e51f8be663a70621a5932ee60888c"\
                 "7e40aa70313e1936bc0c6d742d2c2d2d46c2ceb2b3155ebc777f01bbfad0"\
                 "7985e847f8d00c663706b92cf15fd2504ae8dd838d9576763e4ed12e2d6b"\
                 "0a5f7ea21bed613d371a96a25f2206fe6e1724cfcbf2c03d04dda6f623d0"\
                 "d31c036a63f030158478ae820020cf6eff88c70f335db426eeac8205a287"\
                 "5a393d5d67343d534ef54b0203010001"

#endif

/* Total number of characters in the primary key not including \0 */
#ifndef CONFIG_TINFOIL_PKLEN
#define CONFIG_TINFOIL_PKLEN 1052
#endif

/* Length of the Digest (64 for sha512) */
#ifndef CONFIG_TINFOIL_DGLEN
#define CONFIG_TINFOIL_DGLEN 64
#endif

/* Length of the Digest in Hex (should be 2x the digest) */
#ifndef CONFIG_TINFOIL_HSLEN
#define CONFIG_TINFOIL_HSLEN 128
#endif

/* Primary key algorithm to use, likely "rsa" */
#ifndef CONFIG_TINFOIL_PKALGO
#define CONFIG_TINFOIL_PKALGO "rsa"
#endif

/* Padding method used, likely "pkcs1pad(rsa,sha512)" */
//#ifndef CONFIG_TINFOIL_PKALGOPD
#define CONFIG_TINFOIL_PKALGOPD "pkcs1pad(rsa,sha512)"
//#endif

/* Hash algorithm used, likely "sha512" */
#ifndef CONFIG_TINFOIL_HSALGO
#define CONFIG_TINFOIL_HSALGO "sha512"
#endif

/* Id type for the certificate, likely "X509" */
#ifndef CONFIG_TINFOIL_IDTYPE
#define CONFIG_TINFOIL_IDTYPE "X509"
#endif

DEFINE_SPINLOCK(gs_irq_killer);

/* Record separator for the config file, likely '\n' */
#ifndef CONFIG_TINFOIL_NEW_LINE
#define CONFIG_TINFOIL_NEW_LINE '\n'
#endif

/* Override cmdline parameter */
// Specify this as a kernel cmdline option to bypass check in case
// Of BUG(); being enabled
#ifndef CONFIG_TINFOIL_OVERRIDE
#define CONFIG_TINFOIL_OVERRIDE "tinfoil_override"
#endif

/* Future Use Version Number */
#ifndef CONFIG_TINFOIL_VERSION
#define CONFIG_TINFOIL_VERSION 1
#endif

#ifdef SLOWBOOT_MODULE
static int __init slowboot_mod_init(void)
#endif
#ifndef SLOWBOOT_MODULE
/*
 * Main function for validation
 */
static int slowboot_mod_init(void)
#endif
{
	return __gs_tfsb_go(CONFIG_TINFOIL_CF,
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
			    0);
	
}

#ifdef SLOWBOOT_MODULE
static void __exit slowboot_mod_exit(void) { }


module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GS Tinfoil Slowboot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");
#endif



#ifndef SLOWBOOT_MODULE
/*
 * Verify boot files chaining off a trusted kernel
 * There should be an LSM hook for this
 */
void tinfoil_verify(void)
{
#ifndef CONFIG_TINFOIL
	return;
#endif
	printk(KERN_ERR "tinfoil_verify finished with status: %d\n",
	       slowboot_mod_init());
	printk(KERN_ERR "tinfoil_verify finished with status: %d\n",
			return __gs_tfsb_go(CONFIG_TINFOIL_CF,
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
					    0));
}
#endif
