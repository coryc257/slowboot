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

typedef struct slowboot_validation_item {
	char hash[130];
	char path[PATH_MAX];
	int is_ok;
} slowboot_validation_item;

static u32 mode;
static int failures;
static slowboot_validation_item validation_items[1];
static struct kstat *st;

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

/*******************************************************************************
* Open file, read contents, hash it, compare, log state, free                  *
*******************************************************************************/
static int tinfoil_unwrap (slowboot_validation_item *item)
{
	struct file *fp;
	char *buf;
	long long int pos;
	fp = filp_open(item->path, O_RDONLY, 0);
	if (IS_ERR(fp) || fp == NULL) {
		printk(KERN_ERR "F:%s:%s:%d\n", 
			item->hash, 
			item->path, 
			item->is_ok);
		return;
	} 
	printk(KERN_INFO "1\n");
	pos = 0;
	// TODO: sha512, check, set
	if (
		vfs_getattr(&fp->f_path, st, STATX_SIZE, AT_STATX_SYNC_AS_STAT)
		!= 0) {
		printk(KERN_ERR "Cannot stat:%s\n",
			item->path);
		return;
	}
	printk(KERN_INFO "2\n");
	buf = kmalloc(st->size+1, GFP_KERNEL);
	printk(KERN_INFO "3\n");
	if (!buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		return;
	}
	memset(buf,0,st->size+1);
	printk(KERN_INFO "4\n");
	kernel_read(fp,buf,st->size,&pos);
	printk(KERN_INFO "F:%s\n", buf);
	
	item->is_ok = 1;
	printk(KERN_INFO "S%s:%s:%d\n", item->hash, item->path, item->is_ok);
	

	kfree(buf);
	filp_close(fp, NULL);
	return 0;
}

/*******************************************************************************
* This section contains dynamically generated functions numbered 1-infinity    *
* It will simply register the hash/path for each file to be validated at the   *
* correct location in the array                                                *
*******************************************************************************/
//##########TEMPLATE_INIT_FN##################################################=>
static void svir_1(void) {
	svi_reg(&(validation_items[0]),
		"a904877f33c094a4a8ebda9c2a5ded89f2817a275d9769f9ed834c1d19e2beb7dd9bcbbbd51c6af204b51d8a443900dd9cead0429e5c875b877331e53937ace1",
		"/home/corycraig/configuration_file.config"
	);	
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;
	int validation_count = 1;

//##########TEMPLATE_INIT_SP##################################################=>	
	svir_1();
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	failures = 0;
	for (j = 0; j < validation_count; j++) {
		printk(KERN_INFO "VALDATING\n");
		failures += tinfoil_unwrap(&(validation_items[j]));
	}
}

// init
static int __init slowboot_mod_init(void)
{
	if (mode == 0)
		mode = SLWBT_MODE_REG;
		
	printk(KERN_INFO "Beginning SlowBoot with mode=%u\n", mode);
	
	st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!st)
		return -ENOMEM; // CHECK
	
	switch (mode) {
	case SLWBT_MODE_REG:
		slowboot_run_test();
		break;
	default:
		break;
	}
	kfree(st);
	return 0;
}

// exit
static void __exit slowboot_mod_exit(void) { }

module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

module_param(mode, uint, 1);
MODULE_PARM_DESC(mode, "Validation Method");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");

