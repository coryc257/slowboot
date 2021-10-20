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
	u8 b_hash[65];
	char path[PATH_MAX];
	int is_ok;
	char *buf;
	struct file *fp;
	long long int pos;
} slowboot_validation_item;

//##########TEMPLATE_INIT_SP##################################################=>
typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[1];
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
	
	printk(KERN_INFO "1\n");
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
	printk(KERN_INFO "2\n");
	item->buf = kmalloc(tinfoil.st->size+1, GFP_KERNEL);
	printk(KERN_INFO "3\n");
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		return -1;
	}
	memset(item->buf,0,tinfoil.st->size+1);
	return 0;
}

static void tinfoil_close(slowboot_validation_item *item)
{
	kfree(item->buf);
	filp_close(item->fp, NULL);
}

static int tinfoil_read(slowboot_validation_item *item)
{
	size_t number_read;
	int j;
	number_read = 0;
	number_read = kernel_read(
		item->fp,
		item->buf,
		tinfoil.st->size,
		&(item->pos));
	if (number_read != tinfoil.st->size) {
		kfree(item->buf);
		return -1;
	}
	printk(KERN_INFO "%s\n", "xxxx");
	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "Fail:%s\n", "bad");
	}
	for(j=0;j<64;j++) {
		printk("%x\n",item->b_hash[j]);
	}
	//print_hex_dump_bytes("", DUMP_PREFIX_NONE, item->b_hash, 64);
	return 0;
}

static void tinfoil_check(slowboot_validation_item *item)
{
	struct crypto_ahash *tfm;
	tfm = crypto_alloc_ahash("sha512", 0, 0);
	if (IS_ERR(tfm)) {
		item->is_ok = 1;
		return;
	}
	// TODO: sha512, check, set	
	crypto_free_ahash(tfm);
}

/*******************************************************************************
* Open file, read contents, hash it, compare, log state, free                  *
*******************************************************************************/
static int tinfoil_unwrap (slowboot_validation_item *item)
{
	if (tinfoil_open(item) != 0)
		return -1;
		
	if (tinfoil_stat_alloc(item) != 0)
		return -1;
	
	if (tinfoil_read(item) != 0)
		return -1;

	printk(KERN_INFO "F:%s\n", item->buf);	
	tinfoil_check(item);
	printk(KERN_INFO "S%s:%s:%d\n", item->hash, item->path, item->is_ok);	
	tinfoil_close(item);
	return item->is_ok;
}

/*******************************************************************************
* This section contains dynamically generated functions numbered 1-infinity    *
* It will simply register the hash/path for each file to be validated at the   *
* correct location in the array                                                *
*******************************************************************************/
//##########TEMPLATE_INIT_FN##################################################=>
static void svir_1(void) {
	svi_reg(&(tinfoil.validation_items[0]),
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
	for (j = 0; j < validation_count; j++) {
		printk(KERN_INFO "VALDATING\n");
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
}

// init
static int __init slowboot_mod_init(void)
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
static void __exit slowboot_mod_exit(void) { }

module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

module_param(mode, uint, 1);
MODULE_PARM_DESC(mode, "Validation Method");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");

