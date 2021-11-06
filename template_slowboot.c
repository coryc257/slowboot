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

//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$CT
#ifndef SLWBT_CT
#define SLWBT_CT __get_slwbt_ct()
#endif

DEFINE_MUTEX(gs_concurrency_locker);

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
	int initialized;
	int slwbt_ct;
	char config_file[PATH_MAX];
	char config_file_signature[PATH_MAX];
	char config_pkey[1053];
} slowboot_tinfoil;



static u32 mode;
static slowboot_tinfoil tinfoil = {
		.config_file = "/testing/siggywiggy",
		.config_file_signature = "/testing/siggywiggy.sha512",
		.config_pkey = "3082020a02820201009af1624ec932c82d57d296ebddf3d8c1cdc03a6c5c709cb3658b33797dd8a94b4183146224a63f8dbf04032690f04c4b05138cf9b0955057e4acf4721c84eb3073eeb1ccc5c6e9bec3d36b1b3bd274c13afb42f33c5c057121debaa622f8f2c0e75bbc99cbcf78767d4225025ece9561ca6022b650ab9c9a68763e7e461164bdfdd07b72e4c623e07b38a7767ac2671c06ea899d6291fddb1eb3d8a6d03fbd78719adec4b92f8881562d73923fcf8f2bd41f324993ecf42c40cd9c596c3b58850aa96a7d28a767b0be8e919fb247897cdc557391753db766991f197217b96e430c8e9bfc3f84a9c45b4aad9e6284e87041eb1709e99fd01e8f23f1f97aa86e255eb8d4bfb13ce6f14264347e40372bb79e17a87e1c541077e8e874092f475b9dbfb4fca981c1358971004421454069c3868cd4fe8fd1ea6d46d9daac7dc00d6b60d998bebbe0121126e3f29acfc3ccc2f24e6eb6c4ab9c0f2e7670e920f33d69eb1f0ca7be630098fe220c1f8ef87e51f8be663a70621a5932ee60888c7e40aa70313e1936bc0c6d742d2c2d2d46c2ceb2b3155ebc777f01bbfad07985e847f8d00c663706b92cf15fd2504ae8dd838d9576763e4ed12e2d6b0a5f7ea21bed613d371a96a25f2206fe6e1724cfcbf2c03d04dda6f623d0d31c036a63f030158478ae820020cf6eff88c70f335db426eeac8205a2875a393d5d67343d534ef54b0203010001",
		.initialized = 1
};
static slowboot_validation_item tinfoil_items[] = {
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT
		//{.hash="", .path=""},
};
//static struct kstat *st;

static int __get_slwbt_ct(void)
{
	return tinfoil.slwbt_ct;
}

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


static void slowboot_init(void)
{
	struct file *fp;
	size_t file_size;
	loff_t pos;
	int num_read;
	char *buf;

	printk(KERN_INFO "Beginning SlowBoot 3 '%s'\n", tinfoil.config_file);

	fp = filp_open(tinfoil.config_file, O_RDONLY, 0);
	default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);

	buf = vmalloc(file_size+1);
	pos = 0;

	printk(KERN_INFO "Beginning SlowBoot 3 '%s'::'%d'\n", tinfoil.config_file, file_size);

	num_read = kernel_read(fp,buf,file_size,&pos);

	if (num_read != file_size) {
		printk(KERN_ERR "File Read Error, size mismatch:%d:%d\n", num_read, file_size);
	}

	filp_close(fp, NULL);
	printk(KERN_INFO "Beginning SlowBoot4:%d\n", num_read);
	tinfoil.slwbt_ct = 0;
}

/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;

	mutex_lock(&gs_concurrency_locker);
	printk(KERN_INFO "Beginning SlowBoot2\n");
	if (tinfoil.initialized != 0) {
		tinfoil.initialized = 0;
		//tinfoil.validation_items = tinfoil_items;
		slowboot_init();
	}
	mutex_unlock(&gs_concurrency_locker);

	for (j = 0; j < SLWBT_CT; j++) {
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
	if (tinfoil.failures > 0) {
		GLOW
	}
}

// init
static int __init slowboot_mod_init(void)
//static int slowboot_mod_init(void)
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

// exit
static void __exit slowboot_mod_exit(void) { }

module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");

