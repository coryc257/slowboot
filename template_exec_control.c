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

//##########TEMPLATE_PARM_ST##################################################=>
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#define SHA512_HASH_LEN 130
#define GLOW printk(KERN_ERR "GLOWING\n");

static int snarf_on = 1;

typedef struct snarf_hat_item {
	char filename[PATH_MAX];
	char hash[SHA512_HASH_LEN];
} snarf_hat_item;

typedef struct snarf_hat {
	snarf_hat_item *items;
} snarf_hat;

static snarf_hat tinfoil;
static snarf_hat_item tinfoil_hat[]={
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT
};

/*******************************************************************************
* Register data in array                                                       *
*******************************************************************************/
static void snarf_construct_hat(const char *filename, 
                                const char *hash, 
                                int index)
{
	strncpy(tinfoil.items[index].filename,
	        filename,
	        PATH_MAX);
	strncpy(tinfoil.items[index].hash,
		hash,
		SHA512_HASH_LEN);
}

//##########TEMPLATE_PARM_FN##################################################=>
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$FN
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void snarf_init(void)
{
//##########TEMPLATE_PARM_SP##################################################=>
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$SP
	tinfoil.items = tinfoil_hat;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

// Think about the race condition, what if the file changes between now and
// then??? Can the file be altered after the attempt at execution???
// Initially this method may be ok but going forward I may need to fix this
// With this being dynamically genereted for each "Kernel Release" the details
// Are not important initially as long as prototype functionaly is correct
static int snarf_it(const char *filename, snarf_hat_item *item)
{
	u8 *buf;
	loff_t file_size;
	int number_read;
	struct file *fp;
	u8 b_hash[65];
	loff_t pos;
	struct crypto_shash *alg;
	sdesc *desc;
	unsigned char *digest;
	int j;
	int return_code;


	fp = NULL;
	buf = NULL;
	desc = NULL;
	alg = NULL;
	digest = NULL;
	file_size = 0;
	number_read = 0;
	pos = 0;
	j = 0;
	return_code = 0;


	// Try open file
	fp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(fp) || fp == NULL) {
		printk(KERN_ERR "Snarf Cannot Open File:%s\n", filename);
		goto fail;
	}

	// Determine file size
	printk(KERN_INFO "Snarf Current Position:%lld\n", fp->f_pos);
	default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	printk(KERN_INFO "Snarf File Size:%lld\n", file_size);
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);
	printk(KERN_INFO "Snarf Reset Position:%lld\n", fp->f_pos);

	// Allocate buffer for file, DOS for super sized file???
	buf = vmalloc(file_size+1);
	if (!buf) {
		printk(KERN_ERR "Snarf Cannot Allocate Memory:%s\n", filename);
		goto fail;
	}

	// Allocate space for digest
	digest = kmalloc(65, GFP_KERNEL);
	if (!digest) {
		printk(KERN_ERR "Snarf Cannot Allocate Memory2:%s\n", filename);
		goto fail;
	}

	// Zero the buffers
	memset(buf,0,file_size+1);
	memset(b_hash,0,65);
	memset(digest,0,65);

	// Read the file
	number_read = kernel_read(fp, buf, file_size, &pos);
	if (number_read != file_size) {
		printk(KERN_ERR "Snarf File Size Mismatch:%s,%lld,%lld\n", filename, number_read, pos);
		goto fail;
	}

	// Put stored hex hash into binary format for comparison
	printk(KERN_INFO "Snarf Hex2Bin:%s\n", filename);
	if (hex2bin(b_hash, item->hash, 64) != 0) {
		printk(KERN_ERR "Snarf Stored Hex2Bin Fail:%s\n", filename);
		goto fail;
	}

	// Allocate crypto algorithm sha512 for hashing
	printk(KERN_INFO "Snarf Alloc Crypto Alg %s\n", filename);
	alg = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(alg)) {
		printk(KERN_ERR "Snarf cannot allocate alg sha512\n");
		goto fail;
	}

	// Init sdesc memory with reference to sha512 algorithm
	printk(KERN_INFO "Snarf Init sDesc %s\n", filename);
	desc = init_sdesc(alg);
	if (desc == NULL) {
		printk(KERN_ERR "Snarf cannot allocate sdesc\n");
		goto fail;
	}

	// Hash the file
	printk(KERN_INFO "Snarf Check: %s,%lld,\n", filename, file_size);
	crypto_shash_digest(&(desc->shash), buf, file_size, digest);
	//printk(KERN_INFO "Is is totally tuxed up?[s::x] %*ph \n", b_hash);
	//printk(KERN_INFO "Is is totally tuxed up?[s::x] %*ph \n", digest);

	// Check the Hash
	for(j=0;j<64;j++) {
		if(b_hash[j]!=digest[j])
			goto fail;
	}

	// Success
	goto out;

fail:
	return_code = 1;
out:
	if (buf != NULL)
		vfree(buf);
	if (!IS_ERR(fp) && fp != NULL)
		filp_close(fp, NULL);
	if (desc != NULL)
		kfree(desc);
	if (!IS_ERR(alg) && alg != NULL)
		crypto_free_shash(alg);
	if (digest != NULL)
		kfree(digest);
	return return_code;
}

static int snarf_check(struct filename *fn)
{
	int j;
	int is_ok;
	if (snarf_on != 0) {
		snarf_init();
		snarf_on = 0;
	}

	is_ok = 1;
	printk(KERN_INFO "Snarfing:%s\n", fn->name);
	for (j=0;j<NUM_HATS;j++) {
		if (strcmp(fn->name,tinfoil.items[j].filename) == 0)
			if(snarf_it(fn->name,&tinfoil.items[j]) == 0) {
				is_ok = 0;
				break;
			}
	}
	if (is_ok == 1)
		printk(KERN_ERR "Snarf Gobble:%s\n", fn->name);
	else
		printk(KERN_INFO "Snarf Success:%s\n", fn->name);
	return 0; // Permissive mode for now
}

// exit
