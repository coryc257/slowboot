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
	snarf_hat_item items[NUM_HATS];
} snarf_hat;

static snarf_hat tinfoil;

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
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$FN
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void snarf_init(void)
{
//##########TEMPLATE_PARM_SP##################################################=>
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$SP
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
  char *buf;
  struct kstat st;
  int number_read;
  struct file *fp;
  u8 b_hash[65];
  long long int pos;
  struct crypto_shash *alg;
  sdesc *desc;
  char digest[64];
  int j;

  
  
  fp = filp_open(filename, O_RDONLY, 0);
  if (IS_ERR(fp) || fp == NULL) {
    printk(KERN_ERR "Snaf Cannot Open File:%s\n", filename);
    goto fail;
  }

  if (vfs_getattr(&(fp->f_path),
	      &st,
	      STATX_SIZE,
		  AT_STATX_SYNC_AS_STAT) != 0 ) {
    printk(KERN_ERR "Snarf Cannot Stat:%s\n", filename);
    goto fail;
  }

  buf = vmalloc(st.size+1);
  if (!buf) {
    printk(KERN_ERR "Snarf Cannot Allocate Memory:%s\n", filename);
    goto fail;
  }

  memset(buf,0,st.size+1);
  memset(b_hash,0,65);
  
  number_read = kernel_read(fp, buf, st.size, &pos);
  if (number_read != st.size) {
    printk(KERN_ERR "Snarf File Size Mismatch:%s\n", filename);
    goto fail;
  }

  if (hex2bin(b_hash, item->hash, 64) != 0) {
    printk(KERN_ERR "Snarf Stored Hex2Bin Fail:%s\n", filename);
    goto fail;
  }

  alg = crypto_alloc_shash("sha512", 0, 0);
  if (IS_ERR(alg) || alg == NULL) {
    printk(KERN_ERR "Snarf cannot allocate alg sha512\n");
    goto fail;
  }

  desc = init_sdesc(alg);
  if (desc == NULL) {
    printk(KERN_ERR "Snarf cannot allocate sdesc\n");
    goto fail;
  }

  crypto_shash_digest(&(desc->shash), buf, st.size, digest);
  for(j=0;j<64;j++) {
    if(b_hash[j]!=digest[j])
      goto fail;
  }

  if (buf != NULL)
    vfree(buf);
  if (fp != NULL)
    filp_close(fp, NULL);
  if (!IS_ERR(alg) || alg != NULL)
    crypto_free_shash(alg);
  if (desc != NULL)
    kfree(desc);
  return 0;
 fail:
  if (buf != NULL)
    vfree(buf);
  if (fp != NULL)
    filp_close(fp, NULL);
  if (!IS_ERR(alg) || alg != NULL)
    crypto_free_shash(alg);
  if (desc != NULL)
    kfree(desc);
  return 1;
}

static int snarf_check(const char *filename)
{
	int j;
	int is_ok;
	if (snarf_on != 0) {
		snarf_init();
		snarf_on = 0;
	}

	is_ok = 1;
	
	for (j=0;j<NUM_HATS;j++) {
	  if (strcmp(filename,tinfoil.items[j].filename) == 0)
	    if(snarf_it(filename,&tinfoil.items[j]) == ) {
	      is_ok = 0;
	      break;
	    }
	}
	return is_ok;
}

// exit
