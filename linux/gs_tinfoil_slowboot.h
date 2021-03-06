/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X_GS_TINFOIL_SLOWBOOT_H
#define _X_GS_TINFOIL_SLOWBOOT_H

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
//#include "linux/pbit.h"
#include "pbit.h"

#define GS_STRING_BASE 4096

/* Configuration */
struct gs_tfsb_config {
	int tinfoil;
	char tinfoil_cf[PATH_MAX+1];
	char tinfoil_cfs[PATH_MAX+1];
	char tinfoil_pk[GS_STRING_BASE+1];
	int tinfoil_pklen;
	int tinfoil_hslen;
	char tinfoil_pkalgo[GS_STRING_BASE+1];
	char tinfoil_pkalgopd[GS_STRING_BASE+1];
	char tinfoil_hsalgop[GS_STRING_BASE+1];
	char tinfoil_idtype[GS_STRING_BASE+1];
	char tinfoil_override[GS_STRING_BASE+1];
	int tinfoil_version;
};

/* File Validation item */
struct slowboot_validation_item {
	char hash[GS_STRING_BASE+2];
	u8 b_hash[GS_STRING_BASE+1];
	char path[PATH_MAX+1];
	struct pbit is_ok;
	char *buf;
	size_t buf_len;
	struct file *fp;
	long long int pos;
};

/* Container Struct for the entire process */
struct slowboot_tinfoil {
	struct kstat *st;
	struct slowboot_validation_item *validation_items;
	int failures;
	int initialized;
	int slwbt_ct;
	char config_file[PATH_MAX];
	char config_file_signature[PATH_MAX];
	char config_pkey[GS_STRING_BASE+1];
	int error_code;
	struct pbit error;
};

/* shash container struct */
struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

/* Container for a single item check */
struct tinfoil_check {
	struct slowboot_validation_item *item;
	struct crypto_shash *alg;
	struct sdesc *sd;
	unsigned char *digest;
};

/* Initialization Container Holding initial signature verification items */
struct slowboot_init_container {
	struct file *fp;
	struct file *sfp;
	struct crypto_shash *halg;
	struct sdesc *hsd;
	size_t file_size;
	size_t sfp_file_size;
	loff_t pos;
	loff_t remaining;
	loff_t sfp_pos;
	int num_read;
	int sfp_num_read;
	long int num_items;
	char *buf;
	char *sfp_buf;
	unsigned char *kernel_key;
	unsigned char *digest;
	struct slowboot_validation_item *items;
	struct slowboot_validation_item *c_item;
	int kernel_key_len;
	struct public_key_signature sig;
	struct public_key rsa_pub_key;
};

/* Signature Verification Container */
struct sig_verify {
	struct crypto_wait cwait;
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct scatterlist src_tab[3];
	const char *alg_name;
	void *output;
	unsigned int outlen;
	char alg_name_buf[CRYPTO_MAX_ALG_NAME];
};

char *__gs_read_file_to_memory(struct file *fp,
			       size_t file_size,
			       loff_t *pos,
			       int ignore_size);
size_t __gs_get_file_size(struct file *fp);
int __gs_memmem_sp(const char *s1, size_t s1_len,
		   const char *s2, size_t s2_len);
struct sdesc *__gs_init_sdesc(struct crypto_shash *alg);
int __gs_pk_sig_verify_init(struct sig_verify *sv,
			    const struct public_key *pkey,
			    const struct public_key_signature *sig,
			    const char *pkalgopd);
int __gs_tfsb_go(const char *config_tinfoil_cf,
		 const char *config_tinfoil_cfs,
		 const char *config_tinfoil_pk,
		 int config_tinfoil_pklen,
		 int config_tinfoil_dglen,
		 int config_tinfoil_hslen,
		 const char *config_tinfoil_pkalgo,
		 const char *config_tinfoil_pkalgopd,
		 const char *config_tinfoil_hsalgo,
		 const char *config_tinfoil_idtype,
		 spinlock_t *gs_irq_killer,
		 char config_tinfoil_new_line,
		 const char *config_tinfoil_override,
		 int config_tinfoil_version,
		 const char *config_tinfoil_reserved,
		 const void *config_tinfoil_unused,
		 int config_bug_on_fail);

#endif
