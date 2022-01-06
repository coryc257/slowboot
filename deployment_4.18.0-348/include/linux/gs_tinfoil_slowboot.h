/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X_GS_TINFOIL_SLOWBOOT_H
#define _X_GS_TINFOIL_SLOWBOOT_H
/*
 * GlowSlayer General Functionality
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
#include <linux/gs_pbit.h>

#define GS_LSM_NAME "GlowSlayer"
#define GS_LSM_FLAGS 0
#define GS_FILP_FLAGS 0

#define GS_KEYLEN_INIT 0
#define GS_HEX_DENOM 2

#define GS_STRING_BASE 4096
#define GS_STRING_PAD 1
#define GS_STRING_GUARD 5
#define GS_STRING_MATCH 0

#define GS_SCATTER_LIST_SIZE 3
#define GS_SCATTER_LIST_T_DIGEST 1
#define GS_SCATTER_LIST_T_SIZE 0

#define GS_IRRELEVANT 0
#define GS_MEMSET_DEFAULT 0
#define GS_SEEK_TO_END 0
#define GS_START_OF_FILE 0

#define GS_LOFF_T_MAX (~(loff_t)0U)

enum { GS_TRUE=1, GS_FALSE=0 };
enum { GS_SUCCESS=0, GS_FAIL=1 };
enum { GS_TINFOIL_FAIL=1, GS_TINFOIL_SUCCESS=0 };

/* File Validation item */
struct slowboot_validation_item {
	char hash[GS_STRING_BASE+GS_STRING_PAD+GS_STRING_PAD];
	u8 b_hash[GS_STRING_BASE+GS_STRING_PAD];
	char path[PATH_MAX+GS_STRING_PAD];
	struct pbit is_ok;
	char *buf;
	size_t buf_len;
	struct file *fp;
	long long pos;
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
	char config_pkey[GS_STRING_BASE+GS_STRING_PAD];
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
	u8 *digest;
};

/* Initialization Container Holding initial signature verification items */
struct slowboot_init_container {
	struct file *fp;
	struct file *sfp;
	struct crypto_shash *halg;
	struct sdesc *hsd;
	loff_t file_size;
	loff_t sfp_file_size;
	loff_t pos;
	loff_t remaining;
	loff_t sfp_pos;
	long num_items;
	u8 *buf;
	u8 *sfp_buf;
	unsigned char *kernel_key;
	unsigned char *digest;
	struct slowboot_validation_item *items;
	struct slowboot_validation_item *c_item;
	size_t kernel_key_len;
	struct public_key_signature sig;
	struct public_key rsa_pub_key;
};

/* Signature Verification Container */
struct sig_verify {
	struct crypto_wait cwait;
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct scatterlist src_tab[GS_SCATTER_LIST_SIZE];
	const char *alg_name;
	void *output;
	unsigned int outlen; // int due to value returned by the api
	char alg_name_buf[CRYPTO_MAX_ALG_NAME];
};

static loff_t __always_inline GS_SEEK_TO_START(loff_t current_position)
{
	return current_position * -1;
}

static inline int __must_check __gs_safe_loff_add(loff_t current_value,
						  loff_t requested_add,
						  loff_t *result)
{
	if ((GS_LOFF_T_MAX - current_value) < requested_add)
		goto __gs_safe_loff_adder_err;

	*result = current_value + requested_add;
	return GS_SUCCESS;

__gs_safe_loff_adder_err:
	return -EINVAL;
}

static inline int __must_check __gs_safe_int_add(int x,
						 int y,
						 int *result)
{

	if (((x < 0) && (y < 0) && ((INT_MIN - x) > y))
	    || ((x > 0) && (y > 0) && ((INT_MAX - x) < y)))
		goto __gs_safe_int_adder_fail;

	*result = x + y;
	return GS_SUCCESS;

__gs_safe_int_adder_fail:
	return -EINVAL;
}

static inline int __must_check __gs_safe_long_add(long x,
						  long y,
						  long *result)
{
	if (((x < 0) && (y < 0) && ((LONG_MIN - x) > y))
	    || ((x > 0) && (y > 0) && ((LONG_MAX - x) < y)))
		goto __gs_safe_long_adder_fail;

	*result = x + y;
	return GS_SUCCESS;

__gs_safe_long_adder_fail:
	return -EINVAL;
}

static inline int __must_check GS_PTR_ERR_OR_ZERO(void *p)
{
	long long check;
	if (!IS_ERR(p))
		return 0;
	check = (long long)p;
	if (check > INT_MAX || check < INT_MIN)
		return -EINVAL;
	return (int)check;
}

char *__gs_read_file_to_memory(struct file *fp,
			       loff_t file_size,
			       loff_t *pos,
			       int ignore_size);
loff_t __gs_get_file_size(struct file *fp);
int __gs_memmem_sp(const char *s1, size_t s1_len,
		   const char *s2, size_t s2_len);
struct sdesc *__gs_init_sdesc(struct crypto_shash *alg);
int __gs_pk_sig_verify_init(struct sig_verify *sv,
			    const struct public_key *pkey,
			    const struct public_key_signature *sig,
			    const char *pkalgopd);
int __gs_tinfoil_verify(void);

/*
 * Perform entire test
 * @config_tinfoil_cf: path for the configuration file
 * @config_tinfoil_cfs: path for the configuration file checksum file
 * @config_tinfoil_pk: correctly (DER for RSA) encoded public key in HEX
 * @config_tinfoil_pklen: strlen of @tinfoil_pk
 * @config_tinfoil_dglen: number of bytes in digest 64 for sha512
 * @config_tinfoil_hslen: strlen of hex representation of digest, 128 for sha512
 * @tinfoil_pkalgo: algorithm used, likely "rsa"
 * @tinfoil_pkalgopd: algorithm padding, likely "pkcs1pad(rsa,sha512)" can be ""
 * @tinfoil_hsalgo: digest used, likely "sha512"
 * @config_tinfoil_idtype: public_key.id_type likely "X509"
 * @config_tinfoil_ak_cipher_type: ak_cipher type likely 0
 * @config_tinfoil_ak_cipher_mask: ak_mask likely 0
 * @config_tinfoil_shash_type: shash type likely 0
 * @config_tinfoil_shash_mask: shash likely 0
 * @gs_irq_killer: spinlock_t to block IRQ during test
 * @config_tinfoil_new_line: char for new line '\n'
 * @config_tinfoil_version: logic version to use likely 1
 * @config_tinfoil_reserved: future use
 * @config_tinfoil_unused: future uXCFG_TINFOIL_OVERRIDEse
 */
int __gs_tfsb_go(const char *config_tinfoil_cf,
		 const char *config_tinfoil_cfs,
		 const char *config_tinfoil_pk,
		 size_t config_tinfoil_pklen,
		 size_t config_tinfoil_dglen,
		 size_t config_tinfoil_hslen,
		 const char *config_tinfoil_pkalgo,
		 const char *config_tinfoil_pkalgopd,
		 const char *config_tinfoil_hsalgo,
		 const char *config_tinfoil_idtype,
		 int config_tinfoil_ak_cipher_type,
		 int config_tinfoil_ak_cipher_mask,
		 int config_tinfoil_shash_type,
		 int config_tinfoil_shash_mask,
		 spinlock_t *gs_irq_killer,
		 char config_tinfoil_new_line,
		 int config_tinfoil_version,
		 const void *config_tinfoil_reserved,
		 const void *config_tinfoil_unused);

/*
 * In Depth Documentation of Parameters and Setup
 * This assumes rsa, X509, sha512, pkcs1pad
 *
 * First we need a key pair:
 *
 * DO: openssl genrsa -aes256 -out gs_key.pem 4096
 * ~this makes the private key\
 *
 * DO: openssl rsa -in gs_key.pem -pubout -out gs_pub.pem
 * ~this makes the public key
 *
 * DO: openssl asn1parse -inform PEM -in gs_pub.pem -strparse 19 -out gs_kernel.key
 * ~this makes a key in the format the kernel api can use
 *
 * Now we need to generate a config file. The config file will contain:
 * <hex encoded hash> <path to file>${config_tinfoil_new_line}
 * ...
 * ~this is the output of this program: sha512sum <file> for each file
 * ~gs_utility_generate_tinfoil_params.py
 * ~gs_utility_generate_modules_params.py
 * ~this file will be referred to as /path/cf
 *
 * Once you have the file you need to sign the file
 * DO: openssl dgst -sha512 -sign /path/gs_key.pem -out /path/cf.sig /path/cf
 * (...) means the output of a command
 * [...] means use your intelligence to understand what I am saying
 *
 * @config_tinfoil_cf := "/path/cf"
 * @config_tinfoil_cfs := "/path/cf.sig"
 * @config_tinfoil_pk := "(xxd -c 99999999 -p gs_kernel.key)"
 * @config_tinfoil_pklen := [how many characters is the above key? likely 1052]
 * @config_tinfoil_dglen := [how many characters is your hash digest? 64 for sha512]
 * @config_tinfoil_hslen := [how many characters is in the hex output of your hashing program? sha512sum is 128]
 * @config_tinfoil_pkalgo := "rsa" or something else?
 * @config_tinfoil_pkalgopd := "pkcs1pad(rsa,sha512)"
 * @config_tinfoil_hsalgo := "sha512"
 * @config_tinfoil_idtype := "X509" or something else?
 * @gs_irq_killer := [just a pointer to a defined spinlock_t]
 * @config_tinfoil_newline := '\n' or something else?
 * @config_tinfoil_version := [1 unless you are targeting a different version that uses different logic]
 * @config_tinfoil_reserved := NULL
 * @config_tinfoil_unused := NULL
 *
 * You should be able to infer what to put into the menuconfig/.config file for
 * the kernel. Don't surround strings with "" obviously
 * Don't forget to add GlowSlayer to the list of LSM modules
 * You can disable the check by passing tinfoil_override=${CONFIG_TINFOIL_OVERRIDE}
 * to the kernel boot params
 */
#endif
