// SPDX-License-Identifier: GPL-2.080
/*
 * 	linux/init/tinfoil.c
 *
 * 	Copyright (C) 2021 Cory Craig
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


/*
 * Operational parameters
 */

/*
 *
 * Don't assume that this will be used but if this is to work it should be
 * nearly impossible to disable (eg recompile kernel)
 */
#ifndef CONFIG_TINFOIL
#define CONFIG_TINFOIL 0
#endif

/* Total number of verification items */
#ifndef SLWBT_CT
#define SLWBT_CT __get_slwbt_ct()
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

/* Padding method used, likely "pkcs1pad(rsa,%s)" */
#ifndef CONFIG_TINFOIL_PKALGOPD
#define CONFIG_TINFOIL_PKALGOPD "pkcs1pad(rsa,%s)"
#endif

/* Hash algorithm used, likely "sha512" */
#ifndef CONFIG_TINFOIL_HSALGO
#define CONFIG_TINFOIL_HSALGO "sha512"
#endif

/* Id type for the certificate, likely "X509" */
#ifndef CONFIG_TINFOIL_IDTYPE
#define CONFIG_TINFOIL_IDTYPE "X509"
#endif

DEFINE_MUTEX(gs_concurrency_locker);

/* Record separator for the config file, likely '\n' */
#ifndef CONFIG_TINFOIL_NEW_LINE
#define CONFIG_TINFOIL_NEW_LINE '\n'
#endif

/* What to do if at the end of the test there are failures */
/* The idea is a distro could put in their own thing for
 * the purposes of attempted recovery
 * BUG(); to fail boot
 */
#ifndef CONFIG_TINFOIL_FAIL
#define CONFIG_TINFOIL_FAIL __gs_tinfoil_fail_alert(&tinfoil);
#endif

/* Override cmdline parameter */
#ifndef CONFIG_TINFOIL_OVERRIDE
#define CONFIG_TINFOIL_OVERRIDE "tinfoil_override"
#endif


/* File Validation item */
typedef struct slowboot_validation_item {
	char hash[CONFIG_TINFOIL_HSLEN+2];
	u8 b_hash[CONFIG_TINFOIL_DGLEN+1];
	char path[PATH_MAX+1];
	int is_ok;
	char *buf;
	size_t buf_len;
	struct file *fp;
	long long int pos;
} slowboot_validation_item;

/* Container Struct for the entire process */
typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item *validation_items;
	int failures;
	int initialized;
	int slwbt_ct;
	char config_file[PATH_MAX];
	char config_file_signature[PATH_MAX];
	char config_pkey[CONFIG_TINFOIL_PKLEN+1];
} slowboot_tinfoil;


/* shash container struct */
typedef struct sdesc {
    struct shash_desc shash;
    char ctx[];
} sdesc;

struct tinfoil_check {
	slowboot_validation_item *item;
	struct crypto_shash *alg;
	sdesc *sd;
	unsigned char *digest;
};


/* main data struct */
static slowboot_tinfoil tinfoil = {
		.config_file = CONFIG_TINFOIL_CF,
		.config_file_signature = CONFIG_TINFOIL_CFS,
		.config_pkey = CONFIG_TINFOIL_PK,
		.initialized = 1
};

/*
 * Obtain the count of items to verify
 */
static int __get_slwbt_ct(void)
{
	return tinfoil.slwbt_ct;
}


typedef struct paranoid_container {
	int status;
	int dead_value;
} PARANOID;



/*
 * make the success check fail
 * the magic number is alternating-alternating 0101 meaning an attacker would need
 * pinpoint accuracy
 */
static void paranoid_check_fail(PARANOID *pc)
{
	pc->status = 3482093499;
	pc->dead_value = 1431655765;
}

static void paranoid_check_setup(PARANOID *pc)
{
	paranoid_check_fail(pc);
}

static void paranoid_check_success(PARANOID *pc)
{
	pc->dead_value = 0;
	while (!pc->dead_value)
		get_random_bytes(&pc->dead_value, sizeof(int));
	pc->status = pc->dead_value;
}

static int paranoid_check(PARANOID *pc)
{
	return (pc->status == pc->dead_value ? 0 : 1);
}

/*
 * Obtain size of file via seeking
 */
static size_t __get_file_size(struct file *fp)
{
	size_t file_size;

	file_size = 0;
	if (fp == NULL) {
		goto out;
	}

	default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);

out:
	return file_size;
}

/*
 * Read file into memory, check every thing
 * @fp: file structure
 * @file_size: stated size of file
 * @pos: position offset return value
 */
static char *__read_file_to_memory(struct file *fp,
		                           size_t file_size,
								   loff_t *pos,
								   int ignore_size)
{
	char *buf;
	size_t num_read;

	buf = NULL;

	if (!fp || file_size < 1)
		goto out;

	buf = vmalloc(file_size+1);

	if (!buf)
		goto out;

	*pos = 0;

	default_llseek(fp, 0, SEEK_END);
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);
	num_read = kernel_read(fp, buf, file_size, pos);

	if (num_read != file_size && !ignore_size) {
		vfree(buf);
	}

	out:
		return buf;
}

/*
 * Check string for string, 0 is true
 * @s1: big string
 * @s1_len: length of big_string
 * @s2: little string
 * @s2_len: length of little string
 */
int __gs_memmem_sp(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
	while (s1_len >= s2_len) {
		s1_len--;
		if (!memcmp(s1, s2, s2_len))
			return 0;
		s1++;
	}
	return 1;
}

/*
 * Failure Option to simply alert
 * @tf: slowboot_tinfoil struct
 */
static void __gs_tinfoil_fail_alert(slowboot_tinfoil *tf)
{
	printk(KERN_ERR "Tinfoil Verification Failed\n");
	#ifdef CONFIG_TINFOIL_BUG
	BUG();
	#endif
}

/*
 * Initialize sdesc struct for digest measuring
 * @alg: crypto_shash structure
 */
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

//openssl x509 -C -in my_signing_key_pub.der -inform DER
//xxd -i siggywiggy.sha512
//xxd -ps -c 9999999 siggywiggy.sha512 > siggywiggy.hex


// It helps if you are using an RSA key
//openssl genrsa -aes256 -passout pass:<phrase> -out private.pem 4096
//openssl rsa -in private.pem -passin pass:<phrase> -pubout -out public.pem
//openssl dgst -sha256 -sign <private-key> -out /tmp/sign.sha256 <file>
//openssl base64 -in /tmp/sign.sha256 -out <signature>
//openssl base64 -d -in <signature> -out /tmp/sign.sha256
//openssl dgst -sha256 -verify <pub-key> -signature /tmp/sign.sha256 <file>
//openssl asn1parse -inform PEM -in public.pem -strparse 19 -out kernel.key
//xxd -i kernel.key

//openssl rsa -in private.pem -passin pass:1111 -pubout -out public.pem

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


static int pk_sig_verify_init(struct sig_verify *sv,
		                      const struct public_key *pkey,
							  const struct public_key_signature *sig)
{
	memset(sv, 0, sizeof(struct sig_verify));

	sv->alg_name = sig->pkey_algo;
	if (strcmp(sig->pkey_algo, "rsa") == 0) {
		/* The data wangled by the RSA algorithm is typically padded
		 * and encoded in some manner, such as EMSA-PKCS1-1_5 [RFC3447
		 * sec 8.2].
		 */
		if (snprintf(sv->alg_name_buf, CRYPTO_MAX_ALG_NAME,
					 CONFIG_TINFOIL_PKALGOPD, sig->hash_algo
				 ) >= CRYPTO_MAX_ALG_NAME)
			return 1;
		sv->alg_name = sv->alg_name_buf;
	}

	sg_init_table(sv->src_tab, 3);
	sg_set_buf(&sv->src_tab[1], sig->digest, sig->digest_size);
	sg_set_buf(&sv->src_tab[0], sig->s, sig->s_size);
	return 0;
}

static int pk_sig_verify_alloc(struct sig_verify *sv,
		                       const struct public_key *pkey)
{
	sv->tfm = crypto_alloc_akcipher(sv->alg_name, 0, 0);
	if (IS_ERR(sv->tfm)) {
		sv->tfm = NULL;
		return 1;
	}

	sv->req = akcipher_request_alloc(sv->tfm, GFP_KERNEL);
	if (!sv->req) {
		return 1;
	}


	if (crypto_akcipher_set_pub_key(sv->tfm, pkey->key, pkey->keylen)) {
		return 1;
	}

	sv->outlen = crypto_akcipher_maxsize(sv->tfm);
	sv->output = kmalloc(sv->outlen, GFP_KERNEL);
	if (!sv->output) {
		return 1;
	}

	return 0;
}

static int pk_sig_verify_validate(struct sig_verify *sv,
								  const struct public_key_signature *sig)
{
	akcipher_request_set_crypt(sv->req, sv->src_tab, NULL, sig->s_size,
							   sig->digest_size);

	crypto_init_wait(&sv->cwait);
	akcipher_request_set_callback(sv->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
								  CRYPTO_TFM_REQ_MAY_SLEEP,
								  crypto_req_done, &sv->cwait);


	return crypto_wait_req(crypto_akcipher_verify(sv->req), &sv->cwait);
}

static void pk_sig_verify_free(struct sig_verify *sv)
{
	if (sv->output != NULL)
		kfree(sv->output);
	if (sv->req != NULL)
		akcipher_request_free(sv->req);
	if (sv->tfm != NULL)
		crypto_free_akcipher(sv->tfm);
}



/*
 * Perform ?rsa? signature verification
 * @pkey: public key struct
 * @sig: public key signature struct
 */
int local_public_key_verify_signature(const struct public_key *pkey,
                const struct public_key_signature *sig)
{
	struct sig_verify sv;
	PARANOID pc;

    if (!pkey || !sig || !sig->s || !sig->digest)
        return -ENOPKG;

    paranoid_check_setup(&pc);

    if (pk_sig_verify_init(&sv, pkey, sig)) {
    	goto err;
    }

    if (pk_sig_verify_alloc(&sv, pkey)) {
    	goto err;
    }

    if (pk_sig_verify_validate(&sv, sig) == 0) {
    	paranoid_check_success(&pc);
    	goto out;
    }

err:
	paranoid_check_fail(&pc);
out:
	pk_sig_verify_free(&sv);

    return paranoid_check(&pc);
}

/*
 * Open file related to current item
 * @item: slow boot validation item
 */
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

/*
 * Stat file to get size
 * @item: slow boot validation item
 */
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

/*
 * Close file
 * @item: slowboot validation item
 */
static void tinfoil_close(slowboot_validation_item *item)
{
	filp_close(item->fp, NULL);
}

/*
 * read file into buffer
 * @item: slowboot validation item
 */
static int tinfoil_read(slowboot_validation_item *item)
{
	size_t number_read;
	number_read = 0;
	

	item->buf = vmalloc(item->buf_len+1);
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		goto fail;
	}
	memset(item->buf,0,item->buf_len+1);
	
	item->pos = 0;
	number_read = kernel_read(
		item->fp,
		item->buf,
		tinfoil.st->size,
		&(item->pos));

	if (number_read != item->buf_len) {
		goto fail;
	}

	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "StoredHashFail:%s\n", item->path);
		goto fail;
	}
	
	goto out;
fail:
	if (item->buf != NULL) {
		vfree(item->buf);
		item->buf = NULL;
	}
	return -1;
out:
	return 0;
}



static int tinfoil_check_init(struct tinfoil_check *c,
							  struct slowboot_validation_item *item)
{
	if (item == NULL || item->buf == NULL || item->buf_len == 0)
		return 1;

	memset(c,0,sizeof(struct tinfoil_check));

	c->item = item;

	return 0;
}

static int tinfoil_check_allocate(struct tinfoil_check *c)
{
	c->alg = crypto_alloc_shash(CONFIG_TINFOIL_HSALGO, 0, 0);
	if (IS_ERR(c->alg)) {
		c->alg = NULL;
		printk(KERN_ERR "Can't allocate alg\n");
		return 1;
	}

	c->digest = kmalloc(CONFIG_TINFOIL_DGLEN+1, GFP_KERNEL);
	if (!c->digest) {
		c->digest = NULL;
		printk(KERN_ERR "Can't allocate digest\n");
		return 1;
	}

	memset(c->digest,0,CONFIG_TINFOIL_DGLEN+1);

	c->sd = init_sdesc(c->alg);
	if (!c->sd) {
		c->sd = NULL;
		printk(KERN_ERR "Can't allocate sdesc\n");
		return 1;
	}
	return 0;
}

static void tinfoil_check_validate(struct tinfoil_check *c)
{
	int i;
	crypto_shash_digest(&(c->sd->shash), c->item->buf, c->item->buf_len,
						c->digest);

	c->item->is_ok = 0;
	for (i=0; i<CONFIG_TINFOIL_DGLEN; i++){
		if (c->item->b_hash[i] != c->digest[i]) {
			c->item->is_ok = 1;
			return;
		}
	}
}

static void tinfoil_check_free(struct tinfoil_check *c)
{
	if (c->item->buf != NULL) {
		vfree(c->item->buf);
		c->item->buf = NULL;
	}
	if (c->sd != NULL)
		kfree(c->sd);
	if (c->digest != NULL)
		kfree(c->digest);
	if (c->alg != NULL)
		crypto_free_shash(c->alg);
}

/*
 * Check a single item for validity
 * @item: slowboot validation item
 * consumes item->buf
 */
static void tinfoil_check(struct slowboot_validation_item *item)
{
	/*
	 * init
	 * allocate
	 * check
	 * free
	 */

	struct tinfoil_check check;

	printk(KERN_ERR "1\n");
	if (tinfoil_check_init(&check, item))
		goto err;

	if (tinfoil_check_allocate(&check))
		goto err;

	tinfoil_check_validate(&check);
	goto std_return;
err:
	item->is_ok = 1;
std_return:
	tinfoil_check_free(&check);
}
/*

	struct crypto_shash *alg;
	sdesc *sd;
	unsigned char *digest;
	int j;
	
	alg = NULL; //crypto_free_shash
	sd = NULL; //kfree
	digest = NULL; //kfree

	if (item->buf == NULL || item->buf_len == 0)
		goto err;

	alg = crypto_alloc_shash(CONFIG_TINFOIL_HSALGO, 0, 0);
	if (IS_ERR(alg)) {
		alg = NULL;
		printk(KERN_ERR "Can't allocate alg\n");
		goto err;
	}
	
	digest = kmalloc(CONFIG_TINFOIL_DGLEN+1, GFP_KERNEL);
	if (!digest) {
		digest = NULL;
		printk(KERN_ERR "Can't allocate digest\n");
		goto err;
	}

	memset(digest,0,CONFIG_TINFOIL_DGLEN+1);

	sd = init_sdesc(alg);
	if (!sd) {
		sd = NULL;
		printk(KERN_ERR "Can't allocate sdesc\n");
		goto err;
	}
	
	crypto_shash_digest(&(sd->shash), item->buf, item->buf_len, digest);

	item->is_ok = 0;
	for (j=0; j<CONFIG_TINFOIL_DGLEN; j++){
		if (item->b_hash[j] != digest[j]) {
			goto err;
		}
	}

	goto out;
err:
	item->is_ok = 1;
out:
	if (item->buf != NULL) {
		vfree(item->buf);
		item->buf = NULL;
	}
	if (sd != NULL)
		kfree(sd);
	if (digest != NULL)
		kfree(digest);
	if (alg != NULL)
		crypto_free_shash(alg);
}
*/

/*
 * Validate an item (file against it's hash)
 * @item: slowboot validation item
 */
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

/*
 * Parse one line, fill in the item
 * @item: slowboot validation item
 * @line: start of current line
 * @remaining: remaining bytes
 */
static loff_t fill_in_item(slowboot_validation_item *item,
		                   char *line, loff_t *remaining)
{
	loff_t pos, off, rem;


	if (line == NULL) {
		if (remaining != NULL)
			*remaining = 0;
		return 0;
	}


	pos = 0;
	off = 0;
	rem = *remaining;


	while (rem > 0) {

		if (line[pos] == ' ' && off == 0 && rem > 1) {
			off = pos+1;
		}

		if (line[pos] == CONFIG_TINFOIL_NEW_LINE) {
			break;
		}

		pos++;
		rem--;
	}

	if (item->path != NULL && item->hash != NULL) {
		memset(item->path,0,PATH_MAX+1);
		memset(item->hash,0,CONFIG_TINFOIL_HSLEN+2);

		// Make sure we have a good item
		// This should not happen because who
		// would sign something malicous?
		if (pos > (CONFIG_TINFOIL_HSLEN+5) && (pos-off-1) > 0) {
			memcpy(item->hash, line, CONFIG_TINFOIL_HSLEN);
			memcpy(item->path, line+off, pos-off);
		}
	}

	if (rem > 0) {
		pos++;
		rem--;
	}
	*remaining = rem;
	return pos;
}

/*
 * Signature check the config file and initialize all the data
 */
static int slowboot_init(void)
{
	struct file *fp, *sfp;
	struct crypto_shash *halg;
	sdesc *hsd;
	size_t file_size, sfp_file_size;
	loff_t pos, remaining, sfp_pos;
	int num_read, sfp_num_read, status;
	long int num_items;
	char *buf, *sfp_buf;
	unsigned char *kernel_key;
	unsigned char *digest;
	slowboot_validation_item *items, *c_item;
	int kernel_key_len;
	struct public_key_signature sig;
	struct public_key rsa_pub_key;

	// trustno1
	status = 0;
	fp = NULL; //filp_close
	sfp = NULL; //filp_close
	halg = NULL; //kfree
	file_size = 0;
	sfp_file_size = 0;
	pos = 0;
	remaining = 0;
	sfp_pos = 0;
	num_read = 0;
	sfp_num_read = 0;
	status = 0;
	num_items = 0;
	buf = NULL; //vfree
	sfp_buf = NULL; //vfree
	kernel_key = NULL; //kfree
	digest = NULL; //kfree
	items = NULL; //vfree
	c_item = NULL; //set to null
	kernel_key_len = 0;
	rsa_pub_key.pkey_algo = CONFIG_TINFOIL_PKALGO;
	rsa_pub_key.id_type = CONFIG_TINFOIL_IDTYPE;
	rsa_pub_key.key = NULL;
	rsa_pub_key.keylen = -1;
	sig.s = NULL;
	sig.s_size = 0;
	sig.digest = NULL;
	sig.digest_size = CONFIG_TINFOIL_DGLEN;
	sig.pkey_algo = CONFIG_TINFOIL_PKALGO;
	sig.hash_algo = CONFIG_TINFOIL_HSALGO;


	kernel_key_len = CONFIG_TINFOIL_PKLEN/2; // Hex/2
	kernel_key = kmalloc(kernel_key_len+1, GFP_KERNEL);

	if(!kernel_key)
		goto fail;

	if (hex2bin(kernel_key, tinfoil.config_pkey, kernel_key_len) == 0) {
		kernel_key[kernel_key_len] = '\0';
	} else {
		goto fail;
	}

	rsa_pub_key.key = kernel_key;
	rsa_pub_key.keylen = kernel_key_len;

	if (IS_ERR(fp = filp_open(tinfoil.config_file, O_RDONLY, 0))) {
		fp = NULL;
		printk(KERN_ERR "flip open fp\n");
		goto fail;
	}

	if (IS_ERR(sfp = filp_open(tinfoil.config_file_signature, O_RDONLY, 0))) {
		printk(KERN_ERR "flip open sfp\n");
		sfp = NULL;
		goto fail;
	}


	file_size = __get_file_size(fp);
	sfp_file_size = __get_file_size(sfp);

	/*default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);*/

	/*default_llseek(sfp, 0, SEEK_END);
	sfp_file_size = sfp->f_pos;
	default_llseek(sfp, sfp->f_pos * -1, SEEK_CUR);*/

	if (!(buf = __read_file_to_memory(fp, file_size, &pos, 0))) {
		printk(KERN_ERR "File Read Error:%s\n", tinfoil.config_file);
		goto fail;
	}

	if (!(sfp_buf = __read_file_to_memory(sfp, sfp_file_size, &sfp_pos, 0))) {
		printk(KERN_ERR "File Read Error:%s\n", tinfoil.config_file_signature);
		goto fail;
	}

	/*
	if((buf = vmalloc(file_size+1)) == NULL) {
		printk(KERN_ERR "alloc buf\n");
		goto fail;
	}
	if ((sfp_buf = vmalloc(sfp_file_size+1)) == NULL) {
		printk(KERN_ERR "alloc sfp_buf\n");
		goto fail;
	}

	num_read = kernel_read(fp,buf,file_size,&pos);
	sfp_num_read = kernel_read(sfp,sfp_buf,sfp_file_size,&sfp_pos);

	if (num_read != file_size) {
		printk(KERN_ERR "File Read Error, size mismatch:%d:%ld\n",
			   num_read,
			   file_size);
	}

	if (sfp_num_read != sfp_file_size) {
		printk(KERN_ERR "File Read Error, size mismatch:%d:%ld\n",
			   sfp_num_read,
			   sfp_file_size);
	}*/

	halg = crypto_alloc_shash(CONFIG_TINFOIL_HSALGO,0,0);
	if (IS_ERR(halg)) {
		halg = NULL;
		goto fail;
	}

	if (!(digest = kmalloc(CONFIG_TINFOIL_DGLEN+1, GFP_KERNEL)))
		goto fail;

	memset(digest,0,CONFIG_TINFOIL_DGLEN+1);

	if(!(hsd = init_sdesc(halg)))
		goto fail;

	crypto_shash_digest(&(hsd->shash), buf, file_size, digest);

	sig.s = sfp_buf;
	sig.s_size = sfp_file_size;
	sig.digest = digest;

	if (local_public_key_verify_signature(&rsa_pub_key, &sig) != 0)
		goto fail;

	for (pos = 0; pos < file_size; pos++) {
		if (buf[pos] == CONFIG_TINFOIL_NEW_LINE) {
			num_items++;
		}
	}

	if (num_items == 0)
		goto fail;

	c_item = items = vmalloc(sizeof(slowboot_validation_item)*num_items);

	if (!c_item) {
		printk(KERN_ERR "Cannot allocate items\n");
		goto fail;
	}

	pos = 0; // reusing
	remaining = file_size;
	while (remaining){
		//printk(KERN_INFO "fii:%d\n", pos);
		pos += fill_in_item(c_item, &buf[pos], &remaining);
		c_item++;
	}

	tinfoil.validation_items = items;
	tinfoil.slwbt_ct = num_items;
	goto out;

fail:
	tinfoil.slwbt_ct = 0;
	if (!items) {
		vfree(items);
	}
	tinfoil.validation_items = NULL;
	status = 1;
out:
	if (fp != NULL)
		filp_close(fp, NULL);
	if (sfp != NULL)
		filp_close(sfp, NULL);
	if (halg != NULL)
		kfree(halg);
	if (buf != NULL)
		vfree(buf);
	if (sfp_buf != NULL)
		vfree(sfp_buf);
	if (kernel_key != NULL)
		kfree(kernel_key);
	if (digest != NULL)
		kfree(digest);
	c_item = NULL;

	return status;
}

/*
 * check /proc/cmdline if it has been overridden
 * dead_value is to prevent a theoretical energy weapon attack
 */
static int slowboot_enabled(void)
{
	struct file *fp;
	size_t file_size;
	char *buf;
	loff_t pos;
	int status;
	int dead_value;

	fp = NULL;
	file_size = 0;
	buf = NULL;
	pos = 0;
	status = 0;
	dead_value = -1;


	fp = filp_open("/proc/cmdline", O_RDONLY, 0);
	if (IS_ERR(fp)) {
		fp = NULL;
		goto out;
	}

	file_size = PAGE_SIZE;
	buf = __read_file_to_memory(fp, file_size, &pos, 1);

	if (!buf) {
		goto out;
	}

	get_random_bytes(&dead_value, sizeof(dead_value));

	if(__gs_memmem_sp(buf, file_size,
			    CONFIG_TINFOIL_OVERRIDE, strlen(CONFIG_TINFOIL_OVERRIDE)) == 0)
		status = dead_value;

out:
	if (fp != NULL)
		filp_close(fp, NULL);
	if (buf != NULL)
		vfree(buf);
	return (status == dead_value ? 0 : 1);
}

/*
 * Run validation test
 */
static void slowboot_run_test(void)
{
	int j, hard_fail;

	if (!slowboot_enabled()) {
		printk(KERN_ERR "Slowboot disabled\n");
		return;
	}
	hard_fail = 0;
	mutex_lock(&gs_concurrency_locker);
	if (tinfoil.initialized != 0) {
		tinfoil.initialized = 0;
		tinfoil.validation_items = NULL;
		if (slowboot_init() != 0) {
			hard_fail = 1;
		}
	}
	mutex_unlock(&gs_concurrency_locker);

	if (hard_fail != 0)
		goto out;
	for (j = 0; j < SLWBT_CT; j++) {
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
out:
	mutex_lock(&gs_concurrency_locker);
		if (tinfoil.validation_items != NULL) {
			vfree(tinfoil.validation_items);
			tinfoil.validation_items = NULL;
			tinfoil.initialized = 1;
		}
	mutex_unlock(&gs_concurrency_locker);

	if (tinfoil.failures > 0 || SLWBT_CT == 0 || hard_fail == 1) {
		CONFIG_TINFOIL_FAIL
	}
}

#ifdef SLOWBOOT_MODULE
static int __init slowboot_mod_init(void)
#endif
#ifndef SLOWBOOT_MODULE
static int slowboot_mod_init(void)
#endif
{
	printk(KERN_INFO "Beginning Tinfoil Verification\n");
	
	tinfoil.failures = 0;
	tinfoil.st = NULL;
	tinfoil.st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil.st) {
		CONFIG_TINFOIL_FAIL
		return -ENOMEM;
	}
	
	slowboot_run_test();
	if (tinfoil.st != NULL)
		kfree(tinfoil.st);
	return 0;
}

#ifdef SLOWBOOT_MODULE
static void __exit slowboot_mod_exit(void) { }


module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");
#endif



//#ifndef SLOWBOOT_MODULE
void tinfoil_verify(void)
{
	#ifndef CONFIG_TINFOIL
		return;
	#endif
	if (slowboot_enabled())
		slowboot_mod_init();

}
//#endif
