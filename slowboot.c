// SPDX-License-Identifier: GPL-2.0-or-later

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

//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$CT
#ifndef SLWBT_CT
#define SLWBT_CT __get_slwbt_ct()
#endif

#ifndef SLWBT_CF
#define SLWBT_CF "/testing/siggywiggy"
#endif

#ifndef SLWBT_CFS
#define SLWBT_CFS "/testing/siggywiggy.sha512"
#endif

#ifndef SLWBT_PK
#define SLWBT_PK "3082020a02820201009af1624ec932c82d57d296ebddf3d8c1cdc03a6c5c709cb3658b33797dd8a94b4183146224a63f8dbf04032690f04c4b05138cf9b0955057e4acf4721c84eb3073eeb1ccc5c6e9bec3d36b1b3bd274c13afb42f33c5c057121debaa622f8f2c0e75bbc99cbcf78767d4225025ece9561ca6022b650ab9c9a68763e7e461164bdfdd07b72e4c623e07b38a7767ac2671c06ea899d6291fddb1eb3d8a6d03fbd78719adec4b92f8881562d73923fcf8f2bd41f324993ecf42c40cd9c596c3b58850aa96a7d28a767b0be8e919fb247897cdc557391753db766991f197217b96e430c8e9bfc3f84a9c45b4aad9e6284e87041eb1709e99fd01e8f23f1f97aa86e255eb8d4bfb13ce6f14264347e40372bb79e17a87e1c541077e8e874092f475b9dbfb4fca981c1358971004421454069c3868cd4fe8fd1ea6d46d9daac7dc00d6b60d998bebbe0121126e3f29acfc3ccc2f24e6eb6c4ab9c0f2e7670e920f33d69eb1f0ca7be630098fe220c1f8ef87e51f8be663a70621a5932ee60888c7e40aa70313e1936bc0c6d742d2c2d2d46c2ceb2b3155ebc777f01bbfad07985e847f8d00c663706b92cf15fd2504ae8dd838d9576763e4ed12e2d6b0a5f7ea21bed613d371a96a25f2206fe6e1724cfcbf2c03d04dda6f623d0d31c036a63f030158478ae820020cf6eff88c70f335db426eeac8205a2875a393d5d67343d534ef54b0203010001"
#endif

#ifndef SLWBT_PKLEN
#define SLWBT_PKLEN 1052
#endif

#ifndef SLWBT_DGLEN
#define SLWBT_DGLEN 64
#endif

#ifndef SLWBT_HSLEN
#define SLWBT_HSLEN 128
#endif

#ifndef SLWBT_PKALGO
#define SLWBT_PKALGO "rsa"
#endif

#ifndef SLWBT_PKALGOPD
#define SLWBT_PKALGOPD "pkcs1pad(rsa,%s)"
#endif

#ifndef SLWBT_HSALGO
#define SLWBT_HSALGO "sha512"
#endif

#ifndef SLWBT_IDTYPE
#define SLWBT_IDTYPE "X509"
#endif

DEFINE_MUTEX(gs_concurrency_locker);

#define SHA512_HASH_LEN 130
#define NEW_LINE '\n'
#define GLOW printk(KERN_ERR "GLOWING\n");

typedef struct slowboot_validation_item {
	char hash[SLWBT_HSLEN+2];
	u8 b_hash[SLWBT_DGLEN+1];
	char path[PATH_MAX+1];
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
	char config_pkey[SLWBT_PKLEN+1];
} slowboot_tinfoil;


static slowboot_tinfoil tinfoil = {
		.config_file = SLWBT_CF,
		.config_file_signature = SLWBT_CFS,
		.config_pkey = SLWBT_PK,
		.initialized = 1
};
/*
static slowboot_validation_item tinfoil_items[] = {
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT
		//{.hash="", .path=""},
};*/

//static struct kstat *st;

static int __get_slwbt_ct(void)
{
	return tinfoil.slwbt_ct;
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


int local_public_key_verify_signature(const struct public_key *pkey,
                const struct public_key_signature *sig)
{
    struct crypto_wait cwait;
    struct crypto_akcipher *tfm;
    struct akcipher_request *req;
    struct scatterlist src_tab[3];
    const char *alg_name;
    char alg_name_buf[CRYPTO_MAX_ALG_NAME];
    void *output;
    unsigned int outlen;
    int ret;

    pr_devel("==>%s()\n", __func__);

    BUG_ON(!pkey);
    BUG_ON(!sig);
    BUG_ON(!sig->s);

    if (!sig->digest)
        return -ENOPKG;

    alg_name = sig->pkey_algo;
    if (strcmp(sig->pkey_algo, SLWBT_PKALGO) == 0) {
        /* The data wangled by the RSA algorithm is typically padded
         * and encoded in some manner, such as EMSA-PKCS1-1_5 [RFC3447
         * sec 8.2].
         */
        if (snprintf(alg_name_buf, CRYPTO_MAX_ALG_NAME,
        		     SLWBT_PKALGOPD, sig->hash_algo
                 ) >= CRYPTO_MAX_ALG_NAME)
            return -EINVAL;
        alg_name = alg_name_buf;
    }

    printk(KERN_INFO "ALGO:%s\n", alg_name);
    tfm = crypto_alloc_akcipher(alg_name, 0, 0);
    if (IS_ERR(tfm)) {
    	printk(KERN_ERR "tfm\n");
        return PTR_ERR(tfm);
    }

    ret = -ENOMEM;
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
    	printk(KERN_ERR "2\n");
        goto error_free_tfm;
    }

    ret = crypto_akcipher_set_pub_key(tfm, pkey->key, pkey->keylen);
    if (ret) {
    	printk(KERN_ERR "3\n");
        goto error_free_req;
    }

    ret = -ENOMEM;
    outlen = crypto_akcipher_maxsize(tfm);
    output = kmalloc(outlen, GFP_KERNEL);
    if (!output) {
    	printk(KERN_ERR "4\n");
        goto error_free_req;
    }


    sg_init_table(src_tab, 3);

    sg_set_buf(&src_tab[1], sig->digest, sig->digest_size);
    sg_set_buf(&src_tab[0], sig->s, sig->s_size);

    akcipher_request_set_crypt(req, src_tab, NULL, sig->s_size, sig->digest_size);

    crypto_init_wait(&cwait);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                      CRYPTO_TFM_REQ_MAY_SLEEP,
                      crypto_req_done, &cwait);


    ret = crypto_wait_req(crypto_akcipher_verify(req), &cwait);
    if (ret) {
    	printk(KERN_ERR "5\n");
        goto out_free_output;
    }
    pr_info("verified successfuly!!!\n");

out_free_output:
    kfree(output);
error_free_req:
    akcipher_request_free(req);
error_free_tfm:
    crypto_free_akcipher(tfm);
    pr_devel("<==%s() = %d\n", __func__, ret);
    if (WARN_ON_ONCE(ret > 0))
        ret = -EINVAL;
    return ret;
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
	
	alg = crypto_alloc_shash(SLWBT_HSALGO, 0, 0);
	if (IS_ERR(alg)) {
		printk(KERN_ERR "Can't allocate alg\n");
	}
	
	digest = kmalloc(SLWBT_DGLEN+1, GFP_KERNEL);
	memset(digest,0,SLWBT_DGLEN+1);
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
	for(j=0;j<SLWBT_DGLEN;j++){
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


static loff_t fill_in_item(slowboot_validation_item *item, char *line, loff_t *remaining)
{
	loff_t pos, off, rem, pst;

	pos = 0;
	off = 0;
	rem = *remaining;
	pst = 0;


	while(rem > 0) {

		//printk(KERN_INFO "X:%d,%c\n",line[pos],line[pos]);

		if (line[pos] == ' ' && off == 0 && rem > 2) {
			off = pos+2;
		}

		if (line[pos] == NEW_LINE) {
			pst = 1;
			//line[pos] = '\0';
			//printk(KERN_INFO "Line:%s\n", line);
			//line[pos] = NEW_LINE;
			break;
		}

		pos++;
		rem--;
	}

	memset(item->path,0,PATH_MAX+1);
	memset(item->hash,0,SLWBT_HSLEN+2);

	// Make sure we have a good item
	// This should not happen because who
	// would sign something malicous?
	if (pos > (SLWBT_HSLEN+5) && (pos-off-1) > 0) {
		memcpy(item->hash, line, SLWBT_HSLEN);
		memcpy(item->path, line+off, pos-off);
	}

	if (rem > 0) {
		pos++;
		rem--;
	}
	*remaining = rem;
	return pos;
}

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
	//struct public_key_signature sig;
	struct public_key rsa_pub_key;

	// Trust nothing
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
	rsa_pub_key.pkey_algo = SLWBT_PKALGO;
	rsa_pub_key.id_type = SLWBT_IDTYPE;


	kernel_key_len = SLWBT_PKLEN/2;
	kernel_key = kmalloc(kernel_key_len+1, GFP_KERNEL);

	if(!kernel_key) {
		goto fail;
	}

	if (hex2bin(kernel_key, tinfoil.config_pkey, kernel_key_len) == 0) {
		kernel_key[kernel_key_len] = '\0';
		printk(KERN_INFO "KERNEL KEY:%s\n", kernel_key);
	} else {
		goto fail;
	}


	rsa_pub_key.key = kernel_key;
	rsa_pub_key.keylen = kernel_key_len;
	/*
	struct public_key rsa_pub_key = {
		.key = kernel_key,
		.keylen = kernel_key_len,
		.pkey_algo = SLWBT_PKALGO,
		.id_type = SLWBT_IDTYPE

	};*/



	/*struct public_key_signature sig = {
		.s = siggywiggy_sha512,
		.s_size = siggywiggy_sha512_len,
		.digest = b_hash,
		.digest_size = 64,
		.pkey_algo = "rsa",
		.hash_algo = "sha512"
	};*/


	printk(KERN_INFO "Beginning SlowBoot 3 '%s'\n", tinfoil.config_file);

	if (IS_ERR(fp = filp_open(tinfoil.config_file, O_RDONLY, 0))) {
		printk(KERN_ERR "flip open fp\n");
		return status;
	}
	default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);

	if (IS_ERR(sfp = filp_open(tinfoil.config_file_signature, O_RDONLY, 0))) {
		printk(KERN_ERR "flip open sfp\n");
		return status;
	}
	default_llseek(sfp, 0, SEEK_END);
	sfp_file_size = sfp->f_pos;
	default_llseek(sfp, sfp->f_pos * -1, SEEK_CUR);

	if((buf = vmalloc(file_size+1)) == NULL) {
		printk(KERN_ERR "alloc buf\n");
		return status;
	}
	if ((sfp_buf = vmalloc(sfp_file_size+1)) == NULL) {
		printk(KERN_ERR "alloc sfp_buf\n");
		return status;
	}
	pos = 0;
	sfp_pos = 0;

	printk(KERN_INFO "Beginning SlowBoot 3 '%s'::'%ld'\n",
		   tinfoil.config_file,
		   file_size);

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
	}

	halg = crypto_alloc_shash(SLWBT_HSALGO,0,0);
	digest = kmalloc(SLWBT_DGLEN+1, GFP_KERNEL);
	memset(digest,0,SLWBT_DGLEN+1);
	hsd = init_sdesc(halg);

	crypto_shash_digest(&(hsd->shash), buf, file_size, digest);

	struct public_key_signature sig = {
		.s = sfp_buf,
		.s_size = sfp_file_size,
		.digest = digest,
		.digest_size = SLWBT_DGLEN,
		.pkey_algo = SLWBT_PKALGO,
		.hash_algo = SLWBT_HSALGO
	};

	if (local_public_key_verify_signature(&rsa_pub_key, &sig) == 0) {
		printk(KERN_INFO "GUD\n");
	} else {
		printk(KERN_ERR "BAT\n");
	}

	num_items = 0;

	for (pos = 0; pos < file_size; pos++){
		if (buf[pos] == '\n') {
			num_items++;
		}
	}

	if (num_items == 0)
		goto out;

	c_item = items = vmalloc(sizeof(slowboot_validation_item)*num_items);

	if (!c_item) {
		printk(KERN_ERR "Bad juju\n");
	}

	pos = 0;
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
	status = 1;
out:
	filp_close(fp, NULL);
	printk(KERN_INFO "Beginning SlowBoot4:%d\n", num_read);

	return status;
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
		printk(KERN_INFO "SBI:%d\n",j);
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

