// SPDX-License-Identifier: GPL-2.0
/*
 * GS Tinfoil/Slowboot Integrity Check Shared
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
////////////////////////////////////////////////////////////////////////////////

/*
 * Failure Option to simply alert
 * @tf: slowboot_tinfoil struct
 */
static void __gs_tinfoil_fail_alert(struct slowboot_tinfoil **tf, int is_bug)
{
	printk(KERN_ERR "Tinfoil Verification Failed\n");
	if (is_bug) {
		if (*tf != NULL)
			kfree(*tf);
		*tf = NULL;
		BUG();
	}
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

/*
 * Allocate data for public key signature validation
 * @sv: sig verify container
 * @pk: public key
 */
static int pk_sig_verify_alloc(struct sig_verify *sv,
			       const struct public_key *pkey)
{
	struct pbit pc;
	sv->tfm = crypto_alloc_akcipher(sv->alg_name, 0, 0);
	if (IS_ERR(sv->tfm)) {
		PBIT_Y(pc, (int)(long)sv->tfm);
		sv->tfm = NULL;
		PBIT_RET(pc);
	}

	sv->req = akcipher_request_alloc(sv->tfm, GFP_KERNEL);
	if (!sv->req) {
		return -ENOMEM;
	}

	if (crypto_akcipher_set_pub_key(sv->tfm, pkey->key, pkey->keylen)) {
		return -EINVAL;
	}

	sv->outlen = crypto_akcipher_maxsize(sv->tfm);
	sv->output = kmalloc(sv->outlen, GFP_KERNEL);
	if (!sv->output) {
		return -ENOMEM;
	}

	return 0;
}

/*
 * Perform signature verification of the config file
 * @sv: sig verify container
 * @sig: public key signature
 */
static int pk_sig_verify_validate(struct sig_verify *sv,
				  const struct public_key_signature *sig)
{
	akcipher_request_set_crypt(sv->req, sv->src_tab, NULL, sig->s_size,
				   sig->digest_size);

	crypto_init_wait(&sv->cwait);
	akcipher_request_set_callback(sv->req,
		CRYPTO_TFM_REQ_MAY_BACKLOG|CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &sv->cwait);

	return crypto_wait_req(crypto_akcipher_verify(sv->req), &sv->cwait);
}

/*
 * Deallocate signature verification data
 * @sv: sig verify container
 */
static void pk_sig_verify_free(struct sig_verify *sv)
{
	if (sv->output != NULL)
		kfree(sv->output);
	if (sv->req != NULL)
		akcipher_request_free(sv->req);
	if (sv->tfm != NULL)
		crypto_free_akcipher(sv->tfm);

	sv->output = NULL;
	sv->req = NULL;
	sv->tfm = NULL;
}

/*
 * Perform signature verification
 * @pkey: public key struct
 * @sig: public key signature struct
 */
int local_public_key_verify_signature(const struct public_key *pkey,
				      const struct public_key_signature *sig,
				      const char *CONFIG_TINFOIL_PKALGOPD)
{
	struct sig_verify sv;
	struct pbit pc;

	if (!pkey || !sig || !sig->s || !sig->digest)
		return -ENOPKG;

	PBIT_N(pc, -EINVAL);

	if (__gs_pk_sig_verify_init(&sv, pkey, sig, CONFIG_TINFOIL_PKALGOPD))
		goto err;

	if (pk_sig_verify_alloc(&sv, pkey))
		goto err;

	if (pk_sig_verify_validate(&sv, sig) == 0) {
		PBIT_Y(pc, 0);
		goto out;
	}

err:
	PBIT_N(pc, -EINVAL);
out:
	pk_sig_verify_free(&sv);
	PBIT_RET(pc);
}

/*
 * Open file related to current item
 * @item: slow boot validation item
 */
static int tinfoil_open(struct slowboot_validation_item *item)
{
	struct pbit pc;
	item->fp = filp_open(item->path, O_RDONLY, 0);
	if (IS_ERR(item->fp) || item->fp == NULL) {
		PBIT_N(pc, (int)(long)item->fp);
		item->fp = NULL;
		printk(KERN_ERR "F:%s:%s:%d\n",
			item->hash,
			item->path,
			PBIT_OK(item->is_ok));
		PBIT_RET(pc);
	}
	item->pos = 0;
	return 0;
}

/*
 * Stat file to get size
 * @item: slow boot validation item
 */
static int tinfoil_stat_alloc(struct slowboot_tinfoil *tinfoil,
			      struct slowboot_validation_item *item)
{
	if (
		vfs_getattr(&(item->fp->f_path),
			tinfoil->st,
			STATX_SIZE,
			AT_STATX_SYNC_AS_STAT
		) != 0) {
		printk(KERN_ERR "Cannot stat:%s\n",
			item->path);
		return -EINVAL;
	}

	item->buf_len = tinfoil->st->size;

	return 0;
}

/*
 * Close file
 * @item: slowboot validation item
 */
static void tinfoil_close(struct slowboot_validation_item *item)
{
	if (item->fp != NULL)
		filp_close(item->fp, NULL);
}

/*
 * read file into buffer
 * @item: slowboot validation item
 */
static int tinfoil_read(struct slowboot_tinfoil *tinfoil,
			struct slowboot_validation_item *item)
{
	struct pbit pc;
	size_t number_read;
	number_read = 0;

	PBIT_N(pc, -EINVAL);

	if (item->fp == NULL)
		goto fail;

	item->buf = vmalloc(item->buf_len+1);
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
		       item->path);
		PBIT_N(pc, -ENOMEM);
		goto fail;
	}
	memset(item->buf,0,item->buf_len+1);

	item->pos = 0;
	number_read = kernel_read(item->fp,
				  item->buf,
				  tinfoil->st->size,
				  &(item->pos));

	if (number_read != item->buf_len) {
		goto fail;
	}

	if (hex2bin(item->b_hash,item->hash,64) !=0) {
		printk(KERN_INFO "StoredHashFail:%s\n", item->path);
		goto fail;
	}

	PBIT_Y(pc, 0);
	goto out;
fail:
	if (item->buf != NULL) {
		vfree(item->buf);
		item->buf = NULL;
	}
out:
	PBIT_RET(pc);
}

/*
 * Zero tinfoil_check and set the item
 * @c: struct tinfoil check
 * @item: slowboot validation item
 */
static int tinfoil_check_init(struct tinfoil_check *c,
			      struct slowboot_validation_item *item)
{
	if (item == NULL || item->buf == NULL || item->buf_len == 0)
		return -EINVAL;

	memset(c,0,sizeof(struct tinfoil_check));

	c->item = item;

	return 0;
}

/*
 * Allocate everyting needed to check one item
 * @c: tinfoil check
 */
static int tinfoil_check_allocate(struct tinfoil_check *c,
				  const char *CONFIG_TINFOIL_HSALGO,
				  int CONFIG_TINFOIL_DGLEN)
{
	struct pbit pc;
	c->alg = crypto_alloc_shash(CONFIG_TINFOIL_HSALGO, 0, 0);
	if (IS_ERR(c->alg)) {
		PBIT_N(pc, (int)(long)c->alg);
		c->alg = NULL;
		printk(KERN_ERR "Can't allocate alg\n");
		PBIT_RET(pc);
	}

	c->digest = kmalloc(CONFIG_TINFOIL_DGLEN+1, GFP_KERNEL);
	if (!c->digest) {
		c->digest = NULL;
		printk(KERN_ERR "Can't allocate digest\n");
		return -ENOMEM;
	}

	memset(c->digest,0,CONFIG_TINFOIL_DGLEN+1);

	c->sd = __gs_init_sdesc(c->alg);
	if (!c->sd) {
		c->sd = NULL;
		printk(KERN_ERR "Can't allocate sdesc\n");
		return -EINVAL;
	}
	return 0;
}

/*
 * Hash and validate the hash
 * @c: tinfoil check
 */
static void tinfoil_check_validate(struct tinfoil_check *c,
				   int CONFIG_TINFOIL_DGLEN)
{
	int i;
	crypto_shash_digest(&(c->sd->shash), c->item->buf, c->item->buf_len,
			    c->digest);

	PBIT_Y(c->item->is_ok, 0);
	for (i=0; i<CONFIG_TINFOIL_DGLEN; i++){
		if (c->item->b_hash[i] != c->digest[i]) {
			PBIT_N(c->item->is_ok, 0);
			return;
		}
	}
}

/*
 * Free Items realted to a tinfoil check
 * @c: tinfoil check
 */
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
static void tinfoil_check(struct slowboot_validation_item *item,
			  const char *CONFIG_TINFOIL_HSALGO,
			  int CONFIG_TINFOIL_DGLEN)
{

	struct tinfoil_check check;

	if (tinfoil_check_init(&check, item))
		goto err;

	if (tinfoil_check_allocate(&check,
				   CONFIG_TINFOIL_HSALGO,
				   CONFIG_TINFOIL_DGLEN))
		goto err;

	tinfoil_check_validate(&check, CONFIG_TINFOIL_DGLEN);
	goto std_return;
err:
	PBIT_N(item->is_ok, 0);
std_return:
	tinfoil_check_free(&check);
}

/*
 * Validate an item (file against it's hash)
 * The functions will log the failure
 * This must return 0 or 1 because it adds to a failure count
 * @item: slowboot validation item
 */
static int tinfoil_unwrap (struct slowboot_tinfoil *tinfoil,
			   struct slowboot_validation_item *item,
			   const char *CONFIG_TINFOIL_HSALGO,
			   int CONFIG_TINFOIL_DGLEN)
{
	if (tinfoil_open(item) != 0)
		return 1;

	if (tinfoil_stat_alloc(tinfoil, item) != 0) {
		tinfoil_close(item);
		return 1;
	}

	// Do not access item->buf after this
	if (tinfoil_read(tinfoil, item) != 0) {
		tinfoil_close(item);
		return 1;
	}

	tinfoil_check(item, CONFIG_TINFOIL_HSALGO, CONFIG_TINFOIL_DGLEN);
	if (!PBIT_OK(item->is_ok)) {
		printk(KERN_ERR "File:%s:%s\n",
		       item->path,
		       "Fail");
	}
	tinfoil_close(item);
	if (PBIT_OK(item->is_ok))
		return 0;
	else
		return 1;
}

/*
 * Parse one line, fill in the item
 * @item: slowboot validation item
 * @line: start of current line
 * @remaining: remaining bytes
 */
static loff_t fill_in_item(struct slowboot_validation_item *item,
			   char *line, loff_t *remaining,
			   const char CONFIG_TINFOIL_NEW_LINE,
			   int CONFIG_TINFOIL_HSLEN)
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
 * initialize slowboot init container items
 * @sic: slowboot init container
 */
static void slowboot_init_setup(struct slowboot_init_container *sic,
				const char *CONFIG_TINFOIL_PKALGO,
				const char *CONFIG_TINFOIL_IDTYPE,
				int CONFIG_TINFOIL_DGLEN,
				const char *CONFIG_TINFOIL_HSALGO,
				int CONFIG_TINFOIL_PKLEN)
{
	memset(sic, 0, sizeof(struct slowboot_init_container));

	sic->rsa_pub_key.pkey_algo = CONFIG_TINFOIL_PKALGO;
	sic->rsa_pub_key.id_type = CONFIG_TINFOIL_IDTYPE;
	sic->rsa_pub_key.keylen = -1;
	sic->sig.digest_size = CONFIG_TINFOIL_DGLEN;
	sic->sig.pkey_algo = CONFIG_TINFOIL_PKALGO;
	sic->sig.hash_algo = CONFIG_TINFOIL_HSALGO;
	sic->kernel_key_len = CONFIG_TINFOIL_PKLEN/2; // Hex/2
}

/*
 * Set up keys
 * @sic: slowboot init container
 * @config_pkey: hex representation of DER encoded public key
 */
static int slowboot_init_setup_keys(struct slowboot_init_container *sic,
				    const char * config_pkey)
{

	if (sic->kernel_key_len <= 0 || config_pkey == NULL)
		return -EINVAL;

	sic->kernel_key = (unsigned char *)
			  kmalloc(sic->kernel_key_len+1, GFP_KERNEL);
	if(!sic->kernel_key)
		return -ENOMEM;

	if (hex2bin(sic->kernel_key, config_pkey, sic->kernel_key_len) == 0)
		sic->kernel_key[sic->kernel_key_len] = '\0';
	else
		return -EINVAL;

	sic->rsa_pub_key.key = sic->kernel_key;
	sic->rsa_pub_key.keylen = sic->kernel_key_len;

	return 0;
}

/*
 * Open config files, read them into memory
 * @sic: slowboot init container
 * @config_file: hash path\n format config file
 * @config_file_signature: raw binary checksum file of @config_file
 */
static int slowboot_init_open_files(struct slowboot_init_container *sic,
				    const char *config_file,
				    const char *config_file_signature)
{
	struct pbit pc;

	if (config_file == NULL || config_file_signature == NULL)
		return -EINVAL;

	if (IS_ERR(sic->fp = filp_open(config_file, O_RDONLY, 0))) {
		PBIT_N(pc, (int)(long)sic->fp);
		sic->fp = NULL;
		printk(KERN_ERR "flip open fp\n");
		PBIT_RET(pc);
	}

	if (IS_ERR(sic->sfp = filp_open(config_file_signature, O_RDONLY, 0))) {
		PBIT_N(pc, (int)(long)sic->sfp);
		sic->sfp = NULL;
		printk(KERN_ERR "flip open sfp\n");
		PBIT_RET(pc);
	}

	sic->file_size = __gs_get_file_size(sic->fp);
	sic->sfp_file_size = __gs_get_file_size(sic->sfp);

	if (sic->file_size <= 0 || sic->sfp_file_size <= 0)
		return -EINVAL;

	sic->pos = 0;
	if (!(sic->buf = __gs_read_file_to_memory(sic->fp, sic->file_size,
					       &sic->pos, 0))) {
		printk(KERN_ERR "File Read Error:%s\n", config_file);
		return -EINVAL;
	}

	sic->sfp_pos = 0;
	if (!(sic->sfp_buf = __gs_read_file_to_memory(sic->sfp, sic->sfp_file_size,
						   &sic->sfp_pos, 0))) {
		printk(KERN_ERR "File Read Error:%s\n", config_file_signature);
		return -EINVAL;
	}

	return 0;
}

/*
 * Intiatilize and perform hash digest of the config file
 * @sic: slowboot init container
 */
static int slowboot_init_digest(struct slowboot_init_container *sic,
				int CONFIG_TINFOIL_DGLEN,
				const char *CONFIG_TINFOIL_HSALGO)
{
	struct pbit pc;
	sic->halg = crypto_alloc_shash(CONFIG_TINFOIL_HSALGO,0,0);
	if (IS_ERR(sic->halg)) {
		PBIT_N(pc, (int)(long)sic->halg);
		sic->halg = NULL;
		PBIT_RET(pc);
	}

	if (!(sic->digest = kmalloc(CONFIG_TINFOIL_DGLEN+1, GFP_KERNEL)))
		return -ENOMEM;

	memset(sic->digest,0,CONFIG_TINFOIL_DGLEN+1);

	if(!(sic->hsd = __gs_init_sdesc(sic->halg)))
		return -EINVAL;

	if (sic->buf == NULL || sic->file_size <= 0)
		return -EINVAL;

	crypto_shash_digest(&(sic->hsd->shash), sic->buf, sic->file_size,
			    sic->digest);

	sic->sig.s = sic->sfp_buf; // Raw signature file data
	sic->sig.s_size = sic->sfp_file_size; // Length of Signature File
	sic->sig.digest = sic->digest; // Hash of the config file

	return 0;
}

/*
 * Free slowboot init container items
 * @sic: slowboot init container
 */
static void slowboot_init_free(struct slowboot_init_container *sic)
{
	if (sic->fp != NULL)
		filp_close(sic->fp, NULL);
	if (sic->sfp != NULL)
		filp_close(sic->sfp, NULL);
	if (sic->halg != NULL)
		kfree(sic->halg);
	if (sic->buf != NULL)
		vfree(sic->buf);
	if (sic->sfp_buf != NULL)
		vfree(sic->sfp_buf);
	if (sic->kernel_key != NULL)
		kfree(sic->kernel_key);
	if (sic->digest != NULL)
		kfree(sic->digest);
	sic->c_item = NULL;
}

/*
 * Determine the number of lines, allocate enough space for all items
 * parse all the lines, update values to reflect
 * @sic: slowboot init container
 * @item_ref: ** to array of items, set to not null by function on success
 * @item-ct: * to item count, updated by function
 */
static int slowboot_init_process(struct slowboot_init_container *sic,
				 struct slowboot_validation_item **item_ref,
				 int *item_ct,
				 const char CONFIG_TINFOIL_NEW_LINE,
				 int CONFIG_TINFOIL_HSLEN)
{

	if (sic->file_size <= 0)
		return -EINVAL;

	for (sic->pos = 0; sic->pos < sic->file_size; sic->pos++) {
		if (sic->buf[sic->pos] == CONFIG_TINFOIL_NEW_LINE) {
			sic->num_items++;
		}
	}

	if (sic->num_items == 0)
		return -EINVAL;

	sic->c_item = sic->items = (struct slowboot_validation_item *)
				vmalloc(sizeof(struct slowboot_validation_item)
					*sic->num_items);

	if (!sic->c_item) {
		printk(KERN_ERR "Cannot allocate items\n");
		return -ENOMEM;
	}

	sic->pos = 0; // reusing
	sic->remaining = sic->file_size;
	while (sic->remaining){
		sic->pos += fill_in_item(sic->c_item, &sic->buf[sic->pos],
					 &sic->remaining,
					 CONFIG_TINFOIL_NEW_LINE,
					 CONFIG_TINFOIL_HSLEN);
		sic->c_item++;
	}

	*item_ref = sic->items;
	*item_ct = sic->num_items;
	return 0;
}

/*
 * Signature check the config file and initialize all the data
 * The functions called will log the error so no need to store/check
 * @tinfoil: slowboot tinfoil
 */
static int slowboot_init(struct slowboot_tinfoil *tinfoil,
			 const char *CONFIG_TINFOIL_PKALGOPD,
			 const char *CONFIG_TINFOIL_PKALGO,
			 const char *CONFIG_TINFOIL_IDTYPE,
			 int CONFIG_TINFOIL_DGLEN,
			 const char *CONFIG_TINFOIL_HSALGO,
			 int CONFIG_TINFOIL_PKLEN,
			 const char CONFIG_TINFOIL_NEW_LINE,
			 int CONFIG_TINFOIL_HSLEN)
{
	struct slowboot_init_container sic;
	struct pbit pc;
	PBIT_N(pc, -EINVAL);

	slowboot_init_setup(&sic,
			    CONFIG_TINFOIL_PKALGO,
			    CONFIG_TINFOIL_IDTYPE,
			    CONFIG_TINFOIL_DGLEN,
			    CONFIG_TINFOIL_HSALGO,
			    CONFIG_TINFOIL_PKLEN);

	if(slowboot_init_setup_keys(&sic, tinfoil->config_pkey))
		goto fail;

	if(slowboot_init_open_files(&sic, tinfoil->config_file,
				    tinfoil->config_file_signature))
		goto fail;

	if(slowboot_init_digest(&sic,
				CONFIG_TINFOIL_DGLEN,
				CONFIG_TINFOIL_HSALGO))
		goto fail;

	if (local_public_key_verify_signature(&sic.rsa_pub_key,
					      &sic.sig,
					      CONFIG_TINFOIL_PKALGOPD))
		goto fail;

	if(slowboot_init_process(&sic, &tinfoil->validation_items,
				 &tinfoil->slwbt_ct,
				 CONFIG_TINFOIL_NEW_LINE,
				 CONFIG_TINFOIL_HSLEN))
		goto fail;

	PBIT_Y(pc, 0);
	goto out;

fail:
	PBIT_N(pc, -EINVAL);
	tinfoil->slwbt_ct = 0;
	if (!sic.items) {
		vfree(sic.items);
	}
	tinfoil->validation_items = NULL;
out:
	slowboot_init_free(&sic);
	PBIT_RET(pc);
}

/*
 * Check for /proc/cmdlin override
 */
static int slowboot_enabled(const char *CONFIG_TINFOIL_OVERRIDE)
{
	struct file *fp;
	size_t file_size;
	char *buf;
	loff_t pos;
	struct pbit pc;

	fp = NULL;
	file_size = 0;
	buf = NULL;
	pos = 0;

	PBIT_N(pc, 0);

	fp = filp_open("/proc/cmdline", O_RDONLY, 0);
	if (IS_ERR(fp)) {
		fp = NULL;
		PBIT_N(pc, (int)(long int)fp);
		goto out;
	}

	file_size = PAGE_SIZE;
	buf = __gs_read_file_to_memory(fp, file_size, &pos, 1);

	if (!buf) {
		PBIT_N(pc, -ENOMEM);
		goto out;
	}

	if(__gs_memmem_sp(buf, file_size,
			  CONFIG_TINFOIL_OVERRIDE,
			  strlen(CONFIG_TINFOIL_OVERRIDE)) == 0)
		PBIT_Y(pc, 0);

out:
	if (fp != NULL)
		filp_close(fp, NULL);
	if (buf != NULL)
		vfree(buf);

	if (!PBIT_FAIL(pc) || PBIT_GET(pc) != 0)
		printk(KERN_ERR "Error at slowboot_enabled: %d\n",
		       PBIT_GET(pc));

	if (PBIT_OK(pc) && PBIT_GET(pc) == 0)
		return 0;
	else
		return 1;

}

/*
 * Run validation test
 * @tinfoil: slowboot tinfoil struct
 */
static void slowboot_run_test(struct slowboot_tinfoil *tinfoil,
			      const char *CONFIG_TINFOIL_PKALGOPD,
			      const char *CONFIG_TINFOIL_PKALGO,
			      const char *CONFIG_TINFOIL_IDTYPE,
			      int CONFIG_TINFOIL_DGLEN,
			      const char *CONFIG_TINFOIL_HSALGO,
			      int CONFIG_TINFOIL_PKLEN,
			      const char CONFIG_TINFOIL_NEW_LINE,
			      int CONFIG_TINFOIL_HSLEN,
			      spinlock_t *gs_irq_killer)
{
	int j;
	unsigned long flags;
	struct pbit hard_fail;

	if (tinfoil == NULL)
		BUG();

	PBIT_Y(hard_fail, 0);
	PBIT_N(tinfoil->error, -EINVAL);

	spin_lock_irqsave(gs_irq_killer, flags); // Occupy all threads?
	if (tinfoil->initialized != 0) {
		tinfoil->initialized = 0;
		tinfoil->validation_items = NULL;
		if (slowboot_init(tinfoil,
				  CONFIG_TINFOIL_PKALGOPD,
				  CONFIG_TINFOIL_PKALGO,
				  CONFIG_TINFOIL_IDTYPE,
				  CONFIG_TINFOIL_DGLEN,
				  CONFIG_TINFOIL_HSALGO,
				  CONFIG_TINFOIL_PKLEN,
				  CONFIG_TINFOIL_NEW_LINE,
				  CONFIG_TINFOIL_HSLEN) != 0) {
			PBIT_N(hard_fail, 0);
			goto out;
		}
	}

	for (j = 0; j < tinfoil->slwbt_ct; j++) {
		tinfoil->failures += tinfoil_unwrap(tinfoil,
					&(tinfoil->validation_items[j]),
					CONFIG_TINFOIL_HSALGO,
					CONFIG_TINFOIL_DGLEN);
	}
out:
		if (tinfoil->validation_items != NULL) {
			vfree(tinfoil->validation_items);
			tinfoil->validation_items = NULL;
			tinfoil->initialized = 1;
		}

	if (tinfoil->failures != 0 || tinfoil->slwbt_ct == 0 ||
	    !PBIT_OK(hard_fail))
		PBIT_N(tinfoil->error, -EINVAL);
	else
		PBIT_Y(tinfoil->error, 0);
	spin_unlock_irqrestore(gs_irq_killer, flags);
}

/*
 * Initialize data for verification process
 * @tinfoil: slowboot tinfoil struct
 */
static int slowboot_tinfoil_init(struct slowboot_tinfoil *tinfoil,
				 const char *CONFIG_TINFOIL_CF,
				 const char *CONFIG_TINFOIL_CFS,
				 const char *CONFIG_TINFOIL_PK,
				 int CONFIG_TINFOIL_PKLEN)
{
	if (tinfoil == NULL)
		return -EINVAL;

	memset(tinfoil, 0, sizeof(struct slowboot_tinfoil));
	strncpy(tinfoil->config_file, CONFIG_TINFOIL_CF, PATH_MAX);
	strncpy(tinfoil->config_file_signature, CONFIG_TINFOIL_CFS, PATH_MAX);
	strncpy(tinfoil->config_pkey, CONFIG_TINFOIL_PK, CONFIG_TINFOIL_PKLEN);
	tinfoil->initialized = 1;
	tinfoil->failures = 0;
	PBIT_Y(tinfoil->error, 0);
	tinfoil->st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil->st) {
		PBIT_N(tinfoil->error, -ENOMEM);
		return 1;
	}
	return 0;
}

/*
 * Deallocate data
 * @tinfoil: slowboot tinfoil struct
 */
static void slowboot_tinfoil_free(struct slowboot_tinfoil *tinfoil)
{
	if (tinfoil->st != NULL) {
		kfree(tinfoil->st);
		tinfoil->st = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////
/*
 * Obtain size of file via seeking
 * @fp: struct file
 */
size_t __gs_get_file_size(struct file *fp)
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
char *__gs_read_file_to_memory(struct file *fp,
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
 * Initialize sdesc struct for digest measuring
 * @alg: crypto_shash structure
 */
struct sdesc *__gs_init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = (struct sdesc *)kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return NULL;
	sdesc->shash.tfm = alg;
	return sdesc;
}

/*
 * Initialize public key signature verification
 * @sv: sig verify container
 * @pkey: public key
 * @sig: public key signature
 * @pkalgopd: padding string
 */
int __gs_pk_sig_verify_init(struct sig_verify *sv,
			    const struct public_key *pkey,
			    const struct public_key_signature *sig,
			    const char *pkalgopd)
{
	memset(sv, 0, sizeof(struct sig_verify));

	if (pkalgopd != NULL && strlen(pkalgopd) > 0) {
		snprintf(sv->alg_name_buf, CRYPTO_MAX_ALG_NAME,
				pkalgopd);
		sv->alg_name = sv->alg_name_buf;
	} else
		sv->alg_name = sig->pkey_algo;

	sg_init_table(sv->src_tab, 3);
	sg_set_buf(&sv->src_tab[1], sig->digest, sig->digest_size);
	sg_set_buf(&sv->src_tab[0], sig->s, sig->s_size);
	return 0;
}

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
		 int config_bug_on_fail)
{
	struct slowboot_tinfoil *tinfoil;
	struct pbit pc;

	if (!slowboot_enabled(config_tinfoil_override)) {
		printk(KERN_ERR "slowboot_mod_init: disabled\n");
		return 0;
	}

	PBIT_N(pc, -EINVAL);
	printk(KERN_INFO "Tinfoil Verification Starting\n");

	tinfoil = kmalloc(sizeof(struct slowboot_tinfoil), GFP_KERNEL);
	if (!tinfoil) {
		PBIT_N(pc, -ENOMEM);
		goto out;
	}


	if(slowboot_tinfoil_init(tinfoil,
				 config_tinfoil_cf,
				 config_tinfoil_cfs,
				 config_tinfoil_pk,
				 config_tinfoil_pklen)) {
		PBIT_N(pc, -EINVAL);
		goto out;
	}

	slowboot_run_test(tinfoil,
			  config_tinfoil_pkalgopd,
			  config_tinfoil_pkalgo,
			  config_tinfoil_idtype,
			  config_tinfoil_dglen,
			  config_tinfoil_hsalgo,
			  config_tinfoil_pklen,
			  config_tinfoil_new_line,
			  config_tinfoil_hslen,
			  gs_irq_killer);

out:
	if (tinfoil) {
		slowboot_tinfoil_free(tinfoil);

		printk(KERN_INFO "Tinfoil Audit: {Total:%d/Failures:%d}\n",
		       tinfoil->slwbt_ct, tinfoil->failures);

		if (!PBIT_OK(tinfoil->error) || PBIT_GET(tinfoil->error) != 0) {
			PBIT_N(pc, PBIT_GET(tinfoil->error));
			if (PBIT_GET(tinfoil->error) == 0)
				PBIT_N(pc, -EINVAL);
		} else
			PBIT_Y(pc, 0);

	} else {
		PBIT_N(pc, -EINVAL);
	}


	if (PBIT_GET(pc) != 0 || !PBIT_OK(pc)) {
		__gs_tinfoil_fail_alert(&tinfoil, config_bug_on_fail);
		if (tinfoil != NULL) {
			kfree(tinfoil);
			tinfoil = NULL;
		}
		PBIT_RET(pc);
	} else
		PBIT_RET(pc);

}
