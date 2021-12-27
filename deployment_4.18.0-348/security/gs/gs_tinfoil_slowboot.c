// SPDX-License-Identifier: GPL-2.0
/*
 * GlowSlayer Tinfoil/Slowboot Shared
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
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/random.h>
#include <linux/gs_pbit.h>
#include <linux/gs_tinfoil_slowboot.h>
/*******************************************************************************
 *         ___   _                  ___   _                                    *
 *        / __| | |  ___  __ __ __ / __| | |  __ _   _  _   ___   _ _          *
 *       | (_-\ | | / _ \ \ V  V / \__ \ | | / _` | | || | / -_) | '_|         *
 *        \___| |_| \___/  \_/\_/  |___/ |_| \__,_|  \_, | \___| |_|           *
 *                                                   |__/                      *
 *                        Dedicated to Terry A. Davis                          *
 ******************************************************************************/
#define GLOW(code, spot, FUNC) pr_err("GS TFSB Fail ErrorCode: %d @ %s.%s\n",\
				code, spot, FUNC)
////////////////////////////////////////////////////////////////////////////////

/*
 * Failure Option to simply alert
 * @tf: slowboot_tinfoil struct
 */
static void __gs_tinfoil_fail_alert(struct slowboot_tinfoil **tf)
{
	pr_err("GS TFSB FAIL\n");
}

/*
 * Allocate data for public key signature validation
 * @sv: sig verify container
 * @pk: public key
 */
static int pk_sig_verify_alloc(struct sig_verify *sv,
			       const struct public_key *pkey)
{
	struct pbit pc;

	if (sv == NULL || sv->alg_name == NULL) {
		GLOW(-EINVAL, __func__, "Null Parameters Passed");
		return -EINVAL;
	}

	sv->tfm = crypto_alloc_akcipher(sv->alg_name, 0, 0);
	if (IS_ERR(sv->tfm)) {
		pbit_y(&pc, (int)(long)sv->tfm);
		sv->tfm = NULL;
		GLOW(pbit_get(&pc), __func__, "crypto_alloc_akcipher");
		return pbit_ret(&pc);
	}

	sv->req = akcipher_request_alloc(sv->tfm, GFP_KERNEL);
	if (!sv->req) {
		return -ENOMEM;
	}

	if (pkey == NULL || pkey->key == NULL || pkey->keylen <= 0) {
		GLOW(-EINVAL, __func__, "Invalid Public Key Parameters");
		return -EINVAL;
	}

	if (crypto_akcipher_set_pub_key(sv->tfm, pkey->key, pkey->keylen)) {
		GLOW(-EINVAL,
		     __func__, "crypto_akcipher_set_pub_key");
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
	if (sv == NULL || sig == NULL || sv->req == NULL) {
		GLOW(-EINVAL, __func__, "Invalid Parameters Passed");
		return -EINVAL;
	}

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
				      const char *XCFG_TINFOIL_PKALGOPD)
{
	struct sig_verify sv;
	struct pbit pc;

	if (!pkey || !sig || !sig->s || !sig->digest)
		return -ENOPKG;

	pbit_n(&pc, -EINVAL);

	if (__gs_pk_sig_verify_init(&sv, pkey, sig, XCFG_TINFOIL_PKALGOPD)) {
		GLOW(-EINVAL, __func__, "__gs_pk_sig_verify_init");
		goto err;
	}

	if (pk_sig_verify_alloc(&sv, pkey)) {
		GLOW(-EINVAL, __func__, "pk_sig_verify_alloc");
		goto err;
	}

	if (pk_sig_verify_validate(&sv, sig) == 0) {
		pbit_y(&pc, 0);
		goto out;
	} else
		GLOW(-EINVAL, __func__, "pk_sig_verify_validate");

err:
	pbit_n(&pc, -EINVAL);
out:
	pk_sig_verify_free(&sv);
	return pbit_ret(&pc);
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
		pbit_n(&pc, (int)(long)item->fp);
		item->fp = NULL;
		pr_err("GS TFSB Fail:%s:%s:%d @ %s.filp_open\n",
		       item->hash,
		       item->path,
		       pbit_ok(&item->is_ok),
		       __func__);
		return pbit_ret(&pc);
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
		pr_err("GS TFSB Fail: Cannot Stat:%s @ %s.vfs_getattr\n",
		       item->path,
		       __func__);
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
 * @tinfoil: slowboot_tinfoil
 * @item: slowboot validation item
 */
static int tinfoil_read(struct slowboot_tinfoil *tinfoil,
			struct slowboot_validation_item *item)
{
	struct pbit pc;
	size_t number_read;

	number_read = 0;
	pbit_n(&pc, -EINVAL);

	if (item->fp == NULL)
		goto fail;

	item->buf = vmalloc(item->buf_len+1);
	if (!item->buf) {
		pbit_n(&pc, -ENOMEM);
		goto fail;
	}
	memset(item->buf, 0, item->buf_len+1);

	item->pos = 0;
	number_read = kernel_read(item->fp,
				  item->buf,
				  tinfoil->st->size,
				  &(item->pos));

	if (number_read != item->buf_len)
		goto fail;

	if (hex2bin(item->b_hash, item->hash, 64) != 0) {
		pr_err("GS TFSB Fail: StoredHashFail:%s @ %s.hex2bin\n",
		       item->path, __func__);
		goto fail;
	}

	pbit_y(&pc, 0);
	goto out;
fail:
	if (item->buf != NULL) {
		vfree(item->buf);
		item->buf = NULL;
	}
out:
	return pbit_ret(&pc);
}

/*
 * Zero tinfoil_check and set the item
 * @c: struct tinfoil check
 * @item: slowboot validation item
 */
static int tinfoil_check_init(struct tinfoil_check *c,
			      struct slowboot_validation_item *item)
{
	memset(c, 0, sizeof(struct tinfoil_check));

	if (item == NULL || item->buf == NULL || item->buf_len == 0)
		return -EINVAL;

	c->item = item;

	return 0;
}

/*
 * Allocate everyting needed to check one item
 * @c: tinfoil check
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_DGLEN: digest length
 */
static int tinfoil_check_allocate(struct tinfoil_check *c,
				  const char *XCFG_TINFOIL_HSALGO,
				  int XCFG_TINFOIL_DGLEN)
{
	struct pbit pc;

	c->alg = crypto_alloc_shash(XCFG_TINFOIL_HSALGO, 0, 0);
	if (IS_ERR(c->alg)) {
		pbit_n(&pc, (int)(long)c->alg);
		c->alg = NULL;
		GLOW(pbit_get(&pc), __func__, "crypto_alloc_shash");
		return pbit_ret(&pc);
	}

	c->digest = kmalloc(XCFG_TINFOIL_DGLEN+1, GFP_KERNEL);
	if (!c->digest) {
		c->digest = NULL;
		GLOW(pbit_get(&pc), __func__, "kmalloc");
		return -ENOMEM;
	}

	memset(c->digest, 0, XCFG_TINFOIL_DGLEN+1);

	c->sd = __gs_init_sdesc(c->alg);
	if (!c->sd) {
		c->sd = NULL;
		GLOW(-EINVAL, __func__, "__gs_init_sdesc");
		return -EINVAL;
	}
	return 0;
}

/*
 * Hash and validate the hash
 * @c: tinfoil check
 * @XCFG_TINFOIL_DGLEN: digest length
 */
static void tinfoil_check_validate(struct tinfoil_check *c,
				   int XCFG_TINFOIL_DGLEN)
{
	int i;

	crypto_shash_digest(&(c->sd->shash), c->item->buf, c->item->buf_len,
			    c->digest);

	pbit_y(&c->item->is_ok, 0);
	for (i = 0; i < XCFG_TINFOIL_DGLEN; i++) {
		if (c->item->b_hash[i] != c->digest[i]) {
			pbit_n(&c->item->is_ok, 0);
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
	if (c->item != NULL && c->item->buf != NULL) {
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
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_DGLEN: digest length
 * consumes item->buf
 */
static void tinfoil_check(struct slowboot_validation_item *item,
			  const char *XCFG_TINFOIL_HSALGO,
			  int XCFG_TINFOIL_DGLEN)
{

	struct tinfoil_check check;

	if (tinfoil_check_init(&check, item)) {
		GLOW(-EINVAL, __func__, "tinfoil_check_init");
		goto err;
	}

	if (tinfoil_check_allocate(&check,
				   XCFG_TINFOIL_HSALGO,
				   XCFG_TINFOIL_DGLEN)) {
		GLOW(-EINVAL, __func__, "tinfoil_check_allocate");
		goto err;
	}

	tinfoil_check_validate(&check, XCFG_TINFOIL_DGLEN);
	goto std_return;
err:
	pbit_n(&item->is_ok, 0);
std_return:
	tinfoil_check_free(&check);
}

/*
 * Validate an item (file against it's hash)
 * The functions will log the failure
 * This must return 0 or 1 because it adds to a failure count
 * @tinfoil: slowboot_tinfoil
 * @item: slowboot validation item
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_DGLEN: digest length
 */
static int tinfoil_unwrap(struct slowboot_tinfoil *tinfoil,
			  struct slowboot_validation_item *item,
			  const char *XCFG_TINFOIL_HSALGO,
			  int XCFG_TINFOIL_DGLEN)
{
	if (tinfoil_open(item) != 0) {
		GLOW(1, __func__, "tinfoil_open");
		return 1;
	}

	if (tinfoil_stat_alloc(tinfoil, item) != 0) {
		GLOW(1, __func__, "tinfoil_close");
		tinfoil_close(item);
		return 1;
	}

	// Do not access item->buf after this
	if (tinfoil_read(tinfoil, item) != 0) {
		GLOW(1, __func__, "tinfoil_read");
		tinfoil_close(item);
		return 1;
	}

	tinfoil_check(item, XCFG_TINFOIL_HSALGO, XCFG_TINFOIL_DGLEN);
	if (!pbit_ok(&item->is_ok)) {
		pr_err("GS TFSB Fail:%s:%s @ %s.tinfoil_check\n",
		       item->path,
		       "Fail",
		       __func__);
	}
	tinfoil_close(item);
	if (pbit_ok(&item->is_ok))
		return 0;
	else
		return 1;
}

/*
 * Parse one line, fill in the item
 * @item: slowboot validation item
 * @line: start of current line
 * @remaining: remaining bytes
 * @XCFG_TINFOIL_NEW_LINE: new line character in the config file
 * @XCFG_TINFOIL_HSLEN: hash length in hex encoding (output of sha512sum CLI)
 */
static loff_t fill_in_item(struct slowboot_validation_item *item,
			   char *line, loff_t *remaining,
			   const char XCFG_TINFOIL_NEW_LINE,
			   int XCFG_TINFOIL_HSLEN)
{
	loff_t pos;
	loff_t off;
	loff_t rem;

	if (line == NULL) {
		if (remaining != NULL)
			*remaining = 0;
		return 0;
	}

	pos = 0;
	off = 0;
	rem = *remaining;

	while (rem > 0) {
		if (line[pos] == ' ' && off == 0 && rem > 1)
			off = pos+1;

		if (line[pos] == XCFG_TINFOIL_NEW_LINE)
			break;

		pos++;
		rem--;
	}

	if (item->path != NULL && item->hash != NULL) {
		memset(item->path, 0, PATH_MAX+1);
		memset(item->hash, 0, XCFG_TINFOIL_HSLEN+2);

		// Make sure we have a good item
		// This should not happen because who
		// would sign something malicous?
		if (pos > (XCFG_TINFOIL_HSLEN+5) && (pos-off-1) > 0) {
			memcpy(item->hash, line, XCFG_TINFOIL_HSLEN);
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
 * @XCFG_TINFOIL_PKALGO: public key algorithm
 * @XCFG_TINFOIL_IDTYPE: ID TYPE
 * @XCFG_TINFOIL_DGLEN: digest length
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_PKLEN: public key length
 */
static void slowboot_init_setup(struct slowboot_init_container *sic,
				const char *XCFG_TINFOIL_PKALGO,
				const char *XCFG_TINFOIL_IDTYPE,
				int XCFG_TINFOIL_DGLEN,
				const char *XCFG_TINFOIL_HSALGO,
				int XCFG_TINFOIL_PKLEN)
{
	memset(sic, 0, sizeof(struct slowboot_init_container));

	sic->rsa_pub_key.pkey_algo = XCFG_TINFOIL_PKALGO;
	sic->rsa_pub_key.id_type = XCFG_TINFOIL_IDTYPE;
	sic->rsa_pub_key.keylen = -1;
	sic->sig.digest_size = XCFG_TINFOIL_DGLEN;
	sic->sig.pkey_algo = XCFG_TINFOIL_PKALGO;
	sic->sig.hash_algo = XCFG_TINFOIL_HSALGO;
	sic->kernel_key_len = XCFG_TINFOIL_PKLEN/2; // Hex/2
}

/*
 * Set up keys
 * @sic: slowboot init container
 * @config_pkey: hex representation of DER encoded public key
 */
static int slowboot_init_setup_keys(struct slowboot_init_container *sic,
				    const char *config_pkey)
{

	if (sic->kernel_key_len <= 0 || config_pkey == NULL)
		return -EINVAL;

	sic->kernel_key = kmalloc(sic->kernel_key_len+1, GFP_KERNEL);
	if (!sic->kernel_key)
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

	sic->fp = filp_open(config_file, O_RDONLY, 0);
	if (IS_ERR(sic->fp)) {
		pbit_n(&pc, (int)(long)sic->fp);
		sic->fp = NULL;
		GLOW(pbit_get(&pc), __func__, "config_file");
		return pbit_ret(&pc);
	}

	sic->sfp = filp_open(config_file_signature, O_RDONLY, 0);
	if (IS_ERR(sic->sfp)) {
		pbit_n(&pc, (int)(long)sic->sfp);
		sic->sfp = NULL;
		GLOW(pbit_get(&pc), __func__, "config_file_signature");
		return pbit_ret(&pc);
	}

	sic->file_size = __gs_get_file_size(sic->fp);
	sic->sfp_file_size = __gs_get_file_size(sic->sfp);

	if (sic->file_size <= 0 || sic->sfp_file_size <= 0) {
		GLOW(-EINVAL, __func__, "invalid file size");
		return -EINVAL;
	}

	sic->pos = 0;
	sic->buf = __gs_read_file_to_memory(sic->fp, sic->file_size,
					    &sic->pos, 0);
	if (!sic->buf) {
		pr_err("GS TFSB File Read Error:%s @ %s.config_file\n",
		       config_file,
		       __func__);
		return -EINVAL;
	}

	sic->sfp_pos = 0;
	sic->sfp_buf = __gs_read_file_to_memory(sic->sfp, sic->sfp_file_size,
						&sic->sfp_pos, 0);
	if (!sic->sfp_buf) {
		pr_err("GS TFSB File Read Error:%s @ %s.config_file_signature\n",
			config_file_signature,
			__func__);
		return -EINVAL;
	}

	return 0;
}

/*
 * Intiatilize and perform hash digest of the config file
 * @sic: slowboot init container
 * @XCFG_TINFOIL_DGLEN: digest length
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 */
static int slowboot_init_digest(struct slowboot_init_container *sic,
				int XCFG_TINFOIL_DGLEN,
				const char *XCFG_TINFOIL_HSALGO)
{
	struct pbit pc;

	sic->halg = crypto_alloc_shash(XCFG_TINFOIL_HSALGO, 0, 0);
	if (IS_ERR(sic->halg)) {
		pbit_n(&pc, (int)(long)sic->halg);
		GLOW(pbit_get(&pc), __func__, "crypto_alloc_shash");
		sic->halg = NULL;
		return pbit_ret(&pc);
	}

	sic->digest = kmalloc(XCFG_TINFOIL_DGLEN+1, GFP_KERNEL);
	if (!sic->digest) {
		GLOW(-ENOMEM, __func__, "kmalloc~digest");
		return -ENOMEM;
	}

	memset(sic->digest, 0, XCFG_TINFOIL_DGLEN+1);

	sic->hsd = __gs_init_sdesc(sic->halg);
	if (!sic->hsd) {
		GLOW(-EINVAL, __func__, "__gs_init_sdesc");
		return -EINVAL;
	}

	if (sic->buf == NULL || sic->file_size <= 0) {
		GLOW(-EINVAL, __func__, "~invalid buffer or file_size");
		return -EINVAL;
	}

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
 * @item_ct: * to item count, updated by function
 * @XCFG_TINFOIL_NEW_LINE: new line character in config file
 * @XCFG_TINFOIL_HSLEN: hash length in hex (sha512sum CLI)
 */
static int slowboot_init_process(struct slowboot_init_container *sic,
				 struct slowboot_validation_item **item_ref,
				 int *item_ct,
				 const char XCFG_TINFOIL_NEW_LINE,
				 int XCFG_TINFOIL_HSLEN)
{

	if (sic->file_size <= 0) {
		GLOW(-EINVAL, __func__, "~invalid file size");
		return -EINVAL;
	}

	for (sic->pos = 0; sic->pos < sic->file_size; sic->pos++) {
		if (sic->buf[sic->pos] == XCFG_TINFOIL_NEW_LINE)
			sic->num_items++;
	}

	if (sic->num_items == 0) {
		GLOW(-EINVAL, __func__, "~no items");
		return -EINVAL;
	}

	sic->c_item = sic->items = (struct slowboot_validation_item *)
				vmalloc(sizeof(struct slowboot_validation_item)
					*sic->num_items);

	if (!sic->c_item) {
		GLOW(-ENOMEM, __func__, "vmalloc~c_item");
		return -ENOMEM;
	}

	sic->pos = 0; // reusing
	sic->remaining = sic->file_size;
	while (sic->remaining) {
		sic->pos += fill_in_item(sic->c_item, &sic->buf[sic->pos],
					 &sic->remaining,
					 XCFG_TINFOIL_NEW_LINE,
					 XCFG_TINFOIL_HSLEN);
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
 * @XCFG_TINFOIL_PKALGOPD: padding type
 * @XCFG_TINFOIL_PKALGO: public key algorithm
 * @XCFG_TINFOIL_IDTYPE: ID TYPE
 * @XCFG_TINFOIL_DGLEN: digest length
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_PKLEN: public key length
 * @XCFG_TINFOIL_NEW_LINE: new line character
 * @XCFG_TINFOIL_HSLEN: hash length
 */
static int slowboot_init(struct slowboot_tinfoil *tinfoil,
			 const char *XCFG_TINFOIL_PKALGOPD,
			 const char *XCFG_TINFOIL_PKALGO,
			 const char *XCFG_TINFOIL_IDTYPE,
			 int XCFG_TINFOIL_DGLEN,
			 const char *XCFG_TINFOIL_HSALGO,
			 int XCFG_TINFOIL_PKLEN,
			 const char XCFG_TINFOIL_NEW_LINE,
			 int XCFG_TINFOIL_HSLEN)
{
	struct slowboot_init_container sic;
	struct pbit pc;

	pbit_n(&pc, -EINVAL);

	slowboot_init_setup(&sic,
			    XCFG_TINFOIL_PKALGO,
			    XCFG_TINFOIL_IDTYPE,
			    XCFG_TINFOIL_DGLEN,
			    XCFG_TINFOIL_HSALGO,
			    XCFG_TINFOIL_PKLEN);

	if (slowboot_init_setup_keys(&sic, tinfoil->config_pkey))
		goto fail;

	if (slowboot_init_open_files(&sic, tinfoil->config_file,
				     tinfoil->config_file_signature))
		goto fail;

	if (slowboot_init_digest(&sic,
				 XCFG_TINFOIL_DGLEN,
				 XCFG_TINFOIL_HSALGO))
		goto fail;

	if (local_public_key_verify_signature(&sic.rsa_pub_key,
					      &sic.sig,
					      XCFG_TINFOIL_PKALGOPD))
		goto fail;

	if (slowboot_init_process(&sic, &tinfoil->validation_items,
				  &tinfoil->slwbt_ct,
				  XCFG_TINFOIL_NEW_LINE,
				  XCFG_TINFOIL_HSLEN))
		goto fail;

	pbit_y(&pc, 0);
	goto out;

fail:
	pbit_n(&pc, -EINVAL);
	GLOW(pbit_get(&pc), __func__, "~^^^^^^///////////>");
	tinfoil->slwbt_ct = 0;
	if (!sic.items)
		vfree(sic.items);

	tinfoil->validation_items = NULL;
out:
	slowboot_init_free(&sic);
	return pbit_ret(&pc);
}

/*
 * Run validation test
 * @tinfoil: slowboot tinfoil struct
 * @XCFG_TINFOIL_PKALGOPD: padding type
 * @XCFG_TINFOIL_PKALGO: public key algorithm
 * @XCFG_TINFOIL_IDTYPE: ID TYPE
 * @XCFG_TINFOIL_DGLEN: digest length
 * @XCFG_TINFOIL_HSALGO: hash algorithm
 * @XCFG_TINFOIL_PKLEN: public key length
 * @XCFG_TINFOIL_NEW_LINE: new line character
 * @XCFG_TINFOIL_HSLEN: hash length
 * @gs_irq_killer: spinlock to block IRQ with
 */
static void slowboot_run_test(struct slowboot_tinfoil *tinfoil,
			      const char *XCFG_TINFOIL_PKALGOPD,
			      const char *XCFG_TINFOIL_PKALGO,
			      const char *XCFG_TINFOIL_IDTYPE,
			      int XCFG_TINFOIL_DGLEN,
			      const char *XCFG_TINFOIL_HSALGO,
			      int XCFG_TINFOIL_PKLEN,
			      const char XCFG_TINFOIL_NEW_LINE,
			      int XCFG_TINFOIL_HSLEN,
			      spinlock_t *gs_irq_killer)
{
	int j;
	unsigned long flags;
	struct pbit hard_fail;

	WARN_ON(!tinfoil);
	if (!tinfoil)
		return;

	pbit_y(&hard_fail, 0);
	pbit_n(&tinfoil->error, -EINVAL);

	spin_lock_irqsave(gs_irq_killer, flags); // Occupy all threads?
	if (tinfoil->initialized != 0) {
		tinfoil->initialized = 0;
		tinfoil->validation_items = NULL;
		if (slowboot_init(tinfoil,
				  XCFG_TINFOIL_PKALGOPD,
				  XCFG_TINFOIL_PKALGO,
				  XCFG_TINFOIL_IDTYPE,
				  XCFG_TINFOIL_DGLEN,
				  XCFG_TINFOIL_HSALGO,
				  XCFG_TINFOIL_PKLEN,
				  XCFG_TINFOIL_NEW_LINE,
				  XCFG_TINFOIL_HSLEN) != 0) {
			pbit_n(&hard_fail, 0);
			goto out;
		}
	}

	for (j = 0; j < tinfoil->slwbt_ct; j++) {
		tinfoil->failures += tinfoil_unwrap(tinfoil,
					&(tinfoil->validation_items[j]),
					XCFG_TINFOIL_HSALGO,
					XCFG_TINFOIL_DGLEN);
	}
out:
		if (tinfoil->validation_items != NULL) {
			vfree(tinfoil->validation_items);
			tinfoil->validation_items = NULL;
			tinfoil->initialized = 1;
		}

	if (tinfoil->failures != 0 || tinfoil->slwbt_ct == 0 ||
	    !pbit_ok(&hard_fail))
		pbit_n(&tinfoil->error, -EINVAL);
	else
		pbit_y(&tinfoil->error, 0);
	spin_unlock_irqrestore(gs_irq_killer, flags);
}

/*
 * Initialize data for verification process
 * @tinfoil: slowboot tinfoil struct
 * @XCFG_TINFOIL_CF: path to config file
 * @XCFG_TINFOIL_CFS: path to signature config file
 * @XCFG_TINFOIL_PK: hex encoded public key
 */
static int slowboot_tinfoil_init(struct slowboot_tinfoil *tinfoil,
				 const char *XCFG_TINFOIL_CF,
				 const char *XCFG_TINFOIL_CFS,
				 const char *XCFG_TINFOIL_PK,
				 int XCFG_TINFOIL_PKLEN)
{
	if (tinfoil == NULL)
		return -EINVAL;

	memset(tinfoil, 0, sizeof(struct slowboot_tinfoil));
	strncpy(tinfoil->config_file, XCFG_TINFOIL_CF, PATH_MAX);
	strncpy(tinfoil->config_file_signature, XCFG_TINFOIL_CFS, PATH_MAX);
	strncpy(tinfoil->config_pkey, XCFG_TINFOIL_PK, XCFG_TINFOIL_PKLEN);
	tinfoil->initialized = 1;
	tinfoil->failures = 0;
	pbit_y(&tinfoil->error, 0);
	tinfoil->st = kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil->st) {
		pbit_n(&tinfoil->error, -ENOMEM);
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
	if (fp == NULL)
		goto out;

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
 * @ignore_size: don't fail if the size of the file doesn't match
 */
char *__gs_read_file_to_memory(struct file *fp,
			       size_t file_size,
			       loff_t *pos,
			       int ignore_size)
{
	size_t num_read;
	char *buf;

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
		buf = NULL;
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
	size_t size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	memset(sdesc, 0, size);
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
	size_t s;
	memset(sv, 0, sizeof(struct sig_verify));
	if (pkalgopd != NULL)
		s = strlen(pkalgopd);
	else
		s = 0;

	if (s > 0 && s <= CRYPTO_MAX_ALG_NAME) {
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
 * @gs_irq_killer: Nullable spinlock_t to block IRQ during test
 * @config_tinfoil_new_line: char for new line '\n'
 * @config_tinfoil_override: magic cmdline value to bypass test
 * @config_tinfoil_version: logic version to use likely 1
 * @config_tinfoil_reserved: future use
 * @config_tinfoil_unused: future use
 * @config_bug_on_fail: BUG(); if errors occur
 */
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
		 int config_tinfoil_version,
		 const void *config_tinfoil_reserved,
		 const void *config_tinfoil_unused)
{
	struct slowboot_tinfoil *tinfoil;
	struct pbit pc;

	pbit_n(&pc, -EINVAL);
	pr_info("GS TFSB START\n");

	tinfoil = kmalloc(sizeof(struct slowboot_tinfoil), GFP_KERNEL);
	if (!tinfoil) {
		pbit_n(&pc, -ENOMEM);
		goto out;
	}


	if (slowboot_tinfoil_init(tinfoil,
				 config_tinfoil_cf,
				 config_tinfoil_cfs,
				 config_tinfoil_pk,
				 config_tinfoil_pklen)) {
		pbit_n(&pc, -EINVAL);
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

		pr_info("GS TFSB Audit: {Total:%d/Failures:%d}\n",
			tinfoil->slwbt_ct, tinfoil->failures);

		if (!pbit_ok(&tinfoil->error) || pbit_get(&tinfoil->error) != 0) {
			pbit_n(&pc, pbit_get(&tinfoil->error));
			if (pbit_get(&tinfoil->error) == 0)
				pbit_n(&pc, -EINVAL);
		} else
			pbit_y(&pc, 0);

	} else {
		pbit_n(&pc, -EINVAL);
	}


	if (pbit_get(&pc) != 0 || !pbit_ok(&pc)) {
		__gs_tinfoil_fail_alert(&tinfoil);
		if (tinfoil != NULL) {
			kfree(tinfoil);
			tinfoil = NULL;
		}
		return pbit_ret(&pc);
	} else
		return pbit_ret(&pc);

}
EXPORT_SYMBOL(__gs_tfsb_go);