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
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ST
//#define LD_MASTER_CT 1
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#define SHA512_HASH_LEN 130
#define GLOW printk(KERN_ERR "GLOWING\n");

static int ld_master_on = 1;

typedef struct ld_master_item {
	char filename[PATH_MAX];
	char hash[SHA512_HASH_LEN];
} ld_master_item;

typedef struct ld_master {
	ld_master_item *items;
} ld_master;

static ld_master tinfoil;
static ld_master_item tinfoil_hat[]={
//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$DT
		//{.filename="/home/corycraig/hatcheck", .hash = "82ee6142a2eee5aac1a190a357cec80c1a549c406ba06edb45726ae92f848625a5f5a72c00347e2f9787173ed7d6c1327a2e42011f6d8510258781cccff4614e"}
};

char *ld_master_memmem(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
	while (s1_len >= s2_len) {
		s1_len--;
		if (!memcmp(s1, s2, s2_len))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

static void ld_master_init(void)
{
	tinfoil.items = tinfoil_hat;
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
/**
 * snarf_it
 * @fd:			File Descriptor passed along to the exec
 * @fn: 		File Name passed along to the exec
 * @fl: 		Open flags maded in the exec
 * @item: 		Found item to hash check against based upon file name
 *
 * This will sha512 validate an executable before it is allowed to run (Enforcing) or trigger an alert (Permissive)
 */
static int ld_master_verify(const struct file *fp, const struct filename *fn, ld_master_item *item)
{
	u8 *buf;
	loff_t file_size;
	int number_read;
	u8 b_hash[65];
	loff_t pos;
	struct crypto_shash *alg;
	struct cred *c_cred;
	sdesc *desc;
	unsigned char *digest;
	int j;
	int return_code;


	// Initialize all variables for maximum verbosity usefull in security critical pieces
	buf = NULL;
	desc = NULL;
	alg = NULL;
	digest = NULL;
	file_size = 0;
	number_read = 0;
	pos = 0;
	j = 0;
	return_code = 0;


	// Determine file size
	printk(KERN_INFO "LD master Current Position:%lld\n", fp->f_pos);
	default_llseek(fp, 0, SEEK_END);
	file_size = fp->f_pos;
	printk(KERN_INFO "LD master File Size:%lld\n", file_size);
	default_llseek(fp, fp->f_pos * -1, SEEK_CUR);
	printk(KERN_INFO "LD master Reset Position:%lld\n", fp->f_pos);

	// Allocate buffer for file, DOS for super sized file???
	buf = vmalloc(file_size+1);
	if (!buf) {
		printk(KERN_ERR "LD master Cannot Allocate Memory:%s\n", fn->name);
		goto fail;
	}

	// Allocate space for digest
	digest = kmalloc(65, GFP_KERNEL);
	if (!digest) {
		printk(KERN_ERR "LD master Cannot Allocate Memory2:%s\n", fn->name);
		goto fail;
	}

	// Zero the buffers
	memset(buf,0,file_size+1);
	memset(b_hash,0,65);
	memset(digest,0,65);

	// Read the file
	number_read = kernel_read(fp, buf, file_size, &pos);
	if (number_read != file_size) {
		printk(KERN_ERR "LD master File Size Mismatch:%s,%lld,%lld\n", fn->name, number_read, pos);
		goto fail;
	}

	// Put stored hex hash into binary format for comparison
	printk(KERN_INFO "LD master Hex2Bin:%s\n", fn->name);
	if (hex2bin(b_hash, item->hash, 64) != 0) {
		printk(KERN_ERR "LD master Stored Hex2Bin Fail:%s\n", fn->name);
		goto fail;
	}

	// Allocate crypto algorithm sha512 for hashing
	printk(KERN_INFO "LD master Alloc Crypto Alg %s\n", fn->name);
	alg = crypto_alloc_shash("sha512", 0, 0);
	if (IS_ERR(alg)) {
		printk(KERN_ERR "LD master cannot allocate alg sha512\n");
		goto fail;
	}

	// Init sdesc memory with reference to sha512 algorithm
	printk(KERN_INFO "LD master Init sDesc %s\n", fn->name);
	desc = init_sdesc(alg);
	if (desc == NULL) {
		printk(KERN_ERR "LD master cannot allocate sdesc\n");
		goto fail;
	}

	// Hash the file
	printk(KERN_INFO "LD master Check: %s,%lld,\n", fn->name, file_size);
	crypto_shash_digest(&(desc->shash), buf, file_size, digest);

	// Check the Hash
	for(j=0;j<64;j++) {
		if(b_hash[j]!=digest[j])
			goto fail;
	}

	// Success
	goto out;

fail:
	return_code = 1;
	//filp_close(fp, NULL);
out:
	if (buf != NULL)
		vfree(buf);
	if (desc != NULL)
		kfree(desc);
	if (!IS_ERR(alg) && alg != NULL)
		crypto_free_shash(alg);
	if (digest != NULL)
		kfree(digest);
	return return_code;
}

/*
 *
 *    Get Full File Path
 	char *tmp = (char*)__get_free_page(GFP_TEMPORARY);

    file *file = fget(dfd);
    if (!file) {
        goto out
    }

    char *path = d_path(&file->f_path, tmp, PAGE_SIZE);
    if (IS_ERR(path)) {
        printk("error: %d\n", (int)path);
        goto out;
    }

    printk("path: %s\n", path);
out:
    free_page((unsigned long)tmp);
 */


static int ld_master_check(struct file *fp, struct filename *fn)
{
	int j;
	int is_ok;
	int is_ld_master;
	int return_value;
	char *tmp, *full_path;

	if (ld_master_on != 0) {
		ld_master_init();
		ld_master_on = 0;
	}

	is_ok = 1;
	is_ld_master = 0;
	tmp = (char*)kmalloc(PAGE_SIZE,GFP_KERNEL);
	if (!tmp) {
		return_value = 1;
		goto out;
	}

	full_path = d_path(&fp->f_path, tmp, PAGE_SIZE); // free this???
	if (IS_ERR(full_path)) {
		return_value = 1;
		goto out_with_free;
	}

	return_value = 0;

	// FORCE VALIDATION OF .so files enforced
	if((ld_master_memmem(fn->name, strlen(fn->name)+1, ".so\0", 4) ||
	    ld_master_memmem(fn->name, strlen(fn->name)+1, ".so.", 4)) &&
	    !ld_master_memmem(fn->name, strlen(fn->name)+1, ".cache",6)) // Exclude .so.cache
		is_ld_master = 1;

	for (j=0;j<LD_MASTER_CT;j++) {
		if (strcmp(full_path,tinfoil.items[j].filename) == 0) {
			if (is_ld_master == 0) {
				is_ld_master = 1;
				printk(KERN_INFO "LD master Check File:%s\n", full_path);
			}
			if(ld_master_verify(fp, fn, &tinfoil.items[j]) == 0) {
				is_ok = 0;
				break;
			}
		}
	}
	if (is_ok == 1 && is_ld_master == 1) {
		printk(KERN_ERR "LD master Fail:%s\n", full_path);
		//return_value = 1;
	} else if (is_ld_master == 1) {
		printk(KERN_INFO "LD master Success:%s\n", full_path);
	}

	out_with_free:
	kfree(tmp);
	out:
	return return_value; // Permissive mode for now
}

/*
 * do_sys_openat2:: before the two lines after sucessful open
 	 if(ld_master_check(f,tmp) != 0) {
				filp_close(f, NULL);
				put_unused_fd(fd);
				fd = PTR_ERR(f);
				goto out;
			}



static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		//printk(KERN_INFO "LD_master Checking: %s\n", filename);


		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			if(ld_master_check(f,tmp) != 0) {
				filp_close(f, NULL);
				put_unused_fd(fd);
				fd = PTR_ERR(f);
				goto out;
			}
			fsnotify_open(f);
			//printk(KERN_INFO "LD_master Checking: %s\n", tmp->name);
			fd_install(fd, f);
		}
	}
	out:
	putname(tmp);
	return fd;
}
 */
// exit
