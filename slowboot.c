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


#define SLWBT_MODE_REG 1
#define SLWBT_MODE_TPM 2
#define SLWBT_MODE_TPM2 3

#define SHA512_HASH_LEN 130

#define GLOW BUG();

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

//##########TEMPLATE_INIT_SP##################################################=>
typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[1];
	int failures;	
} slowboot_tinfoil;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static u32 mode;
static slowboot_tinfoil tinfoil;
//static struct kstat *st;



/*******************************************************************************
* Register data in array                                                       *
*******************************************************************************/
static void svi_reg(slowboot_validation_item *item,
		const char *hash,
		const char *path)
{
	strncpy(item->hash, hash, SHA512_HASH_LEN);
	strncpy(item->path, path, PATH_MAX);
	
	switch (mode) {
	case SLWBT_MODE_TPM:
		break;
	case SLWBT_MODE_TPM2:
		break;
	default:
		break;		
	}
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
	item->buf = kmalloc(tinfoil.st->size+1, GFP_KERNEL);
	item->buf_len = tinfoil.st->size;
	if (!item->buf) {
		printk(KERN_ERR "Failure No memory:%s\n",
			item->path);
		return -1;
	}
	memset(item->buf,0,tinfoil.st->size+1);
	return 0;
}

static void tinfoil_close(slowboot_validation_item *item)
{
	kfree(item->buf);
	filp_close(item->fp, NULL);
}

static int tinfoil_read(slowboot_validation_item *item)
{
	size_t number_read;
	number_read = 0;
	number_read = kernel_read(
		item->fp,
		item->buf,
		tinfoil.st->size,
		&(item->pos));
	if (number_read != tinfoil.st->size) {
		kfree(item->buf);
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
		return ERR_PTR(-ENOMEM);
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
	
	crypto_shash_digest(&(sd->shash), item->buf, item->buf_len, digest);
	for(j=0;j<64;j++){
		if(item->b_hash[j]!=digest[j]) {
			item->is_ok = 1;
		}
	}
}

/*******************************************************************************
* Open file, read contents, hash it, compare, log state, free                  *
*******************************************************************************/
static int tinfoil_unwrap (slowboot_validation_item *item)
{
	if (tinfoil_open(item) != 0)
		return -1;
		
	if (tinfoil_stat_alloc(item) != 0)
		return -1;
	
	if (tinfoil_read(item) != 0)
		return -1;
	
	tinfoil_check(item);
	printk(KERN_INFO "File:%s:%s\n", 
	       item->path, 
	       (item->is_ok == 0 ? "PASS" : "FAIL"));	
	tinfoil_close(item);
	return item->is_ok;
}

/*******************************************************************************
* This section contains dynamically generated functions numbered 1-infinity    *
* It will simply register the hash/path for each file to be validated at the   *
* correct location in the array                                                *
*******************************************************************************/
//##########TEMPLATE_INIT_FN##################################################=>
static void svir_1(void) 
{
	svi_reg(&(tinfoil.validation_items[0]),
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        "/usr/sbin/init"
	);
}
static void svir_2(void) 
{
	svi_reg(&(tinfoil.validation_items[1]),
	        "8b44b6b41b2e57801c2ee6dc103542a58a8763f5938773cbdd16ae9d877b17c24d70f659f7a28eff8b65eec24e9c7295fa35dd1ced81e36ab659cc7989d032cc",
	        "/usr/lib/systemd/libsystemd-shared-249.so"
	);
}
static void svir_3(void) 
{
	svi_reg(&(tinfoil.validation_items[2]),
	        "94afe835d287d18588374a28d34b7b7adf7c21eda3c6c2b55668571d7008e8b6ece1fe86554f0e179516d5ea9fcc103e878a52d5fb3d93901384cf9841823e29",
	        "/lib64/libseccomp.so.2"
	);
}
static void svir_4(void) 
{
	svi_reg(&(tinfoil.validation_items[3]),
	        "db703ccb059f65706fa1e945ed82f04c3882e8121b1a52c438cd9892bd54b8a7580f278b60ba777ec72d88945b679839d414a0e487878c1f161fe1fa0e8e0a5b",
	        "/lib64/libselinux.so.1"
	);
}
static void svir_5(void) 
{
	svi_reg(&(tinfoil.validation_items[4]),
	        "227a70f0a149d71281d1a23b05ef73dc578a65e77398b28e44b4bbb6606cb290a310bc0612017c4a0466a0edd997d4f7a49f5db4d71ced5fde7eb6204fcd345e",
	        "/lib64/libmount.so.1"
	);
}
static void svir_6(void) 
{
	svi_reg(&(tinfoil.validation_items[5]),
	        "0e2928eb1bd2376b9239333deffe4d0b1e7fb6b31fdaeef908eed9d01a6784487ced335d8bc694f630fdee6aa02c8c1f1db387d1545ac16dc35c72e06719846e",
	        "/lib64/libpam.so.0"
	);
}
static void svir_7(void) 
{
	svi_reg(&(tinfoil.validation_items[6]),
	        "ce3e7af9680ca4462f5b4ed4b2e820e30370bc0008a50673ac558208883ee13dad636c3c083a8895486da4e12699255bfcb1ec3e12b2be4c9e91c42d8751be4c",
	        "/lib64/libaudit.so.1"
	);
}
static void svir_8(void) 
{
	svi_reg(&(tinfoil.validation_items[7]),
	        "8c8759d2ef2fc039653d9657e3117efa76a9051d1069d14c410c41ac75e7bf65cb18a731acb2e06b27777e02422ecadd394e603a11aea92beffc8bff30b12b9a",
	        "/lib64/libkmod.so.2"
	);
}
static void svir_9(void) 
{
	svi_reg(&(tinfoil.validation_items[8]),
	        "9b71e8d9f91bcab7d805a530aaca58636c5609edf64e4cef17f2c15db60a07650706c7344c611fcc17d663fd7a0ee6f2ced5abb8964df243c9a72c479f68a4cf",
	        "/lib64/libgcc_s.so.1"
	);
}
static void svir_10(void) 
{
	svi_reg(&(tinfoil.validation_items[9]),
	        "5b4effdba4bfd29bd6cb22ec2dc89e533448b83b565edede005acce93d49e51467eb2a7e21fa840c061f76bbe9a4c45b87317d94e0236c889209c48a4eb1999f",
	        "/lib64/libc.so.6"
	);
}
static void svir_11(void) 
{
	svi_reg(&(tinfoil.validation_items[10]),
	        "270d7f8629d6efa9f285590f3fa7f2f4c22c781a3452bd874170b0c5e6c5c9fee95cb915efdc6ea561f28681eab77350dce91460e499b69a860b2369bf9348bc",
	        "/lib64/libacl.so.1"
	);
}
static void svir_12(void) 
{
	svi_reg(&(tinfoil.validation_items[11]),
	        "204ac666854364c803adbd083e51eef1e59500770bf07c6d2be38b9a1ca2ab0644dca1a3ad67b23e3fa8a0d7c8f4942a42b3cbe54ca46ee6ef8c40c53f049956",
	        "/lib64/libblkid.so.1"
	);
}
static void svir_13(void) 
{
	svi_reg(&(tinfoil.validation_items[12]),
	        "5e253856c0b19a2b8629965fb8845b80fdc6c8ff78ed3b95ed12d7819dd43166b8f5de0266d342ae886628924c71919bf5a134cb9d50eeae9cf32c33fa26c508",
	        "/lib64/libcap.so.2"
	);
}
static void svir_14(void) 
{
	svi_reg(&(tinfoil.validation_items[13]),
	        "dbbe916f63a49ea6983f3e02bb28963330885eb49756411e5ee7dc1dafd9f846a71cdc9f07a0e206b553f06acb25d76e817849d0eeb0c13de8baaa4f67226f4b",
	        "/lib64/libcrypt.so.2"
	);
}
static void svir_15(void) 
{
	svi_reg(&(tinfoil.validation_items[14]),
	        "d460bcc4990a3f4ff430f61f945696adc18f5bccf892477a3b25ec587f1e9b396c3b43a7d7f09f3dc08398ec7b2454af7ac8de78c0715420a4b92abb6529f60e",
	        "/lib64/libgcrypt.so.20"
	);
}
static void svir_16(void) 
{
	svi_reg(&(tinfoil.validation_items[15]),
	        "a89cd174c3d537ab8adf96a86aadc768906bd94770cdec136aa63f2fd755b691c55c9dfa0d9908f9491963dd34483a459e9d3ad3bcd89dfc4ca2737af93cf51f",
	        "/lib64/libip4tc.so.2"
	);
}
static void svir_17(void) 
{
	svi_reg(&(tinfoil.validation_items[16]),
	        "1a08045bd5a6312d4400cde34fff9aea64b151fc7113db8d7bd60319522ece9f544f48fe6c62ca8962c076d24a65687c147c9d2452d5a132ae805635b126682c",
	        "/lib64/liblz4.so.1"
	);
}
static void svir_18(void) 
{
	svi_reg(&(tinfoil.validation_items[17]),
	        "3e7b11446bc7ff2db8d3179ba976d4e6d98e13ca3f4a60d8bcd1b9dff8d69f6dac2ee85838a20dbb78a6e09d5407cceaa9130b48ed54904140ea1e74edabaa4a",
	        "/lib64/libcrypto.so.1.1"
	);
}
static void svir_19(void) 
{
	svi_reg(&(tinfoil.validation_items[18]),
	        "8e31e0700c2486bc29ab190d3d5ed6962ae2195368f1f918d3ef39839e724bd0a6af7d182d30fc7119ca06a5953191a2dc254490a3713ed4c5718cd8bc14165e",
	        "/lib64/libp11-kit.so.0"
	);
}
static void svir_20(void) 
{
	svi_reg(&(tinfoil.validation_items[19]),
	        "1a855666ab3870a403e379c2b24da4eca16a762b756517ec5fc2a8694866929ef43644a876150e210acb24e2f25d1608e620d4be67824dd8e967354dedfc96d6",
	        "/lib64/libzstd.so.1"
	);
}
static void svir_21(void) 
{
	svi_reg(&(tinfoil.validation_items[20]),
	        "271869d919db1a74fd2995a91af88c753dcfddb73b0b550983d6998fda7d5a1b1f45aa4fb8d3381e27823a8d3c49faf6ecdffd2cc0daee37b58106fc8e3a1d1f",
	        "/lib64/liblzma.so.5"
	);
}
static void svir_22(void) 
{
	svi_reg(&(tinfoil.validation_items[21]),
	        "8e9d327785083b4aa245cb7e57983de404a3b7602d122cda03e8da0be1153bfa5f36daa5617df0631225346d817a5146412ba750feee458fd2880857a84cdbd1",
	        "/lib64/libpcre2-8.so.0"
	);
}
static void svir_23(void) 
{
	svi_reg(&(tinfoil.validation_items[22]),
	        "f91a9d5e8cfd48a8a03d8d0b5e48c8693bcc63783028d2eb0f88578412c2bfc0fa5169cb3c9b153f3bff53f1236248fd57e58cc34e2ffb1b6e95e4d05fddb54a",
	        "/lib64/libeconf.so.0"
	);
}
static void svir_24(void) 
{
	svi_reg(&(tinfoil.validation_items[23]),
	        "5324a28c9361f0cb04517a1bc9ce4832a51509e74132b6521a38bf6f5012fa03dfbd29ed376031289299e154bcee3762edb69a47b99b1e7844eb9cd29002f943",
	        "/lib64/libm.so.6"
	);
}
static void svir_25(void) 
{
	svi_reg(&(tinfoil.validation_items[24]),
	        "56da592866a38b1f901ed4b60076cb2a12ede05a4eef20a6cfeb2a32263a65645fb9a2e37340ca09ba41308596364ea3826d309711c6f06063be98690aa2686b",
	        "/lib64/libcap-ng.so.0"
	);
}
static void svir_26(void) 
{
	svi_reg(&(tinfoil.validation_items[25]),
	        "654598d4f149484e1ce0e3150729a8d4da81ab1cb2f83e2c13d87e352352854aa6830ac98e86dd42e61474f03d97ab4feee6e97f1ed6877f517b2a1934a37322",
	        "/lib64/libz.so.1"
	);
}
static void svir_27(void) 
{
	svi_reg(&(tinfoil.validation_items[26]),
	        "f69a1989768d0104474bb7ca825b2b9a7fe14275309263b49b820498ef7b45f8735f809332ccdd7f298cb0bbdc3ec32fd78e7248ebbbd535402f39e1acfc93c8",
	        "/lib64/libattr.so.1"
	);
}
static void svir_28(void) 
{
	svi_reg(&(tinfoil.validation_items[27]),
	        "a9c0fbf6dc3b3c3ca2be034d99652240824dae7a5155232ea805cc20504406feadb3daa733b28ed1e250f3b2ad6bbc0bd7728c372a41e1ba615525a3e1578eee",
	        "/lib64/libgpg-error.so.0"
	);
}
static void svir_29(void) 
{
	svi_reg(&(tinfoil.validation_items[28]),
	        "2553045a006713ec27966f9b414b46781246da63b83901f5780a4d103f81699aea94e2f5ead300ef6dfe31745c1167c6370b4ead866967f57e8b084b4fc40f2f",
	        "/lib64/libpcap.so.1"
	);
}
static void svir_30(void) 
{
	svi_reg(&(tinfoil.validation_items[29]),
	        "75817ba2d0306e10ff63fec8e676b14088de65fe5b5e8a48ea883e3478768e1ae119b3f964a2ae56afb6fc8946d5ddac76036b432d39499296e92a44bbbe93a0",
	        "/lib64/libffi.so.6"
	);
}
static void svir_31(void) 
{
	svi_reg(&(tinfoil.validation_items[30]),
	        "2595edec4ec363be3406a5028bb5ee5485074ce1e1d3b1f1c731ae6ffbd768663981d88c5875bd50a632214c4c69b65f5c0034d8913fb7d6521265c624fc7a79",
	        "/lib64/libibverbs.so.1"
	);
}
static void svir_32(void) 
{
	svi_reg(&(tinfoil.validation_items[31]),
	        "232505f482d1a65c81cac3f4997627e75f59e4e0ea673fcdeae68edfb32c77d90ce26ebc4742e683b3e8afdec28dde0b2158925378ccc263370d44cc6690a5ce",
	        "/lib64/libnl-route-3.so.200"
	);
}
static void svir_33(void) 
{
	svi_reg(&(tinfoil.validation_items[32]),
	        "62e5b936290ee2119e399093f449ad8ab5d8adf09952717e8eae93a4f77b1d22cbd8630b830c94cdad0d9d005b5acd8d0eb1e8ddf08e00f50131af7c6d255b95",
	        "/lib64/libnl-3.so.200"
	);
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/*******************************************************************************
* Register all the svirs and then validated them all counting the failures     *
*******************************************************************************/
static void slowboot_run_test(void)
{
	int j;


//##########TEMPLATE_INIT_SP##################################################=>	
	int validation_count = 33;
	svir_1();
	svir_2();
	svir_3();
	svir_4();
	svir_5();
	svir_6();
	svir_7();
	svir_8();
	svir_9();
	svir_10();
	svir_11();
	svir_12();
	svir_13();
	svir_14();
	svir_15();
	svir_16();
	svir_17();
	svir_18();
	svir_19();
	svir_20();
	svir_21();
	svir_22();
	svir_23();
	svir_24();
	svir_25();
	svir_26();
	svir_27();
	svir_28();
	svir_29();
	svir_30();
	svir_31();
	svir_32();
	svir_33();

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	for (j = 0; j < validation_count; j++) {
		tinfoil.failures += tinfoil_unwrap(
			&(tinfoil.validation_items[j]));
	}
	if (tinfoil.failures > 0) {
		GLOW
	}
}

// init
static int __init slowboot_mod_init(void)
{
	if (mode == 0)
		mode = SLWBT_MODE_REG;
		
	printk(KERN_INFO "Beginning SlowBoot with mode=%u\n", mode);
	
	tinfoil.failures = 0;
	tinfoil.st = NULL;
	tinfoil.st = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);
	if (!tinfoil.st)
		return -ENOMEM; // CHECK
	
	switch (mode) {
	case SLWBT_MODE_REG:
		slowboot_run_test();
		break;
	default:
		break;
	}
	kfree(tinfoil.st);
	return 0;
}

// exit
static void __exit slowboot_mod_exit(void) { }

module_init(slowboot_mod_init);
module_exit(slowboot_mod_exit);

module_param(mode, uint, 1);
MODULE_PARM_DESC(mode, "Validation Method");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");
MODULE_VERSION("0.1");

