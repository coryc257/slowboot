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
#define NUM_HATS 3544

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
static void snarf_hat_1(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc.d/10-qt5-check-opengl2.sh",
	        "b3b1436c50530187335ccf0befb79eaec11077925a8a6ff220f82e12df1b9332d9185775fd6bc44a30e43ee3841e0f4832df7320e477453717605dff8496bb8b",
	        0
	);
}
static void snarf_hat_2(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc.d/98vboxadd-xclient.sh",
	        "e0656706bc62ab636e7bd82d5a2e28196c74e569bc16edd2c621094ce4569574d3728b73d85b7df76443506808091acef4ceeb440bab20e322582faa3b60af30",
	        1
	);
}
static void snarf_hat_3(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc.d/localuser.sh",
	        "5121c400e3117bc290aaf8798d570b16a6aeebc657a69dbd0433f4440baa62f0f2452da0deed04562ff5826d38b7ed1841aa2c4e65195c541141c15a1012456f",
	        2
	);
}
static void snarf_hat_4(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc.d/50-systemd-user.sh",
	        "1184927ab1da6634fab24fbe17903930ca357e89d8955f66b83073a6146139ed5c2fac27b4631daeb9b0f1c102837d06d8d96820a7741e75fe5c656f3b9250f4",
	        3
	);
}
static void snarf_hat_5(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc.d/00-start-message-bus.sh",
	        "8d01ea075a2c1e7df9e35df4d46f402eaab497d4f23b4ba8ab3a8222933ed7b4d4b596c2e9dd4ad08fdfab61d7396c76d1f4c80845c1ac8941478a3dedd81ad8",
	        4
	);
}
static void snarf_hat_6(void) 
{
	snarf_construct_hat("/etc/X11/xinit/Xclients",
	        "378934efcfda31725c08c23b3d3292b4d65ddff0b837e12155ee5139a774df18c0ad7ff20424415faa2f4452ebfeda7a339f6356c1116f40900d215992ba7516",
	        5
	);
}
static void snarf_hat_7(void) 
{
	snarf_construct_hat("/etc/X11/xinit/Xsession",
	        "2b53399791c5a7022347d37057a2a71cf1a172e04e6f4c286325fe85d933ae48914a6e5d4885aa81846ae0606a02a8c6c2e7bdfb2a980407314f77ad3c67acbb",
	        6
	);
}
static void snarf_hat_8(void) 
{
	snarf_construct_hat("/etc/X11/xinit/xinitrc",
	        "bf2766232eca0e13c5bd54906651b759194bd5172f2a4b01787615ffda34a51cd07f257257216d031d6a932ec9b07beb16641cf0d8fc2873ec07f2655bada7fc",
	        7
	);
}
static void snarf_hat_9(void) 
{
	snarf_construct_hat("/etc/bash_completion.d/gluster",
	        "06b0aa8cd3c73e155d0e35c6bec8eabea59b668c048f415d0a9cfd03bf5e0b56a448cc79528330c05bc9c4b86eaea92f2091acc6875f5340de7effeee5e83826",
	        8
	);
}
static void snarf_hat_10(void) 
{
	snarf_construct_hat("/etc/brltty/Contraction/latex-access.ctb",
	        "eddeb6ec837bef7c958cb933b10eea1061422329dc24436e8bf6d3974be1a3aa581de5d579a3d33510fe8eae613d7e62ab2b7d38fac28be132a4f9c020f10f06",
	        9
	);
}
static void snarf_hat_11(void) 
{
	snarf_construct_hat("/etc/dhcp/dhclient.d/chrony.sh",
	        "ac48fd441f004e5c22067a8ddc56142d81d25c5d5038b3af42ad4f46996668c0be56d2e202f6fb60fde3af4bf068178a8634b81531c28ffe2f95254976b95cf1",
	        10
	);
}
static void snarf_hat_12(void) 
{
	snarf_construct_hat("/etc/gdm/Init/Default",
	        "21d475be2a9ea401bfd799834b01f5dd63bd108347341a2e769425d2359ad012f172967b5f639f6cfa96b440575a56f063047742b2c25d5cf1415374143c9a11",
	        11
	);
}
static void snarf_hat_13(void) 
{
	snarf_construct_hat("/etc/gdm/PostLogin/Default.sample",
	        "bdc2e8b929343b8bcb4d685352221a2ec860cd30b1508ef90b4a0b0a83d64e3f94972729b7ac65b0beedd329dfba84318bef6d0c038d8f36684c8e108e8ec0f9",
	        12
	);
}
static void snarf_hat_14(void) 
{
	snarf_construct_hat("/etc/gdm/PostSession/Default",
	        "6a70a2231b9b7eaff352609747f702f084e220334e4274a9a8b1fb01626ba2f536ce004e427af4cea2c98b7748b6347e3055c7d1345a764956d7a6bf779a36d9",
	        13
	);
}
static void snarf_hat_15(void) 
{
	snarf_construct_hat("/etc/gdm/PreSession/Default",
	        "708b344aed5b3125769d271a83c51e46950eae68ab0dbd3334d9a40bfcf3c8b17841c5db310a8af9b2da4be39bfe197db2e61cb758c94aba6ff96ad77e7dfb6f",
	        14
	);
}
static void snarf_hat_16(void) 
{
	snarf_construct_hat("/etc/grub.d/00_header",
	        "5ae54d3caf9f6f615a5f31c0b1ddfe70036d9e7082b0cdae4d5d41510bb72061d70d1088efc938047efb340f0f62888976661b6a8f6501b49754fa0487cc3501",
	        15
	);
}
static void snarf_hat_17(void) 
{
	snarf_construct_hat("/etc/grub.d/01_users",
	        "f9cf98f1b184039b55fc4f519aef05dccf4c7db3eeceb0de1e82a8d4a18293fd091c78bb9f07d3189f684c770936aff4f5dfc9fc564a943370359021e60a052b",
	        16
	);
}
static void snarf_hat_18(void) 
{
	snarf_construct_hat("/etc/grub.d/08_fallback_counting",
	        "aaff69bb62cf7cf03275b94f635dfb88d12f88ff2ab0bcbb2682020e94ccdaab9abea7d35ca3e72f95e1beb57222810aed258c5dae1783239f9838a0bb5890c5",
	        17
	);
}
static void snarf_hat_19(void) 
{
	snarf_construct_hat("/etc/grub.d/10_linux",
	        "9d94e369f7d682ba7da21f266c991c7839fc44f92f463da944ce6d289f1276b349b45ade165234174c4881ca23f5e5e81250b287d68f166c548c748996026a72",
	        18
	);
}
static void snarf_hat_20(void) 
{
	snarf_construct_hat("/etc/grub.d/10_reset_boot_success",
	        "c91dfd534ac18f3fae2d254e82cf1b340eb9ff93988eb98dbe8db3192256cd74188a04485731ff6432abc8dadabe3a7bbe80025490eb8fcbaa5c6f267b23e33a",
	        19
	);
}
static void snarf_hat_21(void) 
{
	snarf_construct_hat("/etc/grub.d/12_menu_auto_hide",
	        "1b3967430c709faac4de2b7264380bfaded7d8a72a172c916fd85b1c9f577cb6ed5c623fc47f93d840439d8dd68b1e853e4a7a59ad632d60ad32798567d35fc6",
	        20
	);
}
static void snarf_hat_22(void) 
{
	snarf_construct_hat("/etc/grub.d/14_menu_show_once",
	        "a0946eb8cb184289509b71adec073b7ee6197a2382b4f6b5652e9064e9bd35241706eee7cd6cbed401945753ec81fda3be6b926aedb3e7d59c586d0374007645",
	        21
	);
}
static void snarf_hat_23(void) 
{
	snarf_construct_hat("/etc/grub.d/20_linux_xen",
	        "82fa6cfd9ad38639dee0091d9e0036da7a4589fe4f93edf638e38a787d6e7ba36b24c5af5bf251d5173dacfc371e5ede2bd2b3aa7197fecee3a8a5fb3165f0cf",
	        22
	);
}
static void snarf_hat_24(void) 
{
	snarf_construct_hat("/etc/grub.d/20_ppc_terminfo",
	        "d03fe157cc050133b0c84656eaf0a51cea54360284248e9923617beae43e94c02412636d29efc5848341f7e292cee02e41f69886e5f4ca9eb7410704990be7d1",
	        23
	);
}
static void snarf_hat_25(void) 
{
	snarf_construct_hat("/etc/grub.d/30_os-prober",
	        "c3083d3c0f768db97bcd2fb38b82196bde9c99c51ce71d1a35341a79a567a7a321b9bead73bca5c502af5de9b52704f4dc01e2d0879d38bbf129476145659229",
	        24
	);
}
static void snarf_hat_26(void) 
{
	snarf_construct_hat("/etc/grub.d/30_uefi-firmware",
	        "908fcee217989f624e64c1abab0db9db1c99f91d77c83ac8bba29fcd07610af4fc69fbd75c743d46b9edd15e62f4c0d2131ccc5671a95f0d436c5ef946c09a57",
	        25
	);
}
static void snarf_hat_27(void) 
{
	snarf_construct_hat("/etc/grub.d/40_custom",
	        "75b43ebe6d26fe84882d256c922d1e58a610bda49f8567c87e6a9f1d6ae44b1049d61858e1b1231942bcb7c3a66f1576aec17d5405c43cc9a80b0cbb8ff588cf",
	        26
	);
}
static void snarf_hat_28(void) 
{
	snarf_construct_hat("/etc/grub.d/41_custom",
	        "4bcb083fc01a593b4dd108b90e40586013d970e58c4be9c0b598db6ed92e30580e5e9b069c92d53e2dcb39b841b088c996414ca599902c2183a68392ac3cec03",
	        27
	);
}
static void snarf_hat_29(void) 
{
	snarf_construct_hat("/etc/grub.d/35_fwupd",
	        "22933033c9a5d7e1604f8cf75acd219b96837eaff9b63ee19b50e2e3b1a8548bc68740a57ea88d5a7ce916d28b2d521c6001a050b2d637dec07862c2664b7ed7",
	        28
	);
}
static void snarf_hat_30(void) 
{
	snarf_construct_hat("/etc/mcelog/triggers/cache-error-trigger",
	        "18c243ded864ee1b545100233dd0e04739bbbe1185105db310a8a9c137200e08ba2b87603df31d6faa6478161c0695b6c7252a198dbebdd5d64850e6dc9cc882",
	        29
	);
}
static void snarf_hat_31(void) 
{
	snarf_construct_hat("/etc/mcelog/triggers/dimm-error-trigger",
	        "6b96b9d48d2a005ca3f454639d0bdf0e2644873f5661dba0200c376d9af154610beb53a6d0108c3ae83a54ee6f1f8805e5e327e8556407878a5ff95f57ae973b",
	        30
	);
}
static void snarf_hat_32(void) 
{
	snarf_construct_hat("/etc/mcelog/triggers/page-error-trigger",
	        "6736f194508e18221b96170c55348dc8fa116c0cd7039c642382ba57c4742e75984c1166aca1d37797cd36b79bdf89db3ff71cf1b3ecb3fd2a49efd4cd443c6b",
	        31
	);
}
static void snarf_hat_33(void) 
{
	snarf_construct_hat("/etc/mcelog/triggers/socket-memory-error-trigger",
	        "6c8bd1d2a2b2f1b6584a21f99082d916f611564e066692d165996f25caa882b5c865a10cc34400a2e828e1caed22a35eb03a849d4060ef72da4ac54acd4ee17f",
	        32
	);
}
static void snarf_hat_34(void) 
{
	snarf_construct_hat("/etc/ppp/ip-down",
	        "8e915bf40a74a8f63de523fcdab13d8283a96702ae34ccf71058833f2aecc9df0a22aefcd7069cd1e0f76f97ed9a1a06554d6a385404c811990b2a184c810e23",
	        33
	);
}
static void snarf_hat_35(void) 
{
	snarf_construct_hat("/etc/ppp/ip-down.ipv6to4",
	        "2eca9c8ab2e68633b368c6f895d47a51fe705f6320ca20bef2f5cca9fc34d624dcdacec336569cba6a2abaca318f0ad2226d7599cb60ae07d08524e9ee83fad5",
	        34
	);
}
static void snarf_hat_36(void) 
{
	snarf_construct_hat("/etc/ppp/ip-up",
	        "e98f4a0c2243967c1f0d3d7fac1b69492497065d1500c8eb6d96b21f90fe164c343a6b9c5209e4c6900e48c9089f433bd4d4e95b05b4efa280ef4dcab0a0dab5",
	        35
	);
}
static void snarf_hat_37(void) 
{
	snarf_construct_hat("/etc/ppp/ip-up.ipv6to4",
	        "4103a569182594b0f1c4d08d0b6ae2b5038ee8c0287264e8b9695c1170f8f81607cb2c8f5a2fbd2200ea7485851fb61e1018faace2d7b25134d98a36945ec8c7",
	        36
	);
}
static void snarf_hat_38(void) 
{
	snarf_construct_hat("/etc/ppp/ipv6-down",
	        "8a2382d91e564a66085d0dbd1e3b033ec789af9ce43c97bbded23ae80d25af1bcccd4e7d1910d2b476574b8bf4333da7a648fa93437d5c7a7f5ed88c02bdc56a",
	        37
	);
}
static void snarf_hat_39(void) 
{
	snarf_construct_hat("/etc/ppp/ipv6-up",
	        "25d62b8e83364ce9427961009027174c3e79bc0c147bf2511be9dc3b173b5051a915211b44a16a444ca18968fc5784bbec3928753c3da572d95be3d51fb06387",
	        38
	);
}
static void snarf_hat_40(void) 
{
	snarf_construct_hat("/etc/qemu-ga/fsfreeze-hook",
	        "8a71e91ab1bb88dcfc90d1e2f9e0ccee4a2a88be0725f0b4ebea2a32acc57da4911cb01ab9ac1bdb64c23041420d7929a53db400d58891b65d440089c7e554c8",
	        39
	);
}
static void snarf_hat_41(void) 
{
	snarf_construct_hat("/etc/rc.d/init.d/livesys",
	        "be1af32698dce31f99944e790929d3f601b2efdbb149d0ae9e94cbef5148547c1fd88a7dc27999e492e8af7d8553ece3b8b277641574b93376645859140560af",
	        40
	);
}
static void snarf_hat_42(void) 
{
	snarf_construct_hat("/etc/rc.d/init.d/livesys-late",
	        "5424e508cf799ba5355e066a9c4ae80c58181423ac2755bc232b3e4bc0986fb649be6cfb46266fabbee9518e72d3a4c0107013a2c0b5c5a1ce4b3979eb589d79",
	        41
	);
}
static void snarf_hat_43(void) 
{
	snarf_construct_hat("/etc/security/namespace.init",
	        "aafcd359e4dd40c00e5991af5fe3e79a7441e08707360c7df9e92dff27e7c2e846da295a8af35c319ecf454d68bfe3dff64149797ccdfb3693598e55e6439e3d",
	        42
	);
}
static void snarf_hat_44(void) 
{
	snarf_construct_hat("/etc/vmware-tools/scripts/vmware/network",
	        "5998a33a039c75305b0508ebcb0246763eb2369d70c99c1a7c1f7f531ec980504fabeafe73a43d75794187b24abc3ac0c1bce5d5f8ea5f946df47def32cee954",
	        43
	);
}
static void snarf_hat_45(void) 
{
	snarf_construct_hat("/etc/vmware-tools/poweroff-vm-default",
	        "12f79ef2771486bb92d034e53f7cf87262faa3eeb945bfa7324efb73857400be7a72d1ff0a16fc2653f47c492693df8db37e3e8fac4573c596d005102cd986f5",
	        44
	);
}
static void snarf_hat_46(void) 
{
	snarf_construct_hat("/etc/vmware-tools/poweron-vm-default",
	        "12f79ef2771486bb92d034e53f7cf87262faa3eeb945bfa7324efb73857400be7a72d1ff0a16fc2653f47c492693df8db37e3e8fac4573c596d005102cd986f5",
	        45
	);
}
static void snarf_hat_47(void) 
{
	snarf_construct_hat("/etc/vmware-tools/resume-vm-default",
	        "12f79ef2771486bb92d034e53f7cf87262faa3eeb945bfa7324efb73857400be7a72d1ff0a16fc2653f47c492693df8db37e3e8fac4573c596d005102cd986f5",
	        46
	);
}
static void snarf_hat_48(void) 
{
	snarf_construct_hat("/etc/vmware-tools/statechange.subr",
	        "d0826859e3521c6e9acc0436fe12c3d3020a539df7a0a3f1575fe96322c72159ab8dd1cd75ee663e443832cc7bb29ff68f838fa0376069a7297dcbed833a83d4",
	        47
	);
}
static void snarf_hat_49(void) 
{
	snarf_construct_hat("/etc/vmware-tools/suspend-vm-default",
	        "12f79ef2771486bb92d034e53f7cf87262faa3eeb945bfa7324efb73857400be7a72d1ff0a16fc2653f47c492693df8db37e3e8fac4573c596d005102cd986f5",
	        48
	);
}
static void snarf_hat_50(void) 
{
	snarf_construct_hat("/etc/vpnc/vpnc-script",
	        "ba5a0d642b391515bdfe09a1865ddee0e5380097063cc813bf7c69d0fffe41d9f705ce961a62bcb464f54ba7ec81ea6fa92ecdd3c47ad9cf48d047adb56f350a",
	        49
	);
}
static void snarf_hat_51(void) 
{
	snarf_construct_hat("/etc/xdg/Xwayland-session.d/00-xrdb",
	        "9a930b2853141e0087906f826d55bce17d3b7c4169927b2a03c56bff05695c620b298a2006db242ae27250c18f034d0cafdc91e6532c2cc00990ae8c65120d21",
	        50
	);
}
static void snarf_hat_52(void) 
{
	snarf_construct_hat("/etc/xdg/Xwayland-session.d/00-at-spi",
	        "728b633a01bfae1dc5a5c7a44288a7cbc13a6e87e2ed79a46022e3a4e33589b1eddc4f7ef93d23f3162b27f83e7ffe86db9c5655714d72e806992f18bc8931cf",
	        51
	);
}
static void snarf_hat_53(void) 
{
	snarf_construct_hat("/etc/zfs-fuse/zfs_pool_alert",
	        "0c81bdfcccbb8fb7c3214c92b7394c5ef048ccd5e6a26831f71e15b328059e30dff8dce1d49188493f44926c1ec9483f54e53fd290f0c7faf1f6d5d459c06ce5",
	        52
	);
}
static void snarf_hat_54(void) 
{
	snarf_construct_hat("/usr/bin/VBoxClient",
	        "71b24e66b6525399b3e9162d2cf495f2aec0d13affa662aaeb6c02eb5e21a792f24dc263f942f96eb2783a63ab91948e5f4379441afa509386a890c2a94ca1bc",
	        53
	);
}
static void snarf_hat_55(void) 
{
	snarf_construct_hat("/usr/bin/VBoxControl",
	        "691d85231c6dd6003ff620072a6ed631ec347e7d1c905c261d2bdb51d2a7db91779cc0a703b6e94fb2e4ed9057df992a1bf424c9a1e73f741959580d23a4f5ad",
	        54
	);
}
static void snarf_hat_56(void) 
{
	snarf_construct_hat("/usr/bin/VBoxDRMClient",
	        "31dbff7c12021f4f5f02f2859c292524905ae34255beeb0b58bdb7ddf4032db68a3c3049980b49eb5492ce1427fdb29d0edba8e6edc8d5ebb94284ff012068b6",
	        55
	);
}
static void snarf_hat_57(void) 
{
	snarf_construct_hat("/usr/bin/VGAuthService",
	        "4c3d1f0bb399c727f508f96fe9eadacf80d2e7916cf29f5c44e1f44be9c4dab84bf8ce412b64dde37124fe17d518e84fe064331aafb9996ec25fa408b40edcf8",
	        56
	);
}
static void snarf_hat_58(void) 
{
	snarf_construct_hat("/usr/bin/Xorg",
	        "51ceb7d85eef69768f42cbddeb26dd6bc17aca5daf67ef931109febcbb88ba0b66d86fbe36b218ddb13616fce984bf0f8049b3e3c52fa8b5ee511f3d7a846be1",
	        57
	);
}
static void snarf_hat_59(void) 
{
	snarf_construct_hat("/usr/bin/Xvnc",
	        "a0785b0427d248b7e3fe39dae9872559c29c8b1648f9434e882233b82673c3d8bcb7487e46c5f1c1eb34c86859a32393dc3a7af73f42c79d87c9c4e2d0d07ce0",
	        58
	);
}
static void snarf_hat_60(void) 
{
	snarf_construct_hat("/usr/bin/Xwayland",
	        "0bf056519ee9d34651b4514d584cbde0fd95fbe160ab8597b7a8053ad30becbe1de778b5f73f7c4d91ed026acec6361d574b95f788568d7d2a89dcc446e8654d",
	        59
	);
}
static void snarf_hat_61(void) 
{
	snarf_construct_hat("/usr/bin/[",
	        "195888dffe94e2284bf052005307a44ab13323831dd49544f80486733ffc56bff09aa00d568c534ed402ea7733fb827da806b37b9588554470a1c5ef6f08f39f",
	        60
	);
}
static void snarf_hat_62(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-java",
	        "cc689a0923397445f637aec4f2fd395d4ede8f37fc015a2fba72d24acf3c3d4cc5a2914be61962b38995980b34d98e5fb54b41b070bf4a89b58f6b0cb9ad9adc",
	        61
	);
}
static void snarf_hat_63(void) 
{
	snarf_construct_hat("/usr/bin/ac",
	        "f2118eb682be43a19680781152164ace7b3ebd620e855760bc71abd114cb92f88aa0aaf189c2284310c8b7c8cd7ff742ec66f0479627f93f6f63abc70adb3ef4",
	        62
	);
}
static void snarf_hat_64(void) 
{
	snarf_construct_hat("/usr/bin/aconnect",
	        "8f5ba472afb2f701d792a70e2aaaae8ed4812d2dcb7d1db87f704093a067db8489f9fa3383778108b1fa60277a2d0fc9200010e7388a4d09c16dcda1f8d503bf",
	        63
	);
}
static void snarf_hat_65(void) 
{
	snarf_construct_hat("/usr/bin/activate-global-python-argcomplete",
	        "5a4c0086e6513953a997d533acb7e0e2475e0d825c6802900c37e590230c3daf2b4d6b5b34b5b20c023f1393416c8bc41c40b47205f53dc43409d95f0ce08343",
	        64
	);
}
static void snarf_hat_66(void) 
{
	snarf_construct_hat("/usr/bin/alias",
	        "cbcc3424ad876d24dae29b2a0700af60828a5ec6f73e71a72e602958d7ef124151f6f41fca6e592ae2cc208b4d1ae3123b92a23de2f4987c9b7c3e1ae4563c56",
	        65
	);
}
static void snarf_hat_67(void) 
{
	snarf_construct_hat("/usr/bin/alsaloop",
	        "1d2c66e1521433c8c102309806902ba2d432eea7ec78cefe31a4bbdb39b8280294f4c520234029b08f2fbe1d0d15b011270faea71f0d11a80f171c248ed87ed4",
	        66
	);
}
static void snarf_hat_68(void) 
{
	snarf_construct_hat("/usr/bin/alsamixer",
	        "05c228d65d3142b8b249439c9ba6adb563a364cb610222dc96b3027b14f6b140873e0c00cd9ed5d7bcf64fc89ce50480fa1812d338881ce772337a076ea0e12c",
	        67
	);
}
static void snarf_hat_69(void) 
{
	snarf_construct_hat("/usr/bin/alsaunmute",
	        "4468a9e5bced5d9742f1525e10ead67dab04eaa7998259630257fabf65beaef5cee32ebecac21d5c60361be4533a5d991f3a984e7c04e09382510dd700079ee6",
	        68
	);
}
static void snarf_hat_70(void) 
{
	snarf_construct_hat("/usr/bin/amidi",
	        "7aab83e70d29a279471febebb9c6c869a080b6cdfedfc2f71e4b4282d6ba1bf2cdaebda3407947ae3aa482ef34e45949a600b7c9fcfd0cf45d79b8af3daed0a7",
	        69
	);
}
static void snarf_hat_71(void) 
{
	snarf_construct_hat("/usr/bin/amixer",
	        "02868fbe442311d6500b5398a822405677528372de7e1e8cbbcacc92b34fd39ef9de6091c51f0f0f2206df8b72d25369e0c924f62773263f25b2da5e41613950",
	        70
	);
}
static void snarf_hat_72(void) 
{
	snarf_construct_hat("/usr/bin/amuFormat.sh",
	        "1569a4e44888e7817af2145485ee27e77737c5ddc5b5c089024597c75c315063deef64ab9dabeb51a9e063e10fec293620bfed58d4c84334551b1c5e84a742ea",
	        71
	);
}
static void snarf_hat_73(void) 
{
	snarf_construct_hat("/usr/bin/anthy-agent-unicode",
	        "eb0c1e889b803b6c32200d048ddd433addb572bb1de3f8f51ea2af51adb1e6b3f21009c5062a7a3232f69100635cd6f95b0506ec16a08d460f2bf001509eccab",
	        72
	);
}
static void snarf_hat_74(void) 
{
	snarf_construct_hat("/usr/bin/anthy-dic-tool-unicode",
	        "946967a4ad02245d1b69598fb78a8a074816fb570d1e6501eb75affd80ccc5e97116067be9e427ba171b3a435333112a62aacadb132de3a89d61d336fb842323",
	        73
	);
}
static void snarf_hat_75(void) 
{
	snarf_construct_hat("/usr/bin/anthy-morphological-analyzer-unicode",
	        "d73a4430e9841c2de006d37c78b31be33d6cc3f25269fc00b828d33bf3273fdf528123c2288ce2dac0e5e425f73a737efa16b6b4cb4c8a67241e2d413e798a54",
	        74
	);
}
static void snarf_hat_76(void) 
{
	snarf_construct_hat("/usr/bin/aplay",
	        "0cd24f7dcef6de7f08128a95f1bc75bd1315f182518e308244413fbd4dced6fdf261112b43b020031b5d9a067b09bfad7578b0ecab3bf7306306b383d5c070a7",
	        75
	);
}
static void snarf_hat_77(void) 
{
	snarf_construct_hat("/usr/bin/aplaymidi",
	        "032218adcb0afa087ad8288e455d52c97e55f33fa033bc71187a884e944548b0bca1ce46a9142c43965aa52d9676b03635ba24bfd46438194b87d0b0a1e67e79",
	        76
	);
}
static void snarf_hat_78(void) 
{
	snarf_construct_hat("/usr/bin/applydeltarpm",
	        "8623730e54cba5494cdd939675e9c4d4302575a548cbddb1b13d4cad2740da8da67c6241205de0a22e96fdeeb9c83db8108979a733e5fa1e245318f45e78da1f",
	        77
	);
}
static void snarf_hat_79(void) 
{
	snarf_construct_hat("/usr/bin/appstream-compose",
	        "1318d6c96a0bbafcdd2571d1d4acd4ec74e97f04b2a5262f378c859bf33eb582de4d3347c752170e1916bae6bb0ca2ece9c4a5d2a7691ea2cdfe86e36d1fd59e",
	        78
	);
}
static void snarf_hat_80(void) 
{
	snarf_construct_hat("/usr/bin/appstream-util",
	        "4e9072a2531c8f70b3d42ef0ed9f8767c363ff7c3fe7dc8407204e4cf2dd8dbc10f4f7a2ac19b4536b42c6d90e8464d14b153fa45bcf9adb7c65fc4d98b6fd7b",
	        79
	);
}
static void snarf_hat_81(void) 
{
	snarf_construct_hat("/usr/bin/appstreamcli",
	        "d349ed43e3a9b27d09955d8fbb0746d7c0831c9392b2e4605aa6ba4a03223fda0b983ab50839c5bdb469c65f6696cd999ded8b13dd0343faaac8ff3811372787",
	        80
	);
}
static void snarf_hat_82(void) 
{
	snarf_construct_hat("/usr/bin/arch",
	        "f5012b7eacbdbf7af53b45b0a535a91953297b775dbb82b9be84511c55e195b6bbf212b3ad2901a365bd0e89f0403c29e60ee21d6d25a3e82c1ef858e5c58ceb",
	        81
	);
}
static void snarf_hat_83(void) 
{
	snarf_construct_hat("/usr/bin/arecordmidi",
	        "7c55c8598b8a71c0b1c82371b54bf71578067482da2cbbae61e56d22de96f2d87944e4bbf18968fdf5acecf2d1efeb905a4a4e530df557d6b641c532607af263",
	        82
	);
}
static void snarf_hat_84(void) 
{
	snarf_construct_hat("/usr/bin/arping",
	        "1e46c6fabb7bfe425359a5bebc136ab0232ca7d97b1da27face335a02a7f2e726501369bea71ed168380c0f85654f240eaccffa1eb92b01f2aa737a85bad0d4e",
	        83
	);
}
static void snarf_hat_85(void) 
{
	snarf_construct_hat("/usr/bin/aseqdump",
	        "d1d595b1b91962a9b3bb2bc352cf14ba5c9f3470bf41db835f57888859ac0e3343d77fe7831cb195da73d8a21618f30e00a3e6706a26f681ee1de9dcc383ba36",
	        84
	);
}
static void snarf_hat_86(void) 
{
	snarf_construct_hat("/usr/bin/aseqnet",
	        "86b0bdcc5114c1df59b250dbbfd452ff633b1c68c64ca03757c914d23d92b44d177899af1be427bf5f83aac9276d9d7d6f6a4c3a100f909b5712db8b77eaced4",
	        85
	);
}
static void snarf_hat_87(void) 
{
	snarf_construct_hat("/usr/bin/attr",
	        "eef34371a486e201cf7360a56bb5eb66a942769c729cdb5273fd76636e02acc46241a42166c02669f912c7187052ee49f6be0933f6e60cd824948c698b442005",
	        86
	);
}
static void snarf_hat_88(void) 
{
	snarf_construct_hat("/usr/bin/audit2allow",
	        "2c422c62397ae4564c7d3e6706d396f40bc5e9d96a3cf579b9955e56990b0a68d414bf7ffc6f8834813686d5bf5965c78a37ad0cb7164d00d66c5b32c301be77",
	        87
	);
}
static void snarf_hat_89(void) 
{
	snarf_construct_hat("/usr/bin/authselect",
	        "4508d207a76e18adf31144c8aa5728069eb216a6e98a7e9d401a7851622ed4e19e1b6d14790ae3e0c56d14b2e7d4e2c1b20d64520e3977744a23166050637d59",
	        88
	);
}
static void snarf_hat_90(void) 
{
	snarf_construct_hat("/usr/bin/axfer",
	        "8ad0bf36c059ece76f91359be21eb82860eda34085a01add9a16a8bc86267e839cbec699e27a3b1893348439699d57c88ad58958de8d32b88b99f6d30d943cc8",
	        89
	);
}
static void snarf_hat_91(void) 
{
	snarf_construct_hat("/usr/bin/b2sum",
	        "5aea490e051b5ce1bacb29361fd6698b8639d8dfd3024406851da73985beb2edae6529b450bab9d5a3cf0c27f108bdc8575ce7e518e796609d7b74ef75717fab",
	        90
	);
}
static void snarf_hat_92(void) 
{
	snarf_construct_hat("/usr/bin/b43-fwcutter",
	        "ffafbdb21d1d77c2caa32012b58a33701f8a031b367140412430e103e0e6022a9b6f0a791471f4dadc34089403a7a9d21e30fb37977408abd65caebb426bca37",
	        91
	);
}
static void snarf_hat_93(void) 
{
	snarf_construct_hat("/usr/bin/base32",
	        "31f3ec4d99bb26677b3587129946a4ab68934d3c56a69d4f72291e842a163cf05bd1593f1a83032516f5201e053cf5658afdb0d0adb5bdc9547d3b0667c363c0",
	        92
	);
}
static void snarf_hat_94(void) 
{
	snarf_construct_hat("/usr/bin/base64",
	        "285c582d42df91cc29560301ae7c0b704a3efea038b12ffdde6d72e91c1b62d247806ebed347254f82641a54b1b89893ff3fac02549c9bec1259fdcd07053140",
	        93
	);
}
static void snarf_hat_95(void) 
{
	snarf_construct_hat("/usr/bin/basename",
	        "0fb4a00bf832b80357720615243ecdbd02c2d9ffa9628de3666473c0a686d0c3a09be58c5e3425d7c566cbb4ed6c611ffa8e159fac570901bb98ca71b5b2c542",
	        94
	);
}
static void snarf_hat_96(void) 
{
	snarf_construct_hat("/usr/bin/basenc",
	        "b61cce1079a0babb991ae5e3aee0d472af71dce1607dd05dcb810d2663d7d79077955a430fe0a95649c706864d4330518c43a1eab6fcef2515a94ab14fe325e8",
	        95
	);
}
static void snarf_hat_97(void) 
{
	snarf_construct_hat("/usr/bin/bash",
	        "80a20a3ae25c67f0d450e7684477f2ed862c709d6a84245bf39d3488b80e035c7b6ace048038e76c7f2e9022a3bbcaafc2580e67e35812571019986b9abbaf65",
	        96
	);
}
static void snarf_hat_98(void) 
{
	snarf_construct_hat("/usr/bin/bashbug-64",
	        "f2b9c83c904ccf08595b10f1f79de8db95e39d0d69ad17a30c78beaf0a32dd79f0e9cd37aa44dfa09721e2cdb7db5ea4bb3687edc4580537ecb6cf19e475052e",
	        97
	);
}
static void snarf_hat_99(void) 
{
	snarf_construct_hat("/usr/bin/bg",
	        "f284aa48556964161c0e8b4667b6647cf15d946e91b341fbe75ce8c061e28d9d0212b74ef4e5ee0692ee80de50e49c541ab376ef7bf5dbd0dab43ac3bffe8e79",
	        98
	);
}
static void snarf_hat_100(void) 
{
	snarf_construct_hat("/usr/bin/blivet-gui",
	        "694a6e062d146cfa1a833e6c76ea54865fed9031e4ddd127c9c32b4aeb745f91aae5919aba7c36ed291a5af75be235f2039d70062c35b9a1a97cfb03289f842d",
	        99
	);
}
static void snarf_hat_101(void) 
{
	snarf_construct_hat("/usr/bin/blivet-gui-daemon",
	        "26693d5e1de2352ea9a63f6a1ab34fe283962279ee3e41c102a892323210d710ebf31c8aec14ccc3526f5c37610e53bf468c5d8d95293668868b51f553c10f35",
	        100
	);
}
static void snarf_hat_102(void) 
{
	snarf_construct_hat("/usr/bin/bluetooth-sendto",
	        "056ca567b7f3ce4a1406c459ba28aa0f59de03fb0ddb77ffa2d9a3dd37e49cb862dd87b9c44be2a5d3596850283cc45e86cd5f44cf4635acdea4ce1d4834ee1f",
	        101
	);
}
static void snarf_hat_103(void) 
{
	snarf_construct_hat("/usr/bin/boltctl",
	        "d5cc9ad46e4f70d94a9e730dc1e47e124929a877ab9aef401a91826061b2409acd01caab5ea8c768ef9e9a1323af6a25de4ffda146113ad9c39208ba7d836c73",
	        102
	);
}
static void snarf_hat_104(void) 
{
	snarf_construct_hat("/usr/bin/bond2team",
	        "75f73f0419f1ea81a5b94e70bb5606d879784526b8e0e33dcfecf6c547355257a0f06dd530d4e9a621d976b22413dd78dc8c6811ae307bec9b809feeec80a5a4",
	        103
	);
}
static void snarf_hat_105(void) 
{
	snarf_construct_hat("/usr/bin/brltty",
	        "f653c6f2a5f6b21279e1b3f8944beffb6129fa6837f6fd663efcd4e86210a61b4f685782ba23621e271747539c28b69ebff2fa29f41b703994dc297cbab31929",
	        104
	);
}
static void snarf_hat_106(void) 
{
	snarf_construct_hat("/usr/bin/brltty-atb",
	        "b96d5b6a5ea95d84b5f543b6df22e47535cf3dc028f55fc0c54d42062ac7901ceb82fddf1273f82c79ee804155b3a22258a90dc568f326b38f93459595297afa",
	        105
	);
}
static void snarf_hat_107(void) 
{
	snarf_construct_hat("/usr/bin/brltty-cldr",
	        "aa3c3519fc73333685866e3719bfe395d8a144bf428323229b308a53768d6ecb5945712e758d7b1b3c8a6a998531eabfa09a25ced43e32876c7bc48506b9c782",
	        106
	);
}
static void snarf_hat_108(void) 
{
	snarf_construct_hat("/usr/bin/brltty-clip",
	        "267270d203f1298c03fd1ff242dc60e9246b0bf1aebe716073b1b16dd12d19ae994aae2535b55a21ade9ed57d08d9a8dbc05c3764e5e76af1a90ea67e2e515d6",
	        107
	);
}
static void snarf_hat_109(void) 
{
	snarf_construct_hat("/usr/bin/brltty-config.sh",
	        "6c5026944f901a1d7383a2d26459b983a387c069d5ec91ae4e376cd432709026d5075e8afb5141d2dee7de98b7719c2b18d50d6350719e68f4e14bb9a6149008",
	        108
	);
}
static void snarf_hat_110(void) 
{
	snarf_construct_hat("/usr/bin/brltty-ctb",
	        "4576e3293fcfc70bf58d2d6872c54ec547f17bea0e2be0f4ac81c6d729a1ada488ed0d4d1b6d05632b6d0fd314bf89a66cc32b7c9b41bbf9aeab5b7113b02a5b",
	        109
	);
}
static void snarf_hat_111(void) 
{
	snarf_construct_hat("/usr/bin/brltty-genkey",
	        "9eb503fa3d2cf07b80541787cfb0e19839acf3d66cdc3f839bcb97f128a49808560f64020c37445c0e8645ac6ffbcc9d1b31394b68515df503657d4c3bf4bcc5",
	        110
	);
}
static void snarf_hat_112(void) 
{
	snarf_construct_hat("/usr/bin/brltty-ktb",
	        "775e9b94d44363c6d7e66ab38f9a5d8a16db5512952d7368696b043b119b55cbba69c1daa30a3f3a292fcbbffaa18a3aac6bfa4931ff8458d8dcdad2ef195532",
	        111
	);
}
static void snarf_hat_113(void) 
{
	snarf_construct_hat("/usr/bin/brltty-lscmds",
	        "964f03c367f02d9988ade179e2c5ce2ebdd238439af479285b6e9559109591a2b4dd93c19a52f23816387b87c21b2eacc5223addb6bea74501910de0b765963f",
	        112
	);
}
static void snarf_hat_114(void) 
{
	snarf_construct_hat("/usr/bin/brltty-lsinc",
	        "9f207e4679ef52c2b2d08d2abbef0766a4de0da83aed8e41a5105509ae58dc3b651c58971305849b25d16256b6aebf74e6b97f7202a23057421ad1beb4d76063",
	        113
	);
}
static void snarf_hat_115(void) 
{
	snarf_construct_hat("/usr/bin/brltty-mkuser",
	        "c5e0a0d671b9c8ce892264a4329b38240f2d3c0dc9e2e444d53a131fa5d90f61062d1174c7265db8d6a81df10eb6001208e9770d660fa4fc20c929fdafe16496",
	        114
	);
}
static void snarf_hat_116(void) 
{
	snarf_construct_hat("/usr/bin/brltty-morse",
	        "a3b6634204716127aec395f08e30ff32456bccc7378a62913904463ed656783c44c95e2cbda20eb9598d6fa3eb68c07633b5251258f7773f0ad58260fa8f7bb9",
	        115
	);
}
static void snarf_hat_117(void) 
{
	snarf_construct_hat("/usr/bin/brltty-setcaps",
	        "5bbf18de51f538446ca0fc592606064f31b850f2fea57659d74ad88007e63b8cd379f4ce28e6e156e15c60d2dca1438bbec56fdd1fb28991059c106a39e16b0d",
	        116
	);
}
static void snarf_hat_118(void) 
{
	snarf_construct_hat("/usr/bin/brltty-trtxt",
	        "039aa626a0f3e4168f1ce61a24e5fcf4b7a56a9aeb2a470b95bf14edf465ff78f2a47ea6e94d0e5aeab104db12b25f529bba553748549212b28cb293f9ff5225",
	        117
	);
}
static void snarf_hat_119(void) 
{
	snarf_construct_hat("/usr/bin/brltty-ttb",
	        "13aff79b52a497ddb5c55d4e154d8f766d439ba73fa09da403d73982618feac3cb7f844689a5e6a7989157ecce7a4e894348cc2a26389c86202b7598bd73ffa5",
	        118
	);
}
static void snarf_hat_120(void) 
{
	snarf_construct_hat("/usr/bin/brltty-tune",
	        "42261f7e611b0fa7f1b5ceceea480369e69860ab6a6de4961b6583edcad84bb856a51497aa9b9a30a8e9f02f14b06b44fb3a2ec70607e72ce06b53f4b3c3ff4e",
	        119
	);
}
static void snarf_hat_121(void) 
{
	snarf_construct_hat("/usr/bin/bzdiff",
	        "4a7a22226b8bb189a33d9d5d2d37e57e1eaf465f097dc99c3e94c4a8fd760c0bc652f45cebc228bca7e03676fb7a607711e18b4b34a5fea3c3cfe279ea45bfdb",
	        120
	);
}
static void snarf_hat_122(void) 
{
	snarf_construct_hat("/usr/bin/bzgrep",
	        "57fb423a955494e21e25b71c657815d621656612ef023f142cf0d4d84c3c7c046680fee0480629556c65429810dfc889c34d653f373a011a6d385c186d194d50",
	        121
	);
}
static void snarf_hat_123(void) 
{
	snarf_construct_hat("/usr/bin/bzip2",
	        "c98e1ee32096271e47c23b1e0ba010e9b3d7171dbe285526af3e86947fc158a40ebcfce6ba5805c7b071113f4e19cd1174a3d5064407c9ac407cc9f7cc542069",
	        122
	);
}
static void snarf_hat_124(void) 
{
	snarf_construct_hat("/usr/bin/bzip2recover",
	        "5d38659083e1ea01eab4a05384ee62f554462e4e1b14d72f3f5a18deb37b22c4ff1b06642b84e65f0f4afa273aeddc7b894f97c4ed63b245a3e2ed49128ec2e7",
	        123
	);
}
static void snarf_hat_125(void) 
{
	snarf_construct_hat("/usr/bin/bzmore",
	        "165b137814045d08aec57c974f0266ea1f22a9ef328cdf21aa5d0afbbe4d062e573b2367092876a9cd13fafe734e359a71155a0e3e8f7b8200522765d4cf0a2a",
	        124
	);
}
static void snarf_hat_126(void) 
{
	snarf_construct_hat("/usr/bin/c89",
	        "667d42835cf967c61da8ce191ecd5a8b3dd4b8145ebead2de88cc4f0aca9383679cdefb801fcfe5c0edefa281028342e26b69d766519ecfe55649cc41a53c07d",
	        125
	);
}
static void snarf_hat_127(void) 
{
	snarf_construct_hat("/usr/bin/c99",
	        "c6faf9d1e3eba64ee22326da98e16673cd363e8b8dc9aa639bbe05c7416dbcedeafa6ee923e241e33e242e39d076bf406c404e4cc7a14d8ea35ad1c1af02e478",
	        126
	);
}
static void snarf_hat_128(void) 
{
	snarf_construct_hat("/usr/bin/ca-legacy",
	        "258b9dd753e11008a9075074e3245adc99e7f5fedcd7a572a221e9379fa9c76513147ce8de78fd0a715376703fb0b926e53cfce63f870e7e6d880c213877e001",
	        127
	);
}
static void snarf_hat_129(void) 
{
	snarf_construct_hat("/usr/bin/cal",
	        "e76d872b750c9c607648da9b7a22d7223fd8bfaf93cbaec8ef5ef283c1d12c1605476e5998589fe09c37fc80ed700d2d6f88a43398fd7267684faf358529c5d9",
	        128
	);
}
static void snarf_hat_130(void) 
{
	snarf_construct_hat("/usr/bin/cancel.cups",
	        "6023c2553b932655cc1a8fd2b0f4fa55627af9eccb832ffb5f9ca11d8c82c2ef8c1f6d14efc42117403c7c23d7f8a60de34745cff5e6e31956b9d96562b4c1da",
	        129
	);
}
static void snarf_hat_131(void) 
{
	snarf_construct_hat("/usr/bin/cardos-tool",
	        "5bdbae588ab103799fc5cd5b25eb3169ac6e3ffe0028e42afc8478b09471d823ad4976495d18d1c13b085ad26a7f7681c16cac2705d9d3b30abf36390cfc9197",
	        130
	);
}
static void snarf_hat_132(void) 
{
	snarf_construct_hat("/usr/bin/cat",
	        "775a5f04e1382bc36c5ba3a6555b62347de39c11aafdbb30ac086c3e40acff04370e07465d3e4ba2d865b2888c66e4184fd560fdcffb0ef4277560f0d057e52b",
	        131
	);
}
static void snarf_hat_133(void) 
{
	snarf_construct_hat("/usr/bin/catman",
	        "10f3ed2b578f761d2b08481292dcc77a73deb0abc307938cdc689662bb5f2f8358f3c08a162baf49009c732ced23eaf7f6bb0d302b0a5c758c3fff02a3d81264",
	        132
	);
}
static void snarf_hat_134(void) 
{
	snarf_construct_hat("/usr/bin/cd",
	        "392fb7779f1bfd944a8fb912eb193d579ce22e4b97c3f3e1591bc6bb21244d39031c83b9c05f8a0deb51e7e3d89c842cf19a24d59514a356fe191d72d26d790b",
	        133
	);
}
static void snarf_hat_135(void) 
{
	snarf_construct_hat("/usr/bin/cd-convert",
	        "d3785a9633804ad89ea02267a96d8f2ffb821029b60bce045129abe57e3ac9ea6dad6662132cfbb4f684f045f5f86505a3c21d65fd98b7d319fab5b854814825",
	        134
	);
}
static void snarf_hat_136(void) 
{
	snarf_construct_hat("/usr/bin/cd-create-profile",
	        "aad13fa03c968ab4c640713a2d3294096d4a63cf7f2953e8e6800893f06e4b8ddcee23fffc25cf9a1c6e29a2e71a20438f5f196384bb48adc17a3a96b86b815a",
	        135
	);
}
static void snarf_hat_137(void) 
{
	snarf_construct_hat("/usr/bin/cd-drive",
	        "df3e19aca9231f1dbfe90cd929846ead9d5c919abc1b010cef5e46dd03ce8572bb6c237efad7fab7ea82d857ccb9913c8bebc6153a686f380caa803d7993cff7",
	        136
	);
}
static void snarf_hat_138(void) 
{
	snarf_construct_hat("/usr/bin/cd-fix-profile",
	        "1d00512cf245138ea2d9a201efff35a1b3566b3a5f69c65ca5667a3909f233d08f5c2fee29b19bf9b1c999434cc60d8ada25ca4fa763444d699c6ad66fbced7b",
	        137
	);
}
static void snarf_hat_139(void) 
{
	snarf_construct_hat("/usr/bin/cd-iccdump",
	        "171f34b1eda49993bf131fa6443c90716f94367f75e6f630d1db1b70f660722600540390d8848213dce5f702f4b8a89885856bbf9930e2724a4e4fda1be1d04a",
	        138
	);
}
static void snarf_hat_140(void) 
{
	snarf_construct_hat("/usr/bin/cd-info",
	        "792845ced0e3db3f3b1a1b3c37f09892b5252ee4f93d9b134075edfff2d07b67fa1835e579dacaf34f385dc671e2d2fa4eb1451d741e2a3ea398836a1b7f1a60",
	        139
	);
}
static void snarf_hat_141(void) 
{
	snarf_construct_hat("/usr/bin/cd-it8",
	        "fd27ec9e92d34d907c9e18f07fbb33b925ad5c590f24be345279a3312166bcb383cc80ef505304f6d22be25826e66a41eadec08469150b027f947ca3e1bc645f",
	        140
	);
}
static void snarf_hat_142(void) 
{
	snarf_construct_hat("/usr/bin/cd-paranoia",
	        "fa80d7932483e34dfbcdb3df67b082f8210143c83e40ae6fb89358e762b37b4f26759bcc8c775fcbace0dc3aecb2444721cb5fc2646708587403125fab30c4aa",
	        141
	);
}
static void snarf_hat_143(void) 
{
	snarf_construct_hat("/usr/bin/cd-read",
	        "abc8bec770b0d0664971d303d40fd14832f46b15aed20777aacde46bd2a3088d38b0afd0743830b5c9e1bb6757e9e21c9f9f77afc8cd54d4e7661c40d5fc1437",
	        142
	);
}
static void snarf_hat_144(void) 
{
	snarf_construct_hat("/usr/bin/cdda-player",
	        "0c3fa26198dc00e1040a664a1d998d0b93b9cfe29f957609e35489daf2d5eb8df3c20acaf94eefad1d0af3a4a166054cec9b5d60882bafc5d39f75fb315e05f2",
	        143
	);
}
static void snarf_hat_145(void) 
{
	snarf_construct_hat("/usr/bin/certtool",
	        "59799d5499bcf8442ea72b62fad161b3749998e5ea6c7331c5a37a6f2c7c3787fb97559bab96f8b1614a8423e2c13973348e29bf25a0dce6492b09647f9135d0",
	        144
	);
}
static void snarf_hat_146(void) 
{
	snarf_construct_hat("/usr/bin/chacl",
	        "1d06ce12e7265ca426c60c584721d8e899471b17d559fded37a09197c3022e68d7d56d0d6935897819eaea486fc7f83d97580c198fe9d3d20b142a4a6a48a341",
	        145
	);
}
static void snarf_hat_147(void) 
{
	snarf_construct_hat("/usr/bin/chage",
	        "7219d87cfa6a729ad5073ecd2ed2479201fcc743837cc14539d7ac1619c939dacf1691ef7201f564a44bf712d133328052c1fbf3208810c5ee7340827f50140b",
	        146
	);
}
static void snarf_hat_148(void) 
{
	snarf_construct_hat("/usr/bin/chattr",
	        "a5a540d456299f632ff63512adc563cba255469ff6672974d3d8b336e6305cf791da3fe8ab8e64c129fbba74f1a4540c1ca5f66b66aa8a3c87232f15934686e6",
	        147
	);
}
static void snarf_hat_149(void) 
{
	snarf_construct_hat("/usr/bin/chcat",
	        "79a6f30da041a5238b7008292b9aaab08c37d7377d7105ad8b4f52e33fc6af40f750d8735fc76a71baea427d41b00c1d4b24f2a23ca761a3882ad536ca1e4d62",
	        148
	);
}
static void snarf_hat_150(void) 
{
	snarf_construct_hat("/usr/bin/chcon",
	        "e2eac00ca1c205d1b5b89bc1092fd558615d6145ec0126680d865a1597189b3f37559a02de56baf1597a9f1bda9da1c51f5a0a90a0c0402a66623a8f31a3f371",
	        149
	);
}
static void snarf_hat_151(void) 
{
	snarf_construct_hat("/usr/bin/check-regexp",
	        "c49ad852711fe169280ba19f72868497691abba27514a4cbf2dbc39d430b0cac58130394edfe70e57ae4abcc98c737a6f5b7060a7063d6a9a814ea4e8b5921ef",
	        150
	);
}
static void snarf_hat_152(void) 
{
	snarf_construct_hat("/usr/bin/checkisomd5",
	        "48d208850ee2812f339c9070878f28cfc2df74ea84738fffb1cbdc99dbdb40f5b494f57d622f6ea68c6643f898b441f7cb00a3b8edd5858656385e45504d6a57",
	        151
	);
}
static void snarf_hat_153(void) 
{
	snarf_construct_hat("/usr/bin/checkmodule",
	        "b0292406e63bdc63cdb4aaed126bf084c80caff5ecaf3d40e21bba413ab8eba8884904ee4bae4800029a5c68d655b8341cf32da04692b27f0ee732faf009ffef",
	        152
	);
}
static void snarf_hat_154(void) 
{
	snarf_construct_hat("/usr/bin/checkpolicy",
	        "67c35fb1ff066c139018b6054b74aa095fb62627403ac9641bcd76f32878294ee1dfe4f517309d5ae0e81771b7eb20e0602c67027b7c343a58681aa3c0eff748",
	        153
	);
}
static void snarf_hat_155(void) 
{
	snarf_construct_hat("/usr/bin/checksctp",
	        "4d00b5a1ed3deda6ce273ec36e3607d3e2126fcc3fd18150d3c12811f90c76e40ffba9a3de590c97e9c461fe356d6f4e726ff61646f714f45f9e3fd71564f071",
	        154
	);
}
static void snarf_hat_156(void) 
{
	snarf_construct_hat("/usr/bin/chgrp",
	        "45c1b521e1a513f1345729224f530b750e100dffe74e631379aa843a3955d671c58b242c13cc4256fcb9ca15265aeebfee0cef8cf3e9efecb025515d073c220f",
	        155
	);
}
static void snarf_hat_157(void) 
{
	snarf_construct_hat("/usr/bin/chmem",
	        "c191b348ae7cbfb223b540bf5387ff5d880796fe876ee1367a1c027a8fcb4bb5ccad46cbc2880ca32ab1d15f2da312570a2e471ab7b639472f0d993e2304663d",
	        156
	);
}
static void snarf_hat_158(void) 
{
	snarf_construct_hat("/usr/bin/chmod",
	        "fee55ec5d985699ec18db0154383925921b7b18f9db99c404c3eb9b809833434c8ac147a34ce59eeb3522ddb65e3302557779a1e8f33a4fc733fd23c4a0b8397",
	        157
	);
}
static void snarf_hat_159(void) 
{
	snarf_construct_hat("/usr/bin/choom",
	        "e9f05c5b849f621062f37fc7152f5d3ef8b2cd476411269316e7c283a832005cb81f78af135f971d997b5e3d2d1310b25f0a77e7482fc88760131537ba917adf",
	        158
	);
}
static void snarf_hat_160(void) 
{
	snarf_construct_hat("/usr/bin/chown",
	        "b46b1a8194f781f2870ee8bc73af29e7119b6f08373d6f746aa877b6ef8056f4f53fb705ece653c6b0d7972d5a136430356985f95e67029a2267140aa22956eb",
	        159
	);
}
static void snarf_hat_161(void) 
{
	snarf_construct_hat("/usr/bin/chrome-gnome-shell",
	        "e846a9f51788dfe7e7f053bc4e6987378d9294ab42398c0dd5796d647d67059dfcea40a8d478676f8cd1208321f98b1264a6513f9595afd097ee0b1f957f6516",
	        160
	);
}
static void snarf_hat_162(void) 
{
	snarf_construct_hat("/usr/bin/chronyc",
	        "27c577576c2ee8a352e7aab2eb679684ec4250ca0c6917d247caf5c79867ffe1ddadaf944ca3104e0f4156328362487349aa808d2ba5472e745057967a0fb742",
	        161
	);
}
static void snarf_hat_163(void) 
{
	snarf_construct_hat("/usr/bin/chrt",
	        "08405bae5bc0d7d6b8f6542bb43300beea993f8191bd4aa86ff6f0d100ddaa3cbb92a8c0ce9d8d99bfc78f766304a692f200d06f3a5e37b882a3d1659306cffb",
	        162
	);
}
static void snarf_hat_164(void) 
{
	snarf_construct_hat("/usr/bin/cisco-decrypt",
	        "02e1df46c76f0d336960f78c1087e2a3bb8bce59f9aae49d1815f01bdcfacd4ba0122d00ca4f7ddff7b9fb0cff1a2410fd6921785417bda64d3d7f9938d1553d",
	        163
	);
}
static void snarf_hat_165(void) 
{
	snarf_construct_hat("/usr/bin/cksum",
	        "a9523603da306a3e1c95b5838972be8cdb6a96076e13732c3fd8a6e89f3563e6351e3cee0a9695c4e57bfb7566321b321a60f34d6120d7496bba2cfdf34f1816",
	        164
	);
}
static void snarf_hat_166(void) 
{
	snarf_construct_hat("/usr/bin/clear",
	        "81afe635fc2fbe5a840c32120f6138060ec1c6052b7de53469a2ab5bffaca3a7d9047838210a4a568da2542e687e1695d6e8132dd90c6c8fedb99c17dc235647",
	        165
	);
}
static void snarf_hat_167(void) 
{
	snarf_construct_hat("/usr/bin/clockdiff",
	        "bfa2ea193dd2acdf1e5d8544c4329896f13577944ab73ec343bbb2a9ab7eab3c57089eeb0a18cc46d5802e940dd9387b05bd2933032e0e9f1d899f9588a876e6",
	        166
	);
}
static void snarf_hat_168(void) 
{
	snarf_construct_hat("/usr/bin/cmp",
	        "d6a6c525585069410a921a7aaa2ca1787f6f41719ef7aca6ae7dd3898ddf040e5222699d2cb76ceba8dfdd30e17a1e36d631185e63d8e9ed1f23efa62ecb190d",
	        167
	);
}
static void snarf_hat_169(void) 
{
	snarf_construct_hat("/usr/bin/col",
	        "0c73f6e4fe9a07c0ccfb00a8e753d74ae04ed185adc8e2463af66b9677ee866937e87acda87ee6103b9391246628adc4186926aa6826ae76cb8420da233fa231",
	        168
	);
}
static void snarf_hat_170(void) 
{
	snarf_construct_hat("/usr/bin/colcrt",
	        "ed5c31ae9897388c4b987abe70e626e5d28cb4e88858e37215f9afa2835089c59c8c137a2086fa5a5f7168b5c3966710d3205fb16b0a11688aa28ad33b359cd8",
	        169
	);
}
static void snarf_hat_171(void) 
{
	snarf_construct_hat("/usr/bin/colormgr",
	        "c9cb12fd52639552a9e68edeb3e26bd96b1ca0a09bd4a6a8af4e1f2b13d40a3207e3cd0e2543df615553b515d7cf82723476e87ab0fa38f03c66fc67a2baf961",
	        170
	);
}
static void snarf_hat_172(void) 
{
	snarf_construct_hat("/usr/bin/colrm",
	        "710bec7b40b1d39f6343eb91f418adf23e0a387f8b20566b1594b61dabf0bd4623e0b52df60ffbfacd270239d01227dbd5afc0ac504ff4cecebbdd208d466272",
	        171
	);
}
static void snarf_hat_173(void) 
{
	snarf_construct_hat("/usr/bin/column",
	        "cc4a4b2b0e6ef1e34eaf11adcb1259e575a9b729dd5d18ba65cdca14cbf35d7016b531288b6d542268b72aebc90e857dbc6ee7154f698e7aa3b1f83486f43f72",
	        172
	);
}
static void snarf_hat_174(void) 
{
	snarf_construct_hat("/usr/bin/combinedeltarpm",
	        "57b168f1920ec230cbdd704fe1809a93a6b902e8a8508d5228124458a941f973913944a6b3c0b356917b1cd9bb46400c59152ace54c145119967233101f00087",
	        173
	);
}
static void snarf_hat_175(void) 
{
	snarf_construct_hat("/usr/bin/comm",
	        "1c34ae371719647bb39cefa44acd27a2a4d4b25c3d352fdf4ba65db7df8b854b7bc1ef8b1132adc64dcc9bb41d3e33bbb8482fdd8c6d7bd35b6ddb43b82cfffe",
	        174
	);
}
static void snarf_hat_176(void) 
{
	snarf_construct_hat("/usr/bin/command",
	        "0d689aa740dabfefa527c5447d3ff2dbef0d6bb734bf194d1f4d3f5654eff5150df19bcac3310e439eda408b88964d8f16b83d0b4b0579cb200b40e0eb4f90ff",
	        175
	);
}
static void snarf_hat_177(void) 
{
	snarf_construct_hat("/usr/bin/compsize",
	        "08fb660b6db202f28636749148c581a541bf60ec208b18d76e9d30c77cd38e6bf802ec727681d667652a217225067c1302f6c07d955a65731a8d0b1718a57f90",
	        176
	);
}
static void snarf_hat_178(void) 
{
	snarf_construct_hat("/usr/bin/consolehelper",
	        "0421aab620b730ad23d2f6eb455dcff9749079612e072ec1e096fd54e38d23eeda2fd1b1bbe178c99c87b2426545893d1b0aaf0e81fd731146a026e33ab37a81",
	        177
	);
}
static void snarf_hat_179(void) 
{
	snarf_construct_hat("/usr/bin/cp",
	        "3ec49238c55786c2f371032a38aa7926695197c9e1f28248e7a045102c22bf8600d9d793d4ed165e617904b603597754802f217070b73c197dfd37f9a7f740cd",
	        178
	);
}
static void snarf_hat_180(void) 
{
	snarf_construct_hat("/usr/bin/cpio",
	        "246c8c14061000f7c2d4ce2e1a60be450a82ceb30c73177c845e64d20aca2567e9ffa5e3db1b907e25bde4ed6cd45c490a01bc9f0c27feda6c47e97d322abbc9",
	        179
	);
}
static void snarf_hat_181(void) 
{
	snarf_construct_hat("/usr/bin/cpp",
	        "bd9b0cab41b94ec1ee736c15de10c5ed8be3e1fb963f2c51ad656157d45ab28da7757991c2b5bea22f0db1194fb48f1a811fd91864ee510492c0089d67c9ad74",
	        180
	);
}
static void snarf_hat_182(void) 
{
	snarf_construct_hat("/usr/bin/cpp2html",
	        "eb3c29e854d2e666d83ca4b98616dc3858022228e5d511e487c69362dc3aba8b4573cca358e552017151773884fe509377a28795b46e7d7c181ea2b611651ef4",
	        181
	);
}
static void snarf_hat_183(void) 
{
	snarf_construct_hat("/usr/bin/cryptoflex-tool",
	        "01326552a1977181a8cea2b64de7798abf453edafc11dd089a800f738f11bf28354cf2fcb9392336ba06e35bff5be1594c45d31e146d64438a4c5fe6979a631b",
	        182
	);
}
static void snarf_hat_184(void) 
{
	snarf_construct_hat("/usr/bin/csplit",
	        "27d1d91d7524226ebdb161b60f498a35964f5483cb80301991ee55764a4b0fcc3855d07193ef42990cc295824363ec93b7694aef34b3f4f66489d9b637217755",
	        183
	);
}
static void snarf_hat_185(void) 
{
	snarf_construct_hat("/usr/bin/cstool",
	        "df48956e170801fc9a2df22a1cab4b65c0656d434cd78df788390692392ce7beddc51513d27b87d8cffc662f92c28e5a843350a6c6e509c971ccaa7da2b8f307",
	        184
	);
}
static void snarf_hat_186(void) 
{
	snarf_construct_hat("/usr/bin/ctags",
	        "7c355ca88f2c779a268a06a3d135b5d71974e789feaddcb4a2a94d3e1b7516227a0a67e170e4e6a1937393b881bb40264d42020c677a9aa6f1393ce4234c1acf",
	        185
	);
}
static void snarf_hat_187(void) 
{
	snarf_construct_hat("/usr/bin/cups-calibrate",
	        "ad024d7f5fd78b2ccd1e34fcbc72a295f4565e7a9a41101cc7d56259619f575ab9b54459f0ec89cc57c39a2a4d334104fafeeecf7041657aeedcc94f6f908c21",
	        186
	);
}
static void snarf_hat_188(void) 
{
	snarf_construct_hat("/usr/bin/cupstestppd",
	        "a7af8d042b6af8f641cadd0cd2081ad00d21a5091ccf10dce9fb358ea74212b88642b3c46cf1f1a713aa22c3ca4a76db8cfde1d0e92595dd35167e965ad11b8c",
	        187
	);
}
static void snarf_hat_189(void) 
{
	snarf_construct_hat("/usr/bin/cut",
	        "978bd45e7d94784e3c1877120c82b5d6d6a7e1ffd139a21b040ae4cf432690d3417fdfb9dd76b86cd6ca11b3bb9cfb6b9902ab8fb38b6aca58c051025290369f",
	        188
	);
}
static void snarf_hat_190(void) 
{
	snarf_construct_hat("/usr/bin/cvt",
	        "d6d939e9dfe95d2e0cae4d95547bd45af14cdf051c506619399781ee0245542376f6ea8d5e08eba686257fdbe020d573860957b4843843c2661237146451de13",
	        189
	);
}
static void snarf_hat_191(void) 
{
	snarf_construct_hat("/usr/bin/cvtsudoers",
	        "d9e5a8a75394e0c93a4c691173cf8486e0e2afc5266b4cc021517f9b88ec48c09a310d4787c899992d51e12418738ee897fc10ef1c9936b3ba5f8b7c18593fb9",
	        190
	);
}
static void snarf_hat_192(void) 
{
	snarf_construct_hat("/usr/bin/danetool",
	        "2b345737f359f4816656913d4c2744e14951952ecc9d33e03e78e84cd539d20bb3879814e2924c362ef4a92d554a5431d4df9aea2a875f78e5481c4853b16153",
	        191
	);
}
static void snarf_hat_193(void) 
{
	snarf_construct_hat("/usr/bin/date",
	        "9e5c5af799a320f1eedb7a828557f301fdf9651b9b1297950fd26d1723ed97fdb235f96229a56cd0c77dba95bf3a3f96525ab59e7a0a42ea28d21a54939aec99",
	        192
	);
}
static void snarf_hat_194(void) 
{
	snarf_construct_hat("/usr/bin/dazzle-list-counters",
	        "d8410a5a29da72127e92a62224936e3902cd1bbddf98080b3ed109f29c5b041b7935ad4a20bfe7ae5893a0f0afc471a0ec9384d0bcdea0a29fdda1d511a9d142",
	        193
	);
}
static void snarf_hat_195(void) 
{
	snarf_construct_hat("/usr/bin/dbus-binding-tool",
	        "8fd5fb16a232cc8a559a2075656cf4c55bd940c646a8f14f4f31869782b3fc54d90a88c269562fe1ce7d796e5653ecaf7dce610a08daf09a1fbcf08bcd4ad9c8",
	        194
	);
}
static void snarf_hat_196(void) 
{
	snarf_construct_hat("/usr/bin/dconf",
	        "580e47be3f3639fc4deb239cbca5e9496c45fc982e4217fddd884728ece019c4148132804cc8efc7b220378fc47fca3aca14f289f7e3a112177b16362af17703",
	        195
	);
}
static void snarf_hat_197(void) 
{
	snarf_construct_hat("/usr/bin/dd",
	        "4a87704a895d6e8de6d22aad65ef590d071ae45d1b9dd10ef8c24410c58aef9a57634b9fb3f30917b8922c3ca29208f0c36ab9e8f07d677ff8566dfe1bd3b123",
	        196
	);
}
static void snarf_hat_198(void) 
{
	snarf_construct_hat("/usr/bin/debuginfod-find",
	        "048b827772a2db6f70d8956fa5174d50c8a782f472e321bde628827946dbbf954c7b12377370eed36206fc1c978d3ffb53c80f90cce807fad14111693dbd8872",
	        197
	);
}
static void snarf_hat_199(void) 
{
	snarf_construct_hat("/usr/bin/desktop-file-install",
	        "17723c998226ccc4f3ab93ba3940ed402bf5aec85d1dc92dea96dfeaec86e96b36b7f06d38005d2a74abbf5e923f33caec5f830e5ed01e30d4083ce0c1360166",
	        198
	);
}
static void snarf_hat_200(void) 
{
	snarf_construct_hat("/usr/bin/desktop-file-validate",
	        "855ceb447bccd40923acd7e568e861767e34f28330fddfdbf5f1de528b82c4f803fa1c5283c90ad168ba79563285b02ff43272ac50806fad59f7146d5f1a9100",
	        199
	);
}
static void snarf_hat_201(void) 
{
	snarf_construct_hat("/usr/bin/df",
	        "43bbf64009aed45f38f6f7deab4a089e6a3e86b691155637c2f5866d94d5500311ea7df55e1f5fb6b9f0213c33617032e447f46f8c75a858619c9753d6a3ebb6",
	        200
	);
}
static void snarf_hat_202(void) 
{
	snarf_construct_hat("/usr/bin/diff",
	        "4743863fe0d1ca12feba64dabb1b1f4485ce1d27506f76a95df0aac02a9ed3c27090a6cf3c3cb2d7b24fe1a6f47053c1cc6353dbb6328c9e3da40d07aeeae5b2",
	        201
	);
}
static void snarf_hat_203(void) 
{
	snarf_construct_hat("/usr/bin/diff3",
	        "60b868b9e043b223e46cb04807b4d9747541ca1c5aa2e7107138a1d9063a961d5187df6faaf7d1e0c8514f1e5847e1c38ee093736e5ea88e28aaabc4663b4c9c",
	        202
	);
}
static void snarf_hat_204(void) 
{
	snarf_construct_hat("/usr/bin/dir",
	        "c0ad60509facc2aaec468fa2ae0a4192862dd1ed44caef2b51d35ef9e92f00f7083417cdd950bf11d38248849b3856ba9837025a92462a1276e91ad5c3d963a9",
	        203
	);
}
static void snarf_hat_205(void) 
{
	snarf_construct_hat("/usr/bin/dircolors",
	        "1e20d76098d9c3fd002e7e7ca3f3921135d054dd4da071f0c3fafeaf951ef9000c1f9170e68e8d8d20fbb644143622ec465d756d16743a7f69e2f894bd8cdd9c",
	        204
	);
}
static void snarf_hat_206(void) 
{
	snarf_construct_hat("/usr/bin/dirname",
	        "93b0db38a04f8371708908fb1e41f89b935906a40b880ea25d77f4f5a3ef9f3f1cf1af741338248a2b252790ce253c37cdd10975714bfb6dbeeb7c88dfec85da",
	        205
	);
}
static void snarf_hat_207(void) 
{
	snarf_construct_hat("/usr/bin/distro",
	        "af2aa4f7a04cebbd59cba71a10255cdd022e9c9e3b8f3908f2b4c1028d96aaca33544358e2d314fbc6764fed959188aea7b575ea97f3150ade087f1a89c0c213",
	        206
	);
}
static void snarf_hat_208(void) 
{
	snarf_construct_hat("/usr/bin/dmesg",
	        "e0844dbe6a3b4923c6a8fb7cfafa19c11befc000fe865e187280cdef4ec49a000622887424382e817abb5f45a71e6c6f0363ca779ec8fd27f9b307454219d1a2",
	        207
	);
}
static void snarf_hat_209(void) 
{
	snarf_construct_hat("/usr/bin/dnie-tool",
	        "5041b412c5db3cc0bf892a31a72670aeed1d978a8bc33f64ac265d49b11583b000a59f485af2f1694f737ab3f4b6aead83209e813b1df78a8061971baa94fec9",
	        208
	);
}
static void snarf_hat_210(void) 
{
	snarf_construct_hat("/usr/bin/dog",
	        "a4bb28dc92ee0f58de604050fddce201a4b76215a6bbae8572dd9565acf8eb8fa9bd531618c2e11e8c4d5db64faa9c46d2c822cbe9a1de8f8d7cee74c808512c",
	        209
	);
}
static void snarf_hat_211(void) 
{
	snarf_construct_hat("/usr/bin/dos2unix",
	        "71ca6685f2b65684834297c922ebb32d6bbc1f9bbb7620d040b3d8faf4f4ec823bd0abac44eba2b5ea3803199c73b5252d432326c982ee552ed4ecf0835c2244",
	        210
	);
}
static void snarf_hat_212(void) 
{
	snarf_construct_hat("/usr/bin/du",
	        "181f5bc7bcd462fb5ad5a075f99320ddec334a4d65e309fdd77f21c87eca96e5afa53ea99329ab7e4d6caaa46b6577afdc858da7364f3c83b477116f7ef22964",
	        211
	);
}
static void snarf_hat_213(void) 
{
	snarf_construct_hat("/usr/bin/echo",
	        "7f62b6ba6f87e8e3a0fae9b5daf27b55be8979c7ce272293acd99a37a856e36e4ecf3ec625e42b749bb000a89444a86e9c6dde63484318a23d63ed013acec211",
	        212
	);
}
static void snarf_hat_214(void) 
{
	snarf_construct_hat("/usr/bin/egk-tool",
	        "f85cb3b632632a5071b9a6824ecc99fe20342c8a0a0031f548d40f7909f1dc06a3dc78976de1d55bb22c5e83f574431b8afef6e848eed66a51791f42f9d0b2d8",
	        213
	);
}
static void snarf_hat_215(void) 
{
	snarf_construct_hat("/usr/bin/egrep",
	        "40b97e4d6fc456d35419e11edad1b246b3c385fb9ea3bb460850e01e26ebec99eab8dcaad696b798d96300efbb8f4e5204baf5aaf248d69a223e8befc2da9c7f",
	        214
	);
}
static void snarf_hat_216(void) 
{
	snarf_construct_hat("/usr/bin/eidenv",
	        "f07abfcb41be45ac1caf782827db47f4936222358ded497d67f46f5d4698a2e2098bee32f99482c69dad409385539dd8bfa3d0639f7628156932a1adf92c9430",
	        215
	);
}
static void snarf_hat_217(void) 
{
	snarf_construct_hat("/usr/bin/eject",
	        "8c50b8f82cfa07f4d0925bd8783efab587f768cca26ed7c3c3cddd7c9ae8481bf7b01a592b31ed54f70f5a32a306f2042e38ffae5077082769137ea8d4104624",
	        216
	);
}
static void snarf_hat_218(void) 
{
	snarf_construct_hat("/usr/bin/enchant",
	        "14f7ca587a9c1ad3ac34922cc51aafa5ffb95e03872437506e61f4e376d45fa83daba3964cda6597704e2cac3ba4a2fbc7811724f94e97151c7669a325a89fc8",
	        217
	);
}
static void snarf_hat_219(void) 
{
	snarf_construct_hat("/usr/bin/enchant-2",
	        "f6bdb4ee0a7720cca72c51f463224a0d9e92c6016d5176f6a0a0d75acb6b78a6c4831795589db68b7b1ee52593175c8cd8fc1e4cc9fed1e96865b606b2c1b3c5",
	        218
	);
}
static void snarf_hat_220(void) 
{
	snarf_construct_hat("/usr/bin/enchant-lsmod",
	        "2a6b530a08b60b6463197021c2bbdda4a5047f375c73c93d8b8204d78ed78d3f9b9aa5e2be74afb9c7a8bd36302d0fccbe182c67d192796eb93807ca6ea0653d",
	        219
	);
}
static void snarf_hat_221(void) 
{
	snarf_construct_hat("/usr/bin/enchant-lsmod-2",
	        "7cfa980f900babb5eb32b552cc79ec8b9b704c5a3bfc2e70e323cb00ed1792a9d9a33a6f98bd21360da611c0784339099cdb05b512add8519d80e55a7f76be31",
	        220
	);
}
static void snarf_hat_222(void) 
{
	snarf_construct_hat("/usr/bin/env",
	        "7e1c35635996f076cb504719300f21fa80ed6e1c767f4c41d91bcda3f8a3b6625578c169ccf9a195eee8b2f64f89ac71377c9abf4f542119d81deedd35f26243",
	        221
	);
}
static void snarf_hat_223(void) 
{
	snarf_construct_hat("/usr/bin/envsubst",
	        "e726653965cd9f16facba82e4b60ba27f3108c248a4c61e0d152f5b68496d2ea2001b710fe8e43febd7333d738fdb7d93116e0f9235397d5810129508bb96af6",
	        222
	);
}
static void snarf_hat_224(void) 
{
	snarf_construct_hat("/usr/bin/eqn",
	        "5df56b2770e84a84524ecf2fe8d06e8657852b4fae47dae97fea5385e251a4d80505552e5eb3705d2f5a866155cd8b1c6256eefdb4479dcc8e1911408c332475",
	        223
	);
}
static void snarf_hat_225(void) 
{
	snarf_construct_hat("/usr/bin/escputil",
	        "0d2387f1ac3295244ad30f21a113f75d8237a8a97c0d4b2dae4024e4367a9a8892cf48bc228625ca4674d38d5f8a469378a5fbf92e05a9e0aacd8ce0664eb2b1",
	        224
	);
}
static void snarf_hat_226(void) 
{
	snarf_construct_hat("/usr/bin/espeak-ng",
	        "4fba30aaf2b66d7fe5fefc4a25f6ad26e1528957e41f2478749ccf3c1433f504d256b98ac64a9a04ca8d214755866bc37f4f2ac517367558ec82f9be67c7f20f",
	        225
	);
}
static void snarf_hat_227(void) 
{
	snarf_construct_hat("/usr/bin/eu-addr2line",
	        "dee9621e383f7943dab0ab1d090eec2af5537bdcf05ba14aff87ca97939c92e464017b9b61931a027303b24f4d56119d2a84cde49a72c09a5c11e21536f74583",
	        226
	);
}
static void snarf_hat_228(void) 
{
	snarf_construct_hat("/usr/bin/eu-ar",
	        "009ac0423d37dac84b70d3e5c99792c9448790c3b2747dbd9ac43a5f9c0e6c89f00b4a864a02cfb262056271c120ead942dbe3e482a1eb0a83d16d0c9210a61d",
	        227
	);
}
static void snarf_hat_229(void) 
{
	snarf_construct_hat("/usr/bin/eu-elfclassify",
	        "8dc349b359f5a0d868689eed707f1ffe035d65cbd440203c2b143ed2d332a2595e084a925570e76f9c2995d2d29f6b082621b56d48b6de5de694f6dce02e7a1e",
	        228
	);
}
static void snarf_hat_230(void) 
{
	snarf_construct_hat("/usr/bin/eu-elfcmp",
	        "746492a335be361af90549f58aa1f0d2826e9d5e8f327246fe696ba32e9ae630af4e09e2636ffa7727ca127605ed66f52e122d2900e49c0ab41c5f61670dcfcb",
	        229
	);
}
static void snarf_hat_231(void) 
{
	snarf_construct_hat("/usr/bin/eu-elfcompress",
	        "fb0c0a077c7737651946cecbff1f8e891106552ca06e93bd577d8b3f7c6a7db91c9f74ee564cfe15cee002a3ec807c7fb8c83f5b9cc52eb357cde83619d8e121",
	        230
	);
}
static void snarf_hat_232(void) 
{
	snarf_construct_hat("/usr/bin/eu-elflint",
	        "5e80d258c2bce4329a1d2443b1606bbdbee3f6acc5371d82aa230a2feec6cfc010b3825f8bbcba52852e62dae00edde7cf89ca26a4244cedc36f4994ea331dae",
	        231
	);
}
static void snarf_hat_233(void) 
{
	snarf_construct_hat("/usr/bin/eu-findtextrel",
	        "f77755af89074c77ac2323331dfe35cf306b8a22ce717d78ede8b122d3dbec09dc1a5c008cccad33685d7be2c377692f800a4ac787c52bed928d8c3535bfd4ef",
	        232
	);
}
static void snarf_hat_234(void) 
{
	snarf_construct_hat("/usr/bin/eu-make-debug-archive",
	        "64c3860af8788c173974f1f92365407f223f1ccd7a1919742ef58959c669ad814e6b97423161e30979bb37f2e8b1f91974880e4f95fd4e2033c66ef821e9efe7",
	        233
	);
}
static void snarf_hat_235(void) 
{
	snarf_construct_hat("/usr/bin/eu-nm",
	        "3c52eda6870c55ef1dbe825cf435827c2e5966980c4b61ecfd661a9accde5408e0bf200ddbc5a600b81df566b618c8c5724137a643efa1c366b859bdb92a8aea",
	        234
	);
}
static void snarf_hat_236(void) 
{
	snarf_construct_hat("/usr/bin/eu-objdump",
	        "51ba0627a22879f6e8d65c0de66c225cebbb0c6cfa084be85ec00b6f6b1eed3fd530c2bc59219ca0155d804bdbaf771289598624a5c23d0117d248997827427c",
	        235
	);
}
static void snarf_hat_237(void) 
{
	snarf_construct_hat("/usr/bin/eu-ranlib",
	        "e93adf5020fc0d1d3ea08fe7415f550609ed9dfd3a7b73b65ee5dd7d7e35912df5fecbcdd58ded4e3cfaf7eaa1689fa86ce741d8eb1985c16c4b848d76da6744",
	        236
	);
}
static void snarf_hat_238(void) 
{
	snarf_construct_hat("/usr/bin/eu-readelf",
	        "2a829919e85b9e2ad1e375b6124342ed4509ae90f8f30bb5238d69d7015f5ba7587ea62e5ceb5b42e34bbd32cffd568f56040474ddb5c8c970678494143adfff",
	        237
	);
}
static void snarf_hat_239(void) 
{
	snarf_construct_hat("/usr/bin/eu-size",
	        "27905e05245eb41708a1de1039e12a09c94555434f7d264ed51b1b35fae4ce7f2a9ecf74d6703fa2f541fff4b59e734011f3786a6d17263bebe9f120c2485d60",
	        238
	);
}
static void snarf_hat_240(void) 
{
	snarf_construct_hat("/usr/bin/eu-stack",
	        "62a812f59ca6c6ad01609ae90808ef51317ee5a9ceed62cb74cca78f7617361bd25a10205912b5268c15ccd5cf81e781a9193d5942756d0900acab4e83665534",
	        239
	);
}
static void snarf_hat_241(void) 
{
	snarf_construct_hat("/usr/bin/eu-strings",
	        "d6570e2eaacb25b96dbf8903faae527adf7da49699f197dee3baab4216358d2fcad06ac6f79c62c8c1646af81587a4bda06fb5dfc463d0775ef17b68c1958ddc",
	        240
	);
}
static void snarf_hat_242(void) 
{
	snarf_construct_hat("/usr/bin/eu-strip",
	        "c6567611cd7b3daea2a155860c0d381a6c586337115f7a9b0bed3111b7e3a2537388fc908aa152330ad57e354a2b83c83f654143d71733f2b98916d5a08f6fbc",
	        241
	);
}
static void snarf_hat_243(void) 
{
	snarf_construct_hat("/usr/bin/eu-unstrip",
	        "f60c1ee2eafd6ef15bf6b9ae295520a012456d1a5d206b59022f056985bfb35e950ad81673c33b3c53f2f74d206776064fd05ddc0ac2bea451717c0c05ef4976",
	        242
	);
}
static void snarf_hat_244(void) 
{
	snarf_construct_hat("/usr/bin/eutp",
	        "8ba5c40f4cf7e1062211a34b4823635687a93b4cb220bc6d74ac3ab3eb70ab15d62fbbcb29f98c6109201f14264671b001ff026c1da09ba18e009eb31e0b97d6",
	        243
	);
}
static void snarf_hat_245(void) 
{
	snarf_construct_hat("/usr/bin/evince",
	        "88bc94eb1e629938e60f4b45784b4ae80b5e8072991c94302ff587ba4388c2bd027646c4e54ce90373925d0d10b30cde97080d97f3f3537176b6976703fb3411",
	        244
	);
}
static void snarf_hat_246(void) 
{
	snarf_construct_hat("/usr/bin/evince-previewer",
	        "7810397ffb25263ea40914be6bed450f25dcea15d962ab11a7c7dcd2835096974fbf1fc78e5b620d3893a84625ef4eacd19ee7edf975a286f7e538c68fe8875f",
	        245
	);
}
static void snarf_hat_247(void) 
{
	snarf_construct_hat("/usr/bin/evince-thumbnailer",
	        "31a63db79a688ecebf3de4dd2a137970d2af2eb0a39786c196b3e987c37ae5226d2f497a1ca75adaf7227667c60ba544a28470e76f52cd9f0a128a342935d7c0",
	        246
	);
}
static void snarf_hat_248(void) 
{
	snarf_construct_hat("/usr/bin/evmctl",
	        "c0177226b390e932f5681684313df0866a8a52ba810091e4b9d5aa9ffec49930c52d181da503bb204b91c8528e0ed17484bbfb5c8c269bbd596205b92b7acac5",
	        247
	);
}
static void snarf_hat_249(void) 
{
	snarf_construct_hat("/usr/bin/exempi",
	        "5aa08eb98486078bf5ae96454cca4dcf4751ff90f9d49fda9b9d44bfff33420974e965a3e6ec6d2315fcf5e49b0cc32609eb1836f1ce3f0edc58cd75d0a76355",
	        248
	);
}
static void snarf_hat_250(void) 
{
	snarf_construct_hat("/usr/bin/exiv2",
	        "88f686d8b483505e1a15dcd7827adb309ce6ecf1db533849be9a8393ff19a65bc20f6518e5d6620667091dfb092ffc2fe13c53f78f81aea9d5138614a1e747e1",
	        249
	);
}
static void snarf_hat_251(void) 
{
	snarf_construct_hat("/usr/bin/expand",
	        "c7bb698a40c9f38b32c28d16c66fe9472b9f35dbf6b14d7dbe31a7155554b84471dc54357a66dd12b2853b79aa819c8d2c1ba656b496cca4108987eeaf93eac4",
	        250
	);
}
static void snarf_hat_252(void) 
{
	snarf_construct_hat("/usr/bin/expr",
	        "fd772e6bfa91792404bb25553fc2e930c910fc714b6c9e40ba982b5192bf52c849f1451f7de98aac70a5c170dde4b7ae0e3672b9008cb4694ca34723a851815f",
	        251
	);
}
static void snarf_hat_253(void) 
{
	snarf_construct_hat("/usr/bin/factor",
	        "877353e4add43cec302c13256797c8d9d1732ec299c6e92f0bb0036bcf3efdbe03639518689d765bdacd50b8a36422bf49a952da9b7f8a641d1db2751907b47f",
	        252
	);
}
static void snarf_hat_254(void) 
{
	snarf_construct_hat("/usr/bin/fallocate",
	        "6481359b5b65aac5167b3352186e5167856b6a7185c18d09e6183e48c2b5705a42b32f10a1ebfd66be09ee73fb6317c14669c1edd1388a5c874bbb5dc4078d05",
	        253
	);
}
static void snarf_hat_255(void) 
{
	snarf_construct_hat("/usr/bin/false",
	        "4838d4b8833e4329ebf1888f72343119282cab3d4a9162c477deb2d02fd72ab988827154a020c415a10bf79c93c767c96a8f9fb123f8e76b3f49829f3e81038f",
	        254
	);
}
static void snarf_hat_256(void) 
{
	snarf_construct_hat("/usr/bin/fc",
	        "3349355ad30c506e12926dea12799cd419f61ca696df729c3294cad0031f5fd6bdb5975d0a7c046173924f69e60b12654d3d3f46a4a5a7da5dad70cfa48d7eec",
	        255
	);
}
static void snarf_hat_257(void) 
{
	snarf_construct_hat("/usr/bin/fc-cache",
	        "3f804d411d709f9c6bc3e57d6a80c578efab482bc765e205bbbacbea1f50057ce7da2c5e08f371820493d57df9bdbce494b5f49b81a7f13053dcc56fffe77c0b",
	        256
	);
}
static void snarf_hat_258(void) 
{
	snarf_construct_hat("/usr/bin/fc-cache-64",
	        "d9bb33c75655682511440ed47543240d92b3f405c4bee81c30e727e5589a7f4db4236faeb64aac76c5c34c65e955a9b3c9f80e12139cf176ed4d10dee15f61cc",
	        257
	);
}
static void snarf_hat_259(void) 
{
	snarf_construct_hat("/usr/bin/fc-cat",
	        "487cb79a06042a6f23846f318457bc24b1d70ced0766816cea98a7d6647d7603f4c674957cc4af424c55643e0aa51648c44701278b3bfa29fdeaa71750ecb9bb",
	        258
	);
}
static void snarf_hat_260(void) 
{
	snarf_construct_hat("/usr/bin/fc-conflist",
	        "f66a72ac2c29d900439459cc631563c0f2deabf52c94b2b6626e2555329604a3d55af134a18228cf9cc8f0360c39cb0f649fe4d8448c79444987cbc6e546692a",
	        259
	);
}
static void snarf_hat_261(void) 
{
	snarf_construct_hat("/usr/bin/fc-list",
	        "7c62918410a77a844665a312a4c8bda8c8a9a65b845f98799a23358d4188420d03ce851a4754db96f0aaf92b88c1e6c88c54ae6f68f53e45006224e25c33c564",
	        260
	);
}
static void snarf_hat_262(void) 
{
	snarf_construct_hat("/usr/bin/fc-match",
	        "857c11ac23bb89aa6ff85c6b5be6a95ecc3ba6a22846c9e5539de899c1f629a36038b5e00e594e112cb90659e064af4dad29e956faa8c1e49260a02da7da40b1",
	        261
	);
}
static void snarf_hat_263(void) 
{
	snarf_construct_hat("/usr/bin/fc-pattern",
	        "df814c3a6cfe956b3b1c8e6db922ebb1f49de8669a90c5592980231902771de373a58f1dfdb28ffd8b49bf2899f5663abf2fcc06e557b9675adcc61e2535fdc6",
	        262
	);
}
static void snarf_hat_264(void) 
{
	snarf_construct_hat("/usr/bin/fc-query",
	        "89186ffcad37877fc195b7bded9fe2cd48f143a82325d1de24f6d0f538557995109958121c1bea55088879b9853ae0b6b5d39b929a360de3d606b1e35ef9e5b1",
	        263
	);
}
static void snarf_hat_265(void) 
{
	snarf_construct_hat("/usr/bin/fc-scan",
	        "740867ef1b1e5bccdce5764163f7709680a3941b7d501c50abf0682bc91bdc818fda4f05937b1ce4854b0fb27c6233559ff8d5d5ba288928a47cfff0fb92c046",
	        264
	);
}
static void snarf_hat_266(void) 
{
	snarf_construct_hat("/usr/bin/fc-validate",
	        "360e7b657b10469057a4b7659a4a5db77fded35f16b96460c051b424024e21a1ac1430546d3ee2b967401aecd1d7bf7e2c704713583bcfbc16060253aa5157ae",
	        265
	);
}
static void snarf_hat_267(void) 
{
	snarf_construct_hat("/usr/bin/fg",
	        "995a14b949308878a94b6fa8f59d7ec5388389fd50237288438fff5ee8d8942f67b214b5e2cdd9efa51a88b1006fc69d3aff0b117dbd247135a9ef4a6cb44f03",
	        266
	);
}
static void snarf_hat_268(void) 
{
	snarf_construct_hat("/usr/bin/fgrep",
	        "b15cb010b97a85a05e8429ef407a269fc50fe369ddb7e427a6d668cc790bb465bcdafe6f5f96ce2071a87a201cf966f4f4e275631d48317e4e1c0365c8ed00c1",
	        267
	);
}
static void snarf_hat_269(void) 
{
	snarf_construct_hat("/usr/bin/file",
	        "a45046943a7a0d9f7c3f3c7c6bcaca9d27a41bdd96e5d9654d23671a3253ab68ee2eaf9f972ac72a2daab45ad395777cb0bff329002cf3df89eb2fda13cd7282",
	        268
	);
}
static void snarf_hat_270(void) 
{
	snarf_construct_hat("/usr/bin/fincore",
	        "c6f9cf96c17eda23be7bc8722f60a0ca6ce0270c96bd0d95953e991089fd3c663cc4e54f772055e38e7f29be0efcd6d938c92da48e2c6ebaf45204901458a3cd",
	        269
	);
}
static void snarf_hat_271(void) 
{
	snarf_construct_hat("/usr/bin/find",
	        "e63fdbeecfea110ea39975a127408db48143c0623e468f8f17bb905b8f7a12e810959176bd4c530e3427837709e213be0f042bc8eda9077e5a8505f1aebd11bd",
	        270
	);
}
static void snarf_hat_272(void) 
{
	snarf_construct_hat("/usr/bin/findmnt",
	        "334854271683430c2c32a4055ff4cd5b53f43fae1fccdb71880059b3228aba8f722389501319108b3c9da8a233d82e181c1a7191b17bf25a07ad06fbc53f1956",
	        271
	);
}
static void snarf_hat_273(void) 
{
	snarf_construct_hat("/usr/bin/fips-finish-install",
	        "4df91ebccd55d6ef0b7d32220864bd9e4c8322d83d794f968588dc67ff721e9be4f03d98556f6cb9da2d3372b5209c82062692b749a84149775e8f2b4deb153a",
	        272
	);
}
static void snarf_hat_274(void) 
{
	snarf_construct_hat("/usr/bin/fips-mode-setup",
	        "f56b259c9854744d768c39ef8e0f288da6368762676ba883633c2875950934fecac37a19f4dd5ea858a44218cdffd69952a0f674799f973a02b2553d548bcc28",
	        273
	);
}
static void snarf_hat_275(void) 
{
	snarf_construct_hat("/usr/bin/flexiblas",
	        "ab9482cc84b2b4665a1ed952fc0f58d45ea8a58a9e46decce8fa691f6a713ddcac2f0328edf97efa7771de2e09c89f7aaa53b8f54681b8b966bcb3b1df1fc8cd",
	        274
	);
}
static void snarf_hat_276(void) 
{
	snarf_construct_hat("/usr/bin/flock",
	        "9d203693c61bce0f06cca6f6ead4b29a58010fa9f2474e0d2e5af0e1de91cd62987a935ec1cf3b26c052edcc6b041c370fcffe455d9af11339fa65330821e2f2",
	        275
	);
}
static void snarf_hat_277(void) 
{
	snarf_construct_hat("/usr/bin/fmt",
	        "79343adda6ab29b6accc8a7051210b60d05f0f948e8f5a26476538e63a668fa895dc63b3f1c0e6ce43e30151a9c7f58492761f35cfa4297b2df79c49a81f11a0",
	        276
	);
}
static void snarf_hat_278(void) 
{
	snarf_construct_hat("/usr/bin/fold",
	        "7f8ab22a5c1ce354a24dd9715c8671117066d7b78a794d315c9622a3f37de41d18eda2f3183629d4c84247ea1af46785fe30427998ec9837f6e0c57300bf2684",
	        277
	);
}
static void snarf_hat_279(void) 
{
	snarf_construct_hat("/usr/bin/fpaste",
	        "aa14491d9439781e622af9502ea732ad537845eb27354b3a702e13d46cbfc31b86e9cdf9380571bd5ab530f7027991dbc0c769781d06087b093989013d11841f",
	        278
	);
}
static void snarf_hat_280(void) 
{
	snarf_construct_hat("/usr/bin/fprintd-delete",
	        "714e0cf7c740a1fefadd2b89507b73a53d893a07ec111878c11aa82553251b751acd31ec81bd667fc041aaf861b92e6457a8331760e9c6d555eeb868d4d1ce4f",
	        279
	);
}
static void snarf_hat_281(void) 
{
	snarf_construct_hat("/usr/bin/fprintd-enroll",
	        "8745fd0b8c62bf0bfba460250d914d67fabbc4b2f6e8fc139e5319522f6800711dee451387dd85e9d75d7b57b74f6b27525b087070b6f3bbd4bb5bc9ff9189a4",
	        280
	);
}
static void snarf_hat_282(void) 
{
	snarf_construct_hat("/usr/bin/fprintd-list",
	        "a23066eb53d5b61b372b6ac3045b634a5ec11d766b5795749d8a0c590a07a12ae12ab754ce20d24c7141d03cb4d51387303e214aa1aa23628f3d3e5c4ed44a00",
	        281
	);
}
static void snarf_hat_283(void) 
{
	snarf_construct_hat("/usr/bin/fprintd-verify",
	        "a7fe33fc15d1d9358a4da98f4dfb87fd5ecef6af3bffd193a3d2e23f2c0bb3576ad66b5e91e8bf14130f50a770f3321cbf331c428b1802409c9574c8bedb48ac",
	        282
	);
}
static void snarf_hat_284(void) 
{
	snarf_construct_hat("/usr/bin/free",
	        "e4505ce2ba261ff3396d7ed428a8a25f4d3e14a987ebb3cef5421b03f58dd5bceaeca4ed683d863d677597bfd422da43ef9f8227d1d3f6a9fad54d3eff0d31f3",
	        283
	);
}
static void snarf_hat_285(void) 
{
	snarf_construct_hat("/usr/bin/fribidi",
	        "6baea6b073c0e72d42ab2ce70ed61525eb7c02a8b8d9f16a5f4a229351042355cf911a3a4eb299f7ba7886d150971e6d401e3b8a25a195cd48621e7f47bc59f2",
	        284
	);
}
static void snarf_hat_286(void) 
{
	snarf_construct_hat("/usr/bin/fros",
	        "845c17d6e9bc5f2a9a526e5ed734204da6b721069c2d1f8fff67e0cbd3715140eee53180bafab787d40231145c8cd4a76fa1b4ec8b127b77937abcc1aad11ddf",
	        285
	);
}
static void snarf_hat_287(void) 
{
	snarf_construct_hat("/usr/bin/funzip",
	        "b78ee4eb6bc88b523323e1244a41dc8149c586987bd372c92a0793cb8da03f087c0e1cb630bb5e956070f95c99289b3ce44c45bda4f15eee0a3a34e2aa0d0d35",
	        286
	);
}
static void snarf_hat_288(void) 
{
	snarf_construct_hat("/usr/bin/fuse2fs",
	        "86e7505b5582b05d3cf5a96cfa3b9f05911cf4969f751400ed155e443681dc10f74523fab01b1dcb432025f88d4ddcd274d8c0c1a7a683558d444aa54e4a8274",
	        287
	);
}
static void snarf_hat_289(void) 
{
	snarf_construct_hat("/usr/bin/fusermount",
	        "7027705ee5081ee46da50655f7538ab52e5c9b2f65d1ae3ff058158717f6942c234f0f490a2ca506a9e61ef18a99b86a8487d993e169a8ed35e762b5d0c9cd4a",
	        288
	);
}
static void snarf_hat_290(void) 
{
	snarf_construct_hat("/usr/bin/gamemode-simulate-game",
	        "ae1367a423c15e85ac1d7caf47ac11b3c89710fd46cfe8e7bbea63c633b079d0bb19e3ee3f5d9ce946178607391acd655a1adb1850461cbb3df61ec87f145ba1",
	        289
	);
}
static void snarf_hat_291(void) 
{
	snarf_construct_hat("/usr/bin/gamemoded",
	        "53e9c79473dead55c451cc9273a7052f67bdf09209b1e99b3663bcfc1e0409955442f99894867741da9d99009503331c4d93660467a77f921c05283deb622c66",
	        290
	);
}
static void snarf_hat_292(void) 
{
	snarf_construct_hat("/usr/bin/gamemoderun",
	        "a4f49909d6a73e06bfad148284479382b3b348314093d34c2be1aff2ca641801e13de62889f1b6ed60f036372402762007761146d63e5536bbf05bbe63ca5cda",
	        291
	);
}
static void snarf_hat_293(void) 
{
	snarf_construct_hat("/usr/bin/gawk",
	        "1a5c986509df98c100487a5b6440204543e20000b5c93bfff252997ecb4856c62c16dba7a77a33af5f8da4f9df950a9366f4f92c0da021b229a4781d8b8aa4ef",
	        292
	);
}
static void snarf_hat_294(void) 
{
	snarf_construct_hat("/usr/bin/gcc-ar",
	        "d7537c6e4fca3d0c7b93127b44b4de7599f4efcccb278ebf1db0b557a10f971ef9a1f14e96b61415b4a22c44c075c7d890123d7ca759b0885249ca9f8da337cb",
	        293
	);
}
static void snarf_hat_295(void) 
{
	snarf_construct_hat("/usr/bin/gcc-nm",
	        "c93443073be567014f14f26844965a1ee83f64fbd65f6fdaf1b05c61e50e0b3b2f224b1cd8e1da3b0c991a54f28d7c1791164ad6cda8145ee366138e8a31840c",
	        294
	);
}
static void snarf_hat_296(void) 
{
	snarf_construct_hat("/usr/bin/gcc-ranlib",
	        "6a7c85e9703f8bc672aafb8f828bb8d94e35ad8ddf4f0f711b1e504c3bc19b9ed1a07a3d612960f34275568897d7ef09027e806027a8914cf3787aacd5488358",
	        295
	);
}
static void snarf_hat_297(void) 
{
	snarf_construct_hat("/usr/bin/gcm-import",
	        "f0aa2abd31cda8d7a298dca69e30d6c365b30a863a690a5ad8683d51a3acff68077ae2515fba8328136908612600af078f350068ec2bf5f296eb77844f4d4a8e",
	        296
	);
}
static void snarf_hat_298(void) 
{
	snarf_construct_hat("/usr/bin/gcm-inspect",
	        "fd20c5d879f92e5d973e3d659cad1ced91c1e01440435af75c1bfd3d0a094ac70777c2d6ff83e1ff9905b17cdbe77da0b17aef9c5dc14f8c0d26e53b089f5b69",
	        297
	);
}
static void snarf_hat_299(void) 
{
	snarf_construct_hat("/usr/bin/gcm-picker",
	        "a1750b2735d349398ee29a0ff1d73e68cbd64f24f803447ba1a9b9bfe196f5449375261447371c3d180e17a810b0ae0cec03d8b3a3012e3d1c87ab17b37ede02",
	        298
	);
}
static void snarf_hat_300(void) 
{
	snarf_construct_hat("/usr/bin/gcm-viewer",
	        "1cbce44da2632651c11f5744d24e68dfdd6de38e923f3ce60da47b564354ce9275238be4edbd45702c4ddd71601b482a2fe2a69460efc5c5b73cb2511197d9d2",
	        299
	);
}
static void snarf_hat_301(void) 
{
	snarf_construct_hat("/usr/bin/gcov",
	        "af34bd86af31ff6941c309dc0837e05906d0729650a1c8c92a4f6ed7309192bd2f4907947a93ea3fdbbbb478cd73ef2a5bf2ff579b42bc36b5cd3d5795a14d1b",
	        300
	);
}
static void snarf_hat_302(void) 
{
	snarf_construct_hat("/usr/bin/gcov-dump",
	        "4800584d0c03bac356cd240072066b84506a310dee3cf140d420df024299e127ba259b303e6c98aafc43db55e6d05f8c9268688d37d043d9d7dba48439422809",
	        301
	);
}
static void snarf_hat_303(void) 
{
	snarf_construct_hat("/usr/bin/gcov-tool",
	        "a00c81490382b624b9f8ff430f2af799cc567ad8d3acdeb9ba7da5043c5e5cc50b77f174d9a2d5ec0b97e7486847791602743136679f5b65d3351853f44ee8b7",
	        302
	);
}
static void snarf_hat_304(void) 
{
	snarf_construct_hat("/usr/bin/gdk-pixbuf-query-loaders-64",
	        "43ad2629aa8bce8193682a34ff4de3c680a216a7b6b11bbba9f426940277c95a20d39c6af3a89b53414585b615d5f4a2d144f53c9db715047ba656519ee6c202",
	        303
	);
}
static void snarf_hat_305(void) 
{
	snarf_construct_hat("/usr/bin/gdk-pixbuf-thumbnailer",
	        "efc4d783f8643b261aae4f3ce4fadbd911f711d326389a655637d01fa033d919ee5a50451fc3fe3aabf2141f949084cae9ea95d53d897d213d4020e7da63748f",
	        304
	);
}
static void snarf_hat_306(void) 
{
	snarf_construct_hat("/usr/bin/genisoimage",
	        "15c4d7408124cef2387cb2ad3e7ac33c40b9aabe1b137fa38b2b91e3bfbe4efe255ce857f17689c2bf50f3780ec3a0c9341344da90ad6e5750cff35e1eb169c0",
	        305
	);
}
static void snarf_hat_307(void) 
{
	snarf_construct_hat("/usr/bin/genl-ctrl-list",
	        "dab5829b621cdb7c3ddb6cfd0c58173c8529a48577a2c22ebca8690352e42cb4ce6254392f970c7f5cf8c26a3dfece927ff2fb0f76fc0de81571c7f36d7dd487",
	        306
	);
}
static void snarf_hat_308(void) 
{
	snarf_construct_hat("/usr/bin/getfacl",
	        "df5e910ff0963d70171c5687f0b211815d5daf6da244564d3d377f0f67b35c3f53d70d9683baa4c6565c8239809ef0247eef839301a15e7a594ced3cb24ccc28",
	        307
	);
}
static void snarf_hat_309(void) 
{
	snarf_construct_hat("/usr/bin/getfattr",
	        "2fc34063ae2c4583f362159386dd345656c049ee757fe6bcf231db3e395e57c3ca07d0480af62665565fd3276cc363539af423a91a9785521ff84b7401d8555d",
	        308
	);
}
static void snarf_hat_310(void) 
{
	snarf_construct_hat("/usr/bin/gethostip",
	        "5027a3e5d34c07151631caffa21b5a41c2c7ba3b37b49d1ee415f77fb6e7192a055720e6efe123258acfb4dd47e0f1c4e7c1f4e34b96bbc723831aeab7b811c1",
	        309
	);
}
static void snarf_hat_311(void) 
{
	snarf_construct_hat("/usr/bin/getopt",
	        "0596c5200818c7bb6b75920a96942bd4da8d6782321e6d7a04f0c28a99678c57196298e43658633afc08f2ec0702ab438a41112a71aff54692ac530cc21123cf",
	        310
	);
}
static void snarf_hat_312(void) 
{
	snarf_construct_hat("/usr/bin/getopts",
	        "f522d5e01034c4debc781a48a09bf267f94a441bff4438982da5263781c26be896457bf9be5e208da3ea3bcbc67997922e52ef19424bb400f2451fbb3d42a0ca",
	        311
	);
}
static void snarf_hat_313(void) 
{
	snarf_construct_hat("/usr/bin/gettext",
	        "a04cfa772bcef69a07fc7ae6e65bf6df30350086f16e72f30ab9f175cc848eb1f788ef24d8446bc850adcb3045485a0ad7d383304f5b1f74e85f2d0261872b7a",
	        312
	);
}
static void snarf_hat_314(void) 
{
	snarf_construct_hat("/usr/bin/gettext.sh",
	        "13ffe268821d4f4f610c6095a624edd9ec3b19b6c08d28d1f3558b0a6e29cc0b79656dd2f3735f6dd75272d24d3b6e80e88f0598e1487adc12901f0f3d364f93",
	        313
	);
}
static void snarf_hat_315(void) 
{
	snarf_construct_hat("/usr/bin/gids-tool",
	        "ac3ca10973877a9490754378d130ed8220aea3859d28b155ed9c3138accbc04e900e4ae2796a848ac40758104336cc3e2fd06b14f3577177d322f96b09afb7fd",
	        314
	);
}
static void snarf_hat_316(void) 
{
	snarf_construct_hat("/usr/bin/gkbd-keyboard-display",
	        "6fdb3ae7e22f29f663c041de6644d5d6da8f6a7238ae88597af22dff192b0ea6d079d5336df5bca3ba3210d079c703c96bb2c028a26ae122ca443a6551e7c99e",
	        315
	);
}
static void snarf_hat_317(void) 
{
	snarf_construct_hat("/usr/bin/glxgears",
	        "96700452a9dc0cba6a8db23612e7fd288cee90c8f5866e75a1b74da07101ccf5864105057298f06e379f69bfa111aaffe25efa48de4e5786458c6d250ea627d2",
	        316
	);
}
static void snarf_hat_318(void) 
{
	snarf_construct_hat("/usr/bin/glxinfo",
	        "36207dc48af67d25f7646b5d49aadae4598c9dc04b2d29f64a0fcac657a8c7cc6a83b0a45eb3dcfbc23328ca29c0ea4511dc042972b3d2ed137fdf11d4a40a1a",
	        317
	);
}
static void snarf_hat_319(void) 
{
	snarf_construct_hat("/usr/bin/glxinfo64",
	        "b1997c0dc131441e480cc75911b4d2a6ad43d4ba83d383e236ff7f7de0dea906c418750bccf6178c91ceb25de67e1e3c25dd4df4767ee674b195c2c5d144a098",
	        318
	);
}
static void snarf_hat_320(void) 
{
	snarf_construct_hat("/usr/bin/gnome-abrt",
	        "4ba0fb0c58fc2519410184079517a2136a6ca87e00142c664f4c04995057dfec254267ecf007c69aa4b95634c50f520304404283589a59e5c7c6c4841e9fe64f",
	        319
	);
}
static void snarf_hat_321(void) 
{
	snarf_construct_hat("/usr/bin/gnome-boxes",
	        "b628d355603600152f281afd21ef4051057a62035c5a87e37afa832998affa39b08b296d5621b58120c03bcd28e7e9a518f8352f23c03fb8d2a049150593277c",
	        320
	);
}
static void snarf_hat_322(void) 
{
	snarf_construct_hat("/usr/bin/gnome-clocks",
	        "bbee1f3cbfe9f11e7051879a51542ee50506e18a86e583a0fc9421d6e5795e5960c202e47147495a7deb1938806bc96002dee9e8410edd21460078294c8a0cec",
	        321
	);
}
static void snarf_hat_323(void) 
{
	snarf_construct_hat("/usr/bin/gnome-logs",
	        "db591eaf1e5e2df38d72c0411e2c100118c7628471620860a9d4a2fa102214c44ebbc437fbe7113126fdead411fe870eadb2ed94e3ac865a5780cdb11891c2ab",
	        322
	);
}
static void snarf_hat_324(void) 
{
	snarf_construct_hat("/usr/bin/gnome-photos",
	        "912805a605079286ffc812d5a538d795492fa76705c071d4372bcb9d82684c72c8534fa91b043592dc5858d07982f9fec1a62ebc4b4253d4ef03b604ec521e81",
	        323
	);
}
static void snarf_hat_325(void) 
{
	snarf_construct_hat("/usr/bin/gnome-screenshot",
	        "fb4acd2a05f68af496cecffcfed293f7b2fd05c3fe597698318a68d853d0dbe8f3fa68a87f7e3a7aa502a7503c14cacba4d63e4a1dd9731b3fba8ef8f5669003",
	        324
	);
}
static void snarf_hat_326(void) 
{
	snarf_construct_hat("/usr/bin/gnome-tour",
	        "5bce4342971100f3d8faf872d3ff6be667cec21ca392acd1d9b6f0fc7d76a525fb89db92078075b1aa247efce3a9d2c2f57df7a9d5186460fa6547384deb61f8",
	        325
	);
}
static void snarf_hat_327(void) 
{
	snarf_construct_hat("/usr/bin/gnutls-cli",
	        "c98e60a710587872f8cbecc2ee2a943fae428c140e8ff122fb10258e3dbbbcf12162254b58c77949f8ea45f131e7754d3d5a252da99bcd9688c28296a553c396",
	        326
	);
}
static void snarf_hat_328(void) 
{
	snarf_construct_hat("/usr/bin/gnutls-cli-debug",
	        "c55a16034cd397c39ac339df35feb3c2de5e83d0b561b51f5a1a0649c2807c608e614c9f4180c7cc7fa14591061080bbd520f7750cbb0bf3f950f2c2a2f51fbf",
	        327
	);
}
static void snarf_hat_329(void) 
{
	snarf_construct_hat("/usr/bin/gnutls-serv",
	        "81e0cc648e9af0dc33b0afef8ab080a70f0f11f747f7aa26b7d540b0003c0099e4c68c62c637ea0570452f41e07e1e67f060f87aad4c98bccd63d7f29fdce765",
	        328
	);
}
static void snarf_hat_330(void) 
{
	snarf_construct_hat("/usr/bin/goid-tool",
	        "afa0ef74ae75fd38272086e08b8a01d5de59d93e37e23bc9b76f5b7e1083d99f891d38b935728d5051f6e729b59af8928f1831f85fa83bb0e0d774b78492ef05",
	        329
	);
}
static void snarf_hat_331(void) 
{
	snarf_construct_hat("/usr/bin/gpasswd",
	        "4d7c03eb7da4dbc757f013e293b112c8cac6d35741eac28f35b1200697acf80e144b104f7b9f668906a0375c8f25e41b2712c9f59fe7a8dc6ed85e2f2cf0cfae",
	        330
	);
}
static void snarf_hat_332(void) 
{
	snarf_construct_hat("/usr/bin/gpg-error",
	        "53db67cee0eb8194bdee7921bb30a4ec5efe1f6f83cb4068af4f4c22c2006978242c09689907785cc167fe8989bbb0e4b8202a74cc5ba1c59ed854a857b52ac6",
	        331
	);
}
static void snarf_hat_333(void) 
{
	snarf_construct_hat("/usr/bin/gpgme-json",
	        "beaa821dc38a4638ecd2f1c5c4c2f419aa6873efc55dcd06cf595e51f25d419517bd0afadbb73581492c28dae8f3e0727d5279f8b5670f67b73b1eebbee99467",
	        332
	);
}
static void snarf_hat_334(void) 
{
	snarf_construct_hat("/usr/bin/gr2fonttest",
	        "00be81d6862d90cfea548243786a3720b691b2cd764a09bd985143eb6bdb10c8bdbe293de64bc25743032ef9e0940b412a8c616e3ed5c886bc76efb24af8c449",
	        333
	);
}
static void snarf_hat_335(void) 
{
	snarf_construct_hat("/usr/bin/grep",
	        "da489e66efb8dd8a452a79302ce753f0dc5a51f021c6d1b2fb1ebcf6effdefbaf037d8a43733b6be2d6714a56b07985ae322bbab2e834c94f0c76f8e8d569331",
	        334
	);
}
static void snarf_hat_336(void) 
{
	snarf_construct_hat("/usr/bin/groff",
	        "822a05dc57b761837c9607162bfa370dff11d9182450a1b8560d161ab5e5fce34f7701a1f3370fe58cd784dd1480bacbd1d96e986661fc4cd9d8844e8c8efa25",
	        335
	);
}
static void snarf_hat_337(void) 
{
	snarf_construct_hat("/usr/bin/grops",
	        "4d5698d7814250fcac833c648779f213f3c2dc7c9a8c0bb265a860856d1db4ce24a9377629254fd4a0de12bf5841b8d4f2f8a82fccab7f04dc3ab7ad8368e762",
	        336
	);
}
static void snarf_hat_338(void) 
{
	snarf_construct_hat("/usr/bin/grotty",
	        "8e01a99d68b53950eab35fa7488d0697d0aadec430bdb8ff46f279a6dafb634ffc0c9b21f95d7f371256eab88ef61a591d4d1797807bf216b99062811ccc783b",
	        337
	);
}
static void snarf_hat_339(void) 
{
	snarf_construct_hat("/usr/bin/groups",
	        "9ec0df9edfbb04d6ec336038d41b461af6082871f0252a18b253163360fa3e1684600df43da002051866ab3a15a47b9fd1d7eb53f9a0ad34ddca052f06ee66f2",
	        338
	);
}
static void snarf_hat_340(void) 
{
	snarf_construct_hat("/usr/bin/gsf-office-thumbnailer",
	        "be81b838537ee5ce0f846dd883aa6f404839e46b17d35df02c6dee692c19573058f81c1ffc9473ec4af1a668d96a309c2ae6f2d4b1f13ac09cf58f4ed650028c",
	        339
	);
}
static void snarf_hat_341(void) 
{
	snarf_construct_hat("/usr/bin/gsound-play",
	        "d5ca155629eafb8cdf8fd72db713d9661c112e9dfa14839a139433a4e6853a7437ff61269e45d3b9515301570249dfed56dfdb2873b84786206547b5c34dae53",
	        340
	);
}
static void snarf_hat_342(void) 
{
	snarf_construct_hat("/usr/bin/gtf",
	        "2b020f90f4704ed4b747c8f31756c4383b3d91a73391aa803db67f13db8799cbb63ab28ae2b581727a3a677488494823e27ad58067f3a70c877e629b17831f32",
	        341
	);
}
static void snarf_hat_343(void) 
{
	snarf_construct_hat("/usr/bin/guild",
	        "0e852326d234c24c4860560adfceeabb85522248301b4ca199b2863f143d4c625508761272ebd4ac63faa3344eec24fbbc5e26f837e5d4c56a0612c858c019a9",
	        342
	);
}
static void snarf_hat_344(void) 
{
	snarf_construct_hat("/usr/bin/guild2.2",
	        "87704e55bd83f0e39e286f621272b3da177fbe6bbfaa84ddfa62ba765325590639acfc1e4c0580da3c87a0e2b56f99f1a259608b6fce9ad996547cdda487e3c7",
	        343
	);
}
static void snarf_hat_345(void) 
{
	snarf_construct_hat("/usr/bin/guile",
	        "778df3109426e29a24364be81ede530de1178d6c1c0f02abbaa27fa486d488f417817af1991082c732a3f78a9178428ea8a9ffd9efc87b5c535f0d91acfd0395",
	        344
	);
}
static void snarf_hat_346(void) 
{
	snarf_construct_hat("/usr/bin/guile2.2",
	        "8781fa830252a358975b201ee4b291ca6366f2f1397cf171de877cebd8e600e0b713c6976027e61d0677902d6b716dd530744d896de4e6b74f290b89243620d9",
	        345
	);
}
static void snarf_hat_347(void) 
{
	snarf_construct_hat("/usr/bin/gunzip",
	        "4d5c7e763121b89ebab996b9e74d1ed816083c6a03b075abe09755d870b62de6bc94cb03b01e0ed66ad7d2d997320b4d88c863beee5120e6aa83998898388539",
	        346
	);
}
static void snarf_hat_348(void) 
{
	snarf_construct_hat("/usr/bin/gzexe",
	        "8754af021831211ef192581beb50c39f58c246f4b2d18b6b6fb45605cf7f4fca740887db2333fc6842db5764fcfd425cc6be03d015eabb7803d6304a2f87188b",
	        347
	);
}
static void snarf_hat_349(void) 
{
	snarf_construct_hat("/usr/bin/gzip",
	        "a17bee1441eefc983fd212be611cbf5f942af4410fec37400e8340e2dbef0d19f273c7fe6f7c698513943857864a3c605d8010cd6ccafd833bdb96a7683314e7",
	        348
	);
}
static void snarf_hat_350(void) 
{
	snarf_construct_hat("/usr/bin/hangul",
	        "e3d8acaa4903562a1823f63b47b0bc199b5481b8469a1dd98554f2e7d5651802395e4f68a577b0416f303006a45d6defe45fb68c8e82d077c459331d55d3c05a",
	        349
	);
}
static void snarf_hat_351(void) 
{
	snarf_construct_hat("/usr/bin/hardlink",
	        "c6a0e1c2d3d70c9e18a1efbdcd12ed13383b3d5bad0b8d0af9cb80301b986363dd8d2006c5d4ada46a64058fd409bc5780e6772187c92f30a107384ec7b1701a",
	        350
	);
}
static void snarf_hat_352(void) 
{
	snarf_construct_hat("/usr/bin/hash",
	        "235e6383e2e2ac49f93d637ed0df41b83e84c48fd6a694ac88761c4d495ea7ce2f89ee8c899553bfefbd32a5c80c43097f7b0c34f3175e555be82fb69b2afd9c",
	        351
	);
}
static void snarf_hat_353(void) 
{
	snarf_construct_hat("/usr/bin/head",
	        "82dfb4918d93865bbd2bdc424725e7cdeb78655c28747a02929e94dbc474c54441457320a9b4a04c30e56fae89e3b7bbc302bfe73158bcb170ee10deac4a645d",
	        352
	);
}
static void snarf_hat_354(void) 
{
	snarf_construct_hat("/usr/bin/hexdump",
	        "5007fe8a02af0448f3b174c30e748b5a0b8cfcfca84a168a2a4a80a9dd6025648c5d984733985c9dec2e844a49791f78ad894d7cab02b1694fa7c4c82818a604",
	        353
	);
}
static void snarf_hat_355(void) 
{
	snarf_construct_hat("/usr/bin/hostid",
	        "52f1aea4846e85df73625ec83696da3e71204c53af59998d10c4daf7f1ec631d5ffe741049888c15e06bb106deca5bb77cd4138238eec07a235eb32ef881dfb7",
	        354
	);
}
static void snarf_hat_356(void) 
{
	snarf_construct_hat("/usr/bin/hostname",
	        "6fdb1688680f03502b46b278558fec7753771ef981ad467bcbf6794b2f2fff81f66c7dd51d307bf240f92e7d7bea76a0b68eda0d34c6952e1b2050325293f943",
	        355
	);
}
static void snarf_hat_357(void) 
{
	snarf_construct_hat("/usr/bin/hunspell",
	        "e91bf4f52075680996c99ccfd27329b914f0bc6edc9737cbc5d19edaba6b096b7622748da163eeeaeb121ffe6980305b70dd1df234be1eed8f18493777912e57",
	        356
	);
}
static void snarf_hat_358(void) 
{
	snarf_construct_hat("/usr/bin/iasecc-tool",
	        "91d92705b4b338af24f5eadae9bf59e7a49c7d5f745582b072ed93d2a82166e60648e621c672364528767cab58e4463cc0d5f817f312bbf85441ae4819eef46c",
	        357
	);
}
static void snarf_hat_359(void) 
{
	snarf_construct_hat("/usr/bin/id",
	        "e616c1ae9c9ac781925a82b5441e617e7b0a1c11a450e44cdbc2aef3c8c68a5f246956c6e58c940545070d473fc4cfa736eaad8519bca8d980ceaf0e7aac1b7b",
	        358
	);
}
static void snarf_hat_360(void) 
{
	snarf_construct_hat("/usr/bin/idiag-socket-details",
	        "368848b92fc409d363091d3895e463c8196179f4d62ddd80f270f8aa62bb4774fc4997243c7285b64cf18e7347ac240e196c1fb9331cf5b02dd17b8c2a8330e7",
	        359
	);
}
static void snarf_hat_361(void) 
{
	snarf_construct_hat("/usr/bin/iecset",
	        "5bc1850faf657b6ef3bc30951419f81b5024b4ac11726f8d93665911558972dfb202540dff8c87ff1be9667f3916ba1f1e538d3915690909f98ff704e0514db6",
	        360
	);
}
static void snarf_hat_362(void) 
{
	snarf_construct_hat("/usr/bin/implantisomd5",
	        "91f17a015041b6e820e1a6e38c00d4a811cde392f2a2535da6c44c43a84ac168290e5e519a9c98ab6624cfb2e5ba9e6e1bd93c6dc21f2144352d680dca762af6",
	        361
	);
}
static void snarf_hat_363(void) 
{
	snarf_construct_hat("/usr/bin/infocmp",
	        "063b42c3c4a7a046c34cabcc0772eeb85b3a62fb920e5c019dddf494940a9f25b586d0c32c43d88dfb13c6766e532f2f578a6a0279ba2050b3a2a524d3a9da58",
	        362
	);
}
static void snarf_hat_364(void) 
{
	snarf_construct_hat("/usr/bin/install",
	        "0c0f8fde2eaa1a7aa359d470f001f9aebe67a6f8935da031d5f1f0220005d42636af6c7f9280ffc9a436a59cc38c6994df5bbd82c95933ef183356980b06f525",
	        363
	);
}
static void snarf_hat_365(void) 
{
	snarf_construct_hat("/usr/bin/intel-virtual-output",
	        "0b91d0a77cb0d1443f3ea95733ed133bd48783c6e2c03c7d52e1765f52993a77776fa34616e5ca689b3d444e2ce8bcfb7248ad705386a36e29c67f90bb37b6ac",
	        364
	);
}
static void snarf_hat_366(void) 
{
	snarf_construct_hat("/usr/bin/ionice",
	        "f44d495f04cfeb4ab153aebde3697b2a2355ab52fa8e85d80e97c4831f2a0b17ff8cb07a719d739f86b53f1a84767a9e14874093cd701a1fde5cbadf5f072ee7",
	        365
	);
}
static void snarf_hat_367(void) 
{
	snarf_construct_hat("/usr/bin/ipcalc",
	        "502eabb1e14293c0b44f85ee62bb75d2f59a85a96736b5218a563c0c9c72fe92215b73eb05fb2f5832861139a5a38aada0dfcb88b155303d0d85f051f5156d3b",
	        366
	);
}
static void snarf_hat_368(void) 
{
	snarf_construct_hat("/usr/bin/ipcmk",
	        "942cfdb502ef14e2c0c71d7cf56e3d8a2d477cb72d6b37ab38e702aa379bb9ac473b6bff41fec689ee61aabd3f9c7dd27e6310fcbbecf9a5d0a2ea4b1e8bd473",
	        367
	);
}
static void snarf_hat_369(void) 
{
	snarf_construct_hat("/usr/bin/ipcrm",
	        "3409643f9f4bdc472cf41651cb90163d8d25e75c4661c153712ba6f84e0affc296ffc2cc60ae7b6637f3df2f5c7af5eb868ef7d82e69966e12e4f4c947467b8b",
	        368
	);
}
static void snarf_hat_370(void) 
{
	snarf_construct_hat("/usr/bin/ipcs",
	        "3973b6205c5d4aa1743855f51b6910d9c55e9190c9133e08555f0621167923414410c9e40e31b9a456460816ad600ba18a52f5ff3f4378528736c12a6e5873f4",
	        369
	);
}
static void snarf_hat_371(void) 
{
	snarf_construct_hat("/usr/bin/ipod-read-sysinfo-extended",
	        "ff52f4411915867cc26aff70a7dd0a2037600c730fc2cc32ccfaa05c6123bb6089d0f0c29a41709172a4ae2d2d2fc098f6ebc1f9f0f9adca2994fc8e03082440",
	        370
	);
}
static void snarf_hat_372(void) 
{
	snarf_construct_hat("/usr/bin/ippfind",
	        "723933e72d3958c5d7d7b0c0d7f5f26e1d2de3959d9f67b6c3fc3485760d813c6a2d52c8ad6973c922d5dd3eb43504f6bdc4f183d2203e0b52149cf1de541c13",
	        371
	);
}
static void snarf_hat_373(void) 
{
	snarf_construct_hat("/usr/bin/ipptool",
	        "2f58be4cce9bcfced43b99107323159f2cfe969d1ba0faf911b31cecf0b69d51a2c1af9fb0981bbd55c7f6576881abcfd62363d46ccc96e1c646c51800aadc1e",
	        372
	);
}
static void snarf_hat_374(void) 
{
	snarf_construct_hat("/usr/bin/iptc",
	        "e5b8fe4ba929934b944392a3b7c63a7d4ae6112dde3c8d19e0e094ed6846714a0417283687e812101249b29b393269d064ab6c881b6b432cb7f1ae004ae28fe9",
	        373
	);
}
static void snarf_hat_375(void) 
{
	snarf_construct_hat("/usr/bin/irqtop",
	        "ac4bb35f44f345e25bfc184588ffec64f17261fa77790b978c7112964af75b09d51c5712c4c80d88abf3417512e53cc685b831e28b49b04218f39226b7462b3f",
	        374
	);
}
static void snarf_hat_376(void) 
{
	snarf_construct_hat("/usr/bin/isdv4-serial-inputattach",
	        "a624952004f603e3a32237a91740f7dd84ae585e752a223be5dc8fc893386c62e17539290cb224f3c257429467bf0dfbe843a4275d0a5307d9cd47b93f679827",
	        375
	);
}
static void snarf_hat_377(void) 
{
	snarf_construct_hat("/usr/bin/iso-info",
	        "5c8a049014440d9379696dd79cee2cdf839ad820d910bc91eb65c43c4f625880d26aab1535226f1ed86aebde0d8d85071909c949ea854414708e5890e2c2324a",
	        376
	);
}
static void snarf_hat_378(void) 
{
	snarf_construct_hat("/usr/bin/iso-read",
	        "d39ba08556f7eabf377fcb09010264ec0867e3023e69983410cbb96689100d8bc32fa6e4c815425d4dd3f2e329fd89e2fa2b4d7ade426aea4d839003105d9336",
	        377
	);
}
static void snarf_hat_379(void) 
{
	snarf_construct_hat("/usr/bin/isodebug",
	        "800af11e32d599a9085f97b71789a3ad26d6c474d19538e2e02ef3d02ee9a5a628c2e2260dc5c35103a6390e6c2435d56c8ec0f537aea8e5e60b932eafa2f39b",
	        378
	);
}
static void snarf_hat_380(void) 
{
	snarf_construct_hat("/usr/bin/isodump",
	        "07374a3ef3d772f7c72b934cfd7f496d600c8099cd1f7381e154b3ffcd3a036be3a46a9a636f304e110c89e4198af941fa0c39e93a50e44bb49aa2a2e6c67092",
	        379
	);
}
static void snarf_hat_381(void) 
{
	snarf_construct_hat("/usr/bin/isohybrid",
	        "136fc58c01fb7572b81a0da899a57e4a068f6d2159de9824fa4b8ac416100192e7c21a7a01ce41a06466080fcbedd67e9e81ff7305d09859a89b4c2a613453cd",
	        380
	);
}
static void snarf_hat_382(void) 
{
	snarf_construct_hat("/usr/bin/isoinfo",
	        "e28f2fa3dccd447b8602ed21f368e979514fbc39d3e977f7a05fcb8929632bea311a357d67215089b60ae30c9c794883e6435c747da06449ada31befe3577a6e",
	        381
	);
}
static void snarf_hat_383(void) 
{
	snarf_construct_hat("/usr/bin/isosize",
	        "c3d70ef12482cadbb33e6cc1b8db9aa9c70087a9041e521a86f359384367469a4195f94adb11f65d958a9b4b782d81da7eb73e75017bae94ef85f6920cc14b3f",
	        382
	);
}
static void snarf_hat_384(void) 
{
	snarf_construct_hat("/usr/bin/isovfy",
	        "f83daa06a9e58ddf5f60119754d197cda5d6407f292b91d1588aa809b3a23460bbb9c281542ebe6c6965f48fda349b830c2027f5305d8c2af280f8f40b23ecac",
	        383
	);
}
static void snarf_hat_385(void) 
{
	snarf_construct_hat("/usr/bin/java2html",
	        "3f394e6bf5ee94629d8634380d5ddae96eca3605ffe878dde692d0c7a44bd44f8b7702a7309e77b6de9d3fe5cd43c32a84be7e5fc769e6e80d17695a2e447c16",
	        384
	);
}
static void snarf_hat_386(void) 
{
	snarf_construct_hat("/usr/bin/jcat-tool",
	        "b26ff815cdc2f13f62fb86da285548f7c5de9541ba33049246d0d60fef7e7a614f687d56913fa8344e183bc361aa3e53e15a1e38fa0e66e2401dd787954b1b0d",
	        385
	);
}
static void snarf_hat_387(void) 
{
	snarf_construct_hat("/usr/bin/jobs",
	        "3015582318c16670571bb639daa0e171cb099b5492089b09fab8c64ac95e5a3a7e99093900095f24858553d399157bdea73d697f5f48236350ab32f5951d2d80",
	        386
	);
}
static void snarf_hat_388(void) 
{
	snarf_construct_hat("/usr/bin/join",
	        "7d2f1cf5fa0992e5834b8091d2d07dd29f867726693cfbc09731b8914be487ba0155c3d6efe06968d6521e4f82973308fedd7e98ddde9716e01c64d9f30f6b75",
	        387
	);
}
static void snarf_hat_389(void) 
{
	snarf_construct_hat("/usr/bin/json_reformat",
	        "d9403d181d1ff2f402c3dc0e4197a96c09955c8ea800c1a8b767f52e14b86f99a181aa3c8841e36bc14e1d7a42419bc8a2968064d152efb4cce82d089ca72537",
	        388
	);
}
static void snarf_hat_390(void) 
{
	snarf_construct_hat("/usr/bin/json_verify",
	        "9030d2f55afd8a9c0dd200519a4eb8f915b3d663c0077fd2413c887fcb490c21fed0f78472b24495de806007bd4261d7faa92b10b626fa722a6db2e4957d586e",
	        389
	);
}
static void snarf_hat_391(void) 
{
	snarf_construct_hat("/usr/bin/jwhois",
	        "02381148ceae55185acdbbfeb2b6bdd5f1976e3c0d7f0f21aa69266d439b59eb1cdc4872a2fded2ccffe23aec339494c364d754b1a5b293bb9798f17acde5d34",
	        390
	);
}
static void snarf_hat_392(void) 
{
	snarf_construct_hat("/usr/bin/kasumi-unicode",
	        "3f1317cc2dc24c0d7e69a87902cacd39ec8784022df267a37945f821111361e7e6646cc9c3b87ff3359070b4f4b0f9b1b430dac86d5a99248db7db35396851d1",
	        391
	);
}
static void snarf_hat_393(void) 
{
	snarf_construct_hat("/usr/bin/kdumpctl",
	        "b59214890099e9b83b677401e741bb1a6a68636cccb9f02cf29c0cbe9b0760ca4b4f18bf60487d8f075f1a5d068f4d9ef869535bf6e4b4ea13872b2a43d81e38",
	        392
	);
}
static void snarf_hat_394(void) 
{
	snarf_construct_hat("/usr/bin/keyctl",
	        "55042d7ac9ebded57e5844a9e0b9e610ce8143555c81b3a313ecd17f1a3974bcd679ec1d304881e09f5f1153d6f87d22f6396b2b69efce046151087d328c37f7",
	        393
	);
}
static void snarf_hat_395(void) 
{
	snarf_construct_hat("/usr/bin/kill",
	        "bce9eebbf78f226823cce3673918d5b4f45cdc2a37ae60106e2d0ebe100397dc211bd4b33b944f016051e978aecc9b92ac1c0db646880c8c53ccb3ebfaa00c22",
	        394
	);
}
static void snarf_hat_396(void) 
{
	snarf_construct_hat("/usr/bin/killall",
	        "5fb1706db43a2aaaed87ad9da32a937d9fdae697b1581addae0cf20b71f197ccbab0e2c710c35595a5f0abf920ffbdbac837caacd667ef3492e3f825821575df",
	        395
	);
}
static void snarf_hat_397(void) 
{
	snarf_construct_hat("/usr/bin/kmod",
	        "e2a4098377a4c4000421a1084b8f61b677502b7a060bf4252b8c3e6b6bd58b29921f0f4d8bd06bfb1bc5806cfb0493b1698c208762f0aa0942c31da53ab7d32f",
	        396
	);
}
static void snarf_hat_398(void) 
{
	snarf_construct_hat("/usr/bin/last",
	        "cdd9ab93d8c53acecc8ad28c22a10e93abc26a5406a18fbba80935993f953996c88b92f2c429c41a968faeb0134b3232c1f55639dfe98ac3620d308eccdcee79",
	        397
	);
}
static void snarf_hat_399(void) 
{
	snarf_construct_hat("/usr/bin/lastcomm",
	        "53cc8c7a397ca807eeb6b45b39a02eaf320ec9c1a8107e159d00a9395783cab23efe9d07bb10c22d646530083431bc304aeda6fe4e89e71bbdc638362f35499f",
	        398
	);
}
static void snarf_hat_400(void) 
{
	snarf_construct_hat("/usr/bin/lastlog",
	        "cecfd02a7bf0b9e9a7e1e668da8ae79b8a46463d030b674d413b148b0c9d0258fe2451123d2ce322eac302c5f261f803d9f83c18a2c30fb6ce65f847440c5708",
	        399
	);
}
static void snarf_hat_401(void) 
{
	snarf_construct_hat("/usr/bin/lchfn",
	        "09fcd9b3cd58b894b92c43e0b64a15778adabee1088316d9c00e84654178e44bb0636cafd9f1f67074a6efbce5dab79c2591aea997019be94e85ff5bec4bd71d",
	        400
	);
}
static void snarf_hat_402(void) 
{
	snarf_construct_hat("/usr/bin/lchsh",
	        "4c6aad84b9f8dcbe1944731ad6c89165698b11a51b8e4ad006c76d530230aa364188b34730313ba2a8d04bd7b73e191abe93a297d967b4e2bbeab0fc8de56354",
	        401
	);
}
static void snarf_hat_403(void) 
{
	snarf_construct_hat("/usr/bin/less",
	        "126aa131057fad2702f04275465a0b16055219784ead65475a62cbc7c10fcd2c4f2ef0fb5939b4ecb2636d9caf91a3d1256dca4323ebe143c56b19acd622ed81",
	        402
	);
}
static void snarf_hat_404(void) 
{
	snarf_construct_hat("/usr/bin/lessecho",
	        "f463e6f5985d82614f53894e6803c967b20e89a79dd5855aadcd7f8775aecc34d365b2f36f7d8f9aeb2cdabe96af642dbf7d405ae9cf45e42c76ee019bc1035c",
	        403
	);
}
static void snarf_hat_405(void) 
{
	snarf_construct_hat("/usr/bin/lesskey",
	        "482d7fef6574e5948dca448f85402788256db06c8350a57e77a97703d7602e8cdbe4f4171d04319b56ff5e2040ef521ce060f5b699d539ec817d01664d44e07f",
	        404
	);
}
static void snarf_hat_406(void) 
{
	snarf_construct_hat("/usr/bin/lesspipe.sh",
	        "a2bfe15a0b8a0a803a05aa6756170421f300470d03d11baba27e6fc32d3699f2a994b3fdfe45024898a8689b0bbbc7c2aa03b6e8892e3aa0627ec52397e9817b",
	        405
	);
}
static void snarf_hat_407(void) 
{
	snarf_construct_hat("/usr/bin/lexgrog",
	        "2c4564a55fba89931a4cd7acafcd3f46f803e476191c200ebe4371175616b899418542fb909498fe579284c9417308924497f827a220988a983c57a21acf8377",
	        406
	);
}
static void snarf_hat_408(void) 
{
	snarf_construct_hat("/usr/bin/libgtop_daemon2",
	        "70aca34252c32e1ae661b06116bac519c7b62b18e23710be9f3ceee6ca78635e76114556dd383ac01b76700bb27610de23ff24991fc94f91d3967da826fb043a",
	        407
	);
}
static void snarf_hat_409(void) 
{
	snarf_construct_hat("/usr/bin/libgtop_server2",
	        "f09ba6660c798d07d2a086d23cd84200fca89aff550eba0811ac44ab02ceba3f770b411f5cc94e31ae3922036e23a5341fb4fc3cf1b0742ceea178788024c034",
	        408
	);
}
static void snarf_hat_410(void) 
{
	snarf_construct_hat("/usr/bin/libieee1284_test",
	        "e86aae2eca2acb5fa2b51c52897dbca84051406aad94e46e7426b0494b96c0215850d0ef4dac9b22179d63d43b5c430e4d1e38afeede73ecae3c37bf7379382d",
	        409
	);
}
static void snarf_hat_411(void) 
{
	snarf_construct_hat("/usr/bin/lilv-bench",
	        "d35e07aee8fc205f68af9251c1a88531f1f60f5efb53485e7572e6806b0680c7cd7f01531ab3cecaea93f812d8fbafc95c23cfa70dd2323fe4bb1e48905dfbf7",
	        410
	);
}
static void snarf_hat_412(void) 
{
	snarf_construct_hat("/usr/bin/link",
	        "980015c916b16b17faa22c515227cab0f9d458c34711d5218338f474824fca0c3791dc4eb1c5cb499d3f26f13db8d14d9c980032765a62efe916b8a3af7fff72",
	        411
	);
}
static void snarf_hat_413(void) 
{
	snarf_construct_hat("/usr/bin/linux-boot-prober",
	        "b433baba438b1bd8798d70973f3641f83f8018949e8f717213eb613476aedb4651ad44818c769c7c77565846dacbe5b4a12fa4ec84f8f029fd962239d75bfa6b",
	        412
	);
}
static void snarf_hat_414(void) 
{
	snarf_construct_hat("/usr/bin/ln",
	        "20d57ff970272a7404d14e6f7d063994c278681682c73a8ab8683d6d2536e44625e0a8703380ad7536616eeb4d996abdbb05b19011dd3a5b356e86859d33e238",
	        413
	);
}
static void snarf_hat_415(void) 
{
	snarf_construct_hat("/usr/bin/logger",
	        "d4622a23559598bc39cc9ae9a9f10a3644d3caae735edc27ffdad682d37cfbadecd462ec23685fa04c496d5fc61e75b51cb27a849e8a434115484f0fe1a51c38",
	        414
	);
}
static void snarf_hat_416(void) 
{
	snarf_construct_hat("/usr/bin/login",
	        "9e90b8405e0767ba49196e3c12a3ebb4f3b9d783247087ce338b471f304d4efa7a2668a2d4ec1920306cd8552b2081d954937ecc2c331c06cefcae1c6d1df00b",
	        415
	);
}
static void snarf_hat_417(void) 
{
	snarf_construct_hat("/usr/bin/logname",
	        "9ff923f6492359f4a8b0958f5cf763770e852a658b64e9ecb016bdf127ed7e7f7f859dde8385f57a3bf3971aea8c0623484dec2b1ba72e59f6ecae3010c7715a",
	        416
	);
}
static void snarf_hat_418(void) 
{
	snarf_construct_hat("/usr/bin/look",
	        "f1babc1acec8d7aaceb7aea1257d048fd0caf809cc2064e49114c5ba51b8eabc70fa80185450dbda4ed75659a2e043f2a726b271d83f8694d70c8053ef98ffbf",
	        417
	);
}
static void snarf_hat_419(void) 
{
	snarf_construct_hat("/usr/bin/lp.cups",
	        "d14f578bb6f6e58a5a0fc89d92a806eb4294d6c0c6d2213adcbd48289829ca3f2bc48e4e032eb2baa6183c374c521673dac77b937625b311f5918e7304a5737f",
	        418
	);
}
static void snarf_hat_420(void) 
{
	snarf_construct_hat("/usr/bin/lp_solve",
	        "92c3dc1710fbb25d9962f1fe3382b8cc3245eb0bd24ec460399bf17539b59320eee1531cca3e553a17722853eebeb62986791eb919d4bca44aa82db11ce12381",
	        419
	);
}
static void snarf_hat_421(void) 
{
	snarf_construct_hat("/usr/bin/lpoptions",
	        "545d0fe719b69be7daa35f215e2a8e1b53681986c13b0b0f3c069eec108324db53c8b31511a113bc5daebd30a4f16adad89b98b7cb3d9349bcb7a96c4ee23d1a",
	        420
	);
}
static void snarf_hat_422(void) 
{
	snarf_construct_hat("/usr/bin/lpq.cups",
	        "3f0e163b7b4736df83c606714c3d6f1d3373b511ea07996184ca40ac0efb478dbcfa41537cb0e05e806860e872c66e2ca414efa33cf3f03bb8ee69a96c1b1d2a",
	        421
	);
}
static void snarf_hat_423(void) 
{
	snarf_construct_hat("/usr/bin/lpr.cups",
	        "70cfa5d0ad3c0dc67b8117a0bb25579dc8d141a2b72f5e74f222246dbde342b689e35d904713c7e4e199fde9739f2d15c48c5ec041c6a368a401e9840a72f225",
	        422
	);
}
static void snarf_hat_424(void) 
{
	snarf_construct_hat("/usr/bin/lprm.cups",
	        "463308e71f789fb80423a7a74c2f52b8b31a7e8b8b8218025005ffba01695dabe2a3ac6a99a90837cbbb73bddcbcedc46cb9fa331785d2bd066bb3d6b040da88",
	        423
	);
}
static void snarf_hat_425(void) 
{
	snarf_construct_hat("/usr/bin/lpstat.cups",
	        "9fac0b4a6d5a3b9ca27e72fb5d5761c29f1297936df6822f64e282a18e08879cbcf6a57b5ad6ecbedaf07d2845171179cd196178733da5b4d1071e6cf0f9e27c",
	        424
	);
}
static void snarf_hat_426(void) 
{
	snarf_construct_hat("/usr/bin/ls",
	        "db63e32135f087504df7fc34e9085c411195b99f3fef8df68178761481a3da7dd944a0791bfb5097a7dd82249bb2acb0b0daea1d1f4107a840452da1296001bf",
	        425
	);
}
static void snarf_hat_427(void) 
{
	snarf_construct_hat("/usr/bin/lsattr",
	        "589bc96c3f890b3fd6e4d985ac1fd9915dedadf81638d70fca96228642fb99a79fab05c678c2578944740670ef6f1edba19f69ce93125d08409b69a58640a14e",
	        426
	);
}
static void snarf_hat_428(void) 
{
	snarf_construct_hat("/usr/bin/lsblk",
	        "f782297f3cdb8efc93adcf2d430c7a599d4b37f28364a2cb80deab9d969394454cb2d50f279a01feb303a153b045e9234488f27db4f3135ab40cf7d0116d8298",
	        427
	);
}
static void snarf_hat_429(void) 
{
	snarf_construct_hat("/usr/bin/lscpu",
	        "cddf112723c30381c9ed00d412a96fd4c8162a16a2d1f0a7d88e3da4406bc01f7e6444a2760433cd2ae8ad959d2ec5fa752f8f3127ef6419e28805512bc320c8",
	        428
	);
}
static void snarf_hat_430(void) 
{
	snarf_construct_hat("/usr/bin/lsipc",
	        "bb2153348c246888d47add703b3b4e62fa899ff7aae88f2d381c42c097cde147396acd2179c7309825854ba5a10f3403394dd116896c682f066539fcdca0b152",
	        429
	);
}
static void snarf_hat_431(void) 
{
	snarf_construct_hat("/usr/bin/lsirq",
	        "e0cece01e57e99e2e280f769265843b1486e8ee4daeab1cba77b63ccb816ecdd7376d1061b36f2bd6830f8632bb1c1f393f7f71724a31c0e9c14b90035932547",
	        430
	);
}
static void snarf_hat_432(void) 
{
	snarf_construct_hat("/usr/bin/lslocks",
	        "cee8397cd0e8f4513e624f2824955bf4d235d7b46d1588b2f228aae88e411989bfe9beb7b84bbd27ae55ca6f952d5e00150331cbbb495558f2f2e9fb21fc2675",
	        431
	);
}
static void snarf_hat_433(void) 
{
	snarf_construct_hat("/usr/bin/lslogins",
	        "183b27a4caafcaa7a93db5a752705812e829a7ffc06d33c8aebcb95a1ca3032485b2964a959d833f0132c453da473b288878327a903e32114ee825c939cc0218",
	        432
	);
}
static void snarf_hat_434(void) 
{
	snarf_construct_hat("/usr/bin/lsmem",
	        "2b9470d853eb6c6617e52ffbffc307a4a3838daa141010665c9e625cf4d4ffe5592047c65eebaa352d9f32431984d93db6fe6e17275ac743a790439a090c8001",
	        433
	);
}
static void snarf_hat_435(void) 
{
	snarf_construct_hat("/usr/bin/lsns",
	        "f9aa3b2e95966850fcf64f83c0f2d806ef8b556bb0fd3af7d0a74feea1110ecefa9b13a41a4f8d5ed6857e7e22e1acb913fd51165def442e343f72d97b4aca87",
	        434
	);
}
static void snarf_hat_436(void) 
{
	snarf_construct_hat("/usr/bin/lsof",
	        "5cf5f226b8fa32e33360de471c9c912fcd6decd84df9edeb9d75805fbb3de1a4d9b7a34ad1c078989efd50062571b9797d4a63f72b0dcc3b77df5f7095d0e134",
	        435
	);
}
static void snarf_hat_437(void) 
{
	snarf_construct_hat("/usr/bin/lsusb",
	        "940c61a42baa7af8a3fee20e106abc288ff6ed2ac992e06d7f6ec2db76d9928f834b3875135d7dcb4a3872c9ecd92465c3ff507debd059c438253ddd420c56f9",
	        436
	);
}
static void snarf_hat_438(void) 
{
	snarf_construct_hat("/usr/bin/lsusb.py",
	        "803f015ff0f17dcd63a0b19bb1787cf1443490cb08635ed5dc01778b346d484efc413e5c29043e10cae159b1e03d6d6c6c075c1325b1da90c5f174cea9d2f1d0",
	        437
	);
}
static void snarf_hat_439(void) 
{
	snarf_construct_hat("/usr/bin/lto-dump",
	        "2d3434deb1d54892f77a9817e13c5b2fd248939dc184d632c61c14ee5688468f56a9f015ecbaefe81b27bb16b2db69ea34b7884b532111c48b398a6b34bfdfd6",
	        438
	);
}
static void snarf_hat_440(void) 
{
	snarf_construct_hat("/usr/bin/lua",
	        "73819150742fdf695e48bb306dd9d9c347e200d962bec084560c6ac7a112c951ed2781031855d6f1b6d17e4a2dccc7548465666e3c47b0dd8342f273e281484e",
	        439
	);
}
static void snarf_hat_441(void) 
{
	snarf_construct_hat("/usr/bin/luac",
	        "1e3f12214009aeda928fe97f18fc11304faecc4429198a2b469557ec9a98969ec168e69ffec30858c453d4a0602fe97c15a7ec709682c3cfd1816cce599a890c",
	        440
	);
}
static void snarf_hat_442(void) 
{
	snarf_construct_hat("/usr/bin/lv2apply",
	        "8945fa1ab3addcc5281aff4128c2b725d45176d196a85fb117ed422e379de1ca2c04fab2f42ebcf915ab741ab78119852f8094cf7e34b2229cb797dfd79a7680",
	        441
	);
}
static void snarf_hat_443(void) 
{
	snarf_construct_hat("/usr/bin/lv2bench",
	        "d9982432dc1a85c92d43ab1fe699c9158551835af2bd13fb004cbecd7e5f027e624afad9e8411caef87046a180b2a5d8f06786c4d0893aef11dd031c277743be",
	        442
	);
}
static void snarf_hat_444(void) 
{
	snarf_construct_hat("/usr/bin/lv2info",
	        "ed35a82d67c3ea89e197c94f1077534f6fc7d9e4462386dd211be3538a474d1236de113d508e906400f5bce7de59f50feba2eeabc31852f30a4575d1f73a546d",
	        443
	);
}
static void snarf_hat_445(void) 
{
	snarf_construct_hat("/usr/bin/lv2ls",
	        "fb876e627846ba24f0e1480649a0bc3280480a5f20fbb001d42042dec31e3de534e52bd08e9914cb73a6f4df3ec5e7a1b6108f6d629fbcc59d817bb6ffc74142",
	        444
	);
}
static void snarf_hat_446(void) 
{
	snarf_construct_hat("/usr/bin/lzop",
	        "7335ad2caa9aeefe367a6642379f4e1c435ef0222f897a6d668b1321ede98235e0fc7e9d6c2d4ed5376e37cdca1457242fe77f7cec8080de554fee6096dc7c4d",
	        445
	);
}
static void snarf_hat_447(void) 
{
	snarf_construct_hat("/usr/bin/m17n-conv",
	        "982d1b6fcb326e259f7917314fa26a0dd8d0db6b20cf8877a36f48b4284b31b28aff464a895e2c7506355978edd25ca411cfa7c6a8431510f71aae212b01014d",
	        446
	);
}
static void snarf_hat_448(void) 
{
	snarf_construct_hat("/usr/bin/make",
	        "76d79fee7093db3302cd15ea0f7f870e34cf7afd9f5c19a2e517daad87567271d8b9a59f9e4da00804a449790be9c3735a1f0bcc0bc321d862959d6dff1256f9",
	        447
	);
}
static void snarf_hat_449(void) 
{
	snarf_construct_hat("/usr/bin/makedeltarpm",
	        "245bb00606e97e7133f021d666c469104bd3dc818fe8638300075c1c8d6ad8109d749ac429114b0f7ebd3c5df91667d67dd72220db0c001e31dd6b45dbd93fcf",
	        448
	);
}
static void snarf_hat_450(void) 
{
	snarf_construct_hat("/usr/bin/mako-render-3.10",
	        "8b04c00f3cf9ab0b813df4161d05da94bbe88ad420898bb7b1aae5bc5b3f3df7d510a20186714fadeaefa44a5b46c08b37167d540f4a5c1ba46f30dac3815be1",
	        449
	);
}
static void snarf_hat_451(void) 
{
	snarf_construct_hat("/usr/bin/man-recode",
	        "bf7baf7122449153024c91c02c148509b5bab1d799f896cfedc029d9f64e1c20a234350d5c9cb4ac0721cf7d6022980dc5fffddbeac2165b39d433c1ec0c6817",
	        450
	);
}
static void snarf_hat_452(void) 
{
	snarf_construct_hat("/usr/bin/man.man-db",
	        "eac25857fa27d5ff4708542ae7e8a38ab07a2be3320cb9e4104436e3d9a948f2372a0132ffa62205e64bc4930da35b906a8a1f709001a361ffb8e1045c953706",
	        451
	);
}
static void snarf_hat_453(void) 
{
	snarf_construct_hat("/usr/bin/mandb",
	        "a729d36302c026674bf32a1ea083c419d85a3fcb066df8ff59f4a966c213fec8353ea06dc1c461912891ab6f4fc7e800c7000a07a7d8c17b9a1ebe56a25ad6c4",
	        452
	);
}
static void snarf_hat_454(void) 
{
	snarf_construct_hat("/usr/bin/manpath",
	        "7a0549dc77ba6987ec99ceaf052500e0b96b01b7530365bbb1b8901a720aa1ee9be25f5023d5fc6a8f8e12d18ea4514beb8922e83c03b611ffba1925669be8f6",
	        453
	);
}
static void snarf_hat_455(void) 
{
	snarf_construct_hat("/usr/bin/mbim-network",
	        "ee20a3e66256a260f04b674d676a382eb4d6f2228daec49e8eccbb8e3644c945b1ed4e90737aa9faa094a5b5ed0e6d68d6807f237187ddfcf064332025ec3343",
	        454
	);
}
static void snarf_hat_456(void) 
{
	snarf_construct_hat("/usr/bin/mbimcli",
	        "acd7446627944333628dba072f8ab83b6966754fbb41be6ff4b3dd4797e780f4498fe9f03c2ea1af8ec09d614e0502ac2632dddf2480bc6458d739986fd6a255",
	        455
	);
}
static void snarf_hat_457(void) 
{
	snarf_construct_hat("/usr/bin/mcheck",
	        "93e30d28b2ffdb3e066b4acf99a0ef8f437c66bf63d48530a1ab4ae54ba5f96f1bd3b9e397ecdaa97156e2e93b7ec6681956e62df52816e6f86876d92fc9041e",
	        456
	);
}
static void snarf_hat_458(void) 
{
	snarf_construct_hat("/usr/bin/mcomp",
	        "4bdea9790dfa4a93ca7d995ff2c8b1aba5f26547fb970fae3b013c98b70ef2d65594bc2b631a7ffcea5a411bf72b61a06eed061f8df180abca119a7a2286c836",
	        457
	);
}
static void snarf_hat_459(void) 
{
	snarf_construct_hat("/usr/bin/mcookie",
	        "e3c69b24e14be73a523fc87df9577bcd174b5821a2209e182c1d8ce23a00344a127e75b9a4f1fc8935a735846da56a557cfb326c31e0ae9946f0fc833c485938",
	        458
	);
}
static void snarf_hat_460(void) 
{
	snarf_construct_hat("/usr/bin/md5sum",
	        "6aca3fd087ea4f58b89f1f5a6901bc2bdf10ffff8edaa011746963034786996e68333ce68b6d527e88cc04b3f61ef400917ef6bc487935ca31fb7d9a54e33cac",
	        459
	);
}
static void snarf_hat_461(void) 
{
	snarf_construct_hat("/usr/bin/memdiskfind",
	        "a7ae3375ab54857ba9c45ee56b3a97dbe75ef1c8763285009c5c177df60599ce91a6088d348f400731d0b1506f290b2525697d5e09e133a35009609aeeec5887",
	        460
	);
}
static void snarf_hat_462(void) 
{
	snarf_construct_hat("/usr/bin/memstrack",
	        "b9ddc84089a8718d85a27bc3b5f07df9f8f9d8a441cabe9090b5f30b8c8c9561c808c3c406a5f38ffc3e0f5bbcbcb72a0b72408d7313dc076ff47f9e061ef7dc",
	        461
	);
}
static void snarf_hat_463(void) 
{
	snarf_construct_hat("/usr/bin/mesg",
	        "78f6f52378a7e408959260d9acc2b2e2d161fca1f3197e60b98b1d3785b3973054d561ce4cceb2c50646330858ea6be5c1255fe41d6761c424a44563a7dcf6fe",
	        462
	);
}
static void snarf_hat_464(void) 
{
	snarf_construct_hat("/usr/bin/mkdir",
	        "543d844d92c2b1720cf97625633d0514961388d9817ab2ba6e268044ecb4174859403949acc83072e8aee16fa66aa84b6c9a30a40279138e5d7806fc5e6af3b5",
	        463
	);
}
static void snarf_hat_465(void) 
{
	snarf_construct_hat("/usr/bin/mkfifo",
	        "95d524dc11f134f3c9d8c4977fc9663e8e72ab40b4f2470ed536acc01381e2d75a0cc8076cf509c5f959e46240f2bb5fa2c377cf63d4cbb06f7bd2f66b24322d",
	        464
	);
}
static void snarf_hat_466(void) 
{
	snarf_construct_hat("/usr/bin/mkmanifest",
	        "9f01ef16629a93c46f0681ab54d6a2ef233b8012da2bf3760f180bd743724dfbe4979068b0dc280859e60947f293bdc9a80daf4646e23c5b5695f0604470128c",
	        465
	);
}
static void snarf_hat_467(void) 
{
	snarf_construct_hat("/usr/bin/mknod",
	        "15743d75ae57d66b05f68d70ffa49dba2faee4330cc86d0c76f0f4d4db72b9082ccbd2e5d7793e52e9f22a1fb43fa58eb60b9ca5d282af698a425aeb4329fcd7",
	        466
	);
}
static void snarf_hat_468(void) 
{
	snarf_construct_hat("/usr/bin/mkpasswd",
	        "63021e71fffd3ff08da410122d618d249906fcdd7fc03638047237360511df40aa1914e5d23f878b79fc1beadb503ec02836161aefd70aa83516aa54513114dc",
	        467
	);
}
static void snarf_hat_469(void) 
{
	snarf_construct_hat("/usr/bin/mktemp",
	        "c7008937bc4f38ab069f0917304ca73965f895abdca86cdb98ab79552794926c45b544a556ff093a4a977488e41ac0903ddcc6a1bb59898f31e98ab7491c2826",
	        468
	);
}
static void snarf_hat_470(void) 
{
	snarf_construct_hat("/usr/bin/mmc-tool",
	        "a228dc593b861ffea938ee15a1a166526a84a1e9ac81b449c97409a4f129d1748ca5fefc4360d78956d2c8b46de8270d6c8b85003ee15983ef3fd0d188d70000",
	        469
	);
}
static void snarf_hat_471(void) 
{
	snarf_construct_hat("/usr/bin/mmdblookup",
	        "9af5a97e77847b0479c2de2447f396a14143c5876292c20d49a73d6661cb32ad863c392b5c5252e510c4902a03ef0e30e61127ecf2c50dfecf0317749dc17f0a",
	        470
	);
}
static void snarf_hat_472(void) 
{
	snarf_construct_hat("/usr/bin/mokutil",
	        "b6ed2dcf5d00afdff8f7aa7efccd10d9ac8c42a2ffd1ca9a13e3113c979a42c5e28b3eb294a668f99feea00c19e3b76acc955aa7074717a7fb1a62885011da75",
	        471
	);
}
static void snarf_hat_473(void) 
{
	snarf_construct_hat("/usr/bin/monitor-sensor",
	        "5fc57e9fa9320d552986be3257759572d2a80e3017c126186720cb746720b81aeb05a9cb1b69dd8e3d20d4c9bb98e6aa78e501a1655e0c52c1e8e2aa651ed4f0",
	        472
	);
}
static void snarf_hat_474(void) 
{
	snarf_construct_hat("/usr/bin/more",
	        "e0e56be100796a620d8fcfad23f83f2f3a77d53e3b523387c0f6b54b8f54d343c416701300e0828dcb12871697bc4f8bfce40815e5a5098971fb93646fc2696f",
	        473
	);
}
static void snarf_hat_475(void) 
{
	snarf_construct_hat("/usr/bin/mount",
	        "d2385caade1cd9d90e6ab7a265d6f9fdd459fd9b05eee2703006ba6e6eebd50be2c1c8464c739e363c4fd867af3df3e5987644507c1725fa6ab0588152b526dc",
	        474
	);
}
static void snarf_hat_476(void) 
{
	snarf_construct_hat("/usr/bin/mountpoint",
	        "40555af78924a0c7d20e30768d254b04a140bcbae6abb0f3cedf089543394db90a01641587f7ab5a534c204ea25bfa76ec7f787c4ae0bfcfc4e72e04663a18d7",
	        475
	);
}
static void snarf_hat_477(void) 
{
	snarf_construct_hat("/usr/bin/mpage",
	        "81d6117b00ffe5394c0eed472b9b800fc1da47f17e251dd613adfbd3223bc46a1e9869f65c43253bd3f9d48c0e6ba1d87f52daac7da2471bd502e636d6ebd00c",
	        476
	);
}
static void snarf_hat_478(void) 
{
	snarf_construct_hat("/usr/bin/msgattrib",
	        "751bda8d4dff76e5489d651f2c2b00781696d5e00eb71099285f2690d5e618a0b736c692f604ca2ec5b06504d0bcb001f4022d3ea665e64cf911dbfa2f023b3c",
	        477
	);
}
static void snarf_hat_479(void) 
{
	snarf_construct_hat("/usr/bin/msgcat",
	        "629e8e25725f6b7dd595589434123718fefa0baa510d46223ac467f3c4dc80fdad9ea6d9e8a17a2a3cb33037a53e92aca3f1a31eec930a18e52153b90f800b5c",
	        478
	);
}
static void snarf_hat_480(void) 
{
	snarf_construct_hat("/usr/bin/msgcmp",
	        "6642532919cc69a0176556b92e99fca8d79265d4d5976087ba821eb272dc967c84929c23f5f5ba299149445407292fc7aa38efee1418399bf527a39ec3f41515",
	        479
	);
}
static void snarf_hat_481(void) 
{
	snarf_construct_hat("/usr/bin/msgcomm",
	        "f0e4fb90a31d1c140be5e02e9f8bca95f3ddd52caf2a4ba15dfa78ec9d4c3bc379acb9f961bc09ddccec7e63d7b4be810aaa7bbe4426ec1ad02dcad0f2174364",
	        480
	);
}
static void snarf_hat_482(void) 
{
	snarf_construct_hat("/usr/bin/msgconv",
	        "6c163e53936b6f23dbc7d82121ad8b8d90d0433a2d484616d523638c712d94132918f07f6bc6e88341cc9da79b321a8a73fdb56bf73741fffb922a3f527891f2",
	        481
	);
}
static void snarf_hat_483(void) 
{
	snarf_construct_hat("/usr/bin/msgen",
	        "471ca73c87b537c4ac0e6c644544f24ac5878780c4e498e444e71ec798a175e30120138f4a105361f6f5b4671fd6dd76ac5d8be2104e1776e28a433a4fde0319",
	        482
	);
}
static void snarf_hat_484(void) 
{
	snarf_construct_hat("/usr/bin/msgexec",
	        "718d5f4016c25928ef81b0d9eb71080a1cd8c8e5545c35967c709f342895a13a60f88be497965309a36ace8ca05ae921227ffa3851eb39abfeaceedc10919be3",
	        483
	);
}
static void snarf_hat_485(void) 
{
	snarf_construct_hat("/usr/bin/msgfilter",
	        "088e52f4f2c6b69e2ff7f2623d4c68662cb060943ebfeedfaa10747275c956589f00a1357b6737bb55e1491ae16db423feec0b08e2a49d25dc2b4768332b70e6",
	        484
	);
}
static void snarf_hat_486(void) 
{
	snarf_construct_hat("/usr/bin/msgfmt",
	        "07b29c335d83f65f3dcf60fbde34e20bea27800b5006e0aca15556adf29f22dfb292cb7bf323ce8d121109c80b5326f1ad3cebf4d4ba24decdf25c0dabc24101",
	        485
	);
}
static void snarf_hat_487(void) 
{
	snarf_construct_hat("/usr/bin/msggrep",
	        "eadc90d8c45cb9b7fb4c633bce5be4b6291409e46f0fbdf316bc8fff731c030e1e14cd7369459ed98136c7ced5eacf45a06b4f9b43d5bb80380a49b9dbe034f4",
	        486
	);
}
static void snarf_hat_488(void) 
{
	snarf_construct_hat("/usr/bin/msginit",
	        "9dc87c538988ab9e99082402925864829fd39f015563d73787becf5559da4b144acba2cca1c24c4cd3e9182fc4c5b6be3b931b9767b034378327a70e9255d08e",
	        487
	);
}
static void snarf_hat_489(void) 
{
	snarf_construct_hat("/usr/bin/msgmerge",
	        "db4ea6ecbffcb2d319131c3fa2b054221a88d312fcf5d7e8542d0762196781a776e16c2713f264e1b35dcb8ea88e8126d024e6e7a4e3728dee699d56a5023b80",
	        488
	);
}
static void snarf_hat_490(void) 
{
	snarf_construct_hat("/usr/bin/msgunfmt",
	        "2ddc06c47bee72fb58dac38b9f1ce50966c6796d1d7064807dd04b6ef07d52af9c03d9a20f048024a78f5e225a5f4b6120599829cc2084220a7271cdc4218873",
	        489
	);
}
static void snarf_hat_491(void) 
{
	snarf_construct_hat("/usr/bin/msguniq",
	        "d00ff84dac2ab7e8f5e6b920bcfe355b0acb8d4f861105e0097aa83dba22f31ea6e54602064426e76c017c02baafa0a911e56413e5e6fa897bd25cba414c0b6d",
	        490
	);
}
static void snarf_hat_492(void) 
{
	snarf_construct_hat("/usr/bin/mtools",
	        "e1d13558f8e12b405fb92fc55822f9b6f292909039e0e0637b80ff2ce85122421402bf05c7683d6c1f1ed84155a0612a31e264c623247cf6f403180341b55fcf",
	        491
	);
}
static void snarf_hat_493(void) 
{
	snarf_construct_hat("/usr/bin/mv",
	        "485fe074af48a7743a960cc8890aca402de0c48e677dd6dabb40c861a5c43444dad0b4b57a76c61a065316eb5cbd0669319e613a0f991d55cc0a52b4996b0124",
	        492
	);
}
static void snarf_hat_494(void) 
{
	snarf_construct_hat("/usr/bin/mxtar",
	        "806ae4d51287c80f93827370f9293a4ec59cf06e6ecb96af2c82147e9a379766c0f735e583b775c30522293a232e2a83a26ceab2205929fd70649901bac86e60",
	        493
	);
}
static void snarf_hat_495(void) 
{
	snarf_construct_hat("/usr/bin/namei",
	        "56b45d2c0a72d02c667f03ae62b89fc910ada4ac736b3ce30df9b787cdf3434e5981f5026474cb2adc85312c2895f98fabca02fd5218b646ef7c6491fd1a7241",
	        494
	);
}
static void snarf_hat_496(void) 
{
	snarf_construct_hat("/usr/bin/nano",
	        "3fe3c7fd4a49aca6a460ff26e5d30e609430da8a39833b351987325aa80fd7035f2a4ed105d88bc9b8bb4b386a7cab4ede360dd724eb97ac12baa49b8746582d",
	        495
	);
}
static void snarf_hat_497(void) 
{
	snarf_construct_hat("/usr/bin/ncat",
	        "0d8b570cf0234e7bc0355cf84beb93561277c063a9ae9e0b2ced13501d9fd3ab195094c53eed95178acc561d97fe854e712f1c3eeb5708aee21f5652db1a6e7f",
	        496
	);
}
static void snarf_hat_498(void) 
{
	snarf_construct_hat("/usr/bin/ndctl",
	        "6d6901cac5d85d735c430c068bc3b598c5c11a5bc3a4bd5bd441df9477a1b3557a83b00d2e241a118bd894a1fac222fa3b43be4dd8dccdcbf4ae4a759671b4f7",
	        497
	);
}
static void snarf_hat_499(void) 
{
	snarf_construct_hat("/usr/bin/ndptool",
	        "2015a55d93c9deec7de95e608710bbbe3d2b798c915f2082414f93eac0f749b2a30129024e62584f3975f46a6820727c66ea1ef15223a2d9048e70ac58f31b75",
	        498
	);
}
static void snarf_hat_500(void) 
{
	snarf_construct_hat("/usr/bin/neqn",
	        "d2536df72bc32d4cafc2daab499080d3ecef6e50058fa7d3e616f27bcd55788cdf0ca3018ce44d5aa05e97db39430f8e12fd8e71837e5825a4dc6626ff3b40d5",
	        499
	);
}
static void snarf_hat_501(void) 
{
	snarf_construct_hat("/usr/bin/netkey-tool",
	        "d8266906912b6a59ec4802a36dcad387279e9ac7bb338d21a8127e0522382dde5b93a06e59b783be1fa3729900b8ade77b182bb81f2c1bca71543953ba00dd19",
	        500
	);
}
static void snarf_hat_502(void) 
{
	snarf_construct_hat("/usr/bin/netstat",
	        "ddb961660fd6fa066a9e7ffacca80381fb5264b85143054da2345e36e6c81762e96a2c40fcc96204c43c46e60c34f962d8693be5f67f6cd099f9d15f56f30d38",
	        501
	);
}
static void snarf_hat_503(void) 
{
	snarf_construct_hat("/usr/bin/newgidmap",
	        "611944734455d8797478235b5bfe64e9f12ea894d1a9f466198aeadaf95f1df07e714d974894784f7b74b907e039361f9f63995e5e02eaa75fabd42da3f6f5ea",
	        502
	);
}
static void snarf_hat_504(void) 
{
	snarf_construct_hat("/usr/bin/newgrp",
	        "59220a27f24ef77d56c88f40654730a62f3b3ac089c6c1b93fad79f48e7d45400f154055efba5ef54486f8a516b7beec47bb4e149ed2cadf12d06548e231e1ff",
	        503
	);
}
static void snarf_hat_505(void) 
{
	snarf_construct_hat("/usr/bin/newuidmap",
	        "997059239e7fff17b562272aca0b9d5323170e7b9f59a2e5283f9201b38f5d9fd5419b9c0795de36cbfc4d204ceb3d2a6fa6e2ca20b58331385e0832554b4639",
	        504
	);
}
static void snarf_hat_506(void) 
{
	snarf_construct_hat("/usr/bin/nf-ct-add",
	        "afa1dd9cc8b99b6e2089aa726b8ec79f547cf5ae139030e30e73d6f1fc4250815462006f567a109f1f4f82ebcce92bfa4b7566955a9bce3ccb5263ca88ded8cb",
	        505
	);
}
static void snarf_hat_507(void) 
{
	snarf_construct_hat("/usr/bin/nf-ct-events",
	        "0cc00fb1b5a756ad70b10d1d6c20e60b49ab763a9a61164efe0cdd426be3e8d7b2c92123278a1b9535f947d89460dc5cbaca608bc6cf8e578d5bbfbc8380ffed",
	        506
	);
}
static void snarf_hat_508(void) 
{
	snarf_construct_hat("/usr/bin/nf-ct-list",
	        "b766b5160db5283c92a208c96fe2b5a9f75f22fdb915d013f09d59d7b6f48c7528d3316baf7e11dd196d507a238a3baedd38476ca0b17b83871b8a28ac8f6742",
	        507
	);
}
static void snarf_hat_509(void) 
{
	snarf_construct_hat("/usr/bin/nf-exp-add",
	        "16e9f8a2ec86c1f41bdce70b5e1698e520f574f6f91771f2a5e836027d0fc7f6dfedc0ee15d80747828e5e3dfdc65ab6624d97e5f929978572f044a4c7c5652e",
	        508
	);
}
static void snarf_hat_510(void) 
{
	snarf_construct_hat("/usr/bin/nf-exp-delete",
	        "53b7ac107a9f4e9f72a720c600ab6a38c394582713d40a6f9eab2cacf3e3593699fd2d5adb5ada99125fb04781387b01a92507c2f3a74da2343d237c32e75c3f",
	        509
	);
}
static void snarf_hat_511(void) 
{
	snarf_construct_hat("/usr/bin/nf-exp-list",
	        "e2a27bf57cacaed2ad36f6f7f7ea6898faeef1b17d302413eda03a3f1a871f0de3246c5d6d16f88f9395002d9a470fb85dc4499d04ef64c0da1232d5a663e858",
	        510
	);
}
static void snarf_hat_512(void) 
{
	snarf_construct_hat("/usr/bin/nf-log",
	        "8437125fbf25e29fac0d184c5053cb57139e7c2e91b5ba1ae4b96f906924f43879ae081927c871f7296ebacd0e3fcdd90ba5286da3308488eb370ad45faa31d3",
	        511
	);
}
static void snarf_hat_513(void) 
{
	snarf_construct_hat("/usr/bin/nf-monitor",
	        "bfbbe5296e327e74cedd524207d7ea1f74c419ebb901961b9f8c5b6b3e31005aeaad192ee59becbe1e0223d2c7139aee50d0069c77d14eb697f13afd8754725f",
	        512
	);
}
static void snarf_hat_514(void) 
{
	snarf_construct_hat("/usr/bin/nf-queue",
	        "4758bae2b0c3daf7330a5597937c614f679bbc35be802fca775820179532f4c0bd979f525f5e5e0f7be7dfc1b52e6c9289caf1b866a118f3ad24c553e19fa993",
	        513
	);
}
static void snarf_hat_515(void) 
{
	snarf_construct_hat("/usr/bin/ngettext",
	        "dacbe359a3152197b3a4b6eb502950afd8b45da6e00be580888d2bd97d405178d1f1921543349147fad6100415f32321e90d81cf6583fbf5a4dbe33e84bc217d",
	        514
	);
}
static void snarf_hat_516(void) 
{
	snarf_construct_hat("/usr/bin/nice",
	        "583df87d9731148ac9789fccd297da174fa413725f9aacc39ca097b97c342f95f72157ed9ea920df77aa86ce93eea44f210c523417cae367486a33066aa4739e",
	        515
	);
}
static void snarf_hat_517(void) 
{
	snarf_construct_hat("/usr/bin/nl",
	        "380d58b42ea4edc5fd729ea9f4251adc884ea5097813d6b731f34df855e416d952f02d566decb89dfec362c26adef9136aa1dddb82fcea7ee635f654bfcfa52d",
	        516
	);
}
static void snarf_hat_518(void) 
{
	snarf_construct_hat("/usr/bin/nl-addr-add",
	        "059f13272f0801163846b837851aab121ed4b3555e9ad800a3af3be87a067fca51bf5592a0524283c63cffc031645fc3802c26c001b175479a5681b55029d9f4",
	        517
	);
}
static void snarf_hat_519(void) 
{
	snarf_construct_hat("/usr/bin/nl-addr-delete",
	        "1b6ad7f28814a65f1f17dce53876aa3c8f879507c020256e6536dd98b122d10d5891a8b8f9a2fd6b9bb3c358684eee9c45dc48b0974000181fd770f65a8cab9f",
	        518
	);
}
static void snarf_hat_520(void) 
{
	snarf_construct_hat("/usr/bin/nl-addr-list",
	        "ce747d6ca947e9081512b9f752bafe2c79dadd4138f0afd6425cf3e5514c03899b836e04760db0835b53ec23a7f6dbb79aa61bcfc73923bd6e52e6d81c16aaba",
	        519
	);
}
static void snarf_hat_521(void) 
{
	snarf_construct_hat("/usr/bin/nl-class-add",
	        "bd3744e75c0b80e42667c9c8228aa1e64054b6bc845cb7dc0ece8c0a7403c0b6bdd518f4c4da19ece4456380dbc29a74dbd29bdb4274ebaee51a14583027fe02",
	        520
	);
}
static void snarf_hat_522(void) 
{
	snarf_construct_hat("/usr/bin/nl-class-delete",
	        "ca81c853c441d71d5d84edc17aa7824d6944f2dc97e3ecb237ef9bcc15229c34c22391e1120a5a9755dc51e360a5e4fe6c6380f876717bce19f7d82780a95e2b",
	        521
	);
}
static void snarf_hat_523(void) 
{
	snarf_construct_hat("/usr/bin/nl-class-list",
	        "8211665766e69e35ce42e3c6c94ac5d6ad819d720f7f2ac5e6793b083560cc09e04c743f66ec75a8b66f2af4e2b65efb081b2416c8b21f2fe6c1a7429b9efd49",
	        522
	);
}
static void snarf_hat_524(void) 
{
	snarf_construct_hat("/usr/bin/nl-classid-lookup",
	        "695f1d0ca792f49eec75c4893bdc00ef8cccddb8da9df65e5f7f2d021e74a0b3c0572c46cdfed9217db079ccf10fa9929d56701e8d981508f1340b75bca00b7d",
	        523
	);
}
static void snarf_hat_525(void) 
{
	snarf_construct_hat("/usr/bin/nl-cls-add",
	        "a632891cd9d0362acf13786bd500c6ebb60bd68e09a8f77fcd8fd55d8c9d55b466a062bbd538372d6536a3df000722f30d9589303be4cd2900d847be2d83beb5",
	        524
	);
}
static void snarf_hat_526(void) 
{
	snarf_construct_hat("/usr/bin/nl-cls-delete",
	        "ffa0214d8c42407d689c0d56b64faa5be6e2225a16dc39eefa0482ef5257f2983fe662daced18f12edc1b3202cdf2708679f3491daba6719753754c45df5a3f8",
	        525
	);
}
static void snarf_hat_527(void) 
{
	snarf_construct_hat("/usr/bin/nl-cls-list",
	        "44286982331a63f29656a52f27ccdadefaaa4b507f06fd6936924fdea02a4280c28e103423be10519c1eebfee82c6168f45032ec8739f329d0be66eff1d06f19",
	        526
	);
}
static void snarf_hat_528(void) 
{
	snarf_construct_hat("/usr/bin/nl-fib-lookup",
	        "2b8cf4bf2486ecf38da43c8772961be33f4af656fbc29ca2a0403d831b7a1c606fc54c33b0a89ded90a6a77f774644e89cfcdbfc5916d8bab4919a33f461323d",
	        527
	);
}
static void snarf_hat_529(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-enslave",
	        "99d720678e751f9c915710ddf90658f18109c02a4cdfde4c6d4b501cdc02915599043f39c7945497c3f334a440881c7562b1b7ff6e4dbaf0a64078e2dbfabd71",
	        528
	);
}
static void snarf_hat_530(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-ifindex2name",
	        "d4b09b7a21c3584546cd539ebee80987ae92044a75a227faf638b365a96847a8302f148b1fab16dddbe9ec213579296947060b8b2470f19575dfd4373fb5f057",
	        529
	);
}
static void snarf_hat_531(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-list",
	        "57d7579c81fc1e083c504f2a1fd7fc3303ffe3500e7cab1114271fa93aecac0b8b7dcc235b3869dcbaeef71239c5eb5ac1d20eeaba13479aa6f5a88eb204547d",
	        530
	);
}
static void snarf_hat_532(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-name2ifindex",
	        "7b7806cf37c6216dbd81b7d0aea27c55f4146197cf532496c9ed84bb18cdc6fb1b98733b81b9eaa75f14fe9c519b9188ceda70fd496e7c59dcc848e7a03337ae",
	        531
	);
}
static void snarf_hat_533(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-release",
	        "ea94e715bdd6d4265a95aeac8c570d43ea273f78ca4a7ce37a99ad10746440063b1560acdc4e8e3db98f34b021542788464302dfa5b71181a51cbaabfa159f8d",
	        532
	);
}
static void snarf_hat_534(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-set",
	        "739865a8ce8ab3de41d9156ed4fa919c041ece9cd09fd1c57050d016ee12851e865aa7d97a8708193c5cbc272fec44b8706730eac3d67cfb3a22da02961e3159",
	        533
	);
}
static void snarf_hat_535(void) 
{
	snarf_construct_hat("/usr/bin/nl-link-stats",
	        "495a9ea3d783b7151b55cf0bbde87e4f5f1bf8eb96d188bea8c47f746c7f09c24135ee8f9af465d1403657eb6b1520953c99b707d21301ceb44b3a4648e946ff",
	        534
	);
}
static void snarf_hat_536(void) 
{
	snarf_construct_hat("/usr/bin/nl-list-caches",
	        "fc4d7cc90315083bdeffaf50c199dd083bb41850e6c14cb626eae433c63ed91f035476cb6fe80b36128f439077b0dffef6173a60a98f5642ae44269672e9065c",
	        535
	);
}
static void snarf_hat_537(void) 
{
	snarf_construct_hat("/usr/bin/nl-list-sockets",
	        "73e683275f52c4add69a32a053e2ee2081835f2a5b77176c518a246a787b9a232b13ccd99abf70859ccee04b8fcc7f5250ce409b8c76f6841563c5f53a518563",
	        536
	);
}
static void snarf_hat_538(void) 
{
	snarf_construct_hat("/usr/bin/nl-monitor",
	        "0b956518c4fabc019f79ef3723d9acd226ae3f56fffff631f44f12160c7f581f5ce8740beb4566bb0ebc7bb80b126993f566b0d27495fd2ae017043911d3699d",
	        537
	);
}
static void snarf_hat_539(void) 
{
	snarf_construct_hat("/usr/bin/nl-neigh-add",
	        "ad6fa3abd99d877dd3028c3e2a8033fd3fe91659e414a50666c3423fbb8f37435c6936aef95f64897f7733030866b1fd5d5b2cbe72017bde233d4556da025254",
	        538
	);
}
static void snarf_hat_540(void) 
{
	snarf_construct_hat("/usr/bin/nl-neigh-delete",
	        "bcd21a181ca0b182350129aba90d23ad8f6d1233546877568afe9d1c3a39060ffac00edf7cefd413aa788715da5d8811f60f998734e22a8fd4dc3a9d0c43022e",
	        539
	);
}
static void snarf_hat_541(void) 
{
	snarf_construct_hat("/usr/bin/nl-neigh-list",
	        "672ab8ae08a9f9e2d0fa0defe74254f2333bc710161bfb3c671b2d20f3b6bd652460810d10ecb89ed6f0397610c83f0bb799b8c6cd730cc824d9a188ca232f00",
	        540
	);
}
static void snarf_hat_542(void) 
{
	snarf_construct_hat("/usr/bin/nl-neightbl-list",
	        "63adff27d2328cb1f20269f0ef0f9549d2faa4705385a3d7c81b89384f37555834c88a81340e4cf10eec38bd874f5a0340bf5ea8d15d4453650d2e18adca6746",
	        541
	);
}
static void snarf_hat_543(void) 
{
	snarf_construct_hat("/usr/bin/nl-pktloc-lookup",
	        "9c5789b6b6df69ce32d0813353ae0ded455193b4e3e168c9e4125dfd232ade3c76628503958423626e4c7aa9d3c4cf09459fc3924cb9582d86cf7dea01328f9e",
	        542
	);
}
static void snarf_hat_544(void) 
{
	snarf_construct_hat("/usr/bin/nl-qdisc-add",
	        "8b52850ad82ee97bf1a7837fee8ccd667066a92c9d821a451890123b0347d2ba6eba931f35957b65dfb83bce68b1a5658db5be4b338a0224585e50b5febc8d93",
	        543
	);
}
static void snarf_hat_545(void) 
{
	snarf_construct_hat("/usr/bin/nl-qdisc-delete",
	        "a5dd64b10a919212938c2f66d5a923243c8e924fa22f3de8b86580b90bac64435fe08cbd5471800edd6bd4b5c9928e30856855ec81ae2a4e0468ef5a24b89c91",
	        544
	);
}
static void snarf_hat_546(void) 
{
	snarf_construct_hat("/usr/bin/nl-qdisc-list",
	        "8320f67e9355a95097ed4e81ddcf7408039d4bfdbe6eaf6447a396f054fed07a0aafdc524060493a0c11f3aa198713ae2fb6e1e819dd456f5ddbf67ecd259fc4",
	        545
	);
}
static void snarf_hat_547(void) 
{
	snarf_construct_hat("/usr/bin/nl-route-add",
	        "75fad668979f047e4a8c62babb985dbae5c8071915cfa006b97ad0a2e2c6b3c541d60eae3eebf93410e921d58de48fd8ef85da80042da7931454e159b842bb7b",
	        546
	);
}
static void snarf_hat_548(void) 
{
	snarf_construct_hat("/usr/bin/nl-route-delete",
	        "86cffb76d68b487c0866230e1c91d83eb9d13682b755056cc78c28da3a292b6fabc968dfe5a4fa632a3fd98d00b92054ea3d833a759edfe155865df0c2396de8",
	        547
	);
}
static void snarf_hat_549(void) 
{
	snarf_construct_hat("/usr/bin/nl-route-get",
	        "5e1e24c24e2b373e06ea610fddd03d04b35b027cec041d39e0f2fe66d9c5384efc40f2d62564661cd30f2e96d3a7fe8230ee5d0947f2d4ce890dae1f8d5c51af",
	        548
	);
}
static void snarf_hat_550(void) 
{
	snarf_construct_hat("/usr/bin/nl-route-list",
	        "def3f4e5d87bcda0b57416310cc1c9fbc78cfcc54cd6452bb18d126a62802d1781989db2e376a96cb70e623fa8b9f1baf4b0d96b666e155d7996bb72895932e1",
	        549
	);
}
static void snarf_hat_551(void) 
{
	snarf_construct_hat("/usr/bin/nl-rule-list",
	        "99c45f1a5a411d8777c6eaa846e90a064cfdf3c9ba4e5fa03a3f0d76436c7fe484834bcfad018024c669cacd7579cd0fa7cde4a43f33accbf6be6d2b6b623c99",
	        550
	);
}
static void snarf_hat_552(void) 
{
	snarf_construct_hat("/usr/bin/nl-tctree-list",
	        "e7793ff661b94dd5cff2a99d72063077b37fbd32ba6c739b02d513a3362549acb8cf45a6b6a5d5b0a7cb07483859af129ba8c3224b90ffa0a6b066919f982115",
	        551
	);
}
static void snarf_hat_553(void) 
{
	snarf_construct_hat("/usr/bin/nl-util-addr",
	        "490b790cef96891d14400e2b256065ce5dea5462582e3879a0f2cbec9f44b9025d143d3441899589bc56246a38db5ebfe414ba27c91e34e2a86337e8939b3989",
	        552
	);
}
static void snarf_hat_554(void) 
{
	snarf_construct_hat("/usr/bin/nm-connection-editor",
	        "976c71c69c6c571d77af67018b666c5b1a117ec9ea78157c8811ee848f8df9d6b7cc238db55addac198261cccc9dc328878183c795609652c64666612aaca033",
	        553
	);
}
static void snarf_hat_555(void) 
{
	snarf_construct_hat("/usr/bin/nohup",
	        "46a9eee1fa4a5c5e0220c9a1f4c507958982e879b0cc794d5667053c77d75b343d8fe2db392c3a4d14c9ba24b1ad00af5b9dcd8bd08ae2331632a94e136656cf",
	        554
	);
}
static void snarf_hat_556(void) 
{
	snarf_construct_hat("/usr/bin/normalizer",
	        "8692f0b8b80e12ba189c7d8214c045900156299912d6f77e407bdc0de56b2164a3b86a4caf9e0ffe41145bcb5c893c88a7b86fab6a35374574198bed434036fb",
	        555
	);
}
static void snarf_hat_557(void) 
{
	snarf_construct_hat("/usr/bin/notify-send",
	        "281d596f8fde82143de249d0f51425084c48eb75de75041fada4d732298952a244edc7af9c7126cb7ddded2148a79bb4496798f4f8a68c779e27df01afae3d91",
	        556
	);
}
static void snarf_hat_558(void) 
{
	snarf_construct_hat("/usr/bin/nproc",
	        "41c2926bb2db390ac5f1c6450bb4c5d50fe83a50085b555d470b7508ddd3fb4442d1bf944a81f1e9db4cc555b18e9e1495f29f2dbdf608defc4e27668bebd1de",
	        557
	);
}
static void snarf_hat_559(void) 
{
	snarf_construct_hat("/usr/bin/nroff",
	        "a77683b29a39769e19f6eec6bbb3e1f6c047e132a834e3decea05ad22edf8aa703243a0e75ad0d0237f0ab48def8e978d34c656cddeadad9c9b9d54e654626fc",
	        558
	);
}
static void snarf_hat_560(void) 
{
	snarf_construct_hat("/usr/bin/nsenter",
	        "94a29d6364ca34deba1ca5c7fefd2e4670edfe94f29fae7ad9c85ede7f98fce02cc7aed49b64e9ea3d92ecfb4f57927832a360a719d858e46b464a378bca3c89",
	        559
	);
}
static void snarf_hat_561(void) 
{
	snarf_construct_hat("/usr/bin/numad",
	        "9351fc23528ed0441c92c97ead98bad9a0603a4a34449378cca406c9aa848a19beda2fa5e9efaf8037ffa8a250eb0b827d3ec421b3c0b63be020a8345cfd805f",
	        560
	);
}
static void snarf_hat_562(void) 
{
	snarf_construct_hat("/usr/bin/numfmt",
	        "a5e9f74a4112f76562c7909256bd88214a107c231f0f40bd2c578e27b5845d7270c9e51134d6209348aed08671b08755d0d3c26ad16632ef5e3ec9b5497e51d1",
	        561
	);
}
static void snarf_hat_563(void) 
{
	snarf_construct_hat("/usr/bin/ocsptool",
	        "ed72478421573ee455d25b1566feb7a8da6a00890f27edb80ecf27ad1256d33174c50ab019221c9cd07ed3b4d76b997a878f65c7fe509e8d1d0d962944d0075d",
	        562
	);
}
static void snarf_hat_564(void) 
{
	snarf_construct_hat("/usr/bin/od",
	        "2e98e1de7cec965fdc57e614d30c2a867ef66cc01b6b956b8ef4b25594ca82edf112143b96931e679e0e5e9efe560dbde0bccee6111e902da3a1fc0d88758d2e",
	        563
	);
}
static void snarf_hat_565(void) 
{
	snarf_construct_hat("/usr/bin/openpgp-tool",
	        "544cce3f0ac22e87bd6013a2f018d39c71d2e21eb9984f14f875324d4a5e1e6d54d9105f1bb2f31f3c6bc665330c139507de8620c73290f8dc423599764b107a",
	        564
	);
}
static void snarf_hat_566(void) 
{
	snarf_construct_hat("/usr/bin/opensc-asn1",
	        "6a20e3db398acf57492cd7b2a9c9ee1c869d7074268c8c09e5371e0e9bb0f8b805408b460214e416647975455cc4f0b43414a6f743189c096622094c36c50be4",
	        565
	);
}
static void snarf_hat_567(void) 
{
	snarf_construct_hat("/usr/bin/opensc-explorer",
	        "60c70b41252d197bec420e649bfeca541f6c807f5d2c73a31d0b3b2995c89a9e3ed89470cbad7f380a7a7977d08eedb6ddbe4790871d0dc3c3a96308ef0f3041",
	        566
	);
}
static void snarf_hat_568(void) 
{
	snarf_construct_hat("/usr/bin/opensc-tool",
	        "ab402e02940aacf7417cad1aaa0df8ac746b99be255e84d30c8e7bf85f1a0441d7e042b4be12f9b515d25b90706cc2de03364f16c2b285b97e761ea7ee61ddc4",
	        567
	);
}
static void snarf_hat_569(void) 
{
	snarf_construct_hat("/usr/bin/optscript",
	        "3175d563728dd1850dce8ebcaf493e65828aaf1fb6c6d3415de4033cb6912b441ba5a84b31e2d5fd2242e23a9ade9703043a3c13a1b388e9cd84e6d460bf6da5",
	        568
	);
}
static void snarf_hat_570(void) 
{
	snarf_construct_hat("/usr/bin/orc-bugreport",
	        "bf449570cd903d5014e5db0d2fcd91902e43188a5c122df0b93f990d29af115242b933b3b1af3dc5173b25fde9cf491e6da1fcfc2a0c972fbb5f47fd5d96bf8d",
	        569
	);
}
static void snarf_hat_571(void) 
{
	snarf_construct_hat("/usr/bin/os-prober",
	        "3c63622cad0df69cf5c7405e49fbe57e9726cde2a488b0e9c3b0d94faee198b4f36c439fce3855300e7c4040d24e78f0ac1dbf1909e772f05facf60433d644c5",
	        570
	);
}
static void snarf_hat_572(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-db-export",
	        "efb9e999c8538452c84c02d08e4f6b7502144b843620b3f6321b3ad66f138de928bba3765bcaa01b6d59d1f14b2ed53a525f0da3b07932c882e8f55a78c932c6",
	        571
	);
}
static void snarf_hat_573(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-db-import",
	        "8ff5a9173f2aaf8809b481adecfd03a716a1f327078f14d8edd6c4e2dab31babf22a78289e522a5fdf322f797cbc8c1489e2b516f7ba86f5bf102d22a2edd5b1",
	        572
	);
}
static void snarf_hat_574(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-db-path",
	        "fd1292ac2b472620f032cae94dd8f3b029a17b620cac5acc1fcbf8552bc656ea8658375695199d34438ab94a8dd10c02c4ee9784c47e14644af7214b9134793f",
	        573
	);
}
static void snarf_hat_575(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-db-validate",
	        "633b787c8c9d711f96c7a6690f4e7d34d6f79d0a21e32555778e5512636a5fc9decda980672c5446b10b011ec844544e662469744a31f6befc86c713052f8e2a",
	        574
	);
}
static void snarf_hat_576(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-detect",
	        "16139c20600ef48d6cbc94b2d6af59a9d51b2f49f8cf3608a7e455cad0b4ca58f1464c6d650f98d2912c7bd4d79c13c98f75c45e387b3e2eb896f075a5a2c728",
	        575
	);
}
static void snarf_hat_577(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-install-script",
	        "1729c4c42c68b40b4a67b0872b947364ae1ba325c6f48e2c1fc6293be27a1ef6c264f9e0c08d71e2df8d26b1638cffc8945f271641b9248eb801f47b5d3e241c",
	        576
	);
}
static void snarf_hat_578(void) 
{
	snarf_construct_hat("/usr/bin/osinfo-query",
	        "39fb4cbe535ce61078f614bfbb4370f1ed502c313072d92fb05e4b7a76834832b9794512f4bdc49d8c675aff531a8b122d1b3c02c693e9d489274fd448df5f6a",
	        577
	);
}
static void snarf_hat_579(void) 
{
	snarf_construct_hat("/usr/bin/p11-kit",
	        "341ad362e80fc85327551dccd11a6a7af9db39e88e49f8e07d3bc298691b61fdaaf06906dcc217be3a829d9dda3ddd4da31fb64ca8ccb032257bfa03584d35a9",
	        578
	);
}
static void snarf_hat_580(void) 
{
	snarf_construct_hat("/usr/bin/p11tool",
	        "91ed07043c354e404c66811ed9adc4fd0c241b7846d2df2f5597707a8904a2e51d37a0210549299d9181fb432079a8494f43419c93e60dc7a9f3dd161d75e062",
	        579
	);
}
static void snarf_hat_581(void) 
{
	snarf_construct_hat("/usr/bin/pango-list",
	        "26ca8f7f7da77954b94bea1c0c93840a4e73d179b9757a18956ead0aeb6d92000a46714dd9b64ae2c757d8a754c765fcd584121720a143671e71e281c391d209",
	        580
	);
}
static void snarf_hat_582(void) 
{
	snarf_construct_hat("/usr/bin/pango-segmentation",
	        "5e0d5d6f2af46bbb0e1e07172b46bcacea74974da2e0fe4fca03ed0e56ea75a905d71584b0ecf5adda86d9114c88590efe90c044e6f2ccf1eb38ba2d0f57e2aa",
	        581
	);
}
static void snarf_hat_583(void) 
{
	snarf_construct_hat("/usr/bin/pango-view",
	        "76f9118f0b965eed9318c91aacc15a733b57c902aa8e0fbbd4e574619df009886ad8acdf2f80299c9658ecfb9eb4498b15eecebf3e9da98cbd3c74c6955c3f31",
	        582
	);
}
static void snarf_hat_584(void) 
{
	snarf_construct_hat("/usr/bin/paperconf",
	        "bd6abf3d68ab019458d23d3fdd6d41e1e63dd436a9118abf0ece3ce12e7998c8d6b842306c8c3f85a94b6288ca9b401e8a161170d5ba9aa3c265e30579125947",
	        583
	);
}
static void snarf_hat_585(void) 
{
	snarf_construct_hat("/usr/bin/paps",
	        "548a9a2d77e525a0ffe44767a716fe47b14f7100bc9c52d0748f1fed5f4bd5f5ca836b522e5e01fed488f0e65c967bbbef8254600b7639a9da6fcc16fea2fe3f",
	        584
	);
}
static void snarf_hat_586(void) 
{
	snarf_construct_hat("/usr/bin/passwd",
	        "f9e1d828a34605b07c51fe7aeb875609f88be5b73d7a4e623ff275ddfd00a0ed0ec039c5e598a2a61b49047e553ffe5df8497a8e3fe52f27bccf1f6f65b4e72a",
	        585
	);
}
static void snarf_hat_587(void) 
{
	snarf_construct_hat("/usr/bin/paste",
	        "83efce46779c061fbea1d6b90a65abce4e02371a1b7bba4941995bb2a254842cf0758c4e9d537a87192d1cc497cf8fda55eb35cc2c11b2f4e13d55fcc9257510",
	        586
	);
}
static void snarf_hat_588(void) 
{
	snarf_construct_hat("/usr/bin/pathchk",
	        "db7d78fda7154fd33614fb13c95f8713fb3196edc662a91b477855600ec44d53ef50d9928a46429871a379e8a545e2e454706236b0b80a4b6839bc1e4b4433a0",
	        587
	);
}
static void snarf_hat_589(void) 
{
	snarf_construct_hat("/usr/bin/pdfattach",
	        "cc07e6e7631c6a0973c3666bd7a6f9055e94653272faf9c651d228749c93fc2ca7a26d728f81f59be80d642f2df70d744f58a8b5e5ac1c75d8ffd8fe4b47e6e4",
	        588
	);
}
static void snarf_hat_590(void) 
{
	snarf_construct_hat("/usr/bin/pdfdetach",
	        "4cf6c6aa740f4b023b2b756c6f38bca8eee10f88d41dea1e3046b9f1949c9a230103de925edf91ac365e644779b86d4bee1f64f8d72b7a41258971e8d56f57f9",
	        589
	);
}
static void snarf_hat_591(void) 
{
	snarf_construct_hat("/usr/bin/pdffonts",
	        "a6cc9dc575a2f81ba00cda3bffc2a0b5d3e817ad3743015526c816d24b076bb8f121568450b14b77ce220d92592b0d4d08b9f8b4f01e2c5f188434a9fb000d6d",
	        590
	);
}
static void snarf_hat_592(void) 
{
	snarf_construct_hat("/usr/bin/pdfimages",
	        "0e170221e64d672e6aaa0dae6aa0893f881f8a6d92d7b8e68d36bfc328ae9464d01c59646bf3c34ccae3732ce2d473ffe3063a65727a3311497f2b9ae1830032",
	        591
	);
}
static void snarf_hat_593(void) 
{
	snarf_construct_hat("/usr/bin/pdfinfo",
	        "1961996cf27213c8a63b9a867faf14d581a1238ea2ec0cb7c028a0e2c70029b21e8720b0633757691b697ff3bf99da38efea0fb56942feb7b20a027943d08ac5",
	        592
	);
}
static void snarf_hat_594(void) 
{
	snarf_construct_hat("/usr/bin/pdfseparate",
	        "1997025473bd90f203f61acf2c2f6a6b18d7cc663cf25c76b1e71e7204772be1102775a11d747a408c8a1ebd9a4ccb235ba1a7f1603a7d358cb740f5d2f68017",
	        593
	);
}
static void snarf_hat_595(void) 
{
	snarf_construct_hat("/usr/bin/pdfsig",
	        "0748d0127cc96e2a05990521e71db7018e4dceeb4ef1584ed34853bd8fa09f09023415792e9fd2d779de8a4b23caacff9bbbbc0b288bfecbf2b0bc59c89a70b7",
	        594
	);
}
static void snarf_hat_596(void) 
{
	snarf_construct_hat("/usr/bin/pdftocairo",
	        "8805684c16ad1b7d627f61a14d221c52c2b456ea22eba6780e15095531ad0d77d18e3ceab2ad81e53df9913fb3f240585ff697cd70af8d9c65435ecf3eedc8ee",
	        595
	);
}
static void snarf_hat_597(void) 
{
	snarf_construct_hat("/usr/bin/pdftohtml",
	        "8620baa872ccb16b47765c07357862b024d72843890e973bd45c6fdf2c896fd48407a32619a98adadbd1dfb5225cfc2af60361463edb504fa9059e39d197f2db",
	        596
	);
}
static void snarf_hat_598(void) 
{
	snarf_construct_hat("/usr/bin/pdftoppm",
	        "da14ce120666e057d47ffd2ed88b61cded72fd804caccd7d98abe220d40882fb10ca22e4b512e61c8c878a94a105e08e437f5e2ec361dabee8c9c97c0accaad6",
	        597
	);
}
static void snarf_hat_599(void) 
{
	snarf_construct_hat("/usr/bin/pdftops",
	        "4de3bdd36ad34d9ae1afbd0729391cd7233f8d164fc6e11dda6a887c99405cd2631450e02b4a072fd3fc79d648bfe3c453cb9637d1c34c813762b95d46ac675b",
	        598
	);
}
static void snarf_hat_600(void) 
{
	snarf_construct_hat("/usr/bin/pdftotext",
	        "461809fb086109e2b46c0bc83d012031d5581e20ac24938866f672a892963f91b2c58be79859904f8909ca90732e623dc97515c526b59c7a8c2d73fac37af601",
	        599
	);
}
static void snarf_hat_601(void) 
{
	snarf_construct_hat("/usr/bin/pdfunite",
	        "65862458cdd67e8a6b4a1c4aad742711410a9c39185ddaf889a8a16c4deb4935314c42c75de9d1649ef1cb79fefd64341263080511848f0d057e7e1a7aaf530a",
	        600
	);
}
static void snarf_hat_602(void) 
{
	snarf_construct_hat("/usr/bin/peekfd",
	        "b33037b2c202278753aad09fc861919d63f849cf8227de474000796f4749a5c3d7669d121d67b7395492d0d5e6e5b683a7a34e177d05d971f3b016921ade2139",
	        601
	);
}
static void snarf_hat_603(void) 
{
	snarf_construct_hat("/usr/bin/perl5.34.0",
	        "469d2d8a7c7450c1e181bcde42055d8e4a64654187b8d54e49d43272aa1c7502f33f30bc3aab25ee4cff87d1c4a0ba5ca391593a25b51fe85c210c3033b7334d",
	        602
	);
}
static void snarf_hat_604(void) 
{
	snarf_construct_hat("/usr/bin/perldoc",
	        "87695c442e06e5273560d6741d89af7f3c3c29c4171cf8159f82d57e2a581b7031d3de628140dbeae5e83a1161b0c1d03bedc424b7411b143055adbc0d0794e5",
	        603
	);
}
static void snarf_hat_605(void) 
{
	snarf_construct_hat("/usr/bin/perl",
	        "469d2d8a7c7450c1e181bcde42055d8e4a64654187b8d54e49d43272aa1c7502f33f30bc3aab25ee4cff87d1c4a0ba5ca391593a25b51fe85c210c3033b7334d",
	        604
	);
}
static void snarf_hat_606(void) 
{
	snarf_construct_hat("/usr/bin/pgrep",
	        "c5467e9733162e5c3d7f9a07dcf5a7092c10d9ba7b7020e89244794449ac93bb129ae0d87d9f90c858b5d62f14ea61fee44cc59c0ebb1c10a0bff0ed3966d11a",
	        605
	);
}
static void snarf_hat_607(void) 
{
	snarf_construct_hat("/usr/bin/pic",
	        "7025461d28425a2faa38f352bb0891aa6edc907891af1c5c2a34a2ce3e50e407f80d292042686d6a179577f42519491276565b5b9ee54530785adf86b0060d44",
	        606
	);
}
static void snarf_hat_608(void) 
{
	snarf_construct_hat("/usr/bin/pidof",
	        "b61489f3b819abbcd28582233a36441336254d358c33a80730db9de149bb235450eaf850676e16c416a859c787cb4673d04222ad21cfbb0b75e4d46b002eae3e",
	        607
	);
}
static void snarf_hat_609(void) 
{
	snarf_construct_hat("/usr/bin/pidwait",
	        "38729166be033866f710db22a61bcf63e7bf4842bef4418435fd0df652258a1c014ddaceb067ab9a89d166001157a708b766ae7eb752f56c01d2a2957e7a8003",
	        608
	);
}
static void snarf_hat_610(void) 
{
	snarf_construct_hat("/usr/bin/pinfo",
	        "003c27c21e9883d85f45b246102717514b3d94729d14d8047743d8af59782960e00e6b23513e412f0d27e821b7611d0ada1c10b7942255891a8a7dbb407972f2",
	        609
	);
}
static void snarf_hat_611(void) 
{
	snarf_construct_hat("/usr/bin/ping",
	        "f58c43b6e11dbc1e8889f9cd4c173f9cdf6a15bc5343d34b2f78cf1fac80b5774cb67274894cb3cf49cca5c0f8f680f753b95f90150b93985b51fc23ccdb2eaa",
	        610
	);
}
static void snarf_hat_612(void) 
{
	snarf_construct_hat("/usr/bin/pinky",
	        "cc15c77608b2f14d24d0c05e20bc42d085c04ed44cbd832a2786f0c42a0855e63d0a3df94a05593f80e61a1d0966312c81b805dd17aace374a95020b133af1a3",
	        611
	);
}
static void snarf_hat_613(void) 
{
	snarf_construct_hat("/usr/bin/pitchplay",
	        "428d4e750985e9045b00360b3b118e2b0d4940ac27eb8fb1c3c227142e99322dff71b40f77d4c44c6f4912293d64cc4a93222df5c0e1b9e54afe5852559b45d8",
	        612
	);
}
static void snarf_hat_614(void) 
{
	snarf_construct_hat("/usr/bin/piv-tool",
	        "5950d9a369f9fca01d998e32ba5099b8c45820abeb73bf86214d8c6f83fa8bcb85ea232e64d7f2c35c27d9d89a01fc741c5c266946c2f13abf06aeedb15f61a3",
	        613
	);
}
static void snarf_hat_615(void) 
{
	snarf_construct_hat("/usr/bin/pkcs11-tool",
	        "e7ffae6d4c380e4ac488727dd4290abc38831658367ef48f650712cff5057831d9ea79194e9a2f184b027e6f1f0ec25d27e62d7f29950c387839f656d9e30742",
	        614
	);
}
static void snarf_hat_616(void) 
{
	snarf_construct_hat("/usr/bin/pkcs15-crypt",
	        "c9cba659c5a86ee47e56d96d314650a7b5ce44a694553a69903697dcb9dba97b59a852cb9d0aa8d5372277e677fecfcee22f679b7d2127d58be4a1f7e05786d7",
	        615
	);
}
static void snarf_hat_617(void) 
{
	snarf_construct_hat("/usr/bin/pkcs15-init",
	        "3e052303a23e78cdabf61bab321c1e215aca704688f6c287c70d5047ede50c3bd2954002958e8b310ebd41cef60ae26f329ab10a36c5ba031471eb2c641b5f6d",
	        616
	);
}
static void snarf_hat_618(void) 
{
	snarf_construct_hat("/usr/bin/pkcs15-tool",
	        "19bf2332439afe3953616f8203905bea6289129f847861581a9d5fab80e3b12ea7ad49b78d7cd441543ce84709439964ae426e77b9b89bc8bc3d0cbfe79b117f",
	        617
	);
}
static void snarf_hat_619(void) 
{
	snarf_construct_hat("/usr/bin/pkg-config",
	        "4ee61af93272701542e927352643e3b575808db75a9e400ba4b2117ec91a669497f9128f53d6764e254cd671f4e1fa14604b0fbf12de1d87de2630205ba43182",
	        618
	);
}
static void snarf_hat_620(void) 
{
	snarf_construct_hat("/usr/bin/pkgconf",
	        "e2a883f659174b810f20a12fcb4eb640e2a9b78d890a5f09a7c269a32e829dad2f1550890bcb2ce2662e2aae9f9a73c482f8bcd840b8d7fdac21eb1bff740ff6",
	        619
	);
}
static void snarf_hat_621(void) 
{
	snarf_construct_hat("/usr/bin/pkill",
	        "e4b1aff49609d3982ab9f38ee098533ba2ea4c63eb1b2b2f93b52055135bec47b218c629bc25d1cdd38f8e56c1cd1018880c08621f6f54e6bf2e478ad1d22335",
	        620
	);
}
static void snarf_hat_622(void) 
{
	snarf_construct_hat("/usr/bin/pkla-admin-identities",
	        "ffe5c9a5eef97d6734d78f8fab002c53bdeb817a05a6aeeca672b74e85f6e2864433933e9c5e38f3e19ed265d156e9fe68710af7afca9b60ffafada65863cd80",
	        621
	);
}
static void snarf_hat_623(void) 
{
	snarf_construct_hat("/usr/bin/pkla-check-authorization",
	        "494fad1c48f3fdd2ec98cd77ee46e4266aa26f12d6f478921b64a67d6c952cb383dd6552d3310ccc8bfc928d771e088013ef54476c38cef808f8c0d6b15d9c26",
	        622
	);
}
static void snarf_hat_624(void) 
{
	snarf_construct_hat("/usr/bin/plistutil",
	        "52e26579ccfd02cc39a4642400518abaf59406436bc6ea37aef79a5aaddf40174391853be59dd596723c61c22cf0320e452bdb803a83765f475580016ee0d2ba",
	        623
	);
}
static void snarf_hat_625(void) 
{
	snarf_construct_hat("/usr/bin/plymouth",
	        "7c62fe53825b5e04196121af87c4e9abbd894d0966905eb17c2a9b3d5cb35ce6e023b010fc7e8e83f7f423c001a42e646b12ee285b8fd11bfafcf95c4888f39d",
	        624
	);
}
static void snarf_hat_626(void) 
{
	snarf_construct_hat("/usr/bin/pmap",
	        "309876d91e9780665970332d330976de089d1dd9711b5cfd3c015d681bae3aa21ee87a061a6f16bd3ece2bd9e50f434cb57a9bd0397ba7b3bf08cfed079eb691",
	        625
	);
}
static void snarf_hat_627(void) 
{
	snarf_construct_hat("/usr/bin/pod2man",
	        "ace0975683641e2dc9f34f09493897b89c8c2b636bc26f7a450acae7ddc2be7c3c6fb6d3914a04afe45c8a9ff5bcd82f402c4f20c15acb1193a5238397eb6eb3",
	        626
	);
}
static void snarf_hat_628(void) 
{
	snarf_construct_hat("/usr/bin/pod2text",
	        "db7166ace61c0ed44e93cbdde031a2936b0e505de2914a99d8a79254b2302091eacdc6b8361919dfc43e58e6ed04a15dd3b530657464701881ec9ce8a2dccb46",
	        627
	);
}
static void snarf_hat_629(void) 
{
	snarf_construct_hat("/usr/bin/pod2usage",
	        "852c9bc296342ba377b81d2f4365d2af44639834dbf8a974af4ff21afee2720620a2e33497e23b35af898fb6c9590ec6b63cceb12257b96790063bce9f790025",
	        628
	);
}
static void snarf_hat_630(void) 
{
	snarf_construct_hat("/usr/bin/post-grohtml",
	        "4c4a4ba46a322d2ae22f3de619c852d4c7b19fc6f1f8c2ef3926d2cda25fc0897f2be0514ea7fc218be7d0a5b43d1d2b661a633f2efc21f6851d0e69d25a626c",
	        629
	);
}
static void snarf_hat_631(void) 
{
	snarf_construct_hat("/usr/bin/ppdc",
	        "284eed38c411ba7b9f0e8ac0500852e44beb64b7268213a8ebd3f801f41476b326a0947238b6b6f720f9a68d6df15237b44c2d1e8ba90b4dbbb4c93149d417f1",
	        630
	);
}
static void snarf_hat_632(void) 
{
	snarf_construct_hat("/usr/bin/ppdhtml",
	        "383226e1a3ed2c7777aaf23827c4ca05acc806a617fc53a90c32cbed5add05f256120738ee9b9ddb75c0929c64cf76cf217efb073bc01e6fb2304ad031ef5ba3",
	        631
	);
}
static void snarf_hat_633(void) 
{
	snarf_construct_hat("/usr/bin/ppdi",
	        "b8a05cf16ba9ca5326bc5775449f1fe106a8823b250b67aa27931596b30b9f46243757950d53868fccb530ca8e628b1548b2e804e97d04e5643efc393c92b288",
	        632
	);
}
static void snarf_hat_634(void) 
{
	snarf_construct_hat("/usr/bin/ppdmerge",
	        "0ee9571fc292c47cf8fef81a23dc1d915b7b59072d806249f4a2fba51d552b59583231546407f61e6a4c62173d96556f700498b621e443d7158d3d606e28093c",
	        633
	);
}
static void snarf_hat_635(void) 
{
	snarf_construct_hat("/usr/bin/ppdpo",
	        "7a983ee30e52c2ed1a2f5491c8908bf40940422c45c742335128b3b52829dd76978470af0b9bf118017c8878d7a34dcf6a5bf4951df874eb6ff08d86c62d97c2",
	        634
	);
}
static void snarf_hat_636(void) 
{
	snarf_construct_hat("/usr/bin/pr",
	        "caee64cdb5ac3fdec674a898b0c350f8541d9dcd34a08bddaac529ce6897bd86b4d9c4eceea8fb104ce38cc93b8378948838a450f17940b5f719752f232e3e2d",
	        635
	);
}
static void snarf_hat_637(void) 
{
	snarf_construct_hat("/usr/bin/pre-grohtml",
	        "7acfad9ec8c92b20e9a664102370c5ef57f976e1f649f2bc65ab033ac4654a8192878c0fc3e9a8ee20fd05a789ff421f48d93312ab292f556dbb161373264bd2",
	        636
	);
}
static void snarf_hat_638(void) 
{
	snarf_construct_hat("/usr/bin/preconv",
	        "e14f5662fcf293e43e962f2d1a9e17ecde029c3aec653fbb14864d1258135d4a3225a452c00928f73b44d1507d13fa673e18bcfb51bce14cc864469d58b789fd",
	        637
	);
}
static void snarf_hat_639(void) 
{
	snarf_construct_hat("/usr/bin/printenv",
	        "908b304dbbbcb15088434055b0b07190f471907c60e632d8de25c27b9e205cb50974892b53e0264a9824979d3c2cc4afd28a13601616642f8d72e3d0219d6ecd",
	        638
	);
}
static void snarf_hat_640(void) 
{
	snarf_construct_hat("/usr/bin/printf",
	        "8ce8b374a57ca1b2f6450cdef2d011e517b475887676fdcd3df300654b80550c7383a2efb71df9ca76320c99c1641e56f5bea31281618db1e3a80fe3c84237a7",
	        639
	);
}
static void snarf_hat_641(void) 
{
	snarf_construct_hat("/usr/bin/prlimit",
	        "6584d9f0a7f9f0ea41975ee7025d4a302de6839fe4cfc243257b8f2a955b6dcbbb0ea1eef7d95224d31f3d15e1112acf1e8d3bf5cc4eb05dc9cdb019bbad8da3",
	        640
	);
}
static void snarf_hat_642(void) 
{
	snarf_construct_hat("/usr/bin/prtstat",
	        "37713ecd7d1ddfc675d3c2be53372ffbdf0a3c298b205e7660bae192ad145a484993fcc541bdf44108d739f997fbf4559b7fdbaf47421a742c2523e66a75e366",
	        641
	);
}
static void snarf_hat_643(void) 
{
	snarf_construct_hat("/usr/bin/ps",
	        "b270ac5b8a9ad028da7a11e0f53fc40fc3ee01af35244a4b5d92f50beaf0ca65640fa946bf61872602a7a344a74f2ad5852ec51c2be6d2ded77b3883a0dc3f1e",
	        642
	);
}
static void snarf_hat_644(void) 
{
	snarf_construct_hat("/usr/bin/psktool",
	        "af828abe8fba53db512dd9e4b2ac4ef59ceec47965d0293ab59a70a591d95af3a82ef05759f130c63f6c73f1a192d199cb5125dc8e9d31b7e82e73d309ce720d",
	        643
	);
}
static void snarf_hat_645(void) 
{
	snarf_construct_hat("/usr/bin/pslog",
	        "58cde5349e9339f1f1ff95a343b7700020fa5ac907143709cfa3710f6ac377dae31b96109aed73178b9a27bb0697e92601ec071924dd82eba0ec454f98c753c5",
	        644
	);
}
static void snarf_hat_646(void) 
{
	snarf_construct_hat("/usr/bin/pstree",
	        "7520e41f21afa7b1fc193b3f5eb470339a21bacd367f5504f55c33a87e362d3fc8e4615ddc687b35c26154fb6826d6108f1a536f1d7e577247c2c433485c8f5d",
	        645
	);
}
static void snarf_hat_647(void) 
{
	snarf_construct_hat("/usr/bin/ptx",
	        "927ae30a51d8fd7e67ebc917fa3637b1cdbc6482425de2bfacd13eb748d144476571ebfd1e783a93c187e55aec8bb4a79dfde342e54c48c1932ada40db4a700f",
	        646
	);
}
static void snarf_hat_648(void) 
{
	snarf_construct_hat("/usr/bin/pwd",
	        "6150a1f883cced36b1052736dbb87d1f7ae77f8b0ed833483f13a0bd7501a0ee7834972dade3c2d907a19028f14ba325851eb5ece8b843068c369e6402349ccf",
	        647
	);
}
static void snarf_hat_649(void) 
{
	snarf_construct_hat("/usr/bin/pwdx",
	        "5c77013e39b855ffb99ffb110c6d3cac0ee5a224bee2d0c9efa182fd209fa08d0eead328c0710f2d32731300144081f05fdbcd365c08b1305d808dd22b54ab88",
	        648
	);
}
static void snarf_hat_650(void) 
{
	snarf_construct_hat("/usr/bin/pwmake",
	        "5ff4b38255a13cd6ff34a49ef73f186f62458edb67cb26952eb68406eb6357ea3942f056d072615338f6dc7f5291d7d34a4a9fa77c60b130af4ad01fa2dd649f",
	        649
	);
}
static void snarf_hat_651(void) 
{
	snarf_construct_hat("/usr/bin/pwqcheck",
	        "648c73e761ef79c038f849ea0403b935cae9209bd3f65c89438dbefcd4ddfcbfb11c4322882a98b7061e0d24b13f29556da02d3c5a313d7c4cd1fdf74f15f2ac",
	        650
	);
}
static void snarf_hat_652(void) 
{
	snarf_construct_hat("/usr/bin/pwqfilter",
	        "2c06b368da3b7145bf2419c41301b9eed5fcbcdbf3bed6933d8b03aaa490eb46a12f0543f1b0788f735c6e1f9bbd2b2f5b82e4dd90d1b92b39318f892a28da7e",
	        651
	);
}
static void snarf_hat_653(void) 
{
	snarf_construct_hat("/usr/bin/pwqgen",
	        "11067a99a44edc3867d9adc0853324abbfe6a3f09de4b044a6023aa087a165e0c61a2f45bb77726770a2ef90e232263433aec9f0c860130054f3a705fbe67d17",
	        652
	);
}
static void snarf_hat_654(void) 
{
	snarf_construct_hat("/usr/bin/pwscore",
	        "2f4325ef3b58d608022b23fea2c54aa47427481617935151e596bddb99bf9fff3ed581053a7d46f39059ad8abc71ee5ec846523001b7f9faea102e80551e522d",
	        653
	);
}
static void snarf_hat_655(void) 
{
	snarf_construct_hat("/usr/bin/python-argcomplete-check-easy-install-script",
	        "76467f362a74dbe8d4604e4f3a7c314294838aa5602eec6c905656ab028e27067fc9108cdb8d361bd50a115cbb277ff55495cb2ea41fefcc2a6c4b701fb91bda",
	        654
	);
}
static void snarf_hat_656(void) 
{
	snarf_construct_hat("/usr/bin/python-argcomplete-tcsh",
	        "fc4b9dc80f25e135da885cb3c72920157d3c83ce4a07865a58dab77a906703dec2c8491c3d201b1b44ce3fa5e9577fdf27a32c5fb0773bb39366e53a14720b1b",
	        655
	);
}
static void snarf_hat_657(void) 
{
	snarf_construct_hat("/usr/bin/quota",
	        "4f650714d7250386872bad62013bd04b5bc9d3f55b373e28234d0d16cb6f5673d93e442628ff58ef714023a6339dbfaa75b29c5d7c2cba290605711fb842e602",
	        656
	);
}
static void snarf_hat_658(void) 
{
	snarf_construct_hat("/usr/bin/quotasync",
	        "f5c33f85bd88fee0accc089286ba337a43b697bdb1162bc8a92c02200103d3b96d3f04f6b9e9a4198639a3f039e90a38627ee603b1e54887613365e0c146b79e",
	        657
	);
}
static void snarf_hat_659(void) 
{
	snarf_construct_hat("/usr/bin/rapper",
	        "fa406abc2675f8fce91410d31782cd51c816b9e15fe4da5e41560a6237df5a7a6a6733505fa944bc6810088d40bfc9b54f1adbf189e094c6e6a418fd088331a6",
	        658
	);
}
static void snarf_hat_660(void) 
{
	snarf_construct_hat("/usr/bin/rdfproc",
	        "19c47a6502383669a6cce5e0394bb0c4074322efd75dabfd517a77a5c6ef6bd73a7e3dd4121fb259fae10208168aae8fdd7189736d433e540cde3d461f8443af",
	        659
	);
}
static void snarf_hat_661(void) 
{
	snarf_construct_hat("/usr/bin/read",
	        "e28e44f3563271af0d452bb98720cee0201cbf99fd03b8bce422445e856bd4122b09a29718068672961c6a56f87a94ec9e69959d065b3ce603bc0c07ce0be52f",
	        660
	);
}
static void snarf_hat_662(void) 
{
	snarf_construct_hat("/usr/bin/readlink",
	        "ec2ce4e917a0fc222979d4a46e83699a66e6b859d7ad12c7d2c71c6e89e3415ff7fba34ae406ebda9a654b4ba3d14f0a0b39004c70d419c388fab15eb8da475a",
	        661
	);
}
static void snarf_hat_663(void) 
{
	snarf_construct_hat("/usr/bin/readmult",
	        "a7d3aade30f91a7d43692e9608adf33b707f7f34fa6918d2de78830e4c8436dc6cd92d49da6e711e9f69fbc290822c3781310d24faef5c8815c52fb182832c75",
	        662
	);
}
static void snarf_hat_664(void) 
{
	snarf_construct_hat("/usr/bin/readtags",
	        "e3b5725c56cb239e4ff7e5e9b9e6b53f2f119e89396a65e8d1aa2a487ad5e83be4bbfefd8c2019e44fcb1b833fbd881bcec3c03764a7be967bab78ca6b2c14a4",
	        663
	);
}
static void snarf_hat_665(void) 
{
	snarf_construct_hat("/usr/bin/realpath",
	        "0df3e104a9538c30ef4e13fc4981ffab3d2ea1b7c8258f285648ba106e9610317bf036d27cc0edc1220ecdf6dff4c500e7be08562adb110a1b3135f41badb348",
	        664
	);
}
static void snarf_hat_666(void) 
{
	snarf_construct_hat("/usr/bin/recode-sr-latin",
	        "edfb8ffabf65c1622edc6c730842033756bf13cb9ba9d27c6a4ffddb995f3696d8dbc86ae4b1963940ebe08a27bc439408d12c5d676869390df43029244d872d",
	        665
	);
}
static void snarf_hat_667(void) 
{
	snarf_construct_hat("/usr/bin/redland-db-upgrade",
	        "a5eb1dc81e94367586688abef62c2a5562ff14dfc323f14832639f952ddda446bcb0c64da0580870d839cf2f36eeb05a4580c13b562df93cd53eabd273f00dca",
	        666
	);
}
static void snarf_hat_668(void) 
{
	snarf_construct_hat("/usr/bin/register-python-argcomplete",
	        "62aa745750c800afafec0137c4fba692a8a04085055f7feaa844b0e7060d1749d7cfaf6ef5f5c69171e4e49f8804dc5d50297d9a0e1d9ebfd8273d000218e250",
	        667
	);
}
static void snarf_hat_669(void) 
{
	snarf_construct_hat("/usr/bin/rename",
	        "a27b0ba98e1d6cb0621a8509c6a23c77e785e685156537aa6748c8976f01ae7d0720d9172be550068b329d2c1766fa832f6988c9c3729d0f6a86442d733da1b7",
	        668
	);
}
static void snarf_hat_670(void) 
{
	snarf_construct_hat("/usr/bin/renice",
	        "93937947562c3f3a7756055cf251747422957fb71b211ff795dff7c2520790011742b914a217d51a71147270d3b9ad8d4208ea8f075759fecaf86099c2af7993",
	        669
	);
}
static void snarf_hat_671(void) 
{
	snarf_construct_hat("/usr/bin/report-cli",
	        "265d67dbeda399e827a02b591985bd338b8b885dd04b9168aeef0c894450aa6c9a8d9e5379331a4623eebab9dc5a59623f956a35e200b26b3f5fad13be32f4f4",
	        670
	);
}
static void snarf_hat_672(void) 
{
	snarf_construct_hat("/usr/bin/report-gtk",
	        "e20e7ff1a73d2070e88b4e1db734095b76311e84bd4fb5045a72814cbc62b76cd2ff8a8a8de9152e6874a7b7008d95833a1a89cf845b21def31873dd7d66bf79",
	        671
	);
}
static void snarf_hat_673(void) 
{
	snarf_construct_hat("/usr/bin/reporter-bugzilla",
	        "8b284c65772f79560000b79606913cda72783d5f900a4bfd2b6e4754d091c26dc7b54bb167bdd7395e446f8ca45b8c86be8d4c77dedda8326b469b5767f30b25",
	        672
	);
}
static void snarf_hat_674(void) 
{
	snarf_construct_hat("/usr/bin/reporter-kerneloops",
	        "2de2746f8f5ab09ba908d9de07a88ee29f704708d111887feff05674a8b85c541eb43b972bd4e79e84968ff019c0b8f0d1a8abbd1bd8094eca84d0bbc7d9c1e1",
	        673
	);
}
static void snarf_hat_675(void) 
{
	snarf_construct_hat("/usr/bin/reporter-print",
	        "1c238668148415334d45be2d0e72cb735e469c0d5d9cb83ebae5101748cda857de5dc2dae147a7547e1fbb88297e014249f3e68ebb9513b2babf7372e9db93eb",
	        674
	);
}
static void snarf_hat_676(void) 
{
	snarf_construct_hat("/usr/bin/reporter-systemd-journal",
	        "3722bd872e9f7b995f953f28784f462901e76187f1861e9f2ff2f24e00c6a4a789c019bf416b155af0aaa404d2102793d2ac78e00ebe9e7452699548d6872bfc",
	        675
	);
}
static void snarf_hat_677(void) 
{
	snarf_construct_hat("/usr/bin/reporter-upload",
	        "83fccb795b822398dbceee513118a0f060629bb4cee1fbf37a61a5965b7dfc5228a30d5033ca45d08863328b52d676bd6bc3dd72afb74123131db50df2c7b076",
	        676
	);
}
static void snarf_hat_678(void) 
{
	snarf_construct_hat("/usr/bin/reporter-ureport",
	        "0253021daa57d63d69158edd1d1e19a1b33c921615cda7900c08d6c4103d3ea0a768603b0e63a81b0d7a5720f5306435dfb859aaf2ae117c6844831173de3060",
	        677
	);
}
static void snarf_hat_679(void) 
{
	snarf_construct_hat("/usr/bin/rev",
	        "151b0c9d8fa95da39eb66d6d54c596c50c6255ac4f596f6b9b009613abb62293bfac6224fc0cc6cbfe2624def96e613702eb42baf44bcab61b1fe5b6670800cb",
	        678
	);
}
static void snarf_hat_680(void) 
{
	snarf_construct_hat("/usr/bin/rhythmbox",
	        "5b128f3b1c14dbfffd524dfa5c62207e77fd41b2d7632f418078f2204848c3411bf3b2f54535c0fb23529db8e1aa0056433a50fca0106b9321a189e02fd596c3",
	        679
	);
}
static void snarf_hat_681(void) 
{
	snarf_construct_hat("/usr/bin/rhythmbox-client",
	        "f292017ccc0031823b5e041878c843902642e2862d0dd6b680ae3061dd569a1ed7a49bf5b950fed0f0a4922a702698aaa9d62fb631b2f6be241b2753e7235304",
	        680
	);
}
static void snarf_hat_682(void) 
{
	snarf_construct_hat("/usr/bin/rm",
	        "3a063967b0de98fa5dcf582214f6dfddfd11b3b14d4ec90271efdadf5b6046799dd46dff3011c3679a3fa6a2f179824ee2e525d6aba0ac9643c1ec1542e6b41b",
	        681
	);
}
static void snarf_hat_683(void) 
{
	snarf_construct_hat("/usr/bin/rmdir",
	        "2ab378fe56647325ae316c46a6225d08c96e1cfcd23cde1bedc6f271428cb2f5584438b4b6ffb4c048e04831d254cd1bc5081aac97fd322ab3e551886fe23866",
	        682
	);
}
static void snarf_hat_684(void) 
{
	snarf_construct_hat("/usr/bin/roqet",
	        "1923d62d1e6ec83124b6c20e330a7dd29ae76c1329d7ff92e050c6979573d1738f74beb5242f4468f8c639bdd6bfd4a4922edea6f7adc80cb15ab4e4a5ecf8a4",
	        683
	);
}
static void snarf_hat_685(void) 
{
	snarf_construct_hat("/usr/bin/rpcbind",
	        "e702186a9a5fa1a1f6bef2a916168b737c03a62a284fd472c75b486efb5f1c0fe1cac41fcf0ecd9f5cdaeda5aa1b0c11e697f7fcfcc75b0cb22e76e4cb11eb2f",
	        684
	);
}
static void snarf_hat_686(void) 
{
	snarf_construct_hat("/usr/bin/rpcinfo",
	        "4488484defaf07e6445c8fcb81c20f364288062cb5036ddf5a133ac7bacb3aefbb8620b5ad410ae094c2e89b8907c06dbb41059b28bb9c7189f0fd1b610ab2c0",
	        685
	);
}
static void snarf_hat_687(void) 
{
	snarf_construct_hat("/usr/bin/rpmdumpheader",
	        "8d9f33e4352fa0a4b850d1c91822518d65ea1eae93c6e32c088f72a65751434ec11b5d770454d2617763ef70e09cae43a80b6c0112c5c01ed270d54e1988816c",
	        686
	);
}
static void snarf_hat_688(void) 
{
	snarf_construct_hat("/usr/bin/rsync",
	        "5f264c863c25d60bd59c2514434a1efaf2d850c11a784a77f444a35d3cfbd17dd9cf64d7f2a19efc29101569a4609f3cc95086bb2f0bf5734477214237a8bc27",
	        687
	);
}
static void snarf_hat_689(void) 
{
	snarf_construct_hat("/usr/bin/rsync-ssl",
	        "445dfd738d3ea7b6ab13e0cebe5d14fce0de0391e310ace4f1005d57a69f751e28c28e3ea4abf92bafdb6928ed00d7d38f9249bf795d30d438ab9a6bf55d0789",
	        688
	);
}
static void snarf_hat_690(void) 
{
	snarf_construct_hat("/usr/bin/rz",
	        "5a009e812234f0a5c158d286313752d2fb3e7ac9bbe011dffd0d62e204186bb0e4b909809f44afbf5763373f9e308e5458487d4df50ed548697bbaa154a6d7ae",
	        689
	);
}
static void snarf_hat_691(void) 
{
	snarf_construct_hat("/usr/bin/rx",
	        "5a009e812234f0a5c158d286313752d2fb3e7ac9bbe011dffd0d62e204186bb0e4b909809f44afbf5763373f9e308e5458487d4df50ed548697bbaa154a6d7ae",
	        690
	);
}
static void snarf_hat_692(void) 
{
	snarf_construct_hat("/usr/bin/rb",
	        "5a009e812234f0a5c158d286313752d2fb3e7ac9bbe011dffd0d62e204186bb0e4b909809f44afbf5763373f9e308e5458487d4df50ed548697bbaa154a6d7ae",
	        691
	);
}
static void snarf_hat_693(void) 
{
	snarf_construct_hat("/usr/bin/sane-find-scanner",
	        "bbe67b7e7aaf3010ca8ffe53735427190a79be2453d8e27a5d7eab1c8c18b363e8e92c3f796c447c7b1da6fc91bc1b067e7102ad1aab15eb638461ffe9d0b8b6",
	        692
	);
}
static void snarf_hat_694(void) 
{
	snarf_construct_hat("/usr/bin/satyr",
	        "c144bf0373440ad9b7a69d16dcc053ff103ed5f673d82c504ac2670f8501b7a271be51aa4fb8934a10a263c859a5ee1b0f2e64901a80d6cf48b562557d9e0f35",
	        693
	);
}
static void snarf_hat_695(void) 
{
	snarf_construct_hat("/usr/bin/sc-hsm-tool",
	        "ad786072ebabbc8c30c4460a6c912081f544a63d11cd070c44fbe93da3d07dc40556e7d7ea67f774dc1bf4436d7270515212a4bc0022135ff962417890d5b06e",
	        694
	);
}
static void snarf_hat_696(void) 
{
	snarf_construct_hat("/usr/bin/scanimage",
	        "044f213eb3e33e1e928dbf5cf97939ba32d26ffafcddd94d83ce0f05eeb32f4e1a9df2877c10b79aadef987dded71d70f382e55ca56ace0f269d2b8578b5073b",
	        695
	);
}
static void snarf_hat_697(void) 
{
	snarf_construct_hat("/usr/bin/script",
	        "0ecd6a40d341c991f030220b363a21433b0c1d8efaf2230f407b99335c9e36a6b107b2f9054bb1579f5c32331f9b311dd6710d61a09b1e6a0b8a8f4bebf576c6",
	        696
	);
}
static void snarf_hat_698(void) 
{
	snarf_construct_hat("/usr/bin/scriptlive",
	        "2107943cb234b308402374f34125b7354b9721031b2c6a4e1010237e9f44fce1fab1ce083faed822050c1ab779091ef5b60ef8aca666a6c4c926c1de1b12cae3",
	        697
	);
}
static void snarf_hat_699(void) 
{
	snarf_construct_hat("/usr/bin/scriptreplay",
	        "f6f1e077f5e40e9018435fa9b609642d6755f531a580458269fe9873ea2b73f1c50682736e1dae5ddb30a04cecd7026829ced11f7bc0b44aaf7d248facaeb91b",
	        698
	);
}
static void snarf_hat_700(void) 
{
	snarf_construct_hat("/usr/bin/sctp_darn",
	        "d4b33921ba7c4f74a405a26959aaee8a52d7cc2382ba7839392a433fcfbe7e43a4ecedd1fa7fb02775b08e4024dcd91e031f9bef909986461b6d7c623dcba83d",
	        699
	);
}
static void snarf_hat_701(void) 
{
	snarf_construct_hat("/usr/bin/sctp_status",
	        "7b88e13aa12784bfd58a471bc7b4f2bac4528f2f20dc7e2eeec9485b3770068af6f895e86a3ca47363c2aa9e59553fac7c9af52c26e284a4b42af09cbd9cf863",
	        700
	);
}
static void snarf_hat_702(void) 
{
	snarf_construct_hat("/usr/bin/sctp_test",
	        "5d6145dd6fece36e02f294a081ba817c7bedd2a6f13dfc5dbdeb543efe5db4b25b549fdb03a68b4cef91139807b3062443b7db669642f502e211e35fbe865103",
	        701
	);
}
static void snarf_hat_703(void) 
{
	snarf_construct_hat("/usr/bin/sdiff",
	        "d0d587ed3951b39e22e5a3017cf7fa7199623f2061ee092364da5a34721ae8bcaeb945fea3e5294929aa4511fc7d07ea2bfb76fc72acad5c4e30bbdd0b5459cc",
	        702
	);
}
static void snarf_hat_704(void) 
{
	snarf_construct_hat("/usr/bin/secon",
	        "73d8b66274c40599b077f12b279eeda381e77fd330ee2f16fe6858396cf14cf736eaa4e6ed95120360900c59f3ec4ff3695553e323096bce141642c767ba4bfb",
	        703
	);
}
static void snarf_hat_705(void) 
{
	snarf_construct_hat("/usr/bin/secret-tool",
	        "4d8b36058ec04e932b4d55bed2f0fc12c03101c365e28629130cd3d5c38272ba3ac7c4057cacc1ac9269487b136e3d2dcd25118a1ac6878709efbfcf308b3b9f",
	        704
	);
}
static void snarf_hat_706(void) 
{
	snarf_construct_hat("/usr/bin/sed",
	        "3fb39e9fe5d09450453c0979886f797b28c51f0a48ecc9a5fb95adc28746acf893828f9b0e9a6c094df1bb53b410c2c1f7e2e45c4ffd1625dbdb9680971babce",
	        705
	);
}
static void snarf_hat_707(void) 
{
	snarf_construct_hat("/usr/bin/sedismod",
	        "e7602f01f02c66976f230a01bbf6ef9382ceca54ac82b498f7b07abe7db2b538e8145c50f9d0ca9b3f7f19f6f596e9599129c63e2f3a971447473f910fe7258f",
	        706
	);
}
static void snarf_hat_708(void) 
{
	snarf_construct_hat("/usr/bin/sedispol",
	        "f1f091ee63756a3ea7e3491ac4b60539f1bb7c5ac6db8ef4e57d051ffeb8f1cc7e53323d67157ee216d8764b505cb0d8da14461f1108010f2e9e75fa717d3219",
	        707
	);
}
static void snarf_hat_709(void) 
{
	snarf_construct_hat("/usr/bin/semodule_expand",
	        "31540091e6dd257671f9e8766f245eedad8be2c783b8c5d4b624506fdee170989f15d0e395d97d4360b821f0a2c8c1032858a53e5cb0b92614646398ec2d35a3",
	        708
	);
}
static void snarf_hat_710(void) 
{
	snarf_construct_hat("/usr/bin/semodule_link",
	        "e9f24bd6a4cc71cb78c0f2f198d5dfc578f74f7b236f1d0c3eafca7130c2face7bf6d8420b556e754fdb93713712465c62d9ecc5080f48ac664784f3e8f0f9db",
	        709
	);
}
static void snarf_hat_711(void) 
{
	snarf_construct_hat("/usr/bin/semodule_package",
	        "150aa9e81edb81c28955dbb053d3cf414a06ccc78abfd8c0de299535e9b54ed0dff0a53f08f440647ea38a12a1ed3ab547e95e4731b4bcd63a9520af1de95b7a",
	        710
	);
}
static void snarf_hat_712(void) 
{
	snarf_construct_hat("/usr/bin/semodule_unpackage",
	        "f8559fc508de28e7b8bb7681abbff7a23d5cfc36b34f80f006a2df1b1c7534be6da9174c34d9765ce1c7cdd9a82384acbbe4da290e227d7edf93c07f84f88bd1",
	        711
	);
}
static void snarf_hat_713(void) 
{
	snarf_construct_hat("/usr/bin/seq",
	        "7fb5efba9bef4ebed7d69538226a82dac0e4e859259ad0aa335679a4575184079ba845fddc8711b55213841684595b0d1f76e2213dcd30ea003459a73e05811e",
	        712
	);
}
static void snarf_hat_714(void) 
{
	snarf_construct_hat("/usr/bin/serdi",
	        "2012e2fc2e3b1839731080779d5d4f2f1ee03c23b8f6d0b655932487004fb2ef0253363db5bca4249b4a95d59a83422d0cd9565e168e66bd0f8c308639a07278",
	        713
	);
}
static void snarf_hat_715(void) 
{
	snarf_construct_hat("/usr/bin/sestatus",
	        "621aa68fdd4775fabdfe182d8ee7c4e89d2bce683906e70d5e42f1764d51238fd5603b6fdc2e552b61c682a30d25d587b3da484bad756d0976d2c4c43755f19e",
	        714
	);
}
static void snarf_hat_716(void) 
{
	snarf_construct_hat("/usr/bin/setarch",
	        "e341227bfda404e4e89573571b37afa8bcdabc2f60e7519dba81746d7751caadfa765b3e39f43a257a86fa49decacb7ea46bd16be9294ab53ac97c4cd2820e74",
	        715
	);
}
static void snarf_hat_717(void) 
{
	snarf_construct_hat("/usr/bin/setfacl",
	        "bf072c1bf4323410bdc1de10f1a471d5b40a30257a5b911364c406ff7100801d3cc8409ef96143e9f5a92ed9f685a2d93e34d8df0785002336561da61e8cfa5c",
	        716
	);
}
static void snarf_hat_718(void) 
{
	snarf_construct_hat("/usr/bin/setfattr",
	        "01a2983401a1fcac8199bf83a360c5124cbd64c15bbf60c51bf78fbf623b0dda056c2c2bd6bfa19fbbd89e71474a005c804aa5f257ddc186eae421b0a6945f1f",
	        717
	);
}
static void snarf_hat_719(void) 
{
	snarf_construct_hat("/usr/bin/setpriv",
	        "2863e70ceb608cc9a63737074ce74f4ebad00f330cc2a055b00cd7fe33a7014d024d94a04f25d08e8520a192e13bf9958b6e3ad655393360387a88385ff6913a",
	        718
	);
}
static void snarf_hat_720(void) 
{
	snarf_construct_hat("/usr/bin/setsid",
	        "1735ef84e210e64ebf522db6fe623f9d5824a276b5d26e84778ddf7ee55bd623e924149c52ab47587e33cd0948206020b66ef18c76940b0a6cb4937ebc7723e9",
	        719
	);
}
static void snarf_hat_721(void) 
{
	snarf_construct_hat("/usr/bin/setterm",
	        "9b37fafb2205bee5956b8b1302c059d994b83fcb3d425891fec9e6eb6cbcd6852fdf0ba0b27ed485cff6e245f1613355a954a79ab987aad0fbcef0239cdb90a1",
	        720
	);
}
static void snarf_hat_722(void) 
{
	snarf_construct_hat("/usr/bin/setxkbmap",
	        "fd786646d68e5ddaeb455b277fcc19ae59a3c3558e0cd3c7e252b12abafde3812d7b065b27ff62b483af4be11fe097c9481fea36a9516cd2082efb83783a09bd",
	        721
	);
}
static void snarf_hat_723(void) 
{
	snarf_construct_hat("/usr/bin/sha1sum",
	        "9a87ec998c5e8b09c226570a7fe56f6590c8165a31e3e723dc621cee853c02e58da3fd152fd5ba49eded057fc44aaf28f106fe5449aab8f253c1a31cf8e0c30f",
	        722
	);
}
static void snarf_hat_724(void) 
{
	snarf_construct_hat("/usr/bin/sha224sum",
	        "1bb1902c14d7d13b832d1e888a12adf2ebe782e062725589ae8bb2836353ace214605b989364550c6f31d9acd51941914d6b52e34c036f2be6b817adacd5a36a",
	        723
	);
}
static void snarf_hat_725(void) 
{
	snarf_construct_hat("/usr/bin/sha256sum",
	        "8dfe8775562b3f35a9f66d933cdf7d149572bb776c068094dd491a697f84aa77e42c35a8b34cc9cc93327adb1bfaf2c3b7ca9e5174c5f758ef01757a9cd6a570",
	        724
	);
}
static void snarf_hat_726(void) 
{
	snarf_construct_hat("/usr/bin/sha384sum",
	        "a78e3f86e58b8662ef3ad31e280fd43b432389fef06bb11b5f11e1d2f8e6d322fc9d584611eef8563ff0aac30e978df60c17616ee8bc0a31a700520e1eb6fe18",
	        725
	);
}
static void snarf_hat_727(void) 
{
	snarf_construct_hat("/usr/bin/sha512hmac",
	        "6f5d582e878a5f70d0650c1c7ae89d68e77659c85feed4b38047c9f57284f4cc3da4e834c6a2058417874de7ae6a02d6922c5613a37147484ae7416972c45bad",
	        726
	);
}
static void snarf_hat_728(void) 
{
	snarf_construct_hat("/usr/bin/sha384hmac",
	        "6f5d582e878a5f70d0650c1c7ae89d68e77659c85feed4b38047c9f57284f4cc3da4e834c6a2058417874de7ae6a02d6922c5613a37147484ae7416972c45bad",
	        727
	);
}
static void snarf_hat_729(void) 
{
	snarf_construct_hat("/usr/bin/sha256hmac",
	        "6f5d582e878a5f70d0650c1c7ae89d68e77659c85feed4b38047c9f57284f4cc3da4e834c6a2058417874de7ae6a02d6922c5613a37147484ae7416972c45bad",
	        728
	);
}
static void snarf_hat_730(void) 
{
	snarf_construct_hat("/usr/bin/sha224hmac",
	        "6f5d582e878a5f70d0650c1c7ae89d68e77659c85feed4b38047c9f57284f4cc3da4e834c6a2058417874de7ae6a02d6922c5613a37147484ae7416972c45bad",
	        729
	);
}
static void snarf_hat_731(void) 
{
	snarf_construct_hat("/usr/bin/sha1hmac",
	        "6f5d582e878a5f70d0650c1c7ae89d68e77659c85feed4b38047c9f57284f4cc3da4e834c6a2058417874de7ae6a02d6922c5613a37147484ae7416972c45bad",
	        730
	);
}
static void snarf_hat_732(void) 
{
	snarf_construct_hat("/usr/bin/sha512sum",
	        "f587c1a8173ddb328a9eb0bfb2d0f313c41ee468f4243c4663a2ed00627cd1caad4bbe1f99104be5a303c99ab319c4640467995329749c299a14f8ebfeec60ab",
	        731
	);
}
static void snarf_hat_733(void) 
{
	snarf_construct_hat("/usr/bin/showimage2",
	        "6900ee29742a2a386f6bd0b937424ac3d6e6215fa302bfd2b7ad1dff0cf3b722fff1c875a0ca9c618ae12686132fb509d1ef9070151e74264ce897f6c289b675",
	        732
	);
}
static void snarf_hat_734(void) 
{
	snarf_construct_hat("/usr/bin/shred",
	        "01482f0506395a2152b09439ce6664a56c7af9251b8765d9c7a40d8aa5b3a19cb31f43ee57e426c9d7cb5d87d40d2b04adaa06dba410e259e191e77037d919d0",
	        733
	);
}
static void snarf_hat_735(void) 
{
	snarf_construct_hat("/usr/bin/shuf",
	        "8d86dcebd38e250012fc1f68742b81608bf87707ea49c3949447e13c8f4c52138c73357f5b6fecee79491693d1f0a834195c534f083bad02759852c85f708f37",
	        734
	);
}
static void snarf_hat_736(void) 
{
	snarf_construct_hat("/usr/bin/skill",
	        "df6f4209071bf9a0d3f2513bdf899acb7389e64f47a20783540bd50390f7f041f0fa74cfd535583be43bf686e8857cd85e42d4e2d4c44aae1f8b73bec3594836",
	        735
	);
}
static void snarf_hat_737(void) 
{
	snarf_construct_hat("/usr/bin/slabtop",
	        "05a071ed0b33405dd1f5fcc1e7bb8e07f4090ee35d03f60cc0ae0a395607cb02d90954b5ce3f9c8b96d8acec0b2d0fa506d0abc7682450a16e0394169d256957",
	        736
	);
}
static void snarf_hat_738(void) 
{
	snarf_construct_hat("/usr/bin/sleep",
	        "0088658666d99ed3629061aa4de4fc51d91850aaf3f34fa0a2819a5afc15bc5101e234e0c841c3b35102535e351ff556a667e8dc4e33caf772fcb8d170fb81a5",
	        737
	);
}
static void snarf_hat_739(void) 
{
	snarf_construct_hat("/usr/bin/snice",
	        "6866e1b7c028420d766fe21fdcf57e4c789f822a62fab9560e98b0839d8ece000eae9a88ee5337d996c56d2e15c75d43aa56936b5c5203a4245c3d1eb3ea10a8",
	        738
	);
}
static void snarf_hat_740(void) 
{
	snarf_construct_hat("/usr/bin/soelim.groff",
	        "4b75c14c527733ceb1ed35f7afe8a40221e46cab63217069ae54ba51532dba944610b4c5ec941ae1592b3657fb4f826cfc575c10cb7203d70a93380042aea308",
	        739
	);
}
static void snarf_hat_741(void) 
{
	snarf_construct_hat("/usr/bin/sord_validate",
	        "ffad3dcac74b5d22eb111c1d6f25a5b3961c708ac20d94ed7821154e8919d248f809d5e2943d69594be591f4571e464b13a20eddca4b8dcf2d678bf253ddad90",
	        740
	);
}
static void snarf_hat_742(void) 
{
	snarf_construct_hat("/usr/bin/sordi",
	        "feef62d68df85740c738421c75213a075929f11b94a6b76f4d428f4c2a5c81d0828c0a142b5402ec36e2a980b8886cfdc8cef139be550dc79432bd19022e3e17",
	        741
	);
}
static void snarf_hat_743(void) 
{
	snarf_construct_hat("/usr/bin/sort",
	        "ae234786015e8fca768ead038851d2b672fafe2a2fe890da88527c48cf17d0d67e0cbbfae23a10b8d0e2647d11409ff784d2d86cf8cdb95b1692351625efc524",
	        742
	);
}
static void snarf_hat_744(void) 
{
	snarf_construct_hat("/usr/bin/source-highlight",
	        "771f32449ba42f110355838acf3089bd0ffa06fb95df51482f467e97f7ecfacc89041ef690704e27f072ab8abcd5c5ba9a73da47cea4b50bc0811b0522bb674a",
	        743
	);
}
static void snarf_hat_745(void) 
{
	snarf_construct_hat("/usr/bin/source-highlight-esc.sh",
	        "2bc32aef4592ce67bcae2bf0dfecf13c0efe81c5a558ecd73dc6f6e588c80ea6dbf89d989a2e7f180dc160ca51f547c04ea338fe8d8260b8b2ec947f14c80375",
	        744
	);
}
static void snarf_hat_746(void) 
{
	snarf_construct_hat("/usr/bin/source-highlight-settings",
	        "2e170ae485fb63d2c233070e5456ef0d228eb8f990c38ff897cf5273d8b8231c86717a11fdb092e87e4af46f0474468d810a20c1550d734180c24f8d1fdb3b84",
	        745
	);
}
static void snarf_hat_747(void) 
{
	snarf_construct_hat("/usr/bin/speak-ng",
	        "c23614cfd9091b080d1d968f450bf5e6227748f56cee71de67d54848be686e6661b1424797d5668ef38cadd7329cc1f33d87a7b9293d585af5987b35289fe11e",
	        746
	);
}
static void snarf_hat_748(void) 
{
	snarf_construct_hat("/usr/bin/speaker-test",
	        "dc3c2872f4b5e5e7b95682535b657ec5f56f4271cfc117944ee502c009fb58cdafffb3cc0c08625189705bf88ec01d0700140bec9ef8c9c8316a8e81bdcc787d",
	        747
	);
}
static void snarf_hat_749(void) 
{
	snarf_construct_hat("/usr/bin/speech-dispatcher",
	        "29f25b225b3535e279cbe03304689b6465575da81d035d22e2349528724a68de6d515719580f4ebbf57a216bff30a1b82cf52e495cbddbe95e21ea218e1bf9a2",
	        748
	);
}
static void snarf_hat_750(void) 
{
	snarf_construct_hat("/usr/bin/spellout",
	        "8fe3dbc034cd63606b14d508661f8a16f0be2a72064ef59724bdeb2e9e7f22b767d9a51633ed88f7a0cb2bbad65063d776d66ac282ed56a452f24fd9c5307d97",
	        749
	);
}
static void snarf_hat_751(void) 
{
	snarf_construct_hat("/usr/bin/spice-vdagent",
	        "74c8e40b8c73347164ca22c5b9f2219e90bc604f277df2229119d768f9019d89d9cf98e32b0a033a58444d51811ed2fdce53f1dd867c9a6845e5bfbff97d6891",
	        750
	);
}
static void snarf_hat_752(void) 
{
	snarf_construct_hat("/usr/bin/split",
	        "c6a747bbdca57acdfc39a2af08d92132f9bc4fb182bff44235074de40a88762ee1315e68736d9cea395872147ac67a63a2953d345346f2ef613dbc4954008c0f",
	        751
	);
}
static void snarf_hat_753(void) 
{
	snarf_construct_hat("/usr/bin/sqlite3",
	        "ae78c3c1100317565b8ae5cd042c58af8aa643297525cf07489ca140b08ad1b0f19dab9c818669712fe316d4650dd91dbaabf73d50e928ad13a42c9bc7717943",
	        752
	);
}
static void snarf_hat_754(void) 
{
	snarf_construct_hat("/usr/bin/src-hilite-lesspipe.sh",
	        "89fb06456f26ccb119f9e70cd55f0accd67a1e6495de4d8cc225a1865b5283a700734177fa3648f6a7b782b271c047104ef308b7bbe2647166774ff1af721453",
	        753
	);
}
static void snarf_hat_755(void) 
{
	snarf_construct_hat("/usr/bin/srptool",
	        "6a288dacc370015c4775e9d9d1a3888d37403b9fe58fd42beb23c588c4299201567d55c7952ff5ea685a376781f7018f7ad381fcbea7474c88c3482c0dd4cd11",
	        754
	);
}
static void snarf_hat_756(void) 
{
	snarf_construct_hat("/usr/bin/sshpass",
	        "a2e6a8de0fb620bd863e93565dbfd74059c9f8b689d5a32e87f45965bd27f9636005f6f2382a16fcd5c8ae99480ad345bc71e0aa9a99eb0ed14c5a51164c73e2",
	        755
	);
}
static void snarf_hat_757(void) 
{
	snarf_construct_hat("/usr/bin/startx",
	        "2be25686e39712b38269b9c15fbd9d466405820d44b3f6a7a487f91942f4a50a71eef82527dd4f06a91a5e44e50cd462f589cdc7c50b382b0fd608eb1909609f",
	        756
	);
}
static void snarf_hat_758(void) 
{
	snarf_construct_hat("/usr/bin/stat",
	        "7d6eecc8ae453e2e056b125ef3f629aa32779d741f5aa23f842fa2799d82688948d70806e87e492d53e7fa5468c89fe1ff4868255ced18ca1da928867b635f9e",
	        757
	);
}
static void snarf_hat_759(void) 
{
	snarf_construct_hat("/usr/bin/stdbuf",
	        "fa3c39a850e128d8c719744c22231c4bea3e437c416fb7bf10cbe2d5a6b706ba1d1225dcf6516a96520e43d69fefc4165352546c354fef192305e49054f881c6",
	        758
	);
}
static void snarf_hat_760(void) 
{
	snarf_construct_hat("/usr/bin/stty",
	        "f971695f0bc14fd45d16bab545f3f2eb22e407dc7a11c20a4994525290c0bf773f594efb3dd3178c4e4eb73e1c5210cb92902c483c731bfc4854c2b1b551914a",
	        759
	);
}
static void snarf_hat_761(void) 
{
	snarf_construct_hat("/usr/bin/stunbdc",
	        "3c9585faab89d72c9aa3ef5780d4d1da027516ced98d2be99710272de18bd43b975ce72611d8e902f4e67732b888d48bee11e19da58dbd2f37a8119f76d26a9e",
	        760
	);
}
static void snarf_hat_762(void) 
{
	snarf_construct_hat("/usr/bin/stund",
	        "2ad914e6ad8dec2c55a3cc1daa13a16c3b610b80ac7203ce64bea5690db2a57f8415fae6023651de1905fa6d3fa87d5997bf8f1488245ecaa37bcee4ca0e41dd",
	        761
	);
}
static void snarf_hat_763(void) 
{
	snarf_construct_hat("/usr/bin/su",
	        "2ccc38573b0ca75db14871b6eb5210e41b6aa5f13000c033502edd00ff8d427de63d3bc147fed38cedfcac95b27a3312c2f79d6d1f87a79abf56ac24c0304d04",
	        762
	);
}
static void snarf_hat_764(void) 
{
	snarf_construct_hat("/usr/bin/sudo",
	        "9202ded0203db4eb685c209e18d654ae4a2225b046339f35277f757b3bfc7f73860846a13f612415bc32e68c4a6336da9a888fca3b56a2cc4c1666d567fd91d5",
	        763
	);
}
static void snarf_hat_765(void) 
{
	snarf_construct_hat("/usr/bin/sudoreplay",
	        "ba60c8b4388fac6bc0dc4379d0eb8b9dfcc21d730c79b6247ec52062b32f9f376ca91ede52af2fddc506bf259b46d6a80302b636127dcfbc431164f8395bfb2d",
	        764
	);
}
static void snarf_hat_766(void) 
{
	snarf_construct_hat("/usr/bin/sum",
	        "b1ad115d28c892c621fbe8267c64636a628e563fa01f02a5a659fbb443348bb897691e56e0634cee2717ce7c473ee23c212e0c7098df9ce2c9e5eb8a21bd606d",
	        765
	);
}
static void snarf_hat_767(void) 
{
	snarf_construct_hat("/usr/bin/switcherooctl",
	        "4fc6752e632bc4ef3ed074faad766123c368fc1a1ece607a8dab4f5159fd3b96bf5c78835b34e41ff194cbc76f9d144993636c8adbd1e2153a94dd90e5ea29f4",
	        766
	);
}
static void snarf_hat_768(void) 
{
	snarf_construct_hat("/usr/bin/swtpm",
	        "463cf05b71909a62297baa4768cf510e27c72c6b81d51e0bda6dcbf1332ad3930a14aa6e96ce9a07b4334e172ba8c82b3cf1e195b20873703b77e0945ea070c2",
	        767
	);
}
static void snarf_hat_769(void) 
{
	snarf_construct_hat("/usr/bin/swtpm_bios",
	        "99cae93786ed01190a582cad6803f5337635ab21c2a66c2290a2d1b703d2b37f797d3e499073d24a4eb10d100e6e79016779414d956b29cdc40c52fddba002ce",
	        768
	);
}
static void snarf_hat_770(void) 
{
	snarf_construct_hat("/usr/bin/swtpm_cert",
	        "61b659b71d148e0dd26e5098beb67817d9f89cafd559e0c24861df223d65ebffc382f346c41807cd521ee83ee5ee0d45f7e082e0da28598311b648dead2f6504",
	        769
	);
}
static void snarf_hat_771(void) 
{
	snarf_construct_hat("/usr/bin/swtpm_ioctl",
	        "32a386c81091098c0b7399fae5991f696699dca78df5df1ba11d89ba983b1a74acae51d22c028af292ad40ac405293318e5ddbdf067df9e13b54eea7640e63ae",
	        770
	);
}
static void snarf_hat_772(void) 
{
	snarf_construct_hat("/usr/bin/swtpm_setup",
	        "1acca60bb8c399a95370f1eac1ce84ba48b6eb54d6e111b4cb69739b3ff1153edafceeeb64bb5aba6317d52359fdb6bb23f77a8a0272c5b2326cdfa00935e14c",
	        771
	);
}
static void snarf_hat_773(void) 
{
	snarf_construct_hat("/usr/bin/symlinks",
	        "5ad67bc9b074e749be9d27237103d0ecddc1ca44649a20fb5f946407edb79f374db947ebd18fffc173069419601a5ae88d897d8e94b862187c280734ab8945f5",
	        772
	);
}
static void snarf_hat_774(void) 
{
	snarf_construct_hat("/usr/bin/sync",
	        "c7fa0bcb1d19f62c8e8b2f1a123347fa73af6ddf6786300a4019f0f32d4dcebfb1d034f89e1036a12340494b21b56b74395b2d0a82199b888902dcc79fe8c007",
	        773
	);
}
static void snarf_hat_775(void) 
{
	snarf_construct_hat("/usr/bin/syslinux",
	        "116855ccd6f63a4fe40b1efc231736503afbb26ae3c44648e9311061de4be7a8d12ef7530f1be7589fda514e385bc2eabdf7820953b4e40157308e02c9ad1699",
	        774
	);
}
static void snarf_hat_776(void) 
{
	snarf_construct_hat("/usr/bin/sz",
	        "35ea6bdd991059c99d91bf598bcc72d6628a22d56811c788c9244068f9c636fba8b2c0c717d3324aaff3882400253c30fbeb5938ab95d9ff52933c032c5c2f5c",
	        775
	);
}
static void snarf_hat_777(void) 
{
	snarf_construct_hat("/usr/bin/sx",
	        "35ea6bdd991059c99d91bf598bcc72d6628a22d56811c788c9244068f9c636fba8b2c0c717d3324aaff3882400253c30fbeb5938ab95d9ff52933c032c5c2f5c",
	        776
	);
}
static void snarf_hat_778(void) 
{
	snarf_construct_hat("/usr/bin/sb",
	        "35ea6bdd991059c99d91bf598bcc72d6628a22d56811c788c9244068f9c636fba8b2c0c717d3324aaff3882400253c30fbeb5938ab95d9ff52933c032c5c2f5c",
	        777
	);
}
static void snarf_hat_779(void) 
{
	snarf_construct_hat("/usr/bin/tabs",
	        "f5780021ac79209ba9a48662372afb15e54dfa415417c2eca8ce1542fdb556399af87559bf18b1e200dcfb36f306176f84f54485b80dbc10ae3b562c841fd4c1",
	        778
	);
}
static void snarf_hat_780(void) 
{
	snarf_construct_hat("/usr/bin/tac",
	        "5e51f0d4e729904a0417201183ef1077f292bc51a95a6a5eaa23e39880179ffd29dc543c6eca222648ed8c9d48b2f8158402313ec192e18014c9a67ede576e49",
	        779
	);
}
static void snarf_hat_781(void) 
{
	snarf_construct_hat("/usr/bin/tail",
	        "d35a790bbec4fdbf535acb728f8d4d2ed68f7ba947f37f99e233dfb04dcc7762e72976301b3002d1875f079ad788fd2e2b94a6e707cdd95dfa84e4aee423cda3",
	        780
	);
}
static void snarf_hat_782(void) 
{
	snarf_construct_hat("/usr/bin/tar",
	        "2f24da279ed5c246b7612253ee73ea29502affc78d38e259debdb9bdc1b57be641540c43f1b2757138ed262d5f41775983739d074047146f1084bc641d706b98",
	        781
	);
}
static void snarf_hat_783(void) 
{
	snarf_construct_hat("/usr/bin/taskset",
	        "9e603001118587b7fe9fb34fd6adbd37f0080bfd736c0e73f3b1e25ee6d10ee8b6bf73641fe0543e25edd83e900ef62cd9f242f2c360a27d8f08b5b3b084a818",
	        782
	);
}
static void snarf_hat_784(void) 
{
	snarf_construct_hat("/usr/bin/tbl",
	        "0cf2f92f26b300b332fa021b70e51d29aa3fc89db1dd5479a83f0d65a756d30f4be9a9d88624242240afa808a2c80a369de7b918a0d763cdd72db1ec53198b46",
	        783
	);
}
static void snarf_hat_785(void) 
{
	snarf_construct_hat("/usr/bin/tclsh8.6",
	        "178299ce52bdf5173d4dfe8332639eaa0b5ccec9f28932c9a25169a16bb24186ea4b9c1f379c397b553131496827b33bbe91aeb29cdad22fddcefdd4ebbb9bf9",
	        784
	);
}
static void snarf_hat_786(void) 
{
	snarf_construct_hat("/usr/bin/tcptraceroute",
	        "889c39df2ef34eec4e61095570a17b0d8551499dfddc724de9cf89151ebf4131b7f460a793ea482f55baaadc834ebc0c287b68b5147def1f46067214f2ddb5f0",
	        785
	);
}
static void snarf_hat_787(void) 
{
	snarf_construct_hat("/usr/bin/teamd",
	        "a1b87180235c7482313b32dee67e54d7f9c449368454526bb93441796708788a54602857e2f95e2dab55404e1311cca42cec9d2add09b5bd24cd6c0ec8dbad4e",
	        786
	);
}
static void snarf_hat_788(void) 
{
	snarf_construct_hat("/usr/bin/teamdctl",
	        "8b48acb3ad4ee40dd51264d6d3696e687a967dbe00eb59e323ec9b5a32ee839267617533796f1c94c23572ed701a30681b7e9f5a63e3484be61e7d9a028b26a6",
	        787
	);
}
static void snarf_hat_789(void) 
{
	snarf_construct_hat("/usr/bin/teamnl",
	        "09ccff430ae1bdce5815f2eebdd8e9b727e18c8a661ba21ea85ffbe4024d7afaebb20f9aa96bbd1065862ae30b18362408b63d0e3a2786226a104077e321add6",
	        788
	);
}
static void snarf_hat_790(void) 
{
	snarf_construct_hat("/usr/bin/tee",
	        "32bc5b97a98fa6f5f89149afdd22d2f83ba8d4c9d6da2bf20bc03a01c064d97541efd8814db3f01f935f64fdd952bc80d6a25db3b7eb65a5b669ebd67ed7d638",
	        789
	);
}
static void snarf_hat_791(void) 
{
	snarf_construct_hat("/usr/bin/test",
	        "e82eb2cd69c42263a33a93280dd28538550384ac0d15c5c4f3d4374b008176ae9fa24361683eb89bc7a8cedce247d23c083f711c7a658e732f913a6c369e019e",
	        790
	);
}
static void snarf_hat_792(void) 
{
	snarf_construct_hat("/usr/bin/tgz",
	        "bba0758ddaf98d5b1367e695ff8cfdff288ed4c0761c669fc327843621287dc4e7638fb6fcb1a8acccbf78ddb82b531420ae689ed6fcd35c88f9deb9c121fdf4",
	        791
	);
}
static void snarf_hat_793(void) 
{
	snarf_construct_hat("/usr/bin/thermald-set-pref",
	        "501dd690fb24ac075d2efc6b74b88a8652d5e4736ac2dbd0442db9e5cfb34b25f4a3bec0203a7cb4cba49d7f4b6793a7ba1bb80179a4b079cf5920a40fb1bc35",
	        792
	);
}
static void snarf_hat_794(void) 
{
	snarf_construct_hat("/usr/bin/tic",
	        "47a812005f145dce31a7b40fd23e73f8c1bf8be1133c33fc2d142dd8158dd285fe2f851f0e6ecf028b49d164515a106efed28eab09b9848f06e6564da9468cac",
	        793
	);
}
static void snarf_hat_795(void) 
{
	snarf_construct_hat("/usr/bin/time",
	        "bc8d3331490492b8528e4c523aeb0c110ec3c91cfa7b669b80e3de906017aeaab2a16c8e55973bf1f11a2156665df664023939b774017f6c3c3e8352bc7094f1",
	        794
	);
}
static void snarf_hat_796(void) 
{
	snarf_construct_hat("/usr/bin/timeout",
	        "11c71e4990f01314b9e0b91e266e018f6d07642af909a588bd6e48352a289cb0935a4a63421d9d0de5eb894b38a49ae3c40b7825bc62acb42faa0f71e102ffe3",
	        795
	);
}
static void snarf_hat_797(void) 
{
	snarf_construct_hat("/usr/bin/tload",
	        "2d1c8e5e4a912660480ea8b9ce32409006fcf60923bb6448d4015054914fe976b600f1c0089a7f7aecb387d205cfe22b60dec4581a4ecc060928f4de558c1945",
	        796
	);
}
static void snarf_hat_798(void) 
{
	snarf_construct_hat("/usr/bin/tmux",
	        "dca7583049d9dd595aa36e391a1330437ba31f314fc698cb98eca2839a6fe41c79852604e0a4224358853c2e29ce0f5a99a6d4ead2f3b97b9be7e0b369351b5c",
	        797
	);
}
static void snarf_hat_799(void) 
{
	snarf_construct_hat("/usr/bin/toe",
	        "05cf0477ecee163dd60dd79c2959edd5da653c4c1461879e283e5f3b34f1d8ad99d83788ff2203ee337590575485bdcd6261e858cd77c20e9a530b41880ed2c6",
	        798
	);
}
static void snarf_hat_800(void) 
{
	snarf_construct_hat("/usr/bin/top",
	        "d3c8c914dd49f3ed1742c0dfcb2937ffe4b9005e3eae3b301ebaae93eeac478888bf023980aaf1cb78c73547b4f4d162c0598191147d48b29b98f5af550b6588",
	        799
	);
}
static void snarf_hat_801(void) 
{
	snarf_construct_hat("/usr/bin/touch",
	        "3699dad4add6b8a3c8918418e240ef565ee16f1612dd2f084c8833023f4dc14094ebddbdf7319ab21ef3df4b46b9fad5a560a412dd57a385e27af70339c69cc6",
	        800
	);
}
static void snarf_hat_802(void) 
{
	snarf_construct_hat("/usr/bin/tpmtool",
	        "465dcc26d5e7b05b43a67b20ef323618584d8c46918fa2d866fce4f15fe2c1e31392918455283f1f5c14274b252f9ba37205d9a36fa20b8286d1912a16fbc07c",
	        801
	);
}
static void snarf_hat_803(void) 
{
	snarf_construct_hat("/usr/bin/tput",
	        "67224d0062fb86a553e71be5bb4a5cec681a4f037c3c9645db7fd7bb7e45ecd3009d66c90b34df38f44a45209bb46e0af0011ec0bf3e8c297d338efb5e70a056",
	        802
	);
}
static void snarf_hat_804(void) 
{
	snarf_construct_hat("/usr/bin/tr",
	        "f183e6d58da884c3b9408346b9492818d512f21510014cf8999b3a38cc408ecb2a966dd39b7f7dc8597485a56b4dc31830b8f68f0fda2e6baff11f245830aad7",
	        803
	);
}
static void snarf_hat_805(void) 
{
	snarf_construct_hat("/usr/bin/tracepath",
	        "ed1f6862084da6fec4bb4752687ee0c2c458d2b4d63af5d8ed257ac01e883f4297885d70ced60c433b9fa5ef292b72264cb87a31e56bb3e646dc24d376bee5bf",
	        804
	);
}
static void snarf_hat_806(void) 
{
	snarf_construct_hat("/usr/bin/traceroute",
	        "a954840c630da745876e1d01c324dc966dc91c3f38fab0e72879f4aec97414ad600bf91b8bf99732cd37cda6294bb9d0e03efddd057f06526b259359cfc06732",
	        805
	);
}
static void snarf_hat_807(void) 
{
	snarf_construct_hat("/usr/bin/tree",
	        "0171ebd9688ad33f0bab49a33b1084753416baa5072715c38c62638d9df89f482cf89bb57636ccce932c4584eded847fe849e63db0ac5fdb8bff1d4f1262a667",
	        806
	);
}
static void snarf_hat_808(void) 
{
	snarf_construct_hat("/usr/bin/troff",
	        "63cf0570d05fc892b0c4bf38e9019b9499b7b0e800e6c4658b5ae8d10cd8474530897a86d9ac46ed65c507b85703ff92e6cd75e2f9d41c4b62992b55d14cc3e8",
	        807
	);
}
static void snarf_hat_809(void) 
{
	snarf_construct_hat("/usr/bin/true",
	        "398d389040f0f89ece06e2c224c4a37beaeabb8e3f7a1bef2d7fa691180e7d72232b30b1d0db10dbc50ad168d64e0db7d77b534d3d3e5cbbfc61d2f9dc8756f9",
	        808
	);
}
static void snarf_hat_810(void) 
{
	snarf_construct_hat("/usr/bin/truncate",
	        "825e3a0f1a43028441c2af0a58cd0697f6767d28cafe42c13cb59a5f0283e46da7539377e9a95b33bf5813499c4fdb408f7f772145865e924ce4ffd7beece5b3",
	        809
	);
}
static void snarf_hat_811(void) 
{
	snarf_construct_hat("/usr/bin/trust",
	        "ad22ec99baf19f92fb4b044ddf4c5d414ee98afd257e96b5072e640a1c2ed744fe64c2e64fe823b7c049b23643e119dbeaa6ad5b131ca86db9d4ec65e1e3c8a2",
	        810
	);
}
static void snarf_hat_812(void) 
{
	snarf_construct_hat("/usr/bin/tset",
	        "483da732edef28b61a9a5d9f23ee5d0fc7cb2d65dffbf7370f356c4e47bcbe9b0e846ee6cc5f8728c7d6dc336c15e0778aecc5c7bb01fb76a6dfd4c5a1e8bd25",
	        811
	);
}
static void snarf_hat_813(void) 
{
	snarf_construct_hat("/usr/bin/tsort",
	        "8f5cf6aca8f2fa60517b702f800743be066e51b81c52729c0bea8a07fc14b7f7b95d11d58a8047179d85927e996f411b960d9df4439075ef11b975cf8f16e381",
	        812
	);
}
static void snarf_hat_814(void) 
{
	snarf_construct_hat("/usr/bin/tty",
	        "21588b3f94b0ec593148b873f475c6d3d91d6aa4fc8ae81881f92cd01603bd77cdfc7fbfade610f5d66919127b69ebe272a1e68e8d1d73ea93755989d38a1e6c",
	        813
	);
}
static void snarf_hat_815(void) 
{
	snarf_construct_hat("/usr/bin/type",
	        "7bda89c6e21e98c02a73aa3cad9f78bc10010ac44b0caa66480cec298b02fbc507f3b96839031ff353cd10a9474d8a1552a81b409704620f1d864ca15df7c8c9",
	        814
	);
}
static void snarf_hat_816(void) 
{
	snarf_construct_hat("/usr/bin/uchardet",
	        "7a59aa82bb9d6a34c8e7e2be3fc6ce13d3011bd9d05e0417d5308289d0b334825edec595afcf6bafb672a6926fbfbbaf54532a4436557e99113b1ae9005d9f83",
	        815
	);
}
static void snarf_hat_817(void) 
{
	snarf_construct_hat("/usr/bin/uclampset",
	        "edf39db5536f036e6b37beb1bb62b6086627a26005aa95e20e14376158affdc8fa4174956846b569df409379fecc9fa5b29ba4b64dd1f86fae755d783b9014d7",
	        816
	);
}
static void snarf_hat_818(void) 
{
	snarf_construct_hat("/usr/bin/ul",
	        "55e3f8e569b10754955a6cec5c6d33e5a29ebe0126116d93a3bfcceea65a7ebfebb043db73ff2f33b7e5776b72bb5be1e0eb161d7c62cee16ea9b7fc3e7a8c9f",
	        817
	);
}
static void snarf_hat_819(void) 
{
	snarf_construct_hat("/usr/bin/ulimit",
	        "368212c3b653e48ab8dc9741104c20f34a5be4faa5b898c974654a392d07c6b8a0b0dff460fda9fb4e21331ec0424550ac9e3f7e52ed64b2af1981a69a9500f5",
	        818
	);
}
static void snarf_hat_820(void) 
{
	snarf_construct_hat("/usr/bin/ulockmgr_server",
	        "56f49c72a6fdfd1413d3fcc6570deb55a6d6f7357a6276a8a0e2aaf988249e7eaf6585dda91401b6d99d2d37e9b1193230d83821c1dea9502f701522671666d6",
	        819
	);
}
static void snarf_hat_821(void) 
{
	snarf_construct_hat("/usr/bin/umask",
	        "8498c6e0351c4953fe61ef5b1c13ba7d4774b51cd12662df79a58c54c1cae816bb9699a0dc3ad22f4679d49ddbffe6ed1ab176e12a8324c317f2478dd4d2f3dc",
	        820
	);
}
static void snarf_hat_822(void) 
{
	snarf_construct_hat("/usr/bin/umax_pp",
	        "115cf3ffe8a96b5cf5cb05b10b4ec2259d1ad0bfdc7e8986ee9b8d3c4adfb0a171feafeb2a2e695bdcb61aeec921eb00868a77bb48b8e75f4359bd505d60d1f2",
	        821
	);
}
static void snarf_hat_823(void) 
{
	snarf_construct_hat("/usr/bin/umount",
	        "e9940eab81542676e1e8598d60e01ee847bfde04a0c2f1c8206ebef6b2584f775a9c222f5a42e9a57cfc75f3d3e3cf02df0695d33fe8ae450e94a6b45f122924",
	        822
	);
}
static void snarf_hat_824(void) 
{
	snarf_construct_hat("/usr/bin/unalias",
	        "cf74aecdb336c078e88698d48a7c67098706e71cdbb22cd10cc470430437c9a2bfe9c7d374c11896553013b69cb6e02b21c90eb8d45f5e6a676919a6717e7bdb",
	        823
	);
}
static void snarf_hat_825(void) 
{
	snarf_construct_hat("/usr/bin/uname",
	        "6551fae1285ed55387ebf00a35ed2c9d95e16ca7eecc56d1f6917d3113acdb9ce00f60d8b978207a2598ff4c74bb6bf808741026c0d2ca60bb9aaa8d34d9caf2",
	        824
	);
}
static void snarf_hat_826(void) 
{
	snarf_construct_hat("/usr/bin/unexpand",
	        "31ecab1da9d16599ede925a3d42a44f6502df979f365953be7af37e45550012c2ff034b817409af4d0c08a870c9f001d72efb025e781b7d5173ed8aaeff1c0c9",
	        825
	);
}
static void snarf_hat_827(void) 
{
	snarf_construct_hat("/usr/bin/uniq",
	        "52a13047c46064b8d04809cf0cd60881633ebdc74c61efa78b690cc656307d6056b25155b88d0b33225c97be64518f1b020e643c1f13f55ce95021f40dc60978",
	        826
	);
}
static void snarf_hat_828(void) 
{
	snarf_construct_hat("/usr/bin/unix2dos",
	        "3059a5e9069616372d0feba8727ea39daba6cf848dfaf927fbdd25b89324d76a0038cf45f60363b09702b58d553001dc12f8f04a9cf3f9c751835e3e30a9d8ba",
	        827
	);
}
static void snarf_hat_829(void) 
{
	snarf_construct_hat("/usr/bin/unlink",
	        "e51762a9a0961b30c9bf36e781c87f617f4b95331b68cc61506dfc6007e7603bcaef226bdc880bf7a661a9f98aef7737dbf5fa071c34962742da7f37fb25acbf",
	        828
	);
}
static void snarf_hat_830(void) 
{
	snarf_construct_hat("/usr/bin/unoconv",
	        "8d56e48d6aa20b1203c71ddfac549425e901d02f56ca49ea7029e7d2ee66c064df7d336919cd58a6c9c8c98577869756de9c7d6e5fccd5f197b7672daf55e50e",
	        829
	);
}
static void snarf_hat_831(void) 
{
	snarf_construct_hat("/usr/bin/unpigz",
	        "f6b7a4e62ecc8d61cec43b1d07364282560c82aebe3bc10a15c78c308c6b0883e89223068cceaf61d3890dad0c48d207003a3bbd0a5c7a7345d2a56b62d4cc92",
	        830
	);
}
static void snarf_hat_832(void) 
{
	snarf_construct_hat("/usr/bin/pigz",
	        "f6b7a4e62ecc8d61cec43b1d07364282560c82aebe3bc10a15c78c308c6b0883e89223068cceaf61d3890dad0c48d207003a3bbd0a5c7a7345d2a56b62d4cc92",
	        831
	);
}
static void snarf_hat_833(void) 
{
	snarf_construct_hat("/usr/bin/unshare",
	        "a95ef20d3c8b2cbdbeb236753f6ff01c2aa8f600e901636ee752cd1e02fb7a8e22299f956be8bde75d59dfbe0358090b6712c0dfa557fb00261b2955e040f5cd",
	        832
	);
}
static void snarf_hat_834(void) 
{
	snarf_construct_hat("/usr/bin/unzipsfx",
	        "c0dc354d81c1806395e5de0222a5d1c520991e1f8f09af0e30f8b8d939014f3133aedeb3386cc4ca5800efd49750b6e442c5af3d6d66c6268972c157f5b7e27d",
	        833
	);
}
static void snarf_hat_835(void) 
{
	snarf_construct_hat("/usr/bin/update-ca-trust",
	        "3457e5a5a027065562e15a2602f295f06a268371cd911d0b36f0fea18f849bbc758c2242a83cfac432695d8eeb7d8a318a6015cc0b3699fa49e43644ea1cb4ee",
	        834
	);
}
static void snarf_hat_836(void) 
{
	snarf_construct_hat("/usr/bin/update-crypto-policies",
	        "1138db2113ab6ce50eeaa558e1e411495b39315ed8716a906f9206c8458186767ab66540ab06dccc5c31ab90bddb1e61de7a8d51ccc69f7aff8d5d97d8c791ae",
	        835
	);
}
static void snarf_hat_837(void) 
{
	snarf_construct_hat("/usr/bin/update-desktop-database",
	        "08364841c916dd683e083b7c1695c8475330c2ab8e20004ad42fcd6327edee8a0f4a247adc5216d738ebbb07137bf14d1efb45bc60652d914a848e812ad0804a",
	        836
	);
}
static void snarf_hat_838(void) 
{
	snarf_construct_hat("/usr/bin/update-mime-database",
	        "de3baf9ea81d63a59e641b183a7c8a0932600245fba3f80690c0d3e56a2cc2c2aec1fbe0c2d4381f69904f5158c7ad2c658116b87dbe095fc2edeb64d6ec94f8",
	        837
	);
}
static void snarf_hat_839(void) 
{
	snarf_construct_hat("/usr/bin/upower",
	        "090c35ba15360a5a70e32622bb334fe95f245fb9ed6bef50c0136dde52c4e7a44432b6acdb814f72de8f6dd9b04794c31ff5f6e85e50dcf1cd2441af0fcb7265",
	        838
	);
}
static void snarf_hat_840(void) 
{
	snarf_construct_hat("/usr/bin/uptime",
	        "c6b0bdba15f1d5076f3a2fb521dce5f829595e364c618bb3fc72e04c44927a63f5d83b650240986c9d6c729d2b6b5a8b7f6d3c2a74a7ca0a5e68361d43863b51",
	        839
	);
}
static void snarf_hat_841(void) 
{
	snarf_construct_hat("/usr/bin/usb-devices",
	        "6f658cc9b72c414f3653afd6f7b397f86ce74ef2602a6b96b3091a9f5f6dbded22455c0ffdf7b23619aa54578d3f7d172dbfc8a3fcd2d86eb85692c68bf5a08b",
	        840
	);
}
static void snarf_hat_842(void) 
{
	snarf_construct_hat("/usr/bin/usbhid-dump",
	        "c6f526925f0e033caa9d25806be48a869d57bac8e049cd78acfe0316f9a16b084e825a4855a3c80a1c96a0e0769bcf76a08ebde8cfb0068742b7c67f8e459258",
	        841
	);
}
static void snarf_hat_843(void) 
{
	snarf_construct_hat("/usr/bin/users",
	        "b25ed77212a7c87c9731751ecb67aeb496638dc815c09393cdbffaf3474bd21ff3ae72f2b95e685fee0cc528c468bfc004e33f02fb5eb1b31c3cc40f722550d2",
	        842
	);
}
static void snarf_hat_844(void) 
{
	snarf_construct_hat("/usr/bin/utmpdump",
	        "9c6862cae0ec855532970969cd394da81cdd99d54ff293590410746ae0cedc546330d9107704b3f8fa456aacb27e00ca276e5383ff0acc2e7bf97ab4703c7997",
	        843
	);
}
static void snarf_hat_845(void) 
{
	snarf_construct_hat("/usr/bin/uuidgen",
	        "7aa8100438c8073b903ae1ac8f909187d29e5ff0f40a5d834eaa039f9691d73af27a0bfd8910b509bc4ba207c86a8849817cdf0a637e0021a7d2c973a3b73bfd",
	        844
	);
}
static void snarf_hat_846(void) 
{
	snarf_construct_hat("/usr/bin/uuidparse",
	        "7b5dc23513e237059aefb7980e572921b6c769cbc8592615ff240bc45104943d5e51e4a82e95ed7431546e51dfc01690d15a490d2f453b1bc75eb13d5be1a607",
	        845
	);
}
static void snarf_hat_847(void) 
{
	snarf_construct_hat("/usr/bin/uz",
	        "4436698fd6591b8b20af88bde6e7e18ab85b33e8b4a7d73c9a81268a861c3307839716b9ac21dd1ffe6fb2bcb9ad68410cf84c2a11c52f419e25337af4b3eadc",
	        846
	);
}
static void snarf_hat_848(void) 
{
	snarf_construct_hat("/usr/bin/vdir",
	        "2e3117256621b23e06301d334a2c0770fe80846cbe965f7ff13dd40a70e8abe4105e33de88de459ced8da2b98ab79d4a1ac2857626e646a56c5b96cf9a24f3a7",
	        847
	);
}
static void snarf_hat_849(void) 
{
	snarf_construct_hat("/usr/bin/vm-support",
	        "977ed39b2db5aa59896c61566a215c354c8b238a62a3b74c6af3ef6538940d4df25a0f0f65c66b880149cd905023a3097452441366e085f82a58b253c95cfa4e",
	        848
	);
}
static void snarf_hat_850(void) 
{
	snarf_construct_hat("/usr/bin/vmhgfs-fuse",
	        "06eb035b9f3b620bd922a65640a164ca36770496a902728805471bf6687ccdaa551e1f9b0e81bb9eddfa453c9d652e3baa65ececd459e58fcdb48d38f75994c7",
	        849
	);
}
static void snarf_hat_851(void) 
{
	snarf_construct_hat("/usr/bin/vmstat",
	        "d1188e886eee993496ef95d4f97181c83424097be060fe9621d9e0c0681f43b460e2c098d11d54ccd1fe900fdbcf86d9abf46fd311174f842ddd3904474baf68",
	        850
	);
}
static void snarf_hat_852(void) 
{
	snarf_construct_hat("/usr/bin/vmtoolsd",
	        "a88ab763807b2a486903704ddd51aac6a5cf82aa79a3e703d050669a128bfadeaa232961441a8cc80bd8cf091c76cc194925db3a1da57f9f2c6da205d5ec2014",
	        851
	);
}
static void snarf_hat_853(void) 
{
	snarf_construct_hat("/usr/bin/vmware-alias-import",
	        "f4184c60aae871daa9b34311e33a76e16cd50d428e7ec552e1d62df7bba2fee388364c96f70c2d7e469bdc57e423517955ed5d05697f9b123c8bab7d039b4aea",
	        852
	);
}
static void snarf_hat_854(void) 
{
	snarf_construct_hat("/usr/bin/vmware-checkvm",
	        "d0dca9a48ddcd5121c65c3516ac5f243db7b09b2ea17e8efb289d38120b08f3fa77c202c2e90b5b351797b9e977e72c0049bd258060cdd6eb849c4ac7000d3e9",
	        853
	);
}
static void snarf_hat_855(void) 
{
	snarf_construct_hat("/usr/bin/vmware-hgfsclient",
	        "a35462f490f675888806af4da3a306128a86b298a8487f9978fb4c9119edd4ab8ba95675b05f3120530f7972ff4a3a4c5845f9ffc4df5e91c38359a29e12f09d",
	        854
	);
}
static void snarf_hat_856(void) 
{
	snarf_construct_hat("/usr/bin/vmware-namespace-cmd",
	        "37802d199897205485bc453fe2648eba963c5c8efe7eb1e696ba44226737720defbba6cd5be2512c32942a42204af677341b53cbc375e56050872c813ed5a0b7",
	        855
	);
}
static void snarf_hat_857(void) 
{
	snarf_construct_hat("/usr/bin/vmware-rpctool",
	        "841c588f2a8e41c78bacd8109427bf9f069dca40f18b18b69308f2274735306d778ace0f01ba304acff4f2f5b621e02a4f0b1e9cd5a722cd147e896b1185f41e",
	        856
	);
}
static void snarf_hat_858(void) 
{
	snarf_construct_hat("/usr/bin/vmware-toolbox-cmd",
	        "e026b5c6772b8d4f70acfded4d1e11bb95fa9b406e77ac6c67a91a5c162ba815e35477aabc95a95b5a09e48dbb475e60cf245b992231bf7d677741e767a5c2f1",
	        857
	);
}
static void snarf_hat_859(void) 
{
	snarf_construct_hat("/usr/bin/vmware-user-suid-wrapper",
	        "7fd7d93ea4767258cf8de76ea20b3f50bc1bfad88467dda307c19fb1244ca10fd2406e0e83ba3e38403354d4f5ddfc3fd164e18ad9305162af08ed523e051457",
	        858
	);
}
static void snarf_hat_860(void) 
{
	snarf_construct_hat("/usr/bin/vmware-vgauth-cmd",
	        "6faf38afb790e66b8d401572678035a442a6eb21e0dc38aa11fc0497c801bcf1760d70fd253d8e69e41e578af69c7790031042dcc01e9a9184ba20d4ab756e76",
	        859
	);
}
static void snarf_hat_861(void) 
{
	snarf_construct_hat("/usr/bin/vmware-vmblock-fuse",
	        "69280b0689b99bea32404b6707e619c256d4a1102ffcacf9474489adcdf77af00e7dc8634d8219aa569874dcbf7714f332a26d5f4d1ebf2f9c1a3bdad18494a2",
	        860
	);
}
static void snarf_hat_862(void) 
{
	snarf_construct_hat("/usr/bin/vmware-xferlogs",
	        "96aaaf076d89659661a623981093ba483d53163b9fb36553da956d9cae873a14ff9901396da0505f64e01b3dc2d2126b11c7b72db5a2087d317c0bb33bc8e138",
	        861
	);
}
static void snarf_hat_863(void) 
{
	snarf_construct_hat("/usr/bin/vmwgfxctrl",
	        "c6e1577081a098d1b9825bc24a752889b5f004cd691dee81656ab27a7f0d03826ab14f73747c033aaf3f7214a584d7efb7faef0aeb5fe0cf4ac43ac703e16c6c",
	        862
	);
}
static void snarf_hat_864(void) 
{
	snarf_construct_hat("/usr/bin/vncconfig",
	        "167ea86420f5a89ff3695e14a2af77084a52c931bec7f9f8a18a2f6acf40af948728a6a56716f0c172a741893162dad7cfa07a7e629a4dc45447114ff0469ca9",
	        863
	);
}
static void snarf_hat_865(void) 
{
	snarf_construct_hat("/usr/bin/vncpasswd",
	        "e4eb2a8c41c30e82867d1f30285da04ec1387047ee749bc5f92a2bb12bd8123512c007a13fe4ef2a9fa3f59e2aa479e4962cd550e18193869e3442429108255f",
	        864
	);
}
static void snarf_hat_866(void) 
{
	snarf_construct_hat("/usr/bin/vstp",
	        "5138fe7d1f02f0ba7a62fc9e9c7e186324b75449b647666f6c51597d60dda812da63113fc6df639b0ba266956b37222c76b6521def0efee379e921a4f4b01107",
	        865
	);
}
static void snarf_hat_867(void) 
{
	snarf_construct_hat("/usr/bin/w",
	        "01a5e5623631aff887bb26897eb9e25c1dfdfa16fa9c463b2a60668a9bb43336bc27b592b03323c16662ef41cad80008f68af3301c40b8c412cd0092d78b50e2",
	        866
	);
}
static void snarf_hat_868(void) 
{
	snarf_construct_hat("/usr/bin/wait",
	        "9819e32d50c27368c1299699147205650a825b294798ac5382987752ac39ee31b38af4e1dafa73bd0e8299863d7b47b6c87e402122882f32afb2c809e3e8ed0c",
	        867
	);
}
static void snarf_hat_869(void) 
{
	snarf_construct_hat("/usr/bin/wall",
	        "4a81ba7abea4fc87072bc166cd5aa5ce4e6766de59e1b5f199ab762fbadce29ecd1ae691133fbfa976363289ca0641290770bbcb20be6a6f07685b3519302948",
	        868
	);
}
static void snarf_hat_870(void) 
{
	snarf_construct_hat("/usr/bin/watch",
	        "891957d28a6f28ec1766f1a8e6b689da7bc175c9694f6988a3c63c3def4cb002a6f47cbaef166620032312a0dbd01f74e9968cff81ed17abe437723cfaf5c4fc",
	        869
	);
}
static void snarf_hat_871(void) 
{
	snarf_construct_hat("/usr/bin/wavpack",
	        "73db2199604497b278b38e544953e67412e36d9273d70a171466a65e6373df076f128e886750b93e0e55aa35e9d4c4ce59c9b47182d69e2b2dbf5dff3eb31c95",
	        870
	);
}
static void snarf_hat_872(void) 
{
	snarf_construct_hat("/usr/bin/wc",
	        "7233b6d7543c38600695f162961115ec9e98e42af7648ec47d86179cae650003dc43622f8bc9ff8d47b633b580abd8497498ebfd3b3b342fdc5e22d9dd3c74e2",
	        871
	);
}
static void snarf_hat_873(void) 
{
	snarf_construct_hat("/usr/bin/wdctl",
	        "3dd90a8929055d3f108eb3391b418e34ccf3f65e6ec98226cc26d44ed5e0279f2deae2bc03d7d02f17868def954871ee8c4b570b57fcc6dd193b377ee11025d9",
	        872
	);
}
static void snarf_hat_874(void) 
{
	snarf_construct_hat("/usr/bin/westcos-tool",
	        "af37d8adf609109c42b87937f496a188ed6aed7018e7655ca31af43058c3237966b83a0f5e131cab246354531745af9b212cb3f608b723fe1034f4b8114d8532",
	        873
	);
}
static void snarf_hat_875(void) 
{
	snarf_construct_hat("/usr/bin/whatis.man-db",
	        "5d616aa0b65593adb73083a5a9ee336d5ba9de09abe80385eedc9cc81eb258c673d6172549b0d04cad73d5ef62622aab692c3da87bb73a61c3f1e816b5150f3e",
	        874
	);
}
static void snarf_hat_876(void) 
{
	snarf_construct_hat("/usr/bin/whereis",
	        "a45eb2fdf24bd28b2cf40ea4d765e7cdc6cfa7295ab8065acb49ab5aa739ff0f591a40902f64e442e6153d8fa169ef9480f462c31e3ec922a3b9adcfaa804eba",
	        875
	);
}
static void snarf_hat_877(void) 
{
	snarf_construct_hat("/usr/bin/which",
	        "c12894b5c734f6435fa5969219a01c1c3bb3e3bf0e4a164211f5c1beea75215756118188074e70b0858a739e57307f4fcb65c65051005bd881c0440048b25559",
	        876
	);
}
static void snarf_hat_878(void) 
{
	snarf_construct_hat("/usr/bin/who",
	        "ae56699b6c4f43e939e210093519a1ee94090f12a253b74c84c56273ad47a531812ae4e2bc9c08ab2de166cd7ce4a33be9eb15ea3b3a8389b30bc5143523e93f",
	        877
	);
}
static void snarf_hat_879(void) 
{
	snarf_construct_hat("/usr/bin/whoami",
	        "f5ee479f6997c0bb62be8b347dd7e60e1a688b222057fae8e39a0ffa1c1fae3e925f16c1e05edf4be59909d6e1d7a5c24a3d97cce752c87ba5b0fd209a17980d",
	        878
	);
}
static void snarf_hat_880(void) 
{
	snarf_construct_hat("/usr/bin/withsctp",
	        "230788e1fe65acf40652701d5da527bd620ee4f17a9377ca1f5a722a01642c6555fe5ae61605e2a71ec790ffd2bebf23cd2a48a428428410622a65ba5af729e0",
	        879
	);
}
static void snarf_hat_881(void) 
{
	snarf_construct_hat("/usr/bin/wnck-urgency-monitor",
	        "d6ba6dddb1a87b87d0dcf59d5820216b892057b6b2a2a485de6f0833e688faeb8d3a6fcd5308e025496aac6a0ecc154d0e0d40c463c0a8b3aad53019ba879cf6",
	        880
	);
}
static void snarf_hat_882(void) 
{
	snarf_construct_hat("/usr/bin/write",
	        "49e4e4a2d1f09eb80e8644cacc7dfcc036b49382b21a14b9d6abdc77ec426e10dbcbfe2033a66cc1a9d9729129ed31d4e0c1bd9b0b74395c95da95b0c7ba92e2",
	        881
	);
}
static void snarf_hat_883(void) 
{
	snarf_construct_hat("/usr/bin/wvgain",
	        "275fa5816deaa06a6b31745c25ba2b0ac64418665272f14592920eeac0aeb7e8ac8a789235e82e4f56729d48d64e351fd83080e46cf16f7426522e6e4a6bfc00",
	        882
	);
}
static void snarf_hat_884(void) 
{
	snarf_construct_hat("/usr/bin/wvtag",
	        "8b9a259cd4ebd5ae646151335cc0e9e07365b3172eb7711f94096c29982328d6fbb38e6701cbcdcfcb8f155b84a7b41d2507202ecf29d05782bb1966aff0b940",
	        883
	);
}
static void snarf_hat_885(void) 
{
	snarf_construct_hat("/usr/bin/wvunpack",
	        "515a449b52d57c19f82a301f4cddcf27a8f76f4873825429522a5e8cc1b929a6d92746da6ec669f437d23659bbeb8822acf56bb4382b1443c37e401ff2ca905d",
	        884
	);
}
static void snarf_hat_886(void) 
{
	snarf_construct_hat("/usr/bin/x86_64-redhat-linux-gcc-11",
	        "83ae16a2b7379fb66e476b22c2971ef11d006ba640514a64cf9df3256050a2723d9cd2872c8c13a2efcc93f052a2f5515bfac85ae7337c80c86ad2cfe81a7692",
	        885
	);
}
static void snarf_hat_887(void) 
{
	snarf_construct_hat("/usr/bin/x86_64-redhat-linux-gnu-pkg-config",
	        "1b6bad2b6fc90b9a2ea7b9b265716c81a18f0ab799a47e3d5ffa7dc9cd9f7d7dea19688b2251de95e7ef48bbbf3d6cd433ae26d952a1a4204abf401f0a79741a",
	        886
	);
}
static void snarf_hat_888(void) 
{
	snarf_construct_hat("/usr/bin/x86_64-redhat-linux-gcc",
	        "83ae16a2b7379fb66e476b22c2971ef11d006ba640514a64cf9df3256050a2723d9cd2872c8c13a2efcc93f052a2f5515bfac85ae7337c80c86ad2cfe81a7692",
	        887
	);
}
static void snarf_hat_889(void) 
{
	snarf_construct_hat("/usr/bin/gcc",
	        "83ae16a2b7379fb66e476b22c2971ef11d006ba640514a64cf9df3256050a2723d9cd2872c8c13a2efcc93f052a2f5515bfac85ae7337c80c86ad2cfe81a7692",
	        888
	);
}
static void snarf_hat_890(void) 
{
	snarf_construct_hat("/usr/bin/xargs",
	        "8380337421c644d23bc07eec598173b5377e046b28a23cb928fef2103608626ec4d88b6fea0a9b1b95bf200875049ac8bb9abf3782d387baa7685c9e44f44cf1",
	        889
	);
}
static void snarf_hat_891(void) 
{
	snarf_construct_hat("/usr/bin/xauth",
	        "98d96d8eb9ff8b9a82a55ead7fa3f6ce8fa0f0561b50231349f4e3389f035aaac10a45a5308f2c26f165450a373d8a21744fbc04f385207c5d29570bbb7f92ec",
	        890
	);
}
static void snarf_hat_892(void) 
{
	snarf_construct_hat("/usr/bin/xbrlapi",
	        "177d5328627cdffe41de11aed58c082c7838d7e81c729c13785ffa90989109c3c96f7fa3cde801bd1e12a4024016ef465d750bbfd9851a3e0ba3162103f7540e",
	        891
	);
}
static void snarf_hat_893(void) 
{
	snarf_construct_hat("/usr/bin/xdg-dbus-proxy",
	        "c28aedfb67bb20ddd35446fa47bb93ded0aa3cbd8691036b42e5705fe1ad932bf89a9724d6a8dbe85b18bd1755fac57e2c9fda1ede5df51b1533ab4938730b3d",
	        892
	);
}
static void snarf_hat_894(void) 
{
	snarf_construct_hat("/usr/bin/xdg-desktop-icon",
	        "f83e7a05ac37ecaedc411f21ae52944902f792e477ba85a75cd0c670c7fb137c8788cd7bb598eb6ce646a4a7e0ca0819bf207c7137d0fc305dac2f1bccb1be32",
	        893
	);
}
static void snarf_hat_895(void) 
{
	snarf_construct_hat("/usr/bin/xdg-desktop-menu",
	        "4208ce3edd9c8deb9bc2586caa451f2fcd2c3c0538e252ca58c13c6998d736b924b61d7c2a3293e6e1b5a28c8f8e999fed5e7d7dffee6149797532334a22628b",
	        894
	);
}
static void snarf_hat_896(void) 
{
	snarf_construct_hat("/usr/bin/xdg-email",
	        "7d56fbb3cd6c5c8fe4994869540c83aec34dc003fc1b589f19aa0439d52910a37607c5ff531b23710aa0244b6117f59f1821fad38cc9b35908b1a963300aa275",
	        895
	);
}
static void snarf_hat_897(void) 
{
	snarf_construct_hat("/usr/bin/xdg-icon-resource",
	        "33e3471e8033022b517b6503baf4bf4df7385989dbf0751395a53e2c975cebe2ff7ff8ba503d570dc7b19edcf543192fa387bcf73801e64f5a5b03c517f8fc9a",
	        896
	);
}
static void snarf_hat_898(void) 
{
	snarf_construct_hat("/usr/bin/xdg-mime",
	        "41bb1439fd69af1ce8e5feaa4cca649858af2c9912980e7e39df948b31ed7016ef734b60129c545fcad8023527009debf1250e424b12f0a49fbdd19f6f0c9d19",
	        897
	);
}
static void snarf_hat_899(void) 
{
	snarf_construct_hat("/usr/bin/xdg-open",
	        "c5073086f73cc439124862b2d3ab372b66f86f76e9a89f425718279a61aee87e5100a95850894daab9df8dca6f81e2d92cfb5aa3be77c41d175d12bb462afcac",
	        898
	);
}
static void snarf_hat_900(void) 
{
	snarf_construct_hat("/usr/bin/xdg-screensaver",
	        "1a76d4970aff5d831c90caee54770186a7cf5ca84818150d172c4c1d3858c2d638c39cc242e29a5cb212defed5d01bd6261d66f6de383efb3878518215803a50",
	        899
	);
}
static void snarf_hat_901(void) 
{
	snarf_construct_hat("/usr/bin/xdg-settings",
	        "d876f11bb1b6dfadb68cc889f8a80e7739f0e6665ddc48bceebe0badd0b468faf0e3a92b966e6d51ddaf24ab3dda29d47e1de035d3a3e1dceeca91a7828211d7",
	        900
	);
}
static void snarf_hat_902(void) 
{
	snarf_construct_hat("/usr/bin/xdg-user-dir",
	        "364cdc6af6e327a9e17058c1aede77ae571367435dd9c2c3955ed5cc9efbacebe1ecca876be54a747e705f41efb829901f55e2de4bcc285bcc07f8723966356b",
	        901
	);
}
static void snarf_hat_903(void) 
{
	snarf_construct_hat("/usr/bin/xdg-user-dirs-gtk-update",
	        "307c6d2a99dc2c26c0e14e1ac56fdb9d7f43aaa40a0beb6e6c003ef1d856cde39ab654ada59d3db7226ee07ea6c1ebc11f439ba6c8465023ee997e8a68ea27a6",
	        902
	);
}
static void snarf_hat_904(void) 
{
	snarf_construct_hat("/usr/bin/xdg-user-dirs-update",
	        "d5000976652994ef75c0d54fcb07963e246ca92013a99711e1ba7340ba596e749c03d3a680e3d11e01301b9895ae26c125d404f87dc3af4faf291ac6e7021a11",
	        903
	);
}
static void snarf_hat_905(void) 
{
	snarf_construct_hat("/usr/bin/xdriinfo",
	        "c90fa33cdb3509e84dd85f3ceb0bf7b65f58f2f71ed35d170c538ca7b5fdf3aa8e258949e4ef453bd94a3a1f30c21cc41845ba58f93bfe3841c956d3ae99f43d",
	        904
	);
}
static void snarf_hat_906(void) 
{
	snarf_construct_hat("/usr/bin/xgettext",
	        "16f8c728e09565724e7b79d55a635773a9a80aef92ec23b14b7f5bc495de430d7d5c678ad3b3293dc0be37d6458fde4d1be84b54f7e66875a682e73a5a987aa2",
	        905
	);
}
static void snarf_hat_907(void) 
{
	snarf_construct_hat("/usr/bin/xhost",
	        "93f0986421b9107527d79af3c268e6eaf3db0d9b265eae2d9265a3ba8c576bb5e3921a537181e7f9cf99addbe711018efba06a1b35cd4a96742fcdea290c1a94",
	        906
	);
}
static void snarf_hat_908(void) 
{
	snarf_construct_hat("/usr/bin/xinit",
	        "38f39a5958aeed2a78f8b29eb692b0120e5a780e71f410d958a010636e98748d29676041ea81a58300f037735659e11035960c5e658b4be665ed2a58fd22c7af",
	        907
	);
}
static void snarf_hat_909(void) 
{
	snarf_construct_hat("/usr/bin/xkbcomp",
	        "44d9ea717bc1de691ab46f642e859fe7799a527b0c6817b5bf32d2c37120db535ec8621e28210e7f1ba2f68af4c1dfa33bff319bf2ba5bb6ea208d9ecfa03876",
	        908
	);
}
static void snarf_hat_910(void) 
{
	snarf_construct_hat("/usr/bin/xmlcatalog",
	        "29e5d484aa66cf5350406837a61d746156ed9d4d87f2c3c4f7ce51529b928bfb2d1f613876acc2b3132062cd3306baab3acf651541775155b2493fff6bd0c9fd",
	        909
	);
}
static void snarf_hat_911(void) 
{
	snarf_construct_hat("/usr/bin/xmllint",
	        "b87851cddaa364db4a132672fbb784c72a23808f9c12a0edfbafcd2225f0f61ad6cb72f133aa943cc07fde30255e28721d632332b69ef94b587345d51392f612",
	        910
	);
}
static void snarf_hat_912(void) 
{
	snarf_construct_hat("/usr/bin/xmlsec1",
	        "2fa129dd87d12a5dbf17f34b0467449e947e43cfa94edd32205b052aa243a569d4aeed23b88db9e6074ad2dcc70205e3b8b3295c9f4579fe8a48ba60a21996e8",
	        911
	);
}
static void snarf_hat_913(void) 
{
	snarf_construct_hat("/usr/bin/xmlwf",
	        "222633c835bd6563ab241125c74b303f0f1374e46c56a695b1234fd64d24acfed576bb2a33d570c64b72d974516be5c405b4ee6a71b189fc5e8e345dc160b1c4",
	        912
	);
}
static void snarf_hat_914(void) 
{
	snarf_construct_hat("/usr/bin/xmodmap",
	        "cf026d69079fd5289fa7ffe7c14b0d5762fc5e0a2a69931e00f5ee09115b4211377aaae0199a66cd1f24c88042a8b0c64aa900f8c5465bce93270f7eb2ecada4",
	        913
	);
}
static void snarf_hat_915(void) 
{
	snarf_construct_hat("/usr/bin/xrdb",
	        "1b68b1e4eb3bf232db81548146cbff2d39b3e3c3513f8af326c40e8429c10817efb9a49ee79f12d931f034bdc08a9bfa72594b89043ff6cdebe7bc1063871823",
	        914
	);
}
static void snarf_hat_916(void) 
{
	snarf_construct_hat("/usr/bin/xsetwacom",
	        "6f897eec3149d8eb8a1e40582c92df8a9a6efd55730dadcc8d91cd6ef03e1c388415d0dadeb5e2a04a8ba910c975fe5664cfbe491d271046829653c1918ec05d",
	        915
	);
}
static void snarf_hat_917(void) 
{
	snarf_construct_hat("/usr/bin/xsltproc",
	        "b0d2731bc02310ea502219563e56d5b388bfefb1819236c4e85f5ecbfdc68533e948ff4ed9550312d36c8fb0a49001152eb07fceae930f17757de3d3c32dc4d0",
	        916
	);
}
static void snarf_hat_918(void) 
{
	snarf_construct_hat("/usr/bin/xz",
	        "715f6f3419b0bf1c9330ec151344ca44e9373b2323374b7789a04c29dce929c24fa3b9b400859668bb6bb25e5e551536e6bcfbf003965140b87c076212f69703",
	        917
	);
}
static void snarf_hat_919(void) 
{
	snarf_construct_hat("/usr/bin/xzdec",
	        "350e2230cd9369ef313d55ba3850f10eb48be6550e2b5ad5bcfa9a9fc8d5203044b901fcfd158908b685dcdfaa2b127e3250bdb7b4c33ec761866d2feadff4ba",
	        918
	);
}
static void snarf_hat_920(void) 
{
	snarf_construct_hat("/usr/bin/xzdiff",
	        "592faa3f577e31948a24dbf05f9b30a78027a4b099869b004e1eec464a67c5596e69b582f26e340aa0add14ad9eb74595d9a8d9cee2e998bcf0e32303d0f1f57",
	        919
	);
}
static void snarf_hat_921(void) 
{
	snarf_construct_hat("/usr/bin/xzgrep",
	        "ddef0fc2229602309faea26ab96eb208162838ae47266f7864ce483674431f35bed14393fe09783bdd55e21b479dc0408348085cda415342e2e55c6a455c4ceb",
	        920
	);
}
static void snarf_hat_922(void) 
{
	snarf_construct_hat("/usr/bin/xzless",
	        "b4fe7448f2e7a1318aa5882af3e947148b13d89537843105c63e4ca80bcd57af9dc420445ec7e76ad1082e110927bb60e40c2887c4c81f9e5d01aad6afbf228a",
	        921
	);
}
static void snarf_hat_923(void) 
{
	snarf_construct_hat("/usr/bin/xzmore",
	        "751a3d72be38e4a5e346103edc0dae483009de7bb6bca81ed20d94357c71a1b910290a14481a12534b3cf204b4f929bc9cdc4c424d74702ecbf021a32e7dc5f3",
	        922
	);
}
static void snarf_hat_924(void) 
{
	snarf_construct_hat("/usr/bin/yes",
	        "cfc4f294bc7d543f016e1f8d4f598da059d0bfb264dfbd69f62f0dd0d3eaec2424109493ef534ef7f3c31541fdd48d91da51120153ef4b0c8ca407f5ce906ec0",
	        923
	);
}
static void snarf_hat_925(void) 
{
	snarf_construct_hat("/usr/bin/zcat",
	        "73a3d2fda5949aa0fb8ec1e6d211c5562e9a5b14400dbab965b949fe117a3bb3bfe05bf09bd30f9f1b9886fe1e97c7cd044e54900ea061918dbb68237dc1a207",
	        924
	);
}
static void snarf_hat_926(void) 
{
	snarf_construct_hat("/usr/bin/zcmp",
	        "936c9db71bf9254ef4d1c7ae38751c2d4a5c6e153ae259b9b6b86c10b79c0895f60c19d84e057327e541a05de5b8366506cfbe965c9462412fe4ca817ec23c1e",
	        925
	);
}
static void snarf_hat_927(void) 
{
	snarf_construct_hat("/usr/bin/zdiff",
	        "ea940832770e07ea05b12b2c22c37c58b72f1bda0efccbabb68119a3d39c102e58f27d9297bca71ebe126e5dde40492ab4f91de08576f64fa5c689c3ea62a711",
	        926
	);
}
static void snarf_hat_928(void) 
{
	snarf_construct_hat("/usr/bin/zegrep",
	        "ddb4b75d4798fe8149f7c5ee38c89f5330d3ba3578269486e1a7b20e7c971a4838056b446c2544b5172afb6e7141267f231fd3c27f6a64546be717002c399186",
	        927
	);
}
static void snarf_hat_929(void) 
{
	snarf_construct_hat("/usr/bin/zfgrep",
	        "454f43db55b99a004c78a2f7607ad7bee5161602b6b4f6080b8f43a0ae387ac798bd7ce64c7a36284a337e3626757b3a9170f8b116ab2b50b30c38e3f29798b2",
	        928
	);
}
static void snarf_hat_930(void) 
{
	snarf_construct_hat("/usr/bin/zforce",
	        "00d26f9ccd38e78d5fc2793f34cb1dad84551a82f4553f626d55c206489a376ddd397e52e2a3570fd6c318d9190fafd07e92b09bfc096ae23419667c9f894e6c",
	        929
	);
}
static void snarf_hat_931(void) 
{
	snarf_construct_hat("/usr/bin/zgrep",
	        "3e7b9364f8549b6bb69b52b6e4983628b0e27bb5725cd5fdbfc46baf40c58011021d539dce2ef3a5c69911a02e81db60945a3cc5955678b979d099cbfa7a3cac",
	        930
	);
}
static void snarf_hat_932(void) 
{
	snarf_construct_hat("/usr/bin/zip",
	        "6e0d5d8b1f402d6330e84ead930a09ef09aafd824b6792e5b89c604b8f22903ac63b781acd717fd0d80aafa4a297dbfefc6a07024aee450ed5b272ea72088a0a",
	        931
	);
}
static void snarf_hat_933(void) 
{
	snarf_construct_hat("/usr/bin/zipcloak",
	        "bcca6b32a6fa4e487027a19a24c5f20971f9213329e45bd98e77fa9c38892313b2edb47aecbc73e047596060b260e74b6c8b0278e055587eb8a3f375caf3e19d",
	        932
	);
}
static void snarf_hat_934(void) 
{
	snarf_construct_hat("/usr/bin/zipgrep",
	        "ebfca9a8d7a00e57ce2474f0eb3c60a7765888ae1d1d93af3e74e468bb7ab4fed86606b1279aad063e563d3187335454cf80a1dc517d66952bc0566fad7a0ea4",
	        933
	);
}
static void snarf_hat_935(void) 
{
	snarf_construct_hat("/usr/bin/zipinfo",
	        "506b4af6d8e8f2961c95c153101121dd055b02f1d9b4ba2dddaa4ccf7cc18649f1731ce9591efd3346d177740688197b137a59a649f53b820c093d2d27d757a2",
	        934
	);
}
static void snarf_hat_936(void) 
{
	snarf_construct_hat("/usr/bin/unzip",
	        "506b4af6d8e8f2961c95c153101121dd055b02f1d9b4ba2dddaa4ccf7cc18649f1731ce9591efd3346d177740688197b137a59a649f53b820c093d2d27d757a2",
	        935
	);
}
static void snarf_hat_937(void) 
{
	snarf_construct_hat("/usr/bin/zipnote",
	        "9a0535f811616c3fcf6230d7b8013edb2d0dcaadc9ed8c2baf3bce40fe849aa9905f1a31faf833e34ff37ac78a69273c44c8691826bb11236ef4e6e0df6ba6bd",
	        936
	);
}
static void snarf_hat_938(void) 
{
	snarf_construct_hat("/usr/bin/zipsplit",
	        "680615f29197a5988e2b7a88a0ce2be8806121d21f6e212ea8d89e3e000f6e56394f7ff25b7302babe59f9764895c71fc1585f3426bc0d97f64d29030a8c584c",
	        937
	);
}
static void snarf_hat_939(void) 
{
	snarf_construct_hat("/usr/bin/zless",
	        "2cbdd581a4f0fb59a6470fbc9c3c6f210042a574fd2aff13eeee768f45af5b0803621c3652050c450f557893997477f95cb170eae0c501b82f1bc64d09bcd8f9",
	        938
	);
}
static void snarf_hat_940(void) 
{
	snarf_construct_hat("/usr/bin/zmore",
	        "f4e3aa08bfdf583bf0e81c25120f058bd72ceff12673f4b3a5b6ae91a1a8f392bd3c2bff2e661d3b3e6805724c8ebe64a47eec237b98badc8390de0e376bde42",
	        939
	);
}
static void snarf_hat_941(void) 
{
	snarf_construct_hat("/usr/bin/znew",
	        "9ad44a3e45869bcbfc96b147346812d532ab7248160fc779a2e137069372a671fa822bab43db869eadb4a692bbf440d637323154c05b76fb445bcc85b7d97c34",
	        940
	);
}
static void snarf_hat_942(void) 
{
	snarf_construct_hat("/usr/bin/gtk-query-immodules-2.0-64",
	        "831a9f8c1eed987c39c028e13b2071f1d02fa9eef507419622b6a32752926380debc31849f588f962056acb58a1d9cb15db6a2867ebdaeec9d028593159868ef",
	        941
	);
}
static void snarf_hat_943(void) 
{
	snarf_construct_hat("/usr/bin/update-gtk-immodules",
	        "b69f9be692b8f8f358914094271a1ece10dd148f5fac64b03796c710986031ee9b1c5d6288bd1e9a9ea2667278712fc12455ebbfd85d0ecfb30322c94065034d",
	        942
	);
}
static void snarf_hat_944(void) 
{
	snarf_construct_hat("/usr/bin/hwasan_symbolize",
	        "0c08bcfd50b5bdad049a8dea81db7f6ee0097352bac4bb7b85abf66f28161ed8b7bc2eabbe9dad53aaae718d02c8410c9d724dbbb9596d4290e77d151d7b3ca5",
	        943
	);
}
static void snarf_hat_945(void) 
{
	snarf_construct_hat("/usr/bin/ibus-setup",
	        "fbd95b7cfc566152340c22720a597db878330f81afbb41b6b30720730c3b3ac003192d6c6af7ae667af08b8861245f5131af2379d72644fd4c840fce22ffe7ad",
	        944
	);
}
static void snarf_hat_946(void) 
{
	snarf_construct_hat("/usr/bin/ibus",
	        "4b04e7910cf8590bb589f27231ebf1a1ae68947b5b852baca646addcb3ac91e3a7f40942dfc62ee7f5e7c8d18c6d29d3188611bbef32393b12e46128c04df568",
	        945
	);
}
static void snarf_hat_947(void) 
{
	snarf_construct_hat("/usr/bin/ibus-daemon",
	        "59f3efa8cf582380f8e64ac9306624cdf090d268fbd1b200b0e7af400f0c56a0fb1f5ba51d69ed3154574e24b65cf71f71dabc1b9a307bd75352cbb29b7b28af",
	        946
	);
}
static void snarf_hat_948(void) 
{
	snarf_construct_hat("/usr/bin/gts2dxf",
	        "ee0e247a05051ee2719457ca22a79761e74140e3e33bbe7b26203e4b881adf1465639c85411c14d0572976c77901b7fcd49ecc6f7ddc3acd2081d23433892dc3",
	        947
	);
}
static void snarf_hat_949(void) 
{
	snarf_construct_hat("/usr/bin/gts2oogl",
	        "1307fdf5427197a3fd55bd6523c07ff063999853c39842df1ce8e42ec63d1594e030a67f63079638f5d47b1aba449af1a766805faf1ffe402ecdec8a20bf931d",
	        948
	);
}
static void snarf_hat_950(void) 
{
	snarf_construct_hat("/usr/bin/gts2stl",
	        "0a096298a3cbb2aa95511758d434ff756b3870a8e01b9a4700a45ef2e94b920222d1117ee17e592b3ece68995f4f68e72d2985aacdcb280fd599b59ead4387bc",
	        949
	);
}
static void snarf_hat_951(void) 
{
	snarf_construct_hat("/usr/bin/gts2xyz",
	        "e99dae2900e6e155bdc9501784e20e61550ee1a295a08e95eb93050d12264aabb2485b48e19aca2273fbfd319b8fd8a6878d43bfbd72e78a6e01b6ddc380ab3f",
	        950
	);
}
static void snarf_hat_952(void) 
{
	snarf_construct_hat("/usr/bin/gtscheck",
	        "8b5c14fcd5d5ebda69c45e1f320c358f0b0f515b8f456ac61b8d6630094996e36d5a09471595015457ea9b9b541b479bfb8de5461b64a36860767693599398c9",
	        951
	);
}
static void snarf_hat_953(void) 
{
	snarf_construct_hat("/usr/bin/gtscompare",
	        "e597ac16e50bf732c43ad10b2757058cc9f9be091b94a1538214d9f7de1744267b5f81bebd24c4b14f7a5de0d11fc87693d06be239399aeaa01f1620c10e837e",
	        952
	);
}
static void snarf_hat_954(void) 
{
	snarf_construct_hat("/usr/bin/gtsdelaunay",
	        "4512caec9fe9747f32e45adc5399527310ec788abf2bc4c82117150b9254f53eae962da1fd85cf8311039177915f8f52e6e1d3e2e165f9ceba11cce80bbbb03a",
	        953
	);
}
static void snarf_hat_955(void) 
{
	snarf_construct_hat("/usr/bin/gtshapprox",
	        "4c0c1e2d3b04eb23041a3c8c64fa2620ea0a5e4dcbfb8b003d2b779b2f071a70c43b56f1c9dcde2c5c70a1d1384be08e469aa03ef440539da359db65d86ebfa9",
	        954
	);
}
static void snarf_hat_956(void) 
{
	snarf_construct_hat("/usr/bin/gtstemplate",
	        "b08ee801715f45f005f31c7590596d5add36fbf8bf7a76c7652e4b020eb6bfa6c529118e21f14a3b49b4dde6c7fbaacc857578e25b3f1a3fe53b6cb5c1354d39",
	        955
	);
}
static void snarf_hat_957(void) 
{
	snarf_construct_hat("/usr/bin/gtstransform",
	        "9787506ebaadb471ce8c7c202069ee57290c1d4c9ca9a2b13fb59d9a6b66b8811da80dfbed3ac3488daec08b28b9f5b7eea35ae210525d65874f68da22afafa9",
	        956
	);
}
static void snarf_hat_958(void) 
{
	snarf_construct_hat("/usr/bin/stl2gts",
	        "80b9248a156ceab5f8ee60ae8aed84861495982602439dec3cf47f48c3734fa9fcb288e2b75d61df875c71be1e9e2df13061b09b2c86a9f4b8517c20b0dd02db",
	        957
	);
}
static void snarf_hat_959(void) 
{
	snarf_construct_hat("/usr/bin/mkfontdir",
	        "72bc647b2df776e51511e4a32993632b79de6e274b5f1092f9819e3037c1c8bb55271e17186435031fd174457151daa80e0dea22ce7587a439110d2fb7a7e99a",
	        958
	);
}
static void snarf_hat_960(void) 
{
	snarf_construct_hat("/usr/bin/mkfontscale",
	        "951e5aeaf66ee20381b852a03343d2d6cf2dbe0541b0ce5f32b387f4458bcc465ee8761c981c577bf3317f735d8022069047a8cd3019d8ab211d83bfa6058aeb",
	        959
	);
}
static void snarf_hat_961(void) 
{
	snarf_construct_hat("/usr/bin/acyclic",
	        "b0449bde4a3100712fc00d9b0f9ac48bb5f8d65ba612e4cf417fd45a2480e1ad45a7896e0830e479a92bb332e4a740205bf51fbf6d6a59f5f033a5aac660597a",
	        960
	);
}
static void snarf_hat_962(void) 
{
	snarf_construct_hat("/usr/bin/bcomps",
	        "ce711a36ee50411467cd51b03807d2965bb7b53cb4f07aefd2a13ce63216b68be7e9921a4a680a818c29711f2c5044606647c0ef7088471eb742c7f9d8ea93cf",
	        961
	);
}
static void snarf_hat_963(void) 
{
	snarf_construct_hat("/usr/bin/ccomps",
	        "02bb934b0185db8642952e3ebcd2a80413076faaf5a2893ca07622e7d7dcf7f061c44c6d20a5f4e310f4802e92e94e8b6cde4de6c906f0f3dbbef5d7a1d26e5b",
	        962
	);
}
static void snarf_hat_964(void) 
{
	snarf_construct_hat("/usr/bin/cluster",
	        "e930a1a233e438adacd9d54284d17a8565940fcbb2e21e1a43244844546df123747bc3c46317b3fe4eb6491af178e74460e903648759bcbc25c7240f49e7c009",
	        963
	);
}
static void snarf_hat_965(void) 
{
	snarf_construct_hat("/usr/bin/diffimg",
	        "906d244246445df8081a9205a79a687b5e8ca8b9368cfb081f1f15330a1d8fd97ed574a1a5e88bd830a024857f1c6ab2bad510d0c29e2c0e6e1cb6a1165544bf",
	        964
	);
}
static void snarf_hat_966(void) 
{
	snarf_construct_hat("/usr/bin/dijkstra",
	        "2257feaa0678efaa3b97816dc3e33d196b05a5d526d3c67933159899d648bbc8d9623fe15d7c69fc3be01cf65357f4619d0f414eee91f13caeed4bdd8f3de0e3",
	        965
	);
}
static void snarf_hat_967(void) 
{
	snarf_construct_hat("/usr/bin/dot",
	        "1902b6da14683a1ef1880b6b9a97f7145ae5c6802a6488f12e93671e6e2d0a6a5ab5a579a485995276e1875d46aadfc361e7ad29ea0554f1234594e2e36c1899",
	        966
	);
}
static void snarf_hat_968(void) 
{
	snarf_construct_hat("/usr/bin/dotty",
	        "73fbb5347cf508d010b39fd2218d4cffdc3bbdb19de1ced58035b6e3703c66491b79ca5ce24bedd3012ae854b83ecb6cb41209864849054a67d63fdb4e0a91dd",
	        967
	);
}
static void snarf_hat_969(void) 
{
	snarf_construct_hat("/usr/bin/edgepaint",
	        "dfeb0109069ed11776a84b2bf68d5715ed49b293e0f52d70422bc37c4516699ad3eb531241b568979e24a5f47a6a4a8a4e43a24ca60930434dc00a083a90b5b2",
	        968
	);
}
static void snarf_hat_970(void) 
{
	snarf_construct_hat("/usr/bin/gc",
	        "93f5f8a9ec24d54b07a109e623c020fb50df02108b05eb74696b3e10b790ef5f01d17610c021b58038ef3e0c5265ee90e3ede5ad0e4903e155499be16488ee47",
	        969
	);
}
static void snarf_hat_971(void) 
{
	snarf_construct_hat("/usr/bin/gml2gv",
	        "2da14def8020e0fc4772d0f24c7b98cd984360323731dd4744046c3a2a23571a49f9e60f8bd3a57b50d41bda966db7b623e659b0e6f3826269c0ec15227f4ea3",
	        970
	);
}
static void snarf_hat_972(void) 
{
	snarf_construct_hat("/usr/bin/graphml2gv",
	        "0ac7b8b91f00edfe494051c66e063b6e8c803b7c05dc40ef44c8fc6134c153e545b2b73e94087bd5ba11ed44b138bf12eab9242829d7797d7839e0205c9f5f11",
	        971
	);
}
static void snarf_hat_973(void) 
{
	snarf_construct_hat("/usr/bin/gv2gml",
	        "98ca009a8dc60e9aab2756f2dad2457e95b22c3caee0d71a225e89304e11dc6688a6f1df13c60346edc5fbc996592a3bc2f6059f5e7473c7b650219f55f169ad",
	        972
	);
}
static void snarf_hat_974(void) 
{
	snarf_construct_hat("/usr/bin/gvcolor",
	        "bdccacf412f52458dd8ff27c79f292e58e3edbe550e9c14d80695c5b467fc3ba6beaa15f88d216b7b14b61f64c1fafd81d7b7e232eeec769a18542407feeea96",
	        973
	);
}
static void snarf_hat_975(void) 
{
	snarf_construct_hat("/usr/bin/gvgen",
	        "204883d43ddec9066862d1cfd5769c4e44b0d7970936b196c53fabf6df0ba9d0bc4ec0b13b7e86dc7b62547ec33c7ae7df6e1cf2b2906bc8c2ecf38e926f1748",
	        974
	);
}
static void snarf_hat_976(void) 
{
	snarf_construct_hat("/usr/bin/gvmap",
	        "ebd2060d7bcfe58fec13d59f2cea6205415ad77d86d6a157f37b40cd13d5997b8189eac93042be9cb51df71afda7eb53c8a71ec15e0c85c9dc325de8ebe19e79",
	        975
	);
}
static void snarf_hat_977(void) 
{
	snarf_construct_hat("/usr/bin/gvmap.sh",
	        "9fd4b6198903c250e4fc940c07ffa99d99fc85a36192f318b41b4e0481846b8142dca217a39ff0157cad2d590020513eb637cb11a0f166b6616587a4eb15da7a",
	        976
	);
}
static void snarf_hat_978(void) 
{
	snarf_construct_hat("/usr/bin/gvpack",
	        "806dd5dba30240d49496b2ea8fe9331a46d0f094cd1219c72c749dc99c17d1e71642180a9161849866af72b0aa682b8246f3d3dca6fe1c534009d5877617fe06",
	        977
	);
}
static void snarf_hat_979(void) 
{
	snarf_construct_hat("/usr/bin/gvpr",
	        "4b8c6ad9d4e1685d74d691cddb78135fc27526ffb3903497db5f7acdc121645883f578c5809f5f5ff5adbedfd3d8d237539c871374da0a4f0c27a0a0383e934d",
	        978
	);
}
static void snarf_hat_980(void) 
{
	snarf_construct_hat("/usr/bin/gxl2gv",
	        "4d467029543f53c788a1aa0cf88b8b1bef315b0397ada2e4d9c196b6641cc1910288657ae8935fca4783c0a80b0cd710558b4fa23e5a991feb2e491feb38cd22",
	        979
	);
}
static void snarf_hat_981(void) 
{
	snarf_construct_hat("/usr/bin/lefty",
	        "19b3399d462b075a4e25ab7ce674b7b5572f230dbc71388ac4871557ad6c9054969d7412b3a3109dfd55b89bf83cded21b8d0c1429850531f94dba03beff0cd1",
	        980
	);
}
static void snarf_hat_982(void) 
{
	snarf_construct_hat("/usr/bin/lneato",
	        "313a19289c5c8aa6e461b1edfb611671a1ad36822ffd679d226ae6678317d1beb78a75da6a75a650fabdb257b5f5832344cbd39bcdc48355ac65be70099d2319",
	        981
	);
}
static void snarf_hat_983(void) 
{
	snarf_construct_hat("/usr/bin/mm2gv",
	        "50f61b843368ca98cf98e54e6810f9fb8641e55e8f636dd44e3f0fee70d67b65f9ab1e68248389c26bb07dd6f5a307c14a55b122926243754cb8bd11ad246845",
	        982
	);
}
static void snarf_hat_984(void) 
{
	snarf_construct_hat("/usr/bin/nop",
	        "562bdfef600261d645052f562a95e9c62e0f06450664feec8a787a10150859a949d9f476be4f43c0d30fa2a5236d399987f4c121670a95e425ad5b0342127ad2",
	        983
	);
}
static void snarf_hat_985(void) 
{
	snarf_construct_hat("/usr/bin/prune",
	        "c7395d4720e3bb0f7861aa22d5324cb2fbf27f640ae96f41e39d2817d9b61bb4197fdfee42141716dc2ce48e6280cd44dca1364bd7c46789c4599d7ece229e49",
	        984
	);
}
static void snarf_hat_986(void) 
{
	snarf_construct_hat("/usr/bin/sccmap",
	        "9139032e035bec72b297411981297516fa06250733932129c4e77569663110f80544568e0324c4ded4b4bb29631d08f4df1b97d86945463745089954283f31de",
	        985
	);
}
static void snarf_hat_987(void) 
{
	snarf_construct_hat("/usr/bin/tred",
	        "c263dd2ffa3bfa8bfacbd4bfbed6031d6b465e2e2c7b2429092135a2c8ca8bd546e86b1dc52146e679e3e5e74840f12f75d75602428282cf765ad25f77689ca0",
	        986
	);
}
static void snarf_hat_988(void) 
{
	snarf_construct_hat("/usr/bin/unflatten",
	        "2c88af855d98257f66255bb9ee283de53c399212926812915ee01f81d0afe7dbf0d01d89d61d2e92fc074d9e6f25604f47a9275a0de73b8f3bc82674e6f2415c",
	        987
	);
}
static void snarf_hat_989(void) 
{
	snarf_construct_hat("/usr/bin/vimdot",
	        "622e4072ba379c4ff9fc6d98ed37e5f1e8f805651f5c82cb2407fcdacb92daa54dbedcecac428b5ffb65da7adb9e8be1e09f33f42ee9a568d21bad1a13b509f0",
	        988
	);
}
static void snarf_hat_990(void) 
{
	snarf_construct_hat("/usr/bin/info",
	        "3d86e728988ed159332acb4b38aedbed2b56fe8449ed5cfd9092352e7e8103cea2e08197b6ab4b8551c566cccfab2341f291cae9963ed72a79a69107db684cdc",
	        989
	);
}
static void snarf_hat_991(void) 
{
	snarf_construct_hat("/usr/bin/ed",
	        "0960cb2ebb7612d8253bde67b62d3a73066fefa12456c2b583e9689162eb9c49f7d07962fd262852950da6b84eba306dd86a38573776be1c4b97bd003facf2cb",
	        990
	);
}
static void snarf_hat_992(void) 
{
	snarf_construct_hat("/usr/bin/red",
	        "f9b6bb52a5168a6bb59e7466aecfc34695496331dc9040a25efc22e26dc9942a728e59a89f7b7377e68d5a7a83a107686f7168d108d057da292d4e881c91e555",
	        991
	);
}
static void snarf_hat_993(void) 
{
	snarf_construct_hat("/usr/bin/patch",
	        "de02e5a0da8683b5db0bafd5b686e4a988c72f13cd573f76e03b38abeb629da9277eba7933f0d52db9dbfa5b64b16eb7c08dadad1c62d17fb91063fec2e98e1c",
	        992
	);
}
static void snarf_hat_994(void) 
{
	snarf_construct_hat("/usr/bin/stap",
	        "3a9f2ed3f8cc5c9ecaa42d8ac415c6fa5f399d151ed15d2045010f7be05c916e4da234315b4481fe6ec3aacf0d712cc1db631370b6efe1d71274e2c7a5551685",
	        993
	);
}
static void snarf_hat_995(void) 
{
	snarf_construct_hat("/usr/bin/stap-prep",
	        "bb04b21ac9869657bf99e8b5c9eccba0db9a71870270614e5be6bca0744f233e9a0d9874e0078e41cccf3c137262e3451460d62bc9fb43c026ff25807dab0e1c",
	        994
	);
}
static void snarf_hat_996(void) 
{
	snarf_construct_hat("/usr/bin/stap-merge",
	        "4fc8eb67908c625d065d9e2efd3fe091670cc19fc497f45dc963047d48ce153a74735e9433e74960a6e2e8e38094dcae2846a6f502d6e7f455c0760ebde10959",
	        995
	);
}
static void snarf_hat_997(void) 
{
	snarf_construct_hat("/usr/bin/stapbpf",
	        "bc49ddf36d5a0393e7f0e4b28d3410c3f0802efb93a5e75f7c9b8e16388d7dd2b261cb1d5dae61e3e3af065acac98aed77bcbaf6420331f9422d29c498e80acd",
	        996
	);
}
static void snarf_hat_998(void) 
{
	snarf_construct_hat("/usr/bin/stapdyn",
	        "a155e85c03a2a6434fb286748bcc3b9261e6d0b111324a383a53d2f88d96bf4aa4beb7951558e2435e575a711b4d456284506e6900f6d1d7697847890b19b2e8",
	        997
	);
}
static void snarf_hat_999(void) 
{
	snarf_construct_hat("/usr/bin/staprun",
	        "9f6fa3082664b5d68729d05f425e0357e36eff424b4cc035c96af7c5613faa967f44916f08721c2ee2c7121db98239d18526597981bf31a9a88e5278fc9d7e90",
	        998
	);
}
static void snarf_hat_1000(void) 
{
	snarf_construct_hat("/usr/bin/stapsh",
	        "f13b5e7cc1091c33cea3ec02eca700b6f615b78b687e81f6816b97a26c0d79a303ca7d9f22ee7af1493509c3b2475165c726949f2cd1a1c6c9ac88edb8fb1769",
	        999
	);
}
static void snarf_hat_1001(void) 
{
	snarf_construct_hat("/usr/bin/stap-report",
	        "92832346792eee5a03a8f665b5d1147fc6f275d83b72a488b4409b88e37a06466173d51cd86f54853ff8b95729bf9af6ffc67e976e08ef9db3741bfb7957da1d",
	        1000
	);
}
static void snarf_hat_1002(void) 
{
	snarf_construct_hat("/usr/bin/dehtmldiff",
	        "2bc36bbe03207e05400934b188030bfe66573eec981dd823373e5a93db88e956c75abdb96bfe1071212b12bd7a4a6c418c8aa5e0b22befd1c85f3f4ac5bda1bc",
	        1001
	);
}
static void snarf_hat_1003(void) 
{
	snarf_construct_hat("/usr/bin/editdiff",
	        "1c65efe97a1208173b91fc200155d3b661e22aad48d79641276db021f7c907a186134d91caecdfee546eed73a4c7423337e189162870b45527c59a1183632f29",
	        1002
	);
}
static void snarf_hat_1004(void) 
{
	snarf_construct_hat("/usr/bin/espdiff",
	        "c5852710ed1cdeb73bc66b81d5441d31c8f343c5c1e35621489be5c31a2ecdf4b94c993126087d6367c63555979b50b444d4839516eab21406fca247627e9599",
	        1003
	);
}
static void snarf_hat_1005(void) 
{
	snarf_construct_hat("/usr/bin/filterdiff",
	        "40d5e07e320e766f6a8227bbcbdab94dad25d4ffc70790429ef4aa3485484bb2a213ba3de1714b32f4547876a8024e8f0e30f2e3541491d1cdb16f65c77b4565",
	        1004
	);
}
static void snarf_hat_1006(void) 
{
	snarf_construct_hat("/usr/bin/fixcvsdiff",
	        "b77152da9674d38d238877998a91fbd6c0c09fee1f0ff718800b4bb60bc15127ac28455b28bbe05ee4d39efafdf518c8769836d948cdd0d87593dc310de26fa1",
	        1005
	);
}
static void snarf_hat_1007(void) 
{
	snarf_construct_hat("/usr/bin/gitdiff",
	        "e089af72839244852267b8ef0b96aee9b41e5a609f5aa77a05506e2f481e15e31e113bbfc902cc4e5057d82662c400312c051ccde82f6358ee7da0dfcc9cc360",
	        1006
	);
}
static void snarf_hat_1008(void) 
{
	snarf_construct_hat("/usr/bin/gitdiffview",
	        "2035a975b214590330787bd5dd37d6a47cb8fccb7e1e21be0489ddba21e3144317758a0aae51e4aab6e5a20ae2072b6d9ce9b84bc278b994d8f2e93e27ca793c",
	        1007
	);
}
static void snarf_hat_1009(void) 
{
	snarf_construct_hat("/usr/bin/interdiff",
	        "03bbf9b992d00965974c4c3820ef1ce4394581452912950bf8531e7460d3a6010b0def4ba04dc47764c4027bff4de39827fcff2f5aac8fbc0c196a8eeb35d447",
	        1008
	);
}
static void snarf_hat_1010(void) 
{
	snarf_construct_hat("/usr/bin/recountdiff",
	        "6f9d815bded4d511db04f99605aca65dfca5add03498cee33a5422da41b2f4bec7977f0126c7ebc2c51892dcf2c5c06d3ed98a1e9dbd18a25ec9eed042ccfb54",
	        1009
	);
}
static void snarf_hat_1011(void) 
{
	snarf_construct_hat("/usr/bin/rediff",
	        "75571683a43d3eda1dfc22a5ed201590d1c79bee54826e4a1a011da9896f621b19b5dd0b6c51a92e242574b67a5910b6accc87295c63bf7115a99854e20d4a8a",
	        1010
	);
}
static void snarf_hat_1012(void) 
{
	snarf_construct_hat("/usr/bin/splitdiff",
	        "da0acd76d8a1ad1bb4515bd7d9b39d6bbcc9a10808f881f42475b78b9fa406b2d23723d86f82f49a688cbcc78970fc729dfa2bb9c434cc77a7615686dbe9d107",
	        1011
	);
}
static void snarf_hat_1013(void) 
{
	snarf_construct_hat("/usr/bin/svndiff",
	        "84b6b51f7316c4446f09f39a7a1a89df3a70f3374080526e3eb75f0f034c2b75915bf47bef9afd06563fc581d16d724879320ee3338e09686b798bffda829769",
	        1012
	);
}
static void snarf_hat_1014(void) 
{
	snarf_construct_hat("/usr/bin/svndiffview",
	        "2c94476f43a8c8bebed143db664d4ee6f1def584eb7592cf13d2ad956191237972c35b2b5a426fb788740ad6bd861f1bf02588658cf587979785efd704e1fe42",
	        1013
	);
}
static void snarf_hat_1015(void) 
{
	snarf_construct_hat("/usr/bin/unwrapdiff",
	        "8afbf8a625fab50a3271b4487c415440900c21bf7e96794832e09ecd752566842933628d6ace27f85f33e663dee0ecf68f1a30807cf6931223425b68aeba4bad",
	        1014
	);
}
static void snarf_hat_1016(void) 
{
	snarf_construct_hat("/usr/bin/doxygen",
	        "94e58aa69c54dbb114efc5c556ade4e3fd912eac73cd2dbc9cc47624133afb3edac0153af6b6f22c49cd9e78f72abb89dbbf35345da0ac7bc46b76ace4a18eeb",
	        1015
	);
}
static void snarf_hat_1017(void) 
{
	snarf_construct_hat("/usr/bin/doxyindexer",
	        "582e4e10ed1f4d2d77048a19b03eaccaffd956cc7d51eeb4916405cbb85c5643bfa1d25ed830b7b3a9300409377b2ccd7f51cedadfbff15cbd9a5edb84f50419",
	        1016
	);
}
static void snarf_hat_1018(void) 
{
	snarf_construct_hat("/usr/bin/doxysearch.cgi",
	        "c6464b4f3810b5349445c7895e2ae72250be0fc2a8cba0944707ccd7a9ace484315e4aab0108057a6b5a35d3950aa6e3b220fdb8e172a4c59ea70586fa265c61",
	        1017
	);
}
static void snarf_hat_1019(void) 
{
	snarf_construct_hat("/usr/bin/svn",
	        "71c8eeba06631dac86c9879b6821baef4c82ed893aeee3f1a879e3aa64405fb1832b722a1e18f2b00748111935f489948171f8f572f83284839cad4bb952488f",
	        1018
	);
}
static void snarf_hat_1020(void) 
{
	snarf_construct_hat("/usr/bin/svnadmin",
	        "006b03eb1b172eedb66134e2fff02a9761f80f87f2bff30d47a769f5657dd6a19a487efafa5f828ad32193fa96099fc6ea08cdeb71573e2efb219fee76729885",
	        1019
	);
}
static void snarf_hat_1021(void) 
{
	snarf_construct_hat("/usr/bin/svndumpfilter",
	        "e2a03cc67c77d5135aee3b6bb7769b7a136e0ac8020110298d7524b8adc725a0865252204c1a4c23818a4845a7890af5f654569cfa945e6b0924819986e5d9aa",
	        1020
	);
}
static void snarf_hat_1022(void) 
{
	snarf_construct_hat("/usr/bin/svnfsfs",
	        "b241b66f874b519e47c73e44d59c2add50bbae3e3236dda40e39471bcaa2c87567dca31f515d683f07b143e1db9ece641319e30bfb2c4d9cd589a8cea3ca1840",
	        1021
	);
}
static void snarf_hat_1023(void) 
{
	snarf_construct_hat("/usr/bin/svnlook",
	        "8c797f6822265b64f6595380c4337479dbade3463bfdc1d4cdc68fbfdeccae4841151bf8156ef77dadda545020400849a1702ba8a71ba3c49e3bf07142594460",
	        1022
	);
}
static void snarf_hat_1024(void) 
{
	snarf_construct_hat("/usr/bin/svnrdump",
	        "06ff0c974063c663cc096fdf34afe8548099479a4edb3da610ce9802cc394aeb869ef57e0fb151bf989b482bbccdf64874207ca185bf3a3d814356590b40f372",
	        1023
	);
}
static void snarf_hat_1025(void) 
{
	snarf_construct_hat("/usr/bin/svnserve",
	        "9c8591faadbf324710b9e8908f4685728ceeb33a40e9330a7affca8ef49efbd06c03a3f74d60d84ce37ccb62e71877d59cd1073969df0f9a04f8328ebe4b0296",
	        1024
	);
}
static void snarf_hat_1026(void) 
{
	snarf_construct_hat("/usr/bin/svnsync",
	        "305604a4d020b6ebb3a1ba434523372b62a4cfc48133e27761e703eee0d3224b717efd3353a899dd5de15a9c324d23fce5cffd2ef536a4dac5fdde9fd806da0a",
	        1025
	);
}
static void snarf_hat_1027(void) 
{
	snarf_construct_hat("/usr/bin/svnversion",
	        "9cd99f1fd74ba3e090c8c98a6c01d156bddeadecdcd49bdcafa1dcc2a8888202575258fce40bc1afc11a0608050406b403760a629cf84436dcc4e1d3bd1b7349",
	        1026
	);
}
static void snarf_hat_1028(void) 
{
	snarf_construct_hat("/usr/bin/diffstat",
	        "f5e50124d1f0547f7c1f8aa889fba5ede91d9689e8fbab84b03a9193b4057fdc84c50c1d12359c72545ea540a40f0113b7e5a534ac8c3649e79c93b87439db10",
	        1027
	);
}
static void snarf_hat_1029(void) 
{
	snarf_construct_hat("/usr/bin/catchsegv",
	        "342987561cb861739147504404ac548a4314838f78585ce30a79e23648c61fae820aa0812b40e85b864610f105203e69253f0c9a446bdfed5f05171fe5a0f20a",
	        1028
	);
}
static void snarf_hat_1030(void) 
{
	snarf_construct_hat("/usr/bin/gencat",
	        "c1112988cc492e302aec9c98ced90001ee61eef94bda922b9e0d6c212d7524a8242284571fedf06e6b786b43150960e3460d54dad31d55ca75e6c826b721f617",
	        1029
	);
}
static void snarf_hat_1031(void) 
{
	snarf_construct_hat("/usr/bin/getconf",
	        "2653b0de737792f6cb980ec6bdef112c26411dc71e7b528d4d17942c94f8a82e3a6738f1ad08a8cd8f5e069446d6bbb49fba801887684aad4d705e32281d60b2",
	        1030
	);
}
static void snarf_hat_1032(void) 
{
	snarf_construct_hat("/usr/bin/getent",
	        "6717c337c3a3f9c505f8e908355982184b8e3c99761d7b3ac55bc6df05dedfa7122f87f50bb7178b9d80f9db5fc1bca07bf0e0dc7a4cacd1688a0cf464427ef6",
	        1031
	);
}
static void snarf_hat_1033(void) 
{
	snarf_construct_hat("/usr/bin/iconv",
	        "735f7d740b56a51a79176309a353cda6f072a25f067a13772ecfdc172b68035d92770279c44eebee09790a02e6c0010ac219fbee929d8714953818c297ffd50a",
	        1032
	);
}
static void snarf_hat_1034(void) 
{
	snarf_construct_hat("/usr/bin/ldd",
	        "8398a57741f05de8de7277ae90e648298d681fd4fb4187e350729aae04f903f0e54cdbc5f25ae8f4a8709bdbdd9db3bf38a549f2d0c138127a746cac65618b3d",
	        1033
	);
}
static void snarf_hat_1035(void) 
{
	snarf_construct_hat("/usr/bin/locale",
	        "5f6e200a8eb9f35ab85a266a7c4a3c19cdf324a5ee1c84cb7407ac1f82627c3c9573dc0be47d217b4def6cb2c3a4b0d9a00788b14d2b84d7b8cc8fbeee7f39a7",
	        1034
	);
}
static void snarf_hat_1036(void) 
{
	snarf_construct_hat("/usr/bin/localedef",
	        "aeca19bfd41f519103276c912e46c0cab05a84ab3d3c4bc8f848f34e2362cdc68be16c4f61a74ee2f38cb46c0034accafc1a68b4cf9194782013241075b67acc",
	        1035
	);
}
static void snarf_hat_1037(void) 
{
	snarf_construct_hat("/usr/bin/pldd",
	        "f82d12dc991323f4ca7206a57f3088f5efb968660cbe41720965be61001c7fcc2270a83ff5b06231d0eaa8076eb3962387888cd3c5ee337ebebcc21011c45267",
	        1036
	);
}
static void snarf_hat_1038(void) 
{
	snarf_construct_hat("/usr/bin/sotruss",
	        "7691394abe7330d00110c9339071f2dac7b76a1988e920cebe72db61da7cb7474c478673b16ff6d50880ab4a47d8536bf57c7e39f20716e8b86bc6dee97bd4fa",
	        1037
	);
}
static void snarf_hat_1039(void) 
{
	snarf_construct_hat("/usr/bin/sprof",
	        "c038b9aa816970fd35ca28c643bb13935c6cd87abca587f4a19c478e7682f7925679841db374d78d196e0c27332e20cc60e2bb6904899c59e988550e7770c6c4",
	        1038
	);
}
static void snarf_hat_1040(void) 
{
	snarf_construct_hat("/usr/bin/tzselect",
	        "7435eea4b2971c0b41f9df2814ac9a7b89df05827582f241b844908affc47485b8fc9c06c84824e0bd4a94cf9f713fbac209689d5568ca9101e8735b5e6ecac8",
	        1039
	);
}
static void snarf_hat_1041(void) 
{
	snarf_construct_hat("/usr/bin/zdump",
	        "0fe6099feaac08dead9c0e8e53d3a3eb50565f983639eae6f14f330d2cdc2d3c9a0e8f7ddc6ff6d67b764ec895b1e439b9972ccd07bbd569ea108c958548d5f1",
	        1040
	);
}
static void snarf_hat_1042(void) 
{
	snarf_construct_hat("/usr/bin/gapplication",
	        "f4b32d72ad7724f1660de4dda7a09e47ef81c85151993bf8aef4b0eaab3f556a8f5bb97df6ee56c210cae59a7926b74de060107c1dc1529018fa2cf5cc21b547",
	        1041
	);
}
static void snarf_hat_1043(void) 
{
	snarf_construct_hat("/usr/bin/gdbus",
	        "b0f8a101842e8b785af10004c36f07bc88c8e96ff8db4e6e30e237b5020305b6927c336b15fb8f8f477e209736b5c61f352b45536465da0f2bb7f13f2f12e191",
	        1042
	);
}
static void snarf_hat_1044(void) 
{
	snarf_construct_hat("/usr/bin/gio",
	        "fd441d7ce0b53c0f41328bdd912cbe65ddbdcc45c38c62f4a9517832ebe9e59d3d8df830e9631a83c9ad7966b332041c5f639a75522d065d37ef1dc4f72f2de8",
	        1043
	);
}
static void snarf_hat_1045(void) 
{
	snarf_construct_hat("/usr/bin/gio-querymodules-64",
	        "8b1629222eb18797bc6c1c002e6ed85be21165373f9cd9e7bd452d132793b300af4c433fbeb6c35d3ebe19ed7e0827478aa81cb17d7a7a02286073b212c85bf5",
	        1044
	);
}
static void snarf_hat_1046(void) 
{
	snarf_construct_hat("/usr/bin/glib-compile-schemas",
	        "6c12563f6abb417a19261d9c44308d45ca5106c37623147e8926a1f375f5487f0bf6e48bcf76177934195503600dc5a846f9cefa0d30cc8ccbe3e7010e8dc7af",
	        1045
	);
}
static void snarf_hat_1047(void) 
{
	snarf_construct_hat("/usr/bin/gsettings",
	        "6b33b3c6ac7ef46aa4f55acd11afe76e280c9e79a93288329c9b1c09bb09efc8da8175ebceb12b2b5303943f76b0fe611f51bc4f937605ee461e46e55ea82074",
	        1046
	);
}
static void snarf_hat_1048(void) 
{
	snarf_construct_hat("/usr/bin/aserver",
	        "3444c62deec2ea89eafe0cd6d716e3c3167395ea7f74fffdaf2680cfd1d89b7951dc21434ddbb7b4a25219800acd85143504238a1e82411badd8a5130c228d9b",
	        1047
	);
}
static void snarf_hat_1049(void) 
{
	snarf_construct_hat("/usr/bin/cyrusbdb2current",
	        "e2c58875a9f30c1c00412183434a4d374a3411caf023fb93fd87339bc3ca54c639fb302580da64a63cbc813ae3258ec2dfc3c8c0941ab7e40b8daaa55f764d1c",
	        1048
	);
}
static void snarf_hat_1050(void) 
{
	snarf_construct_hat("/usr/bin/bwrap",
	        "1d00e563ed8fd9e5c2dd6faccf2f65d144fde460c3c3d6111b62f33cafe411d564e1fe5d4d29e8da53f4e6ee6881dbbb97b241243a3ef92b02c98726e5b7c3d5",
	        1049
	);
}
static void snarf_hat_1051(void) 
{
	snarf_construct_hat("/usr/bin/grub2-editenv",
	        "bb05837f0bc283a74180b60f81a9e6c930b85fadd7aead670b8d72be5599194b5b6501ed2a2b148f5ca987b91eaf60b622e4bc03631f1eca08fa259973423241",
	        1050
	);
}
static void snarf_hat_1052(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkpasswd-pbkdf2",
	        "ef3566142f3feac5576b161a20a77bb4efedae0cefb79caafbce802c118bfdb37236121320e8d6c535c243aa2f4466b82720ec899605defecdbeb0824d58d6ca",
	        1051
	);
}
static void snarf_hat_1053(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mount",
	        "3ef41e39281462fea3e69bf437c126b27e3cad4dccb7425bbd09bacc7651a555626d681dcfe91dc1999a8a9fb48a4f1ccf11aa21a3015bf58496396836abf252",
	        1052
	);
}
static void snarf_hat_1054(void) 
{
	snarf_construct_hat("/usr/bin/qemu-img",
	        "f6a792114ae3f99b955d8a0893bbbb3bcd8fb871f67584bfd5617718b0a52800d2d42f34fe466e40695ff38a09eaf3aec623696a60dab777c33468ebd046201b",
	        1053
	);
}
static void snarf_hat_1055(void) 
{
	snarf_construct_hat("/usr/bin/qemu-io",
	        "188d53dbed9625ea4d57995e022d70939d6de1660870050628dcfca0b775dece7e310fe507a6b8f36c81649b760e313ff6fb11e8fcb0460a2fad3bed94b7059d",
	        1054
	);
}
static void snarf_hat_1056(void) 
{
	snarf_construct_hat("/usr/bin/qemu-nbd",
	        "dd7550793dc7a14e020c55c31b7517fa756b83c9798e8544c936e9fe0e8405a5e05b359cbd84ca230e7d9bb3f5fa438833424ab6a7e209dbb95f093467822c04",
	        1055
	);
}
static void snarf_hat_1057(void) 
{
	snarf_construct_hat("/usr/bin/qemu-storage-daemon",
	        "47915837ddfdab9858908873946c0e5f6bf81c14d396cf622ddfe07e1ea612361dfb6ad7d55aa1b73852b1066dc54b9db8c805be75f978dbf23a534bc177e9be",
	        1056
	);
}
static void snarf_hat_1058(void) 
{
	snarf_construct_hat("/usr/bin/ssh-keygen",
	        "f0abb9fa63bb1a1cd175493b528162b269aeeb0be1ae6e532f7eae2ee78fc36050eeacdc26e4f93bbafe9ada7fac2c4e6c7fc36d7a28bf22282e3e386a64f6f1",
	        1057
	);
}
static void snarf_hat_1059(void) 
{
	snarf_construct_hat("/usr/bin/dbus-monitor",
	        "f15353e7752a407e827e0c0917fef99985666f11fc2ee753390dd506eaf2e6b1eb90a84c8c38167c22627eb4b3086737b01e188e6a55f06b7a85a956903ba451",
	        1058
	);
}
static void snarf_hat_1060(void) 
{
	snarf_construct_hat("/usr/bin/dbus-send",
	        "5fc17285e8c7d85c5e2412b2cbb74f631b1039606444dca8f40cdfb7a25f5d06646d7ceb19ef344a9085026abbb4580b8f945f60fb8d79a2211458b89117b66f",
	        1059
	);
}
static void snarf_hat_1061(void) 
{
	snarf_construct_hat("/usr/bin/dbus-update-activation-environment",
	        "893a7c72c056e08d492f742bf022b3121f8d84716c56e7bee3db73b5dc57238597118be5fd1bb223a7bfba96f439adc97213c85d1685635d8907c4d17dce1be2",
	        1060
	);
}
static void snarf_hat_1062(void) 
{
	snarf_construct_hat("/usr/bin/dbus-uuidgen",
	        "a098554b53f499c90a8d3a3695d32358f8ae21db0ae26c5daf6d88c8e2b3028e54122cbd11373671615776d7beb8595474094569c3b0441bb494017fad171692",
	        1061
	);
}
static void snarf_hat_1063(void) 
{
	snarf_construct_hat("/usr/bin/dbus-cleanup-sockets",
	        "a9074985d279d075f9b5e377eada33b4f601f05b72fc7b7cd980ca3504213679b3d6c29ec10fa7add8c13eea6e3705d2bda0bb50d1a17e13106b021a03d48921",
	        1062
	);
}
static void snarf_hat_1064(void) 
{
	snarf_construct_hat("/usr/bin/dbus-daemon",
	        "9b96d32916989816ff5fb139dc60c18f9165361a5e19035a1cb704df23f687a5ad11b65ca89ae7e7db7e86105c8b3613e31f7f99af332e5d82825d6d5624aedf",
	        1063
	);
}
static void snarf_hat_1065(void) 
{
	snarf_construct_hat("/usr/bin/dbus-run-session",
	        "f651a20fb2146344257c993f1b535e6e3b824e085f07306b539044b74ba182fdb5d71113c130d09a377db628bdb1fddc91522c15b6414e83f0ebc32982ccabff",
	        1064
	);
}
static void snarf_hat_1066(void) 
{
	snarf_construct_hat("/usr/bin/dbus-test-tool",
	        "3d29b388628658081534898e602c6739ebf00ac0406e96931ee34b3919569c95c30377872058d5e2c6107f62bff1f078ced6f084d521d20d42ee0591f043f031",
	        1065
	);
}
static void snarf_hat_1067(void) 
{
	snarf_construct_hat("/usr/bin/gtk-update-icon-cache",
	        "8f15f691b769c053c3ab02914466c4bbf31d623cf984f3e8b154216255c2ac78664828792a7f9c0438572acec14fe8495ac09b7b06cffbdda5d100cdf5433d66",
	        1066
	);
}
static void snarf_hat_1068(void) 
{
	snarf_construct_hat("/usr/bin/pinentry",
	        "9aa3c2662692a3c6a2e32871ff0a54fa1d44918a6bed02fa0dc432282153926f4cb14b2b4729f67f6eb1f28e6878f947c9c65d852c4e833a5d256a98746e3296",
	        1067
	);
}
static void snarf_hat_1069(void) 
{
	snarf_construct_hat("/usr/bin/pinentry-curses",
	        "9e4dcb6c70239a1f4edbe43b512524792a89715e0a7a4eb2a707193510d967673f75ffbc2507ad43b94b25a03a759184aefa0a093a39d5f89598d94d28d5a5e4",
	        1068
	);
}
static void snarf_hat_1070(void) 
{
	snarf_construct_hat("/usr/bin/gjs-console",
	        "e46b3478df3b106f62dff439b4d70de57442b63c63c20b0ba7497d34e7ef8538f5b75dda86d9dc1eefd84d065d1b112e17a79e48e4e06fd0d1bb2fb5ab6bd293",
	        1069
	);
}
static void snarf_hat_1071(void) 
{
	snarf_construct_hat("/usr/bin/lowntfs-3g",
	        "4699409ec5bc807668dee6e0bf05f24f6a113f442506551d2918c6fe7b15678a35d7f811c1dfb8966fe1b11ee938e751b13715d99689bd557507318a4e7b89f5",
	        1070
	);
}
static void snarf_hat_1072(void) 
{
	snarf_construct_hat("/usr/bin/ntfs-3g",
	        "f6ea63a067ccb609a21e880432651800f50435597dab9dc513a4c154337cba453a26f43a6eec8997072ec6f8eae42609f09bc84c2a01610c57c4ef3994ac8486",
	        1071
	);
}
static void snarf_hat_1073(void) 
{
	snarf_construct_hat("/usr/bin/ntfs-3g.probe",
	        "2104a475af33dda35ff8f662f2c714275eea2ddb70378c924351e5c31074e98225bcabad57632aaae3e9b45c5ac931570627886458e585ece9458a07a14ff278",
	        1072
	);
}
static void snarf_hat_1074(void) 
{
	snarf_construct_hat("/usr/bin/ntfscat",
	        "bb66b160dbcbc29cd05cfac9b9d12e49c3c09714f13129ab4a398039a6cc8593a279d7897677471960d834288293a42656135ca3716ee90b9166e83430119056",
	        1073
	);
}
static void snarf_hat_1075(void) 
{
	snarf_construct_hat("/usr/bin/ntfsck",
	        "f8630c51294cfaf710d232bd328cbc9b636f77f3e3908432ae725c451fd48faaa15e299430c277343a46d4188f120ff89d4c76b0b2003172bd84e51811264927",
	        1074
	);
}
static void snarf_hat_1076(void) 
{
	snarf_construct_hat("/usr/bin/ntfscluster",
	        "e16cac1eb7c2e812ad4a819863a046d8eaca5f0a52b22695e601a0d66290f1d92094a67af44801145cdda1dd9864d30d2664de89192d3643fd409767c0378f1f",
	        1075
	);
}
static void snarf_hat_1077(void) 
{
	snarf_construct_hat("/usr/bin/ntfscmp",
	        "6c8357a33c401f24e943a03eb0e22d5bb497baa32c5900e82274157ec9c9318667982678129f7e4c97be9f0fe460536ef46f7e3d4b81f1c21ff46969b14fb71e",
	        1076
	);
}
static void snarf_hat_1078(void) 
{
	snarf_construct_hat("/usr/bin/ntfsdecrypt",
	        "66f536f49fadee445ca7ab709709ddc2a2b02d3cce9b7fcfe985c6882c6a2f40bdcbe2082545e7e7256c315d65c14c54a9835680a9092e9a388ba6c31c15e38f",
	        1077
	);
}
static void snarf_hat_1079(void) 
{
	snarf_construct_hat("/usr/bin/ntfsdump_logfile",
	        "f90f2d22918ae21ff940b8a1c16b9d33b84167887fb0bad71b9f25ff76c465d43dcc65ddbc049701048a796addc22b09e0e122b0321108e111620c85aaafa314",
	        1078
	);
}
static void snarf_hat_1080(void) 
{
	snarf_construct_hat("/usr/bin/ntfsfallocate",
	        "f6afcbdc5b671893a1b13da87a6e03c6aef35b28a760288fad429de0e59392feb81f28baa7b966ef2b3767b0c47c82a67f669756b5df82cd34f904f383749fdd",
	        1079
	);
}
static void snarf_hat_1081(void) 
{
	snarf_construct_hat("/usr/bin/ntfsfix",
	        "4d44e6763d91ca7cb4c01757cb6bc358ad502c5a327f2499795ed8ae8431ae59c4f2f49f1489ee145acb690705814a4c449624759ca92325914e5b7e7b5af8ee",
	        1080
	);
}
static void snarf_hat_1082(void) 
{
	snarf_construct_hat("/usr/bin/ntfsinfo",
	        "b3b14a6ed8b3da29f337ba61c2d36b78bc65f386297f3e8fec7497d9df8f3783cef0a2ed186e833bd6c8778cfc4adb399d85fdaa0384d45f9f1ac68ddde5b997",
	        1081
	);
}
static void snarf_hat_1083(void) 
{
	snarf_construct_hat("/usr/bin/ntfsls",
	        "35a3f7096085045efcf0b645a4add9b5ff9df769db67b9820a342f208a18e0470ba1942870390e5f50cd60719809668804e9566b73f30248b6ddbae7bd817b14",
	        1082
	);
}
static void snarf_hat_1084(void) 
{
	snarf_construct_hat("/usr/bin/ntfsmftalloc",
	        "2a20b7db9b8f7e52878c601bc79dd4f1d59a9d3e4f035050111b424e6027c451de05d56e420ca4b411f790e81c66b2bb5badfd07344145fcc8fb0ce2e3ddef6d",
	        1083
	);
}
static void snarf_hat_1085(void) 
{
	snarf_construct_hat("/usr/bin/ntfsmove",
	        "b59185e834d70e90550a527d409588b62dd7dcee04b791b0447d78b071dd7c1bef61118906ae29fdddbe0141b270e87201e694cbb2ee93278e78d363d5f9b2ec",
	        1084
	);
}
static void snarf_hat_1086(void) 
{
	snarf_construct_hat("/usr/bin/ntfsrecover",
	        "2722428eb3692f8bc0bc9de127338cd38d3f86edfa2a097fd12e1535ca1556a2e9ccc89cb510d48f68c2e836b5972242169aa9476252cb89f379e3e45c6a3946",
	        1085
	);
}
static void snarf_hat_1087(void) 
{
	snarf_construct_hat("/usr/bin/ntfssecaudit",
	        "1b9c2ffa693759bf3ca4911ce9441ff8901304c8e5ac003afcc779f71bcd2d82a348ddb0bacc7130c8ef2e6f2fb4092bf3379614faf3998235b12120b57a6d1c",
	        1086
	);
}
static void snarf_hat_1088(void) 
{
	snarf_construct_hat("/usr/bin/ntfstruncate",
	        "b405fdcd98308feefecd126b5cd95f8185e56431d9f2d2a0a4dac80baac14518310e109944ada3a41561ebd7b10d204e802a7f3205c70686dc77a7f7121396dd",
	        1087
	);
}
static void snarf_hat_1089(void) 
{
	snarf_construct_hat("/usr/bin/ntfsusermap",
	        "82a03f4536492c0877cec6bf9294e6c55577c598aa126d911b7786f1e9a60ac0ece3a41c53b48965150baf665f532fa5c898ccea07bcb024b4078e4f0b614536",
	        1088
	);
}
static void snarf_hat_1090(void) 
{
	snarf_construct_hat("/usr/bin/ntfswipe",
	        "6ee7c0762059b3952453b7bdde437cf8c70c3fad256fe1ae64c7fa4de243edffa3e3cb340053bced275774a7ae06d2fec84aab366d0b926e7f2e8ad266a372c7",
	        1089
	);
}
static void snarf_hat_1091(void) 
{
	snarf_construct_hat("/usr/bin/pinentry-gnome3",
	        "9a678526885318db5662c741d0ce9a96e442dd603244eb0195bb61ffff3b687576eaf0b39ada3c826f126708c5292b937d287524351a1d4ba444431ad346106a",
	        1090
	);
}
static void snarf_hat_1092(void) 
{
	snarf_construct_hat("/usr/bin/ab",
	        "f4855dd9a0eba641b4f659070f170718f62603ebd0fecda9ac925009fe414194445810094e4ab8db12753eba668289aa14e54a221e83e84b138567035e5915eb",
	        1091
	);
}
static void snarf_hat_1093(void) 
{
	snarf_construct_hat("/usr/bin/htdbm",
	        "a9d9b243339388c5cdcd41e2d6f7fed6ad3e06ca19367beba9d4f5fd6f8de35a4858168b6b649873d38e71262b613c301c0184ff3147581b5252bba4aab04f83",
	        1092
	);
}
static void snarf_hat_1094(void) 
{
	snarf_construct_hat("/usr/bin/htdigest",
	        "af6beff94e45e39412c32c2172859157ce947a1bf1fb25d3322e7f222a5e585029e8b112e847762044622414131b4c83df69acbe592bff04a133f18b07aaee9d",
	        1093
	);
}
static void snarf_hat_1095(void) 
{
	snarf_construct_hat("/usr/bin/htpasswd",
	        "770ffa046a2c98ba1e9d2eb41f4c5566432f224cda665782c354c0f90adb7344c2cd6da89561b232397e3b120fad10e5c1c5a317d852875bf699b993ffd22ff1",
	        1094
	);
}
static void snarf_hat_1096(void) 
{
	snarf_construct_hat("/usr/bin/httxt2dbm",
	        "0b1d65ddea9a1bc8ff9af2f40d68f6b4f67e0cdf2f4c1f7887229ad207a3e60ee5da5ba59322c8a9254576d063cef00fb896947c6934426ba1bd47789285b16c",
	        1095
	);
}
static void snarf_hat_1097(void) 
{
	snarf_construct_hat("/usr/bin/logresolve",
	        "e19fb7a873b0e70b6954d913da60b6d8175f24297f79e00b094c0f47a0909f34b392feaae86b877df4fada7d9970727e57c82d28d481eabe03a4bbd35ebb7b29",
	        1096
	);
}
static void snarf_hat_1098(void) 
{
	snarf_construct_hat("/usr/bin/dbus-broker",
	        "c884aa66cc49792352b6ba8dcddf7570805ff546614bd80e3246ffa045ea17791d6aa099c438a4ba4c26da6006ff513a87fbf00beafee31e6252ac0837dcf32b",
	        1097
	);
}
static void snarf_hat_1099(void) 
{
	snarf_construct_hat("/usr/bin/dbus-broker-launch",
	        "b3af0eaf4c9c5bf91401437d68d960c4b5027488a306a96de3364c12682cd62b8685ab552588c9d398bb48b802a3a630fe7523a760c76950ca61eb3e370244e0",
	        1098
	);
}
static void snarf_hat_1100(void) 
{
	snarf_construct_hat("/usr/bin/networkctl",
	        "7dc5f6604c77de02879ddb11f4b78c9bcccef9684804c7d5a0647b6175da3e7fbacd619f5fa3a41d658d50b1ea26055d91410ee13e9ba75744abd6682edaa1c5",
	        1099
	);
}
static void snarf_hat_1101(void) 
{
	snarf_construct_hat("/usr/bin/resolvectl",
	        "797da6d8d8f85c336a9242d45dd377c3280feae7f4fa24f47c61a0c35d0ce41050d89005ef37e3fe05ed5e0ed5d800c09e60027b787d1eb9a83ae4e77c3c02f4",
	        1100
	);
}
static void snarf_hat_1102(void) 
{
	snarf_construct_hat("/usr/bin/busctl",
	        "4bf67ee5d0d9b1ac89eebc3b2861693c2454f7ea2c2304703be01982e290fb03710a4261afd20dbe8d859a7d8529a6013a77c661dbfa32464aedf620c04d1575",
	        1101
	);
}
static void snarf_hat_1103(void) 
{
	snarf_construct_hat("/usr/bin/coredumpctl",
	        "719640593acf03d9457c6b1d9c1430a1c342ad1d6d782b1608387c55184b38612e1527f5258cdd39a633e515859d0d188ff204de92243d82d562f0768ebbfbbf",
	        1102
	);
}
static void snarf_hat_1104(void) 
{
	snarf_construct_hat("/usr/bin/hostnamectl",
	        "9ff10516ca76e0a64e00e9feea3f571879e05ad9c4b57abba050c33d22a2d8713c07fa6547f75e09e255d930d6ed29852e618eff188c2ccb6149be7243947498",
	        1103
	);
}
static void snarf_hat_1105(void) 
{
	snarf_construct_hat("/usr/bin/journalctl",
	        "a033ac3a647cbf490f45b7ebe3c50be0529d99671da0fedc14067c1a6975f2be08f25d029fbef668463ef67fd4d80fa32d7fecc0d6b57790f902d55424b2b714",
	        1104
	);
}
static void snarf_hat_1106(void) 
{
	snarf_construct_hat("/usr/bin/localectl",
	        "c5ca7509e9ba35d46c8979bbf9d8cdc07cc2662e33c1c9f13671100bc8ffcf60e4ac01a13aeb6a6251bda08f33c17abb0b583bcddeec24b9aec980822387a16c",
	        1105
	);
}
static void snarf_hat_1107(void) 
{
	snarf_construct_hat("/usr/bin/loginctl",
	        "a2af42b9f744995974644ab40f625c824f9e65c0d09eb8f2055cc250e63254682b5adc88ddb47e44da5799319b02be160b5e4bd8a3a89eae5e9ac0923c908298",
	        1106
	);
}
static void snarf_hat_1108(void) 
{
	snarf_construct_hat("/usr/bin/oomctl",
	        "5c79a6f5eeb6fbba500f2170f3a5fad5796257e5f87cb2811b158664b44ae527792034acc65d8851316367b53bee3408ebe4d69697e71f7d8d2c4dc06e570ab9",
	        1107
	);
}
static void snarf_hat_1109(void) 
{
	snarf_construct_hat("/usr/bin/portablectl",
	        "8df2cb0048747316efb09437a2a2f0ba7891b3a8ab427248bd8885c04d3556bcf46870a32380e702cbe065091cf8bb0cbbc34cdde98e5cc70fddc9cf26febe3e",
	        1108
	);
}
static void snarf_hat_1110(void) 
{
	snarf_construct_hat("/usr/bin/systemctl",
	        "280cb95b0ba73dc5c8ae9bc12ef9a42a809de1503fb67efffb29d64aac4427967378da7bdc6e9d0e5a4d0c0f60e64725cb485cedd41e40bfa1c427c227a5cab9",
	        1109
	);
}
static void snarf_hat_1111(void) 
{
	snarf_construct_hat("/usr/bin/systemd-analyze",
	        "8dbd114012dd5b0e4ec16d4f26b75b39f77e064f49c18f479d2715f6bf56b23f42f94af10c28812785e2529239c9dc44c951082c473bddd6deca78f6cde6a435",
	        1110
	);
}
static void snarf_hat_1112(void) 
{
	snarf_construct_hat("/usr/bin/systemd-ask-password",
	        "f5d688dff7ffbb5f7eb6af7939f7fc76266631dec04ba9048c5883c6f22fd4474518d30465b5cc4fd90d62ce8bd8b2e5a87bca3153355def16080a7694541fac",
	        1111
	);
}
static void snarf_hat_1113(void) 
{
	snarf_construct_hat("/usr/bin/systemd-cat",
	        "e6e215dfaca6b278f6ca247c9c53ce1b9bbc157d39f56c1693ce469d6ac92d8b823d5952d5de590702357d7ee403c34cacde94171623f070f0b446800be983bd",
	        1112
	);
}
static void snarf_hat_1114(void) 
{
	snarf_construct_hat("/usr/bin/systemd-cgls",
	        "bfb8f883dcb07944ac03a8a6824b492166bd21c52d48c27a1776b96241766d2c8036519db249a147072caffa046ceaae80e207af8e044e78d5ff2ec6e06201e5",
	        1113
	);
}
static void snarf_hat_1115(void) 
{
	snarf_construct_hat("/usr/bin/systemd-cgtop",
	        "5fbcc4f16deea86f4d79bb32c78afed57f72e9f6b014f52ed91871b9ae85cbd50e5925a30167aaf9cd5cf3e2c39e8461305df6744c686c5db245209e6b910720",
	        1114
	);
}
static void snarf_hat_1116(void) 
{
	snarf_construct_hat("/usr/bin/systemd-cryptenroll",
	        "67e313ca606b8ed0745696fc67a7c2b89960c49fd8542a42ac77c71f06f98e922a6b2c1ec6f37daa847f9d8288861107c43464539464b68ca7a44b0b4e0eb9e7",
	        1115
	);
}
static void snarf_hat_1117(void) 
{
	snarf_construct_hat("/usr/bin/systemd-delta",
	        "2edf218855f23e7716a7c20c0c8cc9181ffd1c294c6e9658bbaf1176d941756ce892217f6a5c7a54b9214285b64d499307d3d594fee62358a93102afe02fc2e6",
	        1116
	);
}
static void snarf_hat_1118(void) 
{
	snarf_construct_hat("/usr/bin/systemd-detect-virt",
	        "066f2e248dc03cad187b09b18d96a97d6521ede012142b57c9b628d2e10bd453c8c1fccc25268b14cd0835b99a1bfa69687a98d20cb9351519f9b76c1741d8a2",
	        1117
	);
}
static void snarf_hat_1119(void) 
{
	snarf_construct_hat("/usr/bin/systemd-dissect",
	        "6aae2e50f9e11ccf648f47db18a0e580747c0c5c1e7cfdc83a5cffc67b5665ee5b960fb5f2e5f5716645f1fda8c48b483189803eb29105cc5e2c1c2d5fc416d3",
	        1118
	);
}
static void snarf_hat_1120(void) 
{
	snarf_construct_hat("/usr/bin/systemd-escape",
	        "07839f0cd2617582079184a6fc3933678ed6250c4f11c52893be0980df20cbff3d72d1d680470aee5600e482dfee0f6792a875b82c28e3edd58a67119c1f24b9",
	        1119
	);
}
static void snarf_hat_1121(void) 
{
	snarf_construct_hat("/usr/bin/systemd-firstboot",
	        "95b677c0852d9a4d94c0572fd684e90b31393b24ba82ed4f42b1b39de6bec514dcb23d425e8df0e23d14e97ee2e9bb6de38c934c072d2898b60f1e825b105b38",
	        1120
	);
}
static void snarf_hat_1122(void) 
{
	snarf_construct_hat("/usr/bin/systemd-id128",
	        "3f9b2e7708f84faa046e64f7cd03058b04d1028fb729c7bc6fc72bf1da8a56bb9458703ed399c61d9a0e5ca7e6880e461731bfb63f9256694b574a25c0db3b0a",
	        1121
	);
}
static void snarf_hat_1123(void) 
{
	snarf_construct_hat("/usr/bin/systemd-inhibit",
	        "7bfef8207fb4adeb08efb45bfd98349f3639b5a86ec5f05801d3b06f7ea60000bb227ceb62a82ba9ab155169c07dc71f88795c4eb2c3975185b1efe359cb8cb6",
	        1122
	);
}
static void snarf_hat_1124(void) 
{
	snarf_construct_hat("/usr/bin/systemd-machine-id-setup",
	        "d2318bcf307fd4ff69330f5c4449298fbd819fca9d6330fbf9b4d0960cdb49c899552471d376476184740a431274fcf10f01b7e556d9fc5dd2da31fcdd3cf6e5",
	        1123
	);
}
static void snarf_hat_1125(void) 
{
	snarf_construct_hat("/usr/bin/systemd-mount",
	        "db14e43d242db7236ee6a946bcbd4482dd4e45fba9741ef6f2b22ac886ed0df1805665549a4a2ee68b5614ccac0b025f9b7285cdfc76e5a7f61bc10f07c5652c",
	        1124
	);
}
static void snarf_hat_1126(void) 
{
	snarf_construct_hat("/usr/bin/systemd-notify",
	        "00799b1fd54308fbc8982dde30592d97898bebb7fcda0c91475fe1812a8a6e9298dd36448d7f04ecd1ca7ff4b74eb0b7772a0453119f90ad0a37f5c80bb6c4cc",
	        1125
	);
}
static void snarf_hat_1127(void) 
{
	snarf_construct_hat("/usr/bin/systemd-path",
	        "c0a932a07e707dc456a7dfdca9e0a10c26e67adb1cfb11373b7989826b21b0d5297bb9d085cc7eb93663ea3a5280e12e5aae909685d4c6738f34a447581edd06",
	        1126
	);
}
static void snarf_hat_1128(void) 
{
	snarf_construct_hat("/usr/bin/systemd-run",
	        "c2071697f9d757dede31afa1b52dffca53a51558589e753a81c0689484f36a2aea67cb0b30cddefaaed122ea9afb7aec66194c7946f4e03ac0e3448f0724b19c",
	        1127
	);
}
static void snarf_hat_1129(void) 
{
	snarf_construct_hat("/usr/bin/systemd-socket-activate",
	        "e6e39f6750314d08f4d5609a5642f954f3253ad613c5f7cfd9aba68084fe5ff908de627b6951e209e2de218e4ada6aadc8bdec385dd1e03113edb78c43b8683a",
	        1128
	);
}
static void snarf_hat_1130(void) 
{
	snarf_construct_hat("/usr/bin/systemd-stdio-bridge",
	        "3191b8860359d557d48103bd8d7b89668b3d58db648f97e6e7ac8c395c630120a853ada3579f5175fc9bd70d9fc1ff92f804b4ca1faeca4cec02a59f47ccf89c",
	        1129
	);
}
static void snarf_hat_1131(void) 
{
	snarf_construct_hat("/usr/bin/systemd-sysext",
	        "c6395337498a09bc6d97a99d1e520fe3015ef24995fa92b11d41dba3bc196b17a908fabda57d0f4830fc2f6cdc4a4992e3e9e29a9927a9d3bcbae958b77c0f67",
	        1130
	);
}
static void snarf_hat_1132(void) 
{
	snarf_construct_hat("/usr/bin/systemd-sysusers",
	        "6a2ba96d14b32e582033d0fde3653741e127fc8409b50cb6fabd83853fccb73f5af648543c75a53c1a33ef8beaaff00bb3cdc6ef0ff7c7e9efbdf8c135a7b096",
	        1131
	);
}
static void snarf_hat_1133(void) 
{
	snarf_construct_hat("/usr/bin/systemd-tmpfiles",
	        "a659683f56a931b44f1ce69c24c1ac62ab53ea5cf600e9992a08054b5933d4b0464ff71c8f941ed7f84038895b6b9ee2c6c9081fd36f9fa3c004f026d1cb9278",
	        1132
	);
}
static void snarf_hat_1134(void) 
{
	snarf_construct_hat("/usr/bin/systemd-tty-ask-password-agent",
	        "0424bb9173ef9d94e8029a5ff9196c0ecfdd4afe0bfa8ce796dd1c0c52dbbc47e956675ac48caf3fa8cc2225823db7af6b1da501c3c1bf80f255f61dbfc97944",
	        1133
	);
}
static void snarf_hat_1135(void) 
{
	snarf_construct_hat("/usr/bin/timedatectl",
	        "869f81a9034e77c138a26f620d4b93f06a060cb15d66902e4fec67802742fa2eb0261be28f07b2e1533dcf109735ceb3253ce86157733632b0fd9c3e5ab04f50",
	        1134
	);
}
static void snarf_hat_1136(void) 
{
	snarf_construct_hat("/usr/bin/userdbctl",
	        "2f9646d1cc374f526c8d96bd15a4b0501b74915f78c0c26ec9cc3850f59ec890c32efd2acf0a7149a163803163e72443323520d933606c997e5c686992df794d",
	        1135
	);
}
static void snarf_hat_1137(void) 
{
	snarf_construct_hat("/usr/bin/pipewire",
	        "0312e0b5bd4acf23cac75fe94ed5b18269e972e2875888b2bcbb9e2539ccdf3a38689565014b027349524d524a79e2eee120275a21cac910c3d93a6f0b50fd0c",
	        1136
	);
}
static void snarf_hat_1138(void) 
{
	snarf_construct_hat("/usr/bin/wireplumber",
	        "a10d75dce3ec68a15eed094175040c1a1398c1bae34d68ed40b7abdceb1e95381ae92d91ecc681fc5b776262c689a82d1b49d56addb22f34fcea0d9bf8afdab9",
	        1137
	);
}
static void snarf_hat_1139(void) 
{
	snarf_construct_hat("/usr/bin/wpctl",
	        "51642312b33cc96c607893b6cd6ee6fcb86f44614341ccb309c8280bd61ffbccf4ade0122029f81b7f145a6b831b6a9fa198de11d3038d1272ebf00a5f973d1e",
	        1138
	);
}
static void snarf_hat_1140(void) 
{
	snarf_construct_hat("/usr/bin/wpexec",
	        "3ebc84f23cc540b3410f8a038708d6d941d5a4d7629f3b485073b6cdccaf01ad4d130f133405551ae7ec42656deed178aa4c8e427a3a0e025649402d4c17388f",
	        1139
	);
}
static void snarf_hat_1141(void) 
{
	snarf_construct_hat("/usr/bin/pkaction",
	        "7b335e003e585ec25627e6660d705ba4e44f71bcf832a18cbe8acdaccd1c9c8a9fa5ea005eaf1aad1a47a45833a5e9fed9498ad64e0fbcd3ac1c816c9bf22eb8",
	        1140
	);
}
static void snarf_hat_1142(void) 
{
	snarf_construct_hat("/usr/bin/pkcheck",
	        "37b7a05dd0d75d93f25bde84c7583d3de740b7cb7db398930f2625b5c31512e54707916d9eaa47f11f0c999565c9476d6f367c70b61d4bb9bfa093aa65829d35",
	        1141
	);
}
static void snarf_hat_1143(void) 
{
	snarf_construct_hat("/usr/bin/pkexec",
	        "bd9cbf43975c0f47d2dad7451fb067d67f47e9dc53c1fe369033bfdb48752b21d8108aecfdcb019d7140fb4770cd7cfa143a6fba21db4e3d5fdbf2c60d1d7416",
	        1142
	);
}
static void snarf_hat_1144(void) 
{
	snarf_construct_hat("/usr/bin/pkttyagent",
	        "f3b4d08e4a945e03626985fb11fc4b2d9a9774e250eac2895ff7d128ded6b244b07bbb40b778df6d5daecd941ab3a07b22d355508b59b68964f294a50fac3fa8",
	        1143
	);
}
static void snarf_hat_1145(void) 
{
	snarf_construct_hat("/usr/bin/avinfo",
	        "e8331d524692a6fa8295a59a21eed8f35184f5f30223baeb4ad3efb5710cd91831b54c86f1d2f4361f6deafe00b32197633d302ca466d4ef62874c51a616b2e5",
	        1144
	);
}
static void snarf_hat_1146(void) 
{
	snarf_construct_hat("/usr/bin/bluemoon",
	        "e05ca75b5024e3a34013ddab7b59b869f9696c59157e650ffec8e7df9eedc1b0cb2b994faaaf4fdacb43cf3cb5e061487ae74c3214ab6d970f9b6e2e6f3bee07",
	        1145
	);
}
static void snarf_hat_1147(void) 
{
	snarf_construct_hat("/usr/bin/bluetoothctl",
	        "d98fcfee6a3f7aff6bd1c63c6fc631a34917516bbc1c1bcde3563106831b77af55d9ec50b79fa45c53df4ca8327d56b384d4a3f2153c4bc6732631b16c78830e",
	        1146
	);
}
static void snarf_hat_1148(void) 
{
	snarf_construct_hat("/usr/bin/btattach",
	        "b2b68e1b2e03cdbf2e1a37eceb8860ec10618160dfb4cfd387ca4a0d5957d77ab827488ced99fea3666db97b07e1ea4fe5167c3527e5cee7b157d72abd96873d",
	        1147
	);
}
static void snarf_hat_1149(void) 
{
	snarf_construct_hat("/usr/bin/btmgmt",
	        "d51871e8b2a03c948090e097fd9ea2d7f94e59e0b45e0ccb43406c0f53eea49960e3952d561e9142c388092666b82a6973bd9631c5968e13e1e9626f4a5616f3",
	        1148
	);
}
static void snarf_hat_1150(void) 
{
	snarf_construct_hat("/usr/bin/btmon",
	        "912804a0b7ce0b5941c18c4d5dd26aeebbc6e8a89f88def66dcef8b0489924b2bb0f372f372a0dcdf6908fa1dc9383b980b17539b82a3f5dbedda1750593e818",
	        1149
	);
}
static void snarf_hat_1151(void) 
{
	snarf_construct_hat("/usr/bin/hex2hcd",
	        "7b3e09c09da327923376cdd2f76453eab64f6e9651827260d83535ae8bde828dd0ec11af40fd8a2e70c55bce031760a26f2c5855a6ab5202f9beaac3a84bf9c4",
	        1150
	);
}
static void snarf_hat_1152(void) 
{
	snarf_construct_hat("/usr/bin/l2ping",
	        "6c432f8cdefaf7b882c911e2879fbc86563098bddbd2d39659ba5341bd4787c53d1fcc1459166c8ab1cfc3d966caf3356f35f7818e80d55d6871096df6009cbd",
	        1151
	);
}
static void snarf_hat_1153(void) 
{
	snarf_construct_hat("/usr/bin/l2test",
	        "6efcc3180064d3f81476997c60aeebee71928750da234b08785a4e158743480661c70607e0210c2c4ddb6138db790106a1d8cd6b90deded4c29f888867b6b6cd",
	        1152
	);
}
static void snarf_hat_1154(void) 
{
	snarf_construct_hat("/usr/bin/mpris-proxy",
	        "e10851b6eef4b14e636dc864aff8831885349d8da730be06bf4c80fa0ad8fd52dd2467c77080d89e81c28e3fe8c635b0b4b2f6d08de02c80cc8cb60ac7cea38e",
	        1153
	);
}
static void snarf_hat_1155(void) 
{
	snarf_construct_hat("/usr/bin/rctest",
	        "66619ce6cf84f3f2eecebb7826cca09f80e0964c0d55c7fa6388fff8ac7ccac2386b353425b4590628ac39afae9c566a65ade6afd1c15af4127e397e863b46ee",
	        1154
	);
}
static void snarf_hat_1156(void) 
{
	snarf_construct_hat("/usr/bin/pw-jack",
	        "7cbda053dcb689946ea9bdb6135557d22bac16c14f2347e48035b9bfbf24702689df3de64e92e6038c02be652afb2a5c2e2396b6e686d40271c036a688ad062a",
	        1155
	);
}
static void snarf_hat_1157(void) 
{
	snarf_construct_hat("/usr/bin/usleep",
	        "cfae3eb6df357c35f2523a7e432e6f18978f3f6699361fdb0f7af4749fce7f91944667198e8ced2f056e4c8a8d29ab34ea480c64eb312fe31ba3bfa7c6610b7e",
	        1156
	);
}
static void snarf_hat_1158(void) 
{
	snarf_construct_hat("/usr/bin/fusermount-glusterfs",
	        "4f766290ce4803cec6ca6890a748e5161dcd0b04a75e517049125815ff9ed367bc71d67ea556b5cf0898614005d86a340a72800253ce6aeede2039d950aeccc8",
	        1157
	);
}
static void snarf_hat_1159(void) 
{
	snarf_construct_hat("/usr/bin/crun",
	        "ebc34ad3cbd1739dd8ad7c19c729c696130cc39e68f61867e1f0df482ce50a75bdbd64fec84350d2ed118d11f8b00654ac807ee5192764d063eda70fe13b22b8",
	        1158
	);
}
static void snarf_hat_1160(void) 
{
	snarf_construct_hat("/usr/bin/qmi-firmware-update",
	        "967846854e50cb19219990dfff368836552638f0f08f192566094be59478cd26f5a46dcc4361eab6dcccf83a2c096a50d561cd34162aabc0cdac503024a4869c",
	        1159
	);
}
static void snarf_hat_1161(void) 
{
	snarf_construct_hat("/usr/bin/qmi-network",
	        "d7bcd0d9ff47c01d330e0d2d8b9b94ed403715abef616c55d32856c941ca4b2171470d996b8b165cb734922b36fc7fa804da88049f07019cccc1e682cf4ab192",
	        1160
	);
}
static void snarf_hat_1162(void) 
{
	snarf_construct_hat("/usr/bin/qmicli",
	        "d936fba06ada197e8db7c063391d64ea3410d1ba452f34a77d4cc616e0e7133bd7cb6190668c23055605db2814f2a80ccdc5dbaa732b10575fe55250528f8874",
	        1161
	);
}
static void snarf_hat_1163(void) 
{
	snarf_construct_hat("/usr/bin/mmcli",
	        "00a62a3c253f5b75b56f51f53c0ecefe7138ab9dd5a66dbf7ce1f8e9169bf284c67d89327e55899bcfda9e51d96f65fb0187a3b285eec515d09e0ca73daef684",
	        1162
	);
}
static void snarf_hat_1164(void) 
{
	snarf_construct_hat("/usr/bin/wget",
	        "1e3ee9f05d7d1bb9f994ed02ca172b5d31785a58ae7460302d3ef8cc0e9872e6ef967e11e2ae6159590ccb5b49b047b2394e9e45675c35dfcc8937c254b2fa0f",
	        1163
	);
}
static void snarf_hat_1165(void) 
{
	snarf_construct_hat("/usr/bin/setup-nsssysinit.sh",
	        "495a0ee54ab0273cf551c4b05ee74453b45d2be3bd46ac935f5b7b0428d0261970582000d2153df444e868332cddac67f44f63e0f1ed9a1af137870ad16d0eea",
	        1164
	);
}
static void snarf_hat_1166(void) 
{
	snarf_construct_hat("/usr/bin/pydoc3.10",
	        "bb567000a82a8cd30aa33fd02fa786866ee350a911f7b76dd0ba06338d75383ff84b8f285457eb6ddc39a1d017980f62898aef2abd480c56e583ca999cab7fa9",
	        1165
	);
}
static void snarf_hat_1167(void) 
{
	snarf_construct_hat("/usr/bin/python3.10",
	        "a3378ad30761f06e892aa70fa3aadc90bc20949fdc4359b615f5195a53221bc04a305053745bbdd4e76ca392ace4ae2c8dbecbbcf1c472f7cc5cd51070ca4fa8",
	        1166
	);
}
static void snarf_hat_1168(void) 
{
	snarf_construct_hat("/usr/bin/gst-inspect-1.0",
	        "b1661f223934e8ff807e7784b30caeb75d7ad1efeb8d3a3d48dee579fb3dbe38f9c0078c0b90ebd35a937f05c30f7526e942d8a4acabf2a0f86934edb5755c58",
	        1167
	);
}
static void snarf_hat_1169(void) 
{
	snarf_construct_hat("/usr/bin/gst-launch-1.0",
	        "93fe195b05ce15e6d7edf15c1edb7bf35666fd300115c988a30d97a76e4467860b53ae6d8ea06ba7dc858381afb66f9561c4b2c552253fe8c886fb395c28ddb4",
	        1168
	);
}
static void snarf_hat_1170(void) 
{
	snarf_construct_hat("/usr/bin/gst-stats-1.0",
	        "79235bcbe1895013421b7fc186bdab1a4b6c029bff89107cc126ce806a3c45af0316dfe566dcc8d1a194fae344349201eb3e2b53dc03ffa426d96840f6887f97",
	        1169
	);
}
static void snarf_hat_1171(void) 
{
	snarf_construct_hat("/usr/bin/gst-typefind-1.0",
	        "29bbec4e53da44d604b4fdf1ff434955f9d431040de4dfe31c20abe3b94ced7a6f06f46faaf88d856336d6d8bb998e1a92ce967dbe9cd3471eebdd2be4078d2d",
	        1170
	);
}
static void snarf_hat_1172(void) 
{
	snarf_construct_hat("/usr/bin/canberra-boot",
	        "c12ad8466e135a2a41572fedab6189cdd0d926093868e2e4ebc321f8c5f02ed0f2bc56b037c6d929a5d63700a0a936968fce6cdc3d883b54119a315493af33e1",
	        1171
	);
}
static void snarf_hat_1173(void) 
{
	snarf_construct_hat("/usr/bin/tracker3",
	        "b90fa759de4a9c144a420bf7b806283077c455b4c82db0672deba9a081f1d60893a7b2fa14e4a70a4bf6ae0d8f125f15ee38531bd6c70df629b60c7184b9e2dc",
	        1172
	);
}
static void snarf_hat_1174(void) 
{
	snarf_construct_hat("/usr/bin/ges-launch-1.0",
	        "74cb2a206e972e31679581db5810f2b91a4656db6e627f34bfd8e260f194a03e056b102ac38a1414ac0f895679949ec70e57863a2841943bd4b9b7e9da0d1bc0",
	        1173
	);
}
static void snarf_hat_1175(void) 
{
	snarf_construct_hat("/usr/bin/gupnp-dlna-info-2.0",
	        "f00e624bcdbdf458ba0ade45bde542720e4510753a1b9408e01e704e2db7f4b2793215e319c4f4b4d5f5a2052d86abc0a388a6b53e4a91b69f83a3a45840d877",
	        1174
	);
}
static void snarf_hat_1176(void) 
{
	snarf_construct_hat("/usr/bin/gupnp-dlna-ls-profiles-2.0",
	        "f181e18f7d938b9f6589b871f278a95f577da0105fcf6e11354635751220c5ebe5d743dd849488985ac27fd60ebaa1a46368e0caece147da2d3688bdf96c76f1",
	        1175
	);
}
static void snarf_hat_1177(void) 
{
	snarf_construct_hat("/usr/bin/totem-video-thumbnailer",
	        "d5ac734cc59d30e86a68b66544a53d05a36d3dc77a806247b60cbf6816543703382a9204a6d944c2b01c4b9ce54132b543950995dbddeef602aa7d02ef394053",
	        1176
	);
}
static void snarf_hat_1178(void) 
{
	snarf_construct_hat("/usr/bin/smb2-quota",
	        "048d877d574c725fc57ddfc2fd6cdeb71ab7ab348dbcfe30e1ba39c86125d657bd646b406de4cd78afeb05b3ea11bcfb6b38d4dfddb6201d06a9c53fa890ad7d",
	        1177
	);
}
static void snarf_hat_1179(void) 
{
	snarf_construct_hat("/usr/bin/smbinfo",
	        "e45206ab8d28452491db9ae17effa05378f0ddd73e426f8ae9c170884a18586d744772587d0eb9764cbe23875e44969134074b9903696f8110933fa5690d9ee6",
	        1178
	);
}
static void snarf_hat_1180(void) 
{
	snarf_construct_hat("/usr/bin/cifscreds",
	        "9cc77e663cf1e89d46d6f28fd256178cf05a1189b2244924b9657444b9c289cb0ab3457a098c133ebd8d04abcfe901569233ea75a83370d418f504b2e51f5f63",
	        1179
	);
}
static void snarf_hat_1181(void) 
{
	snarf_construct_hat("/usr/bin/getcifsacl",
	        "a8ab7fa305db1be8f34a9bdfb7bb0768008a320f2affbfe232fdb9f71ec65e672b37224a2902487b179a68a35cb62bbda20153a7a01821a38cd87a5d26cce147",
	        1180
	);
}
static void snarf_hat_1182(void) 
{
	snarf_construct_hat("/usr/bin/setcifsacl",
	        "2b42735a3bb32d8f015a8e6a549bbc5bc4de329f181e535935269cae7a90e9d00fb3a32581232e5fd828547035cb284ed0662c9444eb16f143147c211d0e2585",
	        1181
	);
}
static void snarf_hat_1183(void) 
{
	snarf_construct_hat("/usr/bin/powerprofilesctl",
	        "28e3322674b6829dff6dc6b81570eca66ec43d5532648834f9e203235310bc7f9390fa5fe79e7d0f0bc3353491afeb640ccbff5a60776a91f4313a5105459e44",
	        1182
	);
}
static void snarf_hat_1184(void) 
{
	snarf_construct_hat("/usr/bin/conmon",
	        "47494047892fa94246dec61c3f66ac5b5de46999529c9bb29f2e5c3b2a022fd6cb2716fce81ee737168b230b647834d36bcae566db0c8c6bc69213bbaa96c9cf",
	        1183
	);
}
static void snarf_hat_1185(void) 
{
	snarf_construct_hat("/usr/bin/slirp4netns",
	        "1218a9f7c334603b2d21c172aa6b327be19d212fd133d8e0523dcef15ab2ff1ce2d1a208720eb656333bd6bafccb39314e47e50e7907e80fb5f11893641e61d6",
	        1184
	);
}
static void snarf_hat_1186(void) 
{
	snarf_construct_hat("/usr/bin/ld.gold",
	        "db7277de1fb0eba86bbc147230139f489fa2b221bb8c7f595cf23821b94136ff8a960922850019a5dfeb8be3ec99acc808b59b2cbc8edfa2438e011d027b718c",
	        1185
	);
}
static void snarf_hat_1187(void) 
{
	snarf_construct_hat("/usr/bin/addr2line",
	        "fd0846ebb37b787eb16b19adf242ed05fa1f2bd37f750641b526ec500073753870e49a94ca6b8ca88b98c1d7724990ae7a132edbd77f38a3dc053f60e0ec8dec",
	        1186
	);
}
static void snarf_hat_1188(void) 
{
	snarf_construct_hat("/usr/bin/ar",
	        "544fcd04bb1cbb8d205bd2b904c3528b7d7f22fe06a5d55047a12160a314094428ffedea56402bab81c706ec1ef07041dc19ae8fb94b95c39ac550a715e2d314",
	        1187
	);
}
static void snarf_hat_1189(void) 
{
	snarf_construct_hat("/usr/bin/as",
	        "8ce817dc7815582d05a09743a087fbf34c033a3f2b363b74a901f3418c7bb7af9de91baa00833a5090817d4e400f3479e8d23c5f92d8d897c6d6f9aa2cbe169e",
	        1188
	);
}
static void snarf_hat_1190(void) 
{
	snarf_construct_hat("/usr/bin/c++filt",
	        "446cd882bd42cf10293e237fa28a7d4b67009fcbd044f4fccdc60f5f03a772e1311f28f58271efc0357fa024b736673db3c54eda33f66aaba827e69feb39b341",
	        1189
	);
}
static void snarf_hat_1191(void) 
{
	snarf_construct_hat("/usr/bin/dwp",
	        "ad7646ec692e057328dcdf0b920ec1d2e34bdfc0ba58119819a29b876556cccaff6fb5f4cf807858047050d7ab26e2c3246b78bd654edaa488db7d73606566d6",
	        1190
	);
}
static void snarf_hat_1192(void) 
{
	snarf_construct_hat("/usr/bin/elfedit",
	        "5dfb5d0e61aca8e1a2fdfd8aa696a01c53c0d0fff9750a335052250bdbd72ddee72a84de949f5a49f37773becd3042d49e4f7591d78f1807fda1471ef4626e6b",
	        1191
	);
}
static void snarf_hat_1193(void) 
{
	snarf_construct_hat("/usr/bin/gprof",
	        "b028b030b4dc391f8b134d08a2ad0f7aa25f7e6d71a918e364157c3cd44d5542f3ab78a5b38302c234018fa18350ee0138c026c4c56cf18be7abd0fb68e9aedf",
	        1192
	);
}
static void snarf_hat_1194(void) 
{
	snarf_construct_hat("/usr/bin/ld.bfd",
	        "ebcd1325f39e89a144651467bef14c244f7cc51754bf41e24c8e1c7c3b905b9a2dd9c5a1605beb6a461278c2a37f2c82989747a4a6ab556417fab6140fd64d40",
	        1193
	);
}
static void snarf_hat_1195(void) 
{
	snarf_construct_hat("/usr/bin/nm",
	        "dbab5e6f285db1ab9bf685c373f635e050d4cd7ffda77d3ecfd4b9088e251ac3549fee871591ce9612013b1ed793796346e9450861f39322f871c9e5e9ac434f",
	        1194
	);
}
static void snarf_hat_1196(void) 
{
	snarf_construct_hat("/usr/bin/objcopy",
	        "4279f67e22888f681aacba4605bf19ff75ea81feb57b05a137566328107db007affff76be56ff636a1095ce27a7ba8859b323d6db78dd218b75061c0b1a0e6ea",
	        1195
	);
}
static void snarf_hat_1197(void) 
{
	snarf_construct_hat("/usr/bin/objdump",
	        "98f7cb124c4b5d5e9c56ff7ce718fe63f06909ecea450ea937c426ee386a0d9e342ea71882702403d396cdefaa9f56e59cbaf3b2e4c8d7bd082a4365a97d533b",
	        1196
	);
}
static void snarf_hat_1198(void) 
{
	snarf_construct_hat("/usr/bin/ranlib",
	        "3dc7ccba4888d674c0b76b85f9d85f6b47b0aea5342752219e30d65d7633daf0bd34842eea9d88c33421b345836acf29db8f33301e0a2724a6e3d8bb35cef509",
	        1197
	);
}
static void snarf_hat_1199(void) 
{
	snarf_construct_hat("/usr/bin/readelf",
	        "3dc625f95a9b22bd87f8cb241fd2ecb63c43d3e268837cdd8983362374fa6480f1ef01950b2cb1a4007d6f80c0c6aeb2d5c9c6f3ef5fb9daad5b8ef2cd6eb0ee",
	        1198
	);
}
static void snarf_hat_1200(void) 
{
	snarf_construct_hat("/usr/bin/size",
	        "2108505bbdec2a729e25d7f8d35ae58ad28a6f8e81e8363ab72fb4bb24b7e6e489a4dd19dde29c168de99b8902b986d25e1e9040f019774250a8e958d8f7e3c8",
	        1199
	);
}
static void snarf_hat_1201(void) 
{
	snarf_construct_hat("/usr/bin/strings",
	        "b7c98acac120f38698f551e007724372f04cdc61e0fdc3aa6b5acaf7a5a4a66eb484b72815176a2545b3da998b53e0c9ddc0d58abdfae601a91163a256287f07",
	        1200
	);
}
static void snarf_hat_1202(void) 
{
	snarf_construct_hat("/usr/bin/strip",
	        "318dc8ff38e1497e981bf2d9c25cb0d4cda76cd15192963483e9165bba66f395d261706e0c707596a2e97b0fca5322892807ab0ce5e47bed3d166e52d72781e4",
	        1201
	);
}
static void snarf_hat_1203(void) 
{
	snarf_construct_hat("/usr/bin/scp",
	        "2734fbbd4131f4cb3285adc7d99194f6fb5056d1f0761fa078745ccd397ca5095ea1730e0910bc7c57abbf2daa6065d69f545212b45ea4bed769deb837186f4a",
	        1202
	);
}
static void snarf_hat_1204(void) 
{
	snarf_construct_hat("/usr/bin/sftp",
	        "a7da92f6e488b765ae205755e4e97de63eb3805007d511a8491c8f2a4ac8a31fae623e69f85e8f0b24ac4c909d7f1a0c3fa7a11d63dbca5b63d7803124e7e07f",
	        1203
	);
}
static void snarf_hat_1205(void) 
{
	snarf_construct_hat("/usr/bin/ssh",
	        "5ba5d63d5d3560400a6bc6494ca8a0ca94649668bbd4f143958bd652fbf9cd2a701fe53663b9019c0c80d18f3c04f1a13e551eb6aa4e5240f6e161caa3c6ab0f",
	        1204
	);
}
static void snarf_hat_1206(void) 
{
	snarf_construct_hat("/usr/bin/ssh-add",
	        "8f45ee4b94faedba363c5e5bcd83e59552819c8aeb1d4e4dc431386345b110b4b6d018e918914ddee8ed9ebb228d34ae7f7f7d8af88dd257d7a981d32b1dfb4c",
	        1205
	);
}
static void snarf_hat_1207(void) 
{
	snarf_construct_hat("/usr/bin/ssh-agent",
	        "1fa6d0ce90e76d857013358ee6ef237d86524ce874381d63402c83d28b64af3cbf78a91af58ed626586063246e0e6aca2b8a41947eb5cd394cfa27833394d402",
	        1206
	);
}
static void snarf_hat_1208(void) 
{
	snarf_construct_hat("/usr/bin/ssh-copy-id",
	        "794c3cef811c8413a9e7018691345bc8ddea4e1fec1523123afc1ca589245f4ab85c7fca708b9b9b09565d72c76880801c2421d93cfc64e0e9b25e2139e88303",
	        1207
	);
}
static void snarf_hat_1209(void) 
{
	snarf_construct_hat("/usr/bin/ssh-keyscan",
	        "313688f3a51c0fb720a21c547bc97df9accff0f7693afce276d020ff6e3ea0f6a9b83dbbd84ac6ff2de31faf2a24c1fdac77f2e2f83671304d43b938ca4637e5",
	        1208
	);
}
static void snarf_hat_1210(void) 
{
	snarf_construct_hat("/usr/bin/soundstretch",
	        "164e1cc5df0cabd29fc0be165b6c028bd67468ecfb477ada0631774de5e2eeb9953ecfba227799e437f721d2cd94296c80f35d95f4420226f719daaa8695062a",
	        1209
	);
}
static void snarf_hat_1211(void) 
{
	snarf_construct_hat("/usr/bin/gst-transcoder-1.0",
	        "038eeb2df3d4d7de8affc76bcf901d051f273c943b07feda572eb54c593e3e09c74d9aac606e244abe2035c300872f3ec3181d417b78c5c3826a1cae1f329b87",
	        1210
	);
}
static void snarf_hat_1212(void) 
{
	snarf_construct_hat("/usr/bin/bc",
	        "42c709948a6a5fcb2d64550ee71679dcf8597a9c2d38e37e6202b0d8914587bee60e4abf8fc240f4be6fa308f5e0235020fef0a0dd2864cfd0290dfd339d8072",
	        1211
	);
}
static void snarf_hat_1213(void) 
{
	snarf_construct_hat("/usr/bin/dc",
	        "60c931d24724f16fd1815e663abee867216a8520b5632cb1ca66838c27eacf599fb450c047881c89001a6e3b061ee9784bfc6d0a8fdf0871575b692bae26fd12",
	        1212
	);
}
static void snarf_hat_1214(void) 
{
	snarf_construct_hat("/usr/bin/sss_ssh_authorizedkeys",
	        "f7c1694c67314f8f9b88fb36cb44e0b29ef874ad646b731f5fd16cbd36008db8e664e73436ce371ed25569785410441c59f0c37edb006c3eeb3cb98b9b4e9c8d",
	        1213
	);
}
static void snarf_hat_1215(void) 
{
	snarf_construct_hat("/usr/bin/sss_ssh_knownhostsproxy",
	        "7d6de22fd6315da117bdf84f24d22a726bcea1400d7659f0e49c789bb643156d063eaeecb2acf25998de722d31dea19632539ef876072155c82ae2fd860de777",
	        1214
	);
}
static void snarf_hat_1216(void) 
{
	snarf_construct_hat("/usr/bin/gpgsm",
	        "9c97c05a57de17e17bcef093d35a52b3a914fbc204e256813a94462ace86f1bf9da6dae73494d2d517f648a9638178d0ef1955e871daa72768fb453ec3585da9",
	        1215
	);
}
static void snarf_hat_1217(void) 
{
	snarf_construct_hat("/usr/bin/kbxutil",
	        "17b311137c58bf4bce2154bf057be6d23d4806bf5f930160efa99e925e2261cb303d7dc6bbf48e7296f9e3cb19268313fbe807b5921d2b98b48025e095b20865",
	        1216
	);
}
static void snarf_hat_1218(void) 
{
	snarf_construct_hat("/usr/bin/dirmngr",
	        "40ce1e998ba1677644ca41bcae4dc06b5fffe675a2ac9f111ee90a1606111c7f86e6b5805a0d7464160183aa8aa27dba05ed3fa7523eb8c0fd0dfe6b0a35ed7d",
	        1217
	);
}
static void snarf_hat_1219(void) 
{
	snarf_construct_hat("/usr/bin/dirmngr-client",
	        "5980c6a5e45d04d3692eb1c565aacc706a71021f472d617d1e5ee46c67af451178d0935045b105c3be6c0a199f94728e3ea5e25cbb134272a540450a3838e58d",
	        1218
	);
}
static void snarf_hat_1220(void) 
{
	snarf_construct_hat("/usr/bin/g13",
	        "5512db8a0f2f7801753a75eef6d379b619f9badf621e6d8c8ccecf10a2eb51699c8126cf60836bde081f07c91137e06c79e4a33acb4dc9e08a286b111675b1be",
	        1219
	);
}
static void snarf_hat_1221(void) 
{
	snarf_construct_hat("/usr/bin/gpg",
	        "fb5c24268c443b57eee41b6a1e6e5e4001029a1752be295d778db051a0f0034a623494c0544b60bc121437715afc356dad47cc78ec2571bb3f6865e49f14d943",
	        1220
	);
}
static void snarf_hat_1222(void) 
{
	snarf_construct_hat("/usr/bin/gpg-agent",
	        "098ba5775c31ac8a16645c6207cd50b3251c912095e7fd8758166556fad2b7a3eb51b994772c919e51f75a43ce7a9f2d40e6a3a92f260d8d8198a8aadd4f6c72",
	        1221
	);
}
static void snarf_hat_1223(void) 
{
	snarf_construct_hat("/usr/bin/gpg-card",
	        "ed2b365a13d5eb8827c7321dc664025cf00d8cb37cffd44404828531d59bb255bfd93e41221c9d0df34eb879a786cf7ff47527b7668957b5da62d99deea5c7db",
	        1222
	);
}
static void snarf_hat_1224(void) 
{
	snarf_construct_hat("/usr/bin/gpg-connect-agent",
	        "e8b22c2b831fa950492daad21b7319f100712ce11df69bac5fe50cacf8d0a2662044950b49f629ccd668e1ef2e2757f08184b0add7f0f9965bb995d2e598e031",
	        1223
	);
}
static void snarf_hat_1225(void) 
{
	snarf_construct_hat("/usr/bin/gpg-wks-client",
	        "aa8a4cc68c2ac3276b874906e943b382826df8e34e3dc3de4687a1e55c0648bbb61186a6011bf552d1b8e6636d1a9560670d90003bc7e165f25407fe81b32e1f",
	        1224
	);
}
static void snarf_hat_1226(void) 
{
	snarf_construct_hat("/usr/bin/gpg-wks-server",
	        "82cdfe9e0c15c5ca175bf85fc2bf814886c2e78452dc9f9f63173f0a602d469a4806a49d9c02eb9ae928572f2075f243656e7158e32dfedca6c57ff5b2656150",
	        1225
	);
}
static void snarf_hat_1227(void) 
{
	snarf_construct_hat("/usr/bin/gpgconf",
	        "adbfa3c0cd3dca4abf10631f34ead24e45ff8a9a206ba30b223051caf6bc039b29e3ef4a83a622caad8d5d5d9a98cc68d3a2188ce26385dd7f0e2bb443b4358d",
	        1226
	);
}
static void snarf_hat_1228(void) 
{
	snarf_construct_hat("/usr/bin/gpgparsemail",
	        "b3b40771886f20d3703c4804a592de884017cfff0485a595322b15be2e6f965fcec60bccff4290ef82c0474f85f3c8d7574120422a9ba33354621edd7fbba549",
	        1227
	);
}
static void snarf_hat_1229(void) 
{
	snarf_construct_hat("/usr/bin/gpgsplit",
	        "c75c6f7ad36bd176d57f25c96ffde6e3e9c5208acded3a47f9818c0934772d20c3ff017a1f3a00e6f575a4738dd35d2e9eb440746c3cdc48be1cb93c16dcd5d2",
	        1228
	);
}
static void snarf_hat_1230(void) 
{
	snarf_construct_hat("/usr/bin/gpgtar",
	        "c6396b1b28c155e74ab29ea3e4b9d05f1dd0328c057b945865dc0a5e18aa6b9830d7d8bf034d15b776c12eb54b8dbaa83fbc7369f06f4570cb9e66f6123c81a4",
	        1229
	);
}
static void snarf_hat_1231(void) 
{
	snarf_construct_hat("/usr/bin/gpgv",
	        "76dee9a2081095e71ed3031ea58b8d6d3bdc0b6169f14f2f91b5cef768dd7518c538e81b90fc4990d7e4114ba6263b5c52d4a3985664f8e208b474fee4c312a4",
	        1230
	);
}
static void snarf_hat_1232(void) 
{
	snarf_construct_hat("/usr/bin/watchgnupg",
	        "9380566bf013237a93f4a4676488cfb7dc2c1eb25931550698c759410287941d4a17322bd3ca6b05022fd58eefb6bdc6914f8e40056fb0441a181fe1a31f5052",
	        1231
	);
}
static void snarf_hat_1233(void) 
{
	snarf_construct_hat("/usr/bin/pf2afm",
	        "e2923b97793e3e40c827264e8da5fdcfe560d919796bf162c878ca0795bb77abe44f5bf608951576b1b1739f84b9cc51de4097aa21192d29b45ee3b500306c4f",
	        1232
	);
}
static void snarf_hat_1234(void) 
{
	snarf_construct_hat("/usr/bin/pfbtopfa",
	        "103487faac10fff8bb544ce7135ee3cf6486f386a760a6307f15707fd888efaf4748aae254c5c12f6cdbfc968b91b08f0f19845a6c8a051f123fa7baec627c1a",
	        1233
	);
}
static void snarf_hat_1235(void) 
{
	snarf_construct_hat("/usr/bin/printafm",
	        "9aa7a6e5722655ab7c78b13aff3fac62bbfd750a5a167e9916042a396fa4bfb4d3bebf14705504c4cfe901a27430d5cad0517eb61e346f531293147d2c81fd87",
	        1234
	);
}
static void snarf_hat_1236(void) 
{
	snarf_construct_hat("/usr/bin/gsbj",
	        "e80420352c08efed077db3139d024cec2fc24cc47c7e69d10fd43f97fceae3cf4c991a67f2e4460380268a4edb2ae6952142fb4165c86f6cbbf35c275cd6eee6",
	        1235
	);
}
static void snarf_hat_1237(void) 
{
	snarf_construct_hat("/usr/bin/gsdj",
	        "47e1d5ccb4921d93c23a9890b0b48ce6aa4e1beb61a5e6a54dc4e664fe138f4b0c451a3bb74beba7ab075530b8236417add10163905ad664eac49f12e4d277d4",
	        1236
	);
}
static void snarf_hat_1238(void) 
{
	snarf_construct_hat("/usr/bin/gsdj500",
	        "90ba03675ead90145393079bd2f33572b75692ae04452af59f813898f2b836bf47b357f33ff97100e58b257a412ab557f827a8865f471ead30b4da9c3808ec78",
	        1237
	);
}
static void snarf_hat_1239(void) 
{
	snarf_construct_hat("/usr/bin/gslj",
	        "f0a5ac18ae89e48051c8b2a8ccc0f5d3da61e1ee8f66827d3147c7f5c35683d220a8be0e03e8932067fbf7cd2448801a33d8c6410977a041b890b1a2bcba15cb",
	        1238
	);
}
static void snarf_hat_1240(void) 
{
	snarf_construct_hat("/usr/bin/gslp",
	        "954d3734e5d17337e9a9dd56d0177d82d3e053f833eb690591501cb8492c6bf664284498bb956fc46ee9e65e39c4b49989332b6457ae10c5c830b2c9b508efac",
	        1239
	);
}
static void snarf_hat_1241(void) 
{
	snarf_construct_hat("/usr/bin/pphs",
	        "4799f0cae5ec9adc17c655491e69e74e978aaa7e32c597b0ef94b3a928a0d0d941f64d6f847f1d1d7ac77c29e69e75b4c1d4b50845438dc65736869ac037ac20",
	        1240
	);
}
static void snarf_hat_1242(void) 
{
	snarf_construct_hat("/usr/bin/eps2eps",
	        "58f24f6315a46c82398daa3d8ff9cb3ddcce00d1afc022475fbc4703790d09dcbde7d689abd0a5112dfd19d4baf3dc862452ae6dfd42e3c5fb57521e21d49ad7",
	        1241
	);
}
static void snarf_hat_1243(void) 
{
	snarf_construct_hat("/usr/bin/gs",
	        "e339d2e60a26cb7d958f5852cc78ebbfdafb725abdb0ac01c7b780285635e51b23327d2681473956315bddf44dc0f416ee86cbf76295b2178854d53d3e9fc92b",
	        1242
	);
}
static void snarf_hat_1244(void) 
{
	snarf_construct_hat("/usr/bin/gsnd",
	        "34f183f1e10afd158192fe8cfcc5347fd2ffd5601c3e088d7fd412d611776f7ca200a7d893367fcfe356624843dada14f6d774d4eb520897d519c7964c51dbc9",
	        1243
	);
}
static void snarf_hat_1245(void) 
{
	snarf_construct_hat("/usr/bin/pdf2dsc",
	        "7b1caf2c9324034f36a1312d07bf165424b4c9ca610d02de56f6c1f3714e0bc9ea265551a3abdc0e96b5ac21c8c49439d04756720c78a80cf7376614949c7340",
	        1244
	);
}
static void snarf_hat_1246(void) 
{
	snarf_construct_hat("/usr/bin/pdf2ps",
	        "c62bf0cdb0ba3390e0ea10fee99dfb4ef3d90ac0e34c6dafbf404d5ea49764e1caef1b7f4aa46137366f6873ee1ccc4ec6ee3d6e808e646cf24fd0dd9d42360e",
	        1245
	);
}
static void snarf_hat_1247(void) 
{
	snarf_construct_hat("/usr/bin/ps2ascii",
	        "c2a9732ec11e5adcf35159c5b3d7b5401d2db7a1bbeb6fe36e3dc3dab9ec5534750355590129f02db0c3138454a8d054d67278360281ff98bd8d565258f200b3",
	        1246
	);
}
static void snarf_hat_1248(void) 
{
	snarf_construct_hat("/usr/bin/ps2epsi",
	        "1e938d54204dcbc4785b5396be3e39dd591c28238fb59ba4d3fb36347b3b98092bac145db38e9cceabfb474120b39b3bc820ea55be1fe9cf672284243c871824",
	        1247
	);
}
static void snarf_hat_1249(void) 
{
	snarf_construct_hat("/usr/bin/ps2pdf",
	        "daa2eddb50e4c5ba8c77c3add063fcc3607378fa6989931c728bfb61b6a6e36c0074663c9f3ed4a9c8fead5c751a0898a368c642871579d9c56710c16432e7ef",
	        1248
	);
}
static void snarf_hat_1250(void) 
{
	snarf_construct_hat("/usr/bin/ps2pdf12",
	        "d934ac49bee088dea38c23cbd21a02c720f5828851dddb3d93b08191c0cd83cd1a2fed065a6710ff0abbd8f892bba255bb17ab34abf48a2eb3755c27fb0c1927",
	        1249
	);
}
static void snarf_hat_1251(void) 
{
	snarf_construct_hat("/usr/bin/ps2pdf13",
	        "f2616777575426a6a23870a1f4644adec33bc371c240ad211b5b4451433ce5db21de01c61f3d7562bedf93368891838827ff9ac6896cf00168f196b14a25b098",
	        1250
	);
}
static void snarf_hat_1252(void) 
{
	snarf_construct_hat("/usr/bin/ps2pdf14",
	        "74223d4a0eae9ee9624e044fcc708383edda0be5e0ebc82ac5d5d6830e4c17f7b31a65355f9079f892d0ae2897a834ed37a06f6ee9c13fda7dac46537dbbf8ac",
	        1251
	);
}
static void snarf_hat_1253(void) 
{
	snarf_construct_hat("/usr/bin/ps2pdfwr",
	        "a6d7259da8bc10f39ce6b5d4d7e0c1a404cea72c7e65d23eb190cf7ae582319db33ee2a92e637e012a561bbb0e2bbf21d8cebc8b5165b5f7021e1b4dc006a578",
	        1252
	);
}
static void snarf_hat_1254(void) 
{
	snarf_construct_hat("/usr/bin/ps2ps",
	        "a419038cfe2718c5ed6ee52821809b442a46b160fe1cc7f7a6325b39d5894c14fbdfa727018ccaa573611164cef27ff142de54bc8c582a36f077303d27607471",
	        1253
	);
}
static void snarf_hat_1255(void) 
{
	snarf_construct_hat("/usr/bin/ps2ps2",
	        "99de762151f163ad44b4cf54b483e0674029fa986bedad8196697926ad9fedd0917b4e88b1466b9fc1e23191ff54e6909d8adb7dc9d7e003d5c3fcd06bf95596",
	        1254
	);
}
static void snarf_hat_1256(void) 
{
	snarf_construct_hat("/usr/bin/qemu-system-i386",
	        "c3f5adf902bface410f3f595700a7c8515fbfc51e19b7bc9660b540f1d7dffce245b46018b3b26c6f93a5e0ec051c05496ec1ca3b606bb28e0f2c5370bd11abf",
	        1255
	);
}
static void snarf_hat_1257(void) 
{
	snarf_construct_hat("/usr/bin/qemu-system-x86_64",
	        "c3db8fbb454075c242e196f8328b0ddfed99b642d0e8802dd966d695eb5c60590d2319cbfd09eca01e124f0f7b5d2b0021217451bb5c6d307dd0e805a927da2a",
	        1256
	);
}
static void snarf_hat_1258(void) 
{
	snarf_construct_hat("/usr/bin/libwacom-list-devices",
	        "5d4a7e3507542f29ee3d799e6493850ecd1e218dd1c98a2b2cd34b403943a01594aa9696937bcab3deaf356184de39416d79ccf2a77a153204b81e29ce30afe8",
	        1257
	);
}
static void snarf_hat_1259(void) 
{
	snarf_construct_hat("/usr/bin/libwacom-list-local-devices",
	        "ef8085f0044eeaad51cbdf10ecb546c8745aa1e7c3b5f2c24efb8380206a3de427178b1057d76f8923bd6e7e7a8f6592710ac63ad64be9945eddded625612b16",
	        1258
	);
}
static void snarf_hat_1260(void) 
{
	snarf_construct_hat("/usr/bin/libwacom-show-stylus",
	        "d357cf44218d08ad0e4b145022001b61dc36cfacd8445c258a4a4608fb402ccbd3bc0006541773b895a6d7d5139d72a3af3e18cfccff95c21ddb62fbee090ce3",
	        1259
	);
}
static void snarf_hat_1261(void) 
{
	snarf_construct_hat("/usr/bin/libwacom-update-db",
	        "bc87797c05bab12b6de6f939b9c7d15b70948adfb3d3ee476e6c8a0ba838489e4694b4d6ef6c585db8adf1eec7d148ce1660889e69177be18f64da901ec9d817",
	        1260
	);
}
static void snarf_hat_1262(void) 
{
	snarf_construct_hat("/usr/bin/libinput",
	        "03de6b81284be0c3071bda801432b7ac34433cb9a4582a5c44adbe7860fdd9b698d91ccf9d9ee178ee34fa7c737abdd900f09cf2a2c54a86d669953a54fc2f44",
	        1261
	);
}
static void snarf_hat_1263(void) 
{
	snarf_construct_hat("/usr/bin/nm-online",
	        "6a71af07fcb232664dff91f4ea8f40fec056d236bead127a21ced0c6cd82da1637523796cd8db74cfcb12471f0d7221694cf48d46df395381cf7213ea6339d3e",
	        1262
	);
}
static void snarf_hat_1264(void) 
{
	snarf_construct_hat("/usr/bin/nmcli",
	        "87bca35a4738b2fcce96cb5e76b4daed3c1c43ffdc4be9de130115ce6af9f6b693745e209b513ed4914f1f0a7c98dd47cd9620e64f9838ef1d9a82d85fcb1e18",
	        1263
	);
}
static void snarf_hat_1265(void) 
{
	snarf_construct_hat("/usr/bin/virt-admin",
	        "aa9134ffdec949e4f1d5d6bda2b552df77e44d913cf20f8ba3517be5d26939546ad2634b46264945098bdfa0ad7b52aae018195c47b74a5e4756c3e18a9498db",
	        1264
	);
}
static void snarf_hat_1266(void) 
{
	snarf_construct_hat("/usr/bin/virt-host-validate",
	        "7fa41cc9b1910a9ed1a21f3bf5cdc2790284a2397ead0ae195d7ecd003458da8e6cc85898db41459143d28046bd76d9dbb3f307b9f06ca03fa61e5bcbf09212b",
	        1265
	);
}
static void snarf_hat_1267(void) 
{
	snarf_construct_hat("/usr/bin/virt-ssh-helper",
	        "949d9fe840999bd465b010b8a3af49c1cae295ebcce976221b97dab1971f1c54b08e5697b511e73d10ae9ee601041c48890b7b4f72c346ad13d69bfe34ea1746",
	        1266
	);
}
static void snarf_hat_1268(void) 
{
	snarf_construct_hat("/usr/bin/curl",
	        "d78bbd2236bbdce0b2a6ee165a8ed2a19eb0147d6364505e5983de2483fe85786cbc2d1747619b4153536222048e81ac9ef2fbc0466b9d5049e7b338d220081a",
	        1267
	);
}
static void snarf_hat_1269(void) 
{
	snarf_construct_hat("/usr/bin/rpm",
	        "507194f946ea9420fd4f281744168cd8254bf8190f930723ef18ea2acd608fc8ee6cb3a296ef929259ab526dac67301d5aec2c8709d2c352b99ab7ce5888bf03",
	        1268
	);
}
static void snarf_hat_1270(void) 
{
	snarf_construct_hat("/usr/bin/rpm2archive",
	        "0b788e6a580ab2f766344e985efbc139c099149187880c52ebd9b94de12322905fe891a45049711eeacd595b0bfb886ad6ab378cd73b1be573d0fbcfcbf8275d",
	        1269
	);
}
static void snarf_hat_1271(void) 
{
	snarf_construct_hat("/usr/bin/rpm2cpio",
	        "3119772900ca5c845fef29e3c0b5e00eb678f5409031a4adfdb9afd1088db406733fb6e23d59313e21da5d2c727154acbcb1744dc5851d9216eebac6949842a2",
	        1270
	);
}
static void snarf_hat_1272(void) 
{
	snarf_construct_hat("/usr/bin/rpmdb",
	        "298b08dcec648574ff5f7de0278ef91b2c9fc1baaa8f6e73fbdcc848f4469546616bda41451c1846ffbdc486e94d606396cdc80ef1af2ed377a60d8c9b3ae658",
	        1271
	);
}
static void snarf_hat_1273(void) 
{
	snarf_construct_hat("/usr/bin/rpmkeys",
	        "63d5d2e88bd4fa27cf50092d43c74e452e023aa5d0cdd6b70c0fd3b4f512b03a24c1d6f5fde3236b75690fff466acb064d844a9df97f1f3a2d0f89c1fba3d129",
	        1272
	);
}
static void snarf_hat_1274(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-python",
	        "b92634081a42692ae9d1a1c591d8df3bcf4f39eed81cc7c3fc4d4c377606344ab341edf502f5b28a59e2102c0101ef0d2f83bea1aaee98b2e0aa55e56d496226",
	        1273
	);
}
static void snarf_hat_1275(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-xorg",
	        "a7bc4d3e0afedc2d60715806097239460f6f23e96fd708ff183ea3b153b4b2c7b3a346752324323847b3bfc96f322d0723e353b88a77fef3f280c3f79de81d9f",
	        1274
	);
}
static void snarf_hat_1276(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-notify",
	        "f455333d9283657e7b8ff86697e3afa790ffd5412095ff33158bc88a250db6ddd71ab40a1728f65d08dc0ecc637528ed97c21207fc8a9e82b559fea8ef44d76d",
	        1275
	);
}
static void snarf_hat_1277(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-save-package-data",
	        "82db318b1883be141b8d34dccead03247b40105bc7b492c65d562e88d07b40481ac8218fb470c70f5993970ebd855070c4f0b7413c025771a82e93114e6fbc16",
	        1276
	);
}
static void snarf_hat_1278(void) 
{
	snarf_construct_hat("/usr/bin/abrt-handle-upload",
	        "4da0108d44660afbe8d0136164b41e4a72fc6b9402af9568e46c02cc08143ee571029107289853d4b8ceb32e5e5685ca1cd01286ff353274b5867b808045265c",
	        1277
	);
}
static void snarf_hat_1279(void) 
{
	snarf_construct_hat("/usr/bin/abrt-watch-log",
	        "9e32b830ab215f4d8dbea5d400d87fae428444dc817a90775fc50b7570916f5bf5ea6c3d1ccbeb2795a98363ade93f1647e86bab25e5ba9ba3be61263854135d",
	        1278
	);
}
static void snarf_hat_1280(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-oops",
	        "78c66831466d734d99505082c5780db3045f1279fb27bc6c15feedb12295905e0c1fa2f61daccf4bbf0f5ca90ab87dfcbe39dd1c0b99a2b94654e72399f17d8f",
	        1279
	);
}
static void snarf_hat_1281(void) 
{
	snarf_construct_hat("/usr/bin/abrt-dump-journal-oops",
	        "80399c00b815d9d90e3955a6d44d29dc8c416c92506f323e3bdb3de76acd2cbf708d7e58ed1dcfba7f4e95c40855642f4fcdc26737c2d7238f9895b1f91f5d3d",
	        1280
	);
}
static void snarf_hat_1282(void) 
{
	snarf_construct_hat("/usr/bin/abrt-dump-oops",
	        "50b1cff94832e3d09e23f93e5b8eea0d5814673719533adb2c4c52f3d3ea168cbaf8ccd84997f20425d4176034c0f3e872562df46f23faa2f73422c480cc0308",
	        1281
	);
}
static void snarf_hat_1283(void) 
{
	snarf_construct_hat("/usr/bin/modulemd-validator",
	        "63353f56a5a5bc21341b49f36d65594e6ff79b792641601e8110d1c5058ed2415c033006293c845ec2905b0f627c167d3688b5b6f6f2787eebc252b25beebb9a",
	        1282
	);
}
static void snarf_hat_1284(void) 
{
	snarf_construct_hat("/usr/bin/abrt-retrace-client",
	        "1a0c65fb6b89268b6f7583df325a7b5a79035dd7f100bd61448da3f6da849af97f522fb42caf81adf45fb8b406ddee02884068af5e01c4747488cbab9f555185",
	        1283
	);
}
static void snarf_hat_1285(void) 
{
	snarf_construct_hat("/usr/bin/gdb-add-index",
	        "fce8793473cfb94f13e9ef851670c35253a2c62ff254864acf274be7d7060703512681fad86a42e0356c737f8747e6abaa28dc90edb36c350f8a8c9df495d5dc",
	        1284
	);
}
static void snarf_hat_1286(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-backtrace",
	        "d7e8e74af4dabf4b21217dd690655b65777852a2be2ef55d2de34515a7332f5efddfea5eb2e0e5b45e9d432388660f398b9f5f0cd455a64106b807765140cf06",
	        1285
	);
}
static void snarf_hat_1287(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-c",
	        "f98e48571a9f9edf9bf8446658d8e0e95d4e7066822cef55022ae86c83d0f3a31cd88631b5a69f9ad49f9b6e47d49fccb96a7e5a1badca5a7f97c9f853d47347",
	        1286
	);
}
static void snarf_hat_1288(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-ccpp-local",
	        "792c8ac1c68c1b23a9ca2f71f61d30e8fcd18ba01c15b882d2c758130bac8643b1ef03ccbfc560efb74cd0eba9c9c2291d61be25b92c5c841ef0fbe97dd4313a",
	        1287
	);
}
static void snarf_hat_1289(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-core",
	        "f6d72bce4303c3fd9d4ee642dc9340718f1ff459b2822237e20b11ddfd7c05ffe86217771ba49f1534c9e114a7454fe8d58a36bdc464b47055fc184629da13f8",
	        1288
	);
}
static void snarf_hat_1290(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-vulnerability",
	        "47e5a2b7f103fe86d6cdef042d45719092ff0b9c0fc96fa9f11414887c2510915dc725764114dc14c3a85d144f1e6f256dd894a5e214965012d515ffec76853f",
	        1289
	);
}
static void snarf_hat_1291(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-generate-backtrace",
	        "222990c0e7fcc2a777925cb9e8467e7241f34812e2cde8ec556ba0083a411fccf0ffe6f43da978093e22fb95d5e5e11bc8efa210b310dad14951b8038053f1c0",
	        1290
	);
}
static void snarf_hat_1292(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-generate-core-backtrace",
	        "62c67598fa019b49575b0c482156ed44eeb4bc101d2a80f637558bafd8a5a66f53b4b06318f27f8e75ff0f03d4788bd087ecfb203489f73203f3a534e8f0d14d",
	        1291
	);
}
static void snarf_hat_1293(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-install-debuginfo",
	        "18ca749a7842cb838fea31d7e15e0074c3776341d86b972c70d90662a066e35dc1689f8d8b0271661f0ad6d0cb0cf961a7b8c866ff7b8e2fb5029fe34ea7a6d1",
	        1292
	);
}
static void snarf_hat_1294(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-list-dsos",
	        "64632a92b7d95a91f7849efdd0239326c7fbe27a4f18d5839ed7259fdc083f43cd22689e5279e5ec61e8f2abd25b6f385651908d7ce03951522fd01e2f951728",
	        1293
	);
}
static void snarf_hat_1295(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-perform-ccpp-analysis",
	        "3134928bfd49a3bad48cc7db7505ac0370f9a9cc79a74d94981f54e2e6fd37465966dd4080bda3d279e0b05288a85cf84b23c6d7df023eb4f337cc27f47638f2",
	        1294
	);
}
static void snarf_hat_1296(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-trim-files",
	        "20e487a8531c756a67c5d30437343fd2df739285a2c011a4e386d0d08df9f534df5ccae3d43b88625dd09b98827f7bad0f28fe71e963dab583047fa03bf6a437",
	        1295
	);
}
static void snarf_hat_1297(void) 
{
	snarf_construct_hat("/usr/bin/abrt-dump-journal-core",
	        "9281a3a74f380b40d7edff95656855e8aaeac04ca977e5e77f423b40e93fd162e63e35fbf7392c13369e65eb82e8576ea0007680a1cc563ca70ca999a1a4c959",
	        1296
	);
}
static void snarf_hat_1298(void) 
{
	snarf_construct_hat("/usr/bin/abrt-merge-pstoreoops",
	        "653ce82b64fef14187b0f85800d0b4bf1481e076b43329a4d8e60ca0e9e77ece979eac85f1e54d5e95eebcefa1091d1f18c0996032c8f475b3baa942cb7a8691",
	        1297
	);
}
static void snarf_hat_1299(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-analyze-vmcore",
	        "dd906c35a9be551b4eae062859bbfa893a135fef287f044b913274dbfdcd39b299151b4d4dd6c920d3e036a8d0744d9730d623255691cce50a6b7394b7476b92",
	        1298
	);
}
static void snarf_hat_1300(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-check-oops-for-alt-component",
	        "0bf7dc2c8d027fd5db2dccff8ae2842a832f455cfc3d54ca2db0cfd061ed65ceaa0f29d9d4dd9b773108d9f796f102d72e831002b4d598aec8d9ba794d1d45f3",
	        1299
	);
}
static void snarf_hat_1301(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-check-oops-for-hw-error",
	        "6a419ac31ed4f8770694d2e1b15da87ca07e086d79a54e58654000ddbd64bf037353566e80445578298bd0171374ffa78ece3dc3e36c592f2a76b395da30923a",
	        1300
	);
}
static void snarf_hat_1302(void) 
{
	snarf_construct_hat("/usr/bin/abrt-dump-journal-xorg",
	        "a3b788e6bc5c15809fed26017a2a8e9da49623c801b41bd107dfd1a90aba77f624e630b396681a51b60e5129118ce4a9c695c1b1d3f1c8b5f1c0743cfd8bb440",
	        1301
	);
}
static void snarf_hat_1303(void) 
{
	snarf_construct_hat("/usr/bin/abrt-dump-xorg",
	        "8c724cb5b5a88569cc7b05c9eaa71c05cd4bd77c93a438ff2a02bbdc2f1f81fc392743c6a61035a922e4bfa357ec31c1f35b86370dbb48cad18d2114557a4652",
	        1302
	);
}
static void snarf_hat_1304(void) 
{
	snarf_construct_hat("/usr/bin/abrt-action-find-bodhi-update",
	        "e48e401c378e25699e3b298ac2ab24938530bae63f1f283876b115819d3888d0448b7032153cd6fe0734f2ddb5b41534e1555251e8ef0c706f97a77e5368bb44",
	        1303
	);
}
static void snarf_hat_1305(void) 
{
	snarf_construct_hat("/usr/bin/abrt-bodhi",
	        "a2bba02b2e24cde7d9129b41b8571ab7b06e4a547e1bbf2a43fb810c864ec926ddd7357c4a10542e92f4127acfe8ff21a8426c67633ef06deaedb50e0ccab863",
	        1304
	);
}
static void snarf_hat_1306(void) 
{
	snarf_construct_hat("/usr/bin/git",
	        "9deacbd1fd5c2055bf56b688e576a1de89bffac18581ed9956b1022d307a64f1b50ca5714f5d78bc2ff56b8fcae86ff92465883fbf06aadc079a3175fb884370",
	        1305
	);
}
static void snarf_hat_1307(void) 
{
	snarf_construct_hat("/usr/bin/git-shell",
	        "23cd2c23d10baabb0e1b132728e8e8ea0f1b56a02a039c4c7231f46664f94c8abeb1ea952bfd313e791aebca00e18d771d4c6da528588fc40c6dafc386b3bf65",
	        1306
	);
}
static void snarf_hat_1308(void) 
{
	snarf_construct_hat("/usr/bin/abrt",
	        "0fd7dcfcd110dd5f6878661f65a681f827fe2a1e5b2e3b2e685876600f7f7c4f8af020d2fc8eebf43deb00280560eff7f77d08a024581511addd11e6249fb29f",
	        1307
	);
}
static void snarf_hat_1309(void) 
{
	snarf_construct_hat("/usr/bin/createrepo_c",
	        "4488177c75e3cc9ed7982eb4a2f1be40913dd53983640c499d09aa786d4ca6eaefef3f9570d011dad0216520d09bbce43bf49f16f57a7230262d5d0c49925bae",
	        1308
	);
}
static void snarf_hat_1310(void) 
{
	snarf_construct_hat("/usr/bin/mergerepo_c",
	        "21e8236f79b8bf2c02a3d9a43f0dec920b71e370366b9b24b79e471b1c8efb92fa4c31cdabb4d0f99114211bf17e273134d70e9743c21752e83fa5ff4f41775c",
	        1309
	);
}
static void snarf_hat_1311(void) 
{
	snarf_construct_hat("/usr/bin/modifyrepo_c",
	        "4de81b42a5dc9411c027611e2806f69f2a7f8c49b4afb7ec8677525ec2d97eebaa207794b16c6f28d1036adff8edb45c06ffaf21ab3e1299c7aea827417d063c",
	        1310
	);
}
static void snarf_hat_1312(void) 
{
	snarf_construct_hat("/usr/bin/sqliterepo_c",
	        "c741d60cecd6539e26d8959e3cabae6659b1b79bb2dc4ca54f48566d6926097f31448b76c5fbc9d4d7b6d35a51ba3ac3ca0ffb9b68f0697fdf01d0e632dce3a6",
	        1311
	);
}
static void snarf_hat_1313(void) 
{
	snarf_construct_hat("/usr/bin/pkcon",
	        "7a62d169d68b082f8f15e7454d319c563db94125b52d441263d8ce3bdec2f94638fc0e0491c6751674758662615cb2df66a6d4a4c9d743dcc31ce49010c4e36a",
	        1312
	);
}
static void snarf_hat_1314(void) 
{
	snarf_construct_hat("/usr/bin/pkmon",
	        "dc9b29dfbda918604490dcf2ab64f7d7316459a516ccfdf573423bd8d6ee326461366f0f85b5c714c9de14fd24e20c3ba2dbcc3383b552e54cdc365b369e46c4",
	        1313
	);
}
static void snarf_hat_1315(void) 
{
	snarf_construct_hat("/usr/bin/machinectl",
	        "9c89929c1fbe410692c44ac3eec42ad4ef4b58eadd791c5733b94c0b6af956a760bdb2197e37fcffab7cf61ce7c380ea13a84363d6723e89fd645be899a9d14e",
	        1314
	);
}
static void snarf_hat_1316(void) 
{
	snarf_construct_hat("/usr/bin/systemd-nspawn",
	        "050bbf2cc7e128a939815023511c943fc10ef48fef9f561fb1d5b2a1be57bb403c3e42be2466cf1c4c83dfd41196900ce59bb6569d23ae74da260d87a2497d46",
	        1315
	);
}
static void snarf_hat_1317(void) 
{
	snarf_construct_hat("/usr/bin/virt-qemu-run",
	        "cb38e72a177b29af05d1c5cb79c324fae3207da6f81e1543fb9c41121cd78eea3c9eb66b1d06c92422809e3c6ae72c26b0dc345272e460d152fe9d8927e1b468",
	        1316
	);
}
static void snarf_hat_1318(void) 
{
	snarf_construct_hat("/usr/bin/chvt",
	        "768b6ea8c1aeb9441bbb2d50f6434fd71cc97df9cddd485a47967e8891dd9f0827cda4ebf72ea5a0fbee643beba3eb2b9305b50d37fd7fbb09148a301a24cc2d",
	        1317
	);
}
static void snarf_hat_1319(void) 
{
	snarf_construct_hat("/usr/bin/deallocvt",
	        "b342ec6e1e9576680a848b349ebf1f7f3f45ff6dc2f500169c5090556927b5382cf82be111d58c37e5c410083462c3412eed7fb1d10ddbfd7f3f73e58e3a723d",
	        1318
	);
}
static void snarf_hat_1320(void) 
{
	snarf_construct_hat("/usr/bin/dumpkeys",
	        "ebaa35cc1b26e0027f3c40ee98325581ec8414c2a40235559e07965c149f64e9fb426eea9ee5ed366753ade7b773787d46f99b6ab5a4ac42eebf23a2aed8dffa",
	        1319
	);
}
static void snarf_hat_1321(void) 
{
	snarf_construct_hat("/usr/bin/fgconsole",
	        "06e2dff8c90cd276f890e0160d962e751059c7b522817f372402fe39000c2e4d03a6186f0916901dac1056aa2120fec44b2db892785cb1c742a1727f4ca9aa31",
	        1320
	);
}
static void snarf_hat_1322(void) 
{
	snarf_construct_hat("/usr/bin/getkeycodes",
	        "8fa53a066651e21d0cd665a0013940635d65d59ad3be9a1f0330fceee7557011f90aec3a68217e7a420b43ec062f77ddccb3a676145bbc54a4383b7cff1ab687",
	        1321
	);
}
static void snarf_hat_1323(void) 
{
	snarf_construct_hat("/usr/bin/kbd_mode",
	        "a47512d76105e8e28fe5e09ad3be776c4cd130de224dca4ea60a70f37c139bc750e5045734da3391bd392731a26842f5944db46326a4b189eb7ca210c6a3ceb2",
	        1322
	);
}
static void snarf_hat_1324(void) 
{
	snarf_construct_hat("/usr/bin/kbdinfo",
	        "3a816e4cff9a25896a28b55ddb6db1783fbad9affe4963cec67867420400d14f3747959562ce1cda6dd52a1482583bf7a944effbd6c467fe27c5fb0abdf18e24",
	        1323
	);
}
static void snarf_hat_1325(void) 
{
	snarf_construct_hat("/usr/bin/kbdrate",
	        "148d207b6048c91e3fdbcf38a6f91c63aacad40e437062f773466317e3d1fbb5b212c838dd0ea25aeead6e9652e24e5547be2f957abac55e136231f958bc9c58",
	        1324
	);
}
static void snarf_hat_1326(void) 
{
	snarf_construct_hat("/usr/bin/loadkeys",
	        "3b27b970a3246a45ad6589c0ea55fbec33a3a51227bb0b703f3e52a971ccc0d6cb4aa1a1ff5d06469ee97156320af9caad7085de22f9e501bd7bc7272d17632b",
	        1325
	);
}
static void snarf_hat_1327(void) 
{
	snarf_construct_hat("/usr/bin/loadunimap",
	        "3b82ab3dcb06783899a4ba4092a21869cb147c86451dc4677510f20381424df7e8f49d5432df91fec07188205a23958e38c57e2de5fb3ab80cb7f23fb630ec43",
	        1326
	);
}
static void snarf_hat_1328(void) 
{
	snarf_construct_hat("/usr/bin/mapscrn",
	        "c66976aeb803f62b6b985ec148d539b083cb3ceb7d3f2be11fc78c1464817d8cde109b52f2ba535e9e2defe17543b73141737d3836101e099a27ba42d5b540fa",
	        1327
	);
}
static void snarf_hat_1329(void) 
{
	snarf_construct_hat("/usr/bin/openvt",
	        "ab08fe23b3455d9894db34928f049c2bbda3fee0ff0094fcf324d473aaf9fceabe3562725eb81d7534da85811bfb5fd1154ae0d60e65b2f67cb9a71780c6360d",
	        1328
	);
}
static void snarf_hat_1330(void) 
{
	snarf_construct_hat("/usr/bin/psfxtable",
	        "23dabfaae8fb2a649250444dc98de36c5110fb9213d85a237ee009b4f3d9f54f3a344f614de5e1ebf5fef22241c96d4e6563b0c4870344452af88e471b5ec03e",
	        1329
	);
}
static void snarf_hat_1331(void) 
{
	snarf_construct_hat("/usr/bin/resizecons",
	        "ce442d07438b19c674cd42bd385a084870ac43285ebca95ec227c89690185a82a0896e706dc4978cb313fe42c1612d6f25aa7af867c611f5343891b896cad5a1",
	        1330
	);
}
static void snarf_hat_1332(void) 
{
	snarf_construct_hat("/usr/bin/setfont",
	        "171565123bc95c0c7df7472e9523899fd34b4be6cf0780e8ddb5e96bc4bad0a2f986a3ca0ddbc322ce189f664628138f34de9668f6431773c344ab4c353626f1",
	        1331
	);
}
static void snarf_hat_1333(void) 
{
	snarf_construct_hat("/usr/bin/setkeycodes",
	        "dcc8b682a7e4c53b8d8a45636cad86ba03f3659a2d789599aa697b61395faaede719c663325e1261ab48c24c479501d11e27e2c7c11a3f4194e72e7d9c8ab3dc",
	        1332
	);
}
static void snarf_hat_1334(void) 
{
	snarf_construct_hat("/usr/bin/setleds",
	        "43fb655f5845d99597de062bbf36339539d760f0b8ce6ee747a7b29d3a631f573caeff838b7d309bf0592469e2ee9aa4cd78c2f30027b2ab81cbfe341489d065",
	        1333
	);
}
static void snarf_hat_1335(void) 
{
	snarf_construct_hat("/usr/bin/setmetamode",
	        "6dd6b34ac9c613348ce2fbdc6f00a6a7864483be92a84eff53f9a928cfca601a29d318caf4c58d7fb4b11169758a2481728a3917819f6bd3e19729ba6e24748c",
	        1334
	);
}
static void snarf_hat_1336(void) 
{
	snarf_construct_hat("/usr/bin/setvtrgb",
	        "d5de5e33e1d747885a294a3bbcdbf7db008fbe3180e9e53ea4e07f661f226ec9d4b1be21355ae6dba41a605d52e38894ba1f4ca4525d7badb39d76039fc97d16",
	        1335
	);
}
static void snarf_hat_1337(void) 
{
	snarf_construct_hat("/usr/bin/showconsolefont",
	        "f2a85042713abf5bc40ad599b2b377f18844a4155c2f70a9dc1cca11d6f729133b889408b181bafc70c809340c5364ea70df1d50fa05288271332d2beacfeeaf",
	        1336
	);
}
static void snarf_hat_1338(void) 
{
	snarf_construct_hat("/usr/bin/showkey",
	        "7943c1908b9698844d7531ccc1d54131d29d0a8841720dc82bf7f08a126aea83e0b3199c7b011e14c321f3262f481d868ab976b6c7b2a7e01be8f94b61506bc2",
	        1337
	);
}
static void snarf_hat_1339(void) 
{
	snarf_construct_hat("/usr/bin/unicode_start",
	        "099fa1297bb13ffab3977b96b34079fd9a11fcd04f44d0d4d8f45e601f4a860b77d8a095ca77d2bffa096f33b115a8c6cc895d39dd0728240ead1e0e0be3d340",
	        1338
	);
}
static void snarf_hat_1340(void) 
{
	snarf_construct_hat("/usr/bin/unicode_stop",
	        "b143fa197869b2cc558d60ca190ba0d163eab26c12ca13252d344c4b8d9743bb4fd089c5bbc4aa6b344b542b1664034a3e25fa12d68e3e53cf0bddca3ccb3831",
	        1339
	);
}
static void snarf_hat_1341(void) 
{
	snarf_construct_hat("/usr/bin/vlock",
	        "5417dbeefab1b0053567fcf609886c5d215cbc0019d8d448adb32b23e73622b270e7177942ab0e5eb412a3556a4bb08753d8def2782316b2a2edb17a75f35341",
	        1340
	);
}
static void snarf_hat_1342(void) 
{
	snarf_construct_hat("/usr/bin/kernel-install",
	        "77fcda7adc3ee691832cb4280e6fb15271b5466a8055cf28be082788666e796e258b5049b9c2b04d180d7bc39b43f59d80c46924451f572873c26c6ab609b84a",
	        1341
	);
}
static void snarf_hat_1343(void) 
{
	snarf_construct_hat("/usr/bin/systemd-hwdb",
	        "dad57e2296580138884e8baffe0e5974e716250dabb919b1933e68beebf6c00de0f9a683d0bdcec9785221124ebf9acad389bec6bc52e683d4b12d71355f7314",
	        1342
	);
}
static void snarf_hat_1344(void) 
{
	snarf_construct_hat("/usr/bin/systemd-repart",
	        "891daab233e66975cfb734ced1f9343621e61d49c870b9d4bab80a7bad1a23148a7e1261b8d880adb70f88ee624e87538bb913701c28ddc132b2817891b77ed8",
	        1343
	);
}
static void snarf_hat_1345(void) 
{
	snarf_construct_hat("/usr/bin/udevadm",
	        "787ef7ae71688145275bdfe91c7bb046509a76de9c3da37895db3048f6951e7fb6970e300b17a8f29bb001f8d8ed51064eb9bc4dda6a88af9f140c8fb266cc07",
	        1344
	);
}
static void snarf_hat_1346(void) 
{
	snarf_construct_hat("/usr/bin/grub2-file",
	        "c4d5b546297036a410ee72a1515bb7e4c4ac9e0f842b0508b9af89e8c6a48ea9595056fd5038d84bce8c815b3241c7c68374375884a82f0449f3ccc9965a9be8",
	        1345
	);
}
static void snarf_hat_1347(void) 
{
	snarf_construct_hat("/usr/bin/grub2-menulst2cfg",
	        "08dbdaf24bce2e43fd756ef3b39072abd6ece0fd6f57011900e3858da0a38cba72d43b2163006d5d93dd94ed217018bc5c6a141ce9a81fd3cab5f3d432c32327",
	        1346
	);
}
static void snarf_hat_1348(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkimage",
	        "592e7003525a098df50d2082b98b0a468e107727a71d95ee6d8927cea3ad3e35adaeec3cd2a39b2c4c255cf5d08a4b7fad828eb645079e3d88134dd80717d23f",
	        1347
	);
}
static void snarf_hat_1349(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkrelpath",
	        "73d6d85f7f91286e7ed427a09fca9b045d872294aa7fe3ecc2f8fe9ea00f017d3e558a065ad28bc7fe1144c6c9fecc026deace33fc5f62d1ee429a339ecbb4f8",
	        1348
	);
}
static void snarf_hat_1350(void) 
{
	snarf_construct_hat("/usr/bin/grub2-script-check",
	        "f5ae8b2629cc66d7b87aa8c16a85b9161616716e2a98398f28c9bf66573c67da0e914037424874aaa5952a54eca0f4ac3c5607bea08e9445c90a5301ad5b6440",
	        1349
	);
}
static void snarf_hat_1351(void) 
{
	snarf_construct_hat("/usr/bin/udisksctl",
	        "31d491fef45ec0004b919f1155ed33cfa2d44a6889a2a750926fb3cd49c537c54e6de10cfcfe6a33016f3db5b7b86a75e77204379509ffa5059327f490e85471",
	        1350
	);
}
static void snarf_hat_1352(void) 
{
	snarf_construct_hat("/usr/bin/dbxtool",
	        "525079f71c41124e3e60d26a595000069221696ce583c2086c1971ea95eaef711911f1a76a88f5b5a1eb2a70407e8f673e256174800fb5248457b20dd84695fd",
	        1351
	);
}
static void snarf_hat_1353(void) 
{
	snarf_construct_hat("/usr/bin/dfu-tool",
	        "d43fcd46e1fa30f064bd85127f1253a0fcdda5b8658b88a9d1299fd802fc0c260b46dbcc90b47fdd5e1e50cf159ec3c4c27d460aaf13c26b2a43ff27aa957fec",
	        1352
	);
}
static void snarf_hat_1354(void) 
{
	snarf_construct_hat("/usr/bin/fwupdate",
	        "36dd49841e88f49c1d6b5fada2eee5f580897865870d685f20312be2e0c5af8015dc27da4ab935224acec642725a676ff112bbd4fa38ec7d58a3a25b74b5108d",
	        1353
	);
}
static void snarf_hat_1355(void) 
{
	snarf_construct_hat("/usr/bin/fwupdmgr",
	        "0ef023b871f437ed1b2ae960f3211b171a391f137289410df60d8c80c10a1645777a275fb86c507bf2eb891fb4e97e378bfa8e426f8e56034799a6359f0c780c",
	        1354
	);
}
static void snarf_hat_1356(void) 
{
	snarf_construct_hat("/usr/bin/fwupdtool",
	        "6c0c7c70177fa6ffb3c6484d6da6461952e8aef2cefd9de89bfc4888e55a3130059020e5afcc7435d4d5b93e6704c2e8a9324d6851d7f754512e38043d134cbb",
	        1355
	);
}
static void snarf_hat_1357(void) 
{
	snarf_construct_hat("/usr/bin/fwupdtpmevlog",
	        "38a2fcceab3d93170da66ef724fc7fb9d6df08af23184c52126cb8bd487295b264523270ae89702496449168233d1c94a12ffdf0c2f5e178c8bec2c89db45d75",
	        1356
	);
}
static void snarf_hat_1358(void) 
{
	snarf_construct_hat("/usr/bin/ostree",
	        "e3be9730eac24e443162ad8400ea1451a3f9281427b0bed827471fa0aedb0b5d9dc7d6e01dde6bb26f4072ab7f6ede0503ebfdcf401eaf673adbe78221cf836b",
	        1357
	);
}
static void snarf_hat_1359(void) 
{
	snarf_construct_hat("/usr/bin/rofiles-fuse",
	        "a0b91270a676db325fbf53113c4f40386842713c17c45bf59d58bcfd604174484b2a13768d9531fdaade70833eaced5abf5025ab13a5ae97b10a8519adb38aba",
	        1358
	);
}
static void snarf_hat_1360(void) 
{
	snarf_construct_hat("/usr/bin/fusermount3",
	        "6837dc0fc6d99487446bc9f8765db697e1e0fb388fb0fb8ae930422a90694c37523cbdb756a80f2efec81b443e06183356a703ff2de4e7600de702d48f39016d",
	        1359
	);
}
static void snarf_hat_1361(void) 
{
	snarf_construct_hat("/usr/bin/fuse-overlayfs",
	        "38c14dfe4963d46fcdeac5dabcb9e99b66232690aa9bb586cd01cb1b8ddedd027365fd146df9df86a9c250319a6fe3464268db78a2c93e36872180e189cfd8cb",
	        1360
	);
}
static void snarf_hat_1362(void) 
{
	snarf_construct_hat("/usr/bin/dnf-3",
	        "60d30d12d205d766386d6806da0faf3352e5068f767e904ae1dfe8214d6977b77ac032c9ec2330062e31890a3b6901a182dcdd9e4e8f9100032833b4e8847c15",
	        1361
	);
}
static void snarf_hat_1363(void) 
{
	snarf_construct_hat("/usr/bin/anaconda-cleanup",
	        "7ebf482883efc8c826002af31fb29dd084dea86938cfffdbd3bb51d3cb97d55fa6ff019546da30dce524c8dfe0d6379cae4b02a95896b8fb54fd2a48bcc901e8",
	        1362
	);
}
static void snarf_hat_1364(void) 
{
	snarf_construct_hat("/usr/bin/anaconda-disable-nm-ibft-plugin",
	        "41dd8b91634d0e778f38be2ef3a4a515e29eb33386faed89cb707d13161cc111445a6a3cdb8d2f0421d6c968268bc2d3d6ffaa048e039518f9f9ed9eb7578c75",
	        1363
	);
}
static void snarf_hat_1365(void) 
{
	snarf_construct_hat("/usr/bin/analog",
	        "cb9e7df303f2d361ab136da7e1e1c01407a5094d6b6a83c55d3beb380f1ceb116a32774ee478806bdc8201d284e19d9e7a207b5f4d133d9efe48a87443fa13e4",
	        1364
	);
}
static void snarf_hat_1366(void) 
{
	snarf_construct_hat("/usr/bin/instperf",
	        "23f685cff470e707fe92b1209cce4d06d756504642418b5bf1e93d2f1f76b48455f0289342f80c0319a5f5ff03fbf459cfb674c92e2706c31ab338b7f2c54ce9",
	        1365
	);
}
static void snarf_hat_1367(void) 
{
	snarf_construct_hat("/usr/bin/gcore",
	        "12f188510a9c880b6b17cdaf53f91811a63a95b34836fbfb815559b22583798a263fc90a1c6ab041d2b9f5c4acf845fd361bb14faf40025e30f41178ff43bb3e",
	        1366
	);
}
static void snarf_hat_1368(void) 
{
	snarf_construct_hat("/usr/bin/gstack",
	        "82122f9122bfeabda1c82f9d2c7734c2892dcc238e59de5ab8f57710b301e27d131f48a5c6063d127af9121cd2127b7d8d731ff1ce43f73a94df151759b4ed6c",
	        1367
	);
}
static void snarf_hat_1369(void) 
{
	snarf_construct_hat("/usr/bin/arpaname",
	        "a8b6a984dc6f189b6c0b1d6af4ee5de9a68675f4094b51e09fe4f050619d941b77a4620b27984a14e7f0b5725f20e1dfdfa3235014710d2867736e871291338a",
	        1368
	);
}
static void snarf_hat_1370(void) 
{
	snarf_construct_hat("/usr/bin/delv",
	        "fd1af27649233e3024ad0b6c63b8b5aaf3bb5cc7fb994d4089a7dbce376fb1c53edac31e237223f816059af5949aadee3579b5edb7f7e875a6357f04aa3421e2",
	        1369
	);
}
static void snarf_hat_1371(void) 
{
	snarf_construct_hat("/usr/bin/dig",
	        "fa3d17834b94cd7374028c35d890c8034e58309310c02045d23bebd2af294fe4fd435df3ee32c2516a92164cd7de7e6c878776356c148d02912735e4ca31c94d",
	        1370
	);
}
static void snarf_hat_1372(void) 
{
	snarf_construct_hat("/usr/bin/dnstap-read",
	        "4f4dd0bd4ffa8c64b9726ac9bcb4e739c9c3f9c66f1aa1ccd28de0c03f89655e2ada5b37a2df2128f466a9f8593a1f9a38c7ea5ae238de3b4021cfbfe32d9206",
	        1371
	);
}
static void snarf_hat_1373(void) 
{
	snarf_construct_hat("/usr/bin/host",
	        "12b6c8e37f6a2c1f18a716c19c7b8b6dfadc9e79bb9ef138e28931b9a6f49d605b98a4d1011851dcab25985d62e8ef63cf4c2830d505df0956a42f96573795a5",
	        1372
	);
}
static void snarf_hat_1374(void) 
{
	snarf_construct_hat("/usr/bin/nslookup",
	        "abd58489b6cd75db903a11bf78304d1704246fb2e4ec341b9b4ca1c72de8d2b474d4cbc78f02497816c52bf75084b71ae3278d8bfbd80d88ebe7e2fe9104a958",
	        1373
	);
}
static void snarf_hat_1375(void) 
{
	snarf_construct_hat("/usr/bin/nsupdate",
	        "49d06138c179ff03eceaea384bf0975c124221f94978b49f53976e441d83ca2864ad77d86a2e8eca04246c05466512901ede98700cf20fbb2f6a0dab6b7d020f",
	        1374
	);
}
static void snarf_hat_1376(void) 
{
	snarf_construct_hat("/usr/bin/gtk4-broadwayd",
	        "48f70b3ab0ae9d40d9eb8a033214ae875efbcdf7c0c64e45a2f107ff868158972ea4d0e8f8f30edbc1f46e9fa3be2bda427549b4cf46ea8ce448dc75896e2fbf",
	        1375
	);
}
static void snarf_hat_1377(void) 
{
	snarf_construct_hat("/usr/bin/gtk4-launch",
	        "84f14be9447c527cd2e79fbfb13bf9d8c016debe3805b931918e5745bb0007c32994f533570fe88ebe05b4c2e3fddf1b33ef0acb0fccdffc297886a707f93712",
	        1376
	);
}
static void snarf_hat_1378(void) 
{
	snarf_construct_hat("/usr/bin/gtk4-update-icon-cache",
	        "0ce5ae4bc59d695032e14991b91b71df1943fc1cd7390495a618415bbe77e8bff650c764572940073712b118bd2ebf43bfb4d0785865fac3e9e90dbad2763049",
	        1377
	);
}
static void snarf_hat_1379(void) 
{
	snarf_construct_hat("/usr/bin/libreoffice",
	        "64bd7d15324a2261311d55e3c9c0d8b1f55421a7000342222b07337f4868735b0802898ff5e777ccabfcc6bd7f691da6846e07a1ece51986ae51a454c9551927",
	        1378
	);
}
static void snarf_hat_1380(void) 
{
	snarf_construct_hat("/usr/bin/ooffice",
	        "255ceb1110572ad831f5c7e196867eabb196110df5f13ce118231c8076370942c4d291fd767705f4ad689a9ab3f75e521899525d597628a787a55db81ceff375",
	        1379
	);
}
static void snarf_hat_1381(void) 
{
	snarf_construct_hat("/usr/bin/ooviewdoc",
	        "3b3afe6dfb799233de110322ff0a1e94b5500f6f6f6018798f1f24e5c570b6d1dad77582bf291b2d1bf95db9befa2063dd269d58f275ac0b2e7381fda2d283aa",
	        1380
	);
}
static void snarf_hat_1382(void) 
{
	snarf_construct_hat("/usr/bin/unopkg",
	        "62950b5567f129cae85b3ef75eb47bbc2e4f2cddf3a7838362ea863a607b0cc1be9431524eeeff7867494eb673ac57db46a5be79929ad7ceb3d51de31d9ddf70",
	        1381
	);
}
static void snarf_hat_1383(void) 
{
	snarf_construct_hat("/usr/bin/canberra-gtk-play",
	        "5a0cc14773306e01ecc9cfaa6ee3f168418d64eeae37b1e01105bf680efd5167294616be6740776b794f762941e57ab5c03e9cdbdd01b1278049e751029a65cc",
	        1382
	);
}
static void snarf_hat_1384(void) 
{
	snarf_construct_hat("/usr/bin/flatpak",
	        "21c357bdb2ca7e8ded989deefb2d4c1b426d4d838576be09bc1dd28a284db4605fec3f65b17d99a5a625e328b593f3f618d2f2981aada12a35b26582e67c1618",
	        1383
	);
}
static void snarf_hat_1385(void) 
{
	snarf_construct_hat("/usr/bin/flatpak-bisect",
	        "78babe6f02c52361f49613202faa16fafd9ab3fa5475a205bbe25d9eac1672caab00583744da6b14f02dd68198d585dbf5c4d879b0760c325e76ee139ec8f3d1",
	        1384
	);
}
static void snarf_hat_1386(void) 
{
	snarf_construct_hat("/usr/bin/flatpak-coredumpctl",
	        "dae240e5bcb7e35c452070ab119ee0c4511eaec9f479efbb7461c03b1b7aff42a1b9c6dffb29820c42e567948355eda859b7bc8d5d41f0643f25eebcff6de8e1",
	        1385
	);
}
static void snarf_hat_1387(void) 
{
	snarf_construct_hat("/usr/bin/broadwayd",
	        "35c11c604613e79942568fd3ad89170fd099532d78ace4fc149d021f3f080275144b76807d1b4b207620561067495bcb46a9ce2b457fd64896611f98fcd9b1d2",
	        1386
	);
}
static void snarf_hat_1388(void) 
{
	snarf_construct_hat("/usr/bin/gtk-launch",
	        "af7da250bcb7fcf0955232c52d4efb1988554d9199b42e4f72b02ad0ec34aa90eb88da9da3f4f37a1099b74b54888a5fecf7944446ef952ade3bdcd58b9ba48d",
	        1387
	);
}
static void snarf_hat_1389(void) 
{
	snarf_construct_hat("/usr/bin/gtk-query-immodules-3.0-64",
	        "a92647822aa02a22a5b67ee72c9b7df3b102a3d291723c531e013c80d37c263ac3ae50d73b48671da350c712a5437cee883e13bfcfad4323c22c14a0a17348ff",
	        1388
	);
}
static void snarf_hat_1390(void) 
{
	snarf_construct_hat("/usr/bin/WebKitWebDriver",
	        "b13d78b7f2c42339001282064bb01f47a376a363e2ff130a9f2228248968c3404974e5c24b691370ab4e52d5342982a6e2da0c6c77f76631d4cfe1987d8d793c",
	        1389
	);
}
static void snarf_hat_1391(void) 
{
	snarf_construct_hat("/usr/bin/gnome-session",
	        "78b2999b139c9271b2226696925045c9655ce1c7650650deff82e94c0b4dd5b53fe03e30a03f93cad2a48f3285c63fe6f5778d2eb3a015c577b5ff2a79d93a5d",
	        1390
	);
}
static void snarf_hat_1392(void) 
{
	snarf_construct_hat("/usr/bin/gnome-session-custom-session",
	        "d95770fcb9919654801072fe527b85971fa50bd17d3dc40095e6ce532b2218a7ad0e530af6bea2f20f463d0ed0995b245f27aa7c01c75616b7c65f804a3ec1f6",
	        1391
	);
}
static void snarf_hat_1393(void) 
{
	snarf_construct_hat("/usr/bin/gnome-session-inhibit",
	        "29c264cc93c64bd1792dd5e520c614e8e394a3a406ee04b57d845871d43e04be38ebcfecd9de392641e139c9eb0220b368042d98415a07b2329c7398296aa744",
	        1392
	);
}
static void snarf_hat_1394(void) 
{
	snarf_construct_hat("/usr/bin/gnome-session-quit",
	        "b1258188bb319183265563beeaba944bc9fc8bc46a037db771f109e2086d7c05d26dca6258e9caf4726f142e7a8a568b1ca92f93f088e206b4e35ea5cdaddfb1",
	        1393
	);
}
static void snarf_hat_1395(void) 
{
	snarf_construct_hat("/usr/bin/zenity",
	        "6f037b231f20670c2d090cf8c6c2036495e280c5f4c66c731013deba56038a31cd2597191103c710f5876928fe5196cf064be489f987f2085e2990ba0a1053e1",
	        1394
	);
}
static void snarf_hat_1396(void) 
{
	snarf_construct_hat("/usr/bin/oowriter",
	        "29728eeaafd337a27b2b0c9b29ab541026ccf58c4c2c465a90981b02495dcd9ec8952e538e5c58c3698074397a5fed69ad78a63a61583b3b83b5b4dd637e4bab",
	        1395
	);
}
static void snarf_hat_1397(void) 
{
	snarf_construct_hat("/usr/bin/gcr-viewer",
	        "215044bc98a66fbc6f2ad47be5ec2df27591c3ce4785f25eb3dbf3afe7786282f706a40b80e9959829aaa4ce6e94145b6712a2206fd62cb84456a3cffd2ceed6",
	        1396
	);
}
static void snarf_hat_1398(void) 
{
	snarf_construct_hat("/usr/bin/grilo-test-ui-0.3",
	        "1128f209604a1728b3b69dc49a11cd172493c71347208b2ae292ac0cec318d93600e25fd23619147f6665bfdb9e9ade43e96317687051c1618c0485f6c79aad6",
	        1397
	);
}
static void snarf_hat_1399(void) 
{
	snarf_construct_hat("/usr/bin/grl-inspect-0.3",
	        "19bdfe9c7264e5356109c4adfb1b749234f6fc8dee3bbf912a3eda1ac1dd5da45200e8b83353f9348caee8253920b13832f8cb283f36cfb25cc3d13632021087",
	        1398
	);
}
static void snarf_hat_1400(void) 
{
	snarf_construct_hat("/usr/bin/grl-launch-0.3",
	        "a09d5c64f9b3aa528f131583b5e9e98183ffae5d0aae2e1671fd723d89c8feb5d65354d498a52b6663710f8bb7049134fb8e206837bcbd95659c21a71a267292",
	        1399
	);
}
static void snarf_hat_1401(void) 
{
	snarf_construct_hat("/usr/bin/gnome-keyring-3",
	        "106fe79315ec3eecea974b55068362d2be31025c57129d1c9d464ca7c704aeb5002e380f2e1498127bbcb54ae913e0a757eeaa9c1fbfb6d67d5240355f6f26e2",
	        1400
	);
}
static void snarf_hat_1402(void) 
{
	snarf_construct_hat("/usr/bin/gnome-keyring-daemon",
	        "b58d49d43a0b1671a9d5219dfc8c7b204b58858005f6a123ae96b0aa432c261098a844dbd8a8cfda4c33b96b7288100354af22304a67f1b18f620e539063b2cf",
	        1401
	);
}
static void snarf_hat_1403(void) 
{
	snarf_construct_hat("/usr/bin/gnome-terminal",
	        "e9e073ab6bb511006cf2825eaa10f8fc6f0735a0b407ac1ad38be3396464492212324e8acc0497925a4fd5a0e8d9dd7bfbc3e04988f099a513257526ce0e454c",
	        1402
	);
}
static void snarf_hat_1404(void) 
{
	snarf_construct_hat("/usr/bin/nautilus",
	        "9240b22a7b817621a0af3fc48f11f8f39ca55b3eab51bda1ce454b9baca800ecd7f3c9aef258b187c59300a7798a401062bc3f67dfc0395c6bbd5768939883b3",
	        1403
	);
}
static void snarf_hat_1405(void) 
{
	snarf_construct_hat("/usr/bin/nautilus-autorun-software",
	        "9eb3746aa29bf290b5fe4bceb9c13be0ca24916909b1d4198bdf8b07f9c48f8688d2f03fd2b2e2338f5c02f5cc174c9ac489412b24550e0f85252960f5f31233",
	        1404
	);
}
static void snarf_hat_1406(void) 
{
	snarf_construct_hat("/usr/bin/oocalc",
	        "c7d323fb5294cfadc013fe0095c863a0e877b81ab72d1b03fefd262d71d36efd9739f0bab857e9622ba174e01bdbcfa769cf15592eb14e5cbdeff077b8b606f1",
	        1405
	);
}
static void snarf_hat_1407(void) 
{
	snarf_construct_hat("/usr/bin/mutter",
	        "a38125bab2c666635c93090a9df3d06efd127b688e547fa12b104dae0a3b326a1228c83dd242940da9263b0e1ea5f28abe43a721bdd2289a2dfb907e6c3fb5d5",
	        1406
	);
}
static void snarf_hat_1408(void) 
{
	snarf_construct_hat("/usr/bin/yelp",
	        "3953dd3a1df028db1c3db2fe1089e9aed9d4c239b554137412ab64884998974528e7a6166bdce1100025d47794c128070bbec3df459c4d4124a0990a8562dbb7",
	        1407
	);
}
static void snarf_hat_1409(void) 
{
	snarf_construct_hat("/usr/bin/abrt-applet",
	        "609b57ea8b9f60f5f2d81b7feb49bcdf50be83add46ca82e72327a8773d6fcf2e92ba87642244a9c6761f4614b2b58ee94b3695cb2b7f09c50bc1e768c03727f",
	        1408
	);
}
static void snarf_hat_1410(void) 
{
	snarf_construct_hat("/usr/bin/system-config-abrt",
	        "4245d11b13f3f66e0e5d16e2b45264518ff9f80c662a6d0967d3f9d7220299530e5957b88128e34b83537dab035ebd8e3ab623222d2f4f9a83421641e1fb71c1",
	        1409
	);
}
static void snarf_hat_1411(void) 
{
	snarf_construct_hat("/usr/bin/rygel",
	        "e1255a93e18f602545279d93d2438f0120924ff539af5282e45db85173dc00be5f51d8ff142b93b619d503fbc63ea3bbe227aab2aa46a98431df85df409cbdb3",
	        1410
	);
}
static void snarf_hat_1412(void) 
{
	snarf_construct_hat("/usr/bin/rygel-preferences",
	        "d423ba30fac359a2ef04a3be717fc44d1319a04c4ecc1b5609705d8ab968d515f782c7ba39f4d5827b2191e367032ee3a413a711516ab8dd22789c75626a418f",
	        1411
	);
}
static void snarf_hat_1413(void) 
{
	snarf_construct_hat("/usr/bin/malcontent-control",
	        "36e3f878d1ce0b47a603ee8366440e1312c4afbd1bfb971fbaf2bcc8f9acda977eaed51c82cb7781f0a938ce889ef8f515c1f6ccea1c24e1b0828c2f7ceed391",
	        1412
	);
}
static void snarf_hat_1414(void) 
{
	snarf_construct_hat("/usr/bin/gnome-control-center",
	        "8995d391d4477bf7a8cc6a046b90ac95aa53d5608bebc87f2c0a94542ee9564cc2895819a631a67ff6b1f0b2e379bbf3fe5c7a5b15247c6a6a8ab36d56cac6ee",
	        1413
	);
}
static void snarf_hat_1415(void) 
{
	snarf_construct_hat("/usr/bin/gdm-screenshot",
	        "c43bbcba426fb17eec199716796b795365824bdc1caf42e70554d3553eec42c7a497ef88f0dab473f10768d8ab7cd88d3dc9af34612000ce4794a7a44264fa1a",
	        1414
	);
}
static void snarf_hat_1416(void) 
{
	snarf_construct_hat("/usr/bin/gdmflexiserver",
	        "ab12c410b655e0149f47c2c98ddd4b3ffd21a56297efd9edf0103ecc7a7f44e2534f4c8ae6c86259c4588652c715fa8cc9ce478b849f540c83a1d34c9d836ce1",
	        1415
	);
}
static void snarf_hat_1417(void) 
{
	snarf_construct_hat("/usr/bin/gnome-extensions",
	        "1a56752210c9a821972e5e354eee0f37a63541ea02104bd6b8c829ffd9d6a105c9ce726f7478cd4663b76e8a257cf52ba71b2adff46ed504775865b685abed6a",
	        1416
	);
}
static void snarf_hat_1418(void) 
{
	snarf_construct_hat("/usr/bin/gnome-shell",
	        "7e6d3e8cf201c6ee0c42009fc6956d8c4a2d822ef2096927f842563f58cbe46c2ebce4683325198512bb59e5ae67afa6868b709d7ea4c17d7f846e779923d6ff",
	        1417
	);
}
static void snarf_hat_1419(void) 
{
	snarf_construct_hat("/usr/bin/gnome-shell-extension-prefs",
	        "7ba97137afc0170ee8a63afa32a902ad3d4b8c75bc55261f14b7aeb38621fdb563d02a060352cd1f221d8a8279c4122a152ecfd6aae4d6ce69d407e027b51b89",
	        1418
	);
}
static void snarf_hat_1420(void) 
{
	snarf_construct_hat("/usr/bin/gnome-shell-extension-tool",
	        "68dc570868711db7b83c2c6b33dc47f7a148eae2ce388127757e7959dd44632732ba85e8b5c9059c73425a61fbd9eda1236d388e013323c0548593a300cb2a86",
	        1419
	);
}
static void snarf_hat_1421(void) 
{
	snarf_construct_hat("/usr/bin/gnome-shell-perf-tool",
	        "e827427af23f294a87be2e8f4a202e9eed98c997525bd99d22b8bf0058f7bf50620d099468bd2c9ce2a33fdabab576b952a116a640eb65361211abb4bbe947fc",
	        1420
	);
}
static void snarf_hat_1422(void) 
{
	snarf_construct_hat("/usr/bin/scp-dbus-service",
	        "a22b78be8e5974bfdc26e48ba7a37a12638c96c63990f46f1d52461535c555a4d896c0dc1ebf621b8ae8cbf227cc0fad2c7af9dc27982323ee7be388ff123bb7",
	        1421
	);
}
static void snarf_hat_1423(void) 
{
	snarf_construct_hat("/usr/bin/ooimpress",
	        "a93e496fc54fecdffdadc5b9c94c32d0de742d8d66bd4258a25ecca98d377ed8a3fa91e335ed139c90e2e02f4f0c0b6ed990b6642f49f6fede6b8a5c6c507e9d",
	        1422
	);
}
static void snarf_hat_1424(void) 
{
	snarf_construct_hat("/usr/bin/totem",
	        "41768e65ca0d2630797d4c72bed0e665706a31ea4bc1e1c9b0bf2dba64a863d455363780755d995328cf0ca0279ee8ff9cc442d9543991587dd20797621fb89b",
	        1423
	);
}
static void snarf_hat_1425(void) 
{
	snarf_construct_hat("/usr/bin/gnome-calendar",
	        "56d3eb1881ab4d51482b2094114a243f1ab6809fd08ca1ef89bebc8ece1f91244d69514908adb1e43e488f01d1c8b294e0eb1512bf8e105cf9b5f5c5e9ff18b7",
	        1424
	);
}
static void snarf_hat_1426(void) 
{
	snarf_construct_hat("/usr/bin/gnome-contacts",
	        "a3671930c7081e6671a69c65274de4a99d3aab18d9dd812f354b70af09745aaef147a7369ea226293adbca20b21d610d91a9629ac01bd949ed6b9c9933155d67",
	        1425
	);
}
static void snarf_hat_1427(void) 
{
	snarf_construct_hat("/usr/bin/gedit",
	        "d68c222c54982789f5eebe7bd3869b252d5388074855a83c412cf90fe5955ef82cf1ebfcb832dd97a7ace95ef46e6630e673692b7e9d130bfe203e1388d965c0",
	        1426
	);
}
static void snarf_hat_1428(void) 
{
	snarf_construct_hat("/usr/bin/cheese",
	        "c3111285e8c6a4a0567ee24821b1bc8cb17c873efb055ef9a9a51b9f824297cfe1f979a76e2a4f2790609183cf088d87973e62ba6fba77452f598bd1b246a09a",
	        1427
	);
}
static void snarf_hat_1429(void) 
{
	snarf_construct_hat("/usr/bin/eog",
	        "25bc71576b5e8f0e48bbecd6fba719964d4d386199c100113cb26742090e90e785f37c66d687116296e9d01bf3620eab890038559319c3be058b0fd07b6c8749",
	        1428
	);
}
static void snarf_hat_1430(void) 
{
	snarf_construct_hat("/usr/bin/gnome-font-viewer",
	        "24fd8d7dec089309efc267375dc379a365127e560322c65fd981292e3521b447381a346be49139aa98d8ae5370c258dc66b4bd97b3b409e39b70457a35222c0a",
	        1429
	);
}
static void snarf_hat_1431(void) 
{
	snarf_construct_hat("/usr/bin/gnome-thumbnail-font",
	        "722a01ee9880be07514512cc347a0261afce78208b66bd9d8ed6aa502768c9642009c8c787ffbce3659c37a4df6e6ef13ee6acfdfd49620ae77ba9e571ef2b2a",
	        1430
	);
}
static void snarf_hat_1432(void) 
{
	snarf_construct_hat("/usr/bin/baobab",
	        "a3ab7c1dcfbf140aa6b1bc031f12285cce8e708f49f2f3f6bac994c6ddfce5f29c6a7fcfb450af9502e7b685b9fa8ba81f45c23e0bf117a20aa3c854fbc5f38a",
	        1431
	);
}
static void snarf_hat_1433(void) 
{
	snarf_construct_hat("/usr/bin/firefox",
	        "30b4a8eb85ec555212bb7881217db6ec627eed4e5e7d0608e8207332e099c4505c0f668627b3e971ed3f886b95eaaf33ca3188bfc60591049ef324a621bbc981",
	        1432
	);
}
static void snarf_hat_1434(void) 
{
	snarf_construct_hat("/usr/bin/gcalccmd",
	        "6432ec8756caa3ec344949a1edad2ab158fd8179993166193fc5f31eeec5c8b6cfc904cb49017972f10e9883a45a45e51333c3aed54a952f0d4e1a6fd93a7c36",
	        1433
	);
}
static void snarf_hat_1435(void) 
{
	snarf_construct_hat("/usr/bin/gnome-calculator",
	        "00dbbf583ffb646d1971e294aa398ff16314ed4aec2ace22068119f031396edc4096e39e5e6287e396e411fc069df4112be2b0fee75e76859ab181cd40d37033",
	        1434
	);
}
static void snarf_hat_1436(void) 
{
	snarf_construct_hat("/usr/bin/gnome-connections",
	        "b2194f4486cb92c9454e76b3b88c6557566a822be158a9b827e5ebd1f4f79251cc9ee3f6bc3de94f316e135b0e8e885343c6ac5c472499419f7e5f280257e157",
	        1435
	);
}
static void snarf_hat_1437(void) 
{
	snarf_construct_hat("/usr/bin/gnome-disk-image-mounter",
	        "11239ddd4ea1fba9e1876ec2159138c1200a4cf75b4a43390d60013e28b328ac2062f0040a3c77aa8eab197887879819a8496e0fc1aa0a92ef8c6648eaa7a83e",
	        1436
	);
}
static void snarf_hat_1438(void) 
{
	snarf_construct_hat("/usr/bin/gnome-disks",
	        "ea45f35752f0c529679be8f596c1b917c1acf2c81ffbe7468a495ced745965c2bc667a853187ae81c5c717060f04d3fae8ae28d97f375c21392e2919a2897d34",
	        1437
	);
}
static void snarf_hat_1439(void) 
{
	snarf_construct_hat("/usr/bin/gnome-system-monitor",
	        "2ae2f816f85d8bc0a4144a086b518d97c1028f6b117228d20a50b5e44e6507941b6212b79113c40f5cc967afebc6d968da64398af3d92cc2f270d7035c745220",
	        1438
	);
}
static void snarf_hat_1440(void) 
{
	snarf_construct_hat("/usr/bin/simple-scan",
	        "99437bfcda35d108fc80beaeb3163b082fb9e42d2c71e99631d30a599329a9d276e19cc7b2fecf7fecb207a3e82de64f821fdbb414822b037e8a183310e3b2fd",
	        1439
	);
}
static void snarf_hat_1441(void) 
{
	snarf_construct_hat("/usr/bin/sushi",
	        "3cd0d33272487898eedd3de30752274f4167de6d79c97942abe8b3ad9a8b8f112b977455763ae601ee7171458b9cd439800c8ea07dc91757b13b18f778f59303",
	        1440
	);
}
static void snarf_hat_1442(void) 
{
	snarf_construct_hat("/usr/bin/podman",
	        "2bd2c291c298c614a8e2b102f0ae21ab5424da1548110668ddf4b1553145786e4e59e2a3902de0434c1ea9d7f8cec15c01acf11b871cde3aa819b1fb50fd7bb1",
	        1441
	);
}
static void snarf_hat_1443(void) 
{
	snarf_construct_hat("/usr/bin/firewall-cmd",
	        "718b33f8723d2c4fc772a11725e0f2dbeb8390199bc807a0e1577cb582e277b9db11b80c684fdb6d0a837ec86a3eca84de244bf9376f20007854e07519813d41",
	        1442
	);
}
static void snarf_hat_1444(void) 
{
	snarf_construct_hat("/usr/bin/firewall-offline-cmd",
	        "c42ae3eb31ed43ee398b9dd781427298662e9154c21e7875d49a82376a7541cb105ddf78d2b0aa63be2800713b6c82d459b9f98067a96fb641633d3bc52a8721",
	        1443
	);
}
static void snarf_hat_1445(void) 
{
	snarf_construct_hat("/usr/bin/hpcups-update-ppds",
	        "2da3f634f5f03bad4875ac00f436cf812e6419c4811af7a9c96d3d3d2118e8ce088639d2b53248806bbe9483b6ecf6cf24a548f050864712522a6bb01db6f485",
	        1444
	);
}
static void snarf_hat_1446(void) 
{
	snarf_construct_hat("/usr/bin/hpijs",
	        "3af0bbd79c2da7c2cfe7eea90296e70311907fb78ae6058db2b488fcef0ec08255dc45050919b1e0e443697a555d9b36480e6eab9c2a029ee6d1c89b046827af",
	        1445
	);
}
static void snarf_hat_1447(void) 
{
	snarf_construct_hat("/usr/bin/encguess",
	        "324cf1e4c8a7cbdc23fe5432b7e60191221ede2be2fe5333f243810b621211a4c2508e0e07b817bc9f2cc174d9234a9261dd9e823397eb4f2ca64ea5bfea6feb",
	        1446
	);
}
static void snarf_hat_1448(void) 
{
	snarf_construct_hat("/usr/bin/piconv",
	        "02d8ce84b07d5bf1acaf8ca4cbc15b2c907c494a186fa5c6e6ab523a381cb9f0d185acb1e9169dc704697e628f26959612b973f42b183e51d9cd4dd147eb84fe",
	        1447
	);
}
static void snarf_hat_1449(void) 
{
	snarf_construct_hat("/usr/bin/orca",
	        "ec8da455bb8a50f0370110994dacc955ad690fd92ad01930f6dccb4546da53a54e3947c3d1abbd349a38ce9104945427ff4ca1c7c25df51819a3284c8f4ef738",
	        1448
	);
}
static void snarf_hat_1450(void) 
{
	snarf_construct_hat("/usr/bin/fedora-third-party",
	        "254266d3aa4ee43232ce53dff6076559e0f28b8811e66b3fd14ddd99b56e1654979f922cde3ac9c39e8421883b94a07128cdfce1d5e212b26dce5d8c70a58b73",
	        1449
	);
}
static void snarf_hat_1451(void) 
{
	snarf_construct_hat("/usr/bin/airscan-discover",
	        "0f5ebd51284336f5f096def405483d603c676ad740d18cfeea5c97d35fba9adeafea442e66935a0407453c404446192b9dfaf025a07cd01d85933c577a2601ca",
	        1450
	);
}
static void snarf_hat_1452(void) 
{
	snarf_construct_hat("/usr/bin/aulast",
	        "d2f8896556bc3ed295f26486c5234b647219409412fc4d5ff314672adce02aa1aa658e542b6fe28786da71f7b200350a3d24df20d325594807b119849cb821b7",
	        1451
	);
}
static void snarf_hat_1453(void) 
{
	snarf_construct_hat("/usr/bin/aulastlog",
	        "941db0763c54bf6f070f2763b77aef9a624eae88c98999bb3592af3016edf3fe49bd426684443603b019ec531b65a4dc56279c5e9e421ed50a2dee06613d32e7",
	        1452
	);
}
static void snarf_hat_1454(void) 
{
	snarf_construct_hat("/usr/bin/ausyscall",
	        "a29f26555f7f9304a22214dbb1edd45822d17281e8b85ce123c41930cd470ab6123b903d58bdfe3d0315d6ef7f6870eee073cc6ea6123e487817043551e4be2f",
	        1453
	);
}
static void snarf_hat_1455(void) 
{
	snarf_construct_hat("/usr/bin/auvirt",
	        "36abd6f6260024fcb6ed321982b4cf21364ffb71ecb46f64ff6d73efcc6bef227090cde5100218cf0a68c653d995a1f3922f7033e79718eea2243eebcfecab61",
	        1454
	);
}
static void snarf_hat_1456(void) 
{
	snarf_construct_hat("/usr/bin/cifsdd",
	        "f4e5bdb080d620f87cc809a4af64db9a3036500183d5d0d0be6e8d743897cc0bc1340e630db57af276d25355c4d2a3caf028b828b0f4c315510aaf2730e97e76",
	        1455
	);
}
static void snarf_hat_1457(void) 
{
	snarf_construct_hat("/usr/bin/dbwrap_tool",
	        "61561858491c52dc8e206f6551d0e1e20574e3565e2387d15fa14911f1d8949f8007667c6e1c3be0f655fe3ce97a038183d942a1f70537db5d606ede234abf0d",
	        1456
	);
}
static void snarf_hat_1458(void) 
{
	snarf_construct_hat("/usr/bin/dumpmscat",
	        "05774f41ad32044c4cffee98787065d4975cdca5b9d4730cfd836917ffb3253abbf6120c211254b009d92c964e1714babb4a28a4573ca882af81bf4d2588d3fb",
	        1457
	);
}
static void snarf_hat_1459(void) 
{
	snarf_construct_hat("/usr/bin/mdsearch",
	        "0cf45cb3d275625d06dcdd8ba6dcbb18c9eaea0ab9d1cf3053acc000b458a4cb4a920b88fff5c56e51c790b3255e875a9c8e175e4b3220c4c733eddd6fc48436",
	        1458
	);
}
static void snarf_hat_1460(void) 
{
	snarf_construct_hat("/usr/bin/mvxattr",
	        "254ea5dbebaaddcf6f76d83e0193faff9afa11016037fe93d5efb9884a02e887578b9d23eeb29ac574c2dc7149bf765d6ea5b914cf18c1922128b34f34fdc90b",
	        1459
	);
}
static void snarf_hat_1461(void) 
{
	snarf_construct_hat("/usr/bin/nmblookup",
	        "4ce3d314af0ebe7761379f1e3000ee424071d72c73472619168ec97d4cb7830221eae5b6b057eb8e5c7e96e982c1a63b400d812f3f1d0d20c5d207586846efcc",
	        1460
	);
}
static void snarf_hat_1462(void) 
{
	snarf_construct_hat("/usr/bin/oLschema2ldif",
	        "d3f6f55845b411b4d6772626627b8d844bfee1b2692b5c06308fc7ea2cb226ca831ae8c08b5e3723d96cbb1689e4b9fc4826e9cb1a78c54106494c9688fa9c5f",
	        1461
	);
}
static void snarf_hat_1463(void) 
{
	snarf_construct_hat("/usr/bin/regdiff",
	        "a50a77ab38d443769797e5b2378b69069ed35aece9c62097b980d4312a9462f6259112c654f8416c72ef2a133b488c530d00eaf02474c5922d5bb7a2469b4c5a",
	        1462
	);
}
static void snarf_hat_1464(void) 
{
	snarf_construct_hat("/usr/bin/regpatch",
	        "9342d67ea12a1738308f3d603b5a68966b7fd60ca36d70c5b7a712233920e9febcd433e22d2e07eda8f9ef04546d4fabcc4a4fbfd2db9b7805fb14dce08ea43a",
	        1463
	);
}
static void snarf_hat_1465(void) 
{
	snarf_construct_hat("/usr/bin/regshell",
	        "d397416309b0d6be939d7c274bc85df4f0e2139f136637683bae4d1b37515fc3249df3188854ab566273e726c07c5d6aa5d2b8e07307733aff36972c7b2aa20d",
	        1464
	);
}
static void snarf_hat_1466(void) 
{
	snarf_construct_hat("/usr/bin/regtree",
	        "824c03cf75c9dc704de4bd4fe18b68ca7811338db9cdbd5c1200a6a8b064133e52bf8b1a377949afaa9a6ade54299c3d7690c86a2e5714800cd447e85d2b687f",
	        1465
	);
}
static void snarf_hat_1467(void) 
{
	snarf_construct_hat("/usr/bin/rpcclient",
	        "1894cc8631c43de00f71f728644491eecdb1489b4019807c4d7b5025f028afe0986bce2bc1daf941598cab9aa7cf675c7b21e173b83e3cc8542d8d7899a07b7e",
	        1466
	);
}
static void snarf_hat_1468(void) 
{
	snarf_construct_hat("/usr/bin/samba-regedit",
	        "044226370a6e958945205483fc7acb84dd5363d92aad4c2eb7aff92cbde84c8d8766ff380ad415663149814a1cb7b4842fa86b33dfaccfab4e183a7c0e4848ff",
	        1467
	);
}
static void snarf_hat_1469(void) 
{
	snarf_construct_hat("/usr/bin/sharesec",
	        "61ad9b2ae9c8fa99bda05d715d7364e74222aea8fe2d35087037c7ced9c7a2daef2f899b2706757aba2fef0f2ff85096180569ae4b576ec18194345ba53cb5c9",
	        1468
	);
}
static void snarf_hat_1470(void) 
{
	snarf_construct_hat("/usr/bin/smbcacls",
	        "e76e42dbf24287622e41efbfabe94697ca5bbdf2e41f2cc91650463c2a33642917474693c99be2ca63854421ac349ad888b3960ca00a737efd5971a5e484d473",
	        1469
	);
}
static void snarf_hat_1471(void) 
{
	snarf_construct_hat("/usr/bin/smbclient",
	        "a121e2fd03bf63585b25b36d3921ab2b5dbfc30aceaec36afd3ff97ea7822deb97c8bb4b194dfd367cba13d92c1b368ed29999ac59b4ec117f5bf14b6eaa26c6",
	        1470
	);
}
static void snarf_hat_1472(void) 
{
	snarf_construct_hat("/usr/bin/smbcquotas",
	        "a95e8c1094102c7ef89d55df71e4397938c4f532a2cd2699238abeced467aa859bd9ae4d361fbcd8c5f6a03c4e598d3d4db1a286523d1cd8e7ef5f6d75d69310",
	        1471
	);
}
static void snarf_hat_1473(void) 
{
	snarf_construct_hat("/usr/bin/smbget",
	        "8c78fb4df59d13c83f7c694b0ec728fd11de8a7787017ca754532f00489a33513d6a54558ed20b82893521295aafb400a242e1210149396999db0c6968f62e9b",
	        1472
	);
}
static void snarf_hat_1474(void) 
{
	snarf_construct_hat("/usr/bin/smbprint",
	        "2f85865639aef2edcf75a9af117e7972413cfe236ec9a3999a39d172401ec1f59ae1117e5e4628cdd8e0e61f5bfc97df00305a295afa928299672f6be00f2699",
	        1473
	);
}
static void snarf_hat_1475(void) 
{
	snarf_construct_hat("/usr/bin/smbspool",
	        "a5f1072da8b83cf15f63ade082748d9e9999df8391922a6556a4bf1fa880127d42c12e099f569135ee869da1032b8f3e1f1c9a92a9284c0dc6c3ebd0b7a4f269",
	        1474
	);
}
static void snarf_hat_1476(void) 
{
	snarf_construct_hat("/usr/bin/smbtar",
	        "e197a04aeb75607b11f3194436adb14ab9b48031d35ebbf8ca2ccfef943bd43f0c36150546c8a901da1f04ab7085880429a699529dd8167475c4f055df806650",
	        1475
	);
}
static void snarf_hat_1477(void) 
{
	snarf_construct_hat("/usr/bin/smbtree",
	        "079af00451a199c1672842edbdce23ed7598b9caba4ac07f582c04f182ee231bfeedf5e40ce54bedf6f5b81a07b9ba9e7025b07a75a414db28148656f1fc1532",
	        1476
	);
}
static void snarf_hat_1478(void) 
{
	snarf_construct_hat("/usr/bin/pipewire-pulse",
	        "81a0ced6d26081fa6e6713b855d064effcd8199be17e11fab2724e83826f6fb607189655cecfce26af639e6b5f766b8f8fadfd2aae1390503d3234b02ccd54c7",
	        1477
	);
}
static void snarf_hat_1479(void) 
{
	snarf_construct_hat("/usr/bin/pw-cat",
	        "b9f206714a98038c9e9b43c3120e34d57ef4295c17bd7c3956ae052e59146d66a9b0d8fe4bcb138ae0a643f277d6478ff37eb219954710e41ac3e123e4e47243",
	        1478
	);
}
static void snarf_hat_1480(void) 
{
	snarf_construct_hat("/usr/bin/pw-cli",
	        "7f3a5bfe7d6b2915d16f5f39e128777135561b8712ec87a9f114f155871f73790319628fac082842c144555a8b5407a29f51737cc68a854970c321d024134d29",
	        1479
	);
}
static void snarf_hat_1481(void) 
{
	snarf_construct_hat("/usr/bin/pw-dot",
	        "322c1ffbbcfe28c70d71c3493226825785a0381e8cdff72a0c8ddc62e7bcfb5465b6e027dde304bc943f1874fc223483891797cf6a7c7fa6421d8912940af1ec",
	        1480
	);
}
static void snarf_hat_1482(void) 
{
	snarf_construct_hat("/usr/bin/pw-dump",
	        "5d97f9978ac7b83e5bed176d922a5071f3609b5973d6e29fc93efd7293b48674d9d0378e3a95a4ad7039a36123ce0dc6c5e62d11fd10b57624b8c8e317e22387",
	        1481
	);
}
static void snarf_hat_1483(void) 
{
	snarf_construct_hat("/usr/bin/pw-link",
	        "c89083caa7e440ca051a2fcda67c2352b11bad52b7316a97c90c67498f6813ae1a2137815ea6fb0bf9e83cdfc49e4fae2e405baedba52190b8c7085285b1b1b7",
	        1482
	);
}
static void snarf_hat_1484(void) 
{
	snarf_construct_hat("/usr/bin/pw-loopback",
	        "28204bc6780f2e83b752642de5ef1bf4adc4d7437e13c25bce4527e40abeb53db419b300a97a7734d029a6db6b29255618998a5700b3ffa037bcbdd1147375f0",
	        1483
	);
}
static void snarf_hat_1485(void) 
{
	snarf_construct_hat("/usr/bin/pw-metadata",
	        "b4fa2d5638108185bd4aca4e2dbb74ee4fd166d6521367558a31866f392c2101da08e6de9c5719b0481a5664609127d0723d104ac1aaca270cf75472e9c34773",
	        1484
	);
}
static void snarf_hat_1486(void) 
{
	snarf_construct_hat("/usr/bin/pw-mididump",
	        "0f1d890b7819557d4c2aa3923264e4bada1d777ce0008eca4fca23232cec6f8ab7c6686ef1cf13d7ae225f41b654f9deff104c90ac4b443f1c2b9b46e21509b4",
	        1485
	);
}
static void snarf_hat_1487(void) 
{
	snarf_construct_hat("/usr/bin/pw-mon",
	        "383055dbdeec9b6ca452715b4f3e1428b3eee832888a332120376b30cc0d0bccccd9d0106a3e5b41ff8dd404c8eccc64806b7bd91e5a08b1274ae35e1eb0244e",
	        1486
	);
}
static void snarf_hat_1488(void) 
{
	snarf_construct_hat("/usr/bin/pw-profiler",
	        "f93b75875ab0dff05c5c22610f06b33221a633713cc40270b650e46b0684e6b439789d3d30a087af0a68516b86743ddc9f86f87f241c067160038fd18a729d5f",
	        1487
	);
}
static void snarf_hat_1489(void) 
{
	snarf_construct_hat("/usr/bin/pw-reserve",
	        "a818a934421f985f11598953b566748a9ec021f0452367370025905501e91a762a7517f8f45b8508e4979049ede2338960340b89adeff1e4b4083a8360468163",
	        1488
	);
}
static void snarf_hat_1490(void) 
{
	snarf_construct_hat("/usr/bin/pw-top",
	        "609eb7e7f97354f7dda17b496520748967ffa23e60b55ee071e588adda41d2389301b14d2e02ae1e8d00cd576eb29939de90b5a941bf6b2a1eee63759ef76ab6",
	        1489
	);
}
static void snarf_hat_1491(void) 
{
	snarf_construct_hat("/usr/bin/spa-acp-tool",
	        "4882503f73c5fb60ec0b1ddab98f229ee2416b548d211b5a90187a0042cb4abc5d097d537c0215557c3ba314686286506e94ab7bd08df3fe17941a7a3f022857",
	        1490
	);
}
static void snarf_hat_1492(void) 
{
	snarf_construct_hat("/usr/bin/spa-inspect",
	        "b556b56ed7ccc75099cb342cb172d1aafd68095ed4ef2ecd6ad14e34f5721a339da15f14c703503c698956b2d9706710e90fafc55ae4c833adb32ab576ff9973",
	        1491
	);
}
static void snarf_hat_1493(void) 
{
	snarf_construct_hat("/usr/bin/spa-json-dump",
	        "4f9913bb3ccdd69153300af423739e4f96a7709d35f9d41e4fde0bf435d55180c295d895ba7c05e9f3809b2947edab417b3cfd4c5b0c9fcb95b55728cf85ae43",
	        1492
	);
}
static void snarf_hat_1494(void) 
{
	snarf_construct_hat("/usr/bin/spa-monitor",
	        "7094c3a27adbb209167f6e5c34f523a94554bd9d7d7a82354866aaed8f2d8615c2ceadc5a302d8a8306c4d7b9fc4ca4ae44825a6135befe3d9832b19aadb8410",
	        1493
	);
}
static void snarf_hat_1495(void) 
{
	snarf_construct_hat("/usr/bin/spa-resample",
	        "e3c4a97d551bcace2dafe248cbb1ce5007dbe52eda2722d8ec503cfc4fa2bfb83b9e86e2d1b61a0e2b89b40eb60e1ee873cd94673658fa3765faf36dfcdfe73e",
	        1494
	);
}
static void snarf_hat_1496(void) 
{
	snarf_construct_hat("/usr/bin/qemu-ga",
	        "f4ea822341c662b62f50809869009243c2d8d1a4a1f9d1cefee01a0e653f42150bc6ea4f551077fda6111b94e9cfa598d6733152975ae4f65978641d80af4831",
	        1495
	);
}
static void snarf_hat_1497(void) 
{
	snarf_construct_hat("/usr/bin/dbus-launch",
	        "6872635812ad79a36939e428123d5db6b5e0a72667e17dd73ae4566a68d1fc34ca3e0afae644575f82f65754552298bec80d30894db99a9929ee53ec87d20d77",
	        1496
	);
}
static void snarf_hat_1498(void) 
{
	snarf_construct_hat("/usr/bin/grub2-fstest",
	        "c56317b52ba19d39ce6c417d08ff43f4da61e7076521e6495b1d3139395692ff2ca2489dbe7c9c5eb719e0e0920d61b77e2c41b9bba6b59d1b1e3f658947002d",
	        1497
	);
}
static void snarf_hat_1499(void) 
{
	snarf_construct_hat("/usr/bin/grub2-kbdcomp",
	        "9a6cb501f1fdf54360b43ae83204201d268da741f7fcc4ea81100039c2a0bd643eeaceec13e8d35411985b3b600054762b99837e7a15872d602db3f621561d7c",
	        1498
	);
}
static void snarf_hat_1500(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkfont",
	        "cb128b9b8e9895835f2e24a705ffc787b081ee8852ebb38b47755d7d1e3b9b05fe6d2295b839051d10635ab1fd1173ce99e2ef2a23cf206fd0788204050b8b33",
	        1499
	);
}
static void snarf_hat_1501(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mklayout",
	        "c03331437d72779a6dd8e7665dbe21bc3565e08e6b771822381db8dbeb2bae4f904d2f7abb0258c466dfb097922513e65fc9cfdb7bdaf5995657c3a06f0bba2b",
	        1500
	);
}
static void snarf_hat_1502(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mknetdir",
	        "02f26dce940558dee8fed3de4ce84cf7b9b6e7ac8a2339f567406f1b60955ce4f0e748f48a37d8e34f2d9d7c940d43abedd7e8a849bd6c09103ab6afb7fa2ddc",
	        1501
	);
}
static void snarf_hat_1503(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkrescue",
	        "ef27350bc57c38822b4ef7df856735a0bfa512ab11a9e01f1165ee19598d52f02e14941a8d994feac184ed709c03b9714ae1174bbeb1321905c79183af80eb33",
	        1502
	);
}
static void snarf_hat_1504(void) 
{
	snarf_construct_hat("/usr/bin/grub2-mkstandalone",
	        "cac4846fa8e9e2aa5d74cffbe255d9106ac96f244f5ec9175bb673f22d0be8ee9d77858bf400085b33b13b5878893949fd70ee797b86b407aa6d68f05e430afe",
	        1503
	);
}
static void snarf_hat_1505(void) 
{
	snarf_construct_hat("/usr/bin/grub2-syslinux2cfg",
	        "80293f046f082ab3ee13b69779b7746291db569166f9bc5204c907885fb176c6c79b000c12f5f5216edcb7f75a22d5b87171a3f91c576c5a6986e258bb1a3c4f",
	        1504
	);
}
static void snarf_hat_1506(void) 
{
	snarf_construct_hat("/usr/bin/grub2-glue-efi",
	        "e237a1a116cb67046762abb77ac059bad058a8a0a50635ed9c0eb030b128e2e19411987e309337570a242363cd426b9e8de4145f894323be76d02db87c104ebe",
	        1505
	);
}
static void snarf_hat_1507(void) 
{
	snarf_construct_hat("/usr/bin/grub2-render-label",
	        "d599008375eabb7feb669798f504dfc98055aee3de40ad3373317f226204231964a9bb0afa122ffd943504420361d744634076fecc449111ce6ed9857d9572b4",
	        1506
	);
}
static void snarf_hat_1508(void) 
{
	snarf_construct_hat("/usr/bin/locate",
	        "fef8039491a4e26eebfe4bbc1a7b01f82e7a7152112a4b2109a33724e7619ffca470c56b543fae911f4e2e0b97500602e244806a71f484940ffcf4af5d4ae121",
	        1507
	);
}
static void snarf_hat_1509(void) 
{
	snarf_construct_hat("/usr/bin/updatedb",
	        "ccee17ec1984ee87615627b3eb79cb2d0a577737f54013d4acf6b6f4d12d584e31d45a5262d893715d8f927936da1d59081e2a25d463e30d5850e2f222d38db1",
	        1508
	);
}
static void snarf_hat_1510(void) 
{
	snarf_construct_hat("/usr/bin/vi",
	        "5b52441eb3e8e4d5902cee4e6563cae0b8d0b141d5a24a2ae343e88cf31620052570ce42b35c8e69f9a0db325e914b3f7727b55c64557383e79e352cd38985f4",
	        1509
	);
}
static void snarf_hat_1511(void) 
{
	snarf_construct_hat("/usr/bin/view",
	        "7f503c14c216790da0a683e4b37d8a2c6fad15f20486406a659a66035b73a3135f2c9ea29d169b7ceeb95cd6411948f2ce7868508e39aacb5626d346c884ede2",
	        1510
	);
}
static void snarf_hat_1512(void) 
{
	snarf_construct_hat("/usr/bin/dwz",
	        "f5b77a49326a66f9c0bb81fc417c3a55190a41cffa26d1716bf4e4dc5c0c20dce18211d600b12ddc065e9df70726bc2f88568f851881405e864455bf1355f7d2",
	        1511
	);
}
static void snarf_hat_1513(void) 
{
	snarf_construct_hat("/usr/bin/debugedit",
	        "c72ce62a73c5fb5859278285b73b113b0ae897303363ae2c24dda6c9d18df29f64214293724b14a7eb8663ca903d2fbc96f977fe73e992fb62cdbeb91e7cad6d",
	        1512
	);
}
static void snarf_hat_1514(void) 
{
	snarf_construct_hat("/usr/bin/find-debuginfo",
	        "5590c28b3c1cbb63fdccd1b3a7ae1ec01ab2ec834e23c0f8b994ee9851c062f1707ede3f780d5fcdc533ea8bf4e3d7671eb7160dcfd8009c707f1019c6fd4a0f",
	        1513
	);
}
static void snarf_hat_1515(void) 
{
	snarf_construct_hat("/usr/bin/sepdebugcrcfix",
	        "67910fb937f7dea9a3ce74283d3c756c5ecc5bf9e56663a5612cda256bc64a8aeada71550a89a0dd34ef0d61ef4b3b34fe9aa1de6cb444250357f658537f3f51",
	        1514
	);
}
static void snarf_hat_1516(void) 
{
	snarf_construct_hat("/usr/bin/pzstd",
	        "6a87cddb5b4a75f38ef1049d5c7836dc9b19ede7faa66591dce1d33d726ce0a9f6dcc2455627a106530dd7e576edeecdf344c0ce4e27eb27c18013611df7414e",
	        1515
	);
}
static void snarf_hat_1517(void) 
{
	snarf_construct_hat("/usr/bin/zstd",
	        "3a6c87149b14ee988d93008171fd711ed40e1a3f9cb7ac88c27b3b458c58cfea72d147549a123d2a48987b7fb545f84f0cd47b66c4d84f31bf9196701dbc39fc",
	        1516
	);
}
static void snarf_hat_1518(void) 
{
	snarf_construct_hat("/usr/bin/zstdgrep",
	        "3a4c0247a405708d5e6d2af2d91e8002fb653aac49cba1ad20dbbeb5a9495f33146cd0774c36ac81f0bc7e65172dd6e82e12e88ea7f65a7822cab790a44b9139",
	        1517
	);
}
static void snarf_hat_1519(void) 
{
	snarf_construct_hat("/usr/bin/zstdless",
	        "72eb772559d097b92cc700a20e75eaf854ad594f8eef07c8abbff5afa3c8dd03658070e8cc3f5287ca4e342d3af7a5421e7d32e940e40a6ec1b78eb95742db0e",
	        1518
	);
}
static void snarf_hat_1520(void) 
{
	snarf_construct_hat("/usr/bin/pyroute2-cli",
	        "33d9562d651cd2d6558372cf8d035fdaaf0776e01960d8007894b1fa47d55d4493e467acf87ba6a8539f94a54a5e2e58053a8a40750495262d47c378c2f98685",
	        1519
	);
}
static void snarf_hat_1521(void) 
{
	snarf_construct_hat("/usr/bin/ss2",
	        "da02846179f1a9a45802e94748eb645b91a8311797fed1d5086d606e4e99b5b6296d28d21ed856cacdbcbd0a6231d412e3b34da4a1992573e19b5ce8bf7d9ce1",
	        1520
	);
}
static void snarf_hat_1522(void) 
{
	snarf_construct_hat("/usr/bin/koji",
	        "df00ff106386b3bf14a0197d2245763d8c8e4ed5be854d072198fa70ec2e088a732cc35f743b558725ec1f2ab23dec08aa0c4713268650840dd00dffee02e074",
	        1521
	);
}
static void snarf_hat_1523(void) 
{
	snarf_construct_hat("/usr/bin/chardetect",
	        "a779a825c963cccc0e9d9e417f06b00001e33d373652286250d504a9d95c9e7ca8663e9fdfde9afc10b767917317a710ea4c77d17439045e8537e7be013ae434",
	        1522
	);
}
static void snarf_hat_1524(void) 
{
	snarf_construct_hat("/usr/bin/bodhi",
	        "5da8e32501c277fe679caa37092b362637d949cfca60b6ff46f0009e3b4238cebb8802ef973fc9ba63539ee8c9f1bf21ed33a172c093f53cfb132f8b0a6c7eb0",
	        1523
	);
}
static void snarf_hat_1525(void) 
{
	snarf_construct_hat("/usr/bin/certutil",
	        "4c8a072afaca8c2f873087a9c057fbdf214c49afad2131a7992b92aa33af5808084663e26dac43aee13ae2cadb3f49da70287c72c797315c871cb092e8b70073",
	        1524
	);
}
static void snarf_hat_1526(void) 
{
	snarf_construct_hat("/usr/bin/cmsutil",
	        "7b023efac5b66567931b1b983cd5314f3b8fce2741a4b8eb263031e6d87d8390abdfae3b3d4da3565d8df8bd05b77416ef1d4d1f6770a8815c992d23f4754853",
	        1525
	);
}
static void snarf_hat_1527(void) 
{
	snarf_construct_hat("/usr/bin/crlutil",
	        "0e446fb4de1741cc4a3144cde7cdf7f2cd47467262226a86afac0fed9001a3f30c5ddde51b697b27e05eb343e4b1acb06da8f8fb47a0753fde346a1a30f9a777",
	        1526
	);
}
static void snarf_hat_1528(void) 
{
	snarf_construct_hat("/usr/bin/modutil",
	        "41601b483fb1fe2431439393a56b6203f5b32a8d7cf061d0a3d69c1be7dbdba0b62eaaf2b19c36466df52b331c0e6a03541e825edb26ca964ab2177fe90658d4",
	        1527
	);
}
static void snarf_hat_1529(void) 
{
	snarf_construct_hat("/usr/bin/nss-policy-check",
	        "097a9d725e8ba9bf2d8cb60acf4af77e6156bffaba821eb311434696f2d2a9d9ad88386fa2deaf675b3827ebfd8334ae0ca4e38b55c87c6ce93e4bf190e01095",
	        1528
	);
}
static void snarf_hat_1530(void) 
{
	snarf_construct_hat("/usr/bin/pk12util",
	        "0483bc03cf8e8954e29aa6061aec338845090cd82fd9ad26784c74942774e0371642993cc60fedb8e22b3bf580de6b777ccd83ec5e3580cec75fd7d8c0d72021",
	        1529
	);
}
static void snarf_hat_1531(void) 
{
	snarf_construct_hat("/usr/bin/signver",
	        "3f9c4203009871de1428f38a4d7688eb022e6e19bcbfd4a0f671ba3d08ac53e5d4bbc8c571ab09b55de0270462a9794e36d3965e02be9f1fb1433b74c036452c",
	        1530
	);
}
static void snarf_hat_1532(void) 
{
	snarf_construct_hat("/usr/bin/ssltap",
	        "1de7fcfbb924f6c7f7d38131d21f0721972ea1d8c7f5ff580b14e3d7867c9f6e47e25bac23430c4e5bb2d6559ef430883b810246dd28f9a6c4133376cfd2aa80",
	        1531
	);
}
static void snarf_hat_1533(void) 
{
	snarf_construct_hat("/usr/bin/modhex",
	        "3d12b2b128cd91d8efb6bd551f121b0fbb7f252e84fb0084d1d629db3f1a0fd7a47bb27960257715d5f410b0ad0250765d389c8a62d9e9fb7f6ef6487a4ae033",
	        1532
	);
}
static void snarf_hat_1534(void) 
{
	snarf_construct_hat("/usr/bin/ykgenerate",
	        "4a34af8c99cecfd825740eca9fd2c53fd1af1c2ccf2710f3f3822e8c2a83ab85879005727fb70a4dbfc5c8cad3679fb1f54991bdc08d84b108a104a747b4de9c",
	        1533
	);
}
static void snarf_hat_1535(void) 
{
	snarf_construct_hat("/usr/bin/ykparse",
	        "e753f7e5d8b3d78b820defe049cc408995d35c315b803c190f43eab0f5f8ae4be7079669522b16b598922f4e5afb422f17ddbacb5f9602bcd03a934bfaa7feb0",
	        1534
	);
}
static void snarf_hat_1536(void) 
{
	snarf_construct_hat("/usr/bin/ykchalresp",
	        "35ab266ffaaa8fb5870aac040d90d953a95a645bfdb0fa8ae7dd240318099d0c6f58f41f7197acbdba43283c59ce4d8bff2a86d24a1b6eb13ce0fff079bcdaaa",
	        1535
	);
}
static void snarf_hat_1537(void) 
{
	snarf_construct_hat("/usr/bin/ykinfo",
	        "d8581440edf31d66f2914113d6a1fada14284d24bf5b6566b1b4b283d852f95afab7362e5bef565043e4b493ba6270350ac2ff99400a10013be1702b2f0dba37",
	        1536
	);
}
static void snarf_hat_1538(void) 
{
	snarf_construct_hat("/usr/bin/ykpersonalize",
	        "5484ad34fabfc6cca93add29c44ee827f768a9daaa90fae0b06d2a200dac9e2a3e0758b70d4474c189b5525985627fd66144d8b407b524814c8ab173555945d9",
	        1537
	);
}
static void snarf_hat_1539(void) 
{
	snarf_construct_hat("/usr/bin/k5srvutil",
	        "0e99c2c11a9b77e0f01f410dbebfd559b8226e6e7f60fef80aa855d1257b20bb827ce2e9978c1213fb322463b032ec4398d28979426d9ccce9ba731c49544d7c",
	        1538
	);
}
static void snarf_hat_1540(void) 
{
	snarf_construct_hat("/usr/bin/kadmin",
	        "9513b7baf1d3d8d4856193430100952517e031b19145ae254328761d9e8076ec929f919b47c7a907aceecd5f7c29c6716ddff179878705d352899a9840c77eba",
	        1539
	);
}
static void snarf_hat_1541(void) 
{
	snarf_construct_hat("/usr/bin/kdestroy",
	        "4598d8952bde4d3b78f993df000c34bb18e82e5ad6efb50eb4b4eaf8534e809ee95117f7181ed03176e608f00d37792c0ee4ca2875398f4967dad55d90f93b10",
	        1540
	);
}
static void snarf_hat_1542(void) 
{
	snarf_construct_hat("/usr/bin/kinit",
	        "1d906c3afd6b307bfb07aff4ee59f6dbbfbfd7249ea64d8fe38adda1a4ff7aa4212a1f625b1168f21b67e22fb0c6c6e18dcec62519b0b9c728e5544971a45a53",
	        1541
	);
}
static void snarf_hat_1543(void) 
{
	snarf_construct_hat("/usr/bin/klist",
	        "eabb16b4983ef4152d87fbd3d92e62a6e71936b3ea6ba7917b10b26d559e4f15faf2feeeada3a4ff2a71a58465e59b3f97472934400700dba925f75d258e9462",
	        1542
	);
}
static void snarf_hat_1544(void) 
{
	snarf_construct_hat("/usr/bin/kpasswd",
	        "d25c18bf5ba882d4ef086c5efb073ba15c0d6b9e40e8a362a6718cccb375333122c85cdb32d7480775e83f391438ab90453a7613770bedd6d8de9164f3cc7855",
	        1543
	);
}
static void snarf_hat_1545(void) 
{
	snarf_construct_hat("/usr/bin/ksu",
	        "502f493f49850d444bfdb8dcf94ca0c7d71ea1a975b569e5228d5daa41c766317fcf55e479d7b55d1b97d824ac2faaf7a811eef89fd757c7ea842d72e1fab72c",
	        1544
	);
}
static void snarf_hat_1546(void) 
{
	snarf_construct_hat("/usr/bin/kswitch",
	        "c9b322042c86d5e6ce001a74e3645092020363584e766a1aa50e2ff159dfcc91b379fccfa86c75b56e25d2af02aeea81b8a9d71c58604de33b87ca7c9e20dc1b",
	        1545
	);
}
static void snarf_hat_1547(void) 
{
	snarf_construct_hat("/usr/bin/ktutil",
	        "43eec1ad74697f014e05a8cc5c39cbb8fc6f4ddbcd03e550c50200e39cc65012962b7b0c198b0f9959d438cd2389aee1a57f1fa25e45b6b7daa27ca6da2283c5",
	        1546
	);
}
static void snarf_hat_1548(void) 
{
	snarf_construct_hat("/usr/bin/kvno",
	        "cc84647e01133a3b19fb23eeccb49bcc39f8cf950865b5982e1aa7421b3a9972a30e8c4acd075f74e79a9d7ec950623363e2bb8e84cd34c8998e4147553347fb",
	        1547
	);
}
static void snarf_hat_1549(void) 
{
	snarf_construct_hat("/usr/bin/fkinit",
	        "d9400a1f594ec3297a976edae52ca0acf58b626a3af846310988c8969458a709cc01d4235417018640ef9274f045d522d62f2920d884a9cfe95ee011671d2f2e",
	        1548
	);
}
static void snarf_hat_1550(void) 
{
	snarf_construct_hat("/usr/bin/faked-sysv",
	        "50e3ad54aa0d53bf4c356e3c7396881cfd3a7a23e8e018f5452ee59ee7f14959e0790c5e85421ff273d7ba7205460658434cd922d4b6366c8cc7d7b298e9a916",
	        1549
	);
}
static void snarf_hat_1551(void) 
{
	snarf_construct_hat("/usr/bin/faked-tcp",
	        "3fcde477a1cf993ad9864946b41d1d1a85ca30249046751da045ba900fdb6c63881c85cce372f7c64142970832f38c7a33f19aa14bda56b2150aefbc6056e9d5",
	        1550
	);
}
static void snarf_hat_1552(void) 
{
	snarf_construct_hat("/usr/bin/fakeroot-sysv",
	        "a75c11f0f6802314de70f913edec22958b93f87325d1164836be7f2026e2f95861dc50181210a01524daf20af50154b41cca58aed020a596e7ba9afbe4ba1b60",
	        1551
	);
}
static void snarf_hat_1553(void) 
{
	snarf_construct_hat("/usr/bin/fakeroot-tcp",
	        "3a80659850a333dc960da433874627c4b9ae0d44ee5824b57ec3d367e6a4afc29a74acdc19f4e277fa53e61a5b51d7095fe1e4b7c9d286f3839c5a1c8e76a798",
	        1552
	);
}
static void snarf_hat_1554(void) 
{
	snarf_construct_hat("/usr/bin/mock-parse-buildlog",
	        "a484a5f3dae8449562d5022163a35bb43259b5e0f8d10d7f98757d39e0ae3f56179a477a4ade24b43fc75dd9415b304f7699b1dad9cf670ce68ac8a549613e8b",
	        1553
	);
}
static void snarf_hat_1555(void) 
{
	snarf_construct_hat("/usr/bin/mockchain",
	        "1f7acdd6941bb2168d01e85e2bf48984bcbf85a19651ad48287905b166ef565e1631b06b96f456855e61f1bc29da98c3ec3dab6b971aec2783e453a21c351ab3",
	        1554
	);
}
static void snarf_hat_1556(void) 
{
	snarf_construct_hat("/usr/bin/checkbashisms",
	        "e9c3fd8579e60bfb9f13923abc4ef2c0a04baeeaa139834e3c5575fb1f28e61d254608514001fdfd65fc0c49137af7400c0759c7f28c027fef46e58eecc58e8f",
	        1555
	);
}
static void snarf_hat_1557(void) 
{
	snarf_construct_hat("/usr/bin/dash",
	        "86de98d771114f194a10d84492fdc3e2e859a6f798768cdfca36ff91c9d2451270b9e75cb29bb353278407260e302664486e3c9740474faf0cc5904d876a764e",
	        1556
	);
}
static void snarf_hat_1558(void) 
{
	snarf_construct_hat("/usr/bin/gendiff",
	        "720e278e962449461b32e8132853ca6d50f7893033e1f6a2a9a19a45b3acab97ac541864652806047f07e591d2668dddc9f7fb4b329c063bf55be6ef89dfb26d",
	        1557
	);
}
static void snarf_hat_1559(void) 
{
	snarf_construct_hat("/usr/bin/rpmbuild",
	        "d8f5ab6966e4806c23e9603a9fb834edf28e32d0d5d14271ec2ba8e5e79e7bc38e901d35021f8aef6fe9322c809727bf9f3d515e9a9f57f3a796b6181a04c732",
	        1558
	);
}
static void snarf_hat_1560(void) 
{
	snarf_construct_hat("/usr/bin/rpmspec",
	        "748b5bb4ba428d93fe74664502322f00c25f97929db88af4949a8d740391e7ccc8bcd8d9d38329080f325d1bb5fde8963b1b0f3bd544a0819dcee4bb975fceff",
	        1559
	);
}
static void snarf_hat_1561(void) 
{
	snarf_construct_hat("/usr/bin/rpmdiff",
	        "bbd9f920e9b690ff8e663f88120dcd4043d2105dea6688afc3523c48e89a9dc7ab1b20d5bae52bc4a179a017041e484d90ea8446d94c9ea380190d7691dbf7aa",
	        1560
	);
}
static void snarf_hat_1562(void) 
{
	snarf_construct_hat("/usr/bin/rpmlint",
	        "3d6878ceea4609b5ecce1f0ac8b593d3a29bcf5c6a567205eee47b258e8f85bdc5003527b59bd6ae013891a8fbbe74553aee78ed8319bb873176500ff86d2f97",
	        1561
	);
}
static void snarf_hat_1563(void) 
{
	snarf_construct_hat("/usr/bin/rpmargs",
	        "2157af50871d6101b1a743b65672a9fa21969c2a06b67d14dea94079b69a13d4ed3698ea7f8d487b7529dffab07e6d47bbc7c4351cae9447c58a66cfc70af3e1",
	        1562
	);
}
static void snarf_hat_1564(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-bumpspec",
	        "fd0ba0abf4d6dd945da2c5f90e9ce6d9297313523b62a104b365754c79533308e99fbbfedd14ea1d140b684d0febef998f82b2a40f5e2cbe68d7b0608b0998ca",
	        1563
	);
}
static void snarf_hat_1565(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-checksig",
	        "4c6a25ab1a71fb799637ba05ee88253739b55d1fb107fba086a7a6a1c762cbbb0e4bb954329bff49cff6ec431d782a4726b2c1e6e6885d95c63bca993ea19069",
	        1564
	);
}
static void snarf_hat_1566(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-cksum",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1565
	);
}
static void snarf_hat_1567(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-diff",
	        "22ae111e92ddaefe38d516d88739c7d20a056b0f8c8bfa8ea728f81c498586538e84215ec18605bf0678dc69716ad71735f442105b3e74c4aa2cb2c5e673a05e",
	        1566
	);
}
static void snarf_hat_1568(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-extract",
	        "7e89557c864d98fde09834716fad86e1e57f0cf953b6c7375d78ee2a06117c2d82538049271c81765d72d612464eaf28edd6979240a358146f343d7e9dcd1866",
	        1567
	);
}
static void snarf_hat_1569(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-md5",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1568
	);
}
static void snarf_hat_1570(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-newinit",
	        "99c2e015fe6758fc818281ea134f56a9ef71b1fddc56b64b56f4a84cdc3ab71ff6e1180b431accf8d4a3f729863e90a43908f49c3560eae7fe9f08332db08cec",
	        1569
	);
}
static void snarf_hat_1571(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-newspec",
	        "e3e7248160dde5917025d8c49415c46aa7a38c449da3efde54ab4d4d6e53a31a7ccee2404cee80e546766fb5a21fb2523887446e788b2c2f45bab2952f7fc81f",
	        1570
	);
}
static void snarf_hat_1572(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-packager",
	        "ba7ea58e4e24a03d15e9e8767f12e3846ae3b7a970366bf2f133084a01f8cad4b7258676e857f6de162a06694dbce88b79ac23177ddea0735f1ef629b5ccc778",
	        1571
	);
}
static void snarf_hat_1573(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-rmdevelrpms",
	        "75c92202b290073764a9b72ff3efe147de2ca3750b52cc851b925781f7aab47ec960ef9a08b7e5243ef512109e20ec4d8886b6a6d207a65ae250f6bb191b82fa",
	        1572
	);
}
static void snarf_hat_1574(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-setuptree",
	        "5a66fc8f86cf63ac951da1e716fb05bad578ef7aa71025cf82c48add78efa0e9bda67519ef54837c02973268463fa95e4d166992d021b6d80aacdcc1b8439a1f",
	        1573
	);
}
static void snarf_hat_1575(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sha1",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1574
	);
}
static void snarf_hat_1576(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sha224",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1575
	);
}
static void snarf_hat_1577(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sha256",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1576
	);
}
static void snarf_hat_1578(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sha384",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1577
	);
}
static void snarf_hat_1579(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sha512",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1578
	);
}
static void snarf_hat_1580(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sort",
	        "54f057922a7a5eb1fef6ba2cba28b751ee2a4cc283be4648cd871c234de825dc0aef4387fdb86ab72387ec691f662e003fe2207e7a39326f966bc3be6038ff02",
	        1579
	);
}
static void snarf_hat_1581(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-spectool",
	        "00de01c4696b19f17d2c31984ad4996c1fdc5062d0c43562a67b35ecaa7ffcbd85923daeaca088ceb1983fdddcc8ff1a6555724abf73d3c9ab7e22e352ed8b4f",
	        1580
	);
}
static void snarf_hat_1582(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-sum",
	        "a9176e16acf4b64cf167cbe53ba19aea251555de2dccded5ac64a65a614d06a0651730c216eee63b7af3a3f789ad431e916a8a03d06c9c068c68407f21c309ea",
	        1581
	);
}
static void snarf_hat_1583(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-vercmp",
	        "582c7c421c1774aec9c24ea9787501a0efff51d77caaa6f277133a7ca192d7458fdee4b4a3353b0f19dc050cec691f785daf8315299bd6c136ac75f8517c93e8",
	        1582
	);
}
static void snarf_hat_1584(void) 
{
	snarf_construct_hat("/usr/bin/rpmdev-wipetree",
	        "6435fc3727d57fa8fa110f9627c893a5f84314dc78266b9e1c0e32fa8818fc625372eae2668ab7e613a695bfad6f631309efe87d011d33c3be3768674c8acb36",
	        1583
	);
}
static void snarf_hat_1585(void) 
{
	snarf_construct_hat("/usr/bin/rpmelfsym",
	        "26ce522423ea300755618a952272644ad94064a68504f0407677c81a75d4668aae58ca4fe91355830aa1c15bfab1ceb2948e10acb2c5fb2e0224670d55f79f13",
	        1584
	);
}
static void snarf_hat_1586(void) 
{
	snarf_construct_hat("/usr/bin/rpmfile",
	        "27f084ab8ecf1493b6ddc4c1febc1c340f252ba23baca8f547b7edf942147d0f44c60f1dd327679fb0b6128a6aa2065188790781bcd046e717bb042a2daa2ef6",
	        1585
	);
}
static void snarf_hat_1587(void) 
{
	snarf_construct_hat("/usr/bin/rpminfo",
	        "8760e11ad816a723f5252e92dbfdf7298ab89d5f6514900edd1dd2d4c127b99289d00743df7ea6b03424a16378f7720d679dc926752beb7cc307faf4e7da452f",
	        1586
	);
}
static void snarf_hat_1588(void) 
{
	snarf_construct_hat("/usr/bin/rpmls",
	        "213ce73f225e5b9ab2b23dbf4ce87a03b25706c57698cf5b1a55ee750fcd0eba96a4d020227ca0ca858866ef512acf4be93c944d54c7877cbf427bf97bb30615",
	        1587
	);
}
static void snarf_hat_1589(void) 
{
	snarf_construct_hat("/usr/bin/rpmpeek",
	        "cbc82c109b7735217738d51f835a7382cf3460bf464059b1a12a1b85a47b0d6bbeb82e110af0d6388680b05c44c1f124d75a3c9ab1beca64fd7b625e670565a3",
	        1588
	);
}
static void snarf_hat_1590(void) 
{
	snarf_construct_hat("/usr/bin/rpmsodiff",
	        "1faefc788d366fa384b4ce31f8bfa6761e88cf5971918dbd5278ae88426709146bcedf9befbb598e54ad45cf03a26b0d3b6561cc2545080d39af3c5553be02cf",
	        1589
	);
}
static void snarf_hat_1591(void) 
{
	snarf_construct_hat("/usr/bin/rpmsoname",
	        "f998032702a06adffe344808a9ba1e778c7a98caeb9b0074d2753aad7b60f2a04b34b23d57173d0e9e90821a0c2ec560a4b452993b3313afadfd69567108850f",
	        1590
	);
}
static void snarf_hat_1592(void) 
{
	snarf_construct_hat("/usr/bin/fedora-getsvn",
	        "e996af22b959dcc7b40d94fd2d54de5d6b9f44ca9871bd4666daffe161d901e475dfadeb7d7505e83c856ce1d37668d1bb77f32d58dad2a05cad1b383f6bccea",
	        1591
	);
}
static void snarf_hat_1593(void) 
{
	snarf_construct_hat("/usr/bin/pkgname",
	        "e5ccfcab64a63f751df7e5d6d8d69866996b866a1b59f0068d3fb0a84c9f539ea89cd00d559722ffdd6eecb89ad8998b8e7379ae804abaa5b8fc2992c7350613",
	        1592
	);
}
static void snarf_hat_1594(void) 
{
	snarf_construct_hat("/usr/bin/rpmbuild-md5",
	        "84051c9fbb5a77e6cc9bbab74c1a0352b21af7defd0bdf62d70bb86bf3688cad2b574c965e8a3aa93be344b350bc1ba42102c5acd4a00ad1d4bdaabc44f00922",
	        1593
	);
}
static void snarf_hat_1595(void) 
{
	snarf_construct_hat("/usr/bin/s390-koji",
	        "b8a10ea35e61f4e49c14c53db74e10e023b33c1b5825a68c83b7baa7a2f8bb0b2af41e270952a7cadf2172db5b102c0cd7f5d6e6c5c118fe961fb76aa1a1965f",
	        1594
	);
}
static void snarf_hat_1596(void) 
{
	snarf_construct_hat("/usr/bin/stg-koji",
	        "b8a10ea35e61f4e49c14c53db74e10e023b33c1b5825a68c83b7baa7a2f8bb0b2af41e270952a7cadf2172db5b102c0cd7f5d6e6c5c118fe961fb76aa1a1965f",
	        1595
	);
}
static void snarf_hat_1597(void) 
{
	snarf_construct_hat("/usr/bin/fedpkg",
	        "122b2f6515fd6646d8a19347edcf4c8cca496d0199307cc1a1d341c3935def45b691ba3a3d83f79b6e6160bf6d127a28b139f75006b6406a6f745fcf669a8b7d",
	        1596
	);
}
static void snarf_hat_1598(void) 
{
	snarf_construct_hat("/usr/bin/ncurses6-config",
	        "5acddec5879f68aaf88effd14af48edaa9cdf8fd55d2aec5a053644d34c4e7f8e2f4d3890c538d469e9c9263ff3eb13e9aa6b3d67f28152a46acd9ef5609ca22",
	        1597
	);
}
static void snarf_hat_1599(void) 
{
	snarf_construct_hat("/usr/bin/ncursesw6-config",
	        "0d2e3d2d659589eb32f123ec680dc8d9362946b2f15c7e187e5e4a5350720b7f1bae89c40cbd49d0cc027e9a7c775ac9927401c1240169720a902042c205c8eb",
	        1598
	);
}
static void snarf_hat_1600(void) 
{
	snarf_construct_hat("/usr/bin/authvar",
	        "b4f7d86a67e35fda31e07686d2f712425de1d6fe5a09b887099ea0a87620daef8b61d4e652a98346575c8bbcb17d638d165eb8ca78118ae98892179a88388ca3",
	        1599
	);
}
static void snarf_hat_1601(void) 
{
	snarf_construct_hat("/usr/bin/efikeygen",
	        "f7c2bb96da37a8a06387043a981cfcc4944abea345b7ab974f411831c92a1dc2467cdaad6f25180e76239614e6e5d0cd14df4bf1588f5c9d882a2d2283d11c30",
	        1600
	);
}
static void snarf_hat_1602(void) 
{
	snarf_construct_hat("/usr/bin/efisiglist",
	        "c98dfd81dbc5d4f5d6963de8bea72d9991f427bb8377f2d56d3186830ce1048b82a1afedbaac5cd94e684c767e83f2562b84cb58ee0194c8763f78e0a33931ed",
	        1601
	);
}
static void snarf_hat_1603(void) 
{
	snarf_construct_hat("/usr/bin/pesigcheck",
	        "a17c1ac3efc0af751d7ca13f00372062ea7b120aef0c0aa1ace2c356a5f3ae2124dc0bf94418973d57b6c910cb80a8cc5cc5ae6c6049733102a626f4437d2ba1",
	        1602
	);
}
static void snarf_hat_1604(void) 
{
	snarf_construct_hat("/usr/bin/pesign",
	        "2c1c92b16b4608e7ca54ec6bf7b78ec5c06308cb31f3724e49fbec6c7ffd20e3e3cdc169f173597bff30e83a10a7053dd05268754ac7cb590aa214eb79d73b95",
	        1603
	);
}
static void snarf_hat_1605(void) 
{
	snarf_construct_hat("/usr/bin/pesign-client",
	        "57f1e4bef1d99337046b0ca0c78b3cb51730ab4d59d94ed0ecae3468989bf127af56eafb3bb033624fd6023c284478c09154d1b6d413e0c3191f14d63c6c7474",
	        1604
	);
}
static void snarf_hat_1606(void) 
{
	snarf_construct_hat("/usr/bin/callgrind_annotate",
	        "ac1f997e35f62180507c2d9840e7ec02a91a65d1f28746958fe598ccc3e9d6c17a02c323120e29fbd5166f653504066d85c4523b991c0daea15ce8153f3b5628",
	        1605
	);
}
static void snarf_hat_1607(void) 
{
	snarf_construct_hat("/usr/bin/callgrind_control",
	        "1cfcf40eaffc61fb9e47b40e2e7a1f59f34aac043ee00e8d7f32bce6c0c22345776500f527b85f752abe37b32d62b6833ee1a255c1e30e9d688e609dfbbfa96e",
	        1606
	);
}
static void snarf_hat_1608(void) 
{
	snarf_construct_hat("/usr/bin/cg_annotate",
	        "322acb4fbf44d605039370ccd9ed6b94d0ecba221599385cab247bdfa4d6b97d0ffab5ab42e4e3785d84aa97bd5c0064d9bdf91f60ed627b29bb8bac48acda94",
	        1607
	);
}
static void snarf_hat_1609(void) 
{
	snarf_construct_hat("/usr/bin/cg_diff",
	        "41238858085a64f399505222ad741be8636abe18d68d7e7bea6c32aa6664c257af574a0048286db386c36aa623b74c406ee29a8670bb25325b85b48c74c9c1b1",
	        1608
	);
}
static void snarf_hat_1610(void) 
{
	snarf_construct_hat("/usr/bin/cg_merge",
	        "ddb49c19019ba7f977ef5ef4a0971d55405cb415a68d602433617fcf8270da291f76dc0986dad303c84d124a089cc1c5022d5ba7dc79d359a68ada7801f52a31",
	        1609
	);
}
static void snarf_hat_1611(void) 
{
	snarf_construct_hat("/usr/bin/ms_print",
	        "04725431aa8ae95becaf546c7b959b81c215cc0ee50295269c2796b620d96854ea35d970335917bd5e8a5c19e33765cfdf6a71598e548258f7dcaf860b5383cb",
	        1610
	);
}
static void snarf_hat_1612(void) 
{
	snarf_construct_hat("/usr/bin/valgrind",
	        "a70b0b59b15c1e14cb22217c4718e8c1c654ad1f6bbd33c1e84825e6e199137c3964520409e7649094a54653bd1d75f5aeeaaad7294f6ebef8f611d525e3bea2",
	        1611
	);
}
static void snarf_hat_1613(void) 
{
	snarf_construct_hat("/usr/bin/valgrind-di-server",
	        "63a58975e7d505d8cf5ff8c85412db8e704465893ff1b7a8e5433a57f9164572171a0fb8ae6998249bc535e6d8aa22f1a76e36f949db02eb9d98e7a769a42640",
	        1612
	);
}
static void snarf_hat_1614(void) 
{
	snarf_construct_hat("/usr/bin/valgrind-listener",
	        "405f90c84d0c244def0f3f45cecedf1428cedb84afe211bbb383d0e51b9d28934455c085ccc6fadb0f2733268c657c91502b0977775b77f903b6e77adcbf6397",
	        1613
	);
}
static void snarf_hat_1615(void) 
{
	snarf_construct_hat("/usr/bin/vgdb",
	        "83fac2c0f94dafb8e6eaeb0bab97d5f9f169c09b36c33e872ec3efdd80f49c173c9125a4ad9623a063b3818005ad7b674e6b436199b820d1a76a1223b9f896a9",
	        1614
	);
}
static void snarf_hat_1616(void) 
{
	snarf_construct_hat("/usr/bin/pcre2-config",
	        "15e8be952f01df27bdc60962f6e99e6c29663035b309aec03f5ff493b4b3d85ddd4414d49b6930fb91723dfeda4c352138694252a2ce537ad4f8916a8be22878",
	        1615
	);
}
static void snarf_hat_1617(void) 
{
	snarf_construct_hat("/usr/bin/pcre-config",
	        "cf0dc90d5de7bcc1fb94213795c6a75d9a6a93d25b8f91356cf670c44ff62edd2fbfa93c9ff934523239a123e3751eb5cc224d9a536f22d5dbfd5901c311fb43",
	        1616
	);
}
static void snarf_hat_1618(void) 
{
	snarf_construct_hat("/usr/bin/libpng16-config",
	        "ce733b9d48d32305c2b206232656df98c71089a2e9a7b1ac10aa9afdb96287769b286d4eda6f81f3d4089075bf2a5f246abaf51d56b36693625264cf481842c1",
	        1617
	);
}
static void snarf_hat_1619(void) 
{
	snarf_construct_hat("/usr/bin/png-fix-itxt",
	        "de1a20cdd9aa030af74a64d70ed2dae285c4bda1e5c38b7345810f9f1cc218fcefa3b38040398802c933bd77e0983156618577630949a1f30eb3a4b0c92cc4e9",
	        1618
	);
}
static void snarf_hat_1620(void) 
{
	snarf_construct_hat("/usr/bin/pngfix",
	        "f588cd6cde080c9472386cff9937a07b2111bd42eb1d767500d23e8ff668f21d81dcab37212a54eb79dd2586ccff00fb777c33c3bfdfb865fff72f7e03d6f496",
	        1619
	);
}
static void snarf_hat_1621(void) 
{
	snarf_construct_hat("/usr/bin/icu-config",
	        "da538d039d65517475e5b160185e27eaaf8eb5d4e6e3a03b2b33fbb4fdde4c93534498462e4851fa36f0cf1969457d3243867211e35db48509d59f057290f34a",
	        1620
	);
}
static void snarf_hat_1622(void) 
{
	snarf_construct_hat("/usr/bin/icu-config-64",
	        "63d8cb06dddb2155d5fb0d3db1ad10c917f3a33a3163acfe58663b5519d8297b8e542811b47deaceeb354a7ddbf259f2e15afe17a9e29a7d4b6b7cba36b1bc08",
	        1621
	);
}
static void snarf_hat_1623(void) 
{
	snarf_construct_hat("/usr/bin/icuinfo",
	        "e91cbb908393af8aeb9d31c42b16e2ca256812a8c5fbefd65ab7c6c21be944fbb8377f3cdd98e0191f9f1ec19d7240b125ef22c6069310f25048709b7a45bf54",
	        1622
	);
}
static void snarf_hat_1624(void) 
{
	snarf_construct_hat("/usr/bin/gdbus-codegen",
	        "0e3718b024a6f76bee390168ec6932f2d58dd413e600f461155dd7cc36c60276b23b7188d2ed7eea71644ee09f89c910b13ad3c68e2021cf0f13620fc1fb356d",
	        1623
	);
}
static void snarf_hat_1625(void) 
{
	snarf_construct_hat("/usr/bin/glib-compile-resources",
	        "cb4e909bbe59a5c2a1170709e84543cd905cac573e3f8eb19918bb1798fb3c1eb687bf3a2f31ccc28ecbf5a0719209028925c0462ead250a7b8267f7bd0e8974",
	        1624
	);
}
static void snarf_hat_1626(void) 
{
	snarf_construct_hat("/usr/bin/glib-genmarshal",
	        "e7c44dd7b140228a86382fc60c0fc1c5a8cd30acd8851b32583807d6f764c5532fadc3f126090435d236a0bf616393881683ba2ad844ed22fef3c7ce9b1a8e0c",
	        1625
	);
}
static void snarf_hat_1627(void) 
{
	snarf_construct_hat("/usr/bin/glib-gettextize",
	        "0fe25ca30c1344f2c604f2adaed3db405e955be7fa27cb4ed85817909a0b6243421a7a501cc4b88961bc2630554956b5716283c4ab939c17e15776955c8e3c3d",
	        1626
	);
}
static void snarf_hat_1628(void) 
{
	snarf_construct_hat("/usr/bin/glib-mkenums",
	        "c3365333b580366f34bc5cf8929c1da4fe96aabe7e30b1732a6b5e41c60746769a43f3b2bf3cd6a33e3f2e1c1ad72ec3faaf7392e72d9047894b087acfee488c",
	        1627
	);
}
static void snarf_hat_1629(void) 
{
	snarf_construct_hat("/usr/bin/gobject-query",
	        "23ccd50137a37fa3b690d2b7d1159d8d0bc03a7504edb388163b417a4c30ecda1df673de8694aa78fef0b1491f6c124a2c115f5c148a11a17a1e008f9f42fa7b",
	        1628
	);
}
static void snarf_hat_1630(void) 
{
	snarf_construct_hat("/usr/bin/gresource",
	        "1582511ab4885ced78d3e9005b3b29e74c9e06872faae4a5299249ac74df7463ca8f48775073f89fa74bb101a329351e87b76c94e37fb278c92156865de8f5fc",
	        1629
	);
}
static void snarf_hat_1631(void) 
{
	snarf_construct_hat("/usr/bin/gtester",
	        "c758342deba4a6ec57492743ab001edb9d60343e4f6c917c50eee6e88447854460eb331fd8e33e963e767a1e4b0b8c0b8f38d28f3df12bf714cd5b79b2af8489",
	        1630
	);
}
static void snarf_hat_1632(void) 
{
	snarf_construct_hat("/usr/bin/gtester-report",
	        "902f682b4a1e61e42fdffb40b61ab4b20c14997b1c86ccbc6358272f93dbeba75c373aaba8fe34bfaf15897029ce7ed7f0ba018956e404daeeee84906f9562c8",
	        1631
	);
}
static void snarf_hat_1633(void) 
{
	snarf_construct_hat("/usr/bin/xml2-config",
	        "ae87ff2a80add4155a5bfa31a3ac048e8201f60c357fb5cf71a1e6adf961c06c8b1ddb724291dbd3f6c89f7cd3105fe7fb255aae9ad85661fcbde489a694a720",
	        1632
	);
}
static void snarf_hat_1634(void) 
{
	snarf_construct_hat("/usr/bin/brotli",
	        "5ffd6fe955ac7f46b08cc4a730bbd4cd015aedaa560444f6f0f59fd2b67ca2b73b9ada296862027de6eaf85728343383c91066b9e1c6672faa3c3ac327e07a8a",
	        1633
	);
}
static void snarf_hat_1635(void) 
{
	snarf_construct_hat("/usr/bin/hb-ot-shape-closure",
	        "38fdbc38a3e91aaa94cc14f9eb671f5af647c1f611d433b74f9aa5a6a8fb8e47eacf6cdc1ef7b1035ca05dd49e6937c9873c71e5601a7d35637380f7c29e6f54",
	        1634
	);
}
static void snarf_hat_1636(void) 
{
	snarf_construct_hat("/usr/bin/hb-shape",
	        "49ada0f885597ab57f68ddec0ecac8787ae1475e6fb571b53647e9b7cefa77506d5b3de209c5ac76a4ccda9b0ef9302241bd10eff600f16ae78f017726267bae",
	        1635
	);
}
static void snarf_hat_1637(void) 
{
	snarf_construct_hat("/usr/bin/hb-subset",
	        "935c8e7495d6ba30131305bf9cb0d72cc3f6a581d775f621876aac9b7b2216e4c40eecc8746484a248d9416a96ce92b2d626c7da6259feb36384ff4c9589bd50",
	        1636
	);
}
static void snarf_hat_1638(void) 
{
	snarf_construct_hat("/usr/bin/hb-view",
	        "07e16dbf05ea074c7ef1e85d2517fd4cc17ebf7b9acafe211d9255a5612f3e69e52a6616aa264b1b6ca3c04f8765647f8310aeb3baa7b1d1a2c7f55ecaffb161",
	        1637
	);
}
static void snarf_hat_1639(void) 
{
	snarf_construct_hat("/usr/bin/freetype-config",
	        "f74c6ec473a4a018d0e8d22f52b89b9f27c960505c92a54316f37f9a77fe32721dafc2d24cc7acc63c28b561e61f92599b773abe3869941a8741b08f853d0815",
	        1638
	);
}
static void snarf_hat_1640(void) 
{
	snarf_construct_hat("/usr/bin/c++",
	        "ce01c135bae121f414397a41351b48be04778baa3f5b81aea25f1f762a3b34c81a9e633255409ae07cbdb0c01ea4ccd9efba247456a0780b1f6a183e3b971d59",
	        1639
	);
}
static void snarf_hat_1641(void) 
{
	snarf_construct_hat("/usr/bin/g++",
	        "ce01c135bae121f414397a41351b48be04778baa3f5b81aea25f1f762a3b34c81a9e633255409ae07cbdb0c01ea4ccd9efba247456a0780b1f6a183e3b971d59",
	        1640
	);
}
static void snarf_hat_1642(void) 
{
	snarf_construct_hat("/usr/bin/x86_64-redhat-linux-c++",
	        "ce01c135bae121f414397a41351b48be04778baa3f5b81aea25f1f762a3b34c81a9e633255409ae07cbdb0c01ea4ccd9efba247456a0780b1f6a183e3b971d59",
	        1641
	);
}
static void snarf_hat_1643(void) 
{
	snarf_construct_hat("/usr/bin/x86_64-redhat-linux-g++",
	        "ce01c135bae121f414397a41351b48be04778baa3f5b81aea25f1f762a3b34c81a9e633255409ae07cbdb0c01ea4ccd9efba247456a0780b1f6a183e3b971d59",
	        1642
	);
}
static void snarf_hat_1644(void) 
{
	snarf_construct_hat("/usr/bin/m4",
	        "5e1753faaad8a765d20890a454c03b4af56bbbcfb201ae60d382cd04ca9a00f32cfbfdc29c5696573edb1ac1e932696ac9eeffef2443008f563d16df162d4522",
	        1643
	);
}
static void snarf_hat_1645(void) 
{
	snarf_construct_hat("/usr/bin/flex",
	        "d3c327490436090f40f2b59b4f398db3d56787e5afa8817398495bfbbc999b4edf0d63c2d6de3f6df3f4aa95d9f1d5e9fbdee5bf9efd29f9c2c0957bdac11f8c",
	        1644
	);
}
static void snarf_hat_1646(void) 
{
	snarf_construct_hat("/usr/bin/bison",
	        "cc5c46f53ab3c4b712aea76c66672b80446633643de2a5ec8952a258c75793e745c8489f3c22c42c7b078b00a9a59a21623f89f9bc7ee875b8d5c32e73c0aa1a",
	        1645
	);
}
static void snarf_hat_1647(void) 
{
	snarf_construct_hat("/usr/bin/trace-cmd",
	        "3cfc0a32927c7f10bd2890698bae882809b8945c5581c0b646e0a8bfeaa7d087587172ed45280d620d2aa059493395aeb10dd9fb6071db9bb38d8bbcf4103629",
	        1646
	);
}
static void snarf_hat_1648(void) 
{
	snarf_construct_hat("/usr/bin/make-dummy-cert",
	        "57bcc311edee3a0c9ef8da8aaaeaf60b7d35786a60f467623a2c37dbfdfc1091f3acc64c5b4f427b1ffb81d390263532993ffa983411b9af7bd2c7daca1627fd",
	        1647
	);
}
static void snarf_hat_1649(void) 
{
	snarf_construct_hat("/usr/bin/openssl",
	        "abfa3566b3b32cd8a4ef10fbf6111752a60fdb9b88f14d1514a1b7a7b72289f671c7261017922e8f2d723803dc3f858711d49dc134f7356c07df9b4ff76436f0",
	        1648
	);
}
static void snarf_hat_1650(void) 
{
	snarf_construct_hat("/usr/bin/renew-dummy-cert",
	        "61b89a67f75c84e8999d9ec721f88222bb5b9ed2399d27e4438742ae456596f787699f998497b7d3c7c72b715d76ae1ca802c75250304a6b36376a244256a6c8",
	        1649
	);
}
static void snarf_hat_1651(void) 
{
	snarf_construct_hat("/usr/bin/btfdiff",
	        "78fbe16cbb45db25db4d1c6777aec33b9980460397b8aed683610eb11a75025ec6bdfb2e3df6ac37e7d7e67f500023aa2fcb3ab460488b416ce9e487ab352d1e",
	        1650
	);
}
static void snarf_hat_1652(void) 
{
	snarf_construct_hat("/usr/bin/codiff",
	        "c774c62b4582d09bf7d845f080b824191a337a318cc885f3e6e4d6afa7749a05186be5d2b77f1216628428aa963879c9eeb7a5b2703b35c5294a1775735623c6",
	        1651
	);
}
static void snarf_hat_1653(void) 
{
	snarf_construct_hat("/usr/bin/ctracer",
	        "4cc028b6ed45823503e5d43de3a7402fa478dd883b2f4ad31088f9e3617f9a2cdf48850de0561a5d2f4c43b8636d0f2874baae5e21d410f064ad56f30a6bfcfb",
	        1652
	);
}
static void snarf_hat_1654(void) 
{
	snarf_construct_hat("/usr/bin/dtagnames",
	        "7a67cec4aa9fa2ca629abf3c9d1815429296398b7a2f48ec275aa0de8b294a7f29ee429acf305de90b3d558cf4940c69091904d44aea89fac3afbd456f36d04e",
	        1653
	);
}
static void snarf_hat_1655(void) 
{
	snarf_construct_hat("/usr/bin/fullcircle",
	        "d3b2bc3f21b7059ecac09ecc976aecfd609eb0a0deec24f86c3d430aedb30de730a1a0285ba4f7dc03fefd327da889af1f8358f265359df02b33568ed30fa19f",
	        1654
	);
}
static void snarf_hat_1656(void) 
{
	snarf_construct_hat("/usr/bin/ostra-cg",
	        "5371d9501f2c45b54ddce9597054462e0da528e0c885f85703bf884c069ae0be8b1ab766f2af9f108a3505e2561b70a1dcc32f5eef74818910eedd7dd0a1897e",
	        1655
	);
}
static void snarf_hat_1657(void) 
{
	snarf_construct_hat("/usr/bin/pahole",
	        "5c0a1a72f1076a606722db9ce3bee33b42b5d999ff1b83b86478450ca595eb5fc13d0bc5657d966b52558148a3195cc3fa7a78efc85273c29e8136df88bf5f0b",
	        1656
	);
}
static void snarf_hat_1658(void) 
{
	snarf_construct_hat("/usr/bin/pdwtags",
	        "a23bd02f91bc4e339d8ed310e956336e16baa8ff36a9fbe368ce6b53f2bafebff993dd4c754d3f3f1d5fca3d93677257791b9b99aaee6b00ed741e66f487057d",
	        1657
	);
}
static void snarf_hat_1659(void) 
{
	snarf_construct_hat("/usr/bin/pfunct",
	        "24cc11bde79e1ca420b21e414d32cd587fdd41368ac2a5dcb0434d9004ea5526a89fb3b01521118779a5e04703427e9833588e05745b82ddf29edbcde19ca9e6",
	        1658
	);
}
static void snarf_hat_1660(void) 
{
	snarf_construct_hat("/usr/bin/pglobal",
	        "918decebef37d29c6b7f7c671eca026acda4def717593fbcf738e633aa227ca477253fde96141442007859d02f11a6f0fe9d7de99ececb7d5ff50c99d70b64f9",
	        1659
	);
}
static void snarf_hat_1661(void) 
{
	snarf_construct_hat("/usr/bin/prefcnt",
	        "dac206fc292fcd2c41835442b7267a6ae180017958f17f7d88a93337867d3f9f0f6a1960dae32bffbfb71e1c66d8bb4d284dc0efe75500f5c5f0870bb0ca34a9",
	        1660
	);
}
static void snarf_hat_1662(void) 
{
	snarf_construct_hat("/usr/bin/scncopy",
	        "b32d365a8c14f3d8d6778483fad9ac1b36059df890e02c365695e1af6b45741991c8b224bdb96644ab2f11700a38a791c7a7c059d1399ad4d3224351e8f1e87b",
	        1661
	);
}
static void snarf_hat_1663(void) 
{
	snarf_construct_hat("/usr/bin/syscse",
	        "463426134ec34e0aa3750e9aa4b85fb9cb641f72589297506729fbdf0f512e83e1720fe9112e4500b892bf402ae6535dbb4f0951beeeb2d3517e3173ecbcc545",
	        1662
	);
}
static void snarf_hat_1664(void) 
{
	snarf_construct_hat("/usr/bin/sbattach",
	        "9dfb685d8ee886ce0e9eec0ac87edb8d292a11d104f752122f9eba2a99159dbe9146deca30d094f2b464f6cd87b464e8752c2df7497b8bf11081446b324f1090",
	        1663
	);
}
static void snarf_hat_1665(void) 
{
	snarf_construct_hat("/usr/bin/sbkeysync",
	        "19f93c0ade7d4a82a8ffd90143ca3f99d68f214690f48ada7dec8c7b04c080e67aff60c53a434a11b952326d2cef58e4cc22272957eb1762a4246514fb2a7ac9",
	        1664
	);
}
static void snarf_hat_1666(void) 
{
	snarf_construct_hat("/usr/bin/sbsiglist",
	        "bdd6cf6f4e91dfe85ff21a811fff62390adfbb20545f36a890bc45e2986c6c733fbb18a254060c025d74cac3ff8bc62bbb46a590c536b315cb3c18b4428e03f5",
	        1665
	);
}
static void snarf_hat_1667(void) 
{
	snarf_construct_hat("/usr/bin/sbsign",
	        "4901a820b33eb505b581efd67d3dbdd17d5f0213594dfd09747a5bae9d1280303ff865014127a3859c213d6dad1c0dca084a2f99f94fb8436f25a94c630f19da",
	        1666
	);
}
static void snarf_hat_1668(void) 
{
	snarf_construct_hat("/usr/bin/sbvarsign",
	        "9353e8fa7f9967bb734750406a9bd25742b9bacada92081770e50bfd63ee524bfd425efeac1fe08815dbeacec5f046e12989f5af7a18efcf5f3f3821f183ce0c",
	        1667
	);
}
static void snarf_hat_1669(void) 
{
	snarf_construct_hat("/usr/bin/sbverify",
	        "b21de37a7bbeba2fe4a82cb063c324842496365ccc0685a8c87b1f19343c2fabc81016d148bd33cac498368db66708223e3887f6879c6c0e20d5164113efe589",
	        1668
	);
}
static void snarf_hat_1670(void) 
{
	snarf_construct_hat("/usr/bin/cert-to-efi-hash-list",
	        "99d52d4fa6ad41281a6d042ebc6548a6229b292f915ea0903857b18161e789c957fd91cf29dddfcd6b3c216686959255e6d38bd0778b7645d656077f3c6d8997",
	        1669
	);
}
static void snarf_hat_1671(void) 
{
	snarf_construct_hat("/usr/bin/cert-to-efi-sig-list",
	        "c0558fa7b6ecb07d162f36153a7f6f68b1a580aa3ed88d87fefaa2e6b6a0342efb9467b4615a0ecf4053771e4312a9a68c1cb0fc8e8f89926d93e5059f0050d8",
	        1670
	);
}
static void snarf_hat_1672(void) 
{
	snarf_construct_hat("/usr/bin/efi-readvar",
	        "f81f1aa59b2dfadc537d51039d26e5f7a73615c5c376611780f0363a670e8a072cb04dc670e624526924696beb884ea309b693b08de70b942d42e24b1cfdc90f",
	        1671
	);
}
static void snarf_hat_1673(void) 
{
	snarf_construct_hat("/usr/bin/efi-updatevar",
	        "92fc90f781981dd214ffd57f8c949cc8f039218b8056b5840e84d35e6bb5a8f2ed4d16b0b253a214400a7f3b44fb8740a08a24eeb70082de6707f02396e059b4",
	        1672
	);
}
static void snarf_hat_1674(void) 
{
	snarf_construct_hat("/usr/bin/efitool-mkusb",
	        "479fb8b2fef47429c386e9a80efe21972e4378ca5e6a5a8d5f02480a8997563c82b88a9c581c218e72f985036f87b38cfb5493eec740a9594be96924acb50642",
	        1673
	);
}
static void snarf_hat_1675(void) 
{
	snarf_construct_hat("/usr/bin/flash-var",
	        "54fa664f9faa58a3697a557f796142ae56b22adb43633d4f71843d2bc252926c86b82796a308c24ed31244c3f493abeab762fea4b03bf3de72ad1c84a8d84989",
	        1674
	);
}
static void snarf_hat_1676(void) 
{
	snarf_construct_hat("/usr/bin/hash-to-efi-sig-list",
	        "42c3b107cec5a1d08eaadbf73054d7d55260cce475630e75832a1d92beccc3926fce0ecb186725ddc20fe45a116736d7243e7ad0d9fb02c42f6e175441bfe808",
	        1675
	);
}
static void snarf_hat_1677(void) 
{
	snarf_construct_hat("/usr/bin/sig-list-to-certs",
	        "0b46e230707d6f4a03120e176801fdc686d66282f48ad9f5791645f1d34fdf5a875b592c1675a30a54a6355cc31cd0d86f79fd32e65cc15a7a9b1b7ac021fd9b",
	        1676
	);
}
static void snarf_hat_1678(void) 
{
	snarf_construct_hat("/usr/bin/sign-efi-sig-list",
	        "24839d6fb22eaaf91a1b53000931475fe01fce7c2943abc367652542f56341bac60f033ded746f7d7e742c0ad8a1a6f7d2ea3b1d44b3971e80bb8be55fb08566",
	        1677
	);
}
static void snarf_hat_1679(void) 
{
	snarf_construct_hat("/usr/bin/xxd",
	        "5fbba83f9a717895d256d9b7cd8fae0f5d38b88e95fb80eebeef2bc4deaf0a66169257fc0f4d4334df1c8a6f435a7d986b02afd1859d121ff587d0078d4e59f8",
	        1678
	);
}
static void snarf_hat_1680(void) 
{
	snarf_construct_hat("/usr/bin/vim",
	        "e4816703e882bd708437bdc9dac781d72214bda57d732976521992a116c850ff2efb7596259ae16e57d447a03b812dfb493b8b7ba5155f64773f4b7b9dfe4478",
	        1679
	);
}
static void snarf_hat_1681(void) 
{
	snarf_construct_hat("/usr/bin/vimtutor",
	        "793f34020a1a0ee7ef23d8cf7fe5887f45a8cae72e33bc90fa3ef82c68d4b1f053f4ffd95f3a91a36e7e0d3b08c222b9b73294467fb571dd6c428c6a7b165413",
	        1680
	);
}
static void snarf_hat_1682(void) 
{
	snarf_construct_hat("/usr/bin/dracut",
	        "a6fd97532dd7364daf6c2ebe81333953d18c32e83823f0c107d6846fc789c7686eab883d8f315cc6555d870fcd1fc8192b626653ec37fa49574e129f12c391b7",
	        1681
	);
}
static void snarf_hat_1683(void) 
{
	snarf_construct_hat("/usr/bin/lsinitrd",
	        "56875aeba47f3015b05f8e00f8498b1e559c6b30eee64e3318b0a80622cf703abf4779285e816ef5b5402ce4f7e0ebff0fa0ffd175a3fdbb2606b822b9c4f8c9",
	        1682
	);
}
static void snarf_hat_1684(void) 
{
	snarf_construct_hat("/usr/bin/dracut-catimages",
	        "ceef81b36935186c6aab48896a323274aaa953aa53e590e40efca68e05eb6bc3cc12a2a9073112e668f69ed7775948a229c821987c3793582a1a5b3f7377fce1",
	        1683
	);
}
static void snarf_hat_1685(void) 
{
	snarf_construct_hat("/usr/bin/gnome-software",
	        "7c72f08149d2c8094c773d936f75fb5bdb24249bfff530e3d712d48abf01c43f588a54e630b21dba17c5a9d0e28d089994166e1ea2868be74df7b07fe0c0abcf",
	        1684
	);
}
static void snarf_hat_1686(void) 
{
	snarf_construct_hat("/usr/bin/otfdump",
	        "5c95acbbaa74f2281a2e4403308cf8254a1963c312f506e47762ba2b1642951f3e3cd081a0a7aa6cd80dd075fabdb9158f4891e9e46b52081a9954edad7a588a",
	        1685
	);
}
static void snarf_hat_1687(void) 
{
	snarf_construct_hat("/usr/bin/otflist",
	        "9cd40d42e1968bcc8426e8fd431e6aaed7ef7456c46623aa1fdc285f45878871fac146ebfb0063f9b5b1bcf1225d29f537eae3a30a8ee53e1c99c28ac1874a1e",
	        1686
	);
}
static void snarf_hat_1688(void) 
{
	snarf_construct_hat("/usr/bin/otftobdf",
	        "24d95be81ec9145e7bfb092de091a7cc3899f44ce00677149254d6b279f24af0d2f52b973e1bdd933f32da1411864668473807b0e703b58726970def18cf9fb1",
	        1687
	);
}
static void snarf_hat_1689(void) 
{
	snarf_construct_hat("/usr/bin/otfview",
	        "99748e65ebdb0bb96711d3472c6acda17d6b2cea9d729d9201b7af0ca557cdc33d74ddb5cc4258fe2ff700a14f6d22ea19082c5c8ac30d6bd2f03e3789c2fe6b",
	        1688
	);
}
static void snarf_hat_1690(void) 
{
	snarf_construct_hat("/usr/bin/dotlockfile",
	        "05c35ac1930acb62a81ae86539286c552d34a72dd09da84f657e4f4675368f02a3b1b94738c04e20bc68ae496a86cffa901dca3ecee7a035cdaa8a34aa078c5f",
	        1689
	);
}
static void snarf_hat_1691(void) 
{
	snarf_construct_hat("/usr/bin/ebrowse",
	        "aa3f49598400d71f126b8c8ab4433431214e8743a5b3ebecc74c8ad31def7c63bffd0d29a886d9dbc87cf31e6ca36bc326c1109a77ca07274564e59b3b58d46d",
	        1690
	);
}
static void snarf_hat_1692(void) 
{
	snarf_construct_hat("/usr/bin/emacsclient",
	        "a373231c24deaaa033505b862622be3858552fe3f6664f3885670ebbc20605d9c37002e9b68548896f7d1624e736cee2b93d0db982db5455b0dd7ae15fc476cd",
	        1691
	);
}
static void snarf_hat_1693(void) 
{
	snarf_construct_hat("/usr/bin/etags.emacs",
	        "80fd0c9ca0c693c9d5b56e3e5cd13f95cb8e7b00f64c0473c2fd03a0558f6b9d4a4ea8d150a690e70b558da2528965fa66c5bf27d682ed3957772977231a54b1",
	        1692
	);
}
static void snarf_hat_1694(void) 
{
	snarf_construct_hat("/usr/bin/gctags",
	        "c1c57c51457edcb9e8e421ea4b4396c5cd756b277a11392cc1423baa69596fbe831fbd452161605f6d5d8921bf960e62336c322ebb95e7d328d2dd3f7f599b21",
	        1693
	);
}
static void snarf_hat_1695(void) 
{
	snarf_construct_hat("/usr/bin/emacs-27.2",
	        "370fa71d42644b7a1a7ec85d08ed83f7bc992f819158a5b66fe4abe6451368740a0fe52441e0fc54ba04660b47d4c4245ed69197acd07414dde79dbe99b575ed",
	        1694
	);
}
static void snarf_hat_1696(void) 
{
	snarf_construct_hat("/usr/bin/io.elementary.code",
	        "6969b6c528d373cc5830953d4457211fc8c5f446140883c08f8b93d58886c199ec52ae99164d238d1999093a055e09624fc59f7f9949dfa91702dfab4b1437be",
	        1695
	);
}
static void snarf_hat_1697(void) 
{
	snarf_construct_hat("/usr/lib/NetworkManager/dispatcher.d/04-iscsi",
	        "e9e728eabad4ab09978b50f4501975b216ba10f2288a966626dc017667f9e1b6db89e96d8f3c96d100b451c4c4032035a720fc5d8964a5ab8a0a9109d8450c95",
	        1696
	);
}
static void snarf_hat_1698(void) 
{
	snarf_construct_hat("/usr/lib/NetworkManager/dispatcher.d/20-chrony-dhcp",
	        "848b053cca7d64ae104bf2b9988ebbdff345e362621d995596780937777117c5a9d55c1965872938c3c574be1d6f1f48e163104fac4c4ad9f147ac0738f1237a",
	        1697
	);
}
static void snarf_hat_1699(void) 
{
	snarf_construct_hat("/usr/lib/NetworkManager/dispatcher.d/20-chrony-onoffline",
	        "b7dd110632b7e5da3953d0a17b773d5226cd4079b28dab09d2e8a7093482aec2cebec1dfb44dd2744b45d175a5770eec9d1c2d1035cd3206d6419bab1565d5f1",
	        1698
	);
}
static void snarf_hat_1700(void) 
{
	snarf_construct_hat("/usr/lib/NetworkManager/dispatcher.d/11-dhclient",
	        "9b51cab63923b83575d55d17f45872fe83a5b76f3eb8f2fbdc67cee96781297a0f330d81bca4c58abbc139a833e103c673f8b661db8d1c55459dce4a96a4ad74",
	        1699
	);
}
static void snarf_hat_1701(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/dnssd",
	        "964a29e6c043d1ff48259896483123543866cbade246511fca3b1d755ae8852d0139944427f6635387b007a50560d06b93145f5f7044f29778b0af0bca274128",
	        1700
	);
}
static void snarf_hat_1702(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/failover",
	        "6a71b053f9b003235d15e2f674b6b21b7d79dc402ea4f138bcfc065bdc5351e7a19cbd2a22ed962c41d8626e8e59ab1b22987072333eec0eecfdd0795885430f",
	        1701
	);
}
static void snarf_hat_1703(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/gutenprint53+usb",
	        "6139f3ccfc9f7c3f0175eee8976dfd44daeb2644305b9fd5d4c8ed7ed50531a7f85163d46a1dc2bf6ce37d1ebb9709000909172cbc88b196c651352808275ee5",
	        1702
	);
}
static void snarf_hat_1704(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/ipp",
	        "611b389e88447fb21eaf10b3b016035b9d982b7aaaa56d88418966347128090dd11473d9ee71a83a0219619f9f31c9819c7d95f072c31082059b10223d0f460f",
	        1703
	);
}
static void snarf_hat_1705(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/lpd",
	        "414469afbb1b15b74a94495ad8db43572124d4fccd41a37b2f35d2ba18c1c00d16e2282dc8d7b22ced085809dd6869acab278d10dc70521c49735578fee95104",
	        1704
	);
}
static void snarf_hat_1706(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/snmp",
	        "4e6068d9fd038451b02924de0568c82431d5ff1c9f1090813681778e0ecc70b8d923f155f015f150ff314c86c924a9bd223487c206b8990c9087527902a8daab",
	        1705
	);
}
static void snarf_hat_1707(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/socket",
	        "ea9f9e8e520f8fb26a023866748d4dfd7326b93717fd21db87d85a9a89533dfa1c61e8dbba7f987a5f8e9a782c8cbcc6692a0d8b21b29b6ec186d2beef54ae46",
	        1706
	);
}
static void snarf_hat_1708(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/usb",
	        "5e2c2d91759afb12ad5c94df347419fb00198b05eb1feafcaa7ccd976853d813aae199edbcb7f7b3d5cdc6c16dbd93c2e05795fc89c1325d45ed60c46f695a0d",
	        1707
	);
}
static void snarf_hat_1709(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/hp",
	        "54331f22b9c7841126f63687a583626d9090cbda7612416ac709660778a0e2ed49a5ef629db4ddb54fa2410665cdd7cb5873d98383f41be0c72bbdb52dd79843",
	        1708
	);
}
static void snarf_hat_1710(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/hpfax",
	        "3f35129d064b106b605a1857177e50b9b9be8ea69a74c5d7a2b9fea21f1f796a2c1f47f1dc7fa39b92be3df9874eb731f62b14ee5dd6d4d37e4a633c579c7d61",
	        1709
	);
}
static void snarf_hat_1711(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/beh",
	        "9399d735f0fc8ee666f4c5abfb1a6c1bb22d377c4622709e789aefb6a914f73f9aaf875c6142543d9275e9777d8f610417d42741bb5327cbda31d31aa85441ba",
	        1710
	);
}
static void snarf_hat_1712(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/cups-brf",
	        "854c3fd1845c1c6e5306187eeddef4a05b8c0deca8d146603758f5ee56cf44516a3a143cccb6604b4d6c2f78a2bba124cbce649778418cbef926a422979e7fd4",
	        1711
	);
}
static void snarf_hat_1713(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/implicitclass",
	        "f9e5db192b68095bc13252d3343a5c8ab74a1a48d8272bcf3bfa5103d3a389f8034ce2aeb51680d81d800ae7a8a990df4278a57e24b0fa3a4a74f9567d9014ae",
	        1712
	);
}
static void snarf_hat_1714(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/parallel",
	        "4057240cf7da4a62e8b6898eb07385ed30e544fe27047f8625666d104aec6894d9f83f04386a493ebabe0bf0e70349cd3130a571941008cffefa6b71bb235121",
	        1713
	);
}
static void snarf_hat_1715(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/serial",
	        "3af6c5829bb07bba061fdc1513d43fe3ba0364313791520458c4f3825808260d5ee888b65ae44c1d0a0f82c426bf53de01c7ba66b72ad60b5eb15dfd500badf3",
	        1714
	);
}
static void snarf_hat_1716(void) 
{
	snarf_construct_hat("/usr/lib/cups/backend/bluetooth",
	        "a35ddd08730e5b0044bb049990533d9275e1fd3836cac6c0bab7b4db9037d81dfc4a5da04afffc7a229e37612c9ec3f5b8bda1ebb0da9c46e125d103192f3659",
	        1715
	);
}
static void snarf_hat_1717(void) 
{
	snarf_construct_hat("/usr/lib/cups/cgi-bin/admin.cgi",
	        "e8da8084061360b73084ae6ef5210a2529585ecea925438a09e36ba98fcb3b20c5c04615a59b33664558231f7410e0513158617432f584067df4fbca6791f094",
	        1716
	);
}
static void snarf_hat_1718(void) 
{
	snarf_construct_hat("/usr/lib/cups/cgi-bin/classes.cgi",
	        "8e2c24e3ba4145ebdd286e2bafc999ddb5204aa8835ed8aa2bb0c46595b14b59946f6a6c2619d9115938eae1c91c313868b153abc70b16aac428b8fad6fa4eed",
	        1717
	);
}
static void snarf_hat_1719(void) 
{
	snarf_construct_hat("/usr/lib/cups/cgi-bin/help.cgi",
	        "dba7bb6b157b98e8fce7ce85570f72f4f2056b9893fe3387074c73fef4e3a2b0a05f12110932207fe371405dfa03a41faba0ccf283fd96eed695e13136739855",
	        1718
	);
}
static void snarf_hat_1720(void) 
{
	snarf_construct_hat("/usr/lib/cups/cgi-bin/jobs.cgi",
	        "be3abf1bb2eb9c63b280db72dff4a44050c2e6336eff40cfa51e120c66e9691e8edd44dcd0d08ab4f5448df3a9eec795f6bf1c1a2ecc4cc079c44b657e5341f1",
	        1719
	);
}
static void snarf_hat_1721(void) 
{
	snarf_construct_hat("/usr/lib/cups/cgi-bin/printers.cgi",
	        "2159c9992fb54aef61fa2a3e916ed945b753821eb739a7b0a6d2a9db1ada6adcc19ea24b8b41109e8e15817e4c58bdc15be30bd1555ea816a3bbf6e70f6460fe",
	        1720
	);
}
static void snarf_hat_1722(void) 
{
	snarf_construct_hat("/usr/lib/cups/daemon/cups-deviced",
	        "9bf16acfa0334dfb67951bfd431c2073b0fbc9af9a8a201b874dbd04cff87f0df2bf567670f2ee72998d98e96af35b6880ac39cf6d857175417bee80a079bfb9",
	        1721
	);
}
static void snarf_hat_1723(void) 
{
	snarf_construct_hat("/usr/lib/cups/daemon/cups-driverd",
	        "c5421acb0f9e5b238e75e0e590824a9583916ee32f4238ae4779dfaa360782e911e2723bc509c7a5a9072f883f1c272254543822e392a65be279df9007bbda73",
	        1722
	);
}
static void snarf_hat_1724(void) 
{
	snarf_construct_hat("/usr/lib/cups/daemon/cups-exec",
	        "f6258ff12b95d715ffcd287488e736dcb3fc8c1870e9288de2d78fbee689f76675ebae5e3da6f8aa64d4748fd3f7fe87d69d7319f0730fb093cbfbf2f22eb808",
	        1723
	);
}
static void snarf_hat_1725(void) 
{
	snarf_construct_hat("/usr/lib/cups/driver/gutenprint.5.3",
	        "900f0d181510e7e91c01ab5b16995a15981cbe5467279c796280aaea730fe585ada8b5978a9080a37fb08a25623cfca919628a2cfb7649994785ed942bfa3496",
	        1724
	);
}
static void snarf_hat_1726(void) 
{
	snarf_construct_hat("/usr/lib/cups/driver/driverless",
	        "7a2cd194883fe733bfb13654f322f9ee0d9eeaf3664019fe8e3b5fe4d120b1a254bd7274964812431e21929e334f1ae8c415cdb6181d7bf36480103a33643e27",
	        1725
	);
}
static void snarf_hat_1727(void) 
{
	snarf_construct_hat("/usr/lib/cups/driver/driverless-fax",
	        "632129030f9b7f3991a4b7d4a5418dd1badaa5d0aeb17513a46919f1d7c5df9e8ac80ce337ed1852d0cd56e9ae8f7fabdffeb66ab31cfbc69c7204266c0e79ac",
	        1726
	);
}
static void snarf_hat_1728(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/commandtocanon",
	        "89c65a11ed0b7e2358358d393acdc5060e09304a0c19a3b51a83a61f8b26327403a55d7ee1b8a53a1c4692d362a71b0cbe1f744c3e1c8809699c311b09c2a483",
	        1727
	);
}
static void snarf_hat_1729(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/commandtoepson",
	        "008418f39e3d366b6f7178949e4536154a3ad267a5b6376f59962ea6cf4cee01a89a736c06801dbb31da7823febd9590ce37172590380694ed279391e9df4258",
	        1728
	);
}
static void snarf_hat_1730(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/commandtops",
	        "8a45306b66db4788d96c0cdcd4f017bcab9e67c0bdf2c3661b997ab03fb17fc02bd7686f09f305f09790a8a08a3689af563c5ea7c0ae714a1b28c786bb658c51",
	        1729
	);
}
static void snarf_hat_1731(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/gziptoany",
	        "0d4cf25c4e81b69f79728f15cbba5b02a8d337890b1170b1bea89e23eac26a773c050378cc7a6d2efc0ee42d22d70da1463a337c4b236ebeb818ea24fb0ac1c9",
	        1730
	);
}
static void snarf_hat_1732(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/pstops",
	        "31d28df750c87b42667aaebbe25c954720cfadf38f92bc3c1f1220573491863a94cb75b3822f4d69d9b420890ffd0d71bfb2ba49a673edba59eaf49e3ca8ea91",
	        1731
	);
}
static void snarf_hat_1733(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertoepson",
	        "0bcb97eb97f941c7c81116d895f06d38d741839f991bd9c53f5a12c77222f88749dbaa8d96341bbceadf86123c72e7876c047ffcc0d769756109d680ae3a720b",
	        1732
	);
}
static void snarf_hat_1734(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertogutenprint.5.3",
	        "5487a4508c69507dbee79aadc4be6a355aaafa6ea554ac84d71a538694ab40c2197e6e2be7467711e54885d9b89fe84684cc33e44ef7d6ede26e1e1c62f370f1",
	        1733
	);
}
static void snarf_hat_1735(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertohp",
	        "be0c3b52d21111a5eb8f4a0034fcf91fbeae10df1d975381118646a3bed9836f1fabe519ba1a04c4b6f908037ef66c3bf909cd114d2bd65b49742b3909ebde4f",
	        1734
	);
}
static void snarf_hat_1736(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertolabel",
	        "c887d529b3c133d4719ccd11cae9ec96879eff85c3a27ba6a756e225ac42a036784e8d07744a010f4297e79171d787e179c5dfcfab2a0e98fae5502bf643ba47",
	        1735
	);
}
static void snarf_hat_1737(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertopwg",
	        "960bc740dbdf50cf6b3c14165df43878df898a70e5fc8b795e012116fc62c56360dd5e1c7db2edb18eaa022267f906cc7bab409fd9a83f1c85e20d650f4e3885",
	        1736
	);
}
static void snarf_hat_1738(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/hpcups",
	        "984f4b2e4a30a803f61ae7b5d52e41005007ed2ac9a1cbe4db4a2d7af3de3162269b9deb7900bbfaccf110fd40967bd068374de6c3493fa85505feef9fcd060c",
	        1737
	);
}
static void snarf_hat_1739(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/hpcupsfax",
	        "607a2dba735d4532df85ec70da417111ac487847e3367d47e93e1af540c6e57e309fc3a31231c669b542ae446fdafc7f59509c87498944c4453fb3eb0c88e366",
	        1738
	);
}
static void snarf_hat_1740(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/hpps",
	        "63653b598ed00ac265c7a26ef7347b2a7e6abdf02fc1983a2b82e00b9ac5cb946c187b34d19892fa14743a689179950254c59d342ae31e7590751d13bcceff28",
	        1739
	);
}
static void snarf_hat_1741(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/pstotiff",
	        "f4f065462d3a1a7ec089186dff4e6e937b06d5c09fdfff2317021eeaad77fd8fb38fdbe54cd41242212d497f6e19d152ce3c5fffb60c368e939b82bbda0ab4b7",
	        1740
	);
}
static void snarf_hat_1742(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/bannertopdf",
	        "0a12178cf7bb801783532cbc716a6974a4739314a30fbeffe97e27c4546a54d5f1e878a7d26294969c61b492b84ded4e624d1fd0bba6ceeaa163ad59205a24f3",
	        1741
	);
}
static void snarf_hat_1743(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/brftoembosser",
	        "a45c42bb16ff43b583349d6e53eded7478f7ccefa72bfa1be106fa85d9a97f38c4c375364bf2f6651dd756a720d3b86739da2a6b1056cdb065fddaa558a7be08",
	        1742
	);
}
static void snarf_hat_1744(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/brftopagedbrf",
	        "948caa386376f9957cab8f96df24873b16867f28bd0af22d9ac229edff87ad1d0b407c1d0144b357e82ecac4d21355e4e45b2a0ca7d2dfec658c61fd2a7dc3ef",
	        1743
	);
}
static void snarf_hat_1745(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/commandtoescpx",
	        "5b4e72a4a461b69a8e3cf052602ea697f3b6696830b2f6e011518b23b718b57c7e66cfe66a371c673242a9144718360ceaec895d87031267819ece7bb674f675",
	        1744
	);
}
static void snarf_hat_1746(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/commandtopclx",
	        "3ba7417fbe08cc11fba98ec6b7c9bfadfece01099e1f3cab8279a462c2429bb5fa67595c872ac56ba1aaec17f82df337418d6035e4a78ebc253623f4342a30da",
	        1745
	);
}
static void snarf_hat_1747(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/foomatic-rip",
	        "a28a8a7ae959ac76c604f7f6e8bc7f90f318ad9840a67c4f589654a637ff98298a41594c209b74534e4a54c1f9aa67ac4e009831aa3dd9147ee1bf7a72ef20ca",
	        1746
	);
}
static void snarf_hat_1748(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/gstopdf",
	        "9f0ab2a53b8e052b9eff4ea01121b749633c8121e8166dbf94a0eb68e61d3fb121eb5d4d90ec16f931643217605b7178d5e42bd1be68d428da6561b931c14952",
	        1747
	);
}
static void snarf_hat_1749(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/gstopxl",
	        "4be8329d1aafb0bd4a5816cb125134ec0df0c51f72458e0368e5a0b788c34a463fe75a9d7abe2f08991efd3315141aaf750e5bdeaa94f29ac8bb36278211ac08",
	        1748
	);
}
static void snarf_hat_1750(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/gstoraster",
	        "4d1d238f56d07dac9f01e7dd535e7704a7b190763fe85fb28f211d97a0823f6f6319c19e91f09692a1c468794439ae05c236982c8c40954460ec70d73777132e",
	        1749
	);
}
static void snarf_hat_1751(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imagetobrf",
	        "4682fe64cb7bc8762ec5257b45d2324d388fab6e04e0c31eec17b3db7144f2db74117d5b7d60a556875d015e19fcc4319483bf3063f0e2bc261940156978da64",
	        1750
	);
}
static void snarf_hat_1752(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imagetopdf",
	        "2079b2708e0cedcbdd5833c46c48a2d5ef9d0a8d2c8164d1c4989db0801e4415a87100b45a73412bda3eb8587a045255ea0be3fe5e8596c6c3a6827511542eb2",
	        1751
	);
}
static void snarf_hat_1753(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imagetops",
	        "ea314d5d1aefa047fe18160cc08f762abe2791b122a2e20472b38e54a20e8b8d994a3770944bceaae57e6c0f89ca7b32afff69b0b3bf82e2f5c7d99731243de5",
	        1752
	);
}
static void snarf_hat_1754(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imagetoraster",
	        "bc73a5e072a73656fe002ad6b5caa92e62fcf605559a5b8f997e409c3d93f27a6e404a8f5b0c3cf1806b21c41e2e2129090ac4060ef5abfed96c5b535c900431",
	        1753
	);
}
static void snarf_hat_1755(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imageubrltoindexv3",
	        "1a470db68f032e5c960b15d13b1e2ba521a5275f74663ea241e355a8632d46bfe948a679ad9e5161d9bb907fce677c7059109cf2bf56e6a72ecc018b7de49f31",
	        1754
	);
}
static void snarf_hat_1756(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/imageubrltoindexv4",
	        "b0ece97b61f0f74552b587d45fdeea5d5359bb636b63cac38e714e9d0bb08771ac1f3bb3a4e12d605c41a6d813ab693120f24931314688b44ec7acaaaa01c419",
	        1755
	);
}
static void snarf_hat_1757(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/musicxmltobrf",
	        "a1bfc0c9a574558876239911f9396164dbb963de8cb2b00b6f464b3093d2b9c3e54d9d70c88a12a7d4d759b93df3f568a353fb4a3f8c0121adfb40b8eee3baf8",
	        1756
	);
}
static void snarf_hat_1758(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/pdftopdf",
	        "d2dc124ba5437848ed72e8fc0e9b88e836de617db1d6e2f6572f7d76d7c8bec6bc9692d2dc1c30f6914f25de931b0b3c228458863bf699c6d635ce696f5a5796",
	        1757
	);
}
static void snarf_hat_1759(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/pdftops",
	        "68e5fc1ab9650c0b49c81b04ae939f30d3419776d50b10d6e1a18177eefbbc7c7e7025d137d65e62cafd8e9f6a41401a738e69f0a525d1a3429ffb37de9cbc51",
	        1758
	);
}
static void snarf_hat_1760(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/pdftoraster",
	        "a2db656e45dd7f63d8718e466bade5daf711007d70b085c6c7b3a9bd8d28d2dc730c842a20275800dec86fa2a026fc172020e1514ef179d9808c6ab93930b9bf",
	        1759
	);
}
static void snarf_hat_1761(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertoescpx",
	        "00832bd4fd5ad53eeb2dac812855904321f62edb168347fda9ba86b592160b257d7f66fce023a3eb36a5970a91c8c89961384a5bc2166b1be86f2d7eda0af116",
	        1760
	);
}
static void snarf_hat_1762(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertopclm",
	        "3d7f35b85d414e54206df3257c35ec46915211db769f810da38d7cb43cbf601d7f3aff5f889a4ea2cf21ae174a15e414a5bb14f7d10ec7bceb8de98be6f13304",
	        1761
	);
}
static void snarf_hat_1763(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertopclx",
	        "f02b18353dcd8f035367d19ec1c75377f4c44e8261128bdd5f27f51e7e1c04a861200cadaa49c0f979c85f189cf5b4ba0e7de6f10bec0b464f7da7cb89bf6427",
	        1762
	);
}
static void snarf_hat_1764(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertopdf",
	        "70065ee64c585612b43027bae92b121b0a790d69107865691032a72740d276863999952f904f68c9b17f59105c8f7497bddcce1429f7fa2d7e2e149d9b1994c7",
	        1763
	);
}
static void snarf_hat_1765(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/rastertops",
	        "c4bf4ee7dbe6cc4532d1cceb6f62eef422a9e1181aa221681c721fb2b2d12485bd0b703c051099f41897371e2ffe4a88aed92864604e9a03d5093c36e35e74af",
	        1764
	);
}
static void snarf_hat_1766(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/sys5ippprinter",
	        "3e4f23f81bcd2e77404dcc3eb62d72d7b09845f2056f8c7a07260aad4e03566f8822143fa60477f7a06cac157bf2ef53adcec52ca3bf6feb4d21787aec3ca7f9",
	        1765
	);
}
static void snarf_hat_1767(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/textbrftoindexv3",
	        "58e9c94fed7eb6237f135aa78d1b7f1defc01784a871d10da24c981b12a952091b3c8b4403dcb15e8ba69c45a549c229bc45294540d5324ff1cf199a64885ea9",
	        1766
	);
}
static void snarf_hat_1768(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/texttobrf",
	        "89bb7e047ee7a8d91df1371520aa60145b9229c8723428a6f8b16d9a0a505615b6c865196d78af98d45c60d897ca46de50cecbfd628c95b5aa8a090be5307c8d",
	        1767
	);
}
static void snarf_hat_1769(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/texttopdf",
	        "0711c511e87b5450c8788a862428f98294dcdbc0de8e5aecabcc72ca01d2de6f81ac39a99e85abe294d5c68dea92744daeba3f5dc3977c64f20d6a99db297273",
	        1768
	);
}
static void snarf_hat_1770(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/texttops",
	        "0c3457217a4298f9aed09a6f8fd087f3c3c4f2bfec1d060a2497d32082153cb00d75a58ea5662305a283c6b1cc735a1a0a55193810b3cf70bacc7dbb1987a13a",
	        1769
	);
}
static void snarf_hat_1771(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/texttotext",
	        "49e37e9ec494557e883dcada8b226ce8cbf5b57863dd1806220097438be478a8509ad33a687710e439efbc8d45bdfdb6cbaf734cdb5133a341f35ef978bd0e9a",
	        1770
	);
}
static void snarf_hat_1772(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/vectortobrf",
	        "32125411adc9d2f9adc6a290826ccb633c51fcb956cdb559be066c1b580e10ef672d123bad2fc6af41937073fcc52d932fe2e5fe3c3e40f74926fe2ba55cb2d5",
	        1771
	);
}
static void snarf_hat_1773(void) 
{
	snarf_construct_hat("/usr/lib/cups/filter/vectortopdf",
	        "24082e11502eff4d71ab9afbd259938a64429df377e349bdc61b15ef8c2fac1700d4b070ad240a762f00618d25397c995554d9fc75a2107c1e4c96e37e20a853",
	        1772
	);
}
static void snarf_hat_1774(void) 
{
	snarf_construct_hat("/usr/lib/cups/monitor/bcp",
	        "9fb8258cff331c8ca885030509579139d3a6271c974339374328f47fda2c82de2719bc78c6e186fb2ed0da1c080f86d77283d3c1e5c0136fc633313c4725788b",
	        1773
	);
}
static void snarf_hat_1775(void) 
{
	snarf_construct_hat("/usr/lib/cups/monitor/tbcp",
	        "e2fea15fa1676037351bbceb9f4d02f4a2f9db93fc32931ae6ede01e8262be7a55a3d8b0a491f5e02dc1bbf5cbae1f1eb2a92b8961a513d212dbc0d4063c4595",
	        1774
	);
}
static void snarf_hat_1776(void) 
{
	snarf_construct_hat("/usr/lib/cups/notifier/dbus",
	        "c94bbaba741d79179fb9719548f8789c334e270ea38a5031eb4619a51bfd1896fbaa0259bfefda4530a6fe1d67927e59dd2fb191ab9f6c05a46764b887e13b7c",
	        1775
	);
}
static void snarf_hat_1777(void) 
{
	snarf_construct_hat("/usr/lib/cups/notifier/mailto",
	        "be740d2b108594e0e97743df63455f91d0b42a7dfad85bd27034011d76779f94ff50d22b4d894583ad60923a8ed0105d4ba81c5e28120d6560a98203058dc39d",
	        1776
	);
}
static void snarf_hat_1778(void) 
{
	snarf_construct_hat("/usr/lib/cups/notifier/rss",
	        "883fecb8fe27b2ec480f8a02ecc4a602469307e4b99e42d50ecefda624f5fa94d8cd62a260cdac86c1d5ffce794c327f23826d36fa84fbaa8cdbbf982fce36be",
	        1777
	);
}
static void snarf_hat_1779(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/00bash/module-setup.sh",
	        "bf7c43c54576fe67f03b32143e061ec849a46138eceac757c509e0e8f78ae36f79955624137a6fbe24d2ae7bb6f48a50cab887f467f7faeace811e14e3d6bc88",
	        1778
	);
}
static void snarf_hat_1780(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/00systemd-network-management/module-setup.sh",
	        "4c6ca5d42968de04fd21940ac999675522a121424efbb13cc526f4b8a7446f6cb8d8e9b2c8ab9fc62c13effc6517bb4d9b7204312f6f9027baa5f615fb1f8474",
	        1779
	);
}
static void snarf_hat_1781(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/00systemd/module-setup.sh",
	        "9e109637614e045b846055271f33d02e528b59959f0613db49d113eb87c7fc2b0bb65f4f86c45c03241d5ca8f826261c059441c33f2f03c5c54d150eedc9af1f",
	        1780
	);
}
static void snarf_hat_1782(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01fips/fips-boot.sh",
	        "8ba6d28012e90f5271a3d3a4c8030e1e0e0a2a5a153f13a35cf599107750d5c08d59ef6dbf8033ef2a0a562f0de8cbd65e499bf01d3970539efeca85089927d7",
	        1781
	);
}
static void snarf_hat_1783(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01fips/fips-noboot.sh",
	        "7eb601f363f728671d95b351873be44534a6e5d720ec2a8082fd31d46226e90fc5f5abac0b1e52bb62d8f99b4dd5343d86fd1905ae2347e5e09f03fddf03d3e3",
	        1782
	);
}
static void snarf_hat_1784(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01fips/fips.sh",
	        "ddef387ebbdce2b0a30e013a7d8cc7ec46df5e4ad3ca655ebe14712739f5e624f5d5881c6d45859634ee6696cc98d116e6354ce1599103ea2559bbe0d22c3c91",
	        1783
	);
}
static void snarf_hat_1785(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01fips/module-setup.sh",
	        "625acd810b21a64c9345504fa685678999922c344e26d2557c73bcfa760b466f867af39ef93438105c0598dab2522b5b8d6654348e4756e22e0f4c47abff1b5f",
	        1784
	);
}
static void snarf_hat_1786(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-ac-power/module-setup.sh",
	        "a583c84efc9ab46334ea64ee721328e1b7b5a3311b9e706166ad25bad6ae81477fb0286c4f835bc797be35ea6a7755706c27ffaec6f578279b9dda06d2f5fe6b",
	        1785
	);
}
static void snarf_hat_1787(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-ask-password/module-setup.sh",
	        "cffefeac225ac012d66e2ee8b2ccc7702f39a11ddcbb90f428b61311d70f3338731b49d7995e9fbcf919af15606a3956d4cc36904f3244921251f7b82ee05de9",
	        1786
	);
}
static void snarf_hat_1788(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-coredump/module-setup.sh",
	        "9041b2c169ba1a86c0a0a582c2b0ba7270226e4135c9bdeac4766caa43a1c6aa9e5e0879dde9c1990ebb2ee11bc563e73ddfaecb8f84dbb2f701eb40a02ce275",
	        1787
	);
}
static void snarf_hat_1789(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-hostnamed/module-setup.sh",
	        "30a96fb4f44f9f42b2b337a7e594a205b13f4a5c189e47dd66ec010373840e985e324e3289ed586b234785535381b28ba4dbff3a89312080adbbe9d49ed92799",
	        1788
	);
}
static void snarf_hat_1790(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-initrd/module-setup.sh",
	        "8a22f3ff9c691c97f03109f2da2e5c909a7a556b0d8dbe2f8290fd2617efd3f2154e5301366c40c0c4359ec4e2ba9dbf8de0d731e7c3c0dad741cfc9e9c4ce1a",
	        1789
	);
}
static void snarf_hat_1791(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-journald/module-setup.sh",
	        "6944cad6440002b908911b764999bcfb883ca2f8cdb8c786e1d8a87d0e175a37faa654f1801c3d9dbd61f370f95c091a9413062d222e16ca91a715f11480951e",
	        1790
	);
}
static void snarf_hat_1792(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-ldconfig/module-setup.sh",
	        "39112dd08623d89090997a70e006a648f587f32aa908f3832b17cf47ffb7699818ebc6eb1c4728c1e3fdacfbc81370a78d9ed14acbd69d505d43abb3933b2878",
	        1791
	);
}
static void snarf_hat_1793(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-networkd/module-setup.sh",
	        "d3ba5ed93b670adf17411c9b70f1ea135021b2ab010f7872581fcfb6d80442899bae7b05b9ab46e869cc615e40ed83da6c83e66dc816dc9c7c82a92b701c1009",
	        1792
	);
}
static void snarf_hat_1794(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-repart/module-setup.sh",
	        "445f4ed60c1cac117d8f885262fc73cd7b7eb218534ba257057fcb433070fbaf5a0f56b2d7dbed24b0769637f1c2c3d2872459fc5265965accfb5289158e7a43",
	        1793
	);
}
static void snarf_hat_1795(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-resolved/module-setup.sh",
	        "63f8d6be109d49f9bbe3160bddbb2eea8cfb9b8f071562f49de94d854483d12c526258b4fb5bd5201afef6ab741e5a0776b64fe47aa7bd0b1f6f497f35fde791",
	        1794
	);
}
static void snarf_hat_1796(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-rfkill/module-setup.sh",
	        "26f53eade2266b5267065045409a82daf2c15adf8b81836d3a45754ffe794f2870cb010fe3e9605d648939e00f3de4a7ff0664465a928dc4b7b1fa68a348e390",
	        1795
	);
}
static void snarf_hat_1797(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-sysctl/module-setup.sh",
	        "1d5a793901f14b35bb9b79acb0654858329623f8db3f1251674dab20a0ca37ca60203aaf116801479c3ab92a578f6fda6e9ac8146f2a70d65fd7ae20981c6bf5",
	        1796
	);
}
static void snarf_hat_1798(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-sysext/module-setup.sh",
	        "6384fb87bdfb2e3b3c7e1e5413fe505f9843927ca9c5648b2371a590cecbdd104a4ab0fe2b63b6f9e9dd9f3504a557561a7aa4ec36cb781607b8059cbbff481f",
	        1797
	);
}
static void snarf_hat_1799(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-sysusers/module-setup.sh",
	        "d7e92473e728bb52f9c72974cdbc2f809caef434ba8c33d52b88ebb73200b9ababfb3f80e276d988aab793ecbe814a9f74a0ce9cd6a5fe4fcbd0eedbc1ed4269",
	        1798
	);
}
static void snarf_hat_1800(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-timedated/module-setup.sh",
	        "82773c0ea8b03c21e924ac03c2bcdf8d82a7ba6a033779e9ec5038aa2cfd132d9f7a83edb3bb8e4d29143a02cd49f338554b108ed748e921cd0448c989c47cb2",
	        1799
	);
}
static void snarf_hat_1801(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-timesyncd/module-setup.sh",
	        "a8e39b719757f2360891a10e33d5fac3c3d40ce2c7ed2477a385eee5fa17c405f713d5990a18890ce6a7a09db20b070ba19d2cbc7c30891928cf08eed8afeb3e",
	        1800
	);
}
static void snarf_hat_1802(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-tmpfiles/module-setup.sh",
	        "fdc4e01dbf102066d89a86bdbd47b0e42649366ab7a2707b4a734e67ea11d5eac8035d8cc84525f380190bc5859fe0f6922c1dc22f976abe87691ac34036a9fb",
	        1801
	);
}
static void snarf_hat_1803(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-udevd/module-setup.sh",
	        "b87e43b605693a948d1e278ca7cf2f0d6ddf77f89e7938f3169c456885eea7a70a70e010f6ae32bdf5ef12360151955c4fd1f9b1e06646d6d02dec783ee765f3",
	        1802
	);
}
static void snarf_hat_1804(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/01systemd-veritysetup/module-setup.sh",
	        "0bc8317f304fc636e26393a677e8ef46252c44b319d7137810ed900feb908fc927e4c91847721616c226e14505381757710d43839e9af22c9a44187a0647b535",
	        1803
	);
}
static void snarf_hat_1805(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/03modsign/load-modsign-keys.sh",
	        "47ea9943b320576365521f57973ef7013a714057054ee4f9ff8aca51bc6cd5acee0203a7e67277f0cf742544deaa8f10c678638c6a1ae157597a3f8ebdfaef77",
	        1804
	);
}
static void snarf_hat_1806(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/03modsign/module-setup.sh",
	        "2344e2fa2d939478f514731b925b7966bd634afc076dd3843d9891c5b238ac0295d1bdcee03c77013bb478c156fc0cb460fd2eb9e23c19094dbae6445babe30f",
	        1805
	);
}
static void snarf_hat_1807(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/03rescue/module-setup.sh",
	        "e056f03864271894cb7a6667326d620b205590f73bfc5b6df6e36bb104b1537b956aa93a689127d7b4a486ec87dba7bd24818df0a229e70b3f27e0a0d7c1a642",
	        1806
	);
}
static void snarf_hat_1808(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/04watchdog-modules/module-setup.sh",
	        "aa24460055bc41d897e693e2476d6b238168948459247dfd9c470a5efd5911c6cdb5035ee967dfde48ae94f4ce906a0c82685cf50ad4248aecf8131487269dc2",
	        1807
	);
}
static void snarf_hat_1809(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/04watchdog/module-setup.sh",
	        "3969156c00009470b070b3ce8c4e1426159fd6ac7957b280e505b99edf395ee509a60e77017a29aa164048aab018afa304eff41a6dc1465b8adf23e2e4d33351",
	        1808
	);
}
static void snarf_hat_1810(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/04watchdog/watchdog-stop.sh",
	        "f9a427214cb864977f1c2e95dce0ca3eccc6c40dc0547008a7ec34b10a463d4eb61a673513e88e118efef4ba6aa9263253b9ca7687803c9bc61a3323633cc7ea",
	        1809
	);
}
static void snarf_hat_1811(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/04watchdog/watchdog.sh",
	        "6612ed0ca34040281ada8f8d26f8ff910c6cf74d37efd9d764c5e4d291f3e0c04cbf1f09efffb4d395fda57cf0f3fdbcd3a21869df29dcfac00e9ddf54098fce",
	        1810
	);
}
static void snarf_hat_1812(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/05busybox/module-setup.sh",
	        "e0f56df0ba1ad9039fc0754853e785cc2125c187ee84973ae964f72e50224c7deed57826b8ff86969e611660cd9fdf3b5d1ad4f0e36bea8d4dbe3f07341062b9",
	        1811
	);
}
static void snarf_hat_1813(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/05nss-softokn/module-setup.sh",
	        "e41fd0864c51a43137ebac090617876bd5dad54f257886481bfda05fc9d7ca2a7587c7811de2e3fc70459c24371c70c5842e0fc579c628c38f56051ef006e1c7",
	        1812
	);
}
static void snarf_hat_1814(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/06dbus-broker/module-setup.sh",
	        "6c50a01c9c861e416358a244be8651955fdad9feb782794aa8092d2843f9f98e8f31adaa65e6bbccb91e273ae46f8aff8bd272fd76e71ee21cf752803fb7a5e4",
	        1813
	);
}
static void snarf_hat_1815(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/06dbus-daemon/module-setup.sh",
	        "d6c516ba7444e27756a5d29237793ec1e9e163ec9c73a9e9e1ee68e12a2188909f127a633396a5f8baa4870baaff82998ffa50374da6179dffed52e10bb5c871",
	        1814
	);
}
static void snarf_hat_1816(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/09dbus/module-setup.sh",
	        "19da221f2418877935f5f402b94f895632fa94b5b7665d1b6e20a965fb0671fc1d19ad2a2555f460640fd68e72418d6af0e725fb608ee1055dc2164c464acdfa",
	        1815
	);
}
static void snarf_hat_1817(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/10i18n/console_init.sh",
	        "d01cce00cd2035d37f88c6571438ef1e5bae8d668401557febb8423b233acac7af42fe089f1eb7eff0f4dcf4fb578cd46a3940c2e585b92535e2ec260d396fb4",
	        1816
	);
}
static void snarf_hat_1818(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/10i18n/module-setup.sh",
	        "d1d332b2158e3467770dd744fe595d1d45ddaf7e4da5aaa3f854fb81bef8622a33c05c57a70e494b8ab6291613d0c5090a2fb1a18dabcd63baa1c46cfec8f5ee",
	        1817
	);
}
static void snarf_hat_1819(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/10i18n/parse-i18n.sh",
	        "8b4db22d7086492f8928c4b7de3ee38f8c69ab47573acdfd7188ac3b19827c5395da1865698cf7314615111d53ed80b089edc37dccd7b7dc8e5df4a8f9743501",
	        1818
	);
}
static void snarf_hat_1820(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/30convertfs/convertfs.sh",
	        "df7d7b514f097bcee190ef6cca9cf149a35c7f15a04c0e6cde73bc0d1b6b2a16627c111a0ad9e6f8ad457b20f016be92674b05c18c5abba3027a9b3912d8cb59",
	        1819
	);
}
static void snarf_hat_1821(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/30convertfs/do-convertfs.sh",
	        "08b9a554ed2bd2bb0c3cec39e13ceb31336dcf2a2f1dffaaaa49c48bc61943aa9593e4c9d5375467e0d4bdd0870463b637316c6fd5b51287278b7515ef333e7c",
	        1820
	);
}
static void snarf_hat_1822(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/30convertfs/module-setup.sh",
	        "cab8114cd1a79f069f4eec47fd0a3438d7af500266a811bcd4747166c1353da4511fb7f02900e0f07022aeea9bc0fc72568f4b7cb7723a5bbbe4363641ed3ac8",
	        1821
	);
}
static void snarf_hat_1823(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/dhclient-script.sh",
	        "149e030712d64568006e2bb3ba0fa8aed563df9c6b1938a6fcbf567037da966c9c5b65f78839e703904b7f0e8e4989c48cced615adfda6850619f653ccaa8649",
	        1822
	);
}
static void snarf_hat_1824(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/dhcp-multi.sh",
	        "ff801fe831dce5bcb489321653729d3013980fdfe52e39fa9d51e0b027927ce66b2ff48fbdc1eb40e18daafa8ea3c5d7f4c984a1ce21eb47880cf9afcd218600",
	        1823
	);
}
static void snarf_hat_1825(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/ifup.sh",
	        "322e2d8b97356fb3c3f5e0bed57e4f28e75390533aa99e67a7122ea0b6e4f8b8b77dcd54557cf17e215db421764d88a2036294b40652f95262a878317713953a",
	        1824
	);
}
static void snarf_hat_1826(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/kill-dhclient.sh",
	        "55b96f0e58577168e4d3fc0631ba6b3803d67ec86e8f4b8a9f77f34ab77897fa036405684930f1ae22429d8c71c0bc4dd808b3306e94cb07e41046831b2ca793",
	        1825
	);
}
static void snarf_hat_1827(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/module-setup.sh",
	        "a066de5a9d9568f0fcbf18f727929a72a6795ffded8ea194d2de132a656638aa90e647a0c28912da8117c30c2608628e36a8e9f6e1ac4699339c5c0ff14509ad",
	        1826
	);
}
static void snarf_hat_1828(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/net-genrules.sh",
	        "184f2a874af067e91595709dd80318b029d86779e46e12b2c255fd8c2de54e5639b35eaff323bb261a5d24f88cb125d7af64bb909a76ec88758533a6ec1d7d71",
	        1827
	);
}
static void snarf_hat_1829(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-bond.sh",
	        "076bb8e87a2ab2b45246ce37a3f457de34f52c933d1253ad421cca366c8455c0864bd303b7f009f70971ec27cc9d45d7d1c5041e2bcd85964759512edacbb436",
	        1828
	);
}
static void snarf_hat_1830(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-bridge.sh",
	        "19ad54f57ad33393bd97199f7ac74b5570ddeb2fc2b4643584dccd8686278fc58113ee94697c5862aea70f6c1965f4bf0891b749e7d34959e3aeb91299572e40",
	        1829
	);
}
static void snarf_hat_1831(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-ibft.sh",
	        "e9fdaf19ab20b949a9b2d584cc88671a7289cf1e73658903a7e149a890854b8f92b817a57e7865d5592dad8376bf7dd41c89064d289a1da7d451c99737c78ac1",
	        1830
	);
}
static void snarf_hat_1832(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-ifname.sh",
	        "d83def311379f5b2e4e9a15a6239d74a581a239514f0c01c371bdc0c6164ccbb2d569b6d42e49262c4f8813174f821833042802326d411250487d7dc6185ebb1",
	        1831
	);
}
static void snarf_hat_1833(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-ip-opts.sh",
	        "1cfc5f4b36be71b62379f35218bb28376032ea89051561ae4a817b9a969f661f0670d5157095c5a2874ae8e222eac0a598ef23520cbeba9570ccbfef6537e3ef",
	        1832
	);
}
static void snarf_hat_1834(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-team.sh",
	        "7984cf9d886be71232cdf4adc97ba3b76fc354d914bf89df41cbffef54ff4e2556376c4b0dc1c29321caca50aeab6b94320a44fc391dc628fd7f48e2bd8a2ab1",
	        1833
	);
}
static void snarf_hat_1835(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-legacy/parse-vlan.sh",
	        "c43e95e7167c797ca770731870f02bda2adccb24cef9d1e497cf30a6d62fa6c370e223257e9d24d7d2d7f572177ecf83ae422861b65a5da9fcb2ef2e66edc8fb",
	        1834
	);
}
static void snarf_hat_1836(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-manager/module-setup.sh",
	        "67871a4930596f6816df9c745d92bb9af315fa9469c15df5dd56ae42cbcf7e2508b7e856615f9755876e94afc996a0b5910375415586925d7bab2d58ac7af3a2",
	        1835
	);
}
static void snarf_hat_1837(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-manager/nm-config.sh",
	        "e58335ed810a8e0f4a261b57cf2e5f650a37bb62e94075709a847f921e1a6b287ca2463d38eb40cbaf4809847c0be1dc8fbd29192e8be04048ea7aa57aa84b81",
	        1836
	);
}
static void snarf_hat_1838(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-manager/nm-run.sh",
	        "5e0e45f576ba4a83363450fc1d99858f9d3749fa701338834968916a3d9c6d98bcd31bc76c7b724239d0841a537c99665a4dbf0823cb88bd91fe23f8bf52f647",
	        1837
	);
}
static void snarf_hat_1839(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-wicked/module-setup.sh",
	        "1fb7369df0a86a646e846dd75e7c006cd7223d8526ad73bd1af51bf7b425d81612d5f88d3830a7b078c088434209682b279f11f7b881048ee71f631dd09ab5e3",
	        1838
	);
}
static void snarf_hat_1840(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-wicked/wicked-config.sh",
	        "d797c84f43b2c3d208e895d3977667f9bd5eefd83a70ac602ff2d36e78a2362228dc258ba1f774daa36021647d641a9ef2c7842234e8eb8313d3cd63dc69de47",
	        1839
	);
}
static void snarf_hat_1841(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/35network-wicked/wicked-run.sh",
	        "a95d9a44fdc340ffce9ab075cf8a751ffa1eb2c19ce4c98726fcc9054511c4989fb7bd8b0715b0f1c94a5d94e6f8be40f64b7aaaa0c00aaa3d1f9d38f0fa6573",
	        1840
	);
}
static void snarf_hat_1842(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/40network/dhcp-root.sh",
	        "01b72229c9867e297f44768f2ebf2fa07929a980f46b2c9931cc38b6fb3998b73dd7f246f50a383a892a08e2f6b8a5d5a6074c4918e57c71f91285788b8d4356",
	        1841
	);
}
static void snarf_hat_1843(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/40network/ifname-genrules.sh",
	        "31acd0039a78d5beefb924e8337321bd2b8016c959cf9f71d51d563d4cd1151446ad4671a4cdefb4fd77a20c4e943c2dd5a19857bb7df51e8e0dfaddd0312df9",
	        1842
	);
}
static void snarf_hat_1844(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/40network/module-setup.sh",
	        "b5d53fb75bfe2b8499aa0ef20190ac84a78e9291c4c4d1f76c60a5513eebcc41bf7ca3d32f4ba480580f06fc93b58b1b8f11dc7e3989ab0c03ca06b402bfdf0f",
	        1843
	);
}
static void snarf_hat_1845(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/40network/net-lib.sh",
	        "d75a845dcaf23766ea127277f9feabb043fbdc8ce5bf8af51c5ca75a2221d85a1bd4cf3967205a65d1d41fa6991628da5dacecad757d8656990a07a69e703a89",
	        1844
	);
}
static void snarf_hat_1846(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/40network/netroot.sh",
	        "2e6608d88c1c457a636a8e74e000e90699ebb2b4dcf86a2d31b8c36c3f47e7e761c49f42328bdbe7747a779d4728edacb4f0c6d64e7f1dbccbca4f669bd5019d",
	        1845
	);
}
static void snarf_hat_1847(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/45ifcfg/module-setup.sh",
	        "73598afa2f77bdd2c25282517ac9edac5f5c79e082ad788b7f574aac6a1a5760721f1bf3bc227eef13d4e3155fc865bf72435dbc908c93b86ae0ec22b9b54b86",
	        1846
	);
}
static void snarf_hat_1848(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/45ifcfg/write-ifcfg.sh",
	        "21c1189591d0484c8f50b75f050c52ef9059207f15fd2d816b4ef13f8c98636074323bdbfc3817bb22a75e1de78332b1f49e37819136504d9a7349b937ffe683",
	        1847
	);
}
static void snarf_hat_1849(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/45url-lib/module-setup.sh",
	        "a51ca82c38dca889c87e26a7099c0ae7f38187125d90aee092bb3bda69011827290b008bce2f6cc0f85bb21fd96378e2370ef523a075be57f24b7df5f7e66a1f",
	        1848
	);
}
static void snarf_hat_1850(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/45url-lib/url-lib.sh",
	        "bfc0ae6e7d904a47f36e240673103bc7616e19cf031630155104c0fedd062a2f354598e8a84238757b477a8f766aef2f2eb5682c8deadaf60dbcdc273fc4490d",
	        1849
	);
}
static void snarf_hat_1851(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50drm/module-setup.sh",
	        "5196c40e1bf9a092dd961ba16e61a8ee8822b774c81a701b62a754c4f35332e5a512a216523ac0c53cac40d3bb170508339bd6b847cfd0b22f422a99b4eb8ba1",
	        1850
	);
}
static void snarf_hat_1852(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50plymouth/module-setup.sh",
	        "a35329eb4e91cab5d96af026ada3ee74397760dde9ee8745c1cb463b571db483dd73cd603f97d82837c27629195d0953aea9b7db1d208adad9c504255fa26c90",
	        1851
	);
}
static void snarf_hat_1853(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50plymouth/plymouth-emergency.sh",
	        "83b0026310c8956d9fddeeb9dc0d11a62704517426594616fa4c3ae377b6fe3c7cf44e3ca3d1389559efe6b373427a58f1d978f997a52aa866e9c3fd7ee1f601",
	        1852
	);
}
static void snarf_hat_1854(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50plymouth/plymouth-newroot.sh",
	        "6786c8893333ae7213ba99c7ebc896d5a6f148b21cf76cec2fa7b0f3ad455a0fb1fd3b7ced9abf8d49a7187290c07d084de511632b7c95bf21731dddd46f52f2",
	        1853
	);
}
static void snarf_hat_1855(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50plymouth/plymouth-populate-initrd.sh",
	        "20356330807e236cbb372e2799b439e6bc5c69c5f5b2d855efabd59cb954a4a8048a3ec70deb3cfbd04efb40c23d2008e51e8a1bcb22f91efd319dcde96bbbf0",
	        1854
	);
}
static void snarf_hat_1856(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/50plymouth/plymouth-pretrigger.sh",
	        "1c85a66ece668fb4ae8520c1af5370184fddd5664b7528257ba597e044d0cc9b0b41b456ee77f9370addb00ff0c036ef2258dcff9d8eae1b5f4921ad6e93f2a8",
	        1855
	);
}
static void snarf_hat_1857(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/62bluetooth/module-setup.sh",
	        "1f179fa6a65fc958e27c0c2fa86df8080181d6010fe901e83c9384e43c74426d97c2f817e680cc536a8f9ca5988be4bf875c92af0b5335345b132b28f14d144a",
	        1856
	);
}
static void snarf_hat_1858(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/80lvmmerge/lvmmerge.sh",
	        "47d2bda82e5960e646acb6de0158ca23e9cde3c907ebaeaf31bea4c332bc5fd37604b5331b22e990fa5d6bef947e71ac319ad335e35255f2e80ddba3f1066ea9",
	        1857
	);
}
static void snarf_hat_1859(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/80lvmmerge/module-setup.sh",
	        "14ef80696834233e4acdf577b445830b7a0311978e175ed8615f0b71dad133ef84677b4337723e6f317b94271b319987f8c35a3141a7b16a7d1f04e43638413a",
	        1858
	);
}
static void snarf_hat_1860(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90bcache/module-setup.sh",
	        "b6f83492e68cfa1f7862acf4dd00841770234f2b936e3d8d372553f0e73d28d89007686163eb52e51e36b2439c89251d907ff95d385739ea3d7ed1d3dc33b064",
	        1859
	);
}
static void snarf_hat_1861(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90btrfs/btrfs_device_ready.sh",
	        "94c6aeef1ff524391eb5f56304b8e888a76ad2a60bb98e1c875ea82904fde31abb5d7c54c48baf33fc1a819fb07b744549ada4c8990dd69e22cc2cba642375f9",
	        1860
	);
}
static void snarf_hat_1862(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90btrfs/btrfs_finished.sh",
	        "f3f4e2799b213f8ef191ef206a6b58e6367bd49dc35bfbf1b77f2a8ffd37bb2c91121a66eacdf715d021c7985836737ed2b884ecd1c3f395fa532a627029bee6",
	        1861
	);
}
static void snarf_hat_1863(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90btrfs/btrfs_timeout.sh",
	        "3b1b9dec6dcfbd447877d90198885d2776963974a590b305358d83bc0208ef37bdd480a1e3b220dd744e57d570d613bb8bde6e33b9816ef9e045d07ad024858d",
	        1862
	);
}
static void snarf_hat_1864(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90btrfs/module-setup.sh",
	        "5e5e7f166bdf844c530a2f42489dc36802d2621a2605cabf28f66437f30dab4c74e795fb6a7d025e8d6b34094dee24d406f27767cc41f1553a84faecc9261da6",
	        1863
	);
}
static void snarf_hat_1865(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/crypt-cleanup.sh",
	        "9e19342c7cc0c7396d8e8a6ad0230b4b3e90bbb0401141380ff825dedbf9bec45c62189ef9101fdefeb4d1b0c6827a6542174a64c65451e38b4ee854423751b9",
	        1864
	);
}
static void snarf_hat_1866(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/crypt-lib.sh",
	        "d1e01ff6220b8f1340cddbb98d366ec39259517b842a4eab82477909ed5c84e37f88ff48f98c22fdd4b042faad539ae98925818454a2fe4d73c7155dafc035ca",
	        1865
	);
}
static void snarf_hat_1867(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/crypt-run-generator.sh",
	        "7c19fdf8d41173efb4071ca52e4c7566dec65b19ffb2cff7e22263b55509a221e4f219e616f9613f5f16e4f241a947646c7d97e33f8350b1331c3c608d1ca2c3",
	        1866
	);
}
static void snarf_hat_1868(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/cryptroot-ask.sh",
	        "f2b7b56957d5471a694b6bb007c54b0e2d7eda040d55389a83d42a8a49d0302f3ff693821e01e9f3a53301b570f98af547e67f3ce5db81e265518927ee18f936",
	        1867
	);
}
static void snarf_hat_1869(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/module-setup.sh",
	        "60fb9d0a7e7245b9a698a14f4035727aaf1ab9c2f9d1b0545f1ea6604ca5a1f7049885bbb0b4642e333ce966022da606a1d136705111e58232a91f9e14a8e7b2",
	        1868
	);
}
static void snarf_hat_1870(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/parse-crypt.sh",
	        "cc0699f164a934e23cde09588fb540f8a603943b40b4f1150d82600a6c41bb9a791527383312999bee73a59279ae47bd01846dd417566a0e9696ddfd812a318e",
	        1869
	);
}
static void snarf_hat_1871(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/parse-keydev.sh",
	        "e572d4879385e6d5e97bf168fc7e87e440b0ab44c81bcd343e352c7416c9d2c5c6b002cb2fb9220e5d72d8a53226cf0984a8166d63d206e5334c04aeaa57d888",
	        1870
	);
}
static void snarf_hat_1872(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90crypt/probe-keydev.sh",
	        "ab6e40a790d67e0707d60176e59b6ece8b3129736ee0635fb572ad3b5a4241a480365ed7db5fe65f3356ee477f09b6e506ee2cc69e77b4262829ecec6a6728e6",
	        1871
	);
}
static void snarf_hat_1873(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dm/dm-pre-udev.sh",
	        "70a55cb25a8b035621907b2705b23a0a05433be04cfe60ccc276f72838981da2eee1b0d1039ed9224ac1aaf1499c975574d7917a1c9d4b61d624e61cdcd9830e",
	        1872
	);
}
static void snarf_hat_1874(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dm/dm-shutdown.sh",
	        "9b5bfbae56c7fb120790839851bbf0c8896fe08a4acf186ed3520751c5f7b86abfd8367924ca64ce8ce08a7acbcdff4053d9fdc778944aa3a462bd67c189d241",
	        1873
	);
}
static void snarf_hat_1875(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dm/module-setup.sh",
	        "1b2b24c8808a4857aea984a6fef9d969e0cc9ff2f40d3d84c13c71143a43bf428e324fef50235c2cb2fd9ef83c3788c5629be00427ec706821985440d0c5bd8e",
	        1874
	);
}
static void snarf_hat_1876(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmraid/dmraid.sh",
	        "dc2dd7bd5f6eded1c1d487e2ff1615f19927522985ed17ec1d6dbaf339a84a22cc3f664b6833cfc94089f0ee4a0a1ea1bceebdf7a9e1c5bd69af08ef5a22dedb",
	        1875
	);
}
static void snarf_hat_1877(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmraid/module-setup.sh",
	        "fec3fdfe2f339b93c3902a8ba8a5cdedfc9f0f2037603b60c6c823f801da1aadc3cb30731b8545602d0c8019951443a66a219d960a7e3072fe4a773528da954b",
	        1876
	);
}
static void snarf_hat_1878(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmraid/parse-dm.sh",
	        "5e63b348de614844f1e8ad172c3bc8ff8d905fa16b6987d4c3e5ddc4ae93bfa664d0dfcf06b77e3be0c9e34b0c4299fef4e2f35687dcd7c15ee290e44792b11e",
	        1877
	);
}
static void snarf_hat_1879(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live-ntfs/module-setup.sh",
	        "1a7bb31a33ad904f17d9a387c89761fe6be3021f15309dd31d7ca0ac27f79d089ac92e9ae757cf023414414d7320b159ed054aa12eed983becef0fd314af20f0",
	        1878
	);
}
static void snarf_hat_1880(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/apply-live-updates.sh",
	        "3d67d1a0a9f055a1bfda2d04955efb10c451683a724709bfae8449551f2c29bf51fea7b9eed3160c4f655ac73f58e871fd6ea4b4320ab48b052ad63e87132347",
	        1879
	);
}
static void snarf_hat_1881(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/dmsquash-generator.sh",
	        "0523f0fcb21bf21c94392bbd6a0c359ab62065199d25901d93d744c82723f7c761142dcc9708d20d0e1e9e720454ba6e36580615e39889d0c0af40744b639465",
	        1880
	);
}
static void snarf_hat_1882(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/dmsquash-live-genrules.sh",
	        "e73cf5c6a0666d1527f45ef86aea865336894ebb7753f567b9ec57b3802b97747928a61397d8725b4f6e1b5131415d920c8246589276ab2a5b3d7a9d3ed8bc25",
	        1881
	);
}
static void snarf_hat_1883(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/dmsquash-live-root.sh",
	        "3af630e4358ef78ab74fdfea3c2b2ba007ea064990444cf517acee97c8c8794f172faf5555afb8e57e19d12bb84186a945e4713fb7a1b8dce4d851c4cb4f1612",
	        1882
	);
}
static void snarf_hat_1884(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/dmsquash-liveiso-genrules.sh",
	        "323ce09b4ca4852064f110ca58ff5659b745c0f4f42a283a45b4101dac0ef747017384281409c68daa1901e359566b9bd3436634a1fcc7353c54bfe6ee4072d8",
	        1883
	);
}
static void snarf_hat_1885(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/iso-scan.sh",
	        "55f74dd6dd3074b6f5ea5372d363206744590c8330a6242bf5547e8f731039023cf5e82db65222a29b8035fe498e3bbee1f94f84f79878ddc2ddc8370f80fabc",
	        1884
	);
}
static void snarf_hat_1886(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/module-setup.sh",
	        "65e37792ce9f6b8544a602ce7eb49231e6b0520b5b67e8fc50698f048400322f2b52c9ca591734bf0381c99dab5dbe9e4c3d91bbffcba8fffe59617217f7496a",
	        1885
	);
}
static void snarf_hat_1887(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/parse-dmsquash-live.sh",
	        "49fd872191d21da2a4e2c40d25842f411ac379a6c0fc3852d5e9a7b2255cc89535606028fea6776756763f603d1308f1eabe5537bf4a16d96f819ea777e0e7cf",
	        1886
	);
}
static void snarf_hat_1888(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90dmsquash-live/parse-iso-scan.sh",
	        "20f5852bcb32267877f18233c13c899a6311de955d8ffc1cf09f3023575e9fe130a7c73188a7aebb716ae2ba9a753f2d9a9f6f7ac3b7e605f3cf24424ea3b327",
	        1887
	);
}
static void snarf_hat_1889(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90kernel-modules-extra/module-setup.sh",
	        "b33d2b2d047597c8a695652c8f7a4b5367df961f6cbbe8356466e9c484de2d23f38eafd833b01ba2e16ab9873859bb39bcfdb05e86eb42591e510987541b345f",
	        1888
	);
}
static void snarf_hat_1890(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90kernel-modules/insmodpost.sh",
	        "b2084eec74016bb1edac98ca78d9ee99255d9d95d3f860d702a929d9651ac4388af4107f44520cff757c153dae774219b8a43a2db271d8fbe8a6e1492bc9922b",
	        1889
	);
}
static void snarf_hat_1891(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90kernel-modules/module-setup.sh",
	        "037f57e4552cb6fd18f40d1881831100f9fd5a7fd918012847f4b847dd9753487d35e1f55985f167d153fb4d354eae55e9045d1d05e0af842085dea1fb9e4d53",
	        1890
	);
}
static void snarf_hat_1892(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90kernel-modules/parse-kernel.sh",
	        "23861c16b5a2b1957c0ae3164a62eca0a7ab6b15fc9c9bf5b910bfa9d162250ff0b94778978c358bd407f88412b81fb10adfb10b22c35e53a87da01aefc05acf",
	        1891
	);
}
static void snarf_hat_1893(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90kernel-network-modules/module-setup.sh",
	        "0cdf1fa336b5bb940fde17f237d5c84e6500ab7bcbccc691acea6880652af6131a76c3af2263266daca33baa892a6a10c640e96ca819fd768e3cbb2627443dfe",
	        1892
	);
}
static void snarf_hat_1894(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90livenet/fetch-liveupdate.sh",
	        "c9ed24fefd94d73a5bda6dfd5918423de8ff5aabe9044c4785f86288ff1607561aaf43f8b20b83d0e499707b6e70a7dee14143facf3e824de6bffcb3d0e10eb3",
	        1893
	);
}
static void snarf_hat_1895(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90livenet/livenet-generator.sh",
	        "5295079e80343d26beebee0813921b507a9774ed60acf83db2b4a94ce037b670076360202e3c0aac89d3e34b466fad9c53313a224e26927bf6f12d3ce14ec6b1",
	        1894
	);
}
static void snarf_hat_1896(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90livenet/livenetroot.sh",
	        "dca2005e92a4f54216cb2c3ffe607f5af739482591766a4f88ba35da9b87bc764c79d22d883f04ad0398ababab9abdd5aa337380bf7c8878ab075e8838743ce1",
	        1895
	);
}
static void snarf_hat_1897(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90livenet/module-setup.sh",
	        "ae5f95dd91ddd168fc610a937d4efe7c7244641317dcc88cf91d63436640bd8cb5ec4f56878d1c7828ba7e8b0dc8aa3c52af2ccc33c1959db462cd2e32367db3",
	        1896
	);
}
static void snarf_hat_1898(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90livenet/parse-livenet.sh",
	        "8605b1076bfc7493877bb163678c5d649f26670fd81b75c99e49df9fa26743fe0118527d1b0e5758b0e5f211543213108aa5a49693d8ee26f3a2bd778c20e603",
	        1897
	);
}
static void snarf_hat_1899(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90lvm/lvm_scan.sh",
	        "9694cdfb6c1cee1a271b9ea01a375d70f89945e9dcc5201bee733584afca6b7d12a0a4557d94bbc998f36048837349fa747ef92c02b3d9f9941ad1b12da4dae0",
	        1898
	);
}
static void snarf_hat_1900(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90lvm/module-setup.sh",
	        "1a786c780392d0b9ce88968d554ca7991279e1d9de5bdbf680781d1b101f0be71f8715c40159be77ad2b3dd2a70c954ff4799717f1146dd01f4e1bc17292a984",
	        1899
	);
}
static void snarf_hat_1901(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90lvm/parse-lvm.sh",
	        "d5f0b807637de5ef3b2832290203302f6211e182490c08137b12a7561a5cb5629c43b83226076ff888fecf0beca0c486104b1058c910b82cc1e607ef29582918",
	        1900
	);
}
static void snarf_hat_1902(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/md-shutdown.sh",
	        "3c9fc09a303ad92458affdc746103e45955a549e5fe5d97fe8d087f5466f1402ca6fe4934efc4bafc313cfc44e4dd7e894e015c39efffc18e6bc03136a78bb46",
	        1901
	);
}
static void snarf_hat_1903(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdmon-pre-shutdown.sh",
	        "34ba7b75801b40083d11fcfeb8584d72cdeb752340d90c82d31ba05e9c5bc79a610c59379db75a8fbae01493c225563fb5e51f05f848f27c0f1eb03fd5491bce",
	        1902
	);
}
static void snarf_hat_1904(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdmon-pre-udev.sh",
	        "cba332335c84ee1c917babd48215921a9a566d11e13d80c712d41b3ab930bc563a11b27ac3bb8c40704d703a716fb0a160cabe6a6f90c69de47eae2fbb5ba57e",
	        1903
	);
}
static void snarf_hat_1905(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdraid-cleanup.sh",
	        "aa84a5af1a9ffe60967c3a8849b3ae7f89d23e61ff07be40f21318fdc81cd5c519416f886c6d339528321b211f9f97e2c43f5396b20a4c722d79a9bf7e4ab4d6",
	        1904
	);
}
static void snarf_hat_1906(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdraid-needshutdown.sh",
	        "93cb60d566a2acc8317a6b03166a2e889b2f8f8dc0d1eeebd616c051b9c999bbc9eb062c6762537d564b82313007ad507fff2f54d5e8ac1fd9c11d5980140072",
	        1905
	);
}
static void snarf_hat_1907(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdraid-waitclean.sh",
	        "db06eec9c68cd51f9ee2c7d3416abcf72621a8d6d2804476c43f7875d0875d5c71700e093b4f470d18026cf46374d5b57118506198166ff0efe9845d1ae92889",
	        1906
	);
}
static void snarf_hat_1908(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/mdraid_start.sh",
	        "0453aaa67cbd69040c80be752cbf1e0c680cf3d646bb0abfac3f0a4e4b1d4349e6c556cc24f76f2a3792a167caff907aa45a9a121d742b9c4b14990cddf2e517",
	        1907
	);
}
static void snarf_hat_1909(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/module-setup.sh",
	        "288a6279248ad2c4d5008cb8d38186a17b8f69fae604cacb6b3583461d8e4fb6a326f765aa42027900581251ddf8836ff2c902613709143ea9908727c66d7cb8",
	        1908
	);
}
static void snarf_hat_1910(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90mdraid/parse-md.sh",
	        "4716e6516d854b8ed7da6f35ec1cfc497edd7eb32a8602f5f074a706f35550eacd88b721bd7e237c20c40263f87173a4655e01cade2767babfe0cb8f30ef7fc4",
	        1909
	);
}
static void snarf_hat_1911(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90multipath/module-setup.sh",
	        "d801a68910ea986cc0f86f71a62316f591d94a2c14f8cc6e6cb0a699661395f8afee1f32cdf5c5732e7d1cb0a8f8275f5f3d5c0dea817529e6b691b20e4752a3",
	        1910
	);
}
static void snarf_hat_1912(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90multipath/multipath-shutdown.sh",
	        "cb492f33160f828797d942aa0d10282ae234e78d65d7169e7d6f5325b282d62d0e57f8069e880e19fcd680b087fe8d2afaa4eeb9f34be1a4448779ef30c9a590",
	        1911
	);
}
static void snarf_hat_1913(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90multipath/multipathd-needshutdown.sh",
	        "2e01285b1cf508c0de85806da5475540b736dde7389cedf0a3c8d73bf14651ab433ffe73a24722b8616fa0afb198af3e2247f5da4b8873c14f627dbcc9d6ddbc",
	        1912
	);
}
static void snarf_hat_1914(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90multipath/multipathd-stop.sh",
	        "2647455a803c9e05574c14dd15960041a285b650fd900f00ad2da578d773e4aacd15398adf21a4ad97624c736652cb77f1a31e3b725f6e58c92d5940806bc789",
	        1913
	);
}
static void snarf_hat_1915(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90multipath/multipathd.sh",
	        "e408474d251678c4a3cf9a76f4041585862d26548597e89745e0f9cd52d991d2a6873d7a2f0a64405e73aef407d64dbd7550bc2fdf6a140b2ffa7cc3d07ea6d2",
	        1914
	);
}
static void snarf_hat_1916(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90nvdimm/module-setup.sh",
	        "03c51fc0c2bddc812415145c8482692bac9c765dbd831bca17d0e1556ab60eabcf29ff1f841706c3228489c963234a293c61a4ce00325a87ce3d8ddade069a9f",
	        1915
	);
}
static void snarf_hat_1917(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90qemu-net/module-setup.sh",
	        "12e127bf811c2b76b3f5d1182a3328b7370e0c9424b6a047064f0a93d4e647cb08c3fbaed5e83cb7dcd2aa9dff591946abc8fbd27ea3b05057e354eb4ac78620",
	        1916
	);
}
static void snarf_hat_1918(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/90qemu/module-setup.sh",
	        "e383c9b58e939361d3f17591c27584c3a00dbfe80eccd33e361f615ec87553b1889ac878a8d4ad00871b31b29eb87e95f6047d87744aa14605ed9581921c48c3",
	        1917
	);
}
static void snarf_hat_1919(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/91crypt-gpg/crypt-gpg-lib.sh",
	        "c44ad8b881f1018c9f07cabe24f402d9ade6ffd44e9dd61d6ddf51f9005017f33b676bf2dd00dbd2993258b27db85fe7d4c40c9a2a77bd89d599fd965f889222",
	        1918
	);
}
static void snarf_hat_1920(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/91crypt-gpg/module-setup.sh",
	        "8be18663de3a406869ff118c378b39ffdc19b42225d03829e9c213e02013bd6669376b184bc7e7065030924ada48c8aae1ae999f62d1d206658f01d8a6662293",
	        1919
	);
}
static void snarf_hat_1921(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/91crypt-loop/crypt-loop-lib.sh",
	        "cf9ad2925521a56c6150d20bc594d36d945022f8077f3cfeb4059d98e0bc34760a36a063ffc169c0dadf2cd3ae3180cb958bcd91d24c9f9ad845c0d42aaad1d6",
	        1920
	);
}
static void snarf_hat_1922(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/91crypt-loop/module-setup.sh",
	        "f32174b3fd83be527fb05bf787255d66f8487bcd48d796fcb930a53472056c399969f209aa190e7f4904a378a425fe70abec2305ee5be39ab9b0af3e9dcbbad3",
	        1921
	);
}
static void snarf_hat_1923(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/91tpm2-tss/module-setup.sh",
	        "80ae1bb8cfe40f2bdcf2beb5a5857d8893529d1f9bf8970c0ab21e79e0dff65921899986705b109a59078516342091d75fbfb20a61d23f280d46e9fbfcf06075",
	        1922
	);
}
static void snarf_hat_1924(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95cifs/cifs-lib.sh",
	        "732c9741a337ccb0097a8f42fd3cc603b956000c0f7beea87bf0208131dd3b7a7db1bf91740413e3c32ff829879019dde3aea701617f9b65c255953aba08539b",
	        1923
	);
}
static void snarf_hat_1925(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95cifs/cifsroot.sh",
	        "c9a049ca31c0b670b3509a8d97bb7f93a1a3084e844400c5ff72c32b644749da5daa12ac5eedd976ea2dee27206d28126e4733a1a6891fec4206df486db0483f",
	        1924
	);
}
static void snarf_hat_1926(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95cifs/module-setup.sh",
	        "b43507eeba5fee4cea257f71654e65d98abeef078ff6e926bd37be683a8304d8d333b7f642027e020f04a0d6f36a2288823c6681f09ab08c664fbd5193cae7e0",
	        1925
	);
}
static void snarf_hat_1927(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95cifs/parse-cifsroot.sh",
	        "0b5485cef72878a3e8cc3cd17d19c5c108facbc8fe62dc553a15674bc1f07038f72c32b3f347fd7f567e204c9d30c45cde51014bf5a8e4670b6e400ba1e6d035",
	        1926
	);
}
static void snarf_hat_1928(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95debug/module-setup.sh",
	        "da06eba72da73629d8f8a4b9e0c0170edae0527e3a9e9fb4080d7bf8ba5f5c6510f55ee2e87512b1de987f9e821530b572d76b0c02ea5a7bf3e4aa36cd202718",
	        1927
	);
}
static void snarf_hat_1929(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe-uefi/module-setup.sh",
	        "cd33d889aa32ad146967979c0206617e5a69f6946ca981982ae7bce01d7c0da372ea17636e2c80bdebd933b22b531873d14dd5c29540ab65ef72e2ef86159b97",
	        1928
	);
}
static void snarf_hat_1930(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe-uefi/parse-uefifcoe.sh",
	        "cb83ec2776a41a36b3792b12521642f5c64508c02863656bc0db947bdc2675570636d77508b451b709cd2b61b875aabf85966526c9c7a357ecf9b4cc7c62cef6",
	        1929
	);
}
static void snarf_hat_1931(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/cleanup-fcoe.sh",
	        "fe064696350d51a2b1839ff917a5c1344b8c19b7620879040600b6cca1a13b4e7f06726ee80daec2ed22fc01c8b3e670b990e5d8c88a883a90def17b93a4a962",
	        1930
	);
}
static void snarf_hat_1932(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/fcoe-edd.sh",
	        "7370541d165f642b04eadd9206ab843196c94c884778b7c8656d5b26731d2cfbd4cffa6b6b4dd70b4e95242b811a4c6a931d8573999a47377859f7c57b7a3a51",
	        1931
	);
}
static void snarf_hat_1933(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/fcoe-up.sh",
	        "79be2a87473ee7b3798dac6e41c61138c046e314ba7b5f30c77085b8fc859a7fbfe2a81377a4dd76dab1374b66012fd3f856e4b0d7b859dbf3a519d2e5b4b161",
	        1932
	);
}
static void snarf_hat_1934(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/lldpad.sh",
	        "04dee6751ad5531087215a53e7314c10128cdee2a3e61cc5d1376e7d2d65a8e4c9b8add9a0c09d022f126a7ba239df13fa49f619b74fc736dc37d50ac0e10ac5",
	        1933
	);
}
static void snarf_hat_1935(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/module-setup.sh",
	        "929cfa35b20135d692cad0d6738ea5b25201c5ea160e6836e5bd21998b1132d178b1cc831e927b119cbc7d59fed0ed038a7fdba4b0e3962f806707a4a3e3cea6",
	        1934
	);
}
static void snarf_hat_1936(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/parse-fcoe.sh",
	        "27d4a02778f1b4849f6d5336aadc719b9e8847ea6c21f394e874aedc6f9140f4cd64523e678a3b3dfe82a902f5039fd546a58288b1cff3c1cbb73a3e52ece1ce",
	        1935
	);
}
static void snarf_hat_1937(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fcoe/stop-fcoe.sh",
	        "e49c887da176597e0b62838523a78fd669d63373efb846fd63fc9ecae98c70b180791b832a0808ebd5176903678bbc047fb05c258206737b544b0ff6812d53f1",
	        1936
	);
}
static void snarf_hat_1938(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fstab-sys/module-setup.sh",
	        "f39c482adfabbae08d06dcf697711d6542dc9f1c7e2982e62e7fc56c6ba0a8cb15c92833780c21baf995c34ea5fe2091d3df157a14945c3cc5d617dc8e7f9164",
	        1937
	);
}
static void snarf_hat_1939(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95fstab-sys/mount-sys.sh",
	        "9898c2185a2da8c8040c1ae33d996f736ba559c9cc0a2a62a8d991826fd92dedde7bbec2e32e04cc6ae0a8f4a8999172bc1bef561b408606a62d03857c11fcdc",
	        1938
	);
}
static void snarf_hat_1940(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95iscsi/cleanup-iscsi.sh",
	        "8150e12bb9800ee945c099ff97b4076ceaef3a8f28eb1b98610a5bca8b53e2780981b9cdcd486bbef3b8cfb2eb825e648ed74af9d0e07cf9458b7d93aaddeda9",
	        1939
	);
}
static void snarf_hat_1941(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95iscsi/iscsiroot.sh",
	        "190accdc4140c34754e2594adcc92320037e0e0158f138f53ae7b6a0efad38777f675c0b8358374eb532e9b8d49590589547060d0b7f21c36fd601027cfc1530",
	        1940
	);
}
static void snarf_hat_1942(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95iscsi/module-setup.sh",
	        "6252b20b1a10cf84e784ee1dd8dbc8616d858622d292a636707ea0b6440fb94efae73eafbcf8866e62676bd3af54af745c65e68d4a653e90ecf5126977ef3a59",
	        1941
	);
}
static void snarf_hat_1943(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95iscsi/mount-lun.sh",
	        "29e3b1332c2eab45930c45ae9f17acd8b3792b3bf0c454f7e755048332b7d9f7bcd1732da3deafe362bc8a950b6d0c50815ddc74c564d8e1cf616e6a9e777d13",
	        1942
	);
}
static void snarf_hat_1944(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95iscsi/parse-iscsiroot.sh",
	        "f33147d9240b1a6e87bfcfa5a09539fe5afe2887a13abf826ec483c2321791727b3fcfd6b53a865bfc58ece66af81d9569f74e5199a9be3c1aac1c72d2274b18",
	        1943
	);
}
static void snarf_hat_1945(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95lunmask/fc_transport_scan_lun.sh",
	        "5f991bffe6c1efb5e63a78aa476ae413ea6e1b907a63dc6a59071ae208e3049ac60ba57eaae4202ebe9ce489aec50bc58e32b57341fdbc93af105f1e1cac8edc",
	        1944
	);
}
static void snarf_hat_1946(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95lunmask/module-setup.sh",
	        "5f0ceb4bbaee90f11ec8f7544a3326451c42ddd9be22a1b82e84c23a793c14ba184c6a2cb82040f3573302c2c580da569272b592fad37bbdb90ee03e723ccb03",
	        1945
	);
}
static void snarf_hat_1947(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95lunmask/parse-lunmask.sh",
	        "9d1c02a2e69f3012aeaa8b9715f177bb947626a251f111ee094d2ca863e24ebce14076193766fa3ade646ef91fdfc5dc5de178cacd2c713cd780a1b84751ba7e",
	        1946
	);
}
static void snarf_hat_1948(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95lunmask/sas_transport_scan_lun.sh",
	        "455c095349c645e5f250d4caf699fde8a36c586966135602ae68c32c66cbb6ba1cb1fe4548cbd63b99dabca228515329129b8d894e2e270408716ff2b0bcd550",
	        1947
	);
}
static void snarf_hat_1949(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nbd/module-setup.sh",
	        "4ee75af19f2e7d8d45fba7333514eb7ec4e8313f82c78ac9c400fd7a503abcbd6ee4457bd0fcb98ebf32885213d9aaab647b72ea30d1fa008e70c267e5b4b2a5",
	        1948
	);
}
static void snarf_hat_1950(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nbd/nbd-generator.sh",
	        "9ce4ed96ab26e2d7236506f6d1c9d6d80ae7774023549fa488c0e5d8d9013833857cda692645bebc759a84f508666563d1db3cdd1d9d187e0ed079218920f2d2",
	        1949
	);
}
static void snarf_hat_1951(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nbd/nbdroot.sh",
	        "4b9c2cc3e2457fdf8467b91e05d7134373ebd9923403a5778991b5219197f0423a29a81f8718bb530368ed51cd9805effa55b666118701beb66a5fe7f191310a",
	        1950
	);
}
static void snarf_hat_1952(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nbd/parse-nbdroot.sh",
	        "361edc468e7dd7d4c2a698c10d5e5b60b950f443fde8b8dfd5fe41e1834d87d357664587a165828f8847e8d89f1657d6d9ca7cf258ca984d613f66bb922426c7",
	        1951
	);
}
static void snarf_hat_1953(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/module-setup.sh",
	        "655eecb17336464b1e426fa35b5d1cbd5a7e8950acc03088fc5e2445ea2fbad80d054c2615d380ea325a945650629e33360c20045c6f6b37a87a6fed29f7f8a8",
	        1952
	);
}
static void snarf_hat_1954(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/nfs-lib.sh",
	        "2c30b98e998815180e1a1f56c76b3f21f6baf83c3658db63ff35c4a6a148e9b369b40857abe102d3d5ec9cc278713dc70c550fe5c6167b542968e75194088443",
	        1953
	);
}
static void snarf_hat_1955(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/nfs-start-rpc.sh",
	        "46ea96dbb9e02ff54c59989fa05264c2f03f0373f4c723646ce508929ae6ba60a65c0c07775877a5d2e74884d95c5bc7459e6d701f681acbbdf31e8fac985661",
	        1954
	);
}
static void snarf_hat_1956(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/nfsroot-cleanup.sh",
	        "feba5b6152f9d874a100ee02d566a595ccd807e965a67e1e038d41e0d29a9626d1af7fb896f47760cb18bd9b2146affebed4616360d8b6f6cd70735f78ccaab8",
	        1955
	);
}
static void snarf_hat_1957(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/nfsroot.sh",
	        "0755e53ec56b55d87e4bb0575f68e9385eb4fa125c22304db145769e0f78f4b7198a8631265f210dd68789d54347737d6f28d5b7d4df55a0a07c4a35805d499b",
	        1956
	);
}
static void snarf_hat_1958(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nfs/parse-nfsroot.sh",
	        "63cd16829043696847d955a062de43097f3a1f70e63560ae90766f74915d750a5dc89823376213707a3fd47b64c7ca5b3eb2296a7a934d4226fb77e3668e56a3",
	        1957
	);
}
static void snarf_hat_1959(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nvmf/module-setup.sh",
	        "158ee01c54a51464f63e1f774ce2c9f31f3a25eb57d56d2fe3171ca0ded2d1f36507d9f979557bb5cd0f555bcd6528c9595563bb479cf628c2c7f346efcb8afc",
	        1958
	);
}
static void snarf_hat_1960(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95nvmf/parse-nvmf-boot-connections.sh",
	        "1ae440ba439bded6288f4334223fd881d06686ea17d41da0f15f36c8281e7018fd02f1b88fa568719b2dcc76c343ad353f9060f16fa87f3c0ed071fda6feb3f5",
	        1959
	);
}
static void snarf_hat_1961(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95resume/module-setup.sh",
	        "e2c4bcd7e6cfde47ebf483beaaef0857607706a68168f8f543663c3c5ff334b11ca9039adffed42f73588eb893542402c2f597524f5e90b47ae0fcd752749492",
	        1960
	);
}
static void snarf_hat_1962(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95resume/parse-resume.sh",
	        "04cbe6f7a49bcd437b3efee13b0a9cd986d48c40ad4d41b8e02933892d661e66e848bb7ab29ac27ce718d0437baecab84337243a996216601b4255da424b33c9",
	        1961
	);
}
static void snarf_hat_1963(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95resume/resume.sh",
	        "7c31ebf3f73dd99c3884e539222273bbd85e06d233bc029b62d9adeb6abe2f019e6a90b9bba8a60a3684f4552359badc024292b50dfcf96ddd9548e13bbb22cb",
	        1962
	);
}
static void snarf_hat_1964(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95rootfs-block/block-genrules.sh",
	        "55276944681c241a4950fe7fce63c65a308bccc69cbdc1b6962660c2244ca6a98b67e175b832b210ab818a340d1651d741ae58c941eb5cec5ac3bfa218e117f1",
	        1963
	);
}
static void snarf_hat_1965(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95rootfs-block/module-setup.sh",
	        "54752202a1ae7b8b14b799443272c0d8174e97a32ac60879ca25bfa60b65f013de2c0297f06cdf0c827936d41d1b04ac59c0ef97690d7bf8ece584e867d85fb6",
	        1964
	);
}
static void snarf_hat_1966(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95rootfs-block/mount-root.sh",
	        "37d59dc2e1b4cc8982d89563489d991a096565fdcdd6740d32eefd58d6adb494870b7cbc278d65dd5a717634a827233623574b72cc78f155c12e44ed34899659",
	        1965
	);
}
static void snarf_hat_1967(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95rootfs-block/parse-block.sh",
	        "1a6126bfb05f79398ca3d04eadb9782819299677b8fa0742a5a7288085eb03563d69131279339605a42c7afb86f304b4f75d52aa015db8a41ef8a0164fc06b66",
	        1966
	);
}
static void snarf_hat_1968(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95rootfs-block/rootfallback.sh",
	        "a8c81fe64e37400871d1694f523bb73a398ed8eedc23c960f3f0d7f113d0bdbc04fdae21b84e49189c041e823c241df1cd0dfcbae0c251deb493461d2205477c",
	        1967
	);
}
static void snarf_hat_1969(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95ssh-client/module-setup.sh",
	        "5ef035f4c219f44aab1124717ba12bca2b5bf0d20c53521d101d42f164026861ff3b4e01d8c49fb2fd394800cadfc748229ef18e44dc2abcf6547ffc365e80f8",
	        1968
	);
}
static void snarf_hat_1970(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95terminfo/module-setup.sh",
	        "d141b5c77cb5e1c9b25980232eec34ab9d4b6960f021c748ccc53ec483a0ce2afa9d1296625959ca00a6409f6d2154835353d330aab64b22c6fcd13e48002ca9",
	        1969
	);
}
static void snarf_hat_1971(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95udev-rules/load-modules.sh",
	        "f81f8e29782cd324fbb2b5a338fcb090f07a90880ff88c767aacafc81fe88f7ad57dd044ac01baa1b3598b6aed4625b13f99cdf6487de6abdc9eb13c77e5d72a",
	        1970
	);
}
static void snarf_hat_1972(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95udev-rules/module-setup.sh",
	        "2c66dba4b98f40aabd9d0824652b4be370b51a032682e1811bb2b8257e89c825d11ec4c0fe47c25fae620553199c41e4fc06140f2eba5092ac9b84d8ff4c3659",
	        1971
	);
}
static void snarf_hat_1973(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95virtfs/module-setup.sh",
	        "b1c2e5359a852a4baf4738648c4546673c0317951945a2ff6a207c9d1eb374ac491a03d74f4de1f2196720b3d7907d7fc8b2590a3a4464a11e1460ff479e3499",
	        1972
	);
}
static void snarf_hat_1974(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95virtfs/mount-virtfs.sh",
	        "33e74dd9359d63e8c89b4494c4564be2286c43016a68435dd9e3683f351e319103256ef52bd72f9175036f696279dc2baef0640b0405b0ec0c4387f607f54c22",
	        1973
	);
}
static void snarf_hat_1975(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/95virtfs/parse-virtfs.sh",
	        "ab1995416e438bfec62bba49e89a253e820cdd43577a20e800f0bc3fe3c0baa4d9708b6ab8bc8df6aa97de8def057bc2ffe755c627f33988f5b4211b12cc9161",
	        1974
	);
}
static void snarf_hat_1976(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/97biosdevname/module-setup.sh",
	        "36e2370f57864a44f684dfd70a6d5aef9de4eee1bf0d3c3c22e107f0427c075e04209db9dce465f334b46304249b35c264d9e31f8a4426fa9ac1706a6973bd44",
	        1975
	);
}
static void snarf_hat_1977(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/97biosdevname/parse-biosdevname.sh",
	        "701ef427c01ea9fce4964b3389e7551c21a5b037ee2791b638e887ed7a736a03b9fd7d968edc09c10f315ecde8ecf8221578d09c58630689a3080ac446eb85dc",
	        1976
	);
}
static void snarf_hat_1978(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-cmdline-ask.sh",
	        "3a20bc69f74ced6c0d251ba3b8244c0c6d71ff407abe2171c937ae23ad88f1c21f8b4dc92bb3282a8887cfe71e8d021ffe874b734ae3b60781ec76d1469051af",
	        1977
	);
}
static void snarf_hat_1979(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-cmdline.sh",
	        "a75c88e4c77efd29df71b166a7405406a20ad6df26da520345454c316dfd4b74cbbb265d6eb1cc83c4d364977e1335870d15db67841ccaea2745a4bf7f2a6942",
	        1978
	);
}
static void snarf_hat_1980(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-emergency.sh",
	        "8734e2ac401f8e6a2feb1c5f4590a17fb9e8761e239c346096a1c206f1e2c6fb1b7a7cee3d5830991ddc9fd985dadae34d63795e5146215fae618ff40ea53d13",
	        1979
	);
}
static void snarf_hat_1981(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-initqueue.sh",
	        "ad56deb30e2ee425e153b81ef90b6e1e46e9c813d395c7ba85cb3671d6f34237b5732ac24ff8e8825fc9c3f4e84b5c7d45c9925f7af24b292577656267c8894b",
	        1980
	);
}
static void snarf_hat_1982(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-mount.sh",
	        "002cafe9aa8e6cdb3579a5c36a408ca911ecb3246ae364e088d49365347af227c6884245910ce0e13aad7ca163f568af2e9c4b90ab144d7fc33e8341ac01fed6",
	        1981
	);
}
static void snarf_hat_1983(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-pre-mount.sh",
	        "ae71bd75f29773b64dbbe9902755dee241f93f8516e54bdfc5c689f3174d11e96d5d6f8f41bbe675a40c0c3940fe578084bb8a00e0b3470410f445968dc84f92",
	        1982
	);
}
static void snarf_hat_1984(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-pre-pivot.sh",
	        "62616f3f0a29b617605e5ad796b0074e60c21dc98d90e85be6b616b380c366d3140031bfef673b4a0d70f5dd1bc7e99bfce01e3a817557c042dcee7ca7ae2f1e",
	        1983
	);
}
static void snarf_hat_1985(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-pre-trigger.sh",
	        "525ef470fe178560424560818ae6f764a2be5c2ec9710ceb9fb9bba2f38c30d25ab29fa645c705db6f00bace9b6de65e8966fe891c59e85343f2a12a495a6f67",
	        1984
	);
}
static void snarf_hat_1986(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/dracut-pre-udev.sh",
	        "de0a515d47806fc8f8a5200a8d236de4394dd92ea6fa6b8a1b21756445408c7ef6e133b70b0ff7ee52e35da3c81e1d38833767aa7b9a2c56d1feab5b4ebe7bd9",
	        1985
	);
}
static void snarf_hat_1987(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/module-setup.sh",
	        "590dde3d13ca6f1129e2f698abb0d407a77d9a2f85156f74035245038fabfe34e40da42c095b0aed1f9d7ee3e7dde41cb0d346b8ecf41220d2bcffb2dceb3642",
	        1986
	);
}
static void snarf_hat_1988(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98dracut-systemd/rootfs-generator.sh",
	        "eb5b83d61e201ff9b9b19f212d85e7ba1b27087bc89caef72c889328da3784f3520052938b34b3827655fe0f32e0b0322651405d106f0f7eca7cd18f9eab0caa",
	        1987
	);
}
static void snarf_hat_1989(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98ecryptfs/ecryptfs-mount.sh",
	        "8b67dda04764f1334171337c1536663ece43298f3037682ad9266357b4888137ac01c425f8e70bc0e6c7e2e52f8409a44338ed9f4ab71d81506acaced48f86b8",
	        1988
	);
}
static void snarf_hat_1990(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98ecryptfs/module-setup.sh",
	        "cb56170d7d3460e3f9b91e00dbc23145301265b3181c5513245ffa1d7124e9bacdc51b392eb6c57e6a8f0c00b0245d7769e8b5be0f81d4aedc5ace40cfa708b3",
	        1989
	);
}
static void snarf_hat_1991(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98ostree/module-setup.sh",
	        "2770848cadd30a9bd90c59a7690f2a3499b71e9831974e806794cba0d3d6d03445efb840fc4e0dd120398fb29f0f74774c8606daa5b19846dcbe654e88e7752a",
	        1990
	);
}
static void snarf_hat_1992(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98pollcdrom/module-setup.sh",
	        "c9f4dd7b05f7a69c4bbb1ad0187d968f682c3788f33d1956e13e1f33f52fd80cc507327fe77e264aa4c92f8187eb9a906dffa86ffafe69eb7dddaf88c8a6a234",
	        1991
	);
}
static void snarf_hat_1993(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98pollcdrom/pollcdrom.sh",
	        "f2f50cb270266d7dea06afd430076f4ffb23fd21e1a39bd6baa3b85daf13c45b6beecc737189e77781fdeaad4532f4741497c6f9d1de95c78b50d810231e89d9",
	        1992
	);
}
static void snarf_hat_1994(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98selinux/module-setup.sh",
	        "de0d5a94e23599b208aac684b547997c6a3f7ab6b266d03dd74654bba9551c32898cafffd7bb914d3f35bf0622630293943b7a9a5e2ec75df398c27c36bea627",
	        1993
	);
}
static void snarf_hat_1995(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98selinux/selinux-loadpolicy.sh",
	        "5666fb0c1d86d8e978203f63d033ba88b75332a9091db633d3f5ecf7dbe6226b72ac855704a76dcdf9a74cf1ea32d495179d2fb4d786f69d1df135e2141be27a",
	        1994
	);
}
static void snarf_hat_1996(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98syslog/module-setup.sh",
	        "ed449fe2556efc3d466da4364059697715aa0017a1626b9c7c239eae8b1d3b4a85348726fb0c3d5e853fc6ab51b81ab371018293a1c3be6a0ed7a53f0424f911",
	        1995
	);
}
static void snarf_hat_1997(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98syslog/parse-syslog-opts.sh",
	        "fefb3fd633f8800eea31bcf246b99300da964df6aa04bfda561cd6d600c061204565b0862766a7f8f0d3a08dae555294438371b4abb1a612a63ae22d3ddb3f08",
	        1996
	);
}
static void snarf_hat_1998(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98syslog/rsyslogd-start.sh",
	        "2a3f02b49278a87923d68d1e4c966efbee5277ba347750821a9e8392a032a82d1a0d70dd75c65f73fdafdf0279ba32afb23a9ce205a8cbccdc402b31f7454f0f",
	        1997
	);
}
static void snarf_hat_1999(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98syslog/rsyslogd-stop.sh",
	        "c13874a142adcb7e1dcc60d3047940ff87cb932c239e01b713d5c367c0019bd8ea019cb1154b91cb96b8aaba97a5f969a458386c2cf3b0d725467aa1e985c630",
	        1998
	);
}
static void snarf_hat_2000(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98syslog/syslog-cleanup.sh",
	        "18ca61abc19dd045020efd6336a3fe0d44b795b330e8a899f0355692f3ca8ddca70dfc07305249484ddc98a5cecb50b5fad969a811417580f605eee3ec74cbd1",
	        1999
	);
}
static void snarf_hat_2001(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98usrmount/module-setup.sh",
	        "8fbc7ec5ef9e8768a099114975104b765a6c2a98349c5f3ed5c14919c87d30e2e755c199e3e1260aa2525c0309e106b35f95172e62400eb464bbb8eb74d45041",
	        2000
	);
}
static void snarf_hat_2002(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/98usrmount/mount-usr.sh",
	        "01910a34ff9544ba8146eb70c6ef118ce3704bbfb8f38af13845dff6c6743790c2c80a66486aac17a2b1f94fcb34929bdda047c788986c3cc17853eac15f6038",
	        2001
	);
}
static void snarf_hat_2003(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/dracut-dev-lib.sh",
	        "fbc0fc6724fa6bf645434e17ee9dff4e4e188e0f3a076c322746230c8d2fd99395f448bc987632a59aac463dfb9377d05dbc33c5d0575e6074374e3eb8b5936c",
	        2002
	);
}
static void snarf_hat_2004(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/dracut-lib.sh",
	        "1eb77c7e3117e9200ea97d4f7f5117d3c96e5ca335214e3bbb4851d964350485f4d8fd5c011933fd22d0a8b42e343c8ad09488cc8c66832aa2a82e2a456b790a",
	        2003
	);
}
static void snarf_hat_2005(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/init.sh",
	        "04864235190cd65c4cf99d60260512ce01da69dbcbdc6020b4692dcd38445df4b73a62dbd498784b0d8968b02527b54e969d3a8f90c8164365e2e8b3dde9c95d",
	        2004
	);
}
static void snarf_hat_2006(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/initqueue.sh",
	        "23f60be049539c63a5b008f5f6b1572d3176c4d5c61b8cc43cd34d38f2567e7593c07a638c2b618d26868606e8314504a8e03f1a53a3e6ecf04fc8a904f0dddb",
	        2005
	);
}
static void snarf_hat_2007(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/loginit.sh",
	        "eef9b1a8ee72c4094d8575aaba8c7cab58b31f08839615268446dd4b8b9edf3b51c12800bbfe6d8c00d8296264dda12d3946075fe3f3f1463845eaa70ff1e926",
	        2006
	);
}
static void snarf_hat_2008(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/module-setup.sh",
	        "1a729c4c56449452af2da3026d3d27afaa971b9f04cfc842c5feeeaae7c6de91238620d6d9b5767de0fb6fd1fcbd0b0ed6afc303f14b63083a0453a083f69308",
	        2007
	);
}
static void snarf_hat_2009(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/parse-root-opts.sh",
	        "1d5e8560b24662cdcd0561e091e140c05b95da840186e967d909674714b237585202a13985d55871011803c6376d20842493c72df3a4f289d2553f31c3c16b26",
	        2008
	);
}
static void snarf_hat_2010(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99base/rdsosreport.sh",
	        "1dbf433d6b5ea6250e085f2ce22a44eae9f9de24234867a5885e148fbf1899d88f94635dbd807d43e3cd7fcf978aae33d1f666e922867229087a35ef31b36166",
	        2009
	);
}
static void snarf_hat_2011(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99earlykdump/early-kdump.sh",
	        "9a5008df9bed96200468c11fb155798e5bdec368fc8c2257c96a92f095806299b854a1658c319d6062edf1da70efb6913ce6442bf6ad301939f55ac458e7662c",
	        2010
	);
}
static void snarf_hat_2012(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99earlykdump/module-setup.sh",
	        "7b4b571e69bc834a815626ed77e3a8344f1a0282168ab53045438a7a86de8f2a842cc3de285a65a7fa31ee435bba83b0b173a17b5e1233fef6d86b362d5cc4c0",
	        2011
	);
}
static void snarf_hat_2013(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99fs-lib/fs-lib.sh",
	        "6d4ed45554e2a2c665b4d38621956ffca5546aebd797a0bf28250c0a38a667512d93eb7f37262c2e28c80d9682a645626862c1661ee45e4beb88253d6b8cdeec",
	        2012
	);
}
static void snarf_hat_2014(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99fs-lib/module-setup.sh",
	        "e7c94a357942f26f8e2d26750ce576ab21262052f2d50feaf6d9a021a250c73eacf1b32c477d63ddf36a21c9ed5932eed2b2697da286d3317da983eeef19c437",
	        2013
	);
}
static void snarf_hat_2015(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99img-lib/img-lib.sh",
	        "641a6408ce223f9fbe761ab81209624ef122b9fca06398d8761b5baf4b38d360d5220f4b968a10bbae3ddadb1aefc16c5e1b4a00ac71ce280fe8eb00700fa919",
	        2014
	);
}
static void snarf_hat_2016(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99img-lib/module-setup.sh",
	        "0dee49e140ca9965923fbe7ecc90142dd3217279fdc3e370f4d077306fab00e4690c4c165b24da2b5802cbb61aa21442ed75d6ba2c78cc27c29e888ff8a91f35",
	        2015
	);
}
static void snarf_hat_2017(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99kdumpbase/kdump-error-handler.sh",
	        "a9153bb4a2238152289abb2f960a0e9bb08b7c3c2dcc9e76b08179f410e5b5c0a7c695217c6f3a682e0d891c9359feeeffa80a184162c3f152d6e80e1817797a",
	        2016
	);
}
static void snarf_hat_2018(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99kdumpbase/kdump.sh",
	        "5cbd5628d06bbfe8a610824bdca0d7dedbc8b33d37b30c6e460ff3a1a9b1e3e789460723377e8588f1c3d3aede943acd995c49e631cff59fe9a61ca36ba99608",
	        2017
	);
}
static void snarf_hat_2019(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99kdumpbase/module-setup.sh",
	        "745ee5e57da79f8b5647619df1395e7f6c7eb67f150bc8d9f37fd72efc15018861f42e3ce3d856f96b11c0b7743689da773f3c5356e22325196e57ba19744c7f",
	        2018
	);
}
static void snarf_hat_2020(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99memstrack/memstrack-report.sh",
	        "7a886225ee1e7a2993c0e3b0d04b43e2eec75428040981b540ce311d56600240b24bf3d1dfaa6d80dcdb7c2eedbca5c37b4ae22270f3b60b139d6a7555bf2c12",
	        2019
	);
}
static void snarf_hat_2021(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99memstrack/memstrack-start.sh",
	        "07a158662b98498e627f8485aa1a2318c39def7cb0edf1daa48fc2ca4043afadb39d258ef8a42ba3895ba84e14664c25162bd8390abc3ab8887167820e0bd1dc",
	        2020
	);
}
static void snarf_hat_2022(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99memstrack/module-setup.sh",
	        "2dd4bb34c0db823ce884090f0db338f8aee9a03e951182fbab5cda96e37c1dcb0a9949cc2517f757258bb2207117103207dba7eb4172d4d8ea467275e672e127",
	        2021
	);
}
static void snarf_hat_2023(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99shutdown/module-setup.sh",
	        "b2fbe0fe99f4aa7c96c95e513f8fe4af1e60f18e3ce66008978c3c87569a0a4a94344294a85c3e68a4456c55a979042b18bde9725d9182d5d077bae8ef83b27c",
	        2022
	);
}
static void snarf_hat_2024(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99shutdown/shutdown.sh",
	        "3fd78329be9db1bf7dcdc74f589182bcbd6a5c098391a65ae05103b586e7a7b8dbdbd32301c0278c814d19a73d687c7c7d19f90174d8ae92a50a850d5c372185",
	        2023
	);
}
static void snarf_hat_2025(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99squash/init-squash.sh",
	        "cb5049fbb087cdbe2c92babc61634204bb89a7da979a6ba7e456cc3679d09df3881422a71113e85a07da61369fd4369c46cd32d252398f4dc21ba7022de668d1",
	        2024
	);
}
static void snarf_hat_2026(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99uefi-lib/module-setup.sh",
	        "7913b2701e8ac385aeae30304ea642da0199a4644d79948f49229d79b90ecd49d5a0692e18ed73512aae4a796edf364fd2d23a9ecb22d649bb83e251293c00a9",
	        2025
	);
}
static void snarf_hat_2027(void) 
{
	snarf_construct_hat("/usr/lib/dracut/modules.d/99uefi-lib/uefi-lib.sh",
	        "64d79c4328b7c55b16e065f6007baa664615b84573dd390151c4857da9ca1b9850a8f80f5ad7451f54cf50eeb4f98d58a4f99e4040308115de8e92d89fe41166",
	        2026
	);
}
static void snarf_hat_2028(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-functions.sh",
	        "0df51d6fe2251a43e65cce5dc8d9dacd1f1dd56170aae5ece961f7473979d9db0340e9cca241d04553de7778a0c97cc6a38088a619c10a1d7fd1f62309feac1e",
	        2027
	);
}
static void snarf_hat_2029(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-init.sh",
	        "fd0292174fdb018b780ac7c70d65f5943cea8140d4f4f10131e3ef4ac2c116db000d36d4164eff51b4178371ff2e78787c54e791b32196b03ea3181c62a0ab20",
	        2028
	);
}
static void snarf_hat_2030(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-initramfs-restore",
	        "3611dd2bd985a19a550432c85ad2dfad52d102158447a949136b06f6a9251bae9aee67f280e296a99f23da8a6447cfee20763f68aacc48f2857ab39a75e0a6ca",
	        2029
	);
}
static void snarf_hat_2031(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-install",
	        "380873356494f2ccad8e47873f56fec22f85c2b831b07c5c8bfc8bea440b26bf000aea69490a933358ca1723a7f1430ae020e5cc349b206fc4e25e11a608546d",
	        2030
	);
}
static void snarf_hat_2032(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-logger.sh",
	        "1aa1d5b6ba21a90d0384951182fa340134551c400a3a28fe57ced1600b52a838728170f9cebf08a304526c2b27422d958fce19bf6a60aa0f1ebf44f9b7912126",
	        2031
	);
}
static void snarf_hat_2033(void) 
{
	snarf_construct_hat("/usr/lib/dracut/dracut-util",
	        "409cd5c6f06f968d41481fa68824abcc0e24175a6376bf0a2c3b2461ac172b8771cc7193c0c0669e072357bd4ecced56b64be0ee6c0facb2422394cc13469ade",
	        2032
	);
}
static void snarf_hat_2034(void) 
{
	snarf_construct_hat("/usr/lib/dracut/skipcpio",
	        "eabb5c251c330c8b17e64193b6e9b6c833eb28f25e41654913f6d70c9a8891b718c2df8f5853fb61beb69712855812f077bfc41a9a1bce2a93862d8909a59311",
	        2033
	);
}
static void snarf_hat_2035(void) 
{
	snarf_construct_hat("/usr/lib/fedora-third-party/fedora-third-party-opt-out",
	        "350fb9241d04a8e67fa948664634b9a351bcf8d386e64d6021a87e34bd2e1b14f7bdb66eafd762b14e9fa6491276c3bf5940bbadb68a81bc4a3c243d33cf812d",
	        2034
	);
}
static void snarf_hat_2036(void) 
{
	snarf_construct_hat("/usr/lib/grub/i386-pc/kernel.exec",
	        "ff42cac005ff5af652f8741398a8cde26209769b991486b6f87bdacdfeb7e8300045142d8e975197652678422261551fefb03f6f100f8a226d26bebfd056bce4",
	        2035
	);
}
static void snarf_hat_2037(void) 
{
	snarf_construct_hat("/usr/lib/grub/i386-pc/lnxboot.image",
	        "b0acdd575d0b7699c40e7e5a538d03898955db988a9d755c4253b64e9b7bd9429a617fb4f91118722d5ed0d757e3d5baceef36afed5adfb8685536786a4ae7a7",
	        2036
	);
}
static void snarf_hat_2038(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/lib/jexec",
	        "3c1b60fbf8764b61d2f0340fc70329416cade9838738e1896c9755fed6bca5acd4d36654138f26c39aef661be7c8a3dffaeae314278b9615a412ac8f8148b6a9",
	        2037
	);
}
static void snarf_hat_2039(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/lib/jspawnhelper",
	        "3b57e824dc0c56e1ca47055d11d3768671ad275031b506b9f870ad0673d58d6d8718949daf8346f890b5b8f9fef9cbcde98e26e5b66529c55c981623856c4351",
	        2038
	);
}
static void snarf_hat_2040(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/alt-java",
	        "b46ca5f7cac17346f78655d7b96e0615b101795024bbd71bb5d38c9a0d5efe895005dab40316c5d35bccc77cf4c41d5fa3c81ba3e5346087f4f4472d6a9ce60e",
	        2039
	);
}
static void snarf_hat_2041(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/java",
	        "2cda5f051a0930bba97121ea6144466a03de3413ec6e2e7d2e7e626a75001c5ddb4f4419176242a4009d39b77249f336b2eac381d531545367a40cd162e66e82",
	        2040
	);
}
static void snarf_hat_2042(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/jjs",
	        "596402bd733708accfa28a03f55c3fc3809342a094a5fd33b5c072b11fe19e804562b0f165dbf4e30ed478539a6b361b43df9c84f913e786e3018dc431111d94",
	        2041
	);
}
static void snarf_hat_2043(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/keytool",
	        "cfeb6a0c566ca133e03da8ab4937bbef8d8ec098a0bcd31e5215c1f85dd2aa36a53dba4cc63041e332c8c4e114f5372a1556045b02634acae97b770f2b7ebdb8",
	        2042
	);
}
static void snarf_hat_2044(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/pack200",
	        "6d8f94f4db86705bbfefd1c9dcc632f7d2f849425bd9cc2ac2074d1faf4f060163e39b999bf9c45fd18b458ca5a9f2c62e51828a24aa5f2e4e73ecf26cc8cd0d",
	        2043
	);
}
static void snarf_hat_2045(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/rmid",
	        "158c910741c1219c53c1615bf4e31a9554e40d5564dbdf64982cde6d5f3c678d75b492d1848b8c885360d20d338efbbb719cf661a77d41e8dc40cbeaf193ac9a",
	        2044
	);
}
static void snarf_hat_2046(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/rmiregistry",
	        "95c9ec064f0134e5e93cf17e56899d1d66132f30c3503988412306b9cbfc97c847011adc28d0075e46d75014027a6398131c8383e0583b026685f7e20f02dcd8",
	        2045
	);
}
static void snarf_hat_2047(void) 
{
	snarf_construct_hat("/usr/lib/jvm/java-11-openjdk-11.0.12.0.7-4.fc35.x86_64/bin/unpack200",
	        "3922e4299cb2172e53c78b53d8afa55d9012c47422779f399dda8bf73a888f7a453fd5fa14a406788266381fd3dc746140a80d346f53f2b6391d83bd7fc7d6ba",
	        2046
	);
}
static void snarf_hat_2048(void) 
{
	snarf_construct_hat("/usr/lib/kdump/kdump-lib.sh",
	        "f9149d89c71cfe33ba7fb449c0e2b3011f1d3ca21a1a3e81999a47104c90d2e9ff46a7f6aa82c7249ae721cd57c995fd95896a464dd3db3d939fc4c9cbf0767a",
	        2047
	);
}
static void snarf_hat_2049(void) 
{
	snarf_construct_hat("/usr/lib/kdump/kdump-logger.sh",
	        "f2adf7e23f7b7d2063b179cef0b91cbe37f9fafea6dd5e59f34c829be6097df2d7cf535536e3bfcc49492707c7b12106d8285fa3e66b325d415e97d6bb4ff8e8",
	        2048
	);
}
static void snarf_hat_2050(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/10-devicetree.install",
	        "0976320c9564736b921d8c7b5e0902cdee08459144cee941ee69e5738629b1ca0eac27a18b1a244ec863e297aa5b2e1b270dbdeba684554bb1a22a6aae96ce54",
	        2049
	);
}
static void snarf_hat_2051(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/60-kdump.install",
	        "2d3c91931ce4aa35b932636c5f24331a062c6cb6a24286d53428f8d780c5b6827d2a772ad2a4680de29906c1ba3b8fc467d0a001f65f8697196d42f4c17d7635",
	        2050
	);
}
static void snarf_hat_2052(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/92-crashkernel.install",
	        "68a29a2a36669e928eb881b0909e47ee56d7f1b8277d73b1ddc4a749162474c494e2d7b893738b9a3d98508a3f9bc02031f18e09a00936705963a21d1ef64224",
	        2051
	);
}
static void snarf_hat_2053(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/95-kernel-hooks.install",
	        "e2e65db55ae51146b9f0dbc81c8cfe0096b52cbe03abbebf5f887c6d79a01a80f265206f445e8435339d852d611a6d6612ae975e5b6da5a13a2290ce65c2c038",
	        2052
	);
}
static void snarf_hat_2054(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/20-grub.install",
	        "4380ed3ac39ce139bae62ec665b50eaee73c08cc4bbf7767490ea64641b8bccd8b22704c42e1be4270a23dfef8ae965c694526e5c62bcc07b2025feb495926d8",
	        2053
	);
}
static void snarf_hat_2055(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/99-grub-mkconfig.install",
	        "ce4f2bc4054902877cbd1e73fa16047d19419b55419f1cd61e404de40c74e9025a72f126f22f78c64d9ada4bf516fd76b7364f12a32ff9f46f3bf869d6f81172",
	        2054
	);
}
static void snarf_hat_2056(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/00-entry-directory.install",
	        "5be3c46fbda488c098288ee26170fd16c13ac48e1ec1b00f1c895818790c94d1b9853a1136ce9f80446abecb3c6d03932f8b8dbd27864ea8a6e212c7c00280b8",
	        2055
	);
}
static void snarf_hat_2057(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/20-grubby.install",
	        "7ab9b7095d54111ad208b81adb28487cc3cdf37084b92dacdeb6f8fba8575d07e809b3e025ed89b102bc825254cde07bcfbc6a9f11113f5b44e51de2d6717a58",
	        2056
	);
}
static void snarf_hat_2058(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/50-depmod.install",
	        "28eb5ce57469d9e57f002bee543eaa2e5e832f5a64107786198be2a57d5e8c6015aff509844aa8dba29ab73ae89d44dc8e1384ca39ee1bd1572aa48067d0a308",
	        2057
	);
}
static void snarf_hat_2059(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/90-loaderentry.install",
	        "6fbb5c4070a4bdc3386690587c4569c941676f24d6dcc5f37cb4f8adff173b0d8dd64e04f47511c1c1d6f3365015367e4f69317e56e7c73e58db3e3d0424f4b1",
	        2058
	);
}
static void snarf_hat_2060(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/50-dracut.install",
	        "b4fb90b3b9cd0af63f4f181c591d22a5717747f8057cb499064e7a299906fbb597a62d0351b37e37d4216640771657411672ee1734aca44a59de7ff751037556",
	        2059
	);
}
static void snarf_hat_2061(void) 
{
	snarf_construct_hat("/usr/lib/kernel/install.d/51-dracut-rescue.install",
	        "ff1a00ca3f4b9a6f47052eb7c216df4b89d1fa9bb558a1f61e3918fad5ab7e92de119cfee057719b3d003be9716dd823605ee72af60a038ae849b54ee15cdc89",
	        2060
	);
}
static void snarf_hat_2062(void) 
{
	snarf_construct_hat("/usr/lib/modules/5.14.0-60.fc35.x86_64/vmlinuz",
	        "911e18306f8a912b4857cceb2e3d9255943f7ef390db032cce62c3121208e67aa926f6f855781d80361b32e9a51649f7bd69dc1c974bded223f9e95630bf12f7",
	        2061
	);
}
static void snarf_hat_2063(void) 
{
	snarf_construct_hat("/usr/lib/modules/5.14.12-300.fc35.x86_64/vmlinuz",
	        "5fc233b4b2f57a48ccadf74766d0211ea536dfd87a4c4588a014c602462d831c544598759122f68b3b53fb281c9c0ce06cb2e07173f19466439878cc17775de6",
	        2062
	);
}
static void snarf_hat_2064(void) 
{
	snarf_construct_hat("/usr/lib/ostree/ostree-prepare-root",
	        "c494b8f93303f4a1a906c2d4a7b3dda1dbd7771ba634f1ff88c5b190152e3e0fab596af71f1e861b8ca7dbdcdf8ad3a364a73d976cf6370357cc1d71577f21fc",
	        2063
	);
}
static void snarf_hat_2065(void) 
{
	snarf_construct_hat("/usr/lib/ostree/ostree-remount",
	        "26393eb348aa07aa663c1307394b1c0b06feff2d04c9dfad51328eb5786ddc32fa533291e008725842f9cb1eac41a2452ab21f6f0c0ee293f286265c170c6827",
	        2064
	);
}
static void snarf_hat_2066(void) 
{
	snarf_construct_hat("/usr/lib/polkit-1/polkit-agent-helper-1",
	        "736f4539af259f94ca80e17637cefb7083ccdc9f3ed3a7b7a42ed5454d61db36813b584db5e564d1421872d13dfdc31ce2c0eb3237cff10db4efd562ce02e3b7",
	        2065
	);
}
static void snarf_hat_2067(void) 
{
	snarf_construct_hat("/usr/lib/polkit-1/polkitd",
	        "5e4118e37fd641ac53c8f996341d355d52ffe0b5cf7f7d24243f4b713bf0fff4831d93e7cbc4f45cb12d8151cb1d988a669adfa8b171d7a84c7f56523f2bec71",
	        2066
	);
}
static void snarf_hat_2068(void) 
{
	snarf_construct_hat("/usr/lib/rpm/postscriptdriver.prov",
	        "9afca9d902c77bc56dc5319af88215b263f0e81f8e8f6afe520611a1857b509496889eadb3e75c0ac579c93af1d419be9a2f72de6742288215a1854b05cfd881",
	        2067
	);
}
static void snarf_hat_2069(void) 
{
	snarf_construct_hat("/usr/lib/rpm/gstreamer1.prov",
	        "6da777da3c3cd084606322e127342c9decf161e18c31ba49f1825c4bae31f4a9f33caa4c5f2eb45e1243d2ec1c56f40e6534878539b0b9b5d79459058da94b37",
	        2068
	);
}
static void snarf_hat_2070(void) 
{
	snarf_construct_hat("/usr/lib/rpm/rpm2cpio.sh",
	        "aaeed690b401462f677a65b143d6a0cdeea880b6413832304f9e916f4b0f470dff8730179c35cddb18647f3bb4813658bf9d9f582ddb0c270c69fcef88d25933",
	        2069
	);
}
static void snarf_hat_2071(void) 
{
	snarf_construct_hat("/usr/lib/rpm/rpmdb_dump",
	        "f59a52eaa240eaab4425ff47b14b224ea2f7ef225b79a75307bfb34c493d217e203193603860e48ace2d835bb2159d8d0c5bd5ad1cc9c4e75da5a3c0ec0938a4",
	        2070
	);
}
static void snarf_hat_2072(void) 
{
	snarf_construct_hat("/usr/lib/rpm/rpmdb_load",
	        "5ee8e1eceb8f9518d0207b4c71b5064891ea6106b9c39923b068ad6f74689eef9788b597371b0d984a2b32e41adee21c84f8e178f4a32046e90dd0eacf206152",
	        2071
	);
}
static void snarf_hat_2073(void) 
{
	snarf_construct_hat("/usr/lib/rpm/tgpg",
	        "ca846c1ce623aea3af7a1daf9d6ee92ec8f73e793be272646ed6822d87e2b74ca76b298e38c7584cbdaa7187b6dff21d4384b03db3b85ed623468ab790144f94",
	        2072
	);
}
static void snarf_hat_2074(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-boot-efi-times",
	        "77085a4bc35ad7973abe9b9c8850b39b231bf0f01b17820f454f29156350c3c2248a105523d2220ca5efb4e56c11e03c156edbcdee88584e2ce80ffdf284d767",
	        2073
	);
}
static void snarf_hat_2075(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-fix-pyc-reproducibility",
	        "e77c3194958376b09b4f56daafd7724dedbeee1bd2a49e303f535be509f17addf8cd2dab5f2c6324b0a2ae0d4a34affbd804709eba17bb440dcdbe332dd1626d",
	        2074
	);
}
static void snarf_hat_2076(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-python-bytecompile",
	        "d8e362ea3ad6d41399531a9c118d2bdfbbba4c290ca883ab121163d600479a67720211d187e6c4fdea425256ef9fe554779966251c1405d251b348e787502f83",
	        2075
	);
}
static void snarf_hat_2077(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-python-hardlink",
	        "327a5ab8c456e191db1f68ef4c7950b3c0ddea123f5ed77e2a99ecd4d8a372830c68ff420f8e981a78a53ef695cd5aeb66fd817fbf51d8b08c24bdf06b7ed5fc",
	        2076
	);
}
static void snarf_hat_2078(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-ldconfig",
	        "c9c2c89dc7a59e885d99cfcf4e11af6a996dabef8ae9e3eee51846eb926a8f2e40cc6aaf9b21a5e542d4542cc14c625c33fe47de893f186cf7b554cc476af822",
	        2077
	);
}
static void snarf_hat_2079(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-llvm-compile-lto-elf",
	        "fca9a65313d4b6b7bb1c4723a149545cc1d4b910a894d1b74912a9406638bfb9f7c5d289a60cbaf9a4a139bf6659339ccbb12fe630b4f8b8790661fe05f02fee",
	        2078
	);
}
static void snarf_hat_2080(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-mangle-shebangs",
	        "56896943a58bb9ce4c3789976fde312a203c333694bfe2651b3339aaebd2e962ed4a8fa35b0d56cf01e9067a434a275793034a9d6875c8d7478a371713e2d4b0",
	        2079
	);
}
static void snarf_hat_2081(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/brp-strip-lto",
	        "5a7f60d726dba0d9c229b27d77931b3fafbfe325f2cc659ade095f19ff5c6910e864fbf7c5e2dbcee959bf84bec1b177c4c9e26df4529c1b2d73b50d002dbff4",
	        2080
	);
}
static void snarf_hat_2082(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/config.guess",
	        "871ae1f28dbf4a5730c163848849ce85de6267bcc336e09bdece3d111290604c50f95b4d58dddee478bb9ee6f0502d8904f70e86208b1fde3bc98c77fe26a630",
	        2081
	);
}
static void snarf_hat_2083(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/config.sub",
	        "fee5f2e889bf27edc00f265ff9c637ddf22d298e70a23b5eab2fb4a604d75a3e4909e544c1c0e72b2e77ac6d38c980083c3741d55fe0aaf43fe9e0d4f800c479",
	        2082
	);
}
static void snarf_hat_2084(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/dist.sh",
	        "82362620e72d6fe829618738477e213402fd2e4dca17a2ce9ee7580006ddf6c054359e56a34aff86870bfe819387e8d49f755330334dc76a8a085d7696b7e9f7",
	        2083
	);
}
static void snarf_hat_2085(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/find-provides",
	        "6ca488a58f718b0e87f632c8a283c71910b9dcd6912621b88993d7a307d2433f56227e120d70f1497a555ec7b2847b5221d25f3565be2f2a583e7e1cf057c66a",
	        2084
	);
}
static void snarf_hat_2086(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/find-requires",
	        "bf40e518caca64c1bec16a504566756d8d9deed2ee006aaf9bb5f926af0fe76848e3d4b9b4a2720a857f9ceb88232c2be846b1a220b2ae1a28fa39b45020740d",
	        2085
	);
}
static void snarf_hat_2087(void) 
{
	snarf_construct_hat("/usr/lib/rpm/redhat/gpgverify",
	        "f01d9a3d7c0b3ea69c523d13908318a6c4abcce7bd2dc2c7e1b6d96627cdc39d492bc0a907cfa3a14506fcf960d72cda8bf2fc92d3d8d7a34630f8360fa4a67d",
	        2086
	);
}
static void snarf_hat_2088(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-compress",
	        "33a98ac161ac5a83d852ef1755af88a69f66ecd8a70c3d27bde131e6f7988d422adf4dce992f0ec260b580e6b157018e0197a98eda9724c8e9947b5bcba29158",
	        2087
	);
}
static void snarf_hat_2089(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-elfperms",
	        "d7c3f48b1827e76b1b98f9856e3b7cf78fbcaeb545a0bf324fe7ac424a3fb67af1df4bf104a07bed3328bc0bd3ab4dbc68ed361ae4b8adf05c68cf520387cf18",
	        2088
	);
}
static void snarf_hat_2090(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-remove-la-files",
	        "8fb63bca4baaeef9d3b644c68f24b73ad2c9aca8cf11aa59b233f9eacffeef43994ad9e3597f8eaf1e4026620271627e0dc60c32f35b773b0f391bbf5dc548db",
	        2089
	);
}
static void snarf_hat_2091(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-strip",
	        "5b27ddaaf2857e2b4ab647d1637ae9bf2316f9887c3432f240e2539c7b4959f6f630b9d2ba6248d0d4a2230a7ee7650320d6441162c754ad5bf94666a5ada8b1",
	        2090
	);
}
static void snarf_hat_2092(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-strip-comment-note",
	        "59a80fe5c881c7c16068fbcb63c70c966e342cb8df025d917dc5db381e0ff16d7f6ae283fb0996eaeeda7524dd12e67aa9f91c1325040b01f3ffbbbf8629ef3c",
	        2091
	);
}
static void snarf_hat_2093(void) 
{
	snarf_construct_hat("/usr/lib/rpm/brp-strip-static-archive",
	        "ed27c91ca0eb3362fae5a25c460072a27db00066a88f9f351e45508e6fae60a050cc4fa9aa82fa8b0016845fad1e723095f9a6ccca7b7c6238f78be2e3883d33",
	        2092
	);
}
static void snarf_hat_2094(void) 
{
	snarf_construct_hat("/usr/lib/rpm/check-buildroot",
	        "1a361be96dd86403975c096f43ae0636cb96f7c0feaf0d6c82bdee29dab6b2fb95be8cd63de4e1d7c932d2dcf122cdebe75bd1d2c70c0a791daa4d931e874c00",
	        2093
	);
}
static void snarf_hat_2095(void) 
{
	snarf_construct_hat("/usr/lib/rpm/check-files",
	        "8eec6bbdf40a631fdc636ac74e790772b773894c5dbc3400e6826d3b60f78eb363e928e3dea643511a247ef18fe3417ae6aae76898f8936fa273fe74ea65c539",
	        2094
	);
}
static void snarf_hat_2096(void) 
{
	snarf_construct_hat("/usr/lib/rpm/check-prereqs",
	        "cfaf5c8443afcc2006fc0a6cccf42eefd71ad5464acffae4ac5729cd3e1783ebd7ce745a91a0e9891efa1fa1e8e5338328579b2716a0d1d2ea28bf711f966228",
	        2095
	);
}
static void snarf_hat_2097(void) 
{
	snarf_construct_hat("/usr/lib/rpm/check-rpaths",
	        "c33cc9abcb84ea2c9adf67a1eef239a4efac940a62d01c8ffc01bf76310e1baffbd68224288c9403ab347e43684a4928ab64874d4988f368b28514aa85f68fa1",
	        2096
	);
}
static void snarf_hat_2098(void) 
{
	snarf_construct_hat("/usr/lib/rpm/check-rpaths-worker",
	        "3343abff68c529227d3d1b9df534af5d70afbe22a0cf939ed66afa335cf7360629e660fc9467cb9d53074b6cf9da59bb374004b7bebb5f32778450c8c1c53c1f",
	        2097
	);
}
static void snarf_hat_2099(void) 
{
	snarf_construct_hat("/usr/lib/rpm/elfdeps",
	        "4696ff11ae1c402ffccf13a2f05f8310a74b6a6f92aa9863d178b3d5c8a3c4ac6b61902ff5d882b3041c4e85756e7e867f53e427657b51469377d660f2a4ea1b",
	        2098
	);
}
static void snarf_hat_2100(void) 
{
	snarf_construct_hat("/usr/lib/rpm/find-lang.sh",
	        "988c0b3a51cd24ce6d447f9a5f5f29b0e7e7dd18f2d5526010c3a8c86fbfb2f6cc319c6c6a88f9b08b93f0ddbfdc2e387efc1388b9bf5df3f07c63d897f4da4d",
	        2099
	);
}
static void snarf_hat_2101(void) 
{
	snarf_construct_hat("/usr/lib/rpm/find-provides",
	        "a60497d1efaf4eec2bc7a86deb809f960bb2921fa517e9a053a7794c403918e1e3fb0b00071fa3f9599e1299a21e9b32402dbadd54a837315f72debc7e08742a",
	        2100
	);
}
static void snarf_hat_2102(void) 
{
	snarf_construct_hat("/usr/lib/rpm/find-requires",
	        "c62106c2ae2dc16611f007438d5a6aa8d7c3198eb4b7463cb6452d2a8923a8f0e69ee21fe8a1b48115a7820672a38cb2516538d2fa06239ca5d4c4fa35624b5d",
	        2101
	);
}
static void snarf_hat_2103(void) 
{
	snarf_construct_hat("/usr/lib/rpm/fontconfig.prov",
	        "074459fb9a7b0dd13181aefc3b3f96eeaa80a90d0012ce21c168fb362cbfb2fc57a33d1e8ca765816da4ae5493bf8d06e9b3de4320ddbdaf0488ea866b89049e",
	        2102
	);
}
static void snarf_hat_2104(void) 
{
	snarf_construct_hat("/usr/lib/rpm/mkinstalldirs",
	        "d19727d7a3f142e8ab6bb9bc7eff8af3dd212a0fa0267f9447ce21c8b832ead3676bae55d4dd19d45515f0e0c4012cf760ab8a063b952f829be9df65fb8203a7",
	        2103
	);
}
static void snarf_hat_2105(void) 
{
	snarf_construct_hat("/usr/lib/rpm/ocamldeps.sh",
	        "d136f4e83efd610a04e2a553bad96c11b96a02aceca0fcc0f81805114bb0a30aa571a37b54527e4d4da9076668db6610b2d2323e54cbaf9f205897dbefccf188",
	        2104
	);
}
static void snarf_hat_2106(void) 
{
	snarf_construct_hat("/usr/lib/rpm/pkgconfigdeps.sh",
	        "19fa8e3f78b5c82614aa9621d0f8bb7e20185ef8aa33e689df066182552832a58a3dc61ee06d292b6c3bad7fa49e26dbb76ffb811bccbb227be98615c3548a69",
	        2105
	);
}
static void snarf_hat_2107(void) 
{
	snarf_construct_hat("/usr/lib/rpm/rpmdeps",
	        "9294e322cdf0a4b5157e2878f7b199f98f01c71d91c4355c81e4031b4f5b2a56a9bd2ca5258738bb447e43f89152e6d76d939cc5843e4a35bb081c5bc1f2cff6",
	        2106
	);
}
static void snarf_hat_2108(void) 
{
	snarf_construct_hat("/usr/lib/rpm/script.req",
	        "15c4afac07fe21aea809b6bf9302cb0c3fa4a5d9495dfb707000c28799addbe944353fa9ce4d523b17722811d00dac11dfdb846b847d48f2992d1fe21dff0ed6",
	        2107
	);
}
static void snarf_hat_2109(void) 
{
	snarf_construct_hat("/usr/lib/rpm/sysusers.generate-pre.sh",
	        "113dc9af9f162bcd9bb0f0a39c0bf366c2d760fb4fb83dac591f2528d016dd807f3031043569b50a0cc83eda1187563c52df4137b8ce58ec2a305c2e4166bab5",
	        2108
	);
}
static void snarf_hat_2110(void) 
{
	snarf_construct_hat("/usr/lib/rpm/sysusers.prov",
	        "cc27dbee1b7953ac7b21f2bbaccee17b66fcbb733ec6e222a5cabe985c44fa90aa054e0199affd9bafd7b9721cb8a8508097d54392ec962d74402045b83732d6",
	        2109
	);
}
static void snarf_hat_2111(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/kdump-dep-generator.sh",
	        "7f57fb92bc04e4f34c8a6842b41cd586baeb331812226650fd19041d873a4418a506bc0166472011d9ac1a9ba49cd5b3bf97353aa8813f2235e4e62cdb5ced89",
	        2110
	);
}
static void snarf_hat_2112(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/lvm2-activation-generator",
	        "c52556641b9b1b2ca07f507c644f7e319852db364c6a34957d6c5893dd340bbbcaf53a5a222e8955f79cbfb6761f8e0068476c3ef9af620e3753aa7b6544f938",
	        2111
	);
}
static void snarf_hat_2113(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/selinux-autorelabel-generator.sh",
	        "72baf3bceb2150fb313019dd8a914297dd590d66c20c53d45f3e305137a035a473baab2ade08eda6ceb4c81193174f765f6267e7d625fdd27e38b4391b2d6192",
	        2112
	);
}
static void snarf_hat_2114(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/zram-generator",
	        "ac9429760c59b6e2489f06116199c50d26c1e03032edfa98ab37284bc965872dce798bee6b237d1a4e3ee20f3cd3bc1588552647e0253826c9c1faa0f313310c",
	        2113
	);
}
static void snarf_hat_2115(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-debug-generator",
	        "d28760bfb13fae9081426b839ae97e9ff15b95f88286a3beebcba1cf8831f45a25c411e8b4210c4e3fa317913528367524da64f328afa7a3677e193dcd30fdf1",
	        2114
	);
}
static void snarf_hat_2116(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-fstab-generator",
	        "cba9690c6bd6636c831343aa15e51212022ce61eb17b056440a8d1581fcb11433f76e2cd665c1ad530634182f1321c077061c716900f49f9a904e60e6039f58c",
	        2115
	);
}
static void snarf_hat_2117(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-getty-generator",
	        "109b5f2e7866a4ef1996a2da9b407f6fa1d747d3a72d44844663b00b7e903e77de0dd3eb87eb0fa6c449c6f60b30c8c520632faeb66c4f132015c9d4fd0ff25a",
	        2116
	);
}
static void snarf_hat_2118(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-rc-local-generator",
	        "6177210b712c7e99ed7c88ff8b608c6633b520883a4691e6f962292445678ceb555f0f8de0ec6eb22afc0089c1699dcbdf3c71606d9365d8b4a5cb0be33c9ec2",
	        2117
	);
}
static void snarf_hat_2119(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-run-generator",
	        "eaaa9cd72de5cd4756664b5dcdac84791434d53cef6fa7019edd576f1b4ed1652864c959dab7d06c4715d69d46835bcd74a3fe00744eed7b7c362549bb6a016f",
	        2118
	);
}
static void snarf_hat_2120(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-system-update-generator",
	        "8d4be1c154ec1169db8a210faca02ce534f8e7540be913cd361580c235879ef45a0083f8518a75876056390d69684288bd008acd8c2f0f35c3677627852393c4",
	        2119
	);
}
static void snarf_hat_2121(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-sysv-generator",
	        "3428b436f90907a2de853d980a37e22bd1abd69e94b2660f732873a4050c3dc05972f4dacecb353615bf611425e45a9778015e897f74c48a35501fbfa172ddc0",
	        2120
	);
}
static void snarf_hat_2122(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
	        "f212984287f6906afc9c5af49a9862475145be2df798151b9f814956692c0c93ecea52432fa1af94703e39681bdde8f6f05b996c62fa8c695c4262926246f2a4",
	        2121
	);
}
static void snarf_hat_2123(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/nfs-server-generator",
	        "b13bc49e5e2866996415a96a973a7b9c265608fd5f65933937745034a280b059232fd5da108cb865297262c98c725a884251feec3da6eea92f069cd591d2b33d",
	        2122
	);
}
static void snarf_hat_2124(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/rpc-pipefs-generator",
	        "83d003c66975f3e9558ccd5a81518036867b095e370293b08711b16a65528b3ec024f65100726f93ba41a4ab016e6e066ef56c9f0854324f25d66a295f64fa73",
	        2123
	);
}
static void snarf_hat_2125(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-bless-boot-generator",
	        "594fdec39b3f39f80e5b4a60263fe80eaa2ea7cebe16bbfed97c4b28c680c0724f36966e1380e63c96732f0c23eda0118004af0f2463f5199b7b554bc4ff9ba8",
	        2124
	);
}
static void snarf_hat_2126(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-cryptsetup-generator",
	        "0dafc97a4a581c6f060a050f17b8700dc01017065228aa03503b9e579a28dfbe3304a3be929c4b936ca2a22b8ac43002a0eb5bfa6594c84ed7ac64cd91b1c84e",
	        2125
	);
}
static void snarf_hat_2127(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-gpt-auto-generator",
	        "c3562221328b407e6c65125b5dfbef23f7bf646bcb3f43909bdab2d1f43f47089e64fd11ebcee487ce9bb26704afcb00c642ee3abd296348145134ffaadb7c40",
	        2126
	);
}
static void snarf_hat_2128(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/systemd-hibernate-resume-generator",
	        "77111bc8a1b0f5e558d4ab9a02437108f81ab1ad7e7bdad5b3d44a408b724726ff586f18f1853b0a6fe3fdb8d01d2bb82564e1505f447d16c1a4028f22f729f3",
	        2127
	);
}
static void snarf_hat_2129(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/ostree-system-generator",
	        "7cd7755fedc6c82e69433d3ea2122fda0a41e7ced223cc0aa09b810edbceb31cbdfefb801a5b6bf9a55a3122f0b35a035c78b1b6688f9ed1f4f24fe9b00d782d",
	        2128
	);
}
static void snarf_hat_2130(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-generators/anaconda-generator",
	        "c6464ed0024c3b32c339f8e3722c71ce9baddeea9fa253069e3a8d32d54d96e0c7c06c1bed9eba31322c007bcd2fea76fa72dcfa589382a220f32abd445acdd4",
	        2129
	);
}
static void snarf_hat_2131(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-shutdown/mdadm.shutdown",
	        "ba47b0d7eb4fa4025c51dd75910706532384161748f5cd511fc995f64159041b1c5783f9291b03d16217543ff52ab6573de439ad8529008eeeee34161a63ed23",
	        2130
	);
}
static void snarf_hat_2132(void) 
{
	snarf_construct_hat("/usr/lib/systemd/system-shutdown/fwupd.shutdown",
	        "c80aa5e4bffc434170cc2ffb2179e81cd9d34bec314a550acc24383c39d0a90254bc53aefbbca0641fb9c4aac9e9e5d37e81b1cc7d9b1ac94c64471be6b52823",
	        2131
	);
}
static void snarf_hat_2133(void) 
{
	snarf_construct_hat("/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator",
	        "265b6c18c9709ca81db864d56238b11f9e61ae2b9033630a6adb6745627b01f7ecc82056cfdc9471d95f895c1266e40f464c8e36737d82a00d81cc86cc071a32",
	        2132
	);
}
static void snarf_hat_2134(void) 
{
	snarf_construct_hat("/usr/lib/systemd/user-environment-generators/60-flatpak",
	        "2dca0c6321b1b498b6a3b57fb8fc5de056943432b20a47e02c3f39fe540c85c49694d820d789a43a0186a06a11f85b471c9a0a8fefd997586713c28c0510b49b",
	        2133
	);
}
static void snarf_hat_2135(void) 
{
	snarf_construct_hat("/usr/lib/systemd/user-generators/systemd-xdg-autostart-generator",
	        "193bce022c42f987fc1d5ee4261cb3855ac308d7008a0080ee7a1da04d546e9cdb173d48e75d0d5d5bbae1bec6ba94b667d41e4f9e5bbc0fcaf462787879c58f",
	        2134
	);
}
static void snarf_hat_2136(void) 
{
	snarf_construct_hat("/usr/lib/systemd/fedora-dmraid-activation",
	        "07df45d5e88cfd41f1e41c9a8719a39191c31c120c6bdfd4f8709cc0f7841928b6d2a4756d5cadf4223ea0b1b3825703480822bade5691ec2c97f600294b6a9a",
	        2135
	);
}
static void snarf_hat_2137(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-networkd",
	        "03b8f9edcfc7d0f09ec394366d54f9e8ddc17f816472f03f98b96a4cf029ee52b0bdc59b9a42bef67bf8eff68c1b4358a00b77fb8cc02b85852d3c51333ff99a",
	        2136
	);
}
static void snarf_hat_2138(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-networkd-wait-online",
	        "5589e9dcae153965d1c5c0d8ae72d8f3f629b2b12d0bc112c1b7f05475c6ab618af76fbb87248a0c51ecbbce97277a44e0d1cd834bfa52dc6c08046bdb670d09",
	        2137
	);
}
static void snarf_hat_2139(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-resolved",
	        "268d53b69c1bc895c6de5ceb00acc8279ec258ac6c398d7417aec0ca151adf763bf8f125bd25192b03c2ea9530ab25edbef25f1151831ed5c0ccdfd6e0744379",
	        2138
	);
}
static void snarf_hat_2140(void) 
{
	snarf_construct_hat("/usr/lib/systemd/purge-nobody-user",
	        "e5302c038259d1a343ec49a3db08d31c3879ec05ee11dafb4227db8af46934d119b5004d80db3c34670b9f3844091a4f35755d400b069b1a011c12ed5fe0401d",
	        2139
	);
}
static void snarf_hat_2141(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd",
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        2140
	);
}
static void snarf_hat_2142(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-ac-power",
	        "643b4ec809be55afd1055570bce38ee89f58df148d216ca48dbb1f9daa19793ca63c27332b29490d4394288f5dc18484cf9e3c782c4285a4fcf204a2d6b9d215",
	        2141
	);
}
static void snarf_hat_2143(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-binfmt",
	        "5b203b3be5ee1cc920ea0ae7c3f875b9fee4ee2908fb3e2436673ab8eea7891cda58337339cd616f54d345fb924911cd6b6a2082adf32bf4e8670b7c20231275",
	        2142
	);
}
static void snarf_hat_2144(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-boot-check-no-failures",
	        "ded4abb27d4f5e74f406b1cba5d8c5bb1020a0cef931a9df3d6a8623fab912ae38a99d913d834c6c23b2060544a73ce97a59bad3f155d32f82fab407d74c39c9",
	        2143
	);
}
static void snarf_hat_2145(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-cgroups-agent",
	        "4d115c6ba06df4517d05449957ae8dfd5f040658322ecec9840dab6c9de27685d00a90a91451d7a4b79953d3fc181c2a1c17d2221e61b8247fa6a7f28b4212af",
	        2144
	);
}
static void snarf_hat_2146(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-coredump",
	        "d7e0640f3098403ddc039d778b88b2209ee4d28c5c76f48ca2b6fc908eba16960f17346737e679ff52da04884d580bc22d36028e8c11ae7f9330487cbc9c0277",
	        2145
	);
}
static void snarf_hat_2147(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-export",
	        "6c69e995d8fd40cd41ff1829e7e058537321475e3946359787ab941c625a629a3ffc3620a0b1141a1aadbaa50ccac672b7ef66e6f1a9ea9569f3f2cef3406491",
	        2146
	);
}
static void snarf_hat_2148(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-homed",
	        "6adb4e27d5667e27b49b188fcf3b325a4d543cf0a02c722fb64b3fab9c0aa338cec4443fd771e85b252d29cf72e0daa0990066acf4c52a86fde006579efe0eb4",
	        2147
	);
}
static void snarf_hat_2149(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-homework",
	        "6d7fa242ac5f56713b23723b85f61481d6470d662a7b9dea1913b979b5701ffa9503f9cf22d22117574eda996c75b2ed1c2300721e5cfb1cc47135ad08e13f7c",
	        2148
	);
}
static void snarf_hat_2150(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-hostnamed",
	        "ba33d204c9716b0052c4394ec6df59e537980dfb80b4227e0b97386dec9141a0e09f6550fe528fc6b7a568efd3d174a6263fe3d7f0917e4628f4625115d0c3ba",
	        2149
	);
}
static void snarf_hat_2151(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-initctl",
	        "c21eeadb5c8188a141fdadd8f4ee256ddf88a19d02414c01a496bf5610aca38767211af5d5ebc21a9a7503276303207e736b9875bc628e3d1bcf553e3a4d667b",
	        2150
	);
}
static void snarf_hat_2152(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-journald",
	        "67076789b802f54ef6be5d9d86a975efd02eb483c25e4dc3385964ee46b9644da85ea3977dc18387b32b6076ab6b1b778fc9c42e60f591e6f83a33ca1209b68b",
	        2151
	);
}
static void snarf_hat_2153(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-localed",
	        "61c40ba719716f86181e81834c11316470c168c7350742947b63d2af589c73fdcc8643b608437cf9c55394d3f3c5f2966166afcd6beac00abb108240b1d85320",
	        2152
	);
}
static void snarf_hat_2154(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-logind",
	        "0884197893a4196335da5d4d04efad268e26a1ac5bf7f61f9b86dd1623f0d7c2eec70ce47f17cc3662666b0bedb739a17cdf6c5c39aaab02f73a28e9f47cb5da",
	        2153
	);
}
static void snarf_hat_2155(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-network-generator",
	        "350fa8f8a177682d0f6d37028f3a2327ff748809ad3fd834d20ddd8e1a15ab6cd7ed14979774fbac22614ae680d6f2890528f523b2ee2063f5d29f389abeaad3",
	        2154
	);
}
static void snarf_hat_2156(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-oomd",
	        "f6d49661ec827d4fb7e2faf924302805344b2da623e2d40175f44797f509387142b0b3c415f559c352f4f1da290c662965518d45ae88599e6bef36da44203229",
	        2155
	);
}
static void snarf_hat_2157(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-portabled",
	        "bcc99baa872adfb7b42c85041f871359bb5243bd7a77ee61510f6a4c36a42fe8dbca139d3adf95f31497af42052f0c5a339233e4f9c210e3c47931dd5f2cec7e",
	        2156
	);
}
static void snarf_hat_2158(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-reply-password",
	        "f53660d38790af7701b3fe48c9f771214042a3df822b1446f2d0d6d2c7c21a0c4d145f74ba4e032e91c6738fb49e177777cac31c123117d1de170879d2b56275",
	        2157
	);
}
static void snarf_hat_2159(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-shutdown",
	        "cba3fffe157f1b370b4edab1e674dec9fc5413e471eedf6f12b2b69fd327e5337e2f7a97647e8fd6b37ffb37fedac400e1075a9dd5863cae454efb0aaf036657",
	        2158
	);
}
static void snarf_hat_2160(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-socket-proxyd",
	        "85a2a4dac08d36a8db6f32457e6d716f9bcd0e8e550242c3e7caed88c02e4a53e8d13084dc7f00bea40ae4be023fe2601073bd653a79fea31acbc2f47f6325da",
	        2159
	);
}
static void snarf_hat_2161(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-sulogin-shell",
	        "910c196c3a92248d612451ad359b17c1506460baa7e440e6ab79ecc16125cfdbe50ef50da9271c434429c3523475e7ea76f79d2a5eb338b8147f7b93f1f78e6c",
	        2160
	);
}
static void snarf_hat_2162(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-sysctl",
	        "058f5e542ee0c57db34544a61aa31e15abdffcfcd7e2fac788794ad8858aba38ad72555647e6178a9c58e99da0b5b3dc4408c87a251bdcbd6079a0918211433b",
	        2161
	);
}
static void snarf_hat_2163(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-time-wait-sync",
	        "03a22e8200dbb2041488c7275a6ec5c5d4bb33a516bead46dba173fe0d4cf710e3033541d94c68dec2eabf0ccdfcd9bfe3d5c98b6d715fe3a403fd936d31bfd3",
	        2162
	);
}
static void snarf_hat_2164(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-timedated",
	        "fc4f78337330d167a9a738ed39b69b7f860ba4fdecda114cba31cbcd74f6bacf0555d7726347be28959c48c8b49f38044b25b1c2c386b903bbcfc084123756fd",
	        2163
	);
}
static void snarf_hat_2165(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-update-done",
	        "afc1a759bff644228e1c1970b2f73b452cb9e19293a0cd641af552fea46b0db514f9fe7267b923c78f3eb3e73502ddce3ad276e23905acd45748afdb9d7cf59b",
	        2164
	);
}
static void snarf_hat_2166(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-update-helper",
	        "d86983b7bc664a4dd5bc08851ea683aa1d44ec8f1e26e483383cead2a8b48f4b38e4269c41acb19c1e8b4c0857a549656f909a8e78efcdaf5b593019a032deea",
	        2165
	);
}
static void snarf_hat_2167(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-update-utmp",
	        "5c569eb8b4b1f77e4c512da1cddeb7e880b2a9176295664ad97df6035d80fecbafc8848e9f42ec6f9163d3aa050a6d5b339e1a5eb51d55465cbeb8ebbb4b1ea6",
	        2166
	);
}
static void snarf_hat_2168(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-user-runtime-dir",
	        "1d76855367142d06ed9ba1dd4104d625c408dd7a7752fb5d966fdd55b6f5025cf0b4639317e83f0dfb9a186bb45c59527ae5fdfd7cb209e8e07b5aecd530ba71",
	        2167
	);
}
static void snarf_hat_2169(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-user-sessions",
	        "8a5c99d69f2ae5316e7495fe5cc0e35e6969ef1084e803f2a8f3ab8384c4bf6ce969c39c19a31d0bd8ab1447c1318987ee005e53d3e5bdfee6bd9b12cf9ef275",
	        2168
	);
}
static void snarf_hat_2170(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-userdbd",
	        "fecd57f30d7346a191a4be05926dc1821678142431a1a1325beaa49e43f2923bc3e72fa06dc553e2dba4297f11cb0142589fa11635dcb94a5fca6c8aa6831a77",
	        2169
	);
}
static void snarf_hat_2171(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-userwork",
	        "059146a4a6bbcad7f81cf88658e57d09bea55544e5f18d07d739d555438e8127c628a4c53d932b4e75b3e1d5750469c315163695520a73ce8b9a2b4c11174122",
	        2170
	);
}
static void snarf_hat_2172(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-veritysetup",
	        "ef0e5d7056a7293d92ae411bb31f6e28ac06418ef5722208c0a6382bd60a7771c973934a677e4476418f0d63e1873297d13bf6734f124b8b26eb6c3a1fa28ba2",
	        2171
	);
}
static void snarf_hat_2173(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-xdg-autostart-condition",
	        "d54589b8d828eb48221cb9a32ddc7d723b51755a1cce39240f19ac1755154d89d9215cc5b6680400382b5b41849de45cb1b9c6049762e68b1d0f919e30972cae",
	        2172
	);
}
static void snarf_hat_2174(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-import",
	        "abf5d2570bc39d32c296d8a9b390c33146b861b2e84297152c089b589b837167cc74b3e03e2a83aaa3313a8469331307f771e3815b6b1e51d78a726b9f0fb5e1",
	        2173
	);
}
static void snarf_hat_2175(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-import-fs",
	        "cbe865eb6dafb353495f3b12874ae99c630a3f6937a16366fcfece2964a317635c171e9ae0d10503aa190e2d4b8a4793250923c204727d666ce3abb8c35f9f36",
	        2174
	);
}
static void snarf_hat_2176(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-importd",
	        "e7c8aabab7e3285a8f3efc4ef59484b43b16b94e6ca6a81abffadb493f2e759de1cd352e0269d4c725f41bc40ac137c4de44fc7867e0395408e010ebc8facc55",
	        2175
	);
}
static void snarf_hat_2177(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-machined",
	        "5c2dd124f22ad6277863121ba6ed5ab591470fab20d4e5612d5b96c8a5386f23164a62691434e34937f7d8602e5f5bc7bad54a8e56229fbb6f82501e48de7af9",
	        2176
	);
}
static void snarf_hat_2178(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-pull",
	        "d88980eaffaabc98408b4993829f12c0c14d7f88fbf8f6239e07c2114d8d58d524798087d6fb501bf44d2ac46598d5b4c4a70570f6b5d1ebeaf022f04eea57f9",
	        2177
	);
}
static void snarf_hat_2179(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-backlight",
	        "fdf0c798ce5838d5e47e110ba6be8b12fa35cfc2fc8acf5cf0be911197f588bcb8c6404ea8b3c79ad86db0649f81e0d72f6a5032a65859d90ec9b2a1ed67c151",
	        2178
	);
}
static void snarf_hat_2180(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-bless-boot",
	        "60c4cf3d395f39a620a3fea039dacaec399f828dc3c3776c80ad1ec68518ddb0d26f0fdff0ea0e589bccaf77073c60b690e0a51027c29d1e2439fefab4b23332",
	        2179
	);
}
static void snarf_hat_2181(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-cryptsetup",
	        "e0ae1d93e08cb433fc031107e5a91a980c234e58d8bca11610ff3599ff152c990afcf10747c85edc6cf4214677998dcf58a60ab857809eff1a0981236d477ff5",
	        2180
	);
}
static void snarf_hat_2182(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-fsck",
	        "7f94a6095df9780245f797123b835713352b288214b40cb938fad004f2fa700a1de61b00af02c2e959dc46497506347c21fcf46a54e4ec6fcf82389bd753054d",
	        2181
	);
}
static void snarf_hat_2183(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-growfs",
	        "ebadaac46b79a7d5a49304ad6d96b9ac4d6624cbb02739e9b1486ed4e8c46350c266d3a2b9dd8df698fdec4a5e36e88b2c550ac75751c023d041176cc1004ef7",
	        2182
	);
}
static void snarf_hat_2184(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-hibernate-resume",
	        "dfee80bdb8c314181fa155f36ac22ec2b79355eb2e9c1eee1fc386671498c545e9dc9b511295b2057e998bcd57de28639272cabd2e35a7f1329e5e732158e2dc",
	        2183
	);
}
static void snarf_hat_2185(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-makefs",
	        "d3b7f822df40bdca2c85a9f2f19b2fd7168fb30a0cdb187618af2bfc250d6167c117109d039b833979e17954a163bedad2960de3b21b3b68a7d741753ac7bc35",
	        2184
	);
}
static void snarf_hat_2186(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-modules-load",
	        "5c0fa5054f06e2641d72d4ac64a56ed7deffa5ba095e1232a14d23f4d29dff801972cba1c71893af326b5983d2948e49181617d941ebe1b15aadaa5cbc3dc6ce",
	        2185
	);
}
static void snarf_hat_2187(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-pstore",
	        "adbef5242d4af3aa234970023d19868828da14bee1654db7c7924d7dcc7291e324efba95b9b140ccfd4d5d490d973df24d1315911840acc130c48c5afb16ab3d",
	        2186
	);
}
static void snarf_hat_2188(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-quotacheck",
	        "3b14412a3c3d8b3818770bb5d0b3c76c0f6e3b51391f13ea42ac670f9248bcbd60bea4f63831f407c25284d789e4d0c3312130e7a95dbb354c577c352875356a",
	        2187
	);
}
static void snarf_hat_2189(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-random-seed",
	        "5a3730050f1cb18255528b457225a1aad8561237778b2ac1820d6e651fc3b91d04dbc1d3990adeada78b2b46329db259bbe97cff714375173a77d1ed7357031c",
	        2188
	);
}
static void snarf_hat_2190(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-remount-fs",
	        "bd3bc6339c8d399c7620aaa94e570ba6a90a1bc999c78cc3e7944b46371260d4fe689906e2b402f39b0b08d034eb74638b518575d6e4c82937bce87ff224a415",
	        2189
	);
}
static void snarf_hat_2191(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-rfkill",
	        "4d94d03a7cc0237ff87f9e0e0b519e5610700cf7eb68296ba4b6eaf359058f0508e9ef57426ae25bd172410e89cfbf2c578b1a3d793507954f1f229a2dfa3f17",
	        2190
	);
}
static void snarf_hat_2192(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-sleep",
	        "470c66bb266245cc4743c67bbfe1a4ccf324b25d73d21c3f128f5764ed8c655065a7d0ac64e0b5f998c5b1c616366c20e754b8cd3ca8aaaaf4ea6b9d5e7ce5c8",
	        2191
	);
}
static void snarf_hat_2193(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-timesyncd",
	        "d41383c457c585503b83cecf3704a4fcfeb4f9b9057f1097519868bc716638f443a699bcd1419386a7a13d54a25c9bf810d2c0e7b6893b403f710e8cb51bca44",
	        2192
	);
}
static void snarf_hat_2194(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-vconsole-setup",
	        "97c183ab876e1b3fdb534363893789f7919e4ff7bdfa0e27807361e187b7f25b0a0f8ff842534331424ec1c954c09ce4cf665bb5c223687ad3e202cbcad8fb28",
	        2193
	);
}
static void snarf_hat_2195(void) 
{
	snarf_construct_hat("/usr/lib/systemd/systemd-volatile-root",
	        "a4ae0e06989b79d443de78b1797183878aef58184ab6bb411300b3f12fd440b77b08bba7ee9035010664febd31bc6bac6ea6d46fc47a40b4d10cbaa45d33b4b1",
	        2194
	);
}
static void snarf_hat_2196(void) 
{
	snarf_construct_hat("/usr/lib/systemd/init2",
	        "affeefc1057dfacf62e4060f63f9325dc7665b51e175389e6538dff449adcd799f70e15f9ddb68524cf1d03f2c643a01315fc0158e2f24dfb3f2aaf093fcc021",
	        2195
	);
}
static void snarf_hat_2197(void) 
{
	snarf_construct_hat("/usr/lib/udev/bcache-params",
	        "c1edb801bd8ba5b8557422fec5683b431b294a8e9712120c58bb82319812a458da9687cce1c3ca1ee2a1b24c0c67f0c6d85575976a75b33478331e901addd4a1",
	        2196
	);
}
static void snarf_hat_2198(void) 
{
	snarf_construct_hat("/usr/lib/udev/bcache-register",
	        "07ced5f5face07de935fd08b94d193615d46dbb1561af61c2721e6a0adbc3d1ad88f18e81412eaadb5cf2fb56b155d827cb25ce81725551006c345d4d63d5358",
	        2197
	);
}
static void snarf_hat_2199(void) 
{
	snarf_construct_hat("/usr/lib/udev/check-ptp-camera",
	        "78908dfaac2e11e0e583d5ecc039e3c1683273a6c3a608f99354fa08db455b15a63ce7946167d38f9ae71efbdcca4e0abd3a0a004d4ccdae40b928e68bdd31f5",
	        2198
	);
}
static void snarf_hat_2200(void) 
{
	snarf_construct_hat("/usr/lib/udev/iphone-set-info",
	        "cd3cea06de326979761f4e7cafc95a9ecf9faea26ff67d1280af340ade98476831ff0b03e1c47bfdb635e61db8aa6e5b2b11bea65d7bf9a9e4b5f7d64ab4f375",
	        2199
	);
}
static void snarf_hat_2201(void) 
{
	snarf_construct_hat("/usr/lib/udev/ipod-set-info",
	        "62fc915e2e905b25641c22e24bba2992c9121a1b58a7675c2e9a77d5c47350caedebef93fe6337f5d1de30c83b7c7f190bd04769dd94d540608fa1a4856d8968",
	        2200
	);
}
static void snarf_hat_2202(void) 
{
	snarf_construct_hat("/usr/lib/udev/kdump-udev-throttler",
	        "8b775d014b923aa483c24316de3846e4f90701e10bb2adfbeaf085344867f2bc26ecd0b50a8d3aa85aaf637f1ae90fcc32d402a2873990bc4db4299e057c9700",
	        2201
	);
}
static void snarf_hat_2203(void) 
{
	snarf_construct_hat("/usr/lib/udev/kpartx_id",
	        "c2c5c029163e4f4a2b115a55681b2820261d5046bbfa8f63018ad16ac2d0eb73a2727cd1d473d7e7be1e8c6d655790cd2f4ce5de876a43985e5ad8fa0a13e38c",
	        2202
	);
}
static void snarf_hat_2204(void) 
{
	snarf_construct_hat("/usr/lib/udev/mtp-probe",
	        "21db80f14b6a9408c10b8ac6ee411d7184443dae6ee7fe7efdefdc3303062f55e97393cd72f3cab7d364e69035b4bc453f918d946d60674b8c6e70106035b006",
	        2203
	);
}
static void snarf_hat_2205(void) 
{
	snarf_construct_hat("/usr/lib/udev/usb_modeswitch",
	        "79a090f3fb031d8a7b8c419bc1294a708d1292be4d91b493cf9e5ed6ce0147be2e4b641402f8c15fabf12750f3ef985620bee234513afe49f219b07be3a316d9",
	        2204
	);
}
static void snarf_hat_2206(void) 
{
	snarf_construct_hat("/usr/lib/udev/rename_device",
	        "7f3716a9910f13c4176e5240771b4cfd387e225b741d1c7269d2687cddddd0199fb45a23aa96cd2008f2a36f0f38e5559ac597d7900ec3cb6cc51bcab72d1af3",
	        2205
	);
}
static void snarf_hat_2207(void) 
{
	snarf_construct_hat("/usr/lib/udev/libinput-device-group",
	        "306c9b6e78f25a0c25db8b3f5c3ada6e515501bb0e17736597106636988e203c988874cfc93e578ce4ac2dc7771da64063a3da6f72f742b93e6e66c04e59cd13",
	        2206
	);
}
static void snarf_hat_2208(void) 
{
	snarf_construct_hat("/usr/lib/udev/libinput-fuzz-extract",
	        "5164b65a71a2ff9b90e51683af3c8b2eca1b56bbb0a00ae11a893e22f3f36bc5cee02cc2421695d7e6fea098c2786a81d64c0ef2effae3fc14db016af12c5125",
	        2207
	);
}
static void snarf_hat_2209(void) 
{
	snarf_construct_hat("/usr/lib/udev/libinput-fuzz-to-zero",
	        "0187aafc77070327c683209ada1fca67285147229c903b1b546077112802886a5bba86566e5127f699cb99d48ab84a189716fa52d98ed0b791d5f904195edda7",
	        2208
	);
}
static void snarf_hat_2210(void) 
{
	snarf_construct_hat("/usr/lib/udev/ata_id",
	        "35ef1626a3d310fe169b11cc55194c72f9cfbfd76d89c01e59a4ddf9c7605bb758f2bbe994ccfaddbdfd5fe0fb887f8dff843ed310131d23f0a2d9aaea49f474",
	        2209
	);
}
static void snarf_hat_2211(void) 
{
	snarf_construct_hat("/usr/lib/udev/cdrom_id",
	        "b0838ae1932a04c9d4906f7793ba9aa7d3738ee1262308c5c414e0ca098babaacd8ef20b0d9aac25ed286d745122fd23dfb45fe1992a19a1739b9b88ca23881f",
	        2210
	);
}
static void snarf_hat_2212(void) 
{
	snarf_construct_hat("/usr/lib/udev/dmi_memory_id",
	        "6bb68a1b2cbad68f0d3f3c26ffe308e5f619a74f9142f7bcff40de1ce7c304b391a25716a75aaf540cc1fc9a2228faea0899d6db33b2cb7a1a941a14d6a3a769",
	        2211
	);
}
static void snarf_hat_2213(void) 
{
	snarf_construct_hat("/usr/lib/udev/fido_id",
	        "865fe3adb89bd98ccd32f1a695561bfce284df22e17cfd52c68d94c54923582986ad3e9ddccdc760e61166d68bd7caecfdfcdfc65265a48f9f84cdcd3ed75bbc",
	        2212
	);
}
static void snarf_hat_2214(void) 
{
	snarf_construct_hat("/usr/lib/udev/mtd_probe",
	        "219bbd471621dbca904d8015018ec5542757fb8fd100c4bbdcbc5ef8bfe6a3ff77930e0afadc85e87ee1e6cdb8a0921b51a0c416d17e1c4c80fdd33c18afa95d",
	        2213
	);
}
static void snarf_hat_2215(void) 
{
	snarf_construct_hat("/usr/lib/udev/scsi_id",
	        "1193d70e966151c1255f981f1557889cae4abb94282c2868b032c3a23d360c4d675857d14f0ad3ab61bfc8c76f6b349ddb8336c768612b8afb7e7a814cdeb9e9",
	        2214
	);
}
static void snarf_hat_2216(void) 
{
	snarf_construct_hat("/usr/lib/udev/v4l_id",
	        "e1f23e5f2409a25caace88623ecfe2822cb3a0efa0fdb36013a53d43003a8c4df68a641466a1eecaa4a9c5fa3d44de3b0beac6005064f31c05c19197f9d3d0de",
	        2215
	);
}
static void snarf_hat_2217(void) 
{
	snarf_construct_hat("/usr/lib/udev/udev-add-printer",
	        "269a51fab78cda2fe1ec752208184a8703ac6b035c74bcac8432f52b505e73d364f3984c822e6b29d6398b4c231d867864de5023099e7f48eaec0eef0e571abe",
	        2216
	);
}
static void snarf_hat_2218(void) 
{
	snarf_construct_hat("/usr/lib/udev/udev-configure-printer",
	        "ee96339abdba3d7ad91d7ce364dc35cf97a0318c5bb3612f2bbcf994318c607e09f8e7ae0bf52c92d7ea4bf517f043eb851269c0312c84044e5372fbd64c941f",
	        2217
	);
}
static void snarf_hat_2219(void) 
{
	snarf_construct_hat("/usr/lib/python3.9/site-packages/mockbuild/plugins/pesign.py",
	        "134786f1e03a4fd3ccf5e242b80694c4f4f7ee357d3b93e6c76131b1afc8696681a1f1cadeba596e5d23df0417ee1541e869f7993276a67f62006fb8e770ca01",
	        2218
	);
}
static void snarf_hat_2220(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/crashreporter",
	        "8e99d901824e8aed3d61290e8038571a07fa9a6ea1330df09e6c50ecf30eddced16e82639c77f1513b0e4b96540e4b87db471501be40a5b5cd1711373b19cb26",
	        2219
	);
}
static void snarf_hat_2221(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/firefox",
	        "80301cd87c018eb2dd0712049326fee1fbcdc4cd18ca5a1be32c7232c349256c34ab1d4b72ef7de3ddabd8209bea7fff22f455204a84da6e3f387e148f0e82d2",
	        2220
	);
}
static void snarf_hat_2222(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/firefox-bin",
	        "afeead70e8e51c1abd41f0fa9a9a05ac553ce82e65b90e4b1ebd63f683ec3451bf0315aaed4c73b57b421e86b3d07423e3cbc75c1cf691cc37db3c25a4bb81f7",
	        2221
	);
}
static void snarf_hat_2223(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/minidump-analyzer",
	        "932c956d4ef5727378ebdf0ca077f07b32d79eba3184135d6dd8f8940ef97a8e73a3d13d02740574a2b9720682d5c88eeac2e4270ff7e6187eca4ca0a4568029",
	        2222
	);
}
static void snarf_hat_2224(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/pingsender",
	        "5f73a264b8403fb420b96fd3df23dd73abfbd33f4ff5e874aa66a2f751ffcf3d176f4699e70554286cb205a27fd3791f458369caf967a36a33939b6013a2414f",
	        2223
	);
}
static void snarf_hat_2225(void) 
{
	snarf_construct_hat("/usr/lib64/firefox/plugin-container",
	        "cccfcf7b522754ad32992fbe1c7361c9a9b9d71a0439aa0d66fd19699b720efe63eadc68122a1419657ea4ef7e15f44acbc251231de6b80a6f0804ffaeeb2369",
	        2224
	);
}
static void snarf_hat_2226(void) 
{
	snarf_construct_hat("/usr/lib64/gettext/cldr-plurals",
	        "50ba05549c7d33761dd51b0f0498c64d8b71cd92ab4e126b9fa60d5cf93787a57170599ed608e7e953bbecfedea7bf12c2bf0345635f2fe885a8bfd13d4dc196",
	        2225
	);
}
static void snarf_hat_2227(void) 
{
	snarf_construct_hat("/usr/lib64/gettext/hostname",
	        "d31166a72289913f50b415247b027316ce4f56762c494cb615823bbe45b6a65b6761cc6a40556dd0f175c670f5b43ea7f32f4fe37d816c54641c8aa45b1e8c04",
	        2226
	);
}
static void snarf_hat_2228(void) 
{
	snarf_construct_hat("/usr/lib64/gettext/project-id",
	        "db86195e1fc940c9179f9d1e8e9b39dd882b0ecd1098e854dc6b6a5903944d24b3aa19f62fb2504044f63f5ecea27393110c4e774c8264356e533386f6988876",
	        2227
	);
}
static void snarf_hat_2229(void) 
{
	snarf_construct_hat("/usr/lib64/gettext/urlget",
	        "52af96cae7123c5649b82a3960e06551eb7a60b642177db122495959d40d6c5b1b42a555295c6c24691d28c545063d44b065dc168134e2c035109fcf9140f2cf",
	        2228
	);
}
static void snarf_hat_2230(void) 
{
	snarf_construct_hat("/usr/lib64/gettext/user-email",
	        "a6c609d9af7909348ab6bea8abe2cb394fcab7fbc3971940c1dc0868c950aaaeb2d1f5521f7b1d3ebe4b835c8cb25fb1654f8d884ced0b877d3c5fa8e295e3fb",
	        2229
	);
}
static void snarf_hat_2231(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/javaldx",
	        "6cd4e5d637e3a2c533c489195f9fbd5d12a9bdfca3615a2f3e4fcf691d5b30d9df33f5afc5fd73c38ddddab42f1453a8850f5f5634d050eebd725cb45c185fc7",
	        2230
	);
}
static void snarf_hat_2232(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/regmerge",
	        "6bce7baa4bff93562fff1ab53f33f61ad9f51ae034b216eafa5cd195dd5e2bacb29f128b4c207e4721e18773c8b45159d98ba66d4647302f8246b36080d8b7e3",
	        2231
	);
}
static void snarf_hat_2233(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/regview",
	        "0da84959200b719e6908a2701948dcd89148abcda121588ac810df246faf572106f8040ae0c92a529d8308ae3d0005754e7bd79d32425b760aa8769eaf6947b5",
	        2232
	);
}
static void snarf_hat_2234(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/uno",
	        "cb48c110eb10045ae2fcc90b88eb0f969022f1ce510bc2f759fa890b9660ba8f9f0b6216638071ac58b9e2509dbac4a8598c09d08262ab86f2c7e0137322f544",
	        2233
	);
}
static void snarf_hat_2235(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/uno.bin",
	        "a70c340497b029bff55bdfc8e357b5aa2d8b29222af59b9f38bab6389716471d854523dbf64253d185785b12267de2b9cb6afdc65c03d4b85f745c710998eeba",
	        2234
	);
}
static void snarf_hat_2236(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/gengal",
	        "ec7cf447a7c7d30d7b0f94f849e7d98cfc44bfa10153b8f379ba10c32e30aa784506f15c20955ab8573f67c8b6c220b0dec708c55814f2663e1a7d6a08be7a4a",
	        2235
	);
}
static void snarf_hat_2237(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/gengal.bin",
	        "faeafc35e275dc6e2b86748250dcb5ccd86c05bdb69ec07561564515f85ad8d0768c9758b07576ea47f1f53cb42f50af999a0913e9c84897f208a2bc12381670",
	        2236
	);
}
static void snarf_hat_2238(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/oosplash",
	        "5b7ae3fc7fd530bbe56eb5cf1054991b3d592ef3fb37e58d2a504b74637b983e164e3e2af5a28d2549aa5ff409dc7684a8f994bf0c39969788a9f42a7235c1e3",
	        2237
	);
}
static void snarf_hat_2239(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/opencltest",
	        "8f908b2df9fbf3802aa5dee8bd8c268c33a50fe2302ccd6375243b0dc32e25c72889b634405b94ea61dc4f7c84df6b0523f8dbe49ac34033f168eb642410dd9f",
	        2238
	);
}
static void snarf_hat_2240(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/senddoc",
	        "c0ee17e6674e027d4219ddfea03098db66c4bb4cd80950e47f7bdda189e57eb8efab78e36755046d6deb0de6e135b6f8db9b5e3f3c5113b720ef4f779d08b5a4",
	        2239
	);
}
static void snarf_hat_2241(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/soffice",
	        "194f07a374cce6481a69887a27f621706f2d942c7b2ad60f91cdd7bf9133ff7d3904e0dd6ece9d96fdcc86e1524d1093d38eb840f123d248799651d06cf4ccff",
	        2240
	);
}
static void snarf_hat_2242(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/soffice.bin",
	        "7c5966c0ab434219c8566cf5a591c252c0b19fc55786aec102f324fdb0aab259f73b252cfa834a1bbcb4e667805f132f6db424cf12af97fb37ad1aa717dd7fbc",
	        2241
	);
}
static void snarf_hat_2243(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/unoinfo",
	        "76a153ec3c8786e2975f36b0680024da62174c005977bfdfdb4ca6947f7d806fd8ed3b36ae15a257ef37158ee30ae4ea50e0ad384fb5a5522995bfcb94888b80",
	        2242
	);
}
static void snarf_hat_2244(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/unopkg",
	        "2236ea73eb20e1043a098b2dc58e67b416fc50e127352b8aeb762c95c970307e6d2dbe655171b894bad0dd35210e371d988fad9896638ed68e8e504f12dd0ce8",
	        2243
	);
}
static void snarf_hat_2245(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/unopkg.bin",
	        "1d271d444d2f5a06dcbff2f0fbcb0c9416ec85330b2df65d2360c33fce163e85132dd06b725e00ea24ecdb7a5863b67d16501ac5bc4e6df69bf5f0cba3796d27",
	        2244
	);
}
static void snarf_hat_2246(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/uri-encode",
	        "4f4263ae9caf86ca733103941967b8ec7b91c7bc9a21c3e09d4f82ea5956c52efe81d9b62c24a5a2bf21cf4ec1b676064ec88b3fae85fdf29df77ba75ea2161c",
	        2245
	);
}
static void snarf_hat_2247(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/xpdfimport",
	        "0245d2e4e66450f48c296a155f6a67a3d4af171583a738d46ccf078f9b15843784ab224a667ec4e471ed374472442827b9ccb88f5e3831a645d5f4ca06481e00",
	        2246
	);
}
static void snarf_hat_2248(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/swriter",
	        "fdb05d0bff4e69cc838160de29a653197758df86ef4c95ce0bc08c69f05009829b8fb356599c038b94bee55d7e31a28340b47a35c9f28b4bddff9983667b64f1",
	        2247
	);
}
static void snarf_hat_2249(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/scalc",
	        "bfcab328560994a3792a6d5fc09288a40903493d6fc31d6aff4164f150fdf37696b701c09d135977fcfbb6e2805217b0e4eaff0952432f961c564c0934cebd58",
	        2248
	);
}
static void snarf_hat_2250(void) 
{
	snarf_construct_hat("/usr/lib64/libreoffice/program/simpress",
	        "c5bd30adf7b749b9b888f9b112c20caa7717e7bdf131bd79c3228db82ab178173ed7133ba1917ba3f08976ad928d93cef3a573de81bad1e37494df2e79908161",
	        2249
	);
}
static void snarf_hat_2251(void) 
{
	snarf_construct_hat("/usr/lib64/libv4l/ov511-decomp",
	        "f41f71baf0d31280d907711750f0cbfc8ddad5078c0eb8363cfab259c81e971920a93768c23ce1035a52047892cbd204df19ac37aaa9cbe696becb3f4677e177",
	        2250
	);
}
static void snarf_hat_2252(void) 
{
	snarf_construct_hat("/usr/lib64/libv4l/ov518-decomp",
	        "6eecce6083f020699ffcba625eec1213ed39aa621c7417ec326c066c94f1d7ee68bb074b1d825cdf2f564de7fa0b84c3273e0ada2848272594a8dc97982634d7",
	        2251
	);
}
static void snarf_hat_2253(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/bltest",
	        "110a950ae94965e0208df27f8a7573b72c8c03525d51fa17f25a5eb44422dc248b553451a09842fa703ddfa85e0cae46c71b1e24ddfe15996aae41b83da88e56",
	        2252
	);
}
static void snarf_hat_2254(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/ecperf",
	        "99bf2c5fea921e22a1d49c5a8c390fed36335328edc24447d9b339a8799b652804fc67945f122fa20a95749b4cea43e011aedf13b7bbdfa6b85929c56f97d96a",
	        2253
	);
}
static void snarf_hat_2255(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/fbectest",
	        "78cab6540825ea3e5a0eea6c4b70f65c2ce9df2e91eabf0fa6df0956954d290b15589c411e959e869422ad1f40e9fa66b8f07889befc501e862f0f308f2b34e2",
	        2254
	);
}
static void snarf_hat_2256(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/fipstest",
	        "f9a5e6dcf0cfa6bcfad0fbeb254a76a808e1e4cd6d430b72bad7d6503c6d03198716ba5d9a97a046b54383a4ac90f0608236d57a13b57a48130ca41bbb84d6bf",
	        2255
	);
}
static void snarf_hat_2257(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/shlibsign",
	        "b98cf8c3d1cb729f5328cf96900b30847875b4ff42ef21fcda19f5089866d3bc4d572b182a8823e0d853f4303183d3d3f140c36e39fa00e666274de91096942d",
	        2256
	);
}
static void snarf_hat_2258(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/atob",
	        "f54863fac785aaac46c2f63a22b8200c0a798482fcec44d0129e8218f5e13252f3e94386e3e4fae25f40fb028f31c4db8d36a8d8b249e1344c07ce7b3f50725f",
	        2257
	);
}
static void snarf_hat_2259(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/btoa",
	        "e8d512c1f92dd36e2224bf8a650c59b3ab778141fda669babe02a6ca82d4461abe11e462fc49d9cf387c52b3fa3c518c0856fd3afa70d216465316fc91581a39",
	        2258
	);
}
static void snarf_hat_2260(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/derdump",
	        "f25032bc756a6b1a2a44ae615ade9a05fab83a7b6103dbbdfb6cdea85c17b0436181bdca922a655c2cbe09d5c1050985c249b354ebdf6beac55fb2e77806efbf",
	        2259
	);
}
static void snarf_hat_2261(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/listsuites",
	        "1f34718c1a4e3c1f5c112dc22681df4c74ff5db77aada8a4223fd0cc7c9d23749bae880c5093c64b8e5d337577da62739c6dd465801bde378af195a29a2a2b7f",
	        2260
	);
}
static void snarf_hat_2262(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/ocspclnt",
	        "bd7fa82891a8dcae1b7b5da49a788a56c997a3c8f1913006b53c1895330fd4431145daac48981be8c060d383134df0f2c574d5882d83e4a840c951f489fa9338",
	        2261
	);
}
static void snarf_hat_2263(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/pp",
	        "8968178bc02b3d9d8cfa5f3a39d8066272a61ac031bc5886fb9c73606e67bca6d50b7a336c1e5328b8b171615382db420542589b05963d206ddc55d10ffc282a",
	        2262
	);
}
static void snarf_hat_2264(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/selfserv",
	        "ea040f759960f16a36892cb5cc30c0096abf49f4c4b7087b28a8e68832f33207223b4c85f1d45f315af63d6bdacc82dd9e44688ed0000e593a9830083d66739f",
	        2263
	);
}
static void snarf_hat_2265(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/signtool",
	        "218cdd17a814df435060cea489304edfe60555ce48b4439642caafa9d415bfe165c20a353b1ceb794d5be88a1235de08016dfa8d4a39bdabbe6df916458cb0a0",
	        2264
	);
}
static void snarf_hat_2266(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/strsclnt",
	        "d3be52df59e8e4b57a1f874bcabde1f6ce19f49e4dee8134df4728bc7480a819f2a3c5c0e385b3ec75344c2179eaab51b56ab692ac365d93e89654d20ebe5e52",
	        2265
	);
}
static void snarf_hat_2267(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/symkeyutil",
	        "85a57a2b09d964c5ed9808e5382183a7993abb7878a5081e3a38c4a253413a2401cc01338e24a8e28ca3e3eb66ad781d34e412bb6e9c137dea515a9bc0fc5868",
	        2266
	);
}
static void snarf_hat_2268(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/tstclnt",
	        "749e8ef7277cddce9e9188f3102d6e694a7c3f7f2f9c463c207b6155866e76c888f66c6f5f8f8a51ebddaa461afbe97146505ddee0e37e5fa27dd54b809ac575",
	        2267
	);
}
static void snarf_hat_2269(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/vfychain",
	        "3b7164ab239cf34ba3ff5e7ddd5ebd826bd387c6b6a1568af1f8ade8880f143dd56a3dd044b8dd3a701eafebf52debfa725e64cb72ba6ccb1e2467faa2685634",
	        2268
	);
}
static void snarf_hat_2270(void) 
{
	snarf_construct_hat("/usr/lib64/nss/unsupported-tools/vfyserv",
	        "e2e6565bf7847de2e5685d814b6c7edd7d22a4b8f9b9fda3f79a0afac1ea142753508d7a8663944aa19bc8a5330e01496b52e01ea400c72d6756eec5f72e0382",
	        2269
	);
}
static void snarf_hat_2271(void) 
{
	snarf_construct_hat("/usr/lib64/pm-utils/sleep.d/56dhclient",
	        "b2fb34cf1f600e314db2fd02d4eaf33b0a9c02be973e79f6e1ae0a8c62ccc9f5cfbc3579bee5dec229bcbc051586d54edae5e7b32385633729d97c8725915fa3",
	        2270
	);
}
static void snarf_hat_2272(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/ctypes/macholib/fetch_macholib",
	        "510489a7fd4526c33f904e6ea496896319e01f36abaa9e996ffde74232c712c5eb56ae787c3da3971b45fb7dab007f8732a968331006ac32c49ea864cf340a79",
	        2271
	);
}
static void snarf_hat_2273(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/encodings/rot_13.py",
	        "f37759232536e6ac90676bd736608a8d8a7feef3d2691d6f35c136f38f819c3af340a2a03fe2aa6a9a4c61e9a89157d7e73caed056a77b20afa09dfde22e8bd2",
	        2272
	);
}
static void snarf_hat_2274(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/lib2to3/pgen2/token.py",
	        "cb2aebd177bdcb937250e2fc6c5b3fa279b3dc77eddb07c0ebf0277b16e328f2b433676913f4f9db28edeabbab9744a4b698dea9c8983c7db47d37d636ca450d",
	        2273
	);
}
static void snarf_hat_2275(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/__pycache__/capng.cpython-310.pyc",
	        "8469c4babfde1e97bdffc7ded01813b3ee1835ca19fcb15c6dbb19343b528cfb60530e49875c38a785ecca634ab08d6b8476218b5927c4e02fbc338fa10f22fe",
	        2274
	);
}
static void snarf_hat_2276(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/__pycache__/capng.cpython-310.opt-1.pyc",
	        "8469c4babfde1e97bdffc7ded01813b3ee1835ca19fcb15c6dbb19343b528cfb60530e49875c38a785ecca634ab08d6b8476218b5927c4e02fbc338fa10f22fe",
	        2275
	);
}
static void snarf_hat_2277(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/__pycache__/audit.cpython-310.opt-1.pyc",
	        "0b785b2d64b108dd159e69bc20894243906099187a1d030f221e86b042fc35a813f068f4bea5e02a349d10185686ee6d4bf80a9d731a51c0a0674dc1585181e4",
	        2276
	);
}
static void snarf_hat_2278(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/__pycache__/audit.cpython-310.pyc",
	        "0b785b2d64b108dd159e69bc20894243906099187a1d030f221e86b042fc35a813f068f4bea5e02a349d10185686ee6d4bf80a9d731a51c0a0674dc1585181e4",
	        2277
	);
}
static void snarf_hat_2279(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/_capng.la",
	        "788dd5d1e12c750ddfea5a374781c43f9eb4ad6055c940c254e8dcd072857dedeb290dc46685f874cac32b2858eae2b00817eb6ab5c20ad8f71ff41d9c70b26d",
	        2278
	);
}
static void snarf_hat_2280(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/capng.py",
	        "71db886bd2a386e62fccfa5d218d7c865e2fc4691eed03f616b94a79991eab5a293c161d36794a5793adff6856a493c2ce0b9cb7f0073c1e3acf1562a6f5038d",
	        2279
	);
}
static void snarf_hat_2281(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/site-packages/audit.py",
	        "56750b7bad30dfb247d04f3f9ddf06e3cfea056d451dc7cc39ea98aa22fbcc53ac9d3c2e0c50379ae18f0f80b92b53aeb111fd3097deca7013da3b6a75944207",
	        2280
	);
}
static void snarf_hat_2282(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/base64.py",
	        "62f9dd75718074658952905c3f67a203674cc0bdff1025c9407e52890a4bd520514c274c4b0182f3c8269902c261096f9dd890df584c47ff472d45c9f29ab81c",
	        2281
	);
}
static void snarf_hat_2283(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/cProfile.py",
	        "b30869915e8558eb08e8312a8c157460c8ce3419f39e397f114dbec344f22e9a79de979e111918e259397acedb17ccfbb8730d6ce186080301725732f441239d",
	        2282
	);
}
static void snarf_hat_2284(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/cgi.py",
	        "0b5123b77cc7ac0d143f9411b6af77571704eb12252916c15f01ad13722605b80cb1a7165076a703fea5826f925901536a6a069a8aa7188fa383bc5054da9846",
	        2283
	);
}
static void snarf_hat_2285(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/pdb.py",
	        "121a543d8ad15b7c56d752f00998204a13c1ccfaf2fa56281c4330da8da2f6e3a2b03769f95813f7f2290f4de1a0b45661b8e5dc079f48cce59c4696bd5598c2",
	        2284
	);
}
static void snarf_hat_2286(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/platform.py",
	        "332dc40c7c7d345eb19aad8262f11741afa9a3442cdd45ef591deb3675d998da37e408dc0c83bd12b9cadf4d0e86dcfebbc41ce2568b8029769db8429bd7d094",
	        2285
	);
}
static void snarf_hat_2287(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/profile.py",
	        "9e895b672dbcd4605306696f4ab688c8ac782a2175946e645a869ae3bc2e4a8bcf7fb16a38e6637a2a11facc5b982d31777d1781e8712c59aab7f2c43998f734",
	        2286
	);
}
static void snarf_hat_2288(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/pydoc.py",
	        "a9fcb064f76bbde80e4bac4ad45e6aedc31ddcd354dcdc3b85351f96b5162ad6e338cde59695f37491cb87d49f4c6c446b6c44926fbfa1a9dda0f34ad4c8cf1d",
	        2287
	);
}
static void snarf_hat_2289(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/quopri.py",
	        "d540c2cf53663dd2cad6a4b85458652d29c944dec7d6be88184efe685118860c0fa4032b0a4e0445e78f2ac73a1e36f4fb8d1006fd8ebf3b5a916f5e5c34a471",
	        2288
	);
}
static void snarf_hat_2290(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/smtpd.py",
	        "ea4fdc194ad9380810a547da20786d8de6ea6b6a5b29d636fcf23e82eef3cd4680fc689918e1a88b783a56c7c6e1c41a09f7c89b523fd5f31861d47dd287c0b8",
	        2289
	);
}
static void snarf_hat_2291(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/smtplib.py",
	        "f5f9fd80a088e9619ec015dace201f68dd97a0ad4d14f2a4a31e09d5281e1bc9ec86179762266a604f6bec7a6d76d50b6d325ef05bd2fd79849f8860a4a0aa1e",
	        2290
	);
}
static void snarf_hat_2292(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/tabnanny.py",
	        "c56d70727f42de5a06fc047e11b24ad7018587e9d2521ecbdf51b03c9f01c1ad3a2e8e95e26e3d75ed1270c21098fc0f77eacae6521aaf6d7366abf61a055266",
	        2291
	);
}
static void snarf_hat_2293(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/tarfile.py",
	        "cd97ff742dc3ba0e0fff30530fd67d30ccceece6158d18d6bafb47750c2b652253749c76ab769bc9436629065369d262ce0c4d93fb04d8a8fcc7d8a1d76ce342",
	        2292
	);
}
static void snarf_hat_2294(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/timeit.py",
	        "37c9c0c553733733fcc74255629f0accfce515e45e4769d8f0ebe28ce49d88e5415c6b2db6d39b418137fdb458e0545483d7a9884c054800d671f3e246bb9ec4",
	        2293
	);
}
static void snarf_hat_2295(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/trace.py",
	        "772bc0aab734f7ea235153441544e669198b8390d6f02a6f7432a3beee75e7481e6d6b15fd6e1fb73296274fd4645159c4cae00d516833f77923b72141a7aa99",
	        2294
	);
}
static void snarf_hat_2296(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/uu.py",
	        "71654d68e7fe77aade5d858c7462344b653cffc49952f2895564407e578844dba70e50db503f2c665cba6743f5b5b48d76ef9694f84d4ecd37b071e20b79939d",
	        2295
	);
}
static void snarf_hat_2297(void) 
{
	snarf_construct_hat("/usr/lib64/python3.10/webbrowser.py",
	        "d86039026aafc99d12131adccf0277967a139f1a2886fcdef9daff55dbeb62a6e969977fc64a4a61939be24f613a87c138a378f5e78368778e120ad66ae8ce16",
	        2296
	);
}
static void snarf_hat_2298(void) 
{
	snarf_construct_hat("/usr/lib64/security/pam_filter/upperLOWER",
	        "a6611bcd36f2e33aab73a08bd98672183bc5870ab0cb1e32245e194914a721877b68cfd5651cf32380779fbe471614f5a1ac478432acb59bc3660fdd334098f2",
	        2297
	);
}
static void snarf_hat_2299(void) 
{
	snarf_construct_hat("/usr/lib64/speech-dispatcher-modules/sd_cicero",
	        "804410b5ca0d195c32a4df7e54ffe29514030e7a32292708229296a0bef04511971a6c78b11c47380f1185cb54438290cddbe954b8468aff12d5ebeb0810b11f",
	        2298
	);
}
static void snarf_hat_2300(void) 
{
	snarf_construct_hat("/usr/lib64/speech-dispatcher-modules/sd_dummy",
	        "0d7a034babc0850089735f955376151a8d95325f2f81b79b7a04822efa53452b628b542f5a2b1f3b268abad2b8a9123a7188c12c0c98b6f2206b55aecf7085ea",
	        2299
	);
}
static void snarf_hat_2301(void) 
{
	snarf_construct_hat("/usr/lib64/speech-dispatcher-modules/sd_espeak-ng",
	        "524a17f4fd3785ba670f0a15b200efa7325112cab59a091e8fabe0d42030de42357cbdde85bc88ca7af6d897867852ea32606d93702cb513b7f40f76fde706cb",
	        2300
	);
}
static void snarf_hat_2302(void) 
{
	snarf_construct_hat("/usr/lib64/speech-dispatcher-modules/sd_generic",
	        "ea8acdc0e35d14d4409bceda233ba4ce96b36c25b466005970c14891d5fc8a9452b487009a273a5c1162e55f0a70f85b3f4da2062467d585611894e205436398",
	        2301
	);
}
static void snarf_hat_2303(void) 
{
	snarf_construct_hat("/usr/lib64/tracker-3.0/trackertestutils/tracker-sandbox",
	        "59594654dc8f45a2cf9d694338da6e004c99bb754a7fb6b2e18be5b1f0de56994614de9919010148385f3812e04e56b1a30ec6dbb2a5fd202c77c3ab33015947",
	        2302
	);
}
static void snarf_hat_2304(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/assistant",
	        "01289b2264d8b7236ece66fe3559b427e7cce26aefdcdc3dce20454a8371d00286d71a546ab93f316f51f14d8c1d093a910abaa6acb11b08d502a1e71c6d9805",
	        2303
	);
}
static void snarf_hat_2305(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/findtr",
	        "1464dec56f2a93ebb496591b3fb88bcca1b49e5396be689d9853335eea8bdd7ac76819cc71414b251b224100fba8fc3451e32116d4187b7e28718f4c06d0fc4e",
	        2304
	);
}
static void snarf_hat_2306(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/linguist",
	        "0955a42a94624599787cc4e4d6fb22f158923848736dc84f01d3b5ee9c6f14658a1d1eb331697c93621067c4905a532b509cb79e2fc4c1db83d73b83e41c9fba",
	        2305
	);
}
static void snarf_hat_2307(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/lrelease",
	        "3ddf1fafec01f836ee18960e62c9e23cbce82ec5788c5d58b6361881e58e2d0921897b4fdcd7912c545c18116d2e0f912f79d259dbf21536fe94c6fbdc353750",
	        2306
	);
}
static void snarf_hat_2308(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/lupdate",
	        "536de700cf89090c2ff797f84d161f5acd57399f9c4840264bc700f5e187bf0105cad8c06e0c299f4c9e72a54a842b93f0f8048ebc47ebfd83333176546454ba",
	        2307
	);
}
static void snarf_hat_2309(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/moc",
	        "cc97c0ce932e36ba6cc62ee53a1ca9ba6a4eb1ad42bb996500c04a22058cc1717f6b39283254c69067cda11c6e6270801656b0aad0fd00116f440c60dd83b66a",
	        2308
	);
}
static void snarf_hat_2310(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/qembed",
	        "4c1ee891fa22f260f487bf392f9364c4c24686369559762d21df3c1ef5e7a19200caec0960d2f7b741a9fd05412a92040b48e73cfb4fd24ace1f980c8d172915",
	        2309
	);
}
static void snarf_hat_2311(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/qm2ts",
	        "896d35c93cbc6fbed3b8457aa7ffcdf35852768a8065adf9e259e635189e1fa23957344823f7089f616d17c49dd51bcbb7b86a39c681cd58326319da4c1de757",
	        2310
	);
}
static void snarf_hat_2312(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/qmake",
	        "11fe65c28fa2aa6330885b2663e1eae8fd0e3b1e9839ef903f34f6277a9d7b19514b660ea3ee6e0f85a2d05c4395e881c6f7c31c025c927177ef525e5ab7bdfb",
	        2311
	);
}
static void snarf_hat_2313(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/qt20fix",
	        "bfe5a82c2b9de1729eb7088fdc629361b94343c9b0ca2446b08eb5753164e9e689d399a4e9b43d3d5b9b57618169768c2a77e194f693c54a5d91973a13d8c416",
	        2312
	);
}
static void snarf_hat_2314(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/qtrename140",
	        "81ff262b54bcabebe713f06af46e4b27b3c63007e4d84185189058444126bcdce8665259f227de5892f08629234e81cff28768d012e02924c7543dfb8da952c3",
	        2313
	);
}
static void snarf_hat_2315(void) 
{
	snarf_construct_hat("/usr/lib64/qt-3.3/bin/uic",
	        "d89a14c7d0297451ad8beca5ae2578e657060ab386391dd181caf6f4b02ffc41a32ef325af5b332127c5b8c987df7c6cb93316260178b09d344275921bbf60f1",
	        2314
	);
}
static void snarf_hat_2316(void) 
{
	snarf_construct_hat("/usr/libexec/anaconda/anaconda-pre-log-gen",
	        "41c6f2749bb4dde4cb41284ee518359aca5f383d9f5e24d838b5fdffe047d44e0cf21c6e1231e8bc857207d269589206d96b93dc163df1547d93b036275e9222",
	        2315
	);
}
static void snarf_hat_2317(void) 
{
	snarf_construct_hat("/usr/libexec/anaconda/apply-updates",
	        "5146a704fd26afff028b0a1470d6db35e09879403ac051759e20f3d22568b62ab5f66ec91c1379cea007382d08d2025a187093295f35e23d2905f1d70b4b7f55",
	        2316
	);
}
static void snarf_hat_2318(void) 
{
	snarf_construct_hat("/usr/libexec/anaconda/auditd",
	        "8f9830109b6a350fd1af297bf5ee0c910721a0d0a65a9902f5a08780ddda9d4792388dad8e2dd1953e0bf8ca8817902ddcbc6e37f139b8e09e46c86f19d6ad56",
	        2317
	);
}
static void snarf_hat_2319(void) 
{
	snarf_construct_hat("/usr/libexec/anaconda/log-capture",
	        "b712418d5bda23888218ad22381dd8fbbd5a9346c64a5a42080b5e63565e72f4dd9e1a86e00c1bd729e6dbdc646f31fa6e497d0ce19456d6f7b81c5547eb8622",
	        2318
	);
}
static void snarf_hat_2320(void) 
{
	snarf_construct_hat("/usr/libexec/anaconda/start-module",
	        "65ed05af3be77595fd1ab372d8fab1194d075dbe234945c8ad53cc1a2e9e0dc96c9ad8d09e8aacfbe3325c9b1b2c7c26b6326a2241d4a0f2493cad479c82d098",
	        2319
	);
}
static void snarf_hat_2321(void) 
{
	snarf_construct_hat("/usr/libexec/awk/grcat",
	        "0d25cd3d2b92bce6fb3e17cc0cec50e9e3783876f09d99ea5938fcde5ce06b12247b38a5548968f0de75a8cb15371b855d36f72f6e74775f02d17519d6fcee82",
	        2320
	);
}
static void snarf_hat_2322(void) 
{
	snarf_construct_hat("/usr/libexec/awk/pwcat",
	        "ad3bf70d65fbc30d87a57025dc0cfd4749265fc3397bc4d4560b75b9bbffe2463ba935dbfcfb9820900866496ce2df88b1d9e7945d0ba3ded409f9c380bf3207",
	        2321
	);
}
static void snarf_hat_2323(void) 
{
	snarf_construct_hat("/usr/libexec/bluetooth/bluetoothd",
	        "aac46a2457e39b1b6754aebdc7ff719b5c9c049fb5e01610de5096a7a91e8640305ec1637086743d1ceb6be4b89b2313ea098f2696898fccde7693b3a47e93c8",
	        2322
	);
}
static void snarf_hat_2324(void) 
{
	snarf_construct_hat("/usr/libexec/bluetooth/obexd",
	        "b92f8f45d8a275316f233cea7298d08090209039019ed5fade7d088a75a26bc35fbb3f5937bd6afed1e5a887aa4640b997260f21ee67e95f0a607be81f069d18",
	        2323
	);
}
static void snarf_hat_2325(void) 
{
	snarf_construct_hat("/usr/libexec/catatonit/catatonit",
	        "4de619782a87413f36898f7cba0dfc6ea749c67299b19275339c25962a08ad24f847cc37aa020fb904f3b50b26ca1a4c6dacb60340a10ef08aabf2227eb40f3e",
	        2324
	);
}
static void snarf_hat_2326(void) 
{
	snarf_construct_hat("/usr/libexec/cni/bandwidth",
	        "23852453b928283132c092e0e67a1b5fb145338ea526bcef9e1b890a8bb8cce29d639587b8f076ba46567f71da3d9977b4a675ca85af5e8f1264653e921917c6",
	        2325
	);
}
static void snarf_hat_2327(void) 
{
	snarf_construct_hat("/usr/libexec/cni/bridge",
	        "4627602d192cdac1dc8a34d92d9e2d339f293c5815a498a1d69abf77cf7fb414ed2cfa232e7486870b9b20764aafbccac5d8e620ac79e8a83747dbb40349a289",
	        2326
	);
}
static void snarf_hat_2328(void) 
{
	snarf_construct_hat("/usr/libexec/cni/dhcp",
	        "41fb5a5ddebf61cf3815b1edeb5b74ac0e9aed0c945f69fd6139ed482a8157de0a796d8edc6fc05523d1906b04f31b48e9f416a179f4dd1d7fb9cc716c2bb9fb",
	        2327
	);
}
static void snarf_hat_2329(void) 
{
	snarf_construct_hat("/usr/libexec/cni/firewall",
	        "f8b33c386313ec1428164474b6b0a345009d97280fadff2b43861e385fc9d1eeb85e598caa3953308bf8a0014c9b99aef59c6fd9d8c024d7a1c6fb330c85c13e",
	        2328
	);
}
static void snarf_hat_2330(void) 
{
	snarf_construct_hat("/usr/libexec/cni/host-device",
	        "bcc367afe34f3a5c517a5f46ca105092670b24ea123e61fb7799f25d8b4279768ccc07cce5bacdf9f89cdfcd3140b8f432e2e31c210b3afb0f371353e9a91cba",
	        2329
	);
}
static void snarf_hat_2331(void) 
{
	snarf_construct_hat("/usr/libexec/cni/host-local",
	        "f1152b8cdcfcca392c87c68a259efb8d72e4ee57ab89fcdf479c692dc656ae947afc13905cfe488d2a23b407434f351b35d17e1336fe26c8bdedf8f1d23ec373",
	        2330
	);
}
static void snarf_hat_2332(void) 
{
	snarf_construct_hat("/usr/libexec/cni/ipvlan",
	        "8b49ed27aeff811f259e9fb5009761a8da3acd5575fc5256c48c2497b06560127f8099b7c914c196214da67760227a9f95bd11556e84de7c608755eb54f49046",
	        2331
	);
}
static void snarf_hat_2333(void) 
{
	snarf_construct_hat("/usr/libexec/cni/loopback",
	        "c9223cea9171a746f2c756dbfd2ff144d109ea13f194853a6388e43372198a53760fcb8b446fd48801cc83780e55253a52dd983842213486374f57264a412765",
	        2332
	);
}
static void snarf_hat_2334(void) 
{
	snarf_construct_hat("/usr/libexec/cni/macvlan",
	        "10faa9ba04090984c0690d3762f217c4c2a3b8200065e05588ae168221814bf99127434a97ed80f2d4c69340e699bf5c74cd41266241895c5f1f1514cf024f23",
	        2333
	);
}
static void snarf_hat_2335(void) 
{
	snarf_construct_hat("/usr/libexec/cni/portmap",
	        "0abb18f463a75020ba5b72d20e4ef52eaf0e5f3bd3bdba42c9ea3ddd73f5f28ac932417526322223620b772708586f5d0fe6cd0c0bc9c46649ce7195dc312c59",
	        2334
	);
}
static void snarf_hat_2336(void) 
{
	snarf_construct_hat("/usr/libexec/cni/ptp",
	        "b969f797c9c23f0a0bc4c5c6c702d68d871ec816735c1be9104b5895a3fcfd7464b5efaea71e91299b81b4cdc2e22f148ac58ff1cc4a7e99fdd1e2d2a90763ef",
	        2335
	);
}
static void snarf_hat_2337(void) 
{
	snarf_construct_hat("/usr/libexec/cni/sample",
	        "01178d8d25242369e319561220c83601c1e48064c7a0798d316393a4343d5b331e41e192cf1043a2ad23a25d93ccc6bb1347bf6dd1cf8c8be3bba07ca52736ce",
	        2336
	);
}
static void snarf_hat_2338(void) 
{
	snarf_construct_hat("/usr/libexec/cni/sbr",
	        "8b8ba05a26ac15af784cca770a1f75447fc4c9e4755dcf57f0ab29c85f09d389edc6bdd8f69a49a2221cc76b06d26dd97154dbaf6410b4a0aea5231c5310c2d6",
	        2337
	);
}
static void snarf_hat_2339(void) 
{
	snarf_construct_hat("/usr/libexec/cni/static",
	        "8fc57173e0cf52633fbfa2812ee8eeda31b090bf6bcd8734414e8e9fb565b92b7b35cd616af4bff328a637a3c730a69024b6419a8be7772a0379ac7eaa7403dd",
	        2338
	);
}
static void snarf_hat_2340(void) 
{
	snarf_construct_hat("/usr/libexec/cni/tuning",
	        "9c7796b3ba6862cf2d9be05303f5095ea3495028071c75ebc29f1576247c0600212f448ae033adc8c522f07bcaaa213cfaff16122540f60725f1fc5bd370b01a",
	        2339
	);
}
static void snarf_hat_2341(void) 
{
	snarf_construct_hat("/usr/libexec/cni/vlan",
	        "d65b18ce0122d03e3f7b9d005632108a601200c7f86c50a7f3d42933f1d73228c775e94be11524995f568a9399b34530a6136db0763cb28c3bbd25e2076ba642",
	        2340
	);
}
static void snarf_hat_2342(void) 
{
	snarf_construct_hat("/usr/libexec/cni/vrf",
	        "155d2f5ec9d597238fe63226472d42d4a594dd860a66d9268d19637d448eae269632876a4e2218a91652b91f96feba2fcc0a4c9248027697810514061637e66f",
	        2341
	);
}
static void snarf_hat_2343(void) 
{
	snarf_construct_hat("/usr/libexec/cni/dnsname",
	        "426785461847ba5f4fee623cfcb0b0859d69d6c1de7f4f8286a88f67b79523d5d7ee79da7b6466eee7e00621f05e9d5b30b6eab3eb9fdbd439f821e7e31938da",
	        2342
	);
}
static void snarf_hat_2344(void) 
{
	snarf_construct_hat("/usr/libexec/cni/podman-machine",
	        "b75c22b8e3bf9985456ea47f9468d2494993e7104a40c9965af7237bc198263f1e0a60a34786ef62996a60585b4a6bdb10ce416a606f9482f3d34afe138d9670",
	        2343
	);
}
static void snarf_hat_2345(void) 
{
	snarf_construct_hat("/usr/libexec/crio/conmon",
	        "47494047892fa94246dec61c3f66ac5b5de46999529c9bb29f2e5c3b2a022fd6cb2716fce81ee737168b230b647834d36bcae566db0c8c6bc69213bbaa96c9cf",
	        2344
	);
}
static void snarf_hat_2346(void) 
{
	snarf_construct_hat("/usr/libexec/criu/scripts/systemd-autofs-restart.sh",
	        "48261b3472fc1ab1291a701ccb28925847402db78d92a12208365c0f4f3929667d830215eda8bcd4d716c7a285cbbf5b243c4653cbe869e001fefb268dadd32e",
	        2345
	);
}
static void snarf_hat_2347(void) 
{
	snarf_construct_hat("/usr/libexec/dbus-1/dbus-daemon-launch-helper",
	        "cba85e9acdef60c0e3e690b7fd3b328c255cbc1b923ca65e7e61b5510067f709f9d60b89cc860b7b8d3e244ab562fca51b20d06add7ab9f6a65f7b3c03c56c85",
	        2346
	);
}
static void snarf_hat_2348(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-data-server/addressbook-export",
	        "3f4e10909af546a3cc52b3ed09c308aa38256c9cf3c65d106cacea51d3e0d575adb6325af1f0fb08ad54d35f321d2f2ea3038cf0d7b81873b56bf367b4c8cc35",
	        2347
	);
}
static void snarf_hat_2349(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-data-server/evolution-alarm-notify",
	        "49d3beda3f3d5ffdb4a33a9ded63f66d7c6c67537d90cfeaea42fb5a0c0c15f8c73eee1fa5852d5c0b2f0aecb3883973f9a44f23c3620d24921b19f9660c47db",
	        2348
	);
}
static void snarf_hat_2350(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-data-server/list-sources",
	        "d27e7f4e756f4c34a505e6bac720fa4f65c7726dba2c635a56219350025b82b5c084ef452f9a82989b7aa22bfb2b702672d4b5b946ffbac0dbfea525bd999f63",
	        2349
	);
}
static void snarf_hat_2351(void) 
{
	snarf_construct_hat("/usr/libexec/fwupd/efi/fwupdx64.efi",
	        "bce4c9cf5530e74faa00e1a0e78ffb5e5e239caa23f31fa0876d95ca59cfaf1c97c3e1cb93a4f2908f2100439b3d1f6f360e8ea353f8b607c69ad3f14683d69a",
	        2350
	);
}
static void snarf_hat_2352(void) 
{
	snarf_construct_hat("/usr/libexec/fwupd/fwupd",
	        "0fe10530b48a383bb7e1fbae1d6b60bbdc318ba9f0157c3dcb3fd61893965188e5e4bd000cedd2022f1bdf6e3e64527a6bf1f377f738d77f096a2cd98a06cd33",
	        2351
	);
}
static void snarf_hat_2353(void) 
{
	snarf_construct_hat("/usr/libexec/fwupd/fwupd-detect-cet",
	        "f6d5059c737f23fbba551126440ad7e99ec46cc5d2ce84ac2ac401d0f3ee42361d68a2462137f0fefc8603ff11ed9b3396f437195dc284cd71d7e05923c802b6",
	        2352
	);
}
static void snarf_hat_2354(void) 
{
	snarf_construct_hat("/usr/libexec/fwupd/fwupdoffline",
	        "ec606ee5281aaf229d888230b973f956c690e93eabf28b76f5c99799b3fa8d756106f7032907a079b16ebf30caaaadc03e5777453c120fba20ba8fa7ba5f6c63",
	        2353
	);
}
static void snarf_hat_2355(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/cc1",
	        "b681d2e183cc3fd851c9515af38c8bdc9e17b96e8936c606445661b3d0c304a0ef92f9ff9a1cb21e0cda1b2512ff2f39036de16131ea6aefb2590a0f3342285f",
	        2354
	);
}
static void snarf_hat_2356(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/collect2",
	        "53b2e1a7cebf07d637aa8ff17475f340cfdb3a5b16839368ab5fc3111ae8f776c5aade4902df69d13a6dc47ec0002f0c14721c884b8df212af0c31b64c4995ee",
	        2355
	);
}
static void snarf_hat_2357(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/lto-wrapper",
	        "042581b3d1edea356cd809a12b84e13393ccb1b951ababcfe4c8c3bbf88419cb4d8ad4e7a1e74661520edf32dea9a6d8f43ea534f2a20bc21245b581f952b4ab",
	        2356
	);
}
static void snarf_hat_2358(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/lto1",
	        "6c3c10561a47f2d6ee7d0695bda42303de7dcd78ed981d19abf12c8ddf67c547745f0afe90878f7ef925c139cf0d2c745d2f8c09332ec2764de07fe55ad21fac",
	        2357
	);
}
static void snarf_hat_2359(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/cc1plus",
	        "0fde9b621179f4ee1074aee11af8286ff14fde894681a2c82fba4e04f4167dd15486ac698e1121151be31dad311c3494d607dbeab0dddebcd9760ec35edbb9bc",
	        2358
	);
}
static void snarf_hat_2360(void) 
{
	snarf_construct_hat("/usr/libexec/gcc/x86_64-redhat-linux/11/g++-mapper-server",
	        "17d4c9190cf9d94e2a99bd736fa3f2199fc8c48608ccda8c67afa66d5b5e59b89c0ccf0e994a4758cf45d441b9b13db15c3c8e34acb7e824d1604b9c92b211e0",
	        2359
	);
}
static void snarf_hat_2361(void) 
{
	snarf_construct_hat("/usr/libexec/geoclue-2.0/demos/agent",
	        "462e56dcf0bb2c68460496945d0c83ee38bc07628a923bda661b7fc6b151587ff99ff7384fcb677ef02eb30f1efb429ea88dc9975bee7cfeeaec6645f2795f5c",
	        2360
	);
}
static void snarf_hat_2362(void) 
{
	snarf_construct_hat("/usr/libexec/getconf/POSIX_V6_LP64_OFF64",
	        "2653b0de737792f6cb980ec6bdef112c26411dc71e7b528d4d17942c94f8a82e3a6738f1ad08a8cd8f5e069446d6bbb49fba801887684aad4d705e32281d60b2",
	        2361
	);
}
static void snarf_hat_2363(void) 
{
	snarf_construct_hat("/usr/libexec/getconf/POSIX_V7_LP64_OFF64",
	        "2653b0de737792f6cb980ec6bdef112c26411dc71e7b528d4d17942c94f8a82e3a6738f1ad08a8cd8f5e069446d6bbb49fba801887684aad4d705e32281d60b2",
	        2362
	);
}
static void snarf_hat_2364(void) 
{
	snarf_construct_hat("/usr/libexec/getconf/XBS5_LP64_OFF64",
	        "2653b0de737792f6cb980ec6bdef112c26411dc71e7b528d4d17942c94f8a82e3a6738f1ad08a8cd8f5e069446d6bbb49fba801887684aad4d705e32281d60b2",
	        2363
	);
}
static void snarf_hat_2365(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-bisect",
	        "7b242e583555563037733efecb005353ed28cd50a36e5ec2cd6679548ddf7cf93c7fc8722bed4e408c3faae86164b57680cd1b26f9ef797879223a6930ddf9b5",
	        2364
	);
}
static void snarf_hat_2366(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-difftool--helper",
	        "89960d67c99ab35e3d8cecc225046a689e289f9e8e2d29c79c940c4b3becaa7f3f596b49fbfb5bf5f47e5886592ebe412357c8b8293f18b860847190df7c75e6",
	        2365
	);
}
static void snarf_hat_2367(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-http-backend",
	        "75a767544c8ae7da78f6bbeec84f65dea1b924d4c3f9babc6663fa5d87e85eb524c317f316324e9d4a6a79b4395eb14ddcf41b89ad7d7e6c36627d1b307c3fa7",
	        2366
	);
}
static void snarf_hat_2368(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-http-fetch",
	        "b815ee205218deea5bbec3a0eaf98752955f79c44e294ab184459a029196d561639979924cbeb5e141f49434369f87e938c0624ffc891e3274481bd34b82f4ae",
	        2367
	);
}
static void snarf_hat_2369(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-http-push",
	        "9a86e6f8f7e5df9f5d5e3a0695f5bd7284243da55c88e9de6f7c6e20ede89cf036b48c49ba941df0b27116ff8c3cdb915575bf389e2dc7e4afeb4f6679638666",
	        2368
	);
}
static void snarf_hat_2370(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-imap-send",
	        "47295eb7f069f0782cf24b80b99c52a9ec67491aaf1ed9db139255b5f7df26eb5cd87d62f29a22863c4a8e468824c0e0703009c37944f9f07ec928d32a932e1e",
	        2369
	);
}
static void snarf_hat_2371(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-merge-octopus",
	        "024bfc933f850d541e0ceecf54a1c1d7a7efb980e20ff8e0823e5f2df729d10b2b8e2c754893db8a05868e92be9d970bf4aaed0d5d1b969ac39bb6842f2c1197",
	        2370
	);
}
static void snarf_hat_2372(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-merge-one-file",
	        "e9fe9a37b3accf53b06c966b273594d36bd738d96f8b2c08a92b4b86ae0a497077720193d61f6d25bb5a238129f3d7f226995b97fc6fa6d6006b6648c7ce213e",
	        2371
	);
}
static void snarf_hat_2373(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-merge-resolve",
	        "af9a5311837d0b1a681b5bf1a2e211dd3a600fa603041982e2c7b527217468073fa01ae4aae479756741bef76a942954867b02bbff1a160dec588fe4d6ab22fc",
	        2372
	);
}
static void snarf_hat_2374(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-mergetool",
	        "8b0213e60897d03dded5ea8dbd5a9d44de021a80d81fba6102c2ab86aebec7ed9c47e9f81149ecd7bfac80e2be3b72301960406898b3642da1894ba7dc111804",
	        2373
	);
}
static void snarf_hat_2375(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-quiltimport",
	        "7267c378ccd73bae3b0b788f554bff561b10e462febf5e5c905f8fa98478fc274bfe1d4b9ba98c786e0ec4696a1fd3d57add19b73c8f025771dad14d7cb6cd7d",
	        2374
	);
}
static void snarf_hat_2376(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-remote-http",
	        "cbe47b18190967687ae77e58eb4b1faff077334913be7b499a291ccba0712e9f6e1b1c68cedfd3f0eebc26104c1b094e6fd0b8d3150bdb59d61fee821620c571",
	        2375
	);
}
static void snarf_hat_2377(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-sh-i18n--envsubst",
	        "67481dab6c20246025eaa75fbfb53a99e766ca419c64443031f4d4c50a734f6f08ef7e394e1aa86f5e23ea6867c9d7dd26f9ceff0934a6999c9d4055935721fd",
	        2376
	);
}
static void snarf_hat_2378(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-submodule",
	        "15371689b662605db9f108f8e065b574c99d943a79075c1a6b1ea63fb5f5d35c93277245e9c9a553676051fde83037708f3d650e51037cb69e4ad90bf9c68a51",
	        2377
	);
}
static void snarf_hat_2379(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-web--browse",
	        "7ee09bf78ba9ad4ffba0f5e5215e4916191e547f966bb0322334e1d60013daa9b32717ed3ca93da4113d2a2e67e167567fcec9401195034df197cf7136c90260",
	        2378
	);
}
static void snarf_hat_2380(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-add--interactive",
	        "4f4a485de860f95c12fb127e883df07bf470954d2296d2ab21f2ad97ea142c6690a248d1e8f6c77aa129f33f6e8a28b786625a2b2b3741e8a3dc0361e18be988",
	        2379
	);
}
static void snarf_hat_2381(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-contacts",
	        "db03bbaaff567ae5ba06b130be4857922b8e68c18833f06b0763ff3a74b3fa1f2e7d3b2a6824f02e15ddaf1c435d0fed6d44490d97cbf3b92dc886b7621bfbbe",
	        2380
	);
}
static void snarf_hat_2382(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-credential-netrc",
	        "9c6ba5c19ce97780773eaadf2eb329e480e1bd7df2429bde2d0147a7f8ecd712fe142b3d2246c1a1e09446c2947857a8fc880e7c2c022a01301081929b27e784",
	        2381
	);
}
static void snarf_hat_2383(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-filter-branch",
	        "407d42afa25b52fce917f2688007ee16167eeb4295f81c038f361035fc32ace6dfc3a26cc5f0bc83a72267c231ba81d23726aa7e31cfa8b9687026192fafab79",
	        2382
	);
}
static void snarf_hat_2384(void) 
{
	snarf_construct_hat("/usr/libexec/git-core/git-request-pull",
	        "aca052f9c143ed13f720c78e3f8d5498b7c95134b9303b661f34340442a6e9686b88038f5601de54a75e06fc464e023ac10389a2dc86bac49686c8a702afb71d",
	        2383
	);
}
static void snarf_hat_2385(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/gnome-rr-debug",
	        "a4ed5e12c3e7ba79f03a738c9ef968e8990be85f8d1471aefe126f6a5374d0f7bafd9f9fee447a108ecce670affe775d84c7c8ccf4615afff30392440c7fa9e5",
	        2384
	);
}
static void snarf_hat_2386(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-desktop-thumbnail",
	        "f92b6544b3d53ae79f2889f28f9678255c8163cf6cc9e4b02967fd09151a9406a9e3fe8352f55f1e80f655534295ae01a8d5106a9459647cd4776a4a53471e4a",
	        2385
	);
}
static void snarf_hat_2387(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-idle-monitor",
	        "2b7013b61486718739a36ad9e4e94c515e773f5529db4379a4a2bc7fd63b0dfef477ef117c56f513f67298726d38dfec952a4ebb6707c1b8ba8cecb892ef0308",
	        2386
	);
}
static void snarf_hat_2388(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-languages",
	        "22bdddf6a27ed2ecd794f0b1e4e0a6207a36f0cc2b913cdcd77be803521862f708b8f262b43768e687b4467a43f55c89058df795d204df52c1201dc20653b5f2",
	        2387
	);
}
static void snarf_hat_2389(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-pnp-ids",
	        "2066ad598502441790e3173db5dd7d98efb54d8cc6e2ab9fbcc564d8947faf1e8871304646331be49529ec8e8576b9c56538c0727334c9af63c61689f02267c0",
	        2388
	);
}
static void snarf_hat_2390(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-wall-clock",
	        "15eeac851cbabc50720b91f38fbe7783ae00d070e31cc6ccd071e1e94d60a7d90b0ac1b06cdd1fc2d4917500857c9a6d163a84795facbe32237361b9aa7ca73e",
	        2389
	);
}
static void snarf_hat_2391(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-desktop-debug/test-xkb-info",
	        "98440432086a0ad0532c4f0eef511865eed539150c9e2054a93168e1ff77234aafda4c7bbfee1c7bbdf595ae2559797a5aea3efe14e763efbc7a17a536fd93ab",
	        2390
	);
}
static void snarf_hat_2392(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-system-monitor/gsm-kill",
	        "63a3578aad650170038fd049aaf3c3c1b0b9ae04abc2006f34fd1e30ffc96bd59e7bdf4c9fa6825bd6c55c489e52c99eef97ace9f9c486330e37c70db8690ed2",
	        2391
	);
}
static void snarf_hat_2393(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-system-monitor/gsm-renice",
	        "82c13adb79e30be6e6a4007e00f6afb37b66f7d3d15d1ae03274a5801b84de36658f09315adf333c2c6844daa1fe721d562c8eafc64062a8e73c2f7b9211e45d",
	        2392
	);
}
static void snarf_hat_2394(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-system-monitor/gsm-taskset",
	        "c9be9fbc6b4877b180b0ad28652833604f6b09c5f0f64bc7f821efff5a8f1e82512d7c1ea907838b8441161711bbf8b897df5cf6127f446c4ebb85ee5eece45d",
	        2393
	);
}
static void snarf_hat_2395(void) 
{
	snarf_construct_hat("/usr/libexec/grub2/systemd-integration.sh",
	        "15507fa7aeee5bf1e5dbde297e7d305b51819800a80e56a2702ae866f3cc90da5231b07c3fb72ddcaf6a24c8cbd3fd77bee1dd6339138892f0743096abb7f05b",
	        2394
	);
}
static void snarf_hat_2396(void) 
{
	snarf_construct_hat("/usr/libexec/grubby/grubby-bls",
	        "629568c3381d3785c0a9756bdfa3279c8bc88f07152e1bc49b562b082bb9ffd7c58b534e04bb1a3003ba74861f3ad982244e256a28aadce0eca2f0ece2bf419f",
	        2395
	);
}
static void snarf_hat_2397(void) 
{
	snarf_construct_hat("/usr/libexec/grubby/rpm-sort",
	        "d430c7a9f3f0789075de7b8504c835254347b99f2e5fb229912378b028b212d8c2db7170297b9c2eedb275fd7fb8890325d604f46f8ac38db2afa3bae534fee1",
	        2396
	);
}
static void snarf_hat_2398(void) 
{
	snarf_construct_hat("/usr/libexec/gstreamer-1.0/gst-completion-helper",
	        "f9f06fba4b15e991c5581015155635c3ce886b499f78b4fd5557edc0eb4ab020ebc957b308a10dcb0da494896b945b6ebb53633b38831320b7807a809ce046bc",
	        2397
	);
}
static void snarf_hat_2399(void) 
{
	snarf_construct_hat("/usr/libexec/gstreamer-1.0/gst-hotdoc-plugins-scanner",
	        "86bc6920085637612dd41ec282c218266b62f157fafc3523b1affd55a4fead74a0e8bbe34a1d9ef486098e078145ac5bebb730728ca8483082a38b13d22e6d21",
	        2398
	);
}
static void snarf_hat_2400(void) 
{
	snarf_construct_hat("/usr/libexec/gstreamer-1.0/gst-plugin-scanner",
	        "4e71b72857a9321dce7f33251129791848339cbcc35f383f8aaeda9547f001f8a5705b3e2a7cccef1d405bd424560c666ae46e9eef3d5c10d94e87f2c18e0c2a",
	        2399
	);
}
static void snarf_hat_2401(void) 
{
	snarf_construct_hat("/usr/libexec/gstreamer-1.0/gst-plugins-doc-cache-generator",
	        "f5784074eaa7d3f29898d0fc040d8c754b412a0f69bf9fb2aa297adba4fc7e322cfb694a1aa0d66f3aad8ec25d765ff7a2adbe8fd143434f0df37643fdae9e58",
	        2400
	);
}
static void snarf_hat_2402(void) 
{
	snarf_construct_hat("/usr/libexec/gstreamer-1.0/gst-ptp-helper",
	        "d6e04a6763af1829b2f0ba16b98b7ac6f53ef9cd9ddd470aaef71392bb1a527d71ae8fdb0558ebd07fb71ffdfb0674628c84d3e1119aaf66e01226f950e86fc6",
	        2401
	);
}
static void snarf_hat_2403(void) 
{
	snarf_construct_hat("/usr/libexec/hostname/nis-domainname",
	        "f00a244cfc62a973db3396f42b6bbc63aced346ba810689a31af43a36bf450aed97f11fe6a082232c5f7b45ca37b0d8e21a0252086e3317f670c449498913d24",
	        2402
	);
}
static void snarf_hat_2404(void) 
{
	snarf_construct_hat("/usr/libexec/hypervkvpd/hv_get_dhcp_info",
	        "eb7f02ba258caa2d7e3270f440276af4753b8261d9af0cd373d7e2fb09aee6e566af186c4c7da3b20cf567171e0f1a411ad1275522031bb1618154942883d89f",
	        2403
	);
}
static void snarf_hat_2405(void) 
{
	snarf_construct_hat("/usr/libexec/hypervkvpd/hv_get_dns_info",
	        "189742f732bfad94167ec2d68cc1cb25ccc45abd3e013f5791e9a8dc9fe867b3ac9d73da531b4f5197b23f2e08d3e62847e35e2020d1b14ca8886230ef3a8723",
	        2404
	);
}
static void snarf_hat_2406(void) 
{
	snarf_construct_hat("/usr/libexec/hypervkvpd/hv_set_ifconfig",
	        "f8ef38b570f676320e7b33f2305e55ea57e4af576d48e457c0b5a31c86c32d01ccf8b1fafe143d71018fbe5deb2da0ad7ef14d9f504a89053ba3f2ec199b950a",
	        2405
	);
}
static void snarf_hat_2407(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/condrestart",
	        "41472bf76cf765aabe06474f8f16504770f42685fbe48be11b527466b685c9473a498fa3fffd576e2c63c7df9914c9a9b350f201522a6bbeda9eb2b0e154a8f9",
	        2406
	);
}
static void snarf_hat_2408(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/reload",
	        "159a6a0fe11971ab554193eb0e57355e82972e303326933a03abb5df10ad16e32942c96bab8c84d424599c662f0519dec37704d545d9cbb45b25b1278cd5d5e0",
	        2407
	);
}
static void snarf_hat_2409(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/restart",
	        "829cdaa7cb97f32054a0e4a9953c74e3953a10721767b7e55bfc52fa7cf068581e5292e9744acd064d23d3a26b2f0e082d197538a785de6e76e0c731f5f0e17f",
	        2408
	);
}
static void snarf_hat_2410(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/resume",
	        "dbc0095d02132e78237f6dbe87c535e89bbf695377a4e408d317a38c5a4b4f70877fb230ae390d9c205fe61b0ce7ea47c9fd82fba8074031ad8f2f61efdb0435",
	        2409
	);
}
static void snarf_hat_2411(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/rotate",
	        "5fa2b64af6735290f883a7940bf4042688c96a6e3a1c87e6bc67bd6a08613ccfa7494995ab7bc00f1a6143feaa1ab2ca0a29f30fb0d393f775d6a3dc65c9799f",
	        2410
	);
}
static void snarf_hat_2412(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/state",
	        "0e76a8cb6e1acf7231ba891af59a20e20f4d74708cca14fe1eed3710951b6675b4d5fdd7c74d0e529c22f376ccf8cd7585247bbc42d9d593739537dd0ffbd12b",
	        2411
	);
}
static void snarf_hat_2413(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/auditd/stop",
	        "0591b083fe43955c4835ddcfb89c002c11a6985b252ed7084eb24b6feb4dea1c69ae139046b492d9b71498ad32f54c3cc6435aba2e6866b6f8531ef3638a6b1f",
	        2412
	);
}
static void snarf_hat_2414(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/httpd/configtest",
	        "388e567c9c5aae20518f2eaa608acc4a5e7b1c85e22b7e299e34510d9d1347233759bff1461a375fdc60cab9fbde46feaa9aeababe6cde4fc7687329519042da",
	        2413
	);
}
static void snarf_hat_2415(void) 
{
	snarf_construct_hat("/usr/libexec/initscripts/legacy-actions/httpd/graceful",
	        "e719d906b908ed1206a6854cbbfde2815240653516b6a8c5eb78ceb6110bc68f782ee689141dd348aa80d85b7d24e45200e47293a0ee86e68773915e56a2f630",
	        2414
	);
}
static void snarf_hat_2416(void) 
{
	snarf_construct_hat("/usr/libexec/installkernel/installkernel-bls",
	        "fad75874cfd261e0e43d2e70be7c8d24b404a182069b7f239efc04f7ebef267fa2502e04c46b98e40ca129affac6218482e1f098e4c8362c22177924086edbf2",
	        2415
	);
}
static void snarf_hat_2417(void) 
{
	snarf_construct_hat("/usr/libexec/libinput/libinput-debug-events",
	        "007c6a9d9f6af80bb26b1fdcf7dbafafac239964fa5a7dccc2b43ee72656e47fd72782d7c6a895551e5ba6d4237da8a8c77bc3f2b1282a1ff1c01d4712b307ac",
	        2416
	);
}
static void snarf_hat_2418(void) 
{
	snarf_construct_hat("/usr/libexec/libinput/libinput-list-devices",
	        "ed7d5c224623a53c42a1709fe1dd0934fabe1a54223012459a2102a7bc35e82b7cde87378129decb81e876c6437ec5e98b4368de4cf00c4107ddd8456186869c",
	        2417
	);
}
static void snarf_hat_2419(void) 
{
	snarf_construct_hat("/usr/libexec/linux-boot-probes/mounted/40grub",
	        "6464e797fc382a55d99b18fa42f24b41d3166057918addf585b7f3579bcf4e54c70dcbfe65955b3592172209df04913efadf1cc5aa32b5467a72ffa0ca3406fe",
	        2418
	);
}
static void snarf_hat_2420(void) 
{
	snarf_construct_hat("/usr/libexec/linux-boot-probes/mounted/40grub2",
	        "0f6a25e85bb871a89b6572ee6c975ba1fe16a0534429d1da50c9c2e18a8fbbee19d488ec74566fedd4c8ac27dbf408824807798079dbb8bb9d7f95f8d9bbf1cc",
	        2419
	);
}
static void snarf_hat_2421(void) 
{
	snarf_construct_hat("/usr/libexec/linux-boot-probes/mounted/50lilo",
	        "372c0ec52d21a9dc98beedb1ab68f269168718a6c69551403d585b95ba9b1de081b8f106dcac7b616c59dc33dad1222593b8d93c04c35b3ab84d1662fafbbb40",
	        2420
	);
}
static void snarf_hat_2422(void) 
{
	snarf_construct_hat("/usr/libexec/linux-boot-probes/mounted/90fallback",
	        "0d738315b0f58f65caa247ee51d6dcf1e7656945962df7a0994a0b62f86ee0308ebdfec695292c398a0762bcf33b1a38709d1b44af195c0d0631630cda13b0e8",
	        2421
	);
}
static void snarf_hat_2423(void) 
{
	snarf_construct_hat("/usr/libexec/linux-boot-probes/50mounted-tests",
	        "02f809464d4429ffb7929cb359ffefa4f63e3bae57bab6ff8b768c602c0b67de006055d942172c44926e473159b64058d163fc60b0d8bfb8f20e9a14ec382695",
	        2422
	);
}
static void snarf_hat_2424(void) 
{
	snarf_construct_hat("/usr/libexec/man-db/globbing",
	        "9ac7610d0035f6b065b44fcb984ec7b8b5dd165b2660bad376ce6530ce098fb9cb03d37fc6cd6740d532749df1a1f0bb99a85405f40b3c3a901d43b4863449df",
	        2423
	);
}
static void snarf_hat_2425(void) 
{
	snarf_construct_hat("/usr/libexec/man-db/manconv",
	        "ae6abffc5047d578de2f06822b2cc5c69eedd12b6154a0e61e9b81f805e19cae7b521b6a695424d3f2ac2a6744142590ed29caf534cdbe9c0d2ca4ea36e11616",
	        2424
	);
}
static void snarf_hat_2426(void) 
{
	snarf_construct_hat("/usr/libexec/man-db/zsoelim",
	        "81fade7691314b576f59c8b21d1b99472c7b396eaf15b01972d8459516b86a84811de5b4fad78f91f82783453b4e3dcb890cb233ce690e792be906a136df1971",
	        2425
	);
}
static void snarf_hat_2427(void) 
{
	snarf_construct_hat("/usr/libexec/nfs-utils/nfsconvert.sh",
	        "6e373cc6150f080d139546842c9102ea55af9e7a8ad58f588eb7aea56a65bdfdc4b3c98e0381ca78020394045b6bbf7748626a7e93f5176d8fea2f5a14a54104",
	        2426
	);
}
static void snarf_hat_2428(void) 
{
	snarf_construct_hat("/usr/libexec/openconnect/csd-post.sh",
	        "2045ba83b9e82aa5fd8cc61aa99dc47e8544dce74b8bb9b888e0d4baacbc0a54a9ebc635ec58fb72398c5fc9b223b6971254503eb11deb0fbf23cf57ac6dad56",
	        2427
	);
}
static void snarf_hat_2429(void) 
{
	snarf_construct_hat("/usr/libexec/openconnect/csd-wrapper.sh",
	        "e9264f4043a55c952bc26e69d436d0ba1908e406136c9a24df5f98b4d0a28f561d3dd4e8d2585d57aab7ca7de9ae61c1e5fa3dc4fe7386a0a26a21c913286dd0",
	        2428
	);
}
static void snarf_hat_2430(void) 
{
	snarf_construct_hat("/usr/libexec/openconnect/hipreport.sh",
	        "0b27b213da6dc35572dbb1e775e1dc2eb1041edbb0bbb6c03d3f42b5c695280556bc4ec1ed197a2fdfa9768dc26b2caca93fa623be04091fc5680d6d181c16cd",
	        2429
	);
}
static void snarf_hat_2431(void) 
{
	snarf_construct_hat("/usr/libexec/openconnect/tncc-emulate.py",
	        "ec49d3e06b358c337755a86cf701c6c8555e26d8e53d238c1380b70a8d61755bafb6e8a36e4b3897d800cdd5f7c40fdf21390ed5fe61b8c6f447e97fe3d81da2",
	        2430
	);
}
static void snarf_hat_2432(void) 
{
	snarf_construct_hat("/usr/libexec/openssh/ssh-keysign",
	        "2dac77b67d575d054c6754bc38ffbc7c6296935de95c5cfa7be048fef345e533a06bf3046ed83137258694e88b5619c4a660437d942ecd298f9852e71cc40b8d",
	        2431
	);
}
static void snarf_hat_2433(void) 
{
	snarf_construct_hat("/usr/libexec/openssh/ssh-pkcs11-helper",
	        "3440e24fd5374cfdf7480c58d3a280c7d8f680878b0f0ae4f4e129ed5317c451e351983fde4369e88605e440ff1c6642476ea966d6c1c43cd9f9c6ab4f7b22d5",
	        2432
	);
}
static void snarf_hat_2434(void) 
{
	snarf_construct_hat("/usr/libexec/openssh/ssh-sk-helper",
	        "fe38579de7c7be7134a423c7243e9c89514a99cc0e8211f81f0f418684bbf01293aaf6270f4207fbc6cec2e919cbd8df3af340f16ed58e4ee9bb1b6aede33b66",
	        2433
	);
}
static void snarf_hat_2435(void) 
{
	snarf_construct_hat("/usr/libexec/openssh/sftp-server",
	        "ae63c8b39c2e55c447ca534d7696eb5da410e38f72049c4142deb24c7beece90d464bfaaf8cd2d672815343082acef417b02d46cbbcef130c1d16ba0a99a9b23",
	        2434
	);
}
static void snarf_hat_2436(void) 
{
	snarf_construct_hat("/usr/libexec/openssh/sshd-keygen",
	        "7aed32111e87ad3f321c36c8746c356731ec087790850ee5843f318b1dfcf65f5a30cade1799ab7849f38465a89a09bb5254c02e6b14de71795230aceb4ed16c",
	        2435
	);
}
static void snarf_hat_2437(void) 
{
	snarf_construct_hat("/usr/libexec/os-prober/newns",
	        "40b9c2f194c8ad658efe1c01eafa097240fa4cdecb67169d8ceef10955f98d30a74bc032b492cd75f93ac466099575479de836f2e72b8c8469ec6694efa1d6f5",
	        2436
	);
}
static void snarf_hat_2438(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/init/10filesystems",
	        "0fdac75ba66ccf4c07d38b50d152f8717ffeaee3e095eff93e886643ca01e266dba33259796c4f3c9959c359de25de628e82cf4caf082b9f8a35054e47440b75",
	        2437
	);
}
static void snarf_hat_2439(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/efi/10elilo",
	        "e22b8108e3c1da59f57244cc99253435a90c40d9dcddeb89ebd26150d89bd38f3b6cb1fae5a6f889e07e8d03b4edca3ceb2229ef7160b2ef785d7a89b19a238f",
	        2438
	);
}
static void snarf_hat_2440(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/efi/20microsoft",
	        "46d7d1ca36c460360fcb4f027cf7c7c0c5d9dd9b1ac0e5d85df5f845f9b2796470f9774718019ba6b9939f451a612034f8b492c8cfbf0e665f6b5da23bf2a83d",
	        2439
	);
}
static void snarf_hat_2441(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/05efi",
	        "d8091a506a3c1abcf77aa517929c669d1a97a0ecc710a37419bdffd232e63ba66b393d1be3db67da1e658e011bdacb8c495344d091bfe5aa4bb1f7c1a0b0a259",
	        2440
	);
}
static void snarf_hat_2442(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/10freedos",
	        "634177a3b76b56baca7327e6556942236f2377254f55f969b7b42648312807dd1847b2fbc4296d6bc963ef77f8754fffa80611f154def0915fcb07812bb9a8ff",
	        2441
	);
}
static void snarf_hat_2443(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/10qnx",
	        "ef8ac120b5d86ffd208febe9fad3d392aeaa97cc9f3d1c2e894ff7831f6fa05554a282e21bc4d4219ee3b33853cf8d34f286f991ae85cdbb412e3701ea002d17",
	        2442
	);
}
static void snarf_hat_2444(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/20macosx",
	        "7901b340e2ce6db9d8dbe85b0013d8c94b4cff069ec482f8ffc3f2cd8eeffc8593d52f8b7c9f173596996d47edf9af843b166a5ebfd4a001fd917fcae889356d",
	        2443
	);
}
static void snarf_hat_2445(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/20microsoft",
	        "c19195046b8ecf1e14445743a88dc851f9ba61cde0b444645cc5958ac3fac37a3942565ffacad70d6387876787509a8aaf684b879cfac8ee9221ecce096724e9",
	        2444
	);
}
static void snarf_hat_2446(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/30utility",
	        "83e5efad86c7b13773db3828800b1986352c59cc091b4a531c86db3927bcc55f133c1e970ce60a1bd993c098cf2d924562e4357941f7e34f682700ca010caa1d",
	        2445
	);
}
static void snarf_hat_2447(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/40lsb",
	        "04dd1af4051656b0fede6ace06f83bb44f96389bffc1bfbcd1b0c0bbb1616e602eea45749a74bf3e779e6eab83e109b48ae456c598f3e6f74e2f57f2b14d3d35",
	        2446
	);
}
static void snarf_hat_2448(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/70hurd",
	        "499d09d044b67285410d4ca390bf5ec0fd2fd0fe9ff607b4758154043fdcfafc260787cbe2449f48fa70101458a97f42af2fdae04ada66d9b14d31828ee0bfd7",
	        2447
	);
}
static void snarf_hat_2449(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/80minix",
	        "4f2c66707d807e3f91e268e33a10aa999e217db860760488c2bb35bfb4e7f152248dc60a36c07aa151784d73c06c7ad1ac4d21495f4e96fd3d4457b48a98f4f0",
	        2448
	);
}
static void snarf_hat_2450(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/83haiku",
	        "166f08b714b5cd3262d325d3aa395e3c7f2675ed042b3d4aeea62df6ba7f723d9a1ba6b6503fddc3180b7864c3e3520bf6ae33a561d47b4096c95b3d6f6a80d7",
	        2449
	);
}
static void snarf_hat_2451(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/90linux-distro",
	        "3f7287b736f2bd2b9bc44c8f6f2016634ad444b6186c9700cf65be5010c415b21f9fcdbf98ed3e6bc1137b76d2a76650faa30c447ce3a3168b1be8ee5b5e88b4",
	        2450
	);
}
static void snarf_hat_2452(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/mounted/90solaris",
	        "d5ab685d21b044aade0a49597fc1875286fc9266b88f37672ac51c82cfe3019e9479aedf73f97fd6f5d65797a7d99e46b9e2496e950d07fc9b574bc7c834b5e5",
	        2451
	);
}
static void snarf_hat_2453(void) 
{
	snarf_construct_hat("/usr/libexec/os-probes/50mounted-tests",
	        "13d820ab5b3a417e4cfc0ba7e5882eb7e1a407eb03c6cc62ad6b0fb5a74c55dbe8f04e63d2fc8b898422a676e5f6e98ad6c7e9f92af38570bdcac51efbb42ac2",
	        2452
	);
}
static void snarf_hat_2454(void) 
{
	snarf_construct_hat("/usr/libexec/p11-kit/p11-kit-remote",
	        "11657af29054998dd8ba30d66e249e72f23b722f62b944484211ec370a67f6bd57c1e15fe8829881dc26a300c8e9ed1e33f67bb1fdd5a673f405b61daa5c99ad",
	        2453
	);
}
static void snarf_hat_2455(void) 
{
	snarf_construct_hat("/usr/libexec/p11-kit/p11-kit-server",
	        "0fef99e8a4dc5fc4ceb63a9eaed788dc041c89f69c8be78cccf32337bdf2f6830b4a98c635025c65408493b5a44958ee5261369ea9e962f2bb84f1f7c48a7d71",
	        2454
	);
}
static void snarf_hat_2456(void) 
{
	snarf_construct_hat("/usr/libexec/p11-kit/trust-extract-compat",
	        "91210705f9bcf1a13c0de1ca9943e3ac68296bfcb7953fc59241de060247b470b39be6e914dd4d92e38a78d5df0962c83315ad78f8c0eade8e62d884b05fdd42",
	        2455
	);
}
static void snarf_hat_2457(void) 
{
	snarf_construct_hat("/usr/libexec/plymouth/plymouth-generate-initrd",
	        "f010e72a928c6081e838e886d6fdfe2e0242804b4bf1da4f54dddbb469d5afba75b65c7c54b1eb73c97d88a146969195a71382e85a4367cd1dee70acefb451f3",
	        2456
	);
}
static void snarf_hat_2458(void) 
{
	snarf_construct_hat("/usr/libexec/plymouth/plymouth-populate-initrd",
	        "95ec6277f30828110a2efeeb14dd25e92b820c4ded17da2d78cb697dc68481e3c1cfb3c8d0e45bded63f58cabddc636290e82fab4b8f31ee3acd8064396977db",
	        2457
	);
}
static void snarf_hat_2459(void) 
{
	snarf_construct_hat("/usr/libexec/plymouth/plymouth-update-initrd",
	        "6fec9a04c7fca01631f885efb0ad29383937073795c9e4fe1f365253eb4b77d0fb2489de70a611fa50c1383297b5445cceadd09b99103b50e1f05f0d56bb4569",
	        2458
	);
}
static void snarf_hat_2460(void) 
{
	snarf_construct_hat("/usr/libexec/plymouth/plymouthd-drm-escrow",
	        "45714246af66f045609dc5f71d0f7e1aa7b2f693d02680b09903ad115b77771702c47cc8d4da63f68de92dcb79f04c3ac78dd8265c034a5fc4961474915a1bd5",
	        2459
	);
}
static void snarf_hat_2461(void) 
{
	snarf_construct_hat("/usr/libexec/podman/gvproxy",
	        "5a85f229b743744b1d4328f242176bb0347a9babb3ca2109f0321afbbf724a5ca440258cd9e621fd0762044c70c5e6a58a2914ea4ff358b16868a8d249782a0e",
	        2460
	);
}
static void snarf_hat_2462(void) 
{
	snarf_construct_hat("/usr/libexec/psacct/accton-create",
	        "3254ff8ca68c3b439dbf554d0fb75512ac10743af6e4faee007253060ecc3f5a9dbee868fe0a1049c63fa6dbe5d3287c93cea41008034bcf116b72f4fb3a1e53",
	        2461
	);
}
static void snarf_hat_2463(void) 
{
	snarf_construct_hat("/usr/libexec/rygel/mx-extract",
	        "1a9bdb959cece3db17dc73eb6d2be815ea78626681a7db94674fe11b3c43dd86edcf9d0eddbf41b76631820a690d8aec0081b02a5676b5511032be480b3adcbc",
	        2462
	);
}
static void snarf_hat_2464(void) 
{
	snarf_construct_hat("/usr/libexec/selinux/hll/pp",
	        "112ce2dab468b161a0488da3975360157ef40a5baf0d7357b2fa4dce694b54dc39f1af04a0b30e1da5d8855f6164ab51841ac08f6410573e0e161174e976c59f",
	        2463
	);
}
static void snarf_hat_2465(void) 
{
	snarf_construct_hat("/usr/libexec/selinux/selinux-autorelabel",
	        "d96dde7859df340ad02a3c9b4aa07daf329cbee2f0131e738c76671ee3922dd2039ace63ca4457ab0f76a4f7fd49677ed5fbd5d08b82cbca4c16b6c34e555f48",
	        2464
	);
}
static void snarf_hat_2466(void) 
{
	snarf_construct_hat("/usr/libexec/selinux/semanage_migrate_store",
	        "733b9d79ba7f0a59686ac649e283d0a56420965a5e171c0883aefdc1eb7f4342518426aa539400a59adcc0db9029eb01b3d2e390aa57979e3526d6ce97c953de",
	        2465
	);
}
static void snarf_hat_2467(void) 
{
	snarf_construct_hat("/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
	        "a66e4c2d1ed3e4fed74fc3902c96930adde31c33d2a5237c9f6f9808cd5d0dc24843243e0c1606758700d3da0f8c2c0761b75867dacbd8ac5bf51557da30ae71",
	        2466
	);
}
static void snarf_hat_2468(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/p11_child",
	        "6c0029a334503daa52688594b266d029e18810d07c083ebebd2b763519327f16c0fac478faefd50ed81aaf118b42e50e7c683331567e0afeaddd8b5f381596df",
	        2467
	);
}
static void snarf_hat_2469(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sss_signal",
	        "14d8ba25f8d2c433b68f73da3c843db2ee36da6ceb4e2277ee3b49ed9fef06bf11a5d27ea38b85c2622cdd08a1ede67bf1f82efbe4b7457e7d0edd0d0df0b289",
	        2468
	);
}
static void snarf_hat_2470(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_autofs",
	        "663154ae86760c05472e07c035773be0980076334a52a2f8cd484617dc24d76ffa6630a1a303c0696fbccc0c9195bb3e51abca8cda4e2b09bdce7bf1e3e308dc",
	        2469
	);
}
static void snarf_hat_2471(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_be",
	        "1464f4ecf34ffba09a56210595ddfe790dd43e4d66689049cb786a53ee2291b0d9de6757a4300c9aed31ba25f767721c40c11930dfd76928aae17a498e37d729",
	        2470
	);
}
static void snarf_hat_2472(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_check_socket_activated_responders",
	        "bb9c472982f3e6a5c3d48a310b7f04d8c19d087f91e4ddd000560118326592be528f1b0958a033899e42809a5f6501e59b7c964ff29b55390976fd8685c11661",
	        2471
	);
}
static void snarf_hat_2473(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_nss",
	        "233a0bdaa1e3550ef0de0c31c2edd39cd87146055ae751f9231821d1ced5e8c5e5319bc0d7d798ec52b3fa7b65543907c69596482eada020775b44bd8bebb03a",
	        2472
	);
}
static void snarf_hat_2474(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_pam",
	        "89a723093629fed75bfdfd66752ca68ee903742471b31d22b3cb16601e216d7786cb9479665fcccca20ca4e60f8c7be4fad47c9d932645e1788bf555bc06e97b",
	        2473
	);
}
static void snarf_hat_2475(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_ssh",
	        "beb751dbff7ffa5b35d439ef2ca8e358dd881e3ad987c6796371511c94458ebe947cb0a2415c2232caac05ee240e23181f4e0692969c48a224e4c0914b7f19a6",
	        2474
	);
}
static void snarf_hat_2476(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_sudo",
	        "78cf4e64a7413aa199266510ae23f6699f9be8f87160ccf822537490f9717693c59bffb327aed12236cc35dd9a35803fc8741dfee9ce00e10db50767806c4dbb",
	        2475
	);
}
static void snarf_hat_2477(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/krb5_child",
	        "e3f37489b494f9b0c3e375fa03d2df72a102ed7550b1f1a8a6f4d304d7065befdf4fff9c5debd54b7e0755e6eac74871d44589c74b3c7b0990058cc258c74a35",
	        2476
	);
}
static void snarf_hat_2478(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/ldap_child",
	        "afedf6d55a77942a32c987d4a50dbe966e78a1bae70d916066f2daaad448cb7464406af19be8d376fdb19916b6ee79e603e2e6c52d8d7a35939d0f38839e58f2",
	        2477
	);
}
static void snarf_hat_2479(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_pac",
	        "d8f76039860fc2a217dbbeed5e848cfa1ffc45c6467ead923f5525e0de5cb49d25a252f16304c6d55d929f729ce67c8294e0c04f0edf2eaa7bf298b8a63e693a",
	        2478
	);
}
static void snarf_hat_2480(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/proxy_child",
	        "66ac76ad9aa17d7ec6b6accb3873cf0a25201f8d68d24ab4099e117645a64501c3e93c8978b85fe62821e1a51252622e9e6182cf176c1b52459d98872611605c",
	        2479
	);
}
static void snarf_hat_2481(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/gpo_child",
	        "39f73fa97293a7523d9ffba6ea1631ed8e8f3f0a9bd7c17764dbadf00f2624da49de36bccf2cc9e626b606a377474aaf9760943daacd467530b2084b8b7fad96",
	        2480
	);
}
static void snarf_hat_2482(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/selinux_child",
	        "9aece2f8d2916f72ec985dc31aeee02e879579d6a369a9488bb76c16c0075f756a4bf80b0bf09ff93c1d7aff417df3c7e9e8a943dad96002b7a04a4aec1a1a47",
	        2481
	);
}
static void snarf_hat_2483(void) 
{
	snarf_construct_hat("/usr/libexec/sssd/sssd_kcm",
	        "b74f6df408ac8a2e4ad08c9f98d63da24c375de9fb5e732405193a12e17737ab0f43bad9c677775593d98fe9eca74512eb3197c3ab9223e1dc03892220176d2b",
	        2482
	);
}
static void snarf_hat_2484(void) 
{
	snarf_construct_hat("/usr/libexec/sudo/sesh",
	        "4a4505b1263929e8f204fb72a796dbfde24ef27daca0edddf713c2647c5af537df55d19b72334a8c648e59ff40117a72dd237a995de24f209327c58ee6d148bf",
	        2483
	);
}
static void snarf_hat_2485(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/daemon",
	        "4436d805d7788f95e4a25e19dbf72443b24aca2e450c3a045a833ce2ae20fc3239f556bfa06fbb2d2fb16eedb6e58a0ac3a81f8905fbe59a4a5ce27699b6f187",
	        2484
	);
}
static void snarf_hat_2486(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/extract",
	        "2ba341ee3176f3c85b61e9c700a7c546e1bcaab11d04e3a07a31677f012b6fa3936d68f2872e914c8c44911fc9e2d9af752b76e8a1fd461b3aac9f44e4ae43bf",
	        2485
	);
}
static void snarf_hat_2487(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/index",
	        "9be82ca456cc61627eac32d69d5bb75babab495040120e10d465e1cafd718b30be24026de3e93b918e17ce76bd9cd9cdcdc7ba804053a8d06e6edc1036588ff9",
	        2486
	);
}
static void snarf_hat_2488(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/info",
	        "5520fff3d0810c43dd1d3cc3ebb64ce9d081d98221b980eddc981b17d15f0121d46e1185ba132fc0be7812510e71d81e516b960a1e948cecc1b4236093f3efe0",
	        2487
	);
}
static void snarf_hat_2489(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/reset",
	        "7a11964f12dbd98534572f26b0f0a88f71aac0c8d19fdb506b18c81d7bef33be749a6c1d5dda8c87a903696be1149f2096b941fd20d64bef28387c4647a0e170",
	        2488
	);
}
static void snarf_hat_2490(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/search",
	        "8c1e8917fa3759959e983af1939085b1f07e28b634dab8101b243d9e6438e53d622118336752fdcb4812b032f892df030cbcdd9ab1e41fb5596f717fc925a5b3",
	        2489
	);
}
static void snarf_hat_2491(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/status",
	        "8234e4dc2601c154ae1b10f499ab539c66d2ce1ed9ef45e977802baafc1cd1da26464f5d7fe972066cf48ec5aaa8eccbd1908df979d08b2e5399b48cfca302ef",
	        2490
	);
}
static void snarf_hat_2492(void) 
{
	snarf_construct_hat("/usr/libexec/tracker3/tag",
	        "fb2c919319af76b208a31cc4bcc3112217f044234ae4fe9b3823b7ac1add22723a8c1340570ca6cab8ec4b19ffbf6ee7c1254ae60b4fa6c3bc08312710bb9289",
	        2491
	);
}
static void snarf_hat_2493(void) 
{
	snarf_construct_hat("/usr/libexec/udisks2/udisksd",
	        "9a55ab3dc1bb72885ef7e9aecc6e6ddac6d2726ec104c8aab4741bc4a9903914587641b40ec03001183b7c3666774fc0638b2dfaf47263a15f0752d782ac6f76",
	        2492
	);
}
static void snarf_hat_2494(void) 
{
	snarf_construct_hat("/usr/libexec/utempter/utempter",
	        "0749e7173f6a87d946d15a8d0241d3f8f2fd9e9a2699914bb66808cf03edb8d4e98723ef001c8fd6323d58192a514d4da1a765486700fee6069ef17ec13ed5fa",
	        2493
	);
}
static void snarf_hat_2495(void) 
{
	snarf_construct_hat("/usr/libexec/webkit2gtk-4.0/WebKitNetworkProcess",
	        "d1786414b7bf5c03ac2ffebe5a5a82b89433496772ca15896f9949048c50f1164f8eb3e0e0736868608b8dfdbf2e980d63d209eb9e5a283cc1875ae77db4c227",
	        2494
	);
}
static void snarf_hat_2496(void) 
{
	snarf_construct_hat("/usr/libexec/webkit2gtk-4.0/WebKitWebProcess",
	        "837d7225cade557d752f32bf09bdb2d22b079d06663e6e9b2bd05e99e63ea047eea247f06b6ed18d2c90ff3c1a3b126fb807f472099963ae7d387f2cb84265f5",
	        2495
	);
}
static void snarf_hat_2497(void) 
{
	snarf_construct_hat("/usr/libexec/Xorg",
	        "11e95db9c65f6397b4d60fc163e56956b91781a2070ab1bd434fa3ae6773999d499faaa784f4f00eef8e289a20993a78f2eca5d3765206186f0c535d781d0d97",
	        2496
	);
}
static void snarf_hat_2498(void) 
{
	snarf_construct_hat("/usr/libexec/Xorg.wrap",
	        "aa15fa1a8900305a58c9a04b490d5a6cdaa028ef2228fc69e285edeaaa1d224a8960d7316715d7e0ca08586180ffbf87889eab279f68e928209c8a4e20ae4153",
	        2497
	);
}
static void snarf_hat_2499(void) 
{
	snarf_construct_hat("/usr/libexec/accounts-daemon",
	        "6290fbe02867a76a2dbe83d5387c658584bb52afd63f55d975539a79f4350ccc0169eccc3e074af7e3303d87fd7076d74790caffc11f0f2d587f8d33a600b33d",
	        2498
	);
}
static void snarf_hat_2500(void) 
{
	snarf_construct_hat("/usr/libexec/arptables-nft-helper",
	        "d2a1a4b624a379326f81e5fd5f58c91499fe6527f20398c6af3e1e19f02d2b2757c75b04520753d55fc6e9c418045a4003a12856d9011d853c9fb9ef20a661f8",
	        2499
	);
}
static void snarf_hat_2501(void) 
{
	snarf_construct_hat("/usr/libexec/boltd",
	        "74225ec3cb6bc767e8a14376c7f05aab06ab950b4c1352591b0279cba3008e6ba93a6cee878b1791397968128069a6b3d155dc2d394d7b4a3f51268e824effa2",
	        2500
	);
}
static void snarf_hat_2502(void) 
{
	snarf_construct_hat("/usr/libexec/cgroupify",
	        "65642347a97b1047104673bd2693b00ea53d1c307c2d5ba8e6c9cc97848434aa409f72018f843c6455db2c2b098072bc9d0050690f2b24b23c00df4c17dde058",
	        2501
	);
}
static void snarf_hat_2503(void) 
{
	snarf_construct_hat("/usr/libexec/colord",
	        "c599e88f011fc14ee21d2b3115f8842e88e595d1f0987310eb87f5b6a58f644e9434b5668fbeb1b928fca89fa0cd2bd7feb0f7396d3d093d5a3c5086e080dc69",
	        2502
	);
}
static void snarf_hat_2504(void) 
{
	snarf_construct_hat("/usr/libexec/colord-session",
	        "31deb9547523298e654316ac2bc08ed111715045e7af43169bb2fc8104e4a432886cfa64402884d243e72844a2cc6b053b468fbc5b0851b89c68e00dd1ff669d",
	        2503
	);
}
static void snarf_hat_2505(void) 
{
	snarf_construct_hat("/usr/libexec/copy_jdk_configs.lua",
	        "a792817812e26a29106f2a45977e2d28d1cb6264338fc9af833ecdd3f265bf77fb1a8dfec0f1ed2aef0ddabb0b4ca4e243556cf99f5904a22f3f72e71b5c128f",
	        2504
	);
}
static void snarf_hat_2506(void) 
{
	snarf_construct_hat("/usr/libexec/copy_jdk_configs_fixFiles.sh",
	        "6209d1a81f3a9625c693c4825e568f10e779b6c89fd86275a09c80b8ce2b37c0b755a7c957e9fe8db3f1f3ced724a37074542d8e82431a8c997bbfd512a40af4",
	        2505
	);
}
static void snarf_hat_2507(void) 
{
	snarf_construct_hat("/usr/libexec/cpugovctl",
	        "50f8667620b729c74cc4a37bc4d6ea636a217390d505fd2f158177ae5d109ae438a159334ddeba41b23423f7cbef9c630aea47267030d34f447446aaf8ca5d2d",
	        2506
	);
}
static void snarf_hat_2508(void) 
{
	snarf_construct_hat("/usr/libexec/cups-pk-helper-mechanism",
	        "6d81f1cc7a5f02220135b303641cc5611a0d2c95266cad1922dcc02dd0759b42f75d817906c34a12b14319184b5200cff405d0bcb65055d2bebf94d098072564",
	        2507
	);
}
static void snarf_hat_2509(void) 
{
	snarf_construct_hat("/usr/libexec/dconf-service",
	        "66215ce50b94604994aa0e03544db51cb25164005155ba968e257238eaf3518e5c3f893b9754c8d3eeb4541a5fbf9f8a7eede24d5306f68ec5eda2e99bcb5bd8",
	        2508
	);
}
static void snarf_hat_2510(void) 
{
	snarf_construct_hat("/usr/libexec/dleyna-renderer-service",
	        "d66b8f1bb9573ff49c15a845c1c449c0ba425397d9c7ac37d3585f1dbd86ae0d7887474ccb84ab22f6f60787cf0475647ed5cf91a46d5d40c29cb9996fa8f7f8",
	        2509
	);
}
static void snarf_hat_2511(void) 
{
	snarf_construct_hat("/usr/libexec/dleyna-server-service",
	        "6acb7b117a9c7f77edbb7eb879918c1ec5f06839c0cdb72b14425acf61261c4702a87d7b6c8f4a15d1133ffdedeaf967566eb6994447d12fc5357f1fa375d109",
	        2510
	);
}
static void snarf_hat_2512(void) 
{
	snarf_construct_hat("/usr/libexec/evinced",
	        "fedcd515dd617caac8730d24cf941a88066b9c02fb3563bafc792c30ee9ee331e6d0dbfc7d6fa705657d66cc0ad4b39a9d4dbccc8b499c7329cbac598c152320",
	        2511
	);
}
static void snarf_hat_2513(void) 
{
	snarf_construct_hat("/usr/libexec/fprintd",
	        "adb660fc0bd132fae2d4819cf38520703bafd5345693f9ecb92296c12e40f33e9201aeb69608eeacf0181268d5399305e057be84d6258a910d75be51379a578b",
	        2512
	);
}
static void snarf_hat_2514(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-boxes-search-provider",
	        "43b095a99e49f54ebed6f67a766fa1c43af2390fed7e73f46887dadb955372bb426dd083de2e079b2d11a5d4ad97ac6e59fa52179bbed78ffdcd0a577ed183a2",
	        2513
	);
}
static void snarf_hat_2515(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-photos-thumbnailer",
	        "ba305f8c1b3945701d4c422534d70abda6560db38aff90f36c4be3283f9a3acf46f06f0002059ee40a89c3c49f32464a1a161f31ec6d2e88c6627321f40c545d",
	        2514
	);
}
static void snarf_hat_2516(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-user-share-webdav",
	        "8e0f7b5f4b745566b068b1b8cfee4fb8362e3b879a64eb88c924a6d9bc3d5a62daab29d4422eb6e3a2199d7b9714fe76028f0bd0cd3888629cd344ebccbd8bc5",
	        2515
	);
}
static void snarf_hat_2517(void) 
{
	snarf_construct_hat("/usr/libexec/goa-daemon",
	        "d5951d503a6b6ae505c9143948a077ae7a935754a4107983cf2aa1baafee0f63d0c4b8da5879981b0ddda81d9b31185918a3cd4fe7d604b6910e3f2372704649",
	        2516
	);
}
static void snarf_hat_2518(void) 
{
	snarf_construct_hat("/usr/libexec/goa-identity-service",
	        "a28ee736e0b1aa917ef1e8f1dba6eabd379364548be6efb7762991fe98887935a4f7fa7343aa4cd478468ed06809ccf79a96f9f9bbe083f571b047e5e6604688",
	        2517
	);
}
static void snarf_hat_2519(void) 
{
	snarf_construct_hat("/usr/libexec/gom-facebook-miner",
	        "b03ae17de4189d32348263e3d1f2d732af7003c08a7d4b8906ddd4e3dc1c82c80057d57651307a2ae3306356f47eeb21b848a3a346fa338ff58f1f2a282f8bc6",
	        2518
	);
}
static void snarf_hat_2520(void) 
{
	snarf_construct_hat("/usr/libexec/gom-flickr-miner",
	        "c9943a6197a2583a7c5195bd2973bebb010583a93ca34f82084817388c5ca71c83cccf862b047cbdaacea69d9ab423d6e69b21845fd005d5dae29d1c1ee3d743",
	        2519
	);
}
static void snarf_hat_2521(void) 
{
	snarf_construct_hat("/usr/libexec/gom-gdata-miner",
	        "b68c416972222e8d6aa46360a744c3860477855e9624c18a6992dc9d122c1693dde9beaaea83d68712d4784c57aa1ec99dc276da4b319db9d72c162333baae83",
	        2520
	);
}
static void snarf_hat_2522(void) 
{
	snarf_construct_hat("/usr/libexec/gom-media-server-miner",
	        "14a2fdd6509b697e269111a00a1ffca724444d180965cb8178e549fc1dae8408157041e492bc8eab3d22bba4ab8a71c01e9beabce493efb0f00aac85cd936e39",
	        2521
	);
}
static void snarf_hat_2523(void) 
{
	snarf_construct_hat("/usr/libexec/gpuclockctl",
	        "5b596fa68d22de5839024f9f1750bef3a7bdf275176fe5efb1e0ab27da3787f4829b854a0eb4dd3256ffb7d263ec43e14abd997f38122ed14aac8db585bb7c57",
	        2522
	);
}
static void snarf_hat_2524(void) 
{
	snarf_construct_hat("/usr/libexec/grepconf.sh",
	        "260c099d7c1a4c9256883005f9b2dd02f1814d6ecabcc78cca5ca13e523a661091047e55c8000fbe937d681c44a92ba70dfcaba51895bd8fe08ef022ec819de0",
	        2523
	);
}
static void snarf_hat_2525(void) 
{
	snarf_construct_hat("/usr/libexec/gvfs-afc-volume-monitor",
	        "719b95ac559a3f0a57cd6ce0f6cac79fa682ca72336c41e377e006b577ea0c4d199d17430f363fa837afa9c41f5b193247c4c3c90ad1cd72682b6cc8f72f9246",
	        2524
	);
}
static void snarf_hat_2526(void) 
{
	snarf_construct_hat("/usr/libexec/gvfs-goa-volume-monitor",
	        "5995b87d38d895d5eded7d008921a9a1be73f2fcc880418e988e60ffc9b5b5550e8300237ca6baaa652d7677b83725ddaf7a6968716e9203489446e7a0dacefb",
	        2525
	);
}
static void snarf_hat_2527(void) 
{
	snarf_construct_hat("/usr/libexec/gvfs-gphoto2-volume-monitor",
	        "0b3cf2294b9c37661698fe1edc478f8518a79a854306e46a6ec13ec8ad3b3b0098710869efb5284d5511d385192474be3d2be1d2d9d085ef388d6cf381382db4",
	        2526
	);
}
static void snarf_hat_2528(void) 
{
	snarf_construct_hat("/usr/libexec/gvfs-mtp-volume-monitor",
	        "c06d0c07b35f58e5787cb9f89a9acd30f148af3a114e7b715fdc825a85b414ec761a167ee957d1bcfbd14e7991cd0ef0b8fca03b2b88521379fec2a20168c75e",
	        2527
	);
}
static void snarf_hat_2529(void) 
{
	snarf_construct_hat("/usr/libexec/gvfs-udisks2-volume-monitor",
	        "7839e870f1920ecdb8ad080551695460850fe236e0cf4af3d2c78f5d33d136acf6937ca688809666bcc219626c9f9606e76ca0a9d10fc5b2e3b656d1c7163152",
	        2528
	);
}
static void snarf_hat_2530(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd",
	        "8232b2af90df81b0cdf97a635df1da09041a82d37cc96b63b1bd099b2dffaebc218958d1e217003dd2f7eb9c72c27253fbd383eebb4877e0fba144ff7f59298a",
	        2529
	);
}
static void snarf_hat_2531(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-admin",
	        "0b869f38f8ee6908a0c9560fd60d87871c4d1ec36692304283765903b5c77e93e4799cc287577b32fbacb9a57dac33abe2d5c2a1ef578847daddc213b969582f",
	        2530
	);
}
static void snarf_hat_2532(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-afc",
	        "21835f446af360c47d5fe049f5a71314f0863575901c2f8d7bfea852e380b34034ff48d5d9601c1bb9ba22ddcd7c54e5882a942c36b11360cb2f6fbd65e8def2",
	        2531
	);
}
static void snarf_hat_2533(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-afp",
	        "9906c9fb870e93d81570361c71531d6d26e0d660910aca67cd30601c804767202479f020bd09d1767cd36493876b5629216c76ed11e4d07253bf02aa48b508e5",
	        2532
	);
}
static void snarf_hat_2534(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-afp-browse",
	        "f668fab86a44425ddb2ed29437b081082b3d164c763d025cb10885a11fab7485432c7259ef3f9e05d23c4252849a42b8133e5f36cb5c4cbcfbf89895590e41c0",
	        2533
	);
}
static void snarf_hat_2535(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-archive",
	        "daab0662254f2010ea4059ed53442a3f37540871e35bd0bdbfd6f0307cea161a3fdb65f50907bb114997665775008204a8743c87246fe32b83964f000cbb3a3f",
	        2534
	);
}
static void snarf_hat_2536(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-burn",
	        "63fe26e9dd7f7604125f4d8b5f0b86cdb562b65d86de3cec64a0f77c74b9a2358bc116094851134495aff1089724bfa7ee844cd8081913a7533c98d23efa9fc3",
	        2535
	);
}
static void snarf_hat_2537(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-cdda",
	        "0c0880785326f2bdea8be397e93df3675e338f4128c8a8c8dfe6b1c642c80042bd0436662ca1ea8e6913a55c302c1275a456061f6edc87ea47b7c66dfe6359c6",
	        2536
	);
}
static void snarf_hat_2538(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-computer",
	        "964bd4a4efb198ef7934980705a0f594a34ceb56e903a6f396350d6874a551d420497290cdfdc19502e5251a521e7c54513ec189f3b3dfda03310bff7405f331",
	        2537
	);
}
static void snarf_hat_2539(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-dav",
	        "5c7ac572af3692706fc8a76bf4b2ddd8a80dcedf2ba65795c4036151f7fbe92fe2ecf2b5454a2befa394ab9b46a4e12fa7f0181109a0ac4dd39cf1235370b688",
	        2538
	);
}
static void snarf_hat_2540(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-dnssd",
	        "cfbde14c670f53fe37a3e1b0f2fb97d87092b2b211936c3eb5a44bb13b44c122ae98057c827ed402035dc1efb1a9507236c223d98d7e58cef297044f90bc0f9f",
	        2539
	);
}
static void snarf_hat_2541(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-ftp",
	        "dbcfd6b6315fc109e6f49e6a08ef12fa92a1516a8f64c626a4e7076c03343e7d97e55a490ca9de45d78b39d35214db1c0f287eebb7cfbcc4521638c27ed99e20",
	        2540
	);
}
static void snarf_hat_2542(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-fuse",
	        "39be1138a481892f8bb25ed8017aaf6884bde730713fa7f9feea67cafdaa0655904897e1795dd285a82ed32261013aa8f645bcc762b2f8e83e3ae77d6162138f",
	        2541
	);
}
static void snarf_hat_2543(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-google",
	        "f1625e97d489b1d4ba9f12aebe367c9ce2407857af9865648611f3868c067c69bc22c5f99757cada3517100a18f2f7152213dfab6dffcc08ea493eddd813ef29",
	        2542
	);
}
static void snarf_hat_2544(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-gphoto2",
	        "4e4679b8d5da7de36b40046a4933a1c0be7f0bfe23c57d91c7a972ad6cef3e5d5cce36ae313b415e4f75b9f600e669e07b065ae34bc305cf1f95728864d85c05",
	        2543
	);
}
static void snarf_hat_2545(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-http",
	        "dee575680dc0e5cbb71ad3cb27db882a3bcaf7430b336a89527239c5782dd6f6bd185476584f7ed28aafdc54d0046fb7d9ee784b5561250d6029389a6282c319",
	        2544
	);
}
static void snarf_hat_2546(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-localtest",
	        "f713ab0692b72f2634145ee5ce0f3373955a3bc21eb7c84830862e46cb42712e99dcb24f4f91e7f20e81f115c6e059c8e0ba68c88fbf06470f26fb59b4879b91",
	        2545
	);
}
static void snarf_hat_2547(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-metadata",
	        "90314f382abee1e0df7bd0eb00ab011545ea971086f5fe0cfe96a9e4077b71ef8f1110dadeec661af73d0372c9d9f040bcc09c86e31ec2d6bf1681393bbcf306",
	        2546
	);
}
static void snarf_hat_2548(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-mtp",
	        "6cd0c0054c3fc468905b6c876a7adc3587409333e70bda6b7108aa7eb0f3c8268d1c3ee68062696d8b3beff523e58930faf2b7d48ab3836660af0fe97046f502",
	        2547
	);
}
static void snarf_hat_2549(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-network",
	        "38f8a9876e044e9dbe061e86d1d5d636b2dc1177a0d02c75f8c5d6179e2b21d61735b7fcc13f934895603774b96b5116f7422a573f7395450a67aef8037c2f20",
	        2548
	);
}
static void snarf_hat_2550(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-recent",
	        "de27c0c9674ed7781d8581d6645944b9a4a718dacda2571f377359c7515d5cae9e071070d462ad83d21f0745ed2a495750e729394091fc2f200dc77c5e2e8791",
	        2549
	);
}
static void snarf_hat_2551(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-sftp",
	        "ff53d17ecf0ae18d3efc22b3146b93ab95af6c10c7955fa0766a7447fafc2fe3763029beacd4d2491f049069e02487d9fec547798564c8da77fa5c0afed3a9f6",
	        2550
	);
}
static void snarf_hat_2552(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-smb",
	        "d31b2f0fafde82a40baca29c1e0d6a092ca2d606d6a58f425e630b1e23e2fd11678a46cf9425ec84d5c801fd9039d2fa792d4645bff86317c87e2cdf7beb7347",
	        2551
	);
}
static void snarf_hat_2553(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-smb-browse",
	        "c2795eafc8c703f6b0581c9e3ce048fa31f8f0ef5b9da84680b673ce1ee2e0d2bca5aa19474004c7e20e38f68775aeb0afd48ccfc86e7bdefb21fbfefd75a7ba",
	        2552
	);
}
static void snarf_hat_2554(void) 
{
	snarf_construct_hat("/usr/libexec/gvfsd-trash",
	        "0acd65c8c9d7437aa89c587a3efefb9b0a67e61dfad8d50deabd3f9bd0546c8e01377016f607f19d4b0c840318360ac4a6f19bddbbbf5e2e10c1b9d330872a1f",
	        2553
	);
}
static void snarf_hat_2555(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-anthy",
	        "09fd5e7efc519af0804ebed7d152ea12d34dc5feeb98e0ec6f003fe3035030809f9dc718b67d2a86d621f0b9ba0680389ca0f6bbdb5bb9580fbf96f41088fea7",
	        2554
	);
}
static void snarf_hat_2556(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-hangul",
	        "837956a1ccb2de71c0ccd11d9f14a079ec3ed9b64675e2553807f31d631b68cf9aba46774b7b11cb9993467ea94887b2d677e9aba801d825a1ced0a31cb894c5",
	        2555
	);
}
static void snarf_hat_2557(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-libzhuyin",
	        "67c931596682ac03ca60f60a181ae7e3c32740f1d2d0d24b9c0a4fa63951c512434df67dea87c4f4c7981e3fc548274123e8591fdffb6e99999ff80ad1dc090f",
	        2556
	);
}
static void snarf_hat_2558(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-m17n",
	        "348dd7c6dd297cf6c6aa5e110b81307a761d7b3713683b9a223fac5dee20c0f5fb509b77356b80106917978ea77b197dd7ec581aa8b9dd3f5cfaef80b850cff1",
	        2557
	);
}
static void snarf_hat_2559(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-anthy",
	        "414fb06bfef6eb6a8e984edff635a0f01819e0f60fae5e477231647de4a347e7b15a766f8358f1d00e3ce6b2cdd2a0615e6dcd8b0971c5bcf49c954b84c67034",
	        2558
	);
}
static void snarf_hat_2560(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-hangul",
	        "314db34d95e869d54b34fca9f38e89910ff41dce616ac042c77b9abd9c078025dde5b8ac4d59510e27347f0dd4f293328e0e3b458e1af46c957231853f0d5992",
	        2559
	);
}
static void snarf_hat_2561(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-libzhuyin",
	        "491dc5cd5b300aa8b533a6eed051fc37c999ca3c97f42d74f901fe15541879b6c88492816e05a2e979b74f6a5de256406eda4f7861eb39d030959ff1177c08d5",
	        2560
	);
}
static void snarf_hat_2562(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-m17n",
	        "1f31b61184fa35a63d360050ba30154e14185f2e05cc8a49efeb8f26b9fe5866bd3c30cf2008303cf07298c7600b4c14298ca1dc66ebb288545b2bc61fef1390",
	        2561
	);
}
static void snarf_hat_2563(void) 
{
	snarf_construct_hat("/usr/libexec/iio-sensor-proxy",
	        "5e9e9eee1dfe2b95f4741ea6ab18a4052d8be32b460ce14e10e4ad663d217450d3437bb2af4076cb1bcf67c452b122d6a312734f2f1aab0abda648a2185d25b9",
	        2562
	);
}
static void snarf_hat_2564(void) 
{
	snarf_construct_hat("/usr/libexec/iscsi-mark-root-nodes",
	        "e3859dde3d798fda052314e7216d7f965e2c7b90bdcd8cb2d0382a8ffc8f3b60ea0e450f3be46e7769aa134eceda469fb54ff6ef6bfb59c0d23d18143612bad7",
	        2563
	);
}
static void snarf_hat_2565(void) 
{
	snarf_construct_hat("/usr/libexec/low-memory-monitor",
	        "5cc44268ee1f087d56ba1d23e61c89b5930af7bf19318e24b4fdaf3a06e74f8613ee01e1813461b141b280d84d14384d3810931f531c5ffbb25f8530e27ab904",
	        2564
	);
}
static void snarf_hat_2566(void) 
{
	snarf_construct_hat("/usr/libexec/mactel-boot-setup",
	        "bf256d93ba93d6aa98439c39a64983b1c0ce5c3fdb8a4cc815c84b8ddd6369801cfa1f5faad14c1c31d2cb7b4f2bc237b5a20e22fdd4317fde2438ecf744400c",
	        2565
	);
}
static void snarf_hat_2567(void) 
{
	snarf_construct_hat("/usr/libexec/mbim-proxy",
	        "f4331da71d20cf1392433bd260df2a3a9fa6fbedd247e97564498114bd4d90c4a65a6a52d85612adf8a3f76328bfce499c3949a8f0c9f9c154a133cbab783041",
	        2566
	);
}
static void snarf_hat_2568(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openconnect-auth-dialog",
	        "2c11a7c064826e1b1d0074d2e4dea6d0225a5ab52c1fc7758358af3d9fbf38e2a64d6f5c1fd7fa1446bf3fd7a44d9bba0b9df3929dd633e7979d2415d0cec85f",
	        2567
	);
}
static void snarf_hat_2569(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openconnect-service",
	        "156ff654d34607536aa37efbc3975dce729de7f8f0645017cda59171c33907916e124b0f847f4703d08f48c033a9203da5f2e333d19d7e37bdb15eac41b33e45",
	        2568
	);
}
static void snarf_hat_2570(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openconnect-service-openconnect-helper",
	        "95525e23baef7423632df4bff6e95d5f854daeb9843c077efeeb9b48b465c1ee1c667749f1b5369c5c7ed6deff2f4ea410601aaab7cdc4af0b67b21ed6d64e2d",
	        2569
	);
}
static void snarf_hat_2571(void) 
{
	snarf_construct_hat("/usr/libexec/nm-pptp-auth-dialog",
	        "da47978d75f76121aa41736b110ad869775d3b99be0c096d49f25bae53262766765a1239e3cb25b28d33bbe4d323546d62c51504ac1a4d466c8cd7cc94689dc6",
	        2570
	);
}
static void snarf_hat_2572(void) 
{
	snarf_construct_hat("/usr/libexec/nm-pptp-service",
	        "54b5845bb2ceb4bf89a04a7b95687c80e62661c7d2dfc2fe991af8430d7fd8995d4698b34a17aa100c6a771e54b27586cb297e0cc16b0d4437672bc962c214a4",
	        2571
	);
}
static void snarf_hat_2573(void) 
{
	snarf_construct_hat("/usr/libexec/nm-ssh-auth-dialog",
	        "2447efb3ba4f8252c247de409addacfd19b6fd721de5d971f8fc6879b58ea77eb0c5a6c1673f5f520d26edede5b32d5b0f039b7dc12ebbde63fdeba82540697f",
	        2572
	);
}
static void snarf_hat_2574(void) 
{
	snarf_construct_hat("/usr/libexec/nm-ssh-service",
	        "3db0d82084af1b35969d05ddc448ca0204fbf37b5f533d28b9ad921325e056f3c920e9ec1dd2bfa967f13af2e8d72c147707e267ff602c669f2c4d94dfe729a5",
	        2573
	);
}
static void snarf_hat_2575(void) 
{
	snarf_construct_hat("/usr/libexec/nm-vpnc-auth-dialog",
	        "a55c7179ed5ad6f36332f22fa996f9cc2ee00791add64f905aa9c80a2f72cdc740137b23bce46b874bb2c1374a51e784a3dd18896f9a71fc46a6f7e24ed2af42",
	        2574
	);
}
static void snarf_hat_2576(void) 
{
	snarf_construct_hat("/usr/libexec/nm-vpnc-service",
	        "24cb593fd69b2e35246583b2fcd6330d5e880af590720743cb854faf9fe0bf5f13bff9da66d8411eeeac0042fbfc1b5ef22c0f4740dffc8e758d9df7f46b83a3",
	        2575
	);
}
static void snarf_hat_2577(void) 
{
	snarf_construct_hat("/usr/libexec/nm-vpnc-service-vpnc-helper",
	        "b25bfd8573116aa40290e1597c00c2cc1200991e0cf59ccbf4f71400853bc2d2f241deadf86206f916b5673890e9b5d7e99d4eca73d9fdae2dbec98e323394ea",
	        2576
	);
}
static void snarf_hat_2578(void) 
{
	snarf_construct_hat("/usr/libexec/realmd",
	        "0d40e37396680c22c1c54b77a4dc8db9b5af4760a6a8db2cd6059b1b79892584d7a797bf992742cd130dad3766749479dbd4c03291cb84c9d30dc2004e3e9f03",
	        2577
	);
}
static void snarf_hat_2579(void) 
{
	snarf_construct_hat("/usr/libexec/rhythmbox-metadata",
	        "c049112981df2e5f43b46a9e6b419026ee0db28a7f69238d8102c7f2aa73d9ccb1b8fb35af418fd9ca498132da76c27547de9b84741bf335309319b7f3b79ba4",
	        2578
	);
}
static void snarf_hat_2580(void) 
{
	snarf_construct_hat("/usr/libexec/rtkit-daemon",
	        "352a03253de817aa4d541e8a2e34bf08defdac246fe1032ce3dc0a3240ec27969f452e4485921dc74a9ac0ae00fb58f6f95dea2f5f91085653db94424974b323",
	        2579
	);
}
static void snarf_hat_2581(void) 
{
	snarf_construct_hat("/usr/libexec/switcheroo-control",
	        "d5a252adba7213e981c158572aac60cf7cdc1a69ac3143d129e4b03b56ef0b409b9acd4c060a9edd6b2de019df32e29a89059ece9426ef6cff670cd6d71ff754",
	        2580
	);
}
static void snarf_hat_2582(void) 
{
	snarf_construct_hat("/usr/libexec/upowerd",
	        "d448f5d6068c1a4fd7f9f9b968bdfa91a4bbbe077a1ceb672dfe8b82772bc91adb54780e4e2b4c8fcb718b806bd09dc43b519358966a7b9e906d04bcbe69ecb6",
	        2581
	);
}
static void snarf_hat_2583(void) 
{
	snarf_construct_hat("/usr/libexec/uresourced",
	        "9e5b3802708b70a3ca4535f14d937507e49fa48e403d5d1d2034d361662aa61b98c1bf16cb24db5067aa826e28ec437b8a26842dc06ab60b3ffda6bf798b7e08",
	        2582
	);
}
static void snarf_hat_2584(void) 
{
	snarf_construct_hat("/usr/libexec/xf86-video-intel-backlight-helper",
	        "9b88501c2eca2209a6b16e24d1622b1559dfcdf8dad80dbad33e5ab3cbaf73bc781f1d8513dfdda7072cb8dc7bdc1bba6bce4a89ae692a2969ad1b6be17a80e0",
	        2583
	);
}
static void snarf_hat_2585(void) 
{
	snarf_construct_hat("/usr/libexec/zfs-fuse-scrub",
	        "169da3b3fea262f087bdb71f8fa02918ba8d2279f46f8d5a9d128b7169b0cb264d804ebec06189774725352cae27de980f41fd1af9eb925816ffd181fec02db1",
	        2584
	);
}
static void snarf_hat_2586(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-dconf",
	        "63e797b9ba938cab50b72e73d6eb0e06c013c3be1a84b16ea4131c19cb762b2a2e583c8ea2598c74a70b1cf2bcedfd85884e3d43287fef71747822bd2bf4f7a4",
	        2585
	);
}
static void snarf_hat_2587(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-simple",
	        "5d9d92f8338dbfd473826e4d276ae3d7e44c9a62858f9ddbec568fa5a42c12b3b3e62070f164ae8e92be7b3a165a98451f76239646cf8a1a5c8d094a53d4a3f2",
	        2586
	);
}
static void snarf_hat_2588(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-extension-gtk3",
	        "20afb0ff735fe552a79e9ce0b7493e947e4b6662f0a97ca3042668898929250d5b8ab98de564b086a911fa32e406f893fb6b7d44ab6725f8fb2c6be29bc9a46f",
	        2587
	);
}
static void snarf_hat_2589(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-portal",
	        "71eb2907fe3cda252d2221f33f75f1c08cdcaa4f70d09e8f4d449a185fffccb265df3ca8431fc246092601bd46e76b6dd8d9a55508570c6c5eccd508115e69e8",
	        2588
	);
}
static void snarf_hat_2590(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-ui-emojier",
	        "b69ae1614815faa57ed539a0b281fd668b1d0ad8e948fb95629e6b45c2ecb6b6bd3117bf93639c05a81ef01bece4b35900d7d90cdf1fdcd061880f9ca1ad695c",
	        2589
	);
}
static void snarf_hat_2591(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-ui-gtk3",
	        "9f8479bd827d57042e8698edb3e11bab7b1a8b1f5eaa3f2be37bce7192e5c95b99b67d248e0665189920eb50464d7f66f6315a9eebc8511175cdfb592f4e04cb",
	        2590
	);
}
static void snarf_hat_2592(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-x11",
	        "29dce42c0e57231e9affee03e463f6a395d627606fd21724a34d822de1eb941f5d1a825cd2c6ce39b31990892d2f38414987fa6ede806ca421da3b4670d8e6eb",
	        2591
	);
}
static void snarf_hat_2593(void) 
{
	snarf_construct_hat("/usr/libexec/systemtap/stap-authorize-cert",
	        "bd064d0bbd29cdddfa4958371d495016fd313757f8b353173f156704622a87f744c844bf03dcc97dbdfcfe25c87a5435fef0fb9e8a41d05e1167d47b84f6ed90",
	        2592
	);
}
static void snarf_hat_2594(void) 
{
	snarf_construct_hat("/usr/libexec/systemtap/stapio",
	        "adda586f7ebe61c26d457a69a3e2b99e44b0c78b00866a64be5b52d527e2d957886212c7e56ef99686410bac82c4fde68db7ca9d7da1ef3e51b36cf8f8dad5b5",
	        2593
	);
}
static void snarf_hat_2595(void) 
{
	snarf_construct_hat("/usr/libexec/xb-tool",
	        "f78fe16e77bb26aa00b3587e57f392edadcf6772f9e641872a99321990610072e1f9271961240a9f73e51431e247029329a3eac14046ee7181c7be5daac14ffb",
	        2594
	);
}
static void snarf_hat_2596(void) 
{
	snarf_construct_hat("/usr/libexec/qemu-bridge-helper",
	        "ebcba524e2bd84e9d7adf71e203f03f71012a4cf635af8e6f13bf594acb8eb97b06491932bb7ccaaf607328247017682e721cb6a5e2955ab64e4fbbcf751735c",
	        2595
	);
}
static void snarf_hat_2597(void) 
{
	snarf_construct_hat("/usr/libexec/virtfs-proxy-helper",
	        "3ec1fc0a2d94f908348b4c48ab2bb6c394b7d0ded53c44f22ea2b6c96624799955b8420e41291e754a63079951e3e53432182a7dd1fb28c6e81f448acfff9014",
	        2596
	);
}
static void snarf_hat_2598(void) 
{
	snarf_construct_hat("/usr/libexec/virtiofsd",
	        "6429463822131c1cdfe35198ab07b0b7a47c76c64d94d4ee52d547ad41b682a4d390c8e2ddb7e89afd606496ffb824069055b2cc8f91746df47809d64a5b4d43",
	        2597
	);
}
static void snarf_hat_2599(void) 
{
	snarf_construct_hat("/usr/libexec/geoclue",
	        "13542d2318b97cec7d4fe1042052cd45a0a96ab7161f3c87a99863b0aece8d70d1361a8de924d13e8ea5643249d5a7fc31534593938bb64f00aa29d7038dadae",
	        2598
	);
}
static void snarf_hat_2600(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-remote-desktop-daemon",
	        "7092f02850339b60131a28af0abe67979eaa7bc20cea8e9c29b44761c161ddf7b80477042924d175cc0bf734031c08c575a5fb11250289b674d98a1aa31b1f5c",
	        2599
	);
}
static void snarf_hat_2601(void) 
{
	snarf_construct_hat("/usr/libexec/vhost-user-gpu",
	        "d2ef4b1718f4926cf96d07dcd35f0091e95c181fca0eb24f27f53751f0a0c567811b3c6af92ea66c777e8be6d12c32ca1df24fa343f355669a4df2a2f0dd0647",
	        2600
	);
}
static void snarf_hat_2602(void) 
{
	snarf_construct_hat("/usr/libexec/import-state",
	        "36424816f738102d9770957d97be17ace98afd5b2ed21490970b084c86b5a1b5391b5947aace132fca24e75a8d77fe9d89f12832a2c919f5e6cea165c43bfc31",
	        2601
	);
}
static void snarf_hat_2603(void) 
{
	snarf_construct_hat("/usr/libexec/loadmodules",
	        "ba9423c5b754a110b016e6f9868558e641a1b5701ae03a4e42ec651091925f966e1725786744afbd728c5f1ea417a95c42a58197c5d0f8713a6b6ad9eee73679",
	        2602
	);
}
static void snarf_hat_2604(void) 
{
	snarf_construct_hat("/usr/libexec/flatpak-session-helper",
	        "7c87facaa8de45bb62b683c085ba386f3f36d9c0c7e3dc921f98ce5a763805ef7ac384cc43d925f0108fb4db610341e7d2637315ffe9c698c7b240ce5488b432",
	        2603
	);
}
static void snarf_hat_2605(void) 
{
	snarf_construct_hat("/usr/libexec/qmi-proxy",
	        "307d45539816cc3d4cb744ac9747659e56c78d3dfbe0b13e62dbd08adcfb67ef8bd34e5876d21bcfd9da97b22976f8e3378944c4c7ea3d7e496f321f18c1bb11",
	        2604
	);
}
static void snarf_hat_2606(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-xdg-portal-3",
	        "e278085d91f7d82dd86ec4c3666f5774601b50d5e74dd050ac44dc86ba980965bbb31051a7891558aae6db071dad5c758ad5b4bd9119d95f54c6de8d3b7c2424",
	        2605
	);
}
static void snarf_hat_2607(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-extract-3",
	        "c40d94168f4fd1d4dbe23d542b4e6bb35d72f4df28f1b89bc40a878e7fb2e1794c237ed20e47d2c5cc466eca5660f22c61825f11474cad583ad01c192a52c713",
	        2606
	);
}
static void snarf_hat_2608(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-miner-fs-3",
	        "2766853a17af4a47b260d31ef96956765c01aab3ef72f2a08836479806daf562907088143c8592e4f64dab5b80e319734e24ec7a68d2c3191836a5525affc09b",
	        2607
	);
}
static void snarf_hat_2609(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-miner-fs-control-3",
	        "51bd4e40291b0a49a37fdbf2d46ae38657e9cebff5c6d3d58fa82a4897e2b7323cd74d43a79159ae3885341aa00bfbac49c05452378fc59e2765898b6b02b49c",
	        2608
	);
}
static void snarf_hat_2610(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-miner-rss-3",
	        "a047e55fbcf15b8afa9d6016c323d2f2021842dc42d6450181f12da54f1ada18b7516bd612885b015ff4d774be9478c6959e3bf9c3f9380dcac84bb57c3d8099",
	        2609
	);
}
static void snarf_hat_2611(void) 
{
	snarf_construct_hat("/usr/libexec/tracker-writeback-3",
	        "6e883da12beb50cba215a8ea65e2bbd0c50c25f83df6b64235546e63dd8907ecf05a177136647f367cbbba3c488dbc56bfe5bc7953de2291cd716926cfb56bff",
	        2610
	);
}
static void snarf_hat_2612(void) 
{
	snarf_construct_hat("/usr/libexec/blivetd",
	        "8ab56251ef1d57641b9e5d0e56a9de2d82d2705c1603662bf858f8d8ddd2d0a668dae32c338af0cadb05dd8dfb344a83a3b909a903cdbcb4727221b795186cfd",
	        2611
	);
}
static void snarf_hat_2613(void) 
{
	snarf_construct_hat("/usr/libexec/power-profiles-daemon",
	        "f8045a58408094e12ad64c0c014f9593739137cebc5aed77f8e919a821bba374d5f4adf63968dc5d7009213e770683eac3a42d45fb256ac6d7ab98d04880328a",
	        2612
	);
}
static void snarf_hat_2614(void) 
{
	snarf_construct_hat("/usr/libexec/fcoe/dcbcheck.sh",
	        "22f5bca1cfbbdbf48d7a364556b4843766db63a0707cb2850842bff4746ace59e954b522eb00e82ea3d3086dee200940be1c3e22c1c3ac14c3ee7aa877f6ae0f",
	        2613
	);
}
static void snarf_hat_2615(void) 
{
	snarf_construct_hat("/usr/libexec/fcoe/fcc.sh",
	        "9242ad744f7994931ed6823fcb33139d7c417642140010af69da87cb6b4d1b22ea9a05212597c79c8b793d8b692cabda3c77fe3c5361ca0a3dd8ed3b7a3b691a",
	        2614
	);
}
static void snarf_hat_2616(void) 
{
	snarf_construct_hat("/usr/libexec/fcoe/fcoe-setup.sh",
	        "572c5221955bd65eddbf6015fa64a00f425e855532adc2f15ea687d844303920bca2a3c601c35c92d25d8b99cd5b79181e5aff941c5ddcbe098aee098e1e2693",
	        2615
	);
}
static void snarf_hat_2617(void) 
{
	snarf_construct_hat("/usr/libexec/fcoe/fcoe_edd.sh",
	        "335dc03ea19c317361b04278a834dc0c18065e4551f775fc1c21b4b0bdb9d5e8e2cac7929242d7cff2bbdba7401514447eec28757b7baac8ca739c34c3e0dbe7",
	        2616
	);
}
static void snarf_hat_2618(void) 
{
	snarf_construct_hat("/usr/libexec/fcoe/fcoedump.sh",
	        "365946129b350feadf1b70717cb58b375da9d6a1efd4415e0ad7dcce04639c31db06b5ef6cd0082b3ed1258d20454beecf6c9bb10b61fbdb35940b58493ed6a1",
	        2617
	);
}
static void snarf_hat_2619(void) 
{
	snarf_construct_hat("/usr/libexec/vte-urlencode-cwd",
	        "76731660d35bc3c4ee46c60b0f51959849d06e4c1de3e8d6c941fba632c1e0de3afaf9720cca1aafce2c81d817575ae897943213b392d3560794c676f08189a4",
	        2618
	);
}
static void snarf_hat_2620(void) 
{
	snarf_construct_hat("/usr/libexec/dirmngr_ldap",
	        "3bcfafa9c1880319bf05c3f1efbc224e5d527270c91eba976aa870fbc36361f414cb674937f5063e51377c31f79b82db6d7b80526a154f1f3298c60c53cb7a6a",
	        2619
	);
}
static void snarf_hat_2621(void) 
{
	snarf_construct_hat("/usr/libexec/gpg-check-pattern",
	        "7bd3b0ea1a008fbcd74c74805a6090ae38cee4554e2df3dd948bd1318c02539b8f2b36ed6bf8d210aed303e1d04ebbefe631e1bc250678521a3f3518b9bca028",
	        2620
	);
}
static void snarf_hat_2622(void) 
{
	snarf_construct_hat("/usr/libexec/gpg-pair-tool",
	        "c91e440313f884b9474139a51dfa06b25a85ac0a4482c939faabb79418e27b0f6a2e8dd21deaeadb1fa31ba411c33da9096e4c0f091594831c725901d9b5e735",
	        2621
	);
}
static void snarf_hat_2623(void) 
{
	snarf_construct_hat("/usr/libexec/gpg-preset-passphrase",
	        "623417b2620d7ab1045653e70f3c05323dd8cf1ca385d7b932f80a83e160d7600f5d68f9e95c002f5c5d2ec86bfec316868e71dc44e2d957ba3dd06a198b95be",
	        2622
	);
}
static void snarf_hat_2624(void) 
{
	snarf_construct_hat("/usr/libexec/gpg-protect-tool",
	        "7586ec89348907567c83b289f01ca1fd0d1f94ed5ae341f46b9003a8da2af631e484880b1b281db6c545118d7fc342e13676bd12395af436467de9cb22b798a0",
	        2623
	);
}
static void snarf_hat_2625(void) 
{
	snarf_construct_hat("/usr/libexec/gpg-wks-client",
	        "676f2f4e64e9f67579ec3c8d4ca4c87fef49ac15d864033200d54440576c888b43327f8523d24b216b9ec3a4adcf2745afad714f4a2a7f374562b4fe14302341",
	        2624
	);
}
static void snarf_hat_2626(void) 
{
	snarf_construct_hat("/usr/libexec/keyboxd",
	        "6584ef5b260ccb5d25467f232aff1caa88dd8f36389cababc0365bd3c19583aea18258e4a732fbdf48b4d794dfe88af0bde14121ee213391d30fb48146b09160",
	        2625
	);
}
static void snarf_hat_2627(void) 
{
	snarf_construct_hat("/usr/libexec/scdaemon",
	        "a3c6aacd4b48d8aefe6fae4d4005006e87d50ba374dfaca045ebcfa33709670c672048e59d55ab8802e67987e3489d2a93b14d4c41f05a45d4180f7a040aab97",
	        2626
	);
}
static void snarf_hat_2628(void) 
{
	snarf_construct_hat("/usr/libexec/nm-daemon-helper",
	        "777b11eeb594624bfb38b94b36b64f93ef80ee36f5e7082b377ad138df58ab21125309f2eb7e2f67f21d31dc82a255dfc5e1bb0b0ad007d7c44533edd8b5b269",
	        2627
	);
}
static void snarf_hat_2629(void) 
{
	snarf_construct_hat("/usr/libexec/nm-dhcp-helper",
	        "72c3000d1e2b614451aaab0f9942ea621692fc26566ed799906a47417206999d24709508858d6be01f58f3fd66fa224528db32450088f68514f6a37d14b0391e",
	        2628
	);
}
static void snarf_hat_2630(void) 
{
	snarf_construct_hat("/usr/libexec/nm-dispatcher",
	        "da34ed078289642cdbb8c76f28b6a4c636573e1d0463832ebee109f81ac764c0595be9ae520cd06fa73aa485cf6fd34a9afc8e49b69e9fba42a3daf94c949818",
	        2629
	);
}
static void snarf_hat_2631(void) 
{
	snarf_construct_hat("/usr/libexec/nm-iface-helper",
	        "1ab0557e92f61092ba82b50af9de55d9709b4e7c742e4035b6957047dac65ce44feac473a2e7a4bd787aaa63bad05771b6a94b58dc232261c2d2998427c0edb1",
	        2630
	);
}
static void snarf_hat_2632(void) 
{
	snarf_construct_hat("/usr/libexec/nm-ifdown",
	        "d6b85e70ae430629ca067a96510234a28bf0dd70b5f7e975d6c5f7dcf90614d96c26914182da4186101d1548e9ec75fed7825b63cb85ea33fa9e25bc8eb0922c",
	        2631
	);
}
static void snarf_hat_2633(void) 
{
	snarf_construct_hat("/usr/libexec/nm-ifup",
	        "79148b537e646ad4935c152472f58b05cd91bf4ea5ce2536336ee45421d6b2b206a601ac471c4d85de7f2c18b4b585d62fcd0b53637fd6972d6177eb878fb6ea",
	        2632
	);
}
static void snarf_hat_2634(void) 
{
	snarf_construct_hat("/usr/libexec/nm-initrd-generator",
	        "3dd8b7283e0afde105a740434a46cf5816223c05d35431e369a0829ace1faf23a694a356ca833c0bfad0d1ec4f5cfb2dae0c8079d8d385c21463ee393563888e",
	        2633
	);
}
static void snarf_hat_2635(void) 
{
	snarf_construct_hat("/usr/libexec/libvirt-guests.sh",
	        "4176e2bd55daa158ea2796514a2370512bb909eb19afe50fe80d2a2cd3cc54cc94562e52754e82e8c1e521a67bdde5da7b5acafc2e6c03a385a9df22670cb98b",
	        2634
	);
}
static void snarf_hat_2636(void) 
{
	snarf_construct_hat("/usr/libexec/libvirt_iohelper",
	        "0be99b77aa738c1ca633f67af0d6ff73e368a24766a35ea9ba4799b29f74f90ca3d14b7c1ec4c5ed8eb099cbf59d7de558ac1b7feca8328a06287f1b36495b5d",
	        2635
	);
}
static void snarf_hat_2637(void) 
{
	snarf_construct_hat("/usr/libexec/libvirt_parthelper",
	        "cb213fa04a15a719a32ee4e8455f6c711a691d4666067d09c66172ee57fc2fc0e6441e3cc4638ddf3c0540a427c4195d5a74aa8cea392625929d8aadaea6036a",
	        2636
	);
}
static void snarf_hat_2638(void) 
{
	snarf_construct_hat("/usr/libexec/abrt-action-save-container-data",
	        "d580973a7c43bf3a02a0c7eea68232ad9c6cd2ca84a6a3cc403023efb663c39104c15127d2be883d789fab6994c0da23d354ea30b979cfb82b1878b14cd03de4",
	        2637
	);
}
static void snarf_hat_2639(void) 
{
	snarf_construct_hat("/usr/libexec/abrt-action-ureport",
	        "8fbf1cc20e267d5dd007d134e8a3cb061ad7d280d20355480e290001e63b0564737493492a6acd9fa714070e4fa7bfedd84c059d2689b070e6c4ddf57b1811e0",
	        2638
	);
}
static void snarf_hat_2640(void) 
{
	snarf_construct_hat("/usr/libexec/abrt-handle-event",
	        "013da1c1798c6670fe9d97f8fe3d0ffa9316036ccd095c157765314a46f7b7db5ae3be65285a875492085c26675d033920cb176b2a2cd4a1c745a675e479c149",
	        2639
	);
}
static void snarf_hat_2641(void) 
{
	snarf_construct_hat("/usr/libexec/gdb",
	        "7d13fed142e478013bafdf763bafd616da11b9776d421b3e86031bba7979e6d5af1d3d2f436f0e17bff631f8a46d7ebd67d437b64b1ddb723c64742e8ede7e94",
	        2640
	);
}
static void snarf_hat_2642(void) 
{
	snarf_construct_hat("/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache",
	        "605fa31c51df8301956385ce9911954e2acb3e5354820f211ed895bcbbc07fac0e710d6fe1ca3ef7fa40b42adefd40a3c576b5b6ec452da093337394a7f96a92",
	        2641
	);
}
static void snarf_hat_2643(void) 
{
	snarf_construct_hat("/usr/libexec/abrt-gdb-exploitable",
	        "f28f3128bace6d173a793bb13ece216751da7fc985c2a03eacf4652f4a758c302918fdd01e69a54d366016255332c144bf245d2738ae448fec347d9bd029e440",
	        2642
	);
}
static void snarf_hat_2644(void) 
{
	snarf_construct_hat("/usr/libexec/libvirt_leaseshelper",
	        "66055d8b4334d26d3ca75347f4c52515f53f548645fc4464d4a3100438c30bcf5d5c6aa2bc0429e0f75aff638549c0816948cd3cbd2b9d092e78921a8015e5ae",
	        2643
	);
}
static void snarf_hat_2645(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openvpn-service",
	        "852dfce0f439554e151c2a5845291bf8c33fa44b55e8c414f74d60c3ffe82aa6d5aa4df51498738b8bb53977953c46f67350af8b058ddeccd4d75373e2f36e21",
	        2644
	);
}
static void snarf_hat_2646(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openvpn-service-openvpn-helper",
	        "95d503f762a2ebd4854ebc3ea6cdfd327b958ed3f5b8fd69931f0151ce01fa3bfe50900fc5f3a4cbde63a8c49dd35346847d136a49cd9780dcfd14e270ebe979",
	        2645
	);
}
static void snarf_hat_2647(void) 
{
	snarf_construct_hat("/usr/libexec/packagekit-direct",
	        "07cc53ddd5e4f11f965e61a29ab00887292098c08fd1a2f5c107b5a867aa9e28931a7bba4d4d2cde26a4ebd9aba097e65fed4fd2e338134501f93f58b1a892b4",
	        2646
	);
}
static void snarf_hat_2648(void) 
{
	snarf_construct_hat("/usr/libexec/packagekitd",
	        "8f7886c661dc0c9f061b6661b2d73a9639984a830f99524ddcf2213c7206fa7ce4ba615706eb31751843f28eb5f347b370ea7346d931ab5a57a6a58bb3618953",
	        2647
	);
}
static void snarf_hat_2649(void) 
{
	snarf_construct_hat("/usr/libexec/pk-offline-update",
	        "54edd9ba41b15b538877461eafa186fe11285301a6cf6d71b7a9e7afc4fb1e53780d5c6d9968dea3217d2e30406fd287e43c0d6c1b91595db815b0671558e4c9",
	        2648
	);
}
static void snarf_hat_2650(void) 
{
	snarf_construct_hat("/usr/libexec/xdg-desktop-portal-gnome",
	        "6cee4519e62c009b55e2e2767886dd3e9fb5463c28815544520429374cf040ad7af2599c537f9f0d41985dfbc23c4c05e3968382b6a73e4cd43e436f78aa229b",
	        2649
	);
}
static void snarf_hat_2651(void) 
{
	snarf_construct_hat("/usr/libexec/xdg-desktop-portal",
	        "cc96590ddf7b9aa26f7229c829a7763b83612324100f3be5be756efbdf78d8c9efa56fe5c6753595905f0839e197bebaa4919c62c8f54a808b3f38c3e6504277",
	        2650
	);
}
static void snarf_hat_2652(void) 
{
	snarf_construct_hat("/usr/libexec/xdg-document-portal",
	        "247b181519d046a724c33b7e031f31c611637fc107a28310b7cfda1ad27f629ac955352b6da5551fae77cbd64ce8c309ce95a0db34949661acde788fdfd6c3b8",
	        2651
	);
}
static void snarf_hat_2653(void) 
{
	snarf_construct_hat("/usr/libexec/xdg-permission-store",
	        "a3fcee8eb5c2c360faa60711c41afbc04f27ab187a751e16955d81025611d5c47f8d2935afa4026095ed0c0fb9510651cf089e3cdbb441f9e4ee3166953c9e02",
	        2652
	);
}
static void snarf_hat_2654(void) 
{
	snarf_construct_hat("/usr/libexec/flatpak-oci-authenticator",
	        "de321ff318600317610458c3ab6090f799af36d40c134ed3ba01812d44c60c154aa1e240473ef6420541186a02ea0186fd98dbeed0545793b952d584a94ddb46",
	        2653
	);
}
static void snarf_hat_2655(void) 
{
	snarf_construct_hat("/usr/libexec/flatpak-portal",
	        "cf23d003f344c5f863d608247c24b09420760f56a63ce8a30041700fd8e81d8cb8895349703af4b50637f76605dc9c1edd9ef981c754201dcf19db348063363d",
	        2654
	);
}
static void snarf_hat_2656(void) 
{
	snarf_construct_hat("/usr/libexec/flatpak-system-helper",
	        "ce438774e00c8f75817d84b1450fea15c61ea6ea2c83634e84a6f419eee1f90948cd6811fd47634c8052831aad61fbaaca512e557d134b0565ef365c43c8fac8",
	        2655
	);
}
static void snarf_hat_2657(void) 
{
	snarf_construct_hat("/usr/libexec/flatpak-validate-icon",
	        "dee615877f50a05d7b7253625a6c74fd539fc76e2fc1f748da2b7be255fa27e59a7ca9af98394325001dcca2fd1bda50eca10591ad167761fac969168ee86f09",
	        2656
	);
}
static void snarf_hat_2658(void) 
{
	snarf_construct_hat("/usr/libexec/revokefs-fuse",
	        "cd4385680308beb3d4846f1bcb7549d672df8c7d3bee4a2c6ec21f6b79c6fdd1156e011977eb949b1b15ee4c0092a06e608ddea5791d3db05ff0221c816150ca",
	        2657
	);
}
static void snarf_hat_2659(void) 
{
	snarf_construct_hat("/usr/libexec/xdg-desktop-portal-gtk",
	        "3e37adc834adfde33e0fc5210cf70adccc36d51c9365a2128e76a516a74bc62c30af1f72fe5b716d0a0ace997688207a1d0d69d68364f17b34ef96cb469095f0",
	        2658
	);
}
static void snarf_hat_2660(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-a11y-settings",
	        "ab298b3b4844fc52efef3f4d6fe61c2c9f10448475902746482fc471f246f25e010d02385e534f124fa3dd1f157df8595261c007b7f19f03a1d3ac4f9a1171a9",
	        2659
	);
}
static void snarf_hat_2661(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-backlight-helper",
	        "8597026f93329ec03727f3dac38ff525948c2238e15f15be48c9203af4c28db7c9abaf00aed3b545ea82e847da43bdad4170e51e77871e122db1835008112a4a",
	        2660
	);
}
static void snarf_hat_2662(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-color",
	        "71d004a718556f6b0e7117fe4f2b3e7ec011f08fbf9e47143f799fd32949ed13a996ce5380219e4a79828bdb99bc06ae897d52a89fb4d4f28469faea2983a821",
	        2661
	);
}
static void snarf_hat_2663(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-datetime",
	        "cca49d5ec1f60e7a814c3a17b883dbbe23210fe0e957a8ea13fca873f3998b6199346e4e089b88be7eb8d7959ec2c8060ddee1f08d1103caf121cc58f63fbd8b",
	        2662
	);
}
static void snarf_hat_2664(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-housekeeping",
	        "cba238d73cc800c00cf2f661bcd73b78633b686eb5468ca0bd1634afa167d5127dc61ad21132db875f750cdc6ba8bdeee1a99ff047f0dc7de83d9fad2d18d566",
	        2663
	);
}
static void snarf_hat_2665(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-keyboard",
	        "052f30dad4a7b923f8e6268a0945f5a5434461f5003fb8ba32789a43e934ede4dbbc9e1269e25cfa3b442b2a8c300c8f1553c1b754e42c6b277c1f164d5b8e7d",
	        2664
	);
}
static void snarf_hat_2666(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-media-keys",
	        "19a6c9fcff129c06d51ebf2135af9209b33ed197c3f67a7bf35bfd73ebaed11519318657570e53aaabc07e406025048d56c7d63a0f942352868ec6744987b348",
	        2665
	);
}
static void snarf_hat_2667(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-power",
	        "785763d741ab21a32c1752e65b2705153829210490a3423455c05a0ec8f978fcb00798fdb34cfca07a0c97562760d7f8fdad2956861c7a764af1ab133e6d6d43",
	        2666
	);
}
static void snarf_hat_2668(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-print-notifications",
	        "c73cd8f1e315136144222c81963482c344c34cc9d33dc03b50314066a8afa912f0549b1f9577de66547639b9de7aee046ec8d99311d77c5659619afd9aec6428",
	        2667
	);
}
static void snarf_hat_2669(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-printer",
	        "8e1152ae9676a147b2d1f17c103d1d5bc78a9bf1186fab38489797169c81372cb543cf398f6a453fd5ed72f3993a48697149857fca305f12efcd4c99245454e7",
	        2668
	);
}
static void snarf_hat_2670(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-rfkill",
	        "1960a5d8babe46f1b4dbf4f210bd05ee806f85457288e4f78310e1e3b4d71ab753cf3ae69deb8eb03c9eae7d538d1f12bd1b5ae6dccda0fdddefd0df5ab58893",
	        2669
	);
}
static void snarf_hat_2671(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-screensaver-proxy",
	        "6c36aa5cbc32e587dcead6444d7079451a199dd4c5f40ca667edf46d94571c7f824349838453afaf0426c9915f1ef9f2ffa1b4134e12eaf171bd6a26bee286ec",
	        2670
	);
}
static void snarf_hat_2672(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-sharing",
	        "eb0c58bde9c3948f412bcac43714b78a420ebb57b5a850ff6f0df9f8e4c3d984cd6db5ba17fc403278df85eb59046a43a349c5167ae3c58da41a34b3e78bafca",
	        2671
	);
}
static void snarf_hat_2673(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-smartcard",
	        "d924795fd607340166093fd4414ad58c6770e977566ff13b368e8072838289dd31e48c6dfca8cdfe9c23b3cd856dafb8d781b8f65864c9a73a1185a808e5be2d",
	        2672
	);
}
static void snarf_hat_2674(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-sound",
	        "d9b474b1b5078e1d01ecbea20f9334bac6b47190f96ecdd2eefd18f8ca033ca1462de247336c66091c5d1d715757ee7127dbe48ee82d5cf47f4a983e5c3cb633",
	        2673
	);
}
static void snarf_hat_2675(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-usb-protection",
	        "5de095a6a9bd7fa0c12bc4a664314544a3df8a0ca0efc84bb26146612d64ebd7f9a88669a0970b13beee8cdfb872ca537b75a62381de24bb904e57661e604de0",
	        2674
	);
}
static void snarf_hat_2676(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-wacom",
	        "7f7193ac05ecde774ed3fbbbc73388fb81882871283cc6cd446f9350bf54df6d80aa111f92816d7c4d10898d5bf151326ce23c87f6798d96b1e85ca71acdb74e",
	        2675
	);
}
static void snarf_hat_2677(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-wacom-oled-helper",
	        "c97c5d4b2d117ad4272562ce33cf6a55f41ddac5fdc4d385569063871c922e157076ea9c7bf4add42434b91a6b582f942d640b44e284dc29712f7f1111b97f3e",
	        2676
	);
}
static void snarf_hat_2678(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-wwan",
	        "fe1a5fe73784ae2e7f715cef3df9e79018abc1fd24051593618cb6104cb9e1ab3e0183d6c936e7ebe35cca44f5fc37d562255576cd26734d50459e4b7b05e8e6",
	        2677
	);
}
static void snarf_hat_2679(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-xsettings",
	        "a9ade316f5ed99d21b653e57d37d159d8b697902f1b54ea3ef48b2630488dbb9dc7d80c2d3ee845fe91e60fffe55b93055be6939818c49382823b5d1b3666e31",
	        2678
	);
}
static void snarf_hat_2680(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-binary",
	        "d175a0530b3dd69c8c78383b2eeaa90a4da7cbbf33155bc69daa3dbbe0c96a0b7a61419a7f21567d1808e05f73ce2d624f8cb638c86da16172c693cc1c3fffe9",
	        2679
	);
}
static void snarf_hat_2681(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-check-accelerated",
	        "79ce2ba949b15fa522ec7ea1b6bdea007f04f96a8f667dd52bccdafeea59b647b0e17df504373323d59ad235d68811fa6f5b6c6306a9d06081678d4d98c61c57",
	        2680
	);
}
static void snarf_hat_2682(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-check-accelerated-gl-helper",
	        "c2dc208e557f51e312ab713733a44d010609d4b00e42b0e567980a58f429d0d887ce98dde7000a647e6b3f1dcb348bdc7744516a2e921bb9c63940861a031eca",
	        2681
	);
}
static void snarf_hat_2683(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-check-accelerated-gles-helper",
	        "1387daf319c07b1fbb5b8d17d2a118589e3de75bc12544a588235feb7578b87efd9ce8647bf291a09e7b101069a570c0363595de4208e70decc9725ff895837e",
	        2682
	);
}
static void snarf_hat_2684(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-ctl",
	        "d152263803a60f60e63085c686b9b9fb033ae9f7d6299d84d44fdf3dfaa88cc423119e00ed38697b391bb09e225f5373159dd076e557f62aeb02672967260e74",
	        2683
	);
}
static void snarf_hat_2685(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-session-failed",
	        "6329e5c863be7e1f342b1097acd291ee2e30e290cbdb427c746f93c87433b9253b63b64fff87209412f0921d6258533ade79b6e10b62c6ee04ab9a1c1ada714e",
	        2684
	);
}
static void snarf_hat_2686(void) 
{
	snarf_construct_hat("/usr/libexec/gcr-prompter",
	        "94a76bc211fa604d332f8e18f26f458f9c277d8f216f5a61e83737a26164ef94da639708bc2218e3bd9e89caa5c0484345312b6e804336110e5d659eda43e70a",
	        2685
	);
}
static void snarf_hat_2687(void) 
{
	snarf_construct_hat("/usr/libexec/gcr-ssh-agent",
	        "341094b22b2e70c0c63a4a9b1d735f7b3a0eb254c4f3225676e45218f231f8bb3b939030c975bcc47dd722a3c8c62a9044958ced2a129a396a70e005767ec514",
	        2686
	);
}
static void snarf_hat_2688(void) 
{
	snarf_construct_hat("/usr/libexec/gcr-ssh-askpass",
	        "722ba7d1c790f173e85f00247adf517d1c6e5a717dc89819e071a2029801205aa792c8b778569ad80b1a8cbeadf55bb5236d57b45759b7471ee1cb329ae3ac65",
	        2687
	);
}
static void snarf_hat_2689(void) 
{
	snarf_construct_hat("/usr/libexec/camel-gpg-photo-saver",
	        "3977528e77fda831c6d926d7d3e5dd0084d0c9717c035211f23cdec4d36878158254b2a5f2756d35cd83f343c9358569e719ff309302a364dce3472877a30e06",
	        2688
	);
}
static void snarf_hat_2690(void) 
{
	snarf_construct_hat("/usr/libexec/camel-index-control-1.2",
	        "1fa4a7e9c0605be1add2cbac7cd214184be033b621515a0a30da81bf01026f0d0c52e60370fb075cada001f86f571f23865865719657a0ca056b1034029b9444",
	        2689
	);
}
static void snarf_hat_2691(void) 
{
	snarf_construct_hat("/usr/libexec/camel-lock-helper-1.2",
	        "65b5db893264c76f1cc901b2e7c131767ec04c09de6acbc47cd9643f6926a59488efe9e0a9719ee97d1fb0238f495749f6bdd8f32c012ddc6112a6aaee8b6922",
	        2690
	);
}
static void snarf_hat_2692(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-addressbook-factory",
	        "ffe08c6bcc1c7d0e3d52e3874b912826adf2bb1f2ac5187dd06c5edbffe0cf86584b39291991fb364bfd52bab3782c4dc11a0244dc43dc63aaac21d4da78759d",
	        2691
	);
}
static void snarf_hat_2693(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-addressbook-factory-subprocess",
	        "66d8aa43e1620b9c92ade46e2ddc470974c851c1419d36d5673dcf3b814211dc69443a4395f883ed7c3559c47b88ef46fe5826c7a6ba0f92c185684f4c5fd989",
	        2692
	);
}
static void snarf_hat_2694(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-calendar-factory",
	        "b50cbf8aceed86301d9a2a8f2330c52d225b33c4e6508057b4b444b24e27feec5058486861b95ee1f7c7c3861fa07bf1176902ba27fcc9449d6fc79ad9328ef0",
	        2693
	);
}
static void snarf_hat_2695(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-calendar-factory-subprocess",
	        "d2ec342c9a8f91f0f5f6db30e82d0c44518bef236dffdbe20df37d8b9a24a3eec11b238106947d23b1a3b4849c0e3ada4a77c8d03c03d2a9c20a9e8023da8061",
	        2694
	);
}
static void snarf_hat_2696(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-scan-gconf-tree-xml",
	        "f63b2980349332de76f5d23fc13766b6aa168b3b191459cab22302d72ea01374962749206ae876503173e9fae9c560e8651a52ea29e2d1e35a5c42fad69156fd",
	        2695
	);
}
static void snarf_hat_2697(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-source-registry",
	        "91f1b002ab4c200f22617730f1a8ea643bc6339555ccdd9bd7578397cae1a7b4796609c60cdfe5012ff6037090341730db27d27d4f5c30bd8a51694564194ebe",
	        2696
	);
}
static void snarf_hat_2698(void) 
{
	snarf_construct_hat("/usr/libexec/evolution-user-prompter",
	        "d2e53678a31080c13810d3ef14dceea59acd0c1da9f0b56f7993d0c95b05ac830ee6a6cac16f434da84056e069cb05ddaaae1ccb737d9f5e2c372285cfca9ed9",
	        2697
	);
}
static void snarf_hat_2699(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-terminal-server",
	        "de4fb333b5c1f928a81eddfac842a0d247afd474bc7f9b5acbbd8906529500a6264d935dac2f91c345150466083904efdcc362ffc34d53adc9e30f6d2905805f",
	        2698
	);
}
static void snarf_hat_2700(void) 
{
	snarf_construct_hat("/usr/libexec/mutter-restart-helper",
	        "8fa95c8769681b34e4af0842107d24e21ceffb2ef74ca1838c995f53a26796212425fa51ab7389b1a46815431c5dc73d34474f740c0566d9bc9900a6ac57d730",
	        2699
	);
}
static void snarf_hat_2701(void) 
{
	snarf_construct_hat("/usr/libexec/cc-remote-login-helper",
	        "02dd33c1a8d488ddf32c02279d5c20f8e6683c0e8e01325cf1ad066dc1e1cbec5d4bb2e67a1f7037d351d87c4ff97a770904d557d0faedf037bac4ccc5ad3c2d",
	        2700
	);
}
static void snarf_hat_2702(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-control-center-print-renderer",
	        "c035e5c4e0480ab5a5dd896d40cd1e8042c6a88c056ff4fd701b4d710dc5b97de58cf8a5e40cd44433d38d2889ab29a766c5144cfb211b15ac547cac073edfd1",
	        2701
	);
}
static void snarf_hat_2703(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-control-center-search-provider",
	        "e3d3f12ca6f7d19e8aeed15748b030aed402e626914094a670d61df3c88a5e9d107ac6aef5102e3b1454e658485e3f037dcc5b56d6e64e95f7abeb79ea31b8e4",
	        2702
	);
}
static void snarf_hat_2704(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-host-chooser",
	        "41ca2ee11ffbd58387859758d62c45999667010ea4b4b49b466cd0f311cea688f6f70ae5270607cee76826790f1996ea1f0ebf6b0be0d90d4811eb4cb41d9e8c",
	        2703
	);
}
static void snarf_hat_2705(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-runtime-config",
	        "2e3eda0f21fff9e387665d41387aadaecd600087ff662cf5fd56eb497123316b1f63ee042c1325b6ebe199bc7633196dbe883911f9cb2f303999454274e1752e",
	        2704
	);
}
static void snarf_hat_2706(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-session-worker",
	        "a107a1e87949ba4c8fc22e1eeb16a42ee8e7c0d1e3a3500762992507049b4ad1deef4b75412b3bf3ed4999004a3f55b07521ecf4ca94dc76a22e6d5c63a22fc4",
	        2705
	);
}
static void snarf_hat_2707(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-simple-chooser",
	        "4c20d5b099f624901767545ecca4ce1b83320c68fedc61a94014e2f456314648ffc2a5d33273830d2848ae47b55aa970ea9c124f4ff94e55b9843cfaa2448455",
	        2706
	);
}
static void snarf_hat_2708(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-wayland-session",
	        "200664247d74b3c7870620ef0b3d5df3cd286758d1edf034032990dbb4e432283732608b768c9d66c1ad5dbc0c89e2ba9ffc7dacc86f138a91e683c755444f5d",
	        2707
	);
}
static void snarf_hat_2709(void) 
{
	snarf_construct_hat("/usr/libexec/gdm-x-session",
	        "d72453242e2d7ad781b3e62e4eb5cf8a6c609e919090239e733ed2923aafea68e2b5d31d00b06cac69cf78dfea5ab21a613e942f14e6e463893ff394fbcc6034",
	        2708
	);
}
static void snarf_hat_2710(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-shell-calendar-server",
	        "47fca3616940903ea16c3709e8a4a38ff044be0c6ea3c05606ef63b33a71fd710e254a217d09f9dba0de050ed080bc35b6ea1ccc7b45d8f67cb575329ac62e44",
	        2709
	);
}
static void snarf_hat_2711(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-shell-hotplug-sniffer",
	        "48c2fe684d1f1617d2769cc01d62fe95710609281d0eb9814b49c4fb33dea40396813561fb9f83827fca234033ffe7c242abd3658445d42f536aab5e5922d425",
	        2710
	);
}
static void snarf_hat_2712(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-shell-overrides-migration.sh",
	        "c2e57f50873b304ac7a3ab3834cefa92246f8de9bb110746ff4314ef596c97611a1559caf151cfec46d72bc87be38b4f97cfaf13eb11881d0adb0b560ee4a6b0",
	        2711
	);
}
static void snarf_hat_2713(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-shell-perf-helper",
	        "3cb32d7aaf8886c18b835fc8fe472c12582a96a326174a26d62b8972c19ad1682b400579e3b926729c4a1fe95207902ceb2dbb177a36fa84c8aed173f678f1f8",
	        2712
	);
}
static void snarf_hat_2714(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-shell-portal-helper",
	        "180bb4cbd2ca3c2bcf5d2e9d93d8a0da179e1c108b09ccf6f1e9a758fc803ffbfd63a8e148b8f2c9823c2cf333e456355f27b761c4ad100d7b1e91f00594bd29",
	        2713
	);
}
static void snarf_hat_2715(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-initial-setup",
	        "e7b47730ddcf79376b741348363e36968834e2ad712c0c7582c89725fc235be7a06f4736a58d6bb46118518d11d996994aa2e030fd096f451d48da4b7df90b26",
	        2714
	);
}
static void snarf_hat_2716(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-initial-setup-copy-worker",
	        "705c0093c5180b13bdde3cc1ef071b82cbe0a96787b3019aedc55e3031ee9d9903d426bba91c61377f48395991f901625919106b762ee99476a38672dd46ee59",
	        2715
	);
}
static void snarf_hat_2717(void) 
{
	snarf_construct_hat("/usr/libexec/liveinst-setup.sh",
	        "a0fea86f58c7a08a00573004426e28b4e5d0c9a1abdba2b398a4888f524cf70849dd25dd547f6e220e9485f656ed5e5ddad71dbde99174265919990f2039dbc2",
	        2716
	);
}
static void snarf_hat_2718(void) 
{
	snarf_construct_hat("/usr/libexec/totem-gallery-thumbnailer",
	        "9195b097b9c6326b2017f85e5715518c3fc8261770c0b213e92889ad0c27ce694a0cc1fa05cd1687e0dd21f0a34776f40313c168bffe1251a235ce6a1502ebd6",
	        2717
	);
}
static void snarf_hat_2719(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-contacts-search-provider",
	        "af94406d80bcc65b256e4232e88bf18e2601fe4fda92dbfe2225fb3e04c9683ab1194afd370a67f8272aad798f2cb3fa4c57e9157e9bdf2d64e9b45b80b59923",
	        2718
	);
}
static void snarf_hat_2720(void) 
{
	snarf_construct_hat("/usr/libexec/nm-openvpn-auth-dialog",
	        "7f68e85bfb05ffc4fef7b6fa08d1902e5d5cf5a781a8cd02081dab757eb419c931972566c36f12d99e4f330e33be246d2ed37b24a9e11586304dc050491e5baf",
	        2719
	);
}
static void snarf_hat_2721(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-calculator-search-provider",
	        "979f7653f5d7987456dba9f2ff8165531639fe9bc54945fd51efce97fee03e25f010021b7296ff9db293366dcd24f88becb67a7a791abf00fd31e3b9949de2a5",
	        2720
	);
}
static void snarf_hat_2722(void) 
{
	snarf_construct_hat("/usr/libexec/gsd-disk-utility-notify",
	        "8d585ba2d76eb0d829d699c23fe3accd323b47e6455068e2e46fe240746ff6ad0906e76b0cabd892d402794809819402bff39da0afe6372e8490d3d07f6964af",
	        2721
	);
}
static void snarf_hat_2723(void) 
{
	snarf_construct_hat("/usr/libexec/org.gnome.NautilusPreviewer",
	        "39b9b1b2940fc9464264440361d7989110f5c14807971f59358c7a59747f7776972f6585753cc0f8aa6902ade0531248ccfde66549b63d36d64463d420218035",
	        2722
	);
}
static void snarf_hat_2724(void) 
{
	snarf_construct_hat("/usr/libexec/pk-command-not-found",
	        "eeacb6b9b1c0876c43556971eef7cdd7880ef130ccf6a44a5f36250f9dfdedc3042182058be81cfb732672d31e5048db01d6d78b286a5d35b81845635ee6b01a",
	        2723
	);
}
static void snarf_hat_2725(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-typing-booster",
	        "2ac5dd4ad3a1124e5e21bf85a8e01639e79dc7ee22d514df6fb29025e805699fd21d491b59fc1cc3f5d0d24e9b542122fff7786be47984399f1f86b2d1789a7c",
	        2724
	);
}
static void snarf_hat_2726(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-typing-booster",
	        "bc0d7ced345e8ca3114930aea0c5ec873bdff064f810239eca5bdd8885cbe790ea0d31b28999de142523a32072f71dc6277a79714cdb50556dbcca5188c39060",
	        2725
	);
}
static void snarf_hat_2727(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-engine-libpinyin",
	        "9586b975edf25fb43a5ae9ad5efc325d83e482d2de545e6639d91767868328debbd5e83314cad13356d82dc1132ff8b1d65ee8010b36c51b5a2fe289e1301e90",
	        2726
	);
}
static void snarf_hat_2728(void) 
{
	snarf_construct_hat("/usr/libexec/ibus-setup-libpinyin",
	        "a250b922a0de152e1871c0934bee6a1f52c9bdcb6a834e33f5cc462052ce249a2675a618918d788e2f1f429b8bc52d3e226e9feee8fda06aeea135fc38f05ea2",
	        2727
	);
}
static void snarf_hat_2729(void) 
{
	snarf_construct_hat("/usr/libexec/pk-gstreamer-install",
	        "e0720325c26e66aab80701c74932ac1edb7c24f3f4569706247c9a663d435d2fc0b16bc93ff029017a6d82e6612fa7e85b4c282f3a3ac47f718102d300f367f0",
	        2728
	);
}
static void snarf_hat_2730(void) 
{
	snarf_construct_hat("/usr/libexec/at-spi-bus-launcher",
	        "a6c94e6ceac5713df4daf651bb060f683cce4843ec636b22653fd75b781fdfd44257a5891986e2dde7afb801242ad6e5d8bb6036b4f2635cdcc422d8850f086f",
	        2729
	);
}
static void snarf_hat_2731(void) 
{
	snarf_construct_hat("/usr/libexec/at-spi2-registryd",
	        "7fd7522a56d1fe0977e365930fa0ada5ca66e79802273c3bea24675cd6bf4f5a91034dcadd8c7c2b65761d7155f850befd2c7c7fb0a4da2268a234a34641420b",
	        2730
	);
}
static void snarf_hat_2732(void) 
{
	snarf_construct_hat("/usr/libexec/glib-pacrunner",
	        "7d441be1c468149c3fe15cffabb327310c5b9d2c937782f8c008ff48fc2899b809c4248d0e007f76039c8dcba6ba9d7c691eeefa560843ed1949eef7090d869b",
	        2731
	);
}
static void snarf_hat_2733(void) 
{
	snarf_construct_hat("/usr/libexec/mlocate-run-updatedb",
	        "9b5ddb744c0cec98e5ed321e068adc9cb3596641755be7b3a0f2f99fb54bcd249fa0e9de3a7e2231a1e342244d8522ac89f039cf9bf62b93325ad943b673e3d4",
	        2732
	);
}
static void snarf_hat_2734(void) 
{
	snarf_construct_hat("/usr/libexec/vi",
	        "4de68e826057eb0a01f248ed2c36d213c209c90f7134863600d24a98bd29276bf26edafb9c20bfa3c86aee83826fad8a6348a6e1145b7240e3eedef45a45fe84",
	        2733
	);
}
static void snarf_hat_2735(void) 
{
	snarf_construct_hat("/usr/libexec/dnf-utils",
	        "641dd5a92dc2e537af6679da290eddfb0c0b3e0dde88d3005cec77c61b7f3112fbd4cf22522c0cd54d32b0c695fe7cebf6bba12a69a274943f583be6af77956c",
	        2734
	);
}
static void snarf_hat_2736(void) 
{
	snarf_construct_hat("/usr/libexec/mock/create_default_route_in_container.sh",
	        "3417f6cd8b02ec8a51a15431ce6d45fdd54eb5c318d7aba623796a4b25ffb44a49dff157252009feeb59889d63379aef17691a9be57698d78c0a87dc586fa1d0",
	        2735
	);
}
static void snarf_hat_2737(void) 
{
	snarf_construct_hat("/usr/libexec/mock/mock",
	        "1b06c4dd9080f7de7ab5d4accae67d5cd39ca62d71073f77c7f48c118043b70f04b6210a65bfae6851ec49ad38b2b7766ca12cd378e87b948a20e9206404993f",
	        2736
	);
}
static void snarf_hat_2738(void) 
{
	snarf_construct_hat("/usr/libexec/pesign/pesign-authorize",
	        "cbc0efe5f1277c825eeac305c5d13d7301c531814da13e3320ced1f0bcfff45395d3ed2bd602fc5f96a8b3c5943deb07ad3b1d5f849e1f374046eb425865a238",
	        2737
	);
}
static void snarf_hat_2739(void) 
{
	snarf_construct_hat("/usr/libexec/pesign/pesign-rpmbuild-helper",
	        "691f6d53fe6b954566fb677941e0ece3135bc16bd4d4fbfc56ba8afe55c20315b1058f69073ef3bbd16896238c41a52e6385ead286c266cf0338c5395ab06d9e",
	        2738
	);
}
static void snarf_hat_2740(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/cachegrind-amd64-linux",
	        "4e51feb2ab7eddb1f4ac8e7e8045e7c50e00382b31f649cea878b30128795dec4ea459ea2717fb2ca513dda3daa7ea33e5e759d786d00b4dc2b0ff129a19052a",
	        2739
	);
}
static void snarf_hat_2741(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/callgrind-amd64-linux",
	        "c5118a064b226c6d6f93c770f1357bdf880df679e37d38f765e189f39898ccd49ac9339497a86d16721f58f339e2a27e9d6dfb6bf8bf543fe40e8ce833b34e34",
	        2740
	);
}
static void snarf_hat_2742(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/dhat-amd64-linux",
	        "dc49e92e69f854511103495aed98327a198210ab37475e7361b93232c6047877ff23d47e05d191242e91e74b96b899e37675a4a115874535f5a5ef3eba46238a",
	        2741
	);
}
static void snarf_hat_2743(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/drd-amd64-linux",
	        "70bbed039d3f031b724665e0815512c05e552a0337bf49f9b8531c140722f2534324a40ee5a7a793f820874786324ea280e95430d3f86345da8caceee8463cb6",
	        2742
	);
}
static void snarf_hat_2744(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/exp-bbv-amd64-linux",
	        "382641118e6a5c7748a328cd1b79844b426825af9557868119cec0b7da6ec720c7719a20c2971266fe861edb5f84a26213797417d871d62b20b1b31ae422e86f",
	        2743
	);
}
static void snarf_hat_2745(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/getoff-amd64-linux",
	        "6bd8bb341de6b213399766e73c1d4344a771908623a59841346cc42b141fdd873d8b46a13d07705e46eb476ac229686887a8ccab56e3f867e5a1b0aa10c4c552",
	        2744
	);
}
static void snarf_hat_2746(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/helgrind-amd64-linux",
	        "0c4f066a566ae3d22834436352d36757d3002fa82d44f4adacda2310b4d0bb802bc29c32d749360003e540c87f29ce3f1e442ef9270be35f2afe5e405e4daa76",
	        2745
	);
}
static void snarf_hat_2747(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/lackey-amd64-linux",
	        "d4146a34ead068ec4f05593a1067752d576ff0317efd538d26bdf82855b595bd01bc837979943f70a7b595bc6c6cea865319ed2c4a81f41b74dabf746e70efa4",
	        2746
	);
}
static void snarf_hat_2748(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/massif-amd64-linux",
	        "5fe673ffe8f10028830da715c92cc4fb739607b06edd4c96c8695d177aef196bf5b4576a347f576918327c8336e6d9b1b42d4e37b2ca87b9e249a4b585eef223",
	        2747
	);
}
static void snarf_hat_2749(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/memcheck-amd64-linux",
	        "13873da585d9cb7d1d424faf640c04a471e97f46b2305d655479f9186a31de2c3f7af4cca7ef911de5986303418688d806831a97c2def59fe5271a897c18b001",
	        2748
	);
}
static void snarf_hat_2750(void) 
{
	snarf_construct_hat("/usr/libexec/valgrind/none-amd64-linux",
	        "7763392c5d130af6890907a0cf13bbc9f2d73137f8b4e1528f8a6be3d9da2dddedfb64d53128e15fd15787e1b76ad9e4f9f739022b96a30df6c57b66a1288950",
	        2749
	);
}
static void snarf_hat_2751(void) 
{
	snarf_construct_hat("/usr/libexec/virt-what-cpuid-helper",
	        "1029b84afdc0d04cd439b4e45b05717d6e0b6226dd1255fb8433a1dc4b502cc3d4e0c719373473f44364b1b6c7b47125284abb2401918372194891ac4510c1f2",
	        2750
	);
}
static void snarf_hat_2752(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-software-cmd",
	        "a3766375b312c21d6a42e48df4629a2ed46b5c821cf9da34ffdfa97942fca2cfaa77d60fe0050696b2d9f929f408c8567147b1d4630ee12882353a20667dad16",
	        2751
	);
}
static void snarf_hat_2753(void) 
{
	snarf_construct_hat("/usr/libexec/gnome-software-restarter",
	        "a7a6e779a0186bdbaccbc5771cd686041760c4a1a309b7822a4172f7fe8d54b62b40e4ffca94c62218e211907b1c508bc352dfa20a723b025b90bd3cb0b7a3d5",
	        2752
	);
}
static void snarf_hat_2754(void) 
{
	snarf_construct_hat("/usr/libexec/emacs/27.2/x86_64-redhat-linux-gnu/hexl",
	        "95e27a201cdec7d2229e9c626c1e3ccbc1ad5f7abdac70c6bf4741a4993e0a041a93ec69e7f3e6bf94e6c8762591f075f56a57ac8bab7325dcd9d7c41ec4c9ca",
	        2753
	);
}
static void snarf_hat_2755(void) 
{
	snarf_construct_hat("/usr/libexec/emacs/27.2/x86_64-redhat-linux-gnu/movemail",
	        "fb40644d30e7bf3c629df729b91bdaf1267b088588609604a5115281abba99ffe1c64f682abb930c53557fa1e5a6662f7fe1942464df1849aa76be6a6e508c38",
	        2754
	);
}
static void snarf_hat_2756(void) 
{
	snarf_construct_hat("/usr/libexec/emacs/27.2/x86_64-redhat-linux-gnu/rcs2log",
	        "4afe4bc58f4ba0d1233d7b97a0344c6916bcef8c6b9cc478507fac466e8807cc5d20b77a828e09d58210f9ad9342b2eca0c507483b347dcc923f84471d4a8b88",
	        2755
	);
}
static void snarf_hat_2757(void) 
{
	snarf_construct_hat("/usr/sbin/VBoxService",
	        "bb8aa2107cd67e6836400fdeb3c7d2def9fb3da5cf5732493b3f78b009827f84be589ec6423c3eaefb387542a9f85d8622da2e809b5f2d8fce528491657498fe",
	        2756
	);
}
static void snarf_hat_2758(void) 
{
	snarf_construct_hat("/usr/sbin/accessdb",
	        "06e5dd30af06d1439798fe54ad28b32e1e07d0eb064d7824e97b090f6d6639733361f14e28b7bcd6bfec4168c3bf91a54eab4984b3bf4772f1c110a8d45024dc",
	        2757
	);
}
static void snarf_hat_2759(void) 
{
	snarf_construct_hat("/usr/sbin/accton",
	        "650f382568ba9641708a89edaa9569d976b2e638783a8a6364f1dc3d83707ca1f0add4d6a40d50893ac3cc273d9e84bbdfa343a56fa9b1520ee52b90c5b78ec1",
	        2758
	);
}
static void snarf_hat_2760(void) 
{
	snarf_construct_hat("/usr/sbin/adcli",
	        "0924c373807aa8ff1880dff95feb6788fa5905f772f5aff9728362f72cdf537143c309af6e856c54ea41f4c760e5e11793118aae41a5341ddf9cabcb305a0fa5",
	        2759
	);
}
static void snarf_hat_2761(void) 
{
	snarf_construct_hat("/usr/sbin/addpart",
	        "67eb25942843d8513c51b7caa76b48fb3b075254bb1fa14cc15665374afd3e825edfda9d76e4d7d49c590f656f6f467ca523681b377a559a584e649f6bb1b881",
	        2760
	);
}
static void snarf_hat_2762(void) 
{
	snarf_construct_hat("/usr/sbin/agetty",
	        "793849914f521e8159d1c6e498eed392490dadfd93c20efd2f15f4dc5d1319173262899c923dd21284402d7e4afc8066517313fb681d1d7a3de2a4c3d53dd286",
	        2761
	);
}
static void snarf_hat_2763(void) 
{
	snarf_construct_hat("/usr/sbin/alsa-info.sh",
	        "b7a1f1b8bd86ecfe566aa537e59d0157223dbbac6d5e4179b1eb3d12f5a92de2d103b7230376b1d02cf277f0c58c5d76207735197ab14c380b540f92458424ca",
	        2762
	);
}
static void snarf_hat_2764(void) 
{
	snarf_construct_hat("/usr/sbin/alsactl",
	        "330f2e7f09a147bed2c2aa2f85b3463016361bf5cd7b71976234d1cb21aa554db120053767afed7bacc692b165b6ccc921869a2e21f9676034810713567f7bfc",
	        2763
	);
}
static void snarf_hat_2765(void) 
{
	snarf_construct_hat("/usr/sbin/alternatives",
	        "0782c6705ef4c926ac9f3d61fbd36919e8a5f800bf4e18e6326c389143f9f59a1d2ef6161d3c64da27216cfb1d6be80dd0d14f4f9c5969b26aeaba9e0d85dc22",
	        2764
	);
}
static void snarf_hat_2766(void) 
{
	snarf_construct_hat("/usr/sbin/arp",
	        "65da7e03d9d8e9404a0a8b4147eaaa29d7b5526b1a0e0b65f009b2f46de5f2cb2143f537bdcc8a2fea8444e86418de9ed4550f16a5b8b1d92d3ae9c7c527c68c",
	        2765
	);
}
static void snarf_hat_2767(void) 
{
	snarf_construct_hat("/usr/sbin/arpd",
	        "ad19be210c3203f20aeb4ad414e63250c5252990474c2f7720cb08f50135f2c5612a40e71d0149d0f0dab3201f77eebd856c28592c109d3c8e94325ac43e794f",
	        2766
	);
}
static void snarf_hat_2768(void) 
{
	snarf_construct_hat("/usr/sbin/avahi-daemon",
	        "0fd0fb997bd526e51be7b068f4a705cc2ce465785bc327e26b9c28f363797482b45c51c0c9bf00531099e09cb02a7efb9949aa4f384f6882103163b47f834454",
	        2767
	);
}
static void snarf_hat_2769(void) 
{
	snarf_construct_hat("/usr/sbin/avcstat",
	        "01e5c9352255a7a1d8b63fbff27fdd153311d86cfefbebb5421242c63642c5a43038459a313f263847e0b3cc30169f621e5ce41dba35b73f930e5043c1795b01",
	        2768
	);
}
static void snarf_hat_2770(void) 
{
	snarf_construct_hat("/usr/sbin/badblocks",
	        "ab7f21943427b8315e5b4e67cbf6501f30efeb3e53a24114bf65dabe3737720fc9c4bb60de4cc534e5edf5c8e1ff75f292f14fb6bcb86816b2c58f52e70aa30b",
	        2769
	);
}
static void snarf_hat_2771(void) 
{
	snarf_construct_hat("/usr/sbin/bcache",
	        "20c4cb20cafd4293539c76828402582a561d76952b4315be255b3a9fc693a38e95a8251933fd469be54de813ab85eab8be32aa5d9a2f7e685249851e0e13b089",
	        2770
	);
}
static void snarf_hat_2772(void) 
{
	snarf_construct_hat("/usr/sbin/bcache-status",
	        "877381465c47b247ca0a87d169be4f1e4d1f0a866baf116cc42752711ced0fb7c223c96c2b07e931a9e64b76c25cbe099605120dc47863438c3201f354d5a253",
	        2771
	);
}
static void snarf_hat_2773(void) 
{
	snarf_construct_hat("/usr/sbin/bcache-super-show",
	        "f965a1b6a1a792e62d41988d05fa60e29e80446f85574beb0c6b1997eb12753ff452b474255ee59b4b7a7eaf772f7a51d1a4c275accb6f9ef7f2cac5a26b71d6",
	        2772
	);
}
static void snarf_hat_2774(void) 
{
	snarf_construct_hat("/usr/sbin/biosdecode",
	        "73ebc3ad96b597a869e928620be8faa75a31cabe2961429ead0fc1f3c1e675fcaeac192a30fa235cdd2cfc5b30a751bc2797d17191077922669a34f1790cebc1",
	        2773
	);
}
static void snarf_hat_2775(void) 
{
	snarf_construct_hat("/usr/sbin/blkdeactivate",
	        "a8163fc3d64a15a0dba1d073a7db84186ed1be02c81f382168ee73cd6f9f2dd0f2d3a7faa2f86c7fede8f88c89064a99b2cf92ffb7bb0a5c7fba54a99487b41b",
	        2774
	);
}
static void snarf_hat_2776(void) 
{
	snarf_construct_hat("/usr/sbin/blkdiscard",
	        "4c8a191c196c60b943cfd540db382422fe12bad2c272c29fe8e0692c872010bbdccede86bcd05d705cf2b1a8cd006ca347c7215fded0a7e6e57027cc103990ba",
	        2775
	);
}
static void snarf_hat_2777(void) 
{
	snarf_construct_hat("/usr/sbin/blkid",
	        "1c5f9b600d70e169ddb59fa47886ec40f320faa7ef6e919b689af408c925067dc94fa7c77deedc89eda95d8cd5e1e2e744fb09968f6cd156faa627e3bb8b7580",
	        2776
	);
}
static void snarf_hat_2778(void) 
{
	snarf_construct_hat("/usr/sbin/blkzone",
	        "b83846789d4e07c1c95ca614aba7df7dc5fbf6de79dca4bb3b61f5eacc1632016e8ca11452271565c777bc07f5d9442912306090bfe2541a19e9d7f8592361a1",
	        2777
	);
}
static void snarf_hat_2779(void) 
{
	snarf_construct_hat("/usr/sbin/blockdev",
	        "0913c1fd305aa319384d21564d18ee94f73b939cf9fd3e8e60be389d6f0f69b21c5bf6d63032d244fb5c5facb7dbd3b29f914978d0115a64e9397dd82eaea8ac",
	        2778
	);
}
static void snarf_hat_2780(void) 
{
	snarf_construct_hat("/usr/sbin/bridge",
	        "88fe9e97200d1c214c466f6e56314fb36cd8b3ac883f9069720ab6a733c28611a553902764f372e456c4d68c91041b288629f3abbf9bcc6990e82f29de7de3ed",
	        2779
	);
}
static void snarf_hat_2781(void) 
{
	snarf_construct_hat("/usr/sbin/capsh",
	        "1e1fda7c2f8d6ff3ae7400a7b035234b641c32c0e7f6c7544d3037c9b28d919297b63c5188f8bc07280026003c8041a3c9c3bbe20f3916bbce530d6b3176a389",
	        2780
	);
}
static void snarf_hat_2782(void) 
{
	snarf_construct_hat("/usr/sbin/cfdisk",
	        "b00dca0eb244684afd90d78b0f1ef0c0a3635f77e58be9821ec3c47ee8ee154dc781f3581703acc6dd17c1f16a494d750be9c1fd9b8cfef1401d4a4bdd027948",
	        2781
	);
}
static void snarf_hat_2783(void) 
{
	snarf_construct_hat("/usr/sbin/cgdisk",
	        "5aa6c9d0b20acbc173a7099c31b200aa40c24fcbe802319849ad2af453cda4ab365d3823bb8578751cbd50c8a35ca19ea2969d4660917f96b1d7b4323caf0ccb",
	        2782
	);
}
static void snarf_hat_2784(void) 
{
	snarf_construct_hat("/usr/sbin/chat",
	        "355c5763c8a38b605293cf021e403b5664ae6feda891468b288894503f6abb0c8f97174dc90c5d0e94ca95297b1ba2fee5c17b80bf2d8df490d08fd8585279b8",
	        2783
	);
}
static void snarf_hat_2785(void) 
{
	snarf_construct_hat("/usr/sbin/chcpu",
	        "846f327d7a99ab70622cf54bef2ddf9e6f1b59f46c64648cf7b40dbc8cad524ffd160e1d002da6aa45d454e7f18d840e3e8fe1773ee5fa20718b4a3059b1b059",
	        2784
	);
}
static void snarf_hat_2786(void) 
{
	snarf_construct_hat("/usr/sbin/chgpasswd",
	        "bef4e850d349af8a3388b274a8757cc3db1f19e522e918f5fde4c1b76c9b74f4b9c30ede37aca4fef7fa6053ccaf2f13b3d54deb1c0e7bd28e02a5630bc4d6d9",
	        2785
	);
}
static void snarf_hat_2787(void) 
{
	snarf_construct_hat("/usr/sbin/chkconfig",
	        "f16e54c562756572b74aafbdbc5a34eae014a6c9bfb47fb56b5b8232c0706ffc4de5cf668d16fb1d34327a9f02b29b9119e1ea776f424f089729eddd2796a546",
	        2786
	);
}
static void snarf_hat_2788(void) 
{
	snarf_construct_hat("/usr/sbin/chpasswd",
	        "8f9fdf3c94a7ceab1bd9b182e7f98b0f4393bcc46f65752fede291602a38483575011f19cf9cd67f84e18b46edd2773e075b139698e8f5aca9d78be4502d853d",
	        2787
	);
}
static void snarf_hat_2789(void) 
{
	snarf_construct_hat("/usr/sbin/chronyd",
	        "22eedd457e47a12640496c74e9f104f0cd75ee2485451f715c8a3f0eb5512bc0b450a34254f3d84ba2757aed9b19bc505fda7223cd40572356a6f713663d82d7",
	        2788
	);
}
static void snarf_hat_2790(void) 
{
	snarf_construct_hat("/usr/sbin/chroot",
	        "abe8d08a84d0487bf202006042f4ff706637e499d7b0f0bf6f06a20347607ae45be5f871fe1e561c522e98a97fc7fbdd599f7a595225cedc4cec94682b1603b3",
	        2789
	);
}
static void snarf_hat_2791(void) 
{
	snarf_construct_hat("/usr/sbin/convertquota",
	        "c58b4e2618634054e7587ad90033f97674eb99c3a6868e6d0b78d631caa0c2a43b383706ae8c288389cdb4a08cb77b84939c6999c84d0fe3ab87fb51b7422977",
	        2790
	);
}
static void snarf_hat_2792(void) 
{
	snarf_construct_hat("/usr/sbin/ctrlaltdel",
	        "a0ccd48289e9377c85d458e217fcd2ae46049084af719d53c673f6f508feb4671e0f6157bac3d2627c1475cfbfffb1ba503f6a90ef9ce8376c632079398cceeb",
	        2791
	);
}
static void snarf_hat_2793(void) 
{
	snarf_construct_hat("/usr/sbin/cups-genppd.5.3",
	        "52147e59e93981c0ebb08746bda723285760625af3f6110d07f163670581d0c2603c1352f6f11e25c6846240870124a2e00afb3dc5b94482712963cec12f4398",
	        2792
	);
}
static void snarf_hat_2794(void) 
{
	snarf_construct_hat("/usr/sbin/cups-genppdupdate",
	        "8786357b02e02540dee2b7f1634aae6c497a87a6af0c2f2532bebf7884f6a22d8f2e2a267e35fc185db597c7758ad42f58b4b2caed7952778e43fe6849252819",
	        2793
	);
}
static void snarf_hat_2795(void) 
{
	snarf_construct_hat("/usr/sbin/cupsaccept",
	        "b3fd440403564c6922576db6c5e45b1cbd3e59d14378b155bdff07b1535aebf8035df9a5ca113435d60093f45631494b1b595015ef9085f69a24e8d82275adab",
	        2794
	);
}
static void snarf_hat_2796(void) 
{
	snarf_construct_hat("/usr/sbin/cupsctl",
	        "76e68e76467b3849132dbd5d4e1268316b7eaebbff263e99d518660087b942d3cdf76f9bef2dfec606b31862ac03dc5126ddc3a8b71c8ab001fd9c1e1e82ebc7",
	        2795
	);
}
static void snarf_hat_2797(void) 
{
	snarf_construct_hat("/usr/sbin/cupsd",
	        "bff560172465cb8a508c8ff24cb0b9e3d5fd1e2f724dd8c0034627b213e22b2f2716b568cef237bdd8f11aa224836ff4841dde56afec3acdb96ea8e0e847c083",
	        2796
	);
}
static void snarf_hat_2798(void) 
{
	snarf_construct_hat("/usr/sbin/cupsfilter",
	        "1227cf3062cefbb561485038a9cdfa1f38eb7473e1c35db95857e3b4270d01611a570d2742c6c1ed73e6a7e070e87888c51d2420780b04fbd8168353e14f0d8f",
	        2797
	);
}
static void snarf_hat_2799(void) 
{
	snarf_construct_hat("/usr/sbin/dcb",
	        "750a6fa439f2e6add9d2f39306195b2c11c8dd89fce0a80c3d687a20590249d7580b7a8a26a90e8b45b7350e4a596aaa35d03a4c11ab28dc07deb6c59159f783",
	        2798
	);
}
static void snarf_hat_2800(void) 
{
	snarf_construct_hat("/usr/sbin/debugfs",
	        "dfe65fc38bde0c2a37d216e9ea714f74a1ed5a04d261daa0ce114cac3fec6c766da6cfef25298ccc5cacab023882ebc226dd765e5a21de398fb35c391f4997be",
	        2799
	);
}
static void snarf_hat_2801(void) 
{
	snarf_construct_hat("/usr/sbin/delpart",
	        "1012e47f20f06440ccfe94b2c62d01b2679963d7d105f78c9ee229b30fe616eb4a8385fec77dce41b4c42b40b754f399b684aec2a236a9b939ad5a29dc9f9001",
	        2800
	);
}
static void snarf_hat_2802(void) 
{
	snarf_construct_hat("/usr/sbin/devlink",
	        "c5451a264965959082c0523c27ccaa368a5a4b8c0a038b6475daee726ef9de5413facdb7997aa229637b64d28e3519923e86a97ee50aecccd2b70935224d27d7",
	        2801
	);
}
static void snarf_hat_2803(void) 
{
	snarf_construct_hat("/usr/sbin/dmevent_tool",
	        "4a76401a288a7d365335723ec3c270d80e085d85becd4ad0abcddc6b6212a8aa9fff4d55da3064c1eaf99a6f075a861f2358158b84890e53eb6deefa9cddf369",
	        2802
	);
}
static void snarf_hat_2804(void) 
{
	snarf_construct_hat("/usr/sbin/dm_dso_reg_tool",
	        "4a76401a288a7d365335723ec3c270d80e085d85becd4ad0abcddc6b6212a8aa9fff4d55da3064c1eaf99a6f075a861f2358158b84890e53eb6deefa9cddf369",
	        2803
	);
}
static void snarf_hat_2805(void) 
{
	snarf_construct_hat("/usr/sbin/dmeventd",
	        "5e33d971de5b55f68235b4f512e8ef89ae3efb96d34da9bafb74ce1344974959c0d6a8b401c996f0d01a2e8c00b2c5860b36497dd97c25ef3007405d00209da7",
	        2804
	);
}
static void snarf_hat_2806(void) 
{
	snarf_construct_hat("/usr/sbin/dmfilemapd",
	        "cfc432fa9348ed6ee95acb2d494f4d43c28496c5107ff48d9dc7af1243937e80030890875c873298dae080c2057bd2ca239d214bfa00283eb7a289a3a3734194",
	        2805
	);
}
static void snarf_hat_2807(void) 
{
	snarf_construct_hat("/usr/sbin/dmidecode",
	        "02a1a7bc4244dc6f5f8137209f86c08cd779143f024f280c7ad69d08c4d94730fdc1903513591f404e62f1df0fe6b4e03c5237807e74ea48f8c81e42bb25ab0a",
	        2806
	);
}
static void snarf_hat_2808(void) 
{
	snarf_construct_hat("/usr/sbin/dmraid",
	        "2b31f19c61bab32fbe61251476eda4308012893f7d0afd65602588d975e604017f04ef14c42865f4ad769a32a627fbce2482d73d55fa7504a8cf35cea514f425",
	        2807
	);
}
static void snarf_hat_2809(void) 
{
	snarf_construct_hat("/usr/sbin/dmsetup",
	        "86aaf38d6313af9db29216d74e26c8427d3ec14c592e61fd740d40e45b776525001e2a9a949165fff2ac5ff924b8ed542c08aa6e4e0133a73c01b4849dee6974",
	        2808
	);
}
static void snarf_hat_2810(void) 
{
	snarf_construct_hat("/usr/sbin/dump-acct",
	        "4a71d08d864424d26c72f9a534cb45f2684eebeea7dd7f213e047c4dc1e15262931ddc9d0d2f4ac92a2422b7450be4b1c3bd9574f2aab554723ebbd601c7d7ff",
	        2809
	);
}
static void snarf_hat_2811(void) 
{
	snarf_construct_hat("/usr/sbin/dump-utmp",
	        "7ded304b44c93e438f1223f8eed94fd25b67a41049cffc3369460d4453962284935338cd8b4f8dc024415f8925d278e423f2680f4aa0d9d67f35fc9fb7025a24",
	        2810
	);
}
static void snarf_hat_2812(void) 
{
	snarf_construct_hat("/usr/sbin/dump.exfat",
	        "cfc17cf7650ed0fff35f9cac881d60206328bf533560bf88f122306f4ef8cb3ac341672ff1b2e646d7cf0f54037c976061b8b773933ad964bd77fed37ec68559",
	        2811
	);
}
static void snarf_hat_2813(void) 
{
	snarf_construct_hat("/usr/sbin/e2freefrag",
	        "789b755080710fd48025d4c7ca28f2f9e176dd49a00fbd52588f0f25e04340abc5d8cbc6c656c9bf8a6e1a6215fc2820e91c5c649e9ec92a0ff8e1df11e6787e",
	        2812
	);
}
static void snarf_hat_2814(void) 
{
	snarf_construct_hat("/usr/sbin/e2image",
	        "c317c9b48600ba9c47adea7f7a6fe2200b86660bdcd8d6b38dd3fc9a14f82ed2d33eb233667acbc679839cc27c5df2aecf05fcf1354248280cb009d582d4b2a3",
	        2813
	);
}
static void snarf_hat_2815(void) 
{
	snarf_construct_hat("/usr/sbin/e2mmpstatus",
	        "91ca3580828d57103987d939a2a845f5f7ab26409766f6e928368ef04acc2c332af348bae0d3b15cd3d33125f95e7ba1d7df66442da396059de1804d01f88203",
	        2814
	);
}
static void snarf_hat_2816(void) 
{
	snarf_construct_hat("/usr/sbin/dumpe2fs",
	        "91ca3580828d57103987d939a2a845f5f7ab26409766f6e928368ef04acc2c332af348bae0d3b15cd3d33125f95e7ba1d7df66442da396059de1804d01f88203",
	        2815
	);
}
static void snarf_hat_2817(void) 
{
	snarf_construct_hat("/usr/sbin/e2undo",
	        "1b33bf576f6140eb4be70e4e86537912a072d02f3cd4ad786b8e7e850b875d39154d47c6a26818251676dba644610ac2929a5e56fa9f16717e396d47b6dd3700",
	        2816
	);
}
static void snarf_hat_2818(void) 
{
	snarf_construct_hat("/usr/sbin/e4crypt",
	        "0aaaadf6b05b95ede23b5ec15878cc84758f038a003dcc5fc734297b971e76c9d2e4cc4458f8c353a35dbc55bf8024fa9868a0f51b20bb66a2efc85e8770fb89",
	        2817
	);
}
static void snarf_hat_2819(void) 
{
	snarf_construct_hat("/usr/sbin/e4defrag",
	        "971b7fda19bada402de9fd4e99dfc6d1b30657239a400fd4aaf1c99d3b15735430714369a4336d58b5815c7d553516273178936f66c622ebd9d983cb1e93414c",
	        2818
	);
}
static void snarf_hat_2820(void) 
{
	snarf_construct_hat("/usr/sbin/eapol_test",
	        "8e9e08e43868b15a42cc7757ada4eeb1c23c7a2fd6d3d2a8012412177fc5a4621b8969fbd7f00af19456b15c7a6696960ec8cea66b0f5be406d6404503347045",
	        2819
	);
}
static void snarf_hat_2821(void) 
{
	snarf_construct_hat("/usr/sbin/edquota",
	        "45b647b4ee1ef71ec58fcb5ba82c5e8f08bbef12487e61cf5186ac349d666bf49369f66313f9feea688e789381b316c29eaeb9e5e33af333b5c551dc1b35e300",
	        2820
	);
}
static void snarf_hat_2822(void) 
{
	snarf_construct_hat("/usr/sbin/efibootdump",
	        "cf6a0b367970f80000bd1f05483dc5ff9c3cd3c5004645c76efe6ae7e056a64e549c4ba60fdbf29db22ee6c47b08eb1284e93413a5e0d8bfa951b710d3bb7516",
	        2821
	);
}
static void snarf_hat_2823(void) 
{
	snarf_construct_hat("/usr/sbin/efibootmgr",
	        "1c8bc5ddd6253e10c5f3d8c0c544f8289acd895449c50b105ea4db25c9dc5dec310e63bf3949ee99c0696de7e64bdf2882dcab28875c4bfb3d97305ceda527c8",
	        2822
	);
}
static void snarf_hat_2824(void) 
{
	snarf_construct_hat("/usr/sbin/ether-wake",
	        "82677ba88c03de46361f1e96ce8bf5350804481ffe65a8a9297659e4ffdee37ea3e0c07cfae392dfcd21792d73f28b713aa0b92d673e9d5c63a85f79154ab3fa",
	        2823
	);
}
static void snarf_hat_2825(void) 
{
	snarf_construct_hat("/usr/sbin/exfatlabel",
	        "cb76eb623c46e81577b7edbfa7708915bd7e59af966ed6df8b2f032a6506347a34a884888cb7d9d0dc528367b1fc84788eb71befc19b7dd72ce6f42936ce5a9a",
	        2824
	);
}
static void snarf_hat_2826(void) 
{
	snarf_construct_hat("/usr/sbin/extlinux",
	        "8a86ddb257482d57dd0ac75a3fed73f7765a25b533119fef04441427cffb444d0677beb4031b53ccef9a0fdc4e8278532f67e6bf093f2b1d24f2ed6af498214b",
	        2825
	);
}
static void snarf_hat_2827(void) 
{
	snarf_construct_hat("/usr/sbin/fatlabel",
	        "dd38448b7e6aeb94bd25846bd2fc6a42b78ae3a4e909147a9344a2c5bd33269b348d747946d6b810236bac730e890d068402551f8de80b9512df9776b1e4a2c5",
	        2826
	);
}
static void snarf_hat_2828(void) 
{
	snarf_construct_hat("/usr/sbin/fdformat",
	        "bc20812f9781d3a16ef1838a5d2f7c51116cc64d045757cfaf65f3c462ad95499ca72a96938df20f9b7532a402d33dfaba90d9c654e573169e86d36359df7de5",
	        2827
	);
}
static void snarf_hat_2829(void) 
{
	snarf_construct_hat("/usr/sbin/fdisk",
	        "409cdb4e2871f5d200575844bcfb5ba002839381bc9d79795c4dcb37bfc822f55e07b746c4f73df1c507631fbfa3a1081c76b640e4fbd83b5fd7c192a152e039",
	        2828
	);
}
static void snarf_hat_2830(void) 
{
	snarf_construct_hat("/usr/sbin/filefrag",
	        "083257a96ff043adb25a4f97b6d187f7e54204865d5fe1d4f30910782f0a059f0c0495881665d081040007a57e19e25c4755de5eaf902d268223cc714146e6d9",
	        2829
	);
}
static void snarf_hat_2831(void) 
{
	snarf_construct_hat("/usr/sbin/findfs",
	        "e0c4be0b5db4d698c14228bf25f75b9b9d6ea202cfa98a62a7d89a3087bb6ad7ebe855fe3bf1b462d0404db97ed578f3a871bc4b4b8292a5e5e4354a98dd89ef",
	        2830
	);
}
static void snarf_hat_2832(void) 
{
	snarf_construct_hat("/usr/sbin/fixfiles",
	        "c892fa761d5f5d4e96e1c4e19e2b110dd760db6fa8c3ad4a993dceb6243af82a19a91c2b5f8e1784894e69f9f794e1fb68114725818ee451afd60a1e4f6fd0b7",
	        2831
	);
}
static void snarf_hat_2833(void) 
{
	snarf_construct_hat("/usr/sbin/fixparts",
	        "c98c35ab1a6624a9bf83bd0469067ddc6ff288e11fecc6571061cc634464a7ab6f60ecd96fc93a635eb1778bc1f3a825bdbc4f5becd449dc09d91fd013b8d922",
	        2832
	);
}
static void snarf_hat_2834(void) 
{
	snarf_construct_hat("/usr/sbin/flashrom",
	        "a4102a52632fe3a220fde8c5021bef1c4b0f51c9b31377f79dcae7a80953314819faf4db1ce874e3a2930d142910395d1076ea3653a855778981b64d6b9dbc98",
	        2833
	);
}
static void snarf_hat_2835(void) 
{
	snarf_construct_hat("/usr/sbin/fsadm",
	        "5b0ff3f01a44a93ffa977a8c6fef8ea9f10b56ac484f5dd225e75eb0c4f290d9b40360d5059b0337b717de3075f262cb55fde8a557e6a7588a552e3c86ad100f",
	        2834
	);
}
static void snarf_hat_2836(void) 
{
	snarf_construct_hat("/usr/sbin/fsck",
	        "c3ea684a8031727c58d5de6b99d460848df480b2e823351d124e7775f0ffa87ceac3970e835064d2a764b37e0e6f59614b240287e4a22dd1930c53e1c0fa0d05",
	        2835
	);
}
static void snarf_hat_2837(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.cramfs",
	        "41b797f36cfd8fba4f1fce10e4ecb01a9b525aca263f3b918af4d15a9156a1669fa8cc8a9556eae64a2b879113efe6b5e79a6d3299f2a1316503e43afcc88d16",
	        2836
	);
}
static void snarf_hat_2838(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.exfat",
	        "a065d7c9accae2c84e8e0a56138bc1f18a737b280aefa7a12a81ca3b9c2f40935ec2ea68cdd81595597810a3f3cf15f8ca594556c82403272b707d003e7f97df",
	        2837
	);
}
static void snarf_hat_2839(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.ext4",
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        2838
	);
}
static void snarf_hat_2840(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.ext3",
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        2839
	);
}
static void snarf_hat_2841(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.ext2",
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        2840
	);
}
static void snarf_hat_2842(void) 
{
	snarf_construct_hat("/usr/sbin/e2fsck",
	        "7557fbf1bf371e2b3cbde9ceb5f04d97c1dd1dc7d34fe7479d8c6f1ea03e0ea6ba7d5ffaff0f348fd11218b06d018864d40af7a07fe003b8ff578f0c9f5f7b63",
	        2841
	);
}
static void snarf_hat_2843(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.fat",
	        "26b1c82026591a4737afbcf9057c5976344b89356b5bb6285da4cb72e4c62472e19e188e1c6e7a71fb40c081428752008b31883528e1b4056d7c53d2e72b093b",
	        2842
	);
}
static void snarf_hat_2844(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.hfsplus",
	        "f4e25c98eea914237e4597876275e01d71defe48c2b99e94fe43f6f5caf8db12bcab9e11da3747ed344d976decc26908f1c8614b4856e08c42480f2e8c308ec2",
	        2843
	);
}
static void snarf_hat_2845(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.minix",
	        "23e3eb21972aad6b6ceaaba4daa03025378252a35d2d318e6da121ef2ce3bd0649f1eac6a7925642fe069cc74146888dd1315c634e838bb215c9ff4403a44bd6",
	        2844
	);
}
static void snarf_hat_2846(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.xfs",
	        "b96f8755f54155fd436e5f99a2ee1eb0772a0d647c017f5e1816a780009e16878b4662d2fb49e51dac950da97fbbe4c311555ff564a7f90294d334b82b059cf7",
	        2845
	);
}
static void snarf_hat_2847(void) 
{
	snarf_construct_hat("/usr/sbin/fsfreeze",
	        "487f92606dc57139f5444491b51bd17116cc80ae8686ddd56dd3042986c57421916e895cafd38bb7bfcb689b47aca742f3c1d20a771f1950070a46c18ad03f3a",
	        2846
	);
}
static void snarf_hat_2848(void) 
{
	snarf_construct_hat("/usr/sbin/fstrim",
	        "7f4b5cfab8d8ac51406245f0fda833f11d230bab760d564497d7ff255c0a75bfaea8c69d226cde023bbe53c8925f37c7658720deec88fae38a8165f3dd3f4ba7",
	        2847
	);
}
static void snarf_hat_2849(void) 
{
	snarf_construct_hat("/usr/sbin/fuser",
	        "79c013997da21115e73c869e2eaf8471dfa8c60acb59b26f7b0b6bcac24ee395880338927a6db60a21999d3539355b1a12926b6cc7e6ea3d4cbc4c11268988d4",
	        2848
	);
}
static void snarf_hat_2850(void) 
{
	snarf_construct_hat("/usr/sbin/gdisk",
	        "26374249aa2b7f0f1d2c4abecba64e41427d866f6816e7250a09ddc4deaed28cd08837a86ef996b26f773936a4fe0f228e13d539572eed188741dfbed0938637",
	        2849
	);
}
static void snarf_hat_2851(void) 
{
	snarf_construct_hat("/usr/sbin/genl",
	        "7b88955e944cf72e091e1c3b9a2b31d00b397287daeed13e12caefa50437fcf8e19902f54698fbd925719c7de9be12c4908eda4d63c388f62f61a5317d21a936",
	        2850
	);
}
static void snarf_hat_2852(void) 
{
	snarf_construct_hat("/usr/sbin/getcap",
	        "badc0f82f8fd2f45c4f9b12965834b51930a6e7157c0bcb5df35970ca295368a53f04931da0eb4b378c4e783820345f0f230346d6d2fd375535036c2fb9db83e",
	        2851
	);
}
static void snarf_hat_2853(void) 
{
	snarf_construct_hat("/usr/sbin/getenforce",
	        "704a60697c8a7365ec27363be9147c128743e4a1fb60c91d764aefb8c8e931a5bf67eb525f8c6b16b7b16711a4040dc8bfb071a53d36877abffedf4281434674",
	        2852
	);
}
static void snarf_hat_2854(void) 
{
	snarf_construct_hat("/usr/sbin/getpcaps",
	        "e8b30a92149dc2ec8e826c37f1ef3c47d962575a3b5a29d2513b3f8ab50eb8cd4bf006f2ba119e293847b61f14b60add4c7f8403fae6ddaae848ad5f8895b5b3",
	        2853
	);
}
static void snarf_hat_2855(void) 
{
	snarf_construct_hat("/usr/sbin/getsebool",
	        "adbd8e25e3fbbe26b54fcdf3ef7a5fc3ecda990c878cf28e2507a13cf3c006ed33d88b146509a83147721fab2c5e220afd2e19a5a0c8e7c4e220719fd4bef78c",
	        2854
	);
}
static void snarf_hat_2856(void) 
{
	snarf_construct_hat("/usr/sbin/groupadd",
	        "18fe95036f827afff1386b59e39ec58dcba69a923ba07bbd92a3b9806a003a989b680ea3015848577e52891652de3ff0ca3016f543aa571cbccbcbfdeef04523",
	        2855
	);
}
static void snarf_hat_2857(void) 
{
	snarf_construct_hat("/usr/sbin/groupdel",
	        "987cc2c3ec6f0a74debf413d61bb1f1d693fd87d8ee0dbc4e3f06c6dc8a9a1473eb4ea5d8b354fdbe8b6807a33de850c263e25d1d5afcd34093492290e2b83cf",
	        2856
	);
}
static void snarf_hat_2858(void) 
{
	snarf_construct_hat("/usr/sbin/groupmems",
	        "30d5193e3e82a18b1a8d52f236aa8380d461569227c392a4f33b36fecd5106db8da5d150942e0e10e5c9ec9fd834dd0b8b87a99298725a4e13233a578dcce8f4",
	        2857
	);
}
static void snarf_hat_2859(void) 
{
	snarf_construct_hat("/usr/sbin/groupmod",
	        "10e6a06e8a45770e7efb440f73ebdad821db777be12e616d1a83b04b9a10d5ae1174e3e32d16bf46757fafe5b8e79d756fb427352427bba406a3690917c282ff",
	        2858
	);
}
static void snarf_hat_2860(void) 
{
	snarf_construct_hat("/usr/sbin/grpck",
	        "1a0043ec90a7bb6accb5df8eb4cd1872c89bbbaecf62e43f005afd8f2fde8b0ca24688d7a1d7840ac979475d55c51f316ef665f6d485abd9d4de5a4100d07e40",
	        2859
	);
}
static void snarf_hat_2861(void) 
{
	snarf_construct_hat("/usr/sbin/grpconv",
	        "581f33a917af3d71a031363ca01a6582e4b397f576c7b7cbf2509d24e4d7936ca87f29ab15be6b9006f35beba1e994631a47052ac4f5dc3b1b2743a39420a4b9",
	        2860
	);
}
static void snarf_hat_2862(void) 
{
	snarf_construct_hat("/usr/sbin/grpunconv",
	        "c6f798583be2bd71f907be6db5798f0caa211e33b050a29249e7f3b36693259843ba22d7a2d0b16f417899be94cddf419798c3f2da9ef8369e4c720c2658a174",
	        2861
	);
}
static void snarf_hat_2863(void) 
{
	snarf_construct_hat("/usr/sbin/grubby",
	        "6f126d5f8551999c3f3a7923acff65db8a89b0859be71316ca2ace6c80ead0a02e8b21f91a234a7b7464d3f87d3407da67b4601cf2e6b6d76ef0fa33ff0f5e68",
	        2862
	);
}
static void snarf_hat_2864(void) 
{
	snarf_construct_hat("/usr/sbin/gssproxy",
	        "a1b8307c2fc08a4f6bed78cb1cadbf6564d4f76a07c597e82ebfc3fefe7de5c3c91c43e7bc8c902bfb9eb6e1d38e1c60032617bd3d9e1355789b5efad6f93dd5",
	        2863
	);
}
static void snarf_hat_2865(void) 
{
	snarf_construct_hat("/usr/sbin/hfs-bless",
	        "7988b6c5c5de0bf47311c05c70898e1fd2d1e5f85a931287c7dd48c9a1546ec83bb5d9b5ab63b2510f8c3e3c68803ea885a0674400e6c8d3e97639870920472e",
	        2864
	);
}
static void snarf_hat_2866(void) 
{
	snarf_construct_hat("/usr/sbin/hwclock",
	        "a56fc5dfc38a134d2c9bf1e05631e214cddf2d96dc6beddfd73cb1e7eecf32d19de5ca24bb41c48b332a1e8af2089208e335c240990cecf6b9f7b3553fbb8f5e",
	        2865
	);
}
static void snarf_hat_2867(void) 
{
	snarf_construct_hat("/usr/sbin/hypervfcopyd",
	        "48910c8d6eb8b3de8e21a314094656b1236aa81aa2c6dc8bf58c4b5c8f43278f8bb0883ccfd14881e5673bb5c3bc9b7760cc952561dddee00ee6198671fbf42a",
	        2866
	);
}
static void snarf_hat_2868(void) 
{
	snarf_construct_hat("/usr/sbin/hypervkvpd",
	        "4d5d26aa8f53cb20086f297dd8cc0e03b3b366f4190d3a8d52d79b6166e79134c000e1c436bb2ce3a95bd113f727135daaf70abd79cc4712d9999049f626747f",
	        2867
	);
}
static void snarf_hat_2869(void) 
{
	snarf_construct_hat("/usr/sbin/hypervvssd",
	        "11f793fe044442d33e4d8e7a5639b3eb99848fab2745b3e221c51f9584fe4b4c9ec73f75c839a3ab80dfec988849f89f5d9e458daebd76b0af56f096e73cdbea",
	        2868
	);
}
static void snarf_hat_2870(void) 
{
	snarf_construct_hat("/usr/sbin/ifcfg",
	        "76931f0d54837508cf3ff0e80473bf40b54231e6f1b90b1df6d5506b704bc93964a938ee02a05b90b629d414eed0d18e59c84913fd4ac908b7f2db793c9fd540",
	        2869
	);
}
static void snarf_hat_2871(void) 
{
	snarf_construct_hat("/usr/sbin/ifconfig",
	        "ba082930b99e17e82d2f17659160233d07893d4b9b7c05b97bef0d01792bd50755111727df35193e7dcb168aedc987798fc7555455da70d3a446ec95a6a1bf2f",
	        2870
	);
}
static void snarf_hat_2872(void) 
{
	snarf_construct_hat("/usr/sbin/ifenslave",
	        "c0d1217cf600f51172770d17637cc05c88a148bca1caaedd15928bb110461e2c4f85eb2ac477f298bf99c776994a04a63b49b92570f8d51eb82b88bb909a3cfe",
	        2871
	);
}
static void snarf_hat_2873(void) 
{
	snarf_construct_hat("/usr/sbin/ifstat",
	        "ef7892557919392921571ed73765e427beb2fc03b0b9042a576df37841b0ffe1587ab2024ee8cacf2ec7397f0e815113ce51c986a341d4398521985b7b398858",
	        2872
	);
}
static void snarf_hat_2874(void) 
{
	snarf_construct_hat("/usr/sbin/installkernel",
	        "d96660edfa2c6738c63bb761a7ebb3e39d9f4c57422fe6d513e0aa08b7d318507ba097db541ef81a0d6f7fedca62e4ebb3a4beaecfd06b7ff8b75f49d7b324ac",
	        2873
	);
}
static void snarf_hat_2875(void) 
{
	snarf_construct_hat("/usr/sbin/ip",
	        "0aaa85942f9d493d00b6066678a068839f79d445bca57f821c88e90cb9569cea0f2bbd58f4af5eebf211ea6cd26bdceb8ee978b4251632342c93faa73e3dfc0f",
	        2874
	);
}
static void snarf_hat_2876(void) 
{
	snarf_construct_hat("/usr/sbin/ipmaddr",
	        "ff00d20c73e92051f7bf23fc393cd794dab077e757ab17ab25cf07df7cce0e51a82163baff47bb6f2ac4d349d4b15cee43f5065df3f2bfabcb9832df3f462852",
	        2875
	);
}
static void snarf_hat_2877(void) 
{
	snarf_construct_hat("/usr/sbin/ipset",
	        "5d5c7c35903ddf0d93293cecc7cd10d35717309f91a2758f9b2ad1d17dcf86d557e5296777e8ab4e01d27a362be27aaf9e00a3e310e9e30a6bbecb8f7bf080d5",
	        2876
	);
}
static void snarf_hat_2878(void) 
{
	snarf_construct_hat("/usr/sbin/iptstate",
	        "e89ec8e345e0348f9477c795d8bacac7736d70ce9c6c03379a52cdae8d2a61a2184e205c6f48a2cd89f21d4fcc3e66ac82c9d95dc45eda158c3a8c41eb02d406",
	        2877
	);
}
static void snarf_hat_2879(void) 
{
	snarf_construct_hat("/usr/sbin/iptunnel",
	        "3e0b87963c0551e2a96f5109c986cbeeaa556897340b4efdc73abc2f8bf364a869c30c27ca8cf3976d3fba3aaf0b377804628ee436d574f53963acae6e351a93",
	        2878
	);
}
static void snarf_hat_2880(void) 
{
	snarf_construct_hat("/usr/sbin/iscsi-iname",
	        "f26590c319c9fb8fccc7f1aa079a82f6e39783b7beb9f902bd74bea76eb06246378c68cc9ecccd003627431baaeba5208cb08cfcdb345bc46f2818a358e7bdc9",
	        2879
	);
}
static void snarf_hat_2881(void) 
{
	snarf_construct_hat("/usr/sbin/iscsiadm",
	        "7423d77a67bb00862ec34aab5e36d1c2a85e49f3f13d4fd40381ff4b1a16dd68f410c554692b8680cdfcd74ba0dfadd97ee8cbf701710c9945e2200b373de818",
	        2880
	);
}
static void snarf_hat_2882(void) 
{
	snarf_construct_hat("/usr/sbin/iscsid",
	        "9f956bbcfb85e453fa5f7a7ece32f0ec56adf831ec8e474cfda0b15fb7957ed2c3e377bf65ac29d0aa3639e89235c27c849a44307582ac6e77f12f531516065d",
	        2881
	);
}
static void snarf_hat_2883(void) 
{
	snarf_construct_hat("/usr/sbin/iscsistart",
	        "42d4df68ea57292f6ef9b4d614d1c3e07382ee87a4b281b4d5e51758d73d55ff7ac61c854faaf971150e07e96d9a1763bf82f02c5996db2941c0626a5c68e253",
	        2882
	);
}
static void snarf_hat_2884(void) 
{
	snarf_construct_hat("/usr/sbin/iscsiuio",
	        "2ba128c9e3315066556863141db4497c23fd04952f8c6ce024f0d472e7ea0e32725384aaa355f426562bdd5c36b8a23a0556b793c62cf91da42fbbce7b7b0450",
	        2883
	);
}
static void snarf_hat_2885(void) 
{
	snarf_construct_hat("/usr/sbin/iw",
	        "f3165aca913f8763069212063d5bedbd7900411015bc2124f19c043e91952d6da53b1dfb1b6fd260f085c9430d2fce5533c4781510f18954343c166760905423",
	        2884
	);
}
static void snarf_hat_2886(void) 
{
	snarf_construct_hat("/usr/sbin/kexec",
	        "fe59361e7ee38ec831c1878e73cd2f5e1f172a4f19c543e6f337d31934753189b91ce37852c385bc10c7adf19125aff65744f061f3acb5f9f4321563aceb1039",
	        2885
	);
}
static void snarf_hat_2887(void) 
{
	snarf_construct_hat("/usr/sbin/key.dns_resolver",
	        "0c2b61dc6aed3ad8d507a8c33d047c3a4586072e50e15aae3ac641bf7ab6990fff057ccd0e068fd773c6f9ee86c4605f8f4f4ebef9a4779463c7af7844e27b78",
	        2886
	);
}
static void snarf_hat_2888(void) 
{
	snarf_construct_hat("/usr/sbin/kpartx",
	        "8d8d69c1f91a90d217d465f5994f27fc41c740b41aa3ee28b6ea44b63605b50a2054df4b6837c41a1e4bf24bfc8c98086686a780362e3ef1fc6a13d6feb9df10",
	        2887
	);
}
static void snarf_hat_2889(void) 
{
	snarf_construct_hat("/usr/sbin/lchage",
	        "72fd3a8d65754e251eea0d54c9d707ad1d181209e1b5adcf6816426b758aff51704268f443964b2431a8f895f9feb9c1793a1b926f789ee4d3f2a8b6b32be604",
	        2888
	);
}
static void snarf_hat_2890(void) 
{
	snarf_construct_hat("/usr/sbin/ldattach",
	        "27c9922294f4547363b4553260c0820495dabfa95198d08c171ccfdcbf6dab30dd68132d7e2c2f4417fe3b98186a34fe2d300a190229da76bfb19dfe6f4c325f",
	        2889
	);
}
static void snarf_hat_2891(void) 
{
	snarf_construct_hat("/usr/sbin/lgroupadd",
	        "8b58ed586eefa44a8645b1c6945308e9d1e927803f5de6a29e7a33e29dac40bc7129bb716b91cb99953879852fa2dbf7d345c59c9a1709b37e6ae668c3e813cd",
	        2890
	);
}
static void snarf_hat_2892(void) 
{
	snarf_construct_hat("/usr/sbin/lgroupdel",
	        "218ccc2005eb71b11afb0bccbcf2e8143dde2a860869274356f259eb413f0d75123b3e7d40c0d3fc85d17f8fe10c88c8b916f97e843f7386482ac1fd57c095f0",
	        2891
	);
}
static void snarf_hat_2893(void) 
{
	snarf_construct_hat("/usr/sbin/lgroupmod",
	        "bc1e16289b140de9a8586e0374f2a3dfd6a6ca6d885c63b8cf68d6d946ff1a3e90c010739110e7d05e4627792ca174c4f424e768c0b7e9d23e6a4a3f48b81359",
	        2892
	);
}
static void snarf_hat_2894(void) 
{
	snarf_construct_hat("/usr/sbin/lid",
	        "f40ba6183f27c8b7a1375a9212f57bd25f9d809b62c9ab63be778033d802ac6f269b637be1cac33ccc6d0a9c172f385c67d12eabb0432ab877392e299c2754d1",
	        2893
	);
}
static void snarf_hat_2895(void) 
{
	snarf_construct_hat("/usr/sbin/lnewusers",
	        "c217ea967de1c1fd590f3f1895be798894a9edc6b8132439776dd2176ab7b195687c2b298d6279d917e58433ea63416ae5dc19bb4923308f20b9a8276d7ca463",
	        2894
	);
}
static void snarf_hat_2896(void) 
{
	snarf_construct_hat("/usr/sbin/lnstat",
	        "0c2997a3e8d2a470da938901dae4482f8173eaa4fe915456626bac7f60ae2c3c5a144245d3334b9e3be81823b1652e693d31dad7ef020b6c5b105b75d1a41ba0",
	        2895
	);
}
static void snarf_hat_2897(void) 
{
	snarf_construct_hat("/usr/sbin/load_policy",
	        "47672fb4332bbe223baf9ca490e2c099e7ec56a9454e05cc20e106b0c6daabbe65a18ab88855bfb448e2ef54f4f7a17335c4dd7877dea00a1a7dd15bc25b5bc3",
	        2896
	);
}
static void snarf_hat_2898(void) 
{
	snarf_construct_hat("/usr/sbin/lockdev",
	        "d2bb24e5da52a133a2286c7ea8b15838594478808671a70c4d3c7284428ade5c1ee660e13b49c998b2b483d3eb4122656ab29469c72416131e97fc77d16c53e2",
	        2897
	);
}
static void snarf_hat_2899(void) 
{
	snarf_construct_hat("/usr/sbin/logrotate",
	        "80d90ca9908bd25f978af0eab96f430c278b1ed8c7d73c3e23d6445ffcce853b966623ce798b950495a2b4eff64a6382132af9d1db1ade8b7a5e937c1c7639dc",
	        2898
	);
}
static void snarf_hat_2900(void) 
{
	snarf_construct_hat("/usr/sbin/logsave",
	        "d378f4f38477eb479e8d6a914b87cbbfc31e98a301ef031434474f5c48cf5aca0d0f4c72637194db599bc7a2eba4492fa5e431836eb6091efb390b87d65d06e3",
	        2899
	);
}
static void snarf_hat_2901(void) 
{
	snarf_construct_hat("/usr/sbin/losetup",
	        "ff4f5364ac4a67de88d3988675eef8c35d7a6199a68a76e84e6e1b7a1d16f94822216f7ce5b088555537186fcbf549022a293f8dbd4401a745b9c913f0c93d3d",
	        2900
	);
}
static void snarf_hat_2902(void) 
{
	snarf_construct_hat("/usr/sbin/lpadmin",
	        "afe7cbc37b5f3e2e6d24fee1d52f843f980d9203ccee2ddee49aef7a08862af9db2d601d8bd9e98fd49dfe7a2b8d7b47e9662ed08933b0b8778fb5a0ecc4b862",
	        2901
	);
}
static void snarf_hat_2903(void) 
{
	snarf_construct_hat("/usr/sbin/lpasswd",
	        "7ccf714e142ad31ebd58808ec4018b6c26f6b41ea22fa3cb6a2f1d709329dda1b7377cbfb9a03e1c72c7576c758151c652f088a621a47553ae9c946559998916",
	        2902
	);
}
static void snarf_hat_2904(void) 
{
	snarf_construct_hat("/usr/sbin/lpc.cups",
	        "226f1800c9d8f2b71dc868062b435cd9ad317fb022ee08e43161bdbc8e026faf5187eca4a66632322c18843cbb4c749155890f98b149cd5e5924c2a9ec5c9267",
	        2903
	);
}
static void snarf_hat_2905(void) 
{
	snarf_construct_hat("/usr/sbin/lpinfo",
	        "6234bbe26bdb735bd30659b738a84fcbb4a7cbb7e13a401557f695c58375e8140a97143b6ab684203cd1fbc10373a9ddf790adfe436c332468bf14e4b8652034",
	        2904
	);
}
static void snarf_hat_2906(void) 
{
	snarf_construct_hat("/usr/sbin/lpmove",
	        "08725da4bb3dad80fcb4d468df946996d1953cb622b3842c564d3bd755e26eaf620b729525787e9378e5fe289c8ebb6df2b3487d627a08f78c5a2c9a4fcd0ab2",
	        2905
	);
}
static void snarf_hat_2907(void) 
{
	snarf_construct_hat("/usr/sbin/lspci",
	        "9ab693655b28da31b07dcaccf3e9150eb565cbf8f70b9808be9efa487e791616c8627c5e9320c666df8f6fcfd5e7c227afe93d44c664e8f732d8b337188c77e4",
	        2906
	);
}
static void snarf_hat_2908(void) 
{
	snarf_construct_hat("/usr/sbin/luseradd",
	        "4aafc233120ec208f90a60591fa24e6010ef0d24ee7c05bde2bf20556f8c420f94305d69e5eda968646f4a78090951529a8bd8948960ab6a85d673bf46db3444",
	        2907
	);
}
static void snarf_hat_2909(void) 
{
	snarf_construct_hat("/usr/sbin/luserdel",
	        "e69d9abf318092068ef76a99b21ee509aec3680779d0115f3c7a64e03af6cd66b87e2e1a7ff2934994617df8399d9c858a5f3408b9735cadbf911f1a0902163d",
	        2908
	);
}
static void snarf_hat_2910(void) 
{
	snarf_construct_hat("/usr/sbin/lusermod",
	        "c6f4d690b322e8c17ff610e0b7a4e317ab6d678b378ac45863dfcec3a8893e190d21b7bab166160d1524afb95c8efd432e63d9dbdf1d08276422476c977d907d",
	        2909
	);
}
static void snarf_hat_2911(void) 
{
	snarf_construct_hat("/usr/sbin/lvm",
	        "6bd11bd69dfcffdbf455f052f3414e6d50b0744e8d4a73407ed87863caff01ba13fb2b8cb05f40c7c2c5937db56873f059f117619e146f835c7d9fc6f1a30d98",
	        2910
	);
}
static void snarf_hat_2912(void) 
{
	snarf_construct_hat("/usr/sbin/lvmdump",
	        "473dfbf3c1498e36926eabc797581c952ba94f1ee01590fbbd04674ac91a0ca74804cacdf51cc8d9dd2e19769448fcbf552c47f5952d45aecae6de31bdc1f979",
	        2911
	);
}
static void snarf_hat_2913(void) 
{
	snarf_construct_hat("/usr/sbin/lvmpolld",
	        "7f85211b7706f15675b8ed8817ab26dc8895b3afc5265516a6273657051863ea790d303b3b48fbdd8232b91ce3367e17ab8e0e5cc7cbf0e3c4074e6e6594af80",
	        2912
	);
}
static void snarf_hat_2914(void) 
{
	snarf_construct_hat("/usr/sbin/make-bcache",
	        "2af9f44af8c415ee1437aae97d32fb3a0b6f012cee258be5b76facb7da5ee749f4b703a59927bbbd7b1e2b2da518fd7e1f67e3fb7b4fd562647a6d7487256b30",
	        2913
	);
}
static void snarf_hat_2915(void) 
{
	snarf_construct_hat("/usr/sbin/makedumpfile",
	        "e3dc65896c5e0b6c506985584728614a231597b1f6b081a743aa63e00b1c29c9057ef3bc2a1ce04a3fc686d2a4cab75d0ded7098906bfe51af4c6612ee2190b9",
	        2914
	);
}
static void snarf_hat_2916(void) 
{
	snarf_construct_hat("/usr/sbin/matchpathcon",
	        "61b66b1152cce1a93e0589515912576b5959524060a1d9a5cae9a8a32854932f36a973b482106280c5e10a10733e48c5910c86889799fe503d50e779c17dfcfa",
	        2915
	);
}
static void snarf_hat_2917(void) 
{
	snarf_construct_hat("/usr/sbin/mcelog",
	        "56a7d5ee1fc7d589c7da76cd3eea0e945677d4213a3ba5a5867d61373df5510d6b5ad52dcd9f66d4073c78f7392d7fa8005a899c0deded7d1306d9a31e845360",
	        2916
	);
}
static void snarf_hat_2918(void) 
{
	snarf_construct_hat("/usr/sbin/mdadm",
	        "20a61e2d110dd0ff7cf3c0800e6c8aa1bace3cb87813ab1210c4999bd9b2489996ea02710c4c00ae51e83e7b2aee4459d5fd7a6a45ee2f8d2b508aad020ed759",
	        2917
	);
}
static void snarf_hat_2919(void) 
{
	snarf_construct_hat("/usr/sbin/mdmon",
	        "08668f3335b6f3624b7b73468ad746183f703fdfef8fd4a1addf3e6247d1e9688a68d095aa4fd6c70c10bef2b471ab826ecd37b44a0a35a2bb6f932dcf3004b4",
	        2918
	);
}
static void snarf_hat_2920(void) 
{
	snarf_construct_hat("/usr/sbin/mii-diag",
	        "ad41c60f8dadd43e236c050c8b6a85774f09ba65eaacd6b78f51dbff496091b7593a4a9576409430b88f69f029c4b7b6f52f5f87ace7fc1a9dd2398ebdc9fb16",
	        2919
	);
}
static void snarf_hat_2921(void) 
{
	snarf_construct_hat("/usr/sbin/mii-tool",
	        "2c333fc518a756da91778d8232b1b5816c8c1c71193e06c37db310df2fe64500ab8c7516666a684fe976fc356664c389509aeae37996002c30c0ff7f5704dd18",
	        2920
	);
}
static void snarf_hat_2922(void) 
{
	snarf_construct_hat("/usr/sbin/mkdumprd",
	        "a6f66e128e7db3326657724c5f790c168b71d1bf0e27b4eb31e54c952bad8458bd1e5b6c9d9987a4e331a3205cf509cb96a84393492ea1e04f49ad706f5c828b",
	        2921
	);
}
static void snarf_hat_2923(void) 
{
	snarf_construct_hat("/usr/sbin/mkfadumprd",
	        "915a211e640f92f6f62455d027bdead53b179d859c60427617d59d19a135f45cee1b07642078f3c30d9611bef2afb3f58e22cce03ea9102c67752fab512ff41f",
	        2922
	);
}
static void snarf_hat_2924(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs",
	        "013445aab36b4b67fc89a45ad28252867253611f8dea37c65efc1df588fb7aec6cbc99052dff02dbb1f16c88d70ae61d9426b90dbf703247bd1b9fdc95daf530",
	        2923
	);
}
static void snarf_hat_2925(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.cramfs",
	        "fea50a32ee4ca9a9865fa5a78169e5a8c35bcef2d2503ff63c6faedf95c0946574e5a183ee82399b2ad13617385a5acec5dc54e5650f436eeb7b7cff025201b3",
	        2924
	);
}
static void snarf_hat_2926(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.exfat",
	        "f1247dc6accf7c16d07e484ca8e3e346a4da091f3745b530169c1120e928839a21ef43f89cf51929ecefd4e5f24c8cdbd34639c1ef406dddeb95f50d1176da9c",
	        2925
	);
}
static void snarf_hat_2927(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.ext4",
	        "86ca1278cfff8b639d7ddeba1c2978600fe06b2801f3970b744079876c5ad16d8b438cd11bf767b15995b445c0b801401c8fbc2805e3269707fd5817738233e5",
	        2926
	);
}
static void snarf_hat_2928(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.ext3",
	        "86ca1278cfff8b639d7ddeba1c2978600fe06b2801f3970b744079876c5ad16d8b438cd11bf767b15995b445c0b801401c8fbc2805e3269707fd5817738233e5",
	        2927
	);
}
static void snarf_hat_2929(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.ext2",
	        "86ca1278cfff8b639d7ddeba1c2978600fe06b2801f3970b744079876c5ad16d8b438cd11bf767b15995b445c0b801401c8fbc2805e3269707fd5817738233e5",
	        2928
	);
}
static void snarf_hat_2930(void) 
{
	snarf_construct_hat("/usr/sbin/mke2fs",
	        "86ca1278cfff8b639d7ddeba1c2978600fe06b2801f3970b744079876c5ad16d8b438cd11bf767b15995b445c0b801401c8fbc2805e3269707fd5817738233e5",
	        2929
	);
}
static void snarf_hat_2931(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.fat",
	        "2d0e4f4ad76eb4c0d026d8856cd6439576ed06f4fa74af18f853bf68b363a75234b36818e170f9481663db0d7df1b541abcfba064a6a3fa7e7e4e7619dd577be",
	        2930
	);
}
static void snarf_hat_2932(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.hfsplus",
	        "22f77160137ac28fddd30dad3bf499699c785f6c7d580da91758ebe3025847422ccddc39beb69bb6f442806d65395f0898fc7b11a3a5cced3d7a0a1f39202166",
	        2931
	);
}
static void snarf_hat_2933(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.minix",
	        "3ec7adc576f7f0b6d61462cbec1105999c35759b6aedba475a9a8184a4b147e3ffa0c8706386cc22fc24cfb7ac7ea86063310d03b39a0343273085e1f40f9cbc",
	        2932
	);
}
static void snarf_hat_2934(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.xfs",
	        "9b8c734eee161550b6c27a240b562b3e9299f513849ac453c20feb6aa4ba30adb59f740563c9861b1a366aa8ac3c6d11deb02f4681b4c03ba71ee11f2d01837d",
	        2933
	);
}
static void snarf_hat_2935(void) 
{
	snarf_construct_hat("/usr/sbin/mklost+found",
	        "cb85c66d33235bf70becde3eda4837a9a8939e8329fa7593d8ee883fd7a19c2027d5d88072b9453d18107ce31c6066895b5855e27b7ae199e827f70966c60cb9",
	        2934
	);
}
static void snarf_hat_2936(void) 
{
	snarf_construct_hat("/usr/sbin/mkswap",
	        "59a5d90c9601ffd2d156f63ac478d96e3e3eaa0b7c1fd0d88220e4f0de8bf95b3a7a2702f5db626c38c118fea6849954ab57a0cca87ec3f1b518593a074af2f8",
	        2935
	);
}
static void snarf_hat_2937(void) 
{
	snarf_construct_hat("/usr/sbin/mount.fuse",
	        "2bba6e14003f18c7748a4f1ea3c97c47333b60f76e7706caf3720dd622151298e5305b0475a376f90276f212a0f9a44cfa1c23e66de5dcc670716719f4afe7e1",
	        2936
	);
}
static void snarf_hat_2938(void) 
{
	snarf_construct_hat("/usr/sbin/mount.zfs",
	        "d3d83977bcc0372b19c52c6fcde95fbca0d61af3c4f9c00f1a9070f989b515ff198a476976f48d954760dc0be8f5ec5d42d071e18bc6907cd55675c5d728d3c2",
	        2937
	);
}
static void snarf_hat_2939(void) 
{
	snarf_construct_hat("/usr/sbin/mtr",
	        "73fa9ef86f343bd46de6a5975c0ecc8f2f3bca42fdfa95015e143c4844b75ac80ae1580c74237de8527578ebdf6993925b1aed7edcc7669f38a67d8197770c0a",
	        2938
	);
}
static void snarf_hat_2940(void) 
{
	snarf_construct_hat("/usr/sbin/mtr-packet",
	        "e46ff6c938944e554f0b9af68afd33471eed50e293725087859dcd17427afea2f4877220c6dc6fa8c3da013adbda8043d26189e931427c4bad0b4fc9731e0aea",
	        2939
	);
}
static void snarf_hat_2941(void) 
{
	snarf_construct_hat("/usr/sbin/nameif",
	        "48dcc2de31c567d10f9a124b6385071ad15e7ee037616551ef8271d880b4758a765145b37a0ec00009efbc1af050b81bf7202bec594628d0cab2f051c01845f2",
	        2940
	);
}
static void snarf_hat_2942(void) 
{
	snarf_construct_hat("/usr/sbin/newusers",
	        "02aac1164e3f579b0aff2836af45f2c78468fd0824301b81ed20f0532cb0891b06574dd685bcd3cb772a38278cce018becc1f9f7f751b0972545f2554397237b",
	        2941
	);
}
static void snarf_hat_2943(void) 
{
	snarf_construct_hat("/usr/sbin/nologin",
	        "86e7877f8065db1e3e85ecad559ccf7dc15c00006fd27f9eb30e0a892f7401be7bbe4113452e3e5bbe912fcd4e15fc4e6c2d564f1625a967497179da1453c6d6",
	        2942
	);
}
static void snarf_hat_2944(void) 
{
	snarf_construct_hat("/usr/sbin/nstat",
	        "61aa20382e2fc31196a296026966b210cedc0c63a023d3a761d5f3f235fbc230cf439655c27a9181829f5f35599e8e0286bd35ed416b016f245a75568af21782",
	        2943
	);
}
static void snarf_hat_2945(void) 
{
	snarf_construct_hat("/usr/sbin/openconnect",
	        "c103996c371d5a57816a2d6093843a47561aa3c0e10677a5692de5fa1a6b1d1a786fd7e1910cb212a0f06ff589318be0c1e9106f8b35aa9bc6a054619053d3bd",
	        2944
	);
}
static void snarf_hat_2946(void) 
{
	snarf_construct_hat("/usr/sbin/ownership",
	        "0579643809dbaa1b6b735ad979b39abe136100cbeebe333d49809440b83f22550266c30cf95ee22f43672a373fd824cdcdbfc6e2b77f3b9196695fdfc23a0a38",
	        2945
	);
}
static void snarf_hat_2947(void) 
{
	snarf_construct_hat("/usr/sbin/paperconfig",
	        "ba53df7c9644aef70d68dc24aedae32bf71a1d73940113c369156b1893a61454e89543872dc19c5611e7851b9edef4a04dfbccba8c097588778a3d4a9225b2dd",
	        2946
	);
}
static void snarf_hat_2948(void) 
{
	snarf_construct_hat("/usr/sbin/parted",
	        "fe46e2e432b81af21b999480f3fcfd245d16498940b9b19f76ad5dc75e6d3f03cb8898b100e167004f9a819c0edddc629a0361f6359dec9ccb7781e5b1b50dac",
	        2947
	);
}
static void snarf_hat_2949(void) 
{
	snarf_construct_hat("/usr/sbin/partprobe",
	        "ffaba959c491319e4456f43768833164c5946e90fe7a3f38cfdec9b480dd4438ffdbccb6adac4d0e59209f30c38ec6cbedf06615881ef8690062ce96150941e4",
	        2948
	);
}
static void snarf_hat_2950(void) 
{
	snarf_construct_hat("/usr/sbin/partx",
	        "711a2baa89d4483ec0f86f9d4a04cafa15a08c77f06e579fc2a26cdec0473769feaa859c178d8676842b6fb0fb7e3eba483a65348302e7278c48c343bedfea19",
	        2949
	);
}
static void snarf_hat_2951(void) 
{
	snarf_construct_hat("/usr/sbin/pdata_tools",
	        "7f7f50f358324c7a780d8a3138a8db22a07d3d45d6b1cd66d39b8f89555d6db5799c238c48a1ec5df0661fa214d7c735382ecc6aca4554ba73337626ca53df05",
	        2950
	);
}
static void snarf_hat_2952(void) 
{
	snarf_construct_hat("/usr/sbin/pivot_root",
	        "72d56dfc0172b91332c716aa52e4577aed69374b2f8ad208b86067d2942f7ef9dfd7e97c1c1f5ef4b3e90dfe31f8dfc8bbe68692d1e0c0e6c568300221aaed5d",
	        2951
	);
}
static void snarf_hat_2953(void) 
{
	snarf_construct_hat("/usr/sbin/plipconfig",
	        "3c4c31b3dd55af4642edde5f40e84213abc4c655aec8966dfbcc750edfe8b0f11eb83b5c84efb154d2416072992bcf1e854b89e29b57c5c2fa6122103fead27f",
	        2952
	);
}
static void snarf_hat_2954(void) 
{
	snarf_construct_hat("/usr/sbin/plymouth-set-default-theme",
	        "b637db5ca66c2b80427d5fdc73ee276fc811bcee3033124163487e606c5d72590e7d53a8f0d88d154a3cb77fdd2bba077e3dc69045e72de9ca53ddf53b5105f0",
	        2953
	);
}
static void snarf_hat_2955(void) 
{
	snarf_construct_hat("/usr/sbin/plymouthd",
	        "cc7d3ea6bff118e4f781e7cc98160323a81d96f06fe0501cb0425e7d7d1e9c2fde18dcc61f6775685be5ec5680ca5988fb81f51c30abe6ffe42bc4e6ed1735eb",
	        2954
	);
}
static void snarf_hat_2956(void) 
{
	snarf_construct_hat("/usr/sbin/ppp-watch",
	        "ef9724746c2b23f3fff55caddde990c26831be50cda5f551ed9b5b622ef26e8a5d6ea86fe54e6791262b5fd427b7bb51aeb9a6ca7d9f0501e64a052b8cfef310",
	        2955
	);
}
static void snarf_hat_2957(void) 
{
	snarf_construct_hat("/usr/sbin/pppd",
	        "906c2e1f6d7f2f79328a296e725195bc8d1fce5f4c9b1ee0c348e7d5173474bfa1a48fea07fe7376c801710c469ffb32919315474dbe351855bf4d120e2f7d38",
	        2956
	);
}
static void snarf_hat_2958(void) 
{
	snarf_construct_hat("/usr/sbin/pppdump",
	        "146e18b09a4f25782e1b9f190c7ae24c463a16ec9aab664636d3bf6d05080b6b4a96c3ade7e846f4e8f3d5c038bba8ebfea7ea8444e04d1c68ec042ff333c03f",
	        2957
	);
}
static void snarf_hat_2959(void) 
{
	snarf_construct_hat("/usr/sbin/pppoe-discovery",
	        "53bc34e80a4f43ce6bda4023a0df1aea2aea62ac9cbb67d82b70550653b2b980c231b0574862870ce7b2df581f6bd911a30f6910af972b9a8218229e87239ba2",
	        2958
	);
}
static void snarf_hat_2960(void) 
{
	snarf_construct_hat("/usr/sbin/pppstats",
	        "97c6d61d036878928159b014e1c085d1b8e667f8ddc733f11f7105d7b92cbd3b2d4d13c2f90a628caa0add60365e5212ee719a120393dd616274149410d1c4f3",
	        2959
	);
}
static void snarf_hat_2961(void) 
{
	snarf_construct_hat("/usr/sbin/pptp",
	        "0c2351502013a1e2c78845e3468d6d121102bb4bcdb80da59f4fd465a80ec4516cda95d625d0a2995fd5713513bc45319992f75c540cd5348e34bbb69afc2b40",
	        2960
	);
}
static void snarf_hat_2962(void) 
{
	snarf_construct_hat("/usr/sbin/pwck",
	        "e8bd808af4bf1b762d5d8cb69d1211ea41d3606e111fbbb775c18781e99342b52a7b59243bc0c7b8364ef81df92556b31ad4bccc224506a113af03d4a29071e8",
	        2961
	);
}
static void snarf_hat_2963(void) 
{
	snarf_construct_hat("/usr/sbin/pwconv",
	        "98c1a92449855c403656cfd555ec9b1c37b8368448f5d5eb054b78f10f7973bbef65a2e903183783827de199f4d7a63f42ad1a756461fb7e838758a8220053a9",
	        2962
	);
}
static void snarf_hat_2964(void) 
{
	snarf_construct_hat("/usr/sbin/pwunconv",
	        "761fc37cc43f19a98654fd4c6a13ec196b7abe9aa6bf97efc094af1364c9cc014ce0daa20b2e5da247c7b88445609676c51a666f1e08f6ba59e54104893043c5",
	        2963
	);
}
static void snarf_hat_2965(void) 
{
	snarf_construct_hat("/usr/sbin/qb-blackbox",
	        "2bca11cbdd9d87b5a725bcc1fee98fc383784bf1a34061ba377c38b35f8a1154f18f802ba4eea7acf1c644398c1a16ad14ed5cec06f3a47218e4f8ff3016307b",
	        2964
	);
}
static void snarf_hat_2966(void) 
{
	snarf_construct_hat("/usr/sbin/quotacheck",
	        "dc7ce95d3d3350175b95ba569af1f45c412d58617a0ac25503b86692c524cdd5e2184b88c3d19114eb8a2e9c3669aea5c0f00ae2f14af2dd047d17195a24c5a7",
	        2965
	);
}
static void snarf_hat_2967(void) 
{
	snarf_construct_hat("/usr/sbin/quotaon",
	        "298ef4ae7425e56bbac2ada50c3f5f78ededa7649e4feac5e2f2fc6d39f32bd656f6976e3e69a63d8fc7332846dbb918fa422f0a32553d4cffcb2945f65ce3e8",
	        2966
	);
}
static void snarf_hat_2968(void) 
{
	snarf_construct_hat("/usr/sbin/quotastats",
	        "7c088630c0e671bb9ef885d99e17b2096482bdf58442dd6e7ef498a12bf846abbd8e0346ff86cea1463914734426c296b79a45249e4ca31371defcf65af5dd56",
	        2967
	);
}
static void snarf_hat_2969(void) 
{
	snarf_construct_hat("/usr/sbin/radvd",
	        "d59cdc9d8108e117438efa4cf7577e2638334d2a850b30b72cd6622915a9dc220efad0795a6e131f680e531d458cac3316ca319eed506d5172af69c8bcfef368",
	        2968
	);
}
static void snarf_hat_2970(void) 
{
	snarf_construct_hat("/usr/sbin/radvdump",
	        "01a6438bb8088e66942f9bec22793218be4a524cf7b5d2d6c1ac33354011949130b5dd5a93bc850f65d5a482b7009fa504ae21fa1c1d4dd73fb2b17801ea7c97",
	        2969
	);
}
static void snarf_hat_2971(void) 
{
	snarf_construct_hat("/usr/sbin/raid-check",
	        "98370130d1fe703275098192888a3d56d8508fc99206b78b1b9b7805f3438d2eed2be46a0512ef223e1366db655edbcf3ed5fd85aaa5c4a290f17245065a8cdc",
	        2970
	);
}
static void snarf_hat_2972(void) 
{
	snarf_construct_hat("/usr/sbin/rdisc",
	        "37a7baad56b4b901a6049fba0bcd13f3c766e778c67b0af04860afc3936987cb3e02e018540f6ada096d6c4956dd7711d439f8120ef07c4124aca87bfaa09362",
	        2971
	);
}
static void snarf_hat_2973(void) 
{
	snarf_construct_hat("/usr/sbin/rdma",
	        "30f2f4a97e53ef37d5c66b77f8e21da2935932674053300e132af7892dbba1faffac71430cddff6ca02bd08b4420af7b114d3fb28d0fb6c1dd3c2ce8a85072bc",
	        2972
	);
}
static void snarf_hat_2974(void) 
{
	snarf_construct_hat("/usr/sbin/readprofile",
	        "203efb627c35819f93c645878eb7024a89ae22ec7268e2518e962edd50c9ea57c29b07d13b1b50ca14b1d56034f04c4a9698936e271047f117d24ee4d7bd8ddc",
	        2973
	);
}
static void snarf_hat_2975(void) 
{
	snarf_construct_hat("/usr/sbin/realm",
	        "313cdfafbb62b49b13dd769d316c784a76e0e3cc144605e3dd8d897815e3fa34da0a7670ebc469df63fba50492731d101aa9fa88553d02a376913d05e615c2bb",
	        2974
	);
}
static void snarf_hat_2976(void) 
{
	snarf_construct_hat("/usr/sbin/repquota",
	        "ce62096538d2f9219924f72d6f3b065960534f4da0d3b55799056824e8a576d3f09e48050e90174b7a84fb162615e65bdfe5d2962234ddc96c6fb82e9a37370d",
	        2975
	);
}
static void snarf_hat_2977(void) 
{
	snarf_construct_hat("/usr/sbin/request-key",
	        "eac0c9aba08c11406a02c3e5e52f6352a6c891a2a97c2ef94db98ff14b6ed5e9d8f4ae20f1c2e2c39dd64a4e2d5fd8c2886d47bb531cc66ce54631c379f341e5",
	        2976
	);
}
static void snarf_hat_2978(void) 
{
	snarf_construct_hat("/usr/sbin/resize2fs",
	        "8bb92401c97f44a2ae7b1a136ad1877bae603791db5de9efe77d60c95a476fb28ec0a7479c5f2b74daaa5e83d199e5c9b137f8f5d44d63804ea066568413ae5d",
	        2977
	);
}
static void snarf_hat_2979(void) 
{
	snarf_construct_hat("/usr/sbin/resizepart",
	        "75729a6123b8c5e7014ce51753aa3f74ed76864ef41156b7afe2b3f0609fccf366e7639a3a41dd4779b4fc1ce5cdb7a8a04cb4f33e0c152f892bed99e1a632aa",
	        2978
	);
}
static void snarf_hat_2980(void) 
{
	snarf_construct_hat("/usr/sbin/restorecon_xattr",
	        "32b1d5b0a0e177e6da0d481fb302176381331985ee7d2bf2362738ad07369dc783631c7b751ff3905bdfd32e9385139bb1be2c0494b5807250e7c185317cf087",
	        2979
	);
}
static void snarf_hat_2981(void) 
{
	snarf_construct_hat("/usr/sbin/rfkill",
	        "ea2b246c4ae45f34d6d39293cafbc127d065ce3560e0542e5dd6c48e198d9b1e063a8f68e826a307c41fcb46715162efa51571adeefab968d8671fa20fb88e19",
	        2980
	);
}
static void snarf_hat_2982(void) 
{
	snarf_construct_hat("/usr/sbin/route",
	        "a30dae82f89de870b4354e0a9aa3e6e6a5997b1df8076c98269aa3898a1251fd0e76a947b0668cfdda9714c233ee622b62958627412b6ebe6582c874d8b6af8b",
	        2981
	);
}
static void snarf_hat_2983(void) 
{
	snarf_construct_hat("/usr/sbin/routef",
	        "09cf503956a59dd2ac1745a943f8f5fe8cc16964a5b93938e2837f3d65adfdd01960f77db33015a93ba65ad5c92ae7aa3b072e0891fe07192a5bdd0b3675deba",
	        2982
	);
}
static void snarf_hat_2984(void) 
{
	snarf_construct_hat("/usr/sbin/routel",
	        "0b972738210b544ab42ad13aa15f130ac352fbaa1e8bd896b913d6c5cb10ba7434071a1622057fc79c107f528ddb8c1ea835398d4021fc9fb514339e1d37564c",
	        2983
	);
}
static void snarf_hat_2985(void) 
{
	snarf_construct_hat("/usr/sbin/rtacct",
	        "57e44489547c2efde68bd3d537645d8f05e03ee9e7ea45f99959947a20dbf8636fd34b0d58014437354ab54d67cecfb8f8775cd28958d7198b1ff7cc192ec865",
	        2984
	);
}
static void snarf_hat_2986(void) 
{
	snarf_construct_hat("/usr/sbin/rtcwake",
	        "342df383d56df508f49e3ab38069b57121946c186adc72819bc19b7dc2364537fa813f2cf980397f32cbbee3e82348ca1c6fc78268cfadc5450596eff34e802f",
	        2985
	);
}
static void snarf_hat_2987(void) 
{
	snarf_construct_hat("/usr/sbin/rtkitctl",
	        "3cc964525c53b4b370e3fa7bc7de8bddc7bfd58d15863298e228974ed88954b6ce1e1c002ebe666605d15528c9ccafe1ed56fc603d48e3cbf9ae1ba50ab19b7c",
	        2986
	);
}
static void snarf_hat_2988(void) 
{
	snarf_construct_hat("/usr/sbin/rtmon",
	        "b13f1c897e6852621f127e7c66f74f85818f79232ef51f5af0f268122273a12c11c4c66d3107109810033a9f1ea23e5a46b7d2337de3f1ba16052b57d3424a00",
	        2987
	);
}
static void snarf_hat_2989(void) 
{
	snarf_construct_hat("/usr/sbin/rtpr",
	        "2d91e59b9f7058884a364721210c97d3856b2365b5e6c8d9abed189d9679d771c00216c404810b5f661a5a8da64a05dfcc2a53fee974cb3f7c02b35f4d7c7b4f",
	        2988
	);
}
static void snarf_hat_2990(void) 
{
	snarf_construct_hat("/usr/sbin/sa",
	        "465ee70c802bdbab8d4c660f7a232dcf2d16ececd762728957a8b1d82197151b7164268b8c565a82d75c859a4fb7d7cf5ced2782036e579a86def7be12499e04",
	        2989
	);
}
static void snarf_hat_2991(void) 
{
	snarf_construct_hat("/usr/sbin/sefcontext_compile",
	        "6c3b1ef5dd65513a210939091cde7749bd16ab23d2accdd6d6dbe73998b1ef7c546df3532427fc51afe68a10a2f4c1e6f9be44c81b6b2e0ae3bca530f5e39d90",
	        2990
	);
}
static void snarf_hat_2992(void) 
{
	snarf_construct_hat("/usr/sbin/selabel_digest",
	        "0a50c2ec21f5e0d03cc1ca60854bb4b92234cae31cac70a04669b963fe2440600c942ee13592a90a386f461dc33d39d84633cbcb27f78671f2202db8154785b4",
	        2991
	);
}
static void snarf_hat_2993(void) 
{
	snarf_construct_hat("/usr/sbin/selabel_get_digests_all_partial_matches",
	        "2999e596562a26d34f7630e199daeecb5b8ae7ff91471f16f3e3e0122221a1671392da5ade74fbfc6cb79b8d925b640f7bd5ff7562d8cffbfb20c699a37270a8",
	        2992
	);
}
static void snarf_hat_2994(void) 
{
	snarf_construct_hat("/usr/sbin/selabel_lookup",
	        "c0930d42c1412145a3123957e03918bea7f65983d1e9c07db5688125dbab3c1eb3e4c40b8de37395797e00c1655a1688168cca6eea7d805537d351477ac9b68b",
	        2993
	);
}
static void snarf_hat_2995(void) 
{
	snarf_construct_hat("/usr/sbin/selabel_lookup_best_match",
	        "10ba29df7b871d5d74c7de66cb20fd7a06f14b0f54efe340efa516b52197906034f31350116015b73c5dd676064b2d4c02f2b90a26c689ab9db9b2479a7bcd54",
	        2994
	);
}
static void snarf_hat_2996(void) 
{
	snarf_construct_hat("/usr/sbin/selabel_partial_match",
	        "3c19c40eb3d396fdb3abb2cb6c6de45330303415c9517a2028cf9a49e1b9c4cf2d3f4f038b02dc8f8dd7475cd619bb09b558003ba9024ce06be91af48bf0edec",
	        2995
	);
}
static void snarf_hat_2997(void) 
{
	snarf_construct_hat("/usr/sbin/selinux_check_access",
	        "8303832704c99e10119e3e872b57ad046ba91af71a9cdab3cfcab351931fda69dbc5bd5f11950aa5f8dabddc867d603a11fd771174b18e6176fb753191d67f32",
	        2996
	);
}
static void snarf_hat_2998(void) 
{
	snarf_construct_hat("/usr/sbin/selinuxconlist",
	        "54b38b933c97d3a6037031fc332f4f055199577fcc9223065bf404baf4e9e41133207f2d95636ff15fe0cd5afa72d36e5a0568d8cfe02cfa0e65a3e265fa36aa",
	        2997
	);
}
static void snarf_hat_2999(void) 
{
	snarf_construct_hat("/usr/sbin/selinuxdefcon",
	        "f1f3b1dd5219a7152ba32e3190846abd0ff5ca395316ca2ba2fc95c34cdd81233bdad9ba2a1f571280dd32c5af36a12a6fbeff63140780ea1fcb3e18f447dba9",
	        2998
	);
}
static void snarf_hat_3000(void) 
{
	snarf_construct_hat("/usr/sbin/selinuxenabled",
	        "781a7a3a45950a498ec74a03cf60fa75be5342365e27375de8f09b7aa39a335c54ecfcd22a2380345fe6f992e51757b6c52afe1c545fdb5b2151f2cf8db9d76d",
	        2999
	);
}
static void snarf_hat_3001(void) 
{
	snarf_construct_hat("/usr/sbin/selinuxexeccon",
	        "e90cd7c8904d9d34d394d4ee0f2bff9e6ceca3ded4b2f6f5cc6315108c588978e81c4152240ba80548d5706a150538302a196d92aa5d2033c98ef3eb78101663",
	        3000
	);
}
static void snarf_hat_3002(void) 
{
	snarf_construct_hat("/usr/sbin/semanage",
	        "24144fe6d13bfc298746eb8dc437a3380960fbf11899f6edcdc040f0d77633d8edcbbd66d8f3950721e631fc1aab3554fc9cf618cc33a9c7c3700acbcacd7286",
	        3001
	);
}
static void snarf_hat_3003(void) 
{
	snarf_construct_hat("/usr/sbin/semodule",
	        "ffff229d095b6ca6ea5c3e824e4a2e0967fe65bbacd6d18bddfdf6e41fc53d4fed1cf7d90542cb229f5a2075c7f2a73039ecae09ab67a0c7ef4188ce2274e75c",
	        3002
	);
}
static void snarf_hat_3004(void) 
{
	snarf_construct_hat("/usr/sbin/setcap",
	        "43c4b8b86f027a1a97bf8c24207040cc75d076971d4dc2a7558a4093b1a3c0b646fe6d3c7b283fde42b17a7a37da3656fb25152094a0eff61fa7367bb42e8ffe",
	        3003
	);
}
static void snarf_hat_3005(void) 
{
	snarf_construct_hat("/usr/sbin/setenforce",
	        "279fe24a0adc56fddee0fa0e796e622cf45eb5e6201dd5594df049b3f97acf1f13d7be2919440333610364f1c35284e2d962cab09e3aec120882d895be694765",
	        3004
	);
}
static void snarf_hat_3006(void) 
{
	snarf_construct_hat("/usr/sbin/setfiles",
	        "1cca3a8f39f4b248a22f04d30c427519490559ba269230799f85c9bc81c5a651de527efbf288bbf89b3c441f239c82ae5959faee8f589af53e6ab217b680fe4e",
	        3005
	);
}
static void snarf_hat_3007(void) 
{
	snarf_construct_hat("/usr/sbin/setpci",
	        "803152b59064a8cb82fdd4a24950ef6ec5b13e7ee4d39a68531a73c17657d3b4d70c82c88e45c32c38c810f29776c724933513394c1c407a6ae351e9555db138",
	        3006
	);
}
static void snarf_hat_3008(void) 
{
	snarf_construct_hat("/usr/sbin/setquota",
	        "f3467476de7ade935794f880eb9b67e2b7e335977dfc59c00176af95db99a206874da1e9fbddcd7be3d72ed94be92c1f82b06a156852ef925070c8b6b2c42134",
	        3007
	);
}
static void snarf_hat_3009(void) 
{
	snarf_construct_hat("/usr/sbin/setregdomain",
	        "877c9e1eb17d56ed0c631525751b5942d4dbd7c5d66f2626cc6d13a9b7000c79b25219761b791054366ac7f9e63b7249f0e3783b54f9177547dbe63b3f42a966",
	        3008
	);
}
static void snarf_hat_3010(void) 
{
	snarf_construct_hat("/usr/sbin/setsebool",
	        "0a5e160abe9ae98ef6769dab82587b0c65ae0b10a5cd6f63cb80df8b99fd6d32614b6425c8806d95710dca979717260bfcb7594602202dbd1d5e941fc4b9f236",
	        3009
	);
}
static void snarf_hat_3011(void) 
{
	snarf_construct_hat("/usr/sbin/sfdisk",
	        "752c0a00254c16b58a410113289a9f7a8b77062dc8ef8f6eceb48f71deb24b3479b12f483686c5f1ca6494d9180c4e1ca466d7245cb84df9ebd50235b1137fff",
	        3010
	);
}
static void snarf_hat_3012(void) 
{
	snarf_construct_hat("/usr/sbin/sgdisk",
	        "3db5c9e22e8638dc83d07867db232b790a980da1cd7473f28de32c519c4432c554aa0ca1ca2dd86b8236412433a34c74d6588c97736960de7d05ac568cca2fa0",
	        3011
	);
}
static void snarf_hat_3013(void) 
{
	snarf_construct_hat("/usr/sbin/sgpio",
	        "cfa7a33c8b932039c64579df7a24b8d53a4b058350fd633e8e1216b35c648e37e463a9c999c2372157f43cce5c4db9b8a2587731888402c42f0c9187ad3ab53f",
	        3012
	);
}
static void snarf_hat_3014(void) 
{
	snarf_construct_hat("/usr/sbin/sheep",
	        "0a0e688ab6ff339def08fad0339dc820d2e6091635d10607e3a59e8e3bc00fae5f3b188e4c0e643741daf6665352da70027d0e72be1552f08bdd672677c4fdd3",
	        3013
	);
}
static void snarf_hat_3015(void) 
{
	snarf_construct_hat("/usr/sbin/sheepfs",
	        "822358596874c4467f4ebc098ecd97873df0290aa43b799606b86ac4a4517f6c0d2eece5fefc79f281e7d690d81fdb5b36a3a0de54f7ec110be9d6c1bf2680d8",
	        3014
	);
}
static void snarf_hat_3016(void) 
{
	snarf_construct_hat("/usr/sbin/shepherd",
	        "0ed5e75205a46de7c96bf5e4d32f1914ee98db8705d0bec8b105e32e6afab6ddec7c7443c49bdaa224d617889fba7ff904a22ea6b4e951b9d0bc9b5f032f1d60",
	        3015
	);
}
static void snarf_hat_3017(void) 
{
	snarf_construct_hat("/usr/sbin/skdump",
	        "9a4cfd8ade6fb71c2cfb6c94ff94adda8a910ec63abbf990416b593f90f094e0cc35b03cfe73f1d3955d65dbddd30a66b13caf6287f3104a6b6dae4cf65583ae",
	        3016
	);
}
static void snarf_hat_3018(void) 
{
	snarf_construct_hat("/usr/sbin/sktest",
	        "f4a5f0ad43a5cf196c43533054ba32529f9ffe39b48afde05f44262b7684594eca7b7cdc6d1e3954572734c15e3764727c2a57eb3687506366943f0ab53ae1da",
	        3017
	);
}
static void snarf_hat_3019(void) 
{
	snarf_construct_hat("/usr/sbin/slattach",
	        "a98f14c5d909dfb78e8a90dffd313eb8beac4bbbd40f0b76e3dfecf81dcf997033b5eec37539a9df2eba768fb8e7f29bcc8264b32f547c5b1b1a720050a9f871",
	        3018
	);
}
static void snarf_hat_3020(void) 
{
	snarf_construct_hat("/usr/sbin/spice-vdagentd",
	        "b8bcac5640153a88861cbd5a3c7f66ef0a30235de5b073fbc8ab7c340e470bbd4c81f4166ef59cc3f4a8f93ffe2ce2b70d0a875f789f7e51354244db000dbaf1",
	        3019
	);
}
static void snarf_hat_3021(void) 
{
	snarf_construct_hat("/usr/sbin/ss",
	        "f894fbde6e7fba211763b03d7d7e13d9a57ceba55de2fcac9c3557e18d0e212b454630ff2e649209c268d7d898ca6ec2cea7e1804ee9a206b19a1f27d325ed28",
	        3020
	);
}
static void snarf_hat_3022(void) 
{
	snarf_construct_hat("/usr/sbin/sulogin",
	        "727123f197e62f4397c928cf3f7feea2cad47515a6a73e1af965a7166a4529c02e8588f985db59b4cbfcebec1b87897840e287da4b520f60c870cd678da8a62d",
	        3021
	);
}
static void snarf_hat_3023(void) 
{
	snarf_construct_hat("/usr/sbin/swaplabel",
	        "b55b1e829a7239cbd75f8484f25940a0aefd7edd4c04daea59afc137f6674a829b2abfa5006f891f2ee1b210be6d5fa1e06bcb5f574c33b382149cb707893e28",
	        3022
	);
}
static void snarf_hat_3024(void) 
{
	snarf_construct_hat("/usr/sbin/swapoff",
	        "0bfb28fbeacce74902a92234b6ce38e911923986a76468d0a7ebaaa66b6f144e43b143819c46b467b97383768c8e15ea1e09a305ae9d347c0f14936327de9815",
	        3023
	);
}
static void snarf_hat_3025(void) 
{
	snarf_construct_hat("/usr/sbin/swapon",
	        "1955ab691500089a929ad37a2fc7b7321ac888df27c0c872201a023af6399739be6cabcee053f789f1d7951e80581bb4ecbd3c676c8ceed21f4f492443432dbc",
	        3024
	);
}
static void snarf_hat_3026(void) 
{
	snarf_construct_hat("/usr/sbin/switch_root",
	        "42074a2a59ba7b5fd29d4b5b7d2bc86e41b8aac8cc1cb5ba94be2ce38fd3de7b6530dd31c2b084391589d18ea8bc14f5506d4a104a396c81c96c37acb7a3d0cf",
	        3025
	);
}
static void snarf_hat_3027(void) 
{
	snarf_construct_hat("/usr/sbin/sysctl",
	        "7da799d131bf8a20d298169e7b1a0c21889c5d11efcfab93609d96c6a6220712805eed98869ff3079afcef28721c5b8a18b591012379c5f7b254a29063da7578",
	        3026
	);
}
static void snarf_hat_3028(void) 
{
	snarf_construct_hat("/usr/sbin/tc",
	        "7208a039e23a40a0101adee5dce0d288f55855bf9501acfcfc245321788815a88209b33eeb0a95e18a2ddc961907fda055fc721771adc9d2adb68e408c16f9ec",
	        3027
	);
}
static void snarf_hat_3029(void) 
{
	snarf_construct_hat("/usr/sbin/tcpdump",
	        "ab36955bb6f4549d5402e5e48f170e05aad689ae3ce224a83a61f23e6ed5cbf70540c3e8555e617aeffeaa77f776dd6fe410381316b4303d61429501471b8295",
	        3028
	);
}
static void snarf_hat_3030(void) 
{
	snarf_construct_hat("/usr/sbin/tcpslice",
	        "304ffe12681a4a76bca817099d52c9719ae6d1f557efaf88346a53252de09c587bfa003dffbea015fc936e5666f236224ca779dd0a7b676b39738bda55bfd0ba",
	        3029
	);
}
static void snarf_hat_3031(void) 
{
	snarf_construct_hat("/usr/sbin/tcsd",
	        "55dc4d323dbcda57c94118f09bed8ae4d5e31452fdf5cd9f9cf05b215b00ac42cfca46f79f6d0745d87330def9790a2e5b20399ecdda3fbc0d6d446dec38fbe8",
	        3030
	);
}
static void snarf_hat_3032(void) 
{
	snarf_construct_hat("/usr/sbin/thermald",
	        "f68240f350d49788f21da3b532f6e0fdf64fa3ec18aefbd556e1b8defb1b17f5b9c329d1a79c18c95bcc02146dfba40dd3edca0064a849aea0b15c5a6e8f37dc",
	        3031
	);
}
static void snarf_hat_3033(void) 
{
	snarf_construct_hat("/usr/sbin/thin_metadata_pack",
	        "d4b043038da591dda53702e47c36249f3a3d778195373f9b838132d13e1f783040547f1aa3587e3b060debd030354111c8b831c1d65e64e4d690a25a717f65d0",
	        3032
	);
}
static void snarf_hat_3034(void) 
{
	snarf_construct_hat("/usr/sbin/thin_metadata_unpack",
	        "934edd10b283bcfaecbd957160247e908926a8f0ed3cd3557fa43d195bf10ad646301dd9da586fc82b96353c18067115fc9af236616a7067329c9c3d2aa740ec",
	        3033
	);
}
static void snarf_hat_3035(void) 
{
	snarf_construct_hat("/usr/sbin/tipc",
	        "21b30337ce2db8cf5d6fa85a14805bd0efc369c83ee476d26d208a4d03091f98fa3fe4eaf190aea221b10f9d8c380b7d9a885abdb934bd09253851499449be18",
	        3034
	);
}
static void snarf_hat_3036(void) 
{
	snarf_construct_hat("/usr/sbin/tune.exfat",
	        "c8a7210ed276da474bcc84b65e1624d665f9a4ce58b5cbf7f0ab39d47fef19247fc4074e10c884d776cb12f8a2b43987f87217836b646825cd34842b1769a26e",
	        3035
	);
}
static void snarf_hat_3037(void) 
{
	snarf_construct_hat("/usr/sbin/tune2fs",
	        "1ea27db63667146ef6be0de58b4734168109b27feed078793b5cf65c1396c4b502f9a8c80b664a54a7a29aea21223e75689f2f51dcbd15e6244e967bf91ec938",
	        3036
	);
}
static void snarf_hat_3038(void) 
{
	snarf_construct_hat("/usr/sbin/e2label",
	        "1ea27db63667146ef6be0de58b4734168109b27feed078793b5cf65c1396c4b502f9a8c80b664a54a7a29aea21223e75689f2f51dcbd15e6244e967bf91ec938",
	        3037
	);
}
static void snarf_hat_3039(void) 
{
	snarf_construct_hat("/usr/sbin/unbound-anchor",
	        "e25d110ef1642f9ef2cac2ae7cf5754859f65babe3e1c589835ad7d88d53ec2dd3d15c3dd9f2ae668f8aaf551fd390ff1669cba29eb2adb1506d50e462dadba3",
	        3038
	);
}
static void snarf_hat_3040(void) 
{
	snarf_construct_hat("/usr/sbin/update-pciids",
	        "6d476f39a3832f3353793aabe972e270d8da709bf1b3dc0a96e383f3381aeda637b0ffd46c6d5de0bf0987a92752f1fe7b2a4e8580d47c7d63a72f8fe84eab96",
	        3039
	);
}
static void snarf_hat_3041(void) 
{
	snarf_construct_hat("/usr/sbin/usb_modeswitch",
	        "e867d51e01996164636ded4706d2129efebc457365f331b504adc0c5f167a8c83fc81b650a881a8b804dd60db73ba7446ec4c6f1ebcfb769467289145caa5ae0",
	        3040
	);
}
static void snarf_hat_3042(void) 
{
	snarf_construct_hat("/usr/sbin/usb_modeswitch_dispatcher",
	        "8b3c791057b34bec00c3494715b2f5fe38d784f11365c6abe8d3befb594a3871659c34b127e0d54bf48e540138aeedcfeb70a2050e6442c0bf24fdbdfededab4",
	        3041
	);
}
static void snarf_hat_3043(void) 
{
	snarf_construct_hat("/usr/sbin/usbmuxd",
	        "af1e69a9f06f7bbb57496f579eadb3891051dccd7f4a3bb44b6e64d36ec0432df1836d8f5572d56683ec3dd85169c2bdefa02fac7628e15d77735f5898f7c79d",
	        3042
	);
}
static void snarf_hat_3044(void) 
{
	snarf_construct_hat("/usr/sbin/useradd",
	        "cb0c196e12e09b57882e99ebd694a9d0f5aec1889faf5f1c4fba92d098995b8c7f955b761135987909bb28768d5aee6a1078b8ffb4c61acbbeeee20708f6127e",
	        3043
	);
}
static void snarf_hat_3045(void) 
{
	snarf_construct_hat("/usr/sbin/userdel",
	        "526988d972a6dcc2396481ac7fe9385ec12b2056ae48f37e80dd5a9c4de63e9de3e8caf321d47080468c06b93ac7318e50411402c00ba90956ccf28347e6c1a6",
	        3044
	);
}
static void snarf_hat_3046(void) 
{
	snarf_construct_hat("/usr/sbin/userhelper",
	        "a27f2e0d2969abfc5b280f711a0adc2e17dca83620c7e58868f351db53aca7540e092ada4d4debae2c7cc59632ad2732faf0c7e5db3f82fd972ad622eeeee649",
	        3045
	);
}
static void snarf_hat_3047(void) 
{
	snarf_construct_hat("/usr/sbin/usermod",
	        "4f83716b845bddc2424824dcf4b3d974e648633fdddb78319879dbe3bd72f69397fe769dc7ffbc5ae3fc59e41c8ad0898862ccaab83a3182607c5a07f52d40d5",
	        3046
	);
}
static void snarf_hat_3048(void) 
{
	snarf_construct_hat("/usr/sbin/validatetrans",
	        "961c398a1a6cc0673462a44cde92d342f2e8bf379264609645ff32316d5ae29b36153d9c154dbcb397cf8f710340878d07e214c74a937045396f91327e103f7f",
	        3047
	);
}
static void snarf_hat_3049(void) 
{
	snarf_construct_hat("/usr/sbin/vdpa",
	        "9b6111038f1d89769f68b2ea0ed22f6d3c9eb77a40471fd00200706d0087c330ee2b6defd525dcf8ada2b108d78fb5aed0d8461f2d1058783a06b2befa9a40e4",
	        3048
	);
}
static void snarf_hat_3050(void) 
{
	snarf_construct_hat("/usr/sbin/via_regs_dump",
	        "f66d3b5c97aeb5ab86c675fdda030e8cd6520e1c64321de01771cc4c9c61457247a8340e9c9433dbca21d82ad2cf9f345ceb03ed7178c91f7c31925238fcf06e",
	        3049
	);
}
static void snarf_hat_3051(void) 
{
	snarf_construct_hat("/usr/sbin/vipw",
	        "a15c1f1281a25bd231481f88e386287e28f28aaa5a2d8511bd678f18fc684483b802bfc3447bd090dd8e51a21cdaf871f2677f76cea00421fa9433e0d0db38da",
	        3050
	);
}
static void snarf_hat_3052(void) 
{
	snarf_construct_hat("/usr/sbin/visudo",
	        "d1b5f8be6f3fab75797112d486f42b3d273fea7b718ac81263d3d708fa421c2e5251596d5627d122b7e66bafce57ddeb3c84b3fb346d9d60a7d2a777ed45e47e",
	        3051
	);
}
static void snarf_hat_3053(void) 
{
	snarf_construct_hat("/usr/sbin/vmcore-dmesg",
	        "72ee03e66efbc56fef66d0d7f0b00564c94dd6f0774919915f68a54c41df2dbff59c1134d1d76172c5cf7bf503b41df3ba525c447325ec05fd889f8741d98714",
	        3052
	);
}
static void snarf_hat_3054(void) 
{
	snarf_construct_hat("/usr/sbin/vpddecode",
	        "c4fd2eba3b33793014b6968d86f020b06c33269851e1c6b42f4b68929d6e259eee383674c3e68a0d10c0abf094f4ff44ee30038e19cf5437bb25e9d291d93b10",
	        3053
	);
}
static void snarf_hat_3055(void) 
{
	snarf_construct_hat("/usr/sbin/vpnc",
	        "7083ef103837f59063548bc9be0857029cc5cdfdbffa15e9cc5a197c14dc8c5faaf7dba0c65d41c53a082ba0fee51e21f87cb05a13c28736fdf7dc82a4a943f7",
	        3054
	);
}
static void snarf_hat_3056(void) 
{
	snarf_construct_hat("/usr/sbin/vpnc-disconnect",
	        "016d1d2e49549f1ecc9e4f781c8a0aaa76c948f08c68bb30459fbb1594db4e1cb9091fe05f35c79b7d674c66d8a047d738f4d67c3e7d39da7af1068c56616641",
	        3055
	);
}
static void snarf_hat_3057(void) 
{
	snarf_construct_hat("/usr/sbin/wipefs",
	        "6dff23828c09aa112c88bf731698b02b8c81f50a646caa0ca80bb425b25a7c0345218ea66c5b8477c2a3f43dac00d3fa30c0baff243d2dcc65a9de25c3bd284f",
	        3056
	);
}
static void snarf_hat_3058(void) 
{
	snarf_construct_hat("/usr/sbin/wpa_cli",
	        "29963bdc1fa42fe9248ab3746927018677f4acd0e046a1ae8c44c5910d39d7a05dc166acc7c8d8f8a798670f7c4a76ed3c726d88eb265d98602353a89b5f9504",
	        3057
	);
}
static void snarf_hat_3059(void) 
{
	snarf_construct_hat("/usr/sbin/wpa_passphrase",
	        "bd794c64d3fa1fd26eb179626d3dee9ca8f5ee6a5827d825d1dc6cc11531e40d88db9cebd37cb11d1ec606d33b6a8d817ca2b7bb165d687ea3b4775457e0e5f4",
	        3058
	);
}
static void snarf_hat_3060(void) 
{
	snarf_construct_hat("/usr/sbin/wpa_supplicant",
	        "55b2d2f205714d9a83167ad429db185483c37170cb10a52fa71e47327c843d8cb9a76ec7a14cff16a303ee386b521d6c78d7db94a7f831164feb74ef59ab9fd0",
	        3059
	);
}
static void snarf_hat_3061(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_admin",
	        "c2cef139edd5dcc6349fc87745b04f37f1a063d96eb156dd55f057d0dbc583c7db2e8d873c0a7d4d1d9e2d5c264a700c1b19e01afb2baa4cd948e160f3372231",
	        3060
	);
}
static void snarf_hat_3062(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_bmap",
	        "0481078520568fee010b647076f12318c383c151c5035122604a17d8437b101577a383c97ab9541b861354c5a173309df1a0835a253c7290c97ca926da3d3475",
	        3061
	);
}
static void snarf_hat_3063(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_copy",
	        "6e149f8c029f84357cbb4b098b8858fb6d3f85b4b2dd33c6108582edb337ea04ef5099660985bb8eb0b0eed4cf09ece9a87dffbdf073a7d4c9848f09047c7ca8",
	        3062
	);
}
static void snarf_hat_3064(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_db",
	        "0aba09c0c853fe1a2b739b0b641ada26effdf708f130501969eb7976514cd270d90207b2ac5aafca3c68720112e949dafb27619e62666704a6f6e6f6bca655aa",
	        3063
	);
}
static void snarf_hat_3065(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_estimate",
	        "ab95a3de90b92bbe5b9881b3743afe74ac274b730857a119c94ef571ed353c0f466f82ac949af97aefbf70ac32a76476275c76dd7427bdfbcc20bfc76c61c7b7",
	        3064
	);
}
static void snarf_hat_3066(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_freeze",
	        "8ef3385e6a689b6721292f6aa96e065b2246396e2d22e8e4597201d0a748b7e031903bb6f010683c87e5b51eed8cd22eba9d9bdcf3da01bad56c77a58a2972b3",
	        3065
	);
}
static void snarf_hat_3067(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_fsr",
	        "93c1cbe8cb0b0aa2113bf4f67888174759d663f49b2e55b21e3ca8c4886bb80b478eb2ad44360063e52a85b8404e7b59eac7bee1cec8cced8046dc28a5dc251b",
	        3066
	);
}
static void snarf_hat_3068(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_growfs",
	        "d0cb83ba5051265498feddd88b38afe3b958e4b3660bcd34e8a70ad12dbddef9adfebcffd40e8c77adcbf3e330d458bd0f0aca2fc4aceeaf85a951c7a64202f9",
	        3067
	);
}
static void snarf_hat_3069(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_info",
	        "2845a2470acaee7afecb62d8ba7712ce96bbac341a04d77ecb8b8e1419c21192e49a196c897004ef149a5b7375d530605cfca3d8b7020f1104fb2f37b6372812",
	        3068
	);
}
static void snarf_hat_3070(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_io",
	        "d97add556a4a8ded925df5f524d9fa8dfab27693a222638b55efdf2a72f73f1fd32f5eda771fcbbcf305075e3754924f44ff99cdebc7482bad752a07842f23d2",
	        3069
	);
}
static void snarf_hat_3071(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_logprint",
	        "f617ebb577e18de2adcbfef62576fc426897a0be4c53a924f0be10cba27334bd905def18de368850034e5895f203a087bcd5b976a2cb9cb8de0df481a73a2568",
	        3070
	);
}
static void snarf_hat_3072(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_mdrestore",
	        "52234f0934afad61bc509f2794871e1a4a924a7bbb8c96e85bce4a2db4a866afc07590e83ccd7741485655824bcd69bde6041ff6e40643941205b4e77cd49148",
	        3071
	);
}
static void snarf_hat_3073(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_metadump",
	        "07ab1c1bd990535c0a64ecbbb7d7b09a9d8d2e9fc77c8bafaaaa7f861ba5cfda90e88ca9c1dba03a481ee841d7ff4684c77759d39e0d1d1ef9ee6610535e2a60",
	        3072
	);
}
static void snarf_hat_3074(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_mkfile",
	        "e4d758772388d7be41c6ddf794d9e7d075cc8205f354838bde778e3cbdf7c81d1039248e3165c6787c2a8b280d74bf81f7428cb1765808e272ac09382aed5424",
	        3073
	);
}
static void snarf_hat_3075(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_ncheck",
	        "d60ef5bfcff14d37f02857a657bca20f612a7a6c4147ca9943f69cbf6c97fb7bb432fe336ffe9708ff614067af754685fc3ad9d9bc2f439c79ccad08a5ec4f6d",
	        3074
	);
}
static void snarf_hat_3076(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_quota",
	        "8c7555b5b84e81bba90a7ecd072f66bde70f693dc58e8438e95f287c5206314bbfdb3d6a40c2dab3f5d879b2b1b70941259e68950e9ca50e5500c379ce653084",
	        3075
	);
}
static void snarf_hat_3077(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_repair",
	        "c0627a4c6090e34e5d44e28feca275d6885f70eaf2298b2360dacb33b1a18df558b3b44af3c9778d906b5d3f54b143a6e890370582d785e5fc86485ca8226d87",
	        3076
	);
}
static void snarf_hat_3078(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_rtcp",
	        "1832b7cf034d5886ecab1f41931c9e14239ad6824e1ce95bf142888db497cefc8aea44e8cd74451cc71b35c70fc134b71ca73ff1ca51e64179248ba7761a85c2",
	        3077
	);
}
static void snarf_hat_3079(void) 
{
	snarf_construct_hat("/usr/sbin/xfs_spaceman",
	        "c0631611bc8d643fce37e602e2b8fe97388c2d2e946e4de4ab42828771d4a24f14089031f62ccff267f8114be646eff0e1ec435836d6e7cbaaebfbb79547acea",
	        3078
	);
}
static void snarf_hat_3080(void) 
{
	snarf_construct_hat("/usr/sbin/xqmstats",
	        "cf08c7781d537290de31dc45623eec2e247c5501372cd041092f8638a3b6b00d832baec81046b100d3aad1e6d37e1d3973e59fd352cc029aeb921a1ce9c4f7b8",
	        3079
	);
}
static void snarf_hat_3081(void) 
{
	snarf_construct_hat("/usr/sbin/xtables-nft-multi",
	        "5243c4c2875926b3fe801a32e897b3ba08145bd7170ffd024921e3ffbac3cd73b7ac57c714ede68ff382692102c956b5a27a6e2df343c6a662b29e284e83bc54",
	        3080
	);
}
static void snarf_hat_3082(void) 
{
	snarf_construct_hat("/usr/sbin/zdb",
	        "12cf423ea078930de4dcc4938d96f978c55cd02d2e848a7d6b2a8b557a3ea90e9188dc345a4cb8300d7d83ba10da0fbd5adf65708d94245b9eece17053267e62",
	        3081
	);
}
static void snarf_hat_3083(void) 
{
	snarf_construct_hat("/usr/sbin/zfs",
	        "9f2c4b1a0237f769e1f4fed06373959f89ca66365d4dfac73e62620dde1769e1f070ae49bf5ac1072c41d2041830c04ed88d40997ea51f0c31833fde9e84faa7",
	        3082
	);
}
static void snarf_hat_3084(void) 
{
	snarf_construct_hat("/usr/sbin/zfs-fuse",
	        "f62449540987ccdbb34c67c5839e91ce1435b3acae5617e2c658a1e3082c490a67857b4bd667be43459b811e0dc42a04f9388684502ae743284dbe25c4f7080a",
	        3083
	);
}
static void snarf_hat_3085(void) 
{
	snarf_construct_hat("/usr/sbin/zfs-fuse-helper",
	        "aac6240b2f3892079ce595fbd83825db69d8a83300b4fd5238c5005910baa3a3a7300bc80a10f04b16eb021239cec5422ce5c6b14743afb97107b8c46d8eb2b8",
	        3084
	);
}
static void snarf_hat_3086(void) 
{
	snarf_construct_hat("/usr/sbin/zpool",
	        "369bbe48b83a589480310c26d33a8dc3a7ccbadb27dd2a1053de6d20b073a0d8cab40a475e22dd8cf67c35bbf13ee0c03780cd7abdaa9ab64699f0692a6c5ef8",
	        3085
	);
}
static void snarf_hat_3087(void) 
{
	snarf_construct_hat("/usr/sbin/zramctl",
	        "a49e37bdf5184f8c69bad374414d9033216425c474f3a066cb8428d49ec0b0c969813ad564c216b7fa1969648b47dd7fd07d8015accafbb7d265ee404a924435",
	        3086
	);
}
static void snarf_hat_3088(void) 
{
	snarf_construct_hat("/usr/sbin/zstreamdump",
	        "888ba03d7516ff361e85234ac32096ed0477a4def0449a2038c54f97bdfee488b7394ca6e2b951b9b61d70d1049a1113712db472bee4b5a5bddb0e249fff93a9",
	        3087
	);
}
static void snarf_hat_3089(void) 
{
	snarf_construct_hat("/usr/sbin/ztest",
	        "2671d60ea9b2fed3e767af1bd290c0c7bdad6efe7c7f9fe346756d9139aa13bef5ac8276579d5a32b312b904d4e7782495696513ef0ffe4a605a71230fdc51e7",
	        3088
	);
}
static void snarf_hat_3090(void) 
{
	snarf_construct_hat("/usr/sbin/fix-info-dir",
	        "99d199892e3e136c0453cf6078b50fd7b2e1077fc48627ec5f3bd326b1f416353d441d3a4935fddfb3e26aabbf3f0112b200a3e860a2125f7f34522d5a5ccd00",
	        3089
	);
}
static void snarf_hat_3091(void) 
{
	snarf_construct_hat("/usr/sbin/install-info",
	        "35a4b7550e84d80b02362f40e02a0fa27eb49cb831e4a7c6fc4d0af98feedb934fe2bd0a39a8120ed6a02f03695374b4b4bdd677719878701d0eacc628789595",
	        3090
	);
}
static void snarf_hat_3092(void) 
{
	snarf_construct_hat("/usr/sbin/zic",
	        "d18991fc4f2e00a6683589129d9bb965bfe268797075cb8e6c9e7fe87240c489ca1528c947b399e6a240c1e75cd168188a201dc48ee6921015c7eefaa97139be",
	        3091
	);
}
static void snarf_hat_3093(void) 
{
	snarf_construct_hat("/usr/sbin/ldconfig",
	        "ca74b9cb615a9c8d3377cc6c0b43ea6ea38cd53d7b4cb034712607c3809b2695ea5e69b0d5cfe13c8ec8f4a8397f0844421bdac726ccb31a18acafd87c49c4a6",
	        3092
	);
}
static void snarf_hat_3094(void) 
{
	snarf_construct_hat("/usr/sbin/iconvconfig",
	        "4a70718bb71db44d56bff2d4028c314dc0165aaffc3878d97c11b0d181e0b4181ca007501d30e2355b3402586be104ccacfe4e87af2bc36d5ab9f077e2e97d4a",
	        3093
	);
}
static void snarf_hat_3095(void) 
{
	snarf_construct_hat("/usr/sbin/sasldblistusers2",
	        "4c893e1042a1119985b6a12564f6a982fa486763386d10d864bc8bcefdd8c4cbd81abd4017cff3abfd6037069805cab325461915fcb8e2202492823fe5945e65",
	        3094
	);
}
static void snarf_hat_3096(void) 
{
	snarf_construct_hat("/usr/sbin/saslpasswd2",
	        "498b9bab330b374853d3c207f52313c8f6bee3035a9bc1cd8a6e40f62a6f9e8b89623e9747a881acd7ea895fbe8aae107efa5d990a9f62c4850ca59c71d71ca7",
	        3095
	);
}
static void snarf_hat_3097(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-get-kernel-settings",
	        "cd0121b0fcd7b78041ddf7b5d9e2d379069558f802cfd81fa86810f50abc7086d3aa17ad2c5875fe47dc81f6664efbabf0dff5fdadad0623fe64c3451cc2c53f",
	        3096
	);
}
static void snarf_hat_3098(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-probe",
	        "75f4e6116410d2505d0342506762ad8d839d5c40a1ac58830ee68db9aaf566d88dba47aa74baca631f189d34165d297c922cf618d93011e8db8f7a7ae07239da",
	        3097
	);
}
static void snarf_hat_3099(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-set-bootflag",
	        "4a9e3ad1d9814ea93dd94864468957905452846cfd36a6fe513ce8eaf4f542bd0020d4318e1f18ea2503532373f44ef7e6bb07bcf1fed19ed6c65daca06ef55e",
	        3098
	);
}
static void snarf_hat_3100(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-set-default",
	        "aa58a6e6c7391ff0ce771e3a3e2d452e882219c7be6b4bd695ee5f98d4cd9cb7fa4767ea8e18b7197de5ffcf372f68c8348c34b3fe0665cb6650ea1d4d62662b",
	        3099
	);
}
static void snarf_hat_3101(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-set-password",
	        "8b57c9c635cdbaec05512be41662c00a49c0a26520efcfe05c347590fdc426a2104dfd24487c92dabcdc70318a3e4e5e90561525ba7c6df7d30a7a784fd9d52a",
	        3100
	);
}
static void snarf_hat_3102(void) 
{
	snarf_construct_hat("/usr/sbin/faillock",
	        "79d8b4d868a6b8373545ad73a48c106293749a0f8cf2db4f8c337f251082a0b26a343039b2e2b440fbc15045298ea54bad39582e9d764154592656d53566e959",
	        3101
	);
}
static void snarf_hat_3103(void) 
{
	snarf_construct_hat("/usr/sbin/mkhomedir_helper",
	        "86c4e5bfb406d09cc4e633c0910bc260f543fcfe8fb0879d6244e58c99ad09824228d4a6c546aeb027008ef3a23987350f9bd5d9fc6d3f3c5246ba0a98ca0613",
	        3102
	);
}
static void snarf_hat_3104(void) 
{
	snarf_construct_hat("/usr/sbin/pam_console_apply",
	        "c3f10d0a52cd6f72bec19baee367e6116a1e07e1fdd277c1b6b9904fe10cd826ce95d472e59bf5404be3c4799af088385d74bddec08835e62725222e999df83b",
	        3103
	);
}
static void snarf_hat_3105(void) 
{
	snarf_construct_hat("/usr/sbin/pam_namespace_helper",
	        "6dc4a281a71e08d56371b796e8af7502677779922609dc4cf4cd1a379fc9204da02435311bcc44d020ccb6b46875a42054f5ee5ba8b5b45891fec55abb9211c7",
	        3104
	);
}
static void snarf_hat_3106(void) 
{
	snarf_construct_hat("/usr/sbin/pam_timestamp_check",
	        "2210f932be3b968d0451c50062976e53f4ed4a292aca62d98a3d32dbdafd041e97ae82aeadfd79429e7c65b7e608a89e6bbdb02180331fe4802c720746e82c7c",
	        3105
	);
}
static void snarf_hat_3107(void) 
{
	snarf_construct_hat("/usr/sbin/pwhistory_helper",
	        "368fde1b3b39553d1d5c873c72cd1e6a08d5592637d1f57a4f7fcf762397a3b09bc2a3518ceb83f8edada29d1c2e88328ce65637a813d0dbc231edfd3ac65df7",
	        3106
	);
}
static void snarf_hat_3108(void) 
{
	snarf_construct_hat("/usr/sbin/unix_chkpwd",
	        "46d693ff485d68ef872ae5d487e71332daeb990affda2bf142923e00fc58db349bd63cbebbafd7a021f05ac7e22b8b4ec589b3782af4127b7e0906ec09215872",
	        3107
	);
}
static void snarf_hat_3109(void) 
{
	snarf_construct_hat("/usr/sbin/unix_update",
	        "1cb9f77124e5f3f03ae7c7f59e7ceb48c7494a77d339344a6025c2260df0533d84facd2b13f2201d1458fad6c2a7b4503bc9be6f7a9829ccbd9b76f5f7c212b9",
	        3108
	);
}
static void snarf_hat_3110(void) 
{
	snarf_construct_hat("/usr/sbin/nft",
	        "896989f9f5e5c9f8fbf07c8710af6e5e277d5f42b36f4b91c78e58fa2a53656924e036cb8a19eb30cda8eac4358fab2fe89d479a48d3a3baab3eefafe5eef9fd",
	        3109
	);
}
static void snarf_hat_3111(void) 
{
	snarf_construct_hat("/usr/sbin/mkntfs",
	        "16eb68557f6118f45f01c72938b6c0946888edec07c0ddd9bf94c14bc8812d2a8aeb08a509b117a972e4704e09bc9a94db4ed64936a4ff8b745e62afe7afa33e",
	        3110
	);
}
static void snarf_hat_3112(void) 
{
	snarf_construct_hat("/usr/sbin/ntfsclone",
	        "e47728cac1a5c9ffa03cce34cefaefe16aca6a006763b3b70a625b8c0d339a669e7d9ad3800cbd54ca81a208e888790bdcf4d2c226e784fa4cceca54f6f1cc56",
	        3111
	);
}
static void snarf_hat_3113(void) 
{
	snarf_construct_hat("/usr/sbin/ntfscp",
	        "eea6788751a6b2498ebfc1253ea6dda69d13cb8b11c6fc4bf85b1f755e682490817d80ab0e82eaf7fdc72f71ebe29aafb96f73c34fc7e892710dae3e3b001bf5",
	        3112
	);
}
static void snarf_hat_3114(void) 
{
	snarf_construct_hat("/usr/sbin/ntfslabel",
	        "c4667385e8e870fbdf2d9793be0c341901c44617cc285ebed002af2b642ba8f2c247a68bfb6a159f870f99cc0702ad03e365e31d45e10b0b6b3ba609184c74a1",
	        3113
	);
}
static void snarf_hat_3115(void) 
{
	snarf_construct_hat("/usr/sbin/ntfsresize",
	        "80de47f8bc0122484645f5b42de7607d0c2beb31d8b0965e94b7c88efafc4fb8cbff2c7c8e1a696e0389fe724c550e924c5e98c3aade8ca5789d5602255a9182",
	        3114
	);
}
static void snarf_hat_3116(void) 
{
	snarf_construct_hat("/usr/sbin/ntfsundelete",
	        "a79181ff5e24e47f8925d63bb39a2f5d82133ce3f23dc4e9f89ab72fa5fb884bfd8f9f57e51e597190a70ce5ccbf8299342eccacae27ab08d7e2509f275af342",
	        3115
	);
}
static void snarf_hat_3117(void) 
{
	snarf_construct_hat("/usr/sbin/dnsmasq",
	        "3d482ea63ceb62eb280314db61e50dfded4d4211430ae9d7f63e3fcce98d2444bde826fc0ca24941d30fab4c7fe8d7b6f3f63afb4bd1370c656b6a809aa37382",
	        3116
	);
}
static void snarf_hat_3118(void) 
{
	snarf_construct_hat("/usr/sbin/service",
	        "0f94aeacf437ed6d1d7f9b3ffae835fd5af8e29231a53e83aa432be741da43cf368f01405862bdc216aea3a11f75742be32a48f4963c769db165f7cd1c2f0fc8",
	        3117
	);
}
static void snarf_hat_3119(void) 
{
	snarf_construct_hat("/usr/sbin/consoletype",
	        "383738da985455c4d4407c85a92714ff4190becc1d98a9ea0b0d82c41c7b893225b4c3c9281c106bc3511828e31579d69675f2317415308e6f9cd9a2f62bb6eb",
	        3118
	);
}
static void snarf_hat_3120(void) 
{
	snarf_construct_hat("/usr/sbin/genhostid",
	        "a235ceafc866e9bdf45b126697263195ad3e1a96b9a152251f1f4e39fb0ee82f2e2e3b448b5ae6d2137a84a8a7b516bdf03a72d81a7404bd988833708afad309",
	        3119
	);
}
static void snarf_hat_3121(void) 
{
	snarf_construct_hat("/usr/sbin/pluginviewer",
	        "c0082341caebc7d03ce26d7842f154456bab58c1e8e8b15e119707e0a1956d3b63236c8b863dae0e78af12f6216201de9d666d065bab5478973e97a35e629138",
	        3120
	);
}
static void snarf_hat_3122(void) 
{
	snarf_construct_hat("/usr/sbin/saslauthd",
	        "5a77e91eb23e851f9ed4909d07b52add13add7531be58b68ba3de1986022124312dc01303693bbca3fcdd4d8da67fa1706b983cb9d877d89b86b41d2d946340c",
	        3121
	);
}
static void snarf_hat_3123(void) 
{
	snarf_construct_hat("/usr/sbin/testsaslauthd",
	        "b040641393cdbd6c1cb782f8cacb628fc684ccf8677ceda0b2226245bcf655c5a8a1356d2d93d36280762a42af3a79487d98efb14855009d8d65911d1275ee4e",
	        3122
	);
}
static void snarf_hat_3124(void) 
{
	snarf_construct_hat("/usr/sbin/mount.glusterfs",
	        "d12c084757e832146ef89ff68d1800873f7f56f5b3276913d7ebbac5a5a30aecfb438334951ca6ea280ae49c939d7654ee4d0c81ad0446493ba4f56e0d99a78c",
	        3123
	);
}
static void snarf_hat_3125(void) 
{
	snarf_construct_hat("/usr/sbin/glusterfsd",
	        "af0c2ba5705e4eae2a77e2f788238315c35ebb51528fad3ae478201a5ca26e2dff0959a5b826de33b0831f23a68665e95aae2d3cf434bca25567662bbb77137d",
	        3124
	);
}
static void snarf_hat_3126(void) 
{
	snarf_construct_hat("/usr/sbin/openvpn",
	        "341f3c63b1c5e710b5d5b719e603eebd7b30f3c4a73d36812fea781e98a18b64507c4254ba80e4174d78581f0a4d5d7414953a4ecdb6654311d68b7a5ce678ab",
	        3125
	);
}
static void snarf_hat_3127(void) 
{
	snarf_construct_hat("/usr/sbin/criu",
	        "43a3fa3cde905370f0caf36490e7b78d15578852ebf16b287dc0b33a5773a4988a39ff3ca848b0c644e739930e67eb79ef897f69202cca89b2063a4dedc78b63",
	        3126
	);
}
static void snarf_hat_3128(void) 
{
	snarf_construct_hat("/usr/sbin/ModemManager",
	        "949c2b1f513b73270254612627cc3ccc6638d3e6a3b9cc1192fe83b8761a5ec491986a68867d9cc55e8c27274bc276de987ada64f5433454975df40dc3bedcb4",
	        3127
	);
}
static void snarf_hat_3129(void) 
{
	snarf_construct_hat("/usr/sbin/gluster",
	        "60dee093f7a441ee72afbda67137625e9534c461f158e75f6ef918aa65f896a194d055d427c624aa2d8236223fd3b53d7aff03d0c959a79f876bff628409649d",
	        3128
	);
}
static void snarf_hat_3130(void) 
{
	snarf_construct_hat("/usr/sbin/cifs.idmap",
	        "1834710e6b0da9b7640f4e9889abf0d22b7353e31c79196962502ae669be1346859d86fab34b2eb3520021a4d1e2e9c5776a1971b8b39cb52e5a2afc513b9035",
	        3129
	);
}
static void snarf_hat_3131(void) 
{
	snarf_construct_hat("/usr/sbin/cifs.upcall",
	        "8161e78352d037d9fa7e8729eb6f1d89cff91c7e75962e1d0e92dd51705497b6858bed51ccf07cc170eb91e1b5e058c11cdd58fe5ad733492e1a74270ba7ff66",
	        3130
	);
}
static void snarf_hat_3132(void) 
{
	snarf_construct_hat("/usr/sbin/mount.cifs",
	        "e222e13430f9d707e77d74a8dd663df49247d6f50e446c068d903e2ce7b0098ba740890e0c2fd2f6763675fb6f19193f23678ae3a173dfb51e0fed046bc89dac",
	        3131
	);
}
static void snarf_hat_3133(void) 
{
	snarf_construct_hat("/usr/sbin/mount.nfs",
	        "0f4596518146e1b4bbc5524153c25aa94bcebec75788407250562c0ad207849ab9d5a7e0588760111b9ecd39d9bfabdb592d16129696afe2d17f8a49d841d26b",
	        3132
	);
}
static void snarf_hat_3134(void) 
{
	snarf_construct_hat("/usr/sbin/nfsdcltrack",
	        "4a41acea5d05ff85fe21594948c69eecb2d0cf2cc5ce0e55e627b6d7dba95ef891536e4151b992fb593488b0e894c00b7aeca5861a6d9b5b60f87aab83f911b5",
	        3133
	);
}
static void snarf_hat_3135(void) 
{
	snarf_construct_hat("/usr/sbin/rpc.statd",
	        "eb2b893460176d39f7ea53040c9813284125dc42351fecbb851b4a1f962716e945b50d49a6481249af8562621c68b090dfc1932dfe2e99efb1f23dd137b921e4",
	        3134
	);
}
static void snarf_hat_3136(void) 
{
	snarf_construct_hat("/usr/sbin/blkmapd",
	        "3af7046cbb96a4632fd80e1de139bfd88406b8fed3f4ce297a3f976d5c1afeb47f423a4f89d2d7f4550b2ce38198f2212e918657ebad44cde177b1fbe6648929",
	        3135
	);
}
static void snarf_hat_3137(void) 
{
	snarf_construct_hat("/usr/sbin/exportfs",
	        "7a8aef77e3bbfa0051efd5f5e03b635df9c3a6dd798a646403f88d95d3c1b9cd05ab9a3c4484d7cafa8873c23f6a91201dfe13767bb62c064707eaa1002e7d4c",
	        3136
	);
}
static void snarf_hat_3138(void) 
{
	snarf_construct_hat("/usr/sbin/mountstats",
	        "5e6d94f1414e91345f36d746f9a45c83283dbc0950756f4cc92bedb5856686547cde575968298f26d2608115756b20186d1ad694ba44d4bcdf5dd16304da510f",
	        3137
	);
}
static void snarf_hat_3139(void) 
{
	snarf_construct_hat("/usr/sbin/nfsconf",
	        "5e318f07ddb946c96cf99a7ccf41b3ba599c8e3a6da48577763a17a8e99ad295b4b8f8960a9f02ea3b1c5b77296f85a99f4a10649ac5d34ae663d63fe045bcac",
	        3138
	);
}
static void snarf_hat_3140(void) 
{
	snarf_construct_hat("/usr/sbin/nfsconvert",
	        "0cd981fcd0494af83c313b2e647e91c247e494ca33058d463784fa8c3ea3c40388e8a038b35fb2a1b0740e199452967fb314ab5e0991f54172f09cad47b86559",
	        3139
	);
}
static void snarf_hat_3141(void) 
{
	snarf_construct_hat("/usr/sbin/nfsdcld",
	        "9f8e32be0a6ca0b0db131bc0b0c69ac9cf752945baf6fd35f888997601ddef8d0c338fa53b9729f4b09d2de280880deceecc3b280acb1025cc4cf016c8d2453b",
	        3140
	);
}
static void snarf_hat_3142(void) 
{
	snarf_construct_hat("/usr/sbin/nfsdclddb",
	        "12e1e87d4efeb776d4799a303b540cdd76e1543f4c1d42001405018c2229f463e234c5a76a9aac1138ae78429a1ff7f312d2ceeb410cd174395bcf648cec727d",
	        3141
	);
}
static void snarf_hat_3143(void) 
{
	snarf_construct_hat("/usr/sbin/nfsdclnts",
	        "70ac3b5ab53039be37ae5f48a3cb430353d2208bf2cd32d36f61f1f30e2c8b3d1552d70c85befe50c537343ab4ea18f76ec8c46787f239da1e4b873848a825f4",
	        3142
	);
}
static void snarf_hat_3144(void) 
{
	snarf_construct_hat("/usr/sbin/nfsidmap",
	        "208d2780e8ba0ae6b69eddaff59cac96511c2baf44a47524d10ef3d032bf4f2fc230a8cc840792b129f67d560b2abc2b278b28be4e8ce61a74b775e9cbb10d74",
	        3143
	);
}
static void snarf_hat_3145(void) 
{
	snarf_construct_hat("/usr/sbin/nfsiostat",
	        "7b2c9e7652ae628588f7e113cc223de4be0de6f167ffebc45d774539e2942c9870207883c3323af34e67467ff20ef8e5dd6948fb1a876ecfd0d76358c9259b8f",
	        3144
	);
}
static void snarf_hat_3146(void) 
{
	snarf_construct_hat("/usr/sbin/nfsref",
	        "df048c723118f1aa51ccecae1d39a15d7b0a5d3ec36e65076a2c7c7f520baf367b17ec7cb0f4b7bd0971f2c462182718c3f11ca69a96de1d7c6e242b8e44bc46",
	        3145
	);
}
static void snarf_hat_3147(void) 
{
	snarf_construct_hat("/usr/sbin/nfsstat",
	        "5f8618ad0bc792ed5f77c69a8ddba1a596d6045f05f636c8446220899f38b7515cfb5e3f87691ea604e8a60d626dfc365d0f80a1fe9127b4ef15015cf501fa34",
	        3146
	);
}
static void snarf_hat_3148(void) 
{
	snarf_construct_hat("/usr/sbin/rpc.gssd",
	        "16647eab63b520528f12d66b74a677e63b4a04a1c86bdb106bb2098dd3a3706e09f70f4a2a2263fa494c9c9de027e01bbef2081c7e100c59567319f0c607e9c4",
	        3147
	);
}
static void snarf_hat_3149(void) 
{
	snarf_construct_hat("/usr/sbin/rpc.idmapd",
	        "812f309798013ad622b846647d322f085c2c682fde951c11d3c9920cb9cedee2b743964bb3edcf13a8cf46e05963bbb9a82cc9166a3b7a159b88939de7006114",
	        3148
	);
}
static void snarf_hat_3150(void) 
{
	snarf_construct_hat("/usr/sbin/rpc.mountd",
	        "debbc38f60bb716b54263e405dc9ea2200d78bd10f83fe2b9146e8db28eb4b9c67dfd476cf1c1a00edaeffec2b2e33740cbedf00287ad0774cbdfbcf93aa211e",
	        3149
	);
}
static void snarf_hat_3151(void) 
{
	snarf_construct_hat("/usr/sbin/rpc.nfsd",
	        "3a5b31411b20ba2c9a62556bf12d800260ec19b2b950dedb73a5372662e26f55e99614c2cb0b7bf359f608b1d02aea798a4b50264bf792354048a40d9048ed1c",
	        3150
	);
}
static void snarf_hat_3152(void) 
{
	snarf_construct_hat("/usr/sbin/rpcdebug",
	        "daaa3c09f1e2d6d8a150eb39e716b27f0bc5a1f763841ee775310bda7d8cee5fe9ea2e4f5b878b4d19d4f91989be169124225929356f3a61d25737df2a4a52cb",
	        3151
	);
}
static void snarf_hat_3153(void) 
{
	snarf_construct_hat("/usr/sbin/showmount",
	        "43bcda4ad90229872b5dc7796b5cbcbcaad6ebd4f7d1ee9b8b058551413fe47b766648e251828dd30a9186cfadb70b4665927d37f91844c76fe4f93348430ab5",
	        3152
	);
}
static void snarf_hat_3154(void) 
{
	snarf_construct_hat("/usr/sbin/sm-notify",
	        "06ea7541baf107df49ab5aa1002f27640354e321f1fdab4cea14730113e04d41de0b380a4b1296c1197cd9cc87ff4c1b6306eef8b885b996aee3f408de433b6a",
	        3153
	);
}
static void snarf_hat_3155(void) 
{
	snarf_construct_hat("/usr/sbin/start-statd",
	        "68ccc7656d226d4326c2b6c32b9a67e453347494716441ace1a272164df7efa65e29061334d36db8f209a997479fe3c054df13c9a60be1667d51c058510191f1",
	        3154
	);
}
static void snarf_hat_3156(void) 
{
	snarf_construct_hat("/usr/sbin/mpathconf",
	        "37c9a56412d9c5834ad94bc462362c25d29caff4cca529bcb705377f1b37a7356cf087cc92bca9b2bbdef8e0061e2432801254071b61d98836010037cae32500",
	        3155
	);
}
static void snarf_hat_3157(void) 
{
	snarf_construct_hat("/usr/sbin/mpathpersist",
	        "ee2576c1f0c35ef948e289677cc8fbee96793a3ce36637c6fd14bedc415b7cef178525dc746b5d8e2f6d0b92f57c2ef477ca846c1b3cac432e1880265e69d702",
	        3156
	);
}
static void snarf_hat_3158(void) 
{
	snarf_construct_hat("/usr/sbin/multipath",
	        "065492b9c8c1c83ccfea357c625da77519e70bbadac9beb47087a62dc725039114bc40e96c0ac264dbc40c0b8404eee1d370f2b621e69c69a9e6a0dcb80eab12",
	        3157
	);
}
static void snarf_hat_3159(void) 
{
	snarf_construct_hat("/usr/sbin/multipathd",
	        "918817dc8133d495c48a129fd345221c18d515bb936adfd9a367b75e7841f44ea09386a7c2e5ed86d7a928f3963662b7f391f8a6900bfbed28252463b7d0004d",
	        3158
	);
}
static void snarf_hat_3160(void) 
{
	snarf_construct_hat("/usr/sbin/dcbtool",
	        "fa456ae2fe6cfdb52b8bff08b2c6219c51b53f59fc96cb607b07c2c4703f01febf2c60fa48d1f7ea66cd4ed1d09fe5b30eac836eb32675460124708d6f3566c8",
	        3159
	);
}
static void snarf_hat_3161(void) 
{
	snarf_construct_hat("/usr/sbin/lldpad",
	        "3ea2340a99e4a10209eeea589e45b01c3aeb52dfb06f86da86cc76c5ff3a61c462d31f0627cfa92c299b2569483ded9cf41874b702e5ec18a0ceded26fe6a24b",
	        3160
	);
}
static void snarf_hat_3162(void) 
{
	snarf_construct_hat("/usr/sbin/lldptool",
	        "e73164a2771829bcce7c0e19f83238e8c039f52df4926ae23baf7b15efb1148fad0cb41f5a97bd2a88251975cce407f3a3609f65893e5b02bb9743a1875f6463",
	        3161
	);
}
static void snarf_hat_3163(void) 
{
	snarf_construct_hat("/usr/sbin/vdptool",
	        "4be64264cae12fc40c94b0c2649638c078b16994afa03a3d10d5e236c9c32cf7c83f9783db31d7d177b45d726189b364beae3095b074d0856d294ed01356aa65",
	        3162
	);
}
static void snarf_hat_3164(void) 
{
	snarf_construct_hat("/usr/sbin/fcnsq",
	        "1fa5bd04d82d768cd0822d9025fe26587f03795a600896f1ff17b61ae5967d00180d3a4c5b09e8324ca8e22da40e86f9fc8e02872e5453d95fa37681bf62d469",
	        3163
	);
}
static void snarf_hat_3165(void) 
{
	snarf_construct_hat("/usr/sbin/fcoeadm",
	        "05f1966034a1fc75fd66644759de96d6b2dd5f2d978334d5adbf2a8aa590fc39e473937e28a13e108ea8aa55e8c03451676204eef1ad993494018690c1e88787",
	        3164
	);
}
static void snarf_hat_3166(void) 
{
	snarf_construct_hat("/usr/sbin/fcoemon",
	        "f7d4eeee808965e13f92ef4f1c4c4726b30db93d62c634fe16cc8d17d2b0ab13ad935f5f811ad3ed6bee6d74b47a346085e80ffaf74248e3f4a50143484a794e",
	        3165
	);
}
static void snarf_hat_3167(void) 
{
	snarf_construct_hat("/usr/sbin/fcping",
	        "56ab52e0c4a7fafc2ce06b00c521a0262570acf769d57384224a007c039b01d7fa1891daf48f6cdd725eb457eaaa497e6dbac0c5969dde924c5368b5f91d9d82",
	        3166
	);
}
static void snarf_hat_3168(void) 
{
	snarf_construct_hat("/usr/sbin/fcrls",
	        "0e63f2a4abebc7a92b376f5cc18b874bb7d24e3412b6126a53879b41cafae181a568ebb2b335c5eda879fa1e8f6f54438149e664234d136cff889b18d2f412e5",
	        3167
	);
}
static void snarf_hat_3169(void) 
{
	snarf_construct_hat("/usr/sbin/fipvlan",
	        "cfe718664251faa455f9bd479e824c49f8975ca0e2af935d5b8fadbffe1588709ae198e42b246bd21d062fd6feff6c34d688b79a882166cbfb07737e8fc9d717",
	        3168
	);
}
static void snarf_hat_3170(void) 
{
	snarf_construct_hat("/usr/sbin/cracklib-check",
	        "e993762f1ef5bac21687a515771f5dedc54c951b337fb0adb60f613d99ce64469e44f33734e9b06dba4831a3cb3d6067be2f6f7fb47ae088aae6e9ae0788edcf",
	        3169
	);
}
static void snarf_hat_3171(void) 
{
	snarf_construct_hat("/usr/sbin/cracklib-format",
	        "d57517adb6804f687ee80f17f373f812e33d6d970e0cbe75c7b90903a1549eb670ad2bd052665e6a61eb9129cb6b573a747869ca64a52c9efb540d0b47ded04c",
	        3170
	);
}
static void snarf_hat_3172(void) 
{
	snarf_construct_hat("/usr/sbin/cracklib-packer",
	        "79081d3fd1343d197e7efa56decfc83f31c0ab871bb6ae3a93b8478d27111ba08d967575d9863c2b0cbefc60c9ca59d73237cd45a8395380b20e8dedaa66de32",
	        3171
	);
}
static void snarf_hat_3173(void) 
{
	snarf_construct_hat("/usr/sbin/cracklib-unpacker",
	        "d162aec7ebe52a0e93ad3ebb11edec36681076a5a54c030ffc6856837b36381c97cf75308782eefd0d97c902b50b24f072b716567ec1eb2e4a8ecdc7dc0efd31",
	        3172
	);
}
static void snarf_hat_3174(void) 
{
	snarf_construct_hat("/usr/sbin/create-cracklib-dict",
	        "4e9359e60e14edc87743af9b7cc10b635aebd44f599816da0cdf7738ae602411ac9e4baf3f0b135d340d453a7003462a44e4ac12467b0d0421e110f341b9a8a2",
	        3173
	);
}
static void snarf_hat_3175(void) 
{
	snarf_construct_hat("/usr/sbin/mksquashfs",
	        "88fc94dc89d2d108c0908e0dfbafc27997672c6ee4793617f928b9f5fa08a0f9518b12bd18df34589105f71a5706cdbdf19b73a0fa5e96f42aea4b96a82c79d0",
	        3174
	);
}
static void snarf_hat_3176(void) 
{
	snarf_construct_hat("/usr/sbin/unsquashfs",
	        "d7f0609c0d32719d9283c5021a916cc518658bc441150d09d2a9910d6f2da7609cdff8588643772ec0cc7340fd7118f0032542bd57b3395078a7eec18b2227a5",
	        3175
	);
}
static void snarf_hat_3177(void) 
{
	snarf_construct_hat("/usr/sbin/sss_cache",
	        "b3c074aaa652f0c91085a5486e0366aa61a799fec5bbf956802f4b0dd6ea6dedcd30aeee01ded42435d0dc729c68102d55be69bc1c7d7564bbf2cfe29998547d",
	        3176
	);
}
static void snarf_hat_3178(void) 
{
	snarf_construct_hat("/usr/sbin/sssd",
	        "5fa53a3d5a3e3d170487f826837fd3707d63b20465348a592b4e608af7862c64e85dedfd02e3b80a2ae1e30fe707c0764d976a6ae8f55fbf9719470d6f53df52",
	        3177
	);
}
static void snarf_hat_3179(void) 
{
	snarf_construct_hat("/usr/sbin/pcscd",
	        "5265166a9b10fbf5e7596a825365eec29bb1aabd10f0f665381d276b01c104af1bcdf19ccfda702805af118f510731ee41b4e502fb5342e6fdf2e1b46488f56b",
	        3178
	);
}
static void snarf_hat_3180(void) 
{
	snarf_construct_hat("/usr/sbin/addgnupghome",
	        "f28eb40b2ea372ab91942bbb71953b6bb52f1eb1cd8a27bedf18074677705680b320f7c96461a2c2e514a62bb33de16f3d1e0f48584a9f8173592a89b3804719",
	        3179
	);
}
static void snarf_hat_3181(void) 
{
	snarf_construct_hat("/usr/sbin/applygnupgdefaults",
	        "b75f6498f38bc373bfb2f79de4ac703cce7cea07daf4bb3481b5466dd6a6a9fde63d833b471a8e88a05465c3a083f16e73b20cc693bf46d4abe8eda95cb94b19",
	        3180
	);
}
static void snarf_hat_3182(void) 
{
	snarf_construct_hat("/usr/sbin/g13-syshelp",
	        "f01719234bf8a61b7106bcb05f55e91bf6f699a0345c7b8ba5a7369660b88b612ab987959b28b3bcd1f4164205c93d0648fed9a53d749a0f0760aee8eeaca9c9",
	        3181
	);
}
static void snarf_hat_3183(void) 
{
	snarf_construct_hat("/usr/sbin/NetworkManager",
	        "1b455ef04b9e5264e70bb7bb1dd44d4a67404af48ac7ae8b6550e2fc6053de2c331a0a720aad06d0753dccae1709f100ac888eaa6902354d39aa520abc2bd557",
	        3182
	);
}
static void snarf_hat_3184(void) 
{
	snarf_construct_hat("/usr/sbin/libvirtd",
	        "e7aa8f8b46d255e33e2f217943104b097e0fccc3d8b5445cfef25242c75afff108692d6cb14064268b41eeef0749e19761078ebdcac6454977134ba085fb6525",
	        3183
	);
}
static void snarf_hat_3185(void) 
{
	snarf_construct_hat("/usr/sbin/virtlockd",
	        "4d16e762f21c5f54660fbd4724e6a66a29174bce2321d309e6ea1c53928a85ed75bfc7dab4d4881154babeb04a51fbf7decc2bb8d3d386fc2145b3f6565d9932",
	        3184
	);
}
static void snarf_hat_3186(void) 
{
	snarf_construct_hat("/usr/sbin/virtlogd",
	        "56f37b14ac5b7e89abba221d27e0f6a14394e66a03c20f77d8c1ce1c52c84c927ee533e95331b9b166cbe1c8b960adc1b21d45ea5c836120bab15f441e7fc0e2",
	        3185
	);
}
static void snarf_hat_3187(void) 
{
	snarf_construct_hat("/usr/sbin/virtproxyd",
	        "ec78eebddb3c469b911709959384a15d4da670a480eb05e3349aade38b12f60cfbbfd5b0c43b336b2160f083525ee3c57cc0b61f89cd750e80eabf18e4ecfaf7",
	        3186
	);
}
static void snarf_hat_3188(void) 
{
	snarf_construct_hat("/usr/sbin/virtstoraged",
	        "a62c236ad7781263706939539509373eee73961015b71dd815801e3eb8fba20445e892006d6a632d940687bcf310379e743e29edc2a108a744256343145e3974",
	        3187
	);
}
static void snarf_hat_3189(void) 
{
	snarf_construct_hat("/usr/sbin/abrt-dbus",
	        "539fc38234d9ecf0b9e10c0563dee3a7f077b7a7fd34ba578caab1649ad689e5ab82fe8d31e15015f51a14b8f56440f3f2767952a44c2bdc100405d427114e4d",
	        3188
	);
}
static void snarf_hat_3190(void) 
{
	snarf_construct_hat("/usr/sbin/abrt-auto-reporting",
	        "832119b315265ac4a6a82595c8b136cd44e92fb933820e401b73b47d1ae087c90a7998ac5d4977aae42ded5200d9f9645a46e0ac8c22780a1b48465741365816",
	        3189
	);
}
static void snarf_hat_3191(void) 
{
	snarf_construct_hat("/usr/sbin/abrt-server",
	        "d897d8fa45d76654d15c4afedc1f9754421045408e5a7e0ad1323752add9969313343b0345a3ea0ed7069d151dc7d5c0eaef9aa76c7af051450c3a5989a7ba50",
	        3190
	);
}
static void snarf_hat_3192(void) 
{
	snarf_construct_hat("/usr/sbin/abrtd",
	        "7a2d882864e6f5dc52b2f1c74448385cef2802c4e8ceb6bddfe9fc2b36fb1c25565eaca76bce6b718615d593bfb73f8d753c547604cc3188d83c9edd27095fcf",
	        3191
	);
}
static void snarf_hat_3193(void) 
{
	snarf_construct_hat("/usr/sbin/abrt-harvest-pstoreoops",
	        "b7fa8f0415e1025be9faed78f058c510ae8b737e822ac536eecbfd38fa7873cbf86412c9a87408724659a18f49994c822ef0fe8558a99cd3d28383a4337e74f8",
	        3192
	);
}
static void snarf_hat_3194(void) 
{
	snarf_construct_hat("/usr/sbin/abrt-harvest-vmcore",
	        "8efc5528bedb3e92395c4aac0cac04643cd76d4fee2acca0c62bf6d421cc62167002e442edd0d1c2ab2f56e14bcf39460c0d22fee26ce86040eb3f6ecdbe5b15",
	        3193
	);
}
static void snarf_hat_3195(void) 
{
	snarf_construct_hat("/usr/sbin/virtinterfaced",
	        "32dd6cb82ba8a3e3aa32188dd811c1df8d3bb483187d8efe758f04bfab46dca21369e4b99116c2ea074b03474c59a07dd3eb7bd9b837454b7707374b5b869767",
	        3194
	);
}
static void snarf_hat_3196(void) 
{
	snarf_construct_hat("/usr/sbin/virtnetworkd",
	        "d521040ca70f4adae5738da28a150e39910e2c02c308842d961fd52a528ffa8353f4603d04627393e58f480abf28b8a627dc212729554d111c2f859d5a036b08",
	        3195
	);
}
static void snarf_hat_3197(void) 
{
	snarf_construct_hat("/usr/sbin/virtnwfilterd",
	        "7eefed5a1c27e096d3ef83b19141c6889c5cdad1dfbdb51faad0ff20be8208c5ee7c39ab19b89122110193bd3b5ad77b7adcb6a809050801b11e088896fd65dc",
	        3196
	);
}
static void snarf_hat_3198(void) 
{
	snarf_construct_hat("/usr/sbin/virtsecretd",
	        "e0783519ad28d326b84e966e325145910421c9dbc3514247ae6162c2d7031d508292d127552a81697c698811f2a8aa6de16d264e3ab11d0bad8d71e32c552ebd",
	        3197
	);
}
static void snarf_hat_3199(void) 
{
	snarf_construct_hat("/usr/sbin/virtqemud",
	        "3ea7f33d6c38e88ea5cda5381d61a7df898306f447dabaa298a317a36c1a7a3823f990a525df1f0bc7d8b18003cf04c5cd80b334a3d26075fe98ecc0a29f9e3f",
	        3198
	);
}
static void snarf_hat_3200(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-bios-setup",
	        "75b75228a57af8b569454f7b8adf298ed44dba02c245c88b95b1da2eb5a579635cba41a41b609e9fd3efb5fff776aea574196f8e70c5d989be32ff25216c0122",
	        3199
	);
}
static void snarf_hat_3201(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-install",
	        "b202eae7aba2a83b241cd01f549c5bbe9cde684ca4ec54048b3e5e20319b65d2fa00c840000c40fcfbf8f451e2b9a6b036e5e81aa8fdad0dc7c548254b152baa",
	        3200
	);
}
static void snarf_hat_3202(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-mkconfig",
	        "cad01b8c7f0c9cad42a3d4530288e6af1a5598032011276c7f96351b6ee26e0019e6dde6ee5b1e644cd2b19466ac46d3afaed04a4d3aa1207b088969797a62cc",
	        3201
	);
}
static void snarf_hat_3203(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-reboot",
	        "bb2e3b17e57f8dbfc1c1c17b54056bc0a37fd69755285459691adb04df0dd934ddd78ba93aa191516f8e459f544a923a6e7d340d5b9aa07eab14850435c73816",
	        3202
	);
}
static void snarf_hat_3204(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-rpm-sort",
	        "c0cbb70c0e2cd0264829ea3111c534bb7bba96c943a2950f6e37c3ce06f86bde0ce3ebbaac655651bf59ae279a1796a4fccc1d4fae383589c5c9a002f63f579d",
	        3203
	);
}
static void snarf_hat_3205(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-switch-to-blscfg",
	        "2ae1fe0a642325e6dced600072bc307885e6724ecbe4179986090c898e1ad5ee4d24b5fc8bd412b7bdd6ae3bfe9b439b10e494df8223a4aeb8ad377a8ca36f6a",
	        3204
	);
}
static void snarf_hat_3206(void) 
{
	snarf_construct_hat("/usr/sbin/umount.udisks2",
	        "b3020084915b2b5d554b7abf7b3f6bd6083ed236bcdf7b5557ee4396d2b865662d88c93a77a0d30f7c1cab12ad374f615f49dfbddd95f11932d713c9ba611ff0",
	        3205
	);
}
static void snarf_hat_3207(void) 
{
	snarf_construct_hat("/usr/sbin/mdevctl",
	        "74b5359fb9f5784c7149fff31e485e705458ad2423c29768ebdbf4d8d6804131a9846cbdae42e2d99c4a50ced11b9b75cb3a850ec3fbfd8466253ee6c3f3a083",
	        3206
	);
}
static void snarf_hat_3208(void) 
{
	snarf_construct_hat("/usr/sbin/virtnodedevd",
	        "b44ce6292c7c69d7b1f8ca22c81b3d5807a31b9934a7f3195a59c186c0ed6bba705d90f714d7c5c602efe7e0ed4cefa7a77048ae4b3bfd335199baf0d67a4028",
	        3207
	);
}
static void snarf_hat_3209(void) 
{
	snarf_construct_hat("/usr/sbin/apachectl",
	        "f3dc46e1ef011498702b32c2d4c6f27da3d4a4a9cc980048de495b5bbeb4c9367ca3154b8b185a2837fec17741070d8df39b4aede95fd7aa2926f3343b8db073",
	        3208
	);
}
static void snarf_hat_3210(void) 
{
	snarf_construct_hat("/usr/sbin/fcgistarter",
	        "01f3506922fbea053946786fea1f8de40267004cbc8a64fb8879455f8269217bc543bb9fc7c931deb01fa5cbff778f933ff5133d95117c1592206db576bc0924",
	        3209
	);
}
static void snarf_hat_3211(void) 
{
	snarf_construct_hat("/usr/sbin/htcacheclean",
	        "bb80d76fb05e8619b6f7d3dd9157a6c942b4d9c7b01ccb51df0011a627ac243d70a9d33fb1a95f7e404bf66e89eb8d0fcf28b450befb73933ae2ba45899b701c",
	        3210
	);
}
static void snarf_hat_3212(void) 
{
	snarf_construct_hat("/usr/sbin/httpd",
	        "c93a0d4d125b4522eee1662b409b0caab9fc21ed233adc984db7bd43bd86a2ce17c260e3169743f28627f8cad0bbca7a9c04bc659f81704327ff716cafff5b06",
	        3211
	);
}
static void snarf_hat_3213(void) 
{
	snarf_construct_hat("/usr/sbin/rotatelogs",
	        "89b04bc7a981367c53450e0fe6555a58c8328e12dc0158b029e04ac3aa3c33620cd92bc2b3e5269ec794e9241a7ff2d3a24a3fb8fcbe8123e32eb694538a49a5",
	        3212
	);
}
static void snarf_hat_3214(void) 
{
	snarf_construct_hat("/usr/sbin/suexec",
	        "5004e1010ffa103b1b9bd0f69f4f117e363758d35b78cde64c86739697bfb329326eb90be40dd16be8113eb65e6b083a8282c2ebd180946f76030cba5e36171d",
	        3213
	);
}
static void snarf_hat_3215(void) 
{
	snarf_construct_hat("/usr/sbin/mount.fuse3",
	        "09d0e58ecd0a285e0550c9a117a1dc60db05c65ad5502a2fcf6e606dec282a6239b6660af8f070b34f4e4b715211e3158ee690de3a14621eb68642bb43db1c51",
	        3214
	);
}
static void snarf_hat_3216(void) 
{
	snarf_construct_hat("/usr/sbin/anaconda",
	        "c89f722c9645ef905c6b2d935f3491fb10a398b5da5412c61e0bb0be32418f0bd8462f06975c728c2e300c08b43579e485833bd2145eb97ac3e82c1c11a26582",
	        3215
	);
}
static void snarf_hat_3217(void) 
{
	snarf_construct_hat("/usr/sbin/handle-sshpw",
	        "d6a080f658048736e3175db4df324ae5b6c31f3b3088fc805714bb1247cfd859f06dca83ec8aae10156b6944e6d9a399f2a8e194f88d7688296a2804fff19a3c",
	        3216
	);
}
static void snarf_hat_3218(void) 
{
	snarf_construct_hat("/usr/sbin/dhclient",
	        "a1ad5646e9a645dcbbbd9d214a513c8f91a34a828f2c1b0fed756673ddce71a20f236838b0362e6b7b2100bf46470aaa7ab4b662341d663b22387e9d18ed8f54",
	        3217
	);
}
static void snarf_hat_3219(void) 
{
	snarf_construct_hat("/usr/sbin/dhclient-script",
	        "3efc7504abab8266c8b86673c7f119caaa90fd6b94d05f395922219739af4441337f2937ae770bcd1bb861495c9f2d39ec1b59fa9b74dd478c30b250142bbd8f",
	        3218
	);
}
static void snarf_hat_3220(void) 
{
	snarf_construct_hat("/usr/sbin/ddns-confgen",
	        "ec116a13d857c345ffb4ef388a5b57c191d032d772031219eddba34ab0169e29e817381021b039d2612985537607b842bc8da97828cf17907a6c352486cc53a7",
	        3219
	);
}
static void snarf_hat_3221(void) 
{
	snarf_construct_hat("/usr/sbin/named-checkzone",
	        "15f73010defe21cc6d80c77c9faeba52419bd207ea937ecb71907348cddf25bec50b30a128d79f81246a4bddb2e8cefb7c6491f529bf22859e8543b93509c670",
	        3220
	);
}
static void snarf_hat_3222(void) 
{
	snarf_construct_hat("/usr/sbin/named-nzd2nzf",
	        "ab25a4c36c7bc1a0bf8ec07c6efe91c0bdb25614ea76fa379c34baf6925529b6cbef2eb42864c6012b19bfa50de1df039797fa6a818ab2f3e2ca86e607369a35",
	        3221
	);
}
static void snarf_hat_3223(void) 
{
	snarf_construct_hat("/usr/sbin/nsec3hash",
	        "16f65325ef0fb6506c1e4377687802bb51914032b5e8b2feae76c21225fb2f71424db15a6d0e871c1daa761b38ab9df78c472bfe27baa30dc41ce883dcfeffbc",
	        3222
	);
}
static void snarf_hat_3224(void) 
{
	snarf_construct_hat("/usr/sbin/gdm",
	        "ed7c814e7706b3ed0d5221e5eaec44a3e29919e5767d8ff938b4569265e82864601513be8917b5dfb1abe95561bd33c801bdb24eb26794305da4b577a624925c",
	        3223
	);
}
static void snarf_hat_3225(void) 
{
	snarf_construct_hat("/usr/sbin/liveinst",
	        "bd54b1c93ff6b48b5bcb477d1b18dbffaa59fcce8a5114448e76c04059f6f9e230a93ac4e9dd03e556e7ed932885e570b65239e0dab54fb6bd65eaf5ff912383",
	        3224
	);
}
static void snarf_hat_3226(void) 
{
	snarf_construct_hat("/usr/sbin/firewalld",
	        "09adcff3e18d9e81aca7913df6f70f53d14a2cbe3567bb0f36ddcf7cabe88177bd98d07b17d80f5dea6cb594854b89fe9c78360a63b535f966654f823f1926ad",
	        3225
	);
}
static void snarf_hat_3227(void) 
{
	snarf_construct_hat("/usr/sbin/sos",
	        "4685740d717863e778d94e96384cc2f4faac679481b62b685751b1f8a8fbe69faadb01c464a98de5d8e3a1e609cf1f0b850f9eaaf3e843af69e29b85ce6d9e48",
	        3226
	);
}
static void snarf_hat_3228(void) 
{
	snarf_construct_hat("/usr/sbin/sos-collector",
	        "616d54a7670a1725d6fa6475861cfe627bab32d4f3a772713bf16efb22c7be2140b738665d2b38f1f59e43f9ca505e36e9aebc2f16676891548dc942d6e553c5",
	        3227
	);
}
static void snarf_hat_3229(void) 
{
	snarf_construct_hat("/usr/sbin/sosreport",
	        "6d00856fd9d09b00999920896909bc8daa55c70bfdaa8089ce24e1ed502b84dd32f3197fe4a1b53a58e941c99a0d78536316cb0d091decea071e5ebee6ce25ea",
	        3228
	);
}
static void snarf_hat_3230(void) 
{
	snarf_construct_hat("/usr/sbin/cups-browsed",
	        "e478294c24f736dffd603a443289ef81db75cffd5ad81e3ff19f6e7c5094ae4874e91931d3949c8aeb2e60d7e5a9f4e303e68660fad2969d82ace0af2505102d",
	        3229
	);
}
static void snarf_hat_3231(void) 
{
	snarf_construct_hat("/usr/sbin/auditctl",
	        "b60c705b10ca08ebeeaded0e5e9e35de8e2cfb03ad0786a6ec0cce2f8cd732415ace91839130ea17c8113cee9c584a53946e797cb623fba81844325d21a2614f",
	        3230
	);
}
static void snarf_hat_3232(void) 
{
	snarf_construct_hat("/usr/sbin/auditd",
	        "cd62a01abf58dd412e74d9cb955ae50c5a91e82d517ace48a87c4fd2ea8b67f3f50e711d6e63dfa2be0486ab3bbbd081190141c3f9f96a3876b1afd84ff2e8d8",
	        3231
	);
}
static void snarf_hat_3233(void) 
{
	snarf_construct_hat("/usr/sbin/augenrules",
	        "29aa472217d486113e3a982c53d50cb5da8f73f85f30c38f412138e87c40d8a485aefdb84c08ddabcb420d570596c74585aa6220dae655f44405116871dc2298",
	        3232
	);
}
static void snarf_hat_3234(void) 
{
	snarf_construct_hat("/usr/sbin/aureport",
	        "1289fe9024d71a8b917721a546a025d245b513bc3c8565a567c598b76f33a3b1ab1a5d07a375d22a799c591c8712924e2df5f9290e58f644d957ae7c9a9e56e5",
	        3233
	);
}
static void snarf_hat_3235(void) 
{
	snarf_construct_hat("/usr/sbin/ausearch",
	        "ba548c753c720283c60c7b1f2f49db11d4995be597ad461fcb200d28394bd494ecd352056b8ff9483cfc9f56a086445e1fbce7a5eaac4e0a5e372d29d50e1e86",
	        3234
	);
}
static void snarf_hat_3236(void) 
{
	snarf_construct_hat("/usr/sbin/autrace",
	        "08d957f5086b7901201552b4d6c4b815c10a3d5e40ac743df15f3b4f1943c8f94b71499899c38db6ec9d7cb66b82eeaef9f1ee75d972b91ec08a01d2b4052259",
	        3235
	);
}
static void snarf_hat_3237(void) 
{
	snarf_construct_hat("/usr/sbin/sshd",
	        "47ea5fa2d763edcc690c5d960795bdd8fe6bc9d868cb96c6ca0c836d28bc51bdbe203bc7387a60c98cef2befa68846ad6edd76927d2a5cee0175319c7324ca53",
	        3236
	);
}
static void snarf_hat_3238(void) 
{
	snarf_construct_hat("/usr/sbin/cryptsetup",
	        "0107cd7e52b99ebf436cb0aef5313974ff866fe36f565a86110c3b7bd66c98992274f682eecc0d788e64493f5c73ffa6e46a3d316c0fe4a3ad7635eb04ebc64a",
	        3237
	);
}
static void snarf_hat_3239(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs",
	        "bade5883b38d9340eec437adf5450e5f867c4ffc0cdb21a04ec200a46ef1b26ae746e6b954ebde4d063b91de5ba84bdd79bbb2f1aa2cce2dcd20b492965461fb",
	        3238
	);
}
static void snarf_hat_3240(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs-convert",
	        "f35e089f257d2d8247529f85927cc0816c31d5d0f454cfc04b1a400a0e6457c5d0f40ea7e5f564e6f0e4e1c2062aff9d63878d79dacbf3e6a65b86ce3ccd3132",
	        3239
	);
}
static void snarf_hat_3241(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs-find-root",
	        "2cfe0df8776eed2afdd3f6c5e914f7a735550e1433afd5caabd186a88f3342cf641f4d8c18f438a18c865f6191afd1deae2ce18a606932695bbb60b56845014d",
	        3240
	);
}
static void snarf_hat_3242(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs-image",
	        "277440fad3785fe06617e08280bb70bb5c14d044b6fbaa5d4c0fa1ba6e85a82a0baa85f8be6ea63db7e36019b704e6e3e0ee805532f527948db4e0bf968aa8de",
	        3241
	);
}
static void snarf_hat_3243(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs-map-logical",
	        "8d02719f0d5ba21d0247f57a48b2f372d31fafe4c5e5ca2e551e24369668c3a0c6b6606f76499298dabfc39d79a09f41b83f2b2b79a57105df1a052614ec44c1",
	        3242
	);
}
static void snarf_hat_3244(void) 
{
	snarf_construct_hat("/usr/sbin/btrfs-select-super",
	        "ea32ff5e9831b0db3f613d7e3787ea82d20b2dda42e83526cddc4cd5b3a247fb16f7d3ec457292b539065d29f517878760ec4ef2414a8dd3c453c37ad0af0c41",
	        3243
	);
}
static void snarf_hat_3245(void) 
{
	snarf_construct_hat("/usr/sbin/btrfstune",
	        "e5a02f6431ec6886a1be99a3c44bdf231fc73b5d80125a06680494cf8d57df57c807d8bc592245500ac4c0cddde0626b5b306176f839d4ba1a7650c627baee42",
	        3244
	);
}
static void snarf_hat_3246(void) 
{
	snarf_construct_hat("/usr/sbin/fsck.btrfs",
	        "c4ae2fd25c6619cc5c2f63ee5e9b94cd1ff8a3fe239f1df7fc84e4ede6b506fde673eb8c3fb7c287e8c2775f7ed1806f4984ac54a71187c8d66c72f3304e2404",
	        3245
	);
}
static void snarf_hat_3247(void) 
{
	snarf_construct_hat("/usr/sbin/mkfs.btrfs",
	        "5ee88533309df1d0de09280a14df832b9a3371f1adb0729e92e7ad51101086e73eadcf843c294807ac902521340fe2c9f882520fbe72f4df3bac9f09291b682c",
	        3246
	);
}
static void snarf_hat_3248(void) 
{
	snarf_construct_hat("/usr/sbin/ethtool",
	        "021a16f250f18627a5b9534d7bf450735bdb837d9afe5cf2ddc192b0322bab2fe4669fd5fd01aed7155bf4cfb1fe2b11c1815d539fd8ba06af3a7b0326ad1cf6",
	        3247
	);
}
static void snarf_hat_3249(void) 
{
	snarf_construct_hat("/usr/sbin/grub2-macbless",
	        "9063d8a88c0af92a8404eb317826d2f893842ded8a5d49670f597ea3947947f5c652dd9a36a59dfb67c6466f8919326583bcfbc93ef2103409d525b82c7883d4",
	        3248
	);
}
static void snarf_hat_3250(void) 
{
	snarf_construct_hat("/usr/sbin/fedora-burn-yubikey",
	        "ad181564d3e01ded65b977a063fa7b764ee4ea86e1d7d022fddcb9336382eb71564a59203bebf8397e72f8ae2fa9aca369400b94da1c3859c47553cd5c554616",
	        3249
	);
}
static void snarf_hat_3251(void) 
{
	snarf_construct_hat("/usr/sbin/virt-what",
	        "9c8f921dee87e99f6165665fc7978a8cfd9339f25cfc7d0d093470ba9034d6160a7416e7adec49db6443769bfe7d99f8b919d4fb56ec4dc33f652d03685aa143",
	        3250
	);
}
static void snarf_hat_3252(void) 
{
	snarf_construct_hat("/usr/share/PackageKit/helpers/test_spawn/search-name.sh",
	        "9d5827a89f66f3a8f727091c97e21ce93d086c176f63c904a60117fae2b65b3f8a6dbe5601c6f84ac474fa4b24ab4fb3ec166ba5284b4d93099ea206e5f6f4c0",
	        3251
	);
}
static void snarf_hat_3253(void) 
{
	snarf_construct_hat("/usr/share/anaconda/gnome/fedora-welcome",
	        "f5e0a8ec9db2260ab2ccbded083f9e9df23482ac730d07969f905de6c2d0509af89a5c634d3b37f525c049ce3976dbc3005f36f646d83e6a1dfe22faddf2fc36",
	        3252
	);
}
static void snarf_hat_3254(void) 
{
	snarf_construct_hat("/usr/share/anaconda/list-harddrives-stub",
	        "5bb5fac670ef077dfd0237fcef33117966608dbf84443c6f6d659c23ad846c8eba2d70804d6285c9de05feef746bff499a343cc29e8cec12af4ed4c213717d5b",
	        3253
	);
}
static void snarf_hat_3255(void) 
{
	snarf_construct_hat("/usr/share/anaconda/restart-anaconda",
	        "b4406164ed266edc118daafbe55f29e699ff2a2b2df84576036504a71f15d9eccc5b3644c694d8a93571894f05b6a9ae97f327c182cdf799f13f9b33be48f6ca",
	        3254
	);
}
static void snarf_hat_3256(void) 
{
	snarf_construct_hat("/usr/share/backgrounds/f35/default/f35-01-day.png",
	        "090451b7379825268866b338286d4d7d950933ee4503e50b0f2fd168434ab18e1e0635c2fe4ea049499db91f6cecb84f8d32fe4d8bd618dd8499c87fa818140d",
	        3255
	);
}
static void snarf_hat_3257(void) 
{
	snarf_construct_hat("/usr/share/backgrounds/f35/default/f35-02-night.png",
	        "07137ea7679b41e32311b8ccb5ca29d294ac636bf3604c4cf06706aa0f765c7ff39037066b360e01cc9739a5473f6ce770012d32cef38c3da2260fd929563677",
	        3256
	);
}
static void snarf_hat_3258(void) 
{
	snarf_construct_hat("/usr/share/crypto-policies/python/build-crypto-policies.py",
	        "e983e6f7b607dedd20a29bae1397d948b0c5d21eb639561e5f07502b38cedeffc746e7b16293e1cb0c48b2c402b34757bf8c15df0ed492f0daa9f3538cbc1c2b",
	        3257
	);
}
static void snarf_hat_3259(void) 
{
	snarf_construct_hat("/usr/share/crypto-policies/python/update-crypto-policies.py",
	        "eb81f5c90f0d568eecd3220367a65fad965ed9f918ff6620745f0f0a44e827ac909c7bed395324007e19b10e4d59d972690d5b2322cfdbdbd684b7e0351025a1",
	        3258
	);
}
static void snarf_hat_3260(void) 
{
	snarf_construct_hat("/usr/share/doc/atkmm/NEWS",
	        "b30a6f72b4e374b3aca745c682578d8369889b54458621284d301148097aeeeb9b998564734cd5e2ed28cb93a0d858e3dd48b9545c422caf51da13858b29cadd",
	        3259
	);
}
static void snarf_hat_3261(void) 
{
	snarf_construct_hat("/usr/share/doc/dleyna-renderer/ChangeLog",
	        "a7a6e093e090b1754d0186d8d585ade5b159188fe9146f02ad08559ddd14357dc7a2479f2dc48171df7e87a69ebf16eb4cb1453baf3e4956b96983da410a348c",
	        3260
	);
}
static void snarf_hat_3262(void) 
{
	snarf_construct_hat("/usr/share/doc/dleyna-server/ChangeLog",
	        "c69775bf746131ac9be9f1421d0a28f2f93bd9583f9f8a89755496186d817c70ad541e3aa581be6be0a71b54c8a3edc3f3d2da0b72a61b7b5fae3dde33de2040",
	        3261
	);
}
static void snarf_hat_3263(void) 
{
	snarf_construct_hat("/usr/share/doc/glibmm24/NEWS",
	        "fd6ca3fb5159559f591db8705623f36766e3c60d16407fc3e500383f91a7be112b5daa1dae0eb213939b7f05ca81a9091a07b217a625c63493cb497bdeb41e02",
	        3262
	);
}
static void snarf_hat_3264(void) 
{
	snarf_construct_hat("/usr/share/doc/nftables/examples/ct_helpers.nft",
	        "1af18a7ace0f36ae2083fad4ffe517218208e407de3df4da6d41b464015a9905d4858e7774d7e3d87c673b1eab08ee437c679cbca7bf9db92dbca7c795198d26",
	        3263
	);
}
static void snarf_hat_3265(void) 
{
	snarf_construct_hat("/usr/share/doc/nftables/examples/load_balancing.nft",
	        "ae7c272c19b159f1f5dd53372861eddb518e5f57e2a7367d6f4e5645f01eef72b55f7c09b47ac6656b4f09e2366bf2657f0bc657a03fcbcfb3368cd192725a16",
	        3264
	);
}
static void snarf_hat_3266(void) 
{
	snarf_construct_hat("/usr/share/doc/nftables/examples/secmark.nft",
	        "7b35f62ac35e7a0b56ffb4a93d442e56d5a08a6b05fbffa78a9769a8aa2e246a6f8532dd126b0a1690727fdf85eb839eb246b1f286fe38443ee187003b2e8693",
	        3265
	);
}
static void snarf_hat_3267(void) 
{
	snarf_construct_hat("/usr/share/doc/nftables/examples/sets_and_maps.nft",
	        "3c0f9b280c307b7b41113bb44ba1721378f804d5b4cb875a8df6792371b1e104e02c72da7e38644a0f08268cadcef8183aced550d0ef83b6dd0e754660f210a5",
	        3266
	);
}
static void snarf_hat_3268(void) 
{
	snarf_construct_hat("/usr/share/doc/nmap-ncat/examples/scripts/http-scan/scan-example",
	        "1b0c40e338b04868458b0e6023f081b2ca0fd05c2e3d02ca0f5c09a090a203de7f156a6d959be7ee191057525ceb2fe83ba5a8c962900ff5216e3106ce6aca5b",
	        3267
	);
}
static void snarf_hat_3269(void) 
{
	snarf_construct_hat("/usr/share/doc/nmap-ncat/examples/scripts/http-proxy",
	        "dcdf0289e42dfd8e39d1b4b0e1f00b844d2693fd5c0ee19e3d287c09eb34b7e521047796e88c7763fd7e1721980e43849462ba146ea5816ce398eb8f31803a27",
	        3268
	);
}
static void snarf_hat_3270(void) 
{
	snarf_construct_hat("/usr/share/doc/pangomm/NEWS",
	        "b79aa51e469fdd39cb08d157c5bacaf68afc65d903b4a61d2fe2e0cd81b022c34e07d357a1e0faeb42bf03e65dd474b96e5fb69a49832de26da30438cdb6d098",
	        3269
	);
}
static void snarf_hat_3271(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/astat.py",
	        "11c97f7ccb26588a541a616ca767387f5c9b026d09dbb5e7318945e2783e4b8149a3cca7ec9f91d3d51427ea9eed8eaf90728ad6b28d3fc44f96078e7a9a65b2",
	        3270
	);
}
static void snarf_hat_3272(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/cgishell.cgi",
	        "4dca6b4e7693bc1ec5b1af09bccf57262410660f05d2e901fe9f795af0b1a30fcdeec04f32cb18b75e153319cecc95da026c52e351d80d71c6b7b075cf5ca6c3",
	        3271
	);
}
static void snarf_hat_3273(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/chess.py",
	        "5b9b1c624846a17db33c85fc5ec7de4137b67807d2ca4bc94b9f5cc9551998cfef3ba7edab389dcacdbac0f3365c4cfff42f3496fcc9dda2d6212cbc432005b5",
	        3272
	);
}
static void snarf_hat_3274(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/chess2.py",
	        "be0c187c2bf72c847519ad40a7df21b7f7e8f3e0876a858b117b48d68ea2ee1175d65d0f7a7f324508e7fd3972130ff4258b8b0201e0f7a8bc6483228f7542f3",
	        3273
	);
}
static void snarf_hat_3275(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/chess3.py",
	        "32faad1c74498293b062554072f4510dba0b06edbf9d4e6d4c2544d81d646922ee6f5dfedc090b929c96736a98dd3b251178407826874d232404da17937644bd",
	        3274
	);
}
static void snarf_hat_3276(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/df.py",
	        "7bf61ee6a8be29054aa99b83598164a93221b3a379be611d55f11ce4e3db0968d0a0987efa20a50346eb26f0b2a829a289c1c328d6aad3bd63d8519846c165ce",
	        3275
	);
}
static void snarf_hat_3277(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/ftp.py",
	        "0d7a37a80bf5b1249f502da018b512bd52c4fdf3649f0c40c1a61694cb0042651dd8d295f051942301b243f0fbf340c309e894699bb47fb7256d62127f185878",
	        3276
	);
}
static void snarf_hat_3278(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/hive.py",
	        "3e64213f9ef328768406e9c7f0fda3dc86a592cc7707a2f121c4189fd9fa5d072bcbb60ead39832913f4cb5556d910dfb64d804c4fc2300e89a5e445dcc89765",
	        3277
	);
}
static void snarf_hat_3279(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/monitor.py",
	        "e6860be628b066370aa459f891d9238cd36cfb83cf3e9c0f85f28a1cabb6e8cbaa1f033a16701a983892be5f5186a96057924f5921b83005629bf6790dde4573",
	        3278
	);
}
static void snarf_hat_3280(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/passmass.py",
	        "ec12912ee9e489816b45c989d13471898c145ba8e1806a4ad42217c1dca5b4460b593c335728f3aeee82f28b2f6e0379b8fe938a809c6c1a088db51c2deff7e6",
	        3279
	);
}
static void snarf_hat_3281(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/python.py",
	        "6cfe07f325fbc8a65268a3905d76f1aebde0eb0cf690ec5fbda47f44a455b6ccc29673e0452641c91632a4dfa3cfce782d4145166b709af55bedeac0fb6fc735",
	        3280
	);
}
static void snarf_hat_3282(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/script.py",
	        "3b1e83db70b2f6dcc8c1f2b9de3c524bf4027f155f21ff87d8487637e2272a3ec174048af4e68d22f33d3499b7400b3910547c17b85466231fd9e9f013148f42",
	        3281
	);
}
static void snarf_hat_3283(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/ssh_tunnel.py",
	        "0f5680f5d90524e92582ac4219df94b2af39a3b52a580cd2459263e0755c004df1d9a3855e818e2422f0deaf937198f0c4679bd6435b9b357ca9f98049151f4f",
	        3282
	);
}
static void snarf_hat_3284(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/topip.py",
	        "de59668fabb5182a83e3c6d2dad6437c6a73157bcfdb40f90976246cc20f49d7ecdf77dc89a7178c0494b79e85e40f155a18013481e0dfc1405c3d4ba5236606",
	        3283
	);
}
static void snarf_hat_3285(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pexpect/examples/uptime.py",
	        "58ae7fb1aec21ec7dc7bc8257e21257899dbf1b009a36577d8ce2507421edb0a7ba934440694f53d6d2cec45db60e6d239e908fc2411426c43994aa0237b794e",
	        3284
	);
}
static void snarf_hat_3286(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pyatspi/magFocusTracker.py",
	        "b06746a28f198cc00ece513f252168eb7e5765e6f321dc99bd0fd80ea919c8e1aad2a15a95b2286f152b84390abe384b61748329982e4014fd6f056c6886ea7e",
	        3285
	);
}
static void snarf_hat_3287(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/ext/test-suite.sh",
	        "128fddc0b0e910d6db6684e139203a779adc14c1dbb20b4773700ef836e22aa038dd826e2961970e6ffaaa52eea9b47526b3496f9f96d240e37dbe8d7173c13c",
	        3286
	);
}
static void snarf_hat_3288(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/fake-curl/curl-config-empty",
	        "54ad771b45a39826918850e3fcd8e36b149daea1eb6d72ebfaa2f00bfcb8f213c5c16469bbe917a10d80acbd33dcccdb66b035ff460c0c9bad71ee29d8c47587",
	        3287
	);
}
static void snarf_hat_3289(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/fake-curl/curl-config-libs-and-static-libs",
	        "521b0862963d5f4b48d5cf51b62663dfc0b39b289e762865f44eb1a02dd73b6ffde7c0506c46480886febfb78145f1fec110725ec657096e5f150b059d0df8f5",
	        3288
	);
}
static void snarf_hat_3290(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/fake-curl/curl-config-ssl-feature-only",
	        "a0c479dec75a0ea5fa9c1afb4f80969b77ac7a03bf44b245a42f3e6883ef917f7503774d17834f4688faaf1955e2d35e3e7d1a252ce31d41839a564b85f311ad",
	        3289
	);
}
static void snarf_hat_3291(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/fake-curl/curl-config-ssl-in-libs",
	        "7da54e05dc72c3dc93fb7463a52784ada9a25a15b4569438bdb251dd3aec8e95369bc72f34e0216d10148d69ed79ec681e38017e76ef402cb03c6c402fcf6b2f",
	        3290
	);
}
static void snarf_hat_3292(void) 
{
	snarf_construct_hat("/usr/share/doc/python3-pycurl/tests/fake-curl/curl-config-ssl-in-static-libs",
	        "b5ee13a37a736c764eab5b1b1ed7b711a101132ffa1abd61f05d1c68100f6419e8e5d2ce9c5b34a61b7e51026778f49e292c1e723143b463a355938e0bd8b426",
	        3291
	);
}
static void snarf_hat_3293(void) 
{
	snarf_construct_hat("/usr/share/doc/wpa_supplicant/examples/60_wpa_supplicant",
	        "4b332120e8e6513d8a0d9aa527005aeb1814a3ecadbeab524ac15af1b66a63003f5f8b7388bd4e49929aadde434f43f440dae05874f845d6f3cd660a92c66ff7",
	        3292
	);
}
static void snarf_hat_3294(void) 
{
	snarf_construct_hat("/usr/share/doc/wpa_supplicant/examples/p2p-action-udhcp.sh",
	        "1c0582c956c0f3c9ebb58613e3849c72ec50fee5f9ba0f2b5e5b45f4ae8f7838dbff3d9a7aa3ec2f7068346f173500eaa7127556818410384550fdacadba4429",
	        3293
	);
}
static void snarf_hat_3295(void) 
{
	snarf_construct_hat("/usr/share/doc/wpa_supplicant/examples/p2p-action.sh",
	        "cc3bde46b9e55ae62a61abff841c98bf6a6231f3a4010a2580159cf89769e9bf456ac4878f43dcba46cee47e0e617c5e4ff13123fc968c167ab8b6a0f0d04b96",
	        3294
	);
}
static void snarf_hat_3296(void) 
{
	snarf_construct_hat("/usr/share/doc/wpa_supplicant/examples/wps-ap-cli",
	        "0690c9ba410e6154231fd77c6f2031eb9eee0cb880ff4381de640ad4e7346eeb666b3c41a97e9f44ce35fe4978b164d39133b602ed3a80fee50944b6f927d200",
	        3295
	);
}
static void snarf_hat_3297(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/solaris/onnv-gate/export",
	        "61063f9586e8e00d0df126bc9de7b9f368d9f4dc6f9ec2b2c9a73161938b9f03241c792347a8ecdbb0548488617e95d35d8fea0fac215cb83c651edffe07b044",
	        3296
	);
}
static void snarf_hat_3298(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/solaris/onnv-gate/log",
	        "771e8af597b42369b7c1d99c2db51d3de41b887d9f9fef30ecd3e00511e4036e23efdfcf69ea8f8bfec258c7607e64e881e61e0f360efad7c235a605b345eac9",
	        3297
	);
}
static void snarf_hat_3299(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/solaris/copysolaris.sh",
	        "b256d08d68bdd5bba6ab6523c03c63e663c3c70a4232e3b79987bffb71764b3aa6f01fd0523e402d45e738855b43184cdc1923134236fbe08b6d0ec9f11ef7d4",
	        3298
	);
}
static void snarf_hat_3300(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/solaris/copyumem.sh",
	        "1e098821e8cdff55b21ca8324fe1237c5007f0b3d383e385fcd8384bb7f1d1063023694049e2784ece075d068934d78f703b5f7d906fc93604fde092c63a24db",
	        3299
	);
}
static void snarf_hat_3301(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/make-dist",
	        "cd085a8b4d7fc85620671df101cccfde863fb9a0a8f0b85a6f25677ca5d1dbf623780edc1de7bc5ce00d790e954d0245055f2fe8d3ac5b11b4dc183be98563a5",
	        3300
	);
}
static void snarf_hat_3302(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/publish-master",
	        "bf92ee1f7a5d48f2a050b8f6a0c8ea3366d4f30f16d41ba268c116c4cdc55d769227ea1b03b4be722262b3cd3d421f68711d0db551c45aeac0b460578115db87",
	        3301
	);
}
static void snarf_hat_3303(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/zfs-fuse.initd",
	        "df46adb274edaa7829ae822fa4edc55b1d169e0d9a965102337ce7fd4e9144daa9054071013b511779ce606d8075a21e4893fb23217ab61133fca054d4b3dbef",
	        3302
	);
}
static void snarf_hat_3304(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/zfs-fuse.initd.ubuntu",
	        "94347790dcdfc059b0008c39bceb241b58caf507b5a7984cdd55d068d35cc146f447fff26f149a6dd50dbb55761a83ec4f44113ed362e522a058e47e2c7b3222",
	        3303
	);
}
static void snarf_hat_3305(void) 
{
	snarf_construct_hat("/usr/share/doc/zfs-fuse/contrib/zfs_pool_alert",
	        "0c81bdfcccbb8fb7c3214c92b7394c5ef048ccd5e6a26831f71e15b328059e30dff8dce1d49188493f44926c1ec9483f54e53fd290f0c7faf1f6d5d459c06ce5",
	        3304
	);
}
static void snarf_hat_3306(void) 
{
	snarf_construct_hat("/usr/share/doc/krb5-workstation/convert-config-files",
	        "aa6557645575bcac1a3a059cdda4000372c42f353d898d9f8104516a65b08c157bfff0ba3ac5207376943e089b4e6ddc0a360c4d72baa87e80c6240a3a549e5d",
	        3305
	);
}
static void snarf_hat_3307(void) 
{
	snarf_construct_hat("/usr/share/flatpak/triggers/desktop-database.trigger",
	        "77278d52f0f79290aba597018d8002368030a96522c4f8830ec0b277c3bfa8bca48e3b8a2728afe071719920f14b9f300c43c279aee51729040a98d77f3db92d",
	        3306
	);
}
static void snarf_hat_3308(void) 
{
	snarf_construct_hat("/usr/share/flatpak/triggers/gtk-icon-cache.trigger",
	        "d99e43d401398a8ee9c0ab4d7fbdf1580ea48eb5446b58270dc8795b0f1211d6e6cb3528f4c0e53cfc7dfd4e54f78fe9bd80d1cbf7b63f52503cd2d6610ba011",
	        3307
	);
}
static void snarf_hat_3309(void) 
{
	snarf_construct_hat("/usr/share/flatpak/triggers/mime-database.trigger",
	        "b2028ffa984e29b0d9e1a28c735a066b7dca16c7e31942f475217fffa0942ccbf22e57c09185ab43aa77f053cfbb773ffb0a8ea598ea9e5ef5f3b04d45ff256f",
	        3308
	);
}
static void snarf_hat_3310(void) 
{
	snarf_construct_hat("/usr/share/fwupd/add_capsule_header.py",
	        "c701e98fabe1c8d4e4d7ef3f48d3c16e2d0f602f1b90d3ee1cfd48972fe539bbfc0972c53620da9e0444dc9c2b41facf330e315f249401a464c8c357bed3b587",
	        3309
	);
}
static void snarf_hat_3311(void) 
{
	snarf_construct_hat("/usr/share/fwupd/firmware_packager.py",
	        "d7de9735e25f0e6939d0216704604ea366b5aac7911be233c010a47f027bd16f3a8b4b3440414771475434bd977cddeba72e9eea0baf7b2d02fef8d0ee67d2f0",
	        3310
	);
}
static void snarf_hat_3312(void) 
{
	snarf_construct_hat("/usr/share/fwupd/install_dell_bios_exe.py",
	        "2c795a4ba6ac63ff7b76724e2022063bb13456dd7fba2a00e46bc299394e85df5e93964b51891af7f4d97c18b73769118863afa6716cd74246bc17bd2968ad8c",
	        3311
	);
}
static void snarf_hat_3313(void) 
{
	snarf_construct_hat("/usr/share/fwupd/simple_client.py",
	        "ed0bb479210dd5b320269736018d36644a4ef5d2a857317120c47cdee433b358147ed9d1c69b862669cd8fc012943e06bf15e4440e69bd38669159d47ae6b453",
	        3312
	);
}
static void snarf_hat_3314(void) 
{
	snarf_construct_hat("/usr/share/git-core/contrib/hooks/post-receive-email",
	        "eb0df706d469e3c5c51d47c5d7f551b538a5c0de0369fa3fbcfb1095a9ff83dd11506f2ac50c067428bac389e8168ef826780ff3a1c2921ee1a35ce265971e4e",
	        3313
	);
}
static void snarf_hat_3315(void) 
{
	snarf_construct_hat("/usr/share/git-core/contrib/hooks/pre-auto-gc-battery",
	        "db23eaddc8c6044637e37e85027141ff2147de8e2150ab1c1e3a348a32b68d7c099b0e2f7f09cc43f2f115efc6e43c35ecd63fe8cc53ed9b2b30417ea16445eb",
	        3314
	);
}
static void snarf_hat_3316(void) 
{
	snarf_construct_hat("/usr/share/git-core/contrib/hooks/setgitperms.perl",
	        "08a126425ab03aa0f4ca798bc15979e9d6f524767b88c1f222ebf426c7980afddfcdb3e3b4af8a9abd77060372651271f21518b2f1bf370978db79d0e830d87d",
	        3315
	);
}
static void snarf_hat_3317(void) 
{
	snarf_construct_hat("/usr/share/git-core/contrib/hooks/update-paranoid",
	        "9711e79325af5082ece082f0e72e480a27134ab5ba60b22e8933bc1c98ab86722c0245fd7b2f02193ac84391707d9911cc1be258e7314c1df3f54bd77fbcb45d",
	        3316
	);
}
static void snarf_hat_3318(void) 
{
	snarf_construct_hat("/usr/share/git-core/contrib/diff-highlight",
	        "c4280e4baa5b5a9640e8aea331004178d391fc69f3b8d7de58ae78355396e6ec8d55d652a8ca317278c5244f0895d8909808c9432ed8b51a4030f25c94e16401",
	        3317
	);
}
static void snarf_hat_3319(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/applypatch-msg.sample",
	        "797f231a8cff05c8e45e1bc6d86737d314459249c40e80d85da4c988a3b80ac0f42a01fc2b24f7b25a3da052a2433075c96be578aba5297e3030ea51402e1764",
	        3318
	);
}
static void snarf_hat_3320(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/commit-msg.sample",
	        "7f6ef596a39a46acebecab41ff14f775b1774cfa45abfa35644a47d7e0dd399a41b7185a818782f8a887a89a42d2bed4db228a887d825b3b845c5ea4b0e17e91",
	        3319
	);
}
static void snarf_hat_3321(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/post-update.sample",
	        "4ad767f7be6eb2aeb43c9985da0b37972989e4731b192911efc2e50b086a00a5b9cb241ebd612c49d61e76b40d5bd6137753f7331da394c78046cc1f478ec8c3",
	        3320
	);
}
static void snarf_hat_3322(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-applypatch.sample",
	        "678e8161bbbbd0f5557d915b455e280a227d2eb4018b47a0679df3d7f1d278b7700b05b23ef26f9b931e0aa54bc9cad295e3b27f176cdb4309f5703a64dceb65",
	        3321
	);
}
static void snarf_hat_3323(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-commit.sample",
	        "a96cea731722fe24a31215cfbb282ce35947071d4ec4e3ad7fd1e23961dd9a8f61cc092bf2739968a7cf9c91d5fd977f29b873651fd501b39db227bf839c1677",
	        3322
	);
}
static void snarf_hat_3324(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-merge-commit.sample",
	        "4b83edbf58ad52735cd1a0cb2959df92d974e62e2a608b02751bfaf9dc31eb2c30512e9024e2de5c538b930bf873ab65ba9c59164f5bb657d8ae2dfb9c764ddc",
	        3323
	);
}
static void snarf_hat_3325(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-push.sample",
	        "9af4308f207582d1183a8fdadd4c5ef57fea7fcd8f7084cae8610392df484855fee6184898022019bc7ac252100649f99c295a18bc5c379b81325da45fa4b882",
	        3324
	);
}
static void snarf_hat_3326(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-receive.sample",
	        "3afcda68d7b78faf51d0e11defb728821f1627c48b2a94d9eb4da126272e4da378e149ff3583606cd97844395578911bc1ff18dcf99930209043ecac35bfd822",
	        3325
	);
}
static void snarf_hat_3327(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/push-to-checkout.sample",
	        "83cc33816f951e0d3f33fc46be8e08ec28e7c452b42c04dad335a2891d9a1e3acb10f011617f88d3e6cdba153a50a286d19f60e244c5491fbdfe04d37c53ef8b",
	        3326
	);
}
static void snarf_hat_3328(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/update.sample",
	        "8ca9e460f6f10d9a70bc6889c1a82928c3ff7a2a5763407249bfd7384f02c2f0baa8a231625e1c777cfe783ae5e4272406bd568afa36de4570246bbfff019605",
	        3327
	);
}
static void snarf_hat_3329(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/fsmonitor-watchman.sample",
	        "f5a4d2bff93161eb61b9902ff74d5ee20de3316f2b1c5ad49299deaf1adf231848c5501b6e4a840e5b898791f86c66eed6f3b05ff573073674177a33a1f2ae9c",
	        3328
	);
}
static void snarf_hat_3330(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/pre-rebase.sample",
	        "6a909a865b091603d77822f89461f7817e1e48cb6960fba44e33e223882da8fd650b4d9910d0934d5890ff7a866070a2955ebe648575ceeba2d18b4348ab2c93",
	        3329
	);
}
static void snarf_hat_3331(void) 
{
	snarf_construct_hat("/usr/share/git-core/templates/hooks/prepare-commit-msg.sample",
	        "43e3c7ae31aca318c411beeba28799aff1d4fc6f06fd5c590260c01e2a75e212af5c58169d4dbc18ec15764923a826a924425ad84e4a4d84b8cbdd8d75008c40",
	        3330
	);
}
static void snarf_hat_3332(void) 
{
	snarf_construct_hat("/usr/share/glusterfs/scripts/post-upgrade-script-for-quota.sh",
	        "5d34942061cbfceb5929d314189a3a22b3a89a3c3fd0aa0cc43bf1c630ee0a1aea860ed2c61501135e1dab43841490b8703a2674394b023892b55bbc7b5759f4",
	        3331
	);
}
static void snarf_hat_3333(void) 
{
	snarf_construct_hat("/usr/share/glusterfs/scripts/pre-upgrade-script-for-quota.sh",
	        "a33a30d0d517b4c937943d865f62ab77c76d5e3a11fd5a4d0b5811ccd59129a9a347a48cd05054c85bc8a7b88f6114a690043664299e8691213025c3ae82d70e",
	        3332
	);
}
static void snarf_hat_3334(void) 
{
	snarf_construct_hat("/usr/share/gnome-maps/org.gnome.Maps",
	        "df86ada0cca276029260ce8a2c2b4ed4d9d0cabcdcd7bad7ae7ece640c897a04940b30f3b2f44db4014d69e654f6beb7c3f11deff763fc45c1791bf16498b471",
	        3333
	);
}
static void snarf_hat_3335(void) 
{
	snarf_construct_hat("/usr/share/gnome/shutdown/libcanberra-logout-sound.sh",
	        "eb24bc981e7a192dd30144a3314b8bc553ed56bd4d48a1500f40cd1d767cf0a22f567047816ef6d0ce05268ff6dfd219ebc637944e24883ea8e96b6a0b54330e",
	        3334
	);
}
static void snarf_hat_3336(void) 
{
	snarf_construct_hat("/usr/share/hplip/__init__.py",
	        "83865c9ce5356194fcea0efd35561886227e82c58d5bee87cf84d4a2e484ff7d969061ab2f5d1ce39ba6a4a2f473e3ca5113581a4235c50f6079bf95835591c2",
	        3335
	);
}
static void snarf_hat_3337(void) 
{
	snarf_construct_hat("/usr/share/hplip/align.py",
	        "42c9f62f0706bed75529cda5a942a9ff659aea738561c04ab406d37bbecaca62a697d05559dfa4226e7fe81d2ac81c56b2042e11c45b57527ce378bae8c74df0",
	        3336
	);
}
static void snarf_hat_3338(void) 
{
	snarf_construct_hat("/usr/share/hplip/clean.py",
	        "906902c978cc9c5c7f6d5dfc423d50e17dbe99bb08f33d4c66958574bab6fb541ff5f0bc1ba9b83f3fd77fbea42aebf2504989a40378d5d1a9b5b3cf1e85bfb8",
	        3337
	);
}
static void snarf_hat_3339(void) 
{
	snarf_construct_hat("/usr/share/hplip/colorcal.py",
	        "da1a29e59ee41e5ffe34df570f97e6e27373448bf846a4d2b2e80b3710161ce4f364772485bb21ae650d5428992a3ee7a561504a2c40a62e409d89a3511927e2",
	        3338
	);
}
static void snarf_hat_3340(void) 
{
	snarf_construct_hat("/usr/share/hplip/config_usb_printer.py",
	        "91465a1d5a0827922ee103a0131788eb02fb33fedd4fe4d09d635a36bf85c10f3d7e69cd351bc5467b9ded628d281fe3ee9e7d054a2c2a5dbbf53fc28f1c2a07",
	        3339
	);
}
static void snarf_hat_3341(void) 
{
	snarf_construct_hat("/usr/share/hplip/diagnose_queues.py",
	        "465bf6688de1e6027600071e47cd54a963d32e305db925560c7ecf0cda8c993937b31fae3d681b6e86fcc982cb5fa1d6b2e166c20aef550867c1812cf9b27464",
	        3340
	);
}
static void snarf_hat_3342(void) 
{
	snarf_construct_hat("/usr/share/hplip/fab.py",
	        "b9d82b22cfbcf640270e4e0ff393a4a273805ba2bf8645094fdff31c8c336737a3f00e8c6facb54e18410b9a683c846c59df0def4383713bca6cddfa675540b6",
	        3341
	);
}
static void snarf_hat_3343(void) 
{
	snarf_construct_hat("/usr/share/hplip/firmware.py",
	        "345d3e92efc184835311786075e22a6c4d666381cad7f06fdb80e122dca5a7c58a3d4589bfc8050ef783fdaf01fef19c44e90b5f882767ba64e1611ed718791a",
	        3342
	);
}
static void snarf_hat_3344(void) 
{
	snarf_construct_hat("/usr/share/hplip/hpdio.py",
	        "a99d8c1cff66a1e17819cd53ae1513afac1394332059ead8eb9ce836207d7833513cde6780f1b1a76cbd44beb2de5f36bdab0733a95377f943bb43c8d1603213",
	        3343
	);
}
static void snarf_hat_3345(void) 
{
	snarf_construct_hat("/usr/share/hplip/hpssd.py",
	        "906f05fe03bc41a2c3ce2c700e292a53de4832d9f47dff32092ced54f1b3b6fa1fe29c39249f466663d0a5c94ee7d44fcc861934194cb754fa40250a7776625f",
	        3344
	);
}
static void snarf_hat_3346(void) 
{
	snarf_construct_hat("/usr/share/hplip/info.py",
	        "bd6da47ef7a9f0120cd0f7f72f34bd63dde9d2e3fd8ff6b05979c019a7f6b0f01d86b5f610bc6961094a1d1a127e2260546d7e09d6f04971cb8078a3e892f695",
	        3345
	);
}
static void snarf_hat_3347(void) 
{
	snarf_construct_hat("/usr/share/hplip/levels.py",
	        "b658876994cb55753e6a3e44f3e05b888ca683da172f196f49cdfe7f3258772bb3670db9b02669d572cf13f33ae8c62052f27ba156c8e7ce8d982d1ac69b2f38",
	        3346
	);
}
static void snarf_hat_3348(void) 
{
	snarf_construct_hat("/usr/share/hplip/makeuri.py",
	        "f2dbbc88f91a127de0af8281bab9796078fabb411d21a11af6f15fca4d15bc52bc9dc6c033f830c7e40e96dcc3603f79d4968380b368e0cff079a08275402ea3",
	        3347
	);
}
static void snarf_hat_3349(void) 
{
	snarf_construct_hat("/usr/share/hplip/plugin.py",
	        "7c485c917cb3268b19129dc898c1d9c3831ea945ac674dfd8ca1b28e1b4fce506f07c7766a7f0773da26c810fb0ad3a0c1d915a10528e8c8d7cbb9790503d316",
	        3348
	);
}
static void snarf_hat_3350(void) 
{
	snarf_construct_hat("/usr/share/hplip/probe.py",
	        "3f861c6e692153e967f6f6de254fad0f822a547683755e34c55dbaaf9548d7118a4bb0899673fd9c13f1b8dbcd3aeef607f91b2c132bdb47ded6129806048bcd",
	        3349
	);
}
static void snarf_hat_3351(void) 
{
	snarf_construct_hat("/usr/share/hplip/query.py",
	        "b8e12b02c1ff93ebe04aedf2096f23366c3f792cf6f4a32c2966a3593989c30ce8efd456e60d0a4ec9ed189ec8552d5317225a80eb81b849363fd7fb36c1f529",
	        3350
	);
}
static void snarf_hat_3352(void) 
{
	snarf_construct_hat("/usr/share/hplip/scan.py",
	        "175ab712d9219689be10bcbbcf47b2376d2964354ce0c890305406d75198916113d474a5fb0797cfa3a4dd784ce0fbf6978b09d2e6b75588d34964d9d7a603cb",
	        3351
	);
}
static void snarf_hat_3353(void) 
{
	snarf_construct_hat("/usr/share/hplip/sendfax.py",
	        "cb97e6ef86ce1e02a14c5c7548733439971c9abd61b6a84040d5840ddf05b849a6748b46d2b61ea4afa4c5d7ca5ee0b9c1f1521b33601201f7a8d78247fd6cc0",
	        3352
	);
}
static void snarf_hat_3354(void) 
{
	snarf_construct_hat("/usr/share/hplip/setup.py",
	        "7480047adf9c5fd893ceacd50b5e689a23b080c0c2fde230666eb0e959c2c50bb8770a36939224d16881d7ab13e6b50af88f2f3f3b41824c7c7f8a27b32ff46d",
	        3353
	);
}
static void snarf_hat_3355(void) 
{
	snarf_construct_hat("/usr/share/hplip/testpage.py",
	        "6fa665eab1dfcee3efb90f8cd438e1a0d6c2a5af27af329a8fb222053940083d8fafebf4943638482e91afdb5d3f35ee7071abdd34c0fc9c1d99c8f4e2acbfe2",
	        3354
	);
}
static void snarf_hat_3356(void) 
{
	snarf_construct_hat("/usr/share/hplip/timedate.py",
	        "29a53c1f36c8b0019c9f49e1ab1826d3d17641176e151b8770cc192d18331d3781b1d28929c40141d609b0bd1c8de53311540eb7fee84e524794462265a2d715",
	        3355
	);
}
static void snarf_hat_3357(void) 
{
	snarf_construct_hat("/usr/share/hplip/unload.py",
	        "3ffe0208be67850507d175268432006584e7d3a956dca28302fa5ac1da68de77ed8f71a3ba39a5586928ee5d331e91d23a01fdc5a64f0786c100d94b52e740bb",
	        3356
	);
}
static void snarf_hat_3358(void) 
{
	snarf_construct_hat("/usr/share/keyutils/request-key-debug.sh",
	        "3001f091a03573d5611886fd8d6fa652114d1dccfd226ffa6247b1c9505201fbfa1883b24f6514a8238f0cde9fb6e9c694b20931a07004b8633475b5bf7dee80",
	        3357
	);
}
static void snarf_hat_3359(void) 
{
	snarf_construct_hat("/usr/share/m17n/scripts/tbl2mim.awk",
	        "d2bb4dc78b51850d377ea3424f9682c5a3b16ae4684a14e783f7d156b62bceb308898c579995d06e338fc74199c93e16efea3617e8ecf09eb176c779e4a2c3e2",
	        3358
	);
}
static void snarf_hat_3360(void) 
{
	snarf_construct_hat("/usr/share/org.gnome.Characters/org.gnome.Characters",
	        "ff83317338653d15fec72f388a18d7ded2d3bb6bfb8ff6feed69d79ef39c537044ef5f7307a658a8d935453a30e6cf50594335f8289bf912f6f035a3744e5adc",
	        3359
	);
}
static void snarf_hat_3361(void) 
{
	snarf_construct_hat("/usr/share/org.gnome.Characters/org.gnome.Characters.BackgroundService",
	        "1722d7d70ba54455ff3789641f0ab7b5e062769bd68792f3b2c9bab6169d687d5a8f2e16e466dc411af7a4ac4678007f5e2ccc37196253628e2d5158c5f78949",
	        3360
	);
}
static void snarf_hat_3362(void) 
{
	snarf_construct_hat("/usr/share/org.gnome.Weather/org.gnome.Weather",
	        "1aae3680a2e59ca19c33723405d8298fd2b1606bbd9d3216984c124df6aedaac6af2c6b028ca5d422792a3558bb40f867b1b6c914b9f3c812dc80f19819fe41d",
	        3361
	);
}
static void snarf_hat_3363(void) 
{
	snarf_construct_hat("/usr/share/org.gnome.Weather/org.gnome.Weather.BackgroundService",
	        "bb6ae62d7a524656a81b0131aa4ee11b5acd7ce004913b634fa3c3660865cfbb0148cf356032ce5f723185e8e11e72aa3b2563122b06e54eaa5a2f4a7b6bf2ea",
	        3362
	);
}
static void snarf_hat_3364(void) 
{
	snarf_construct_hat("/usr/share/python-wheels/setuptools-57.4.0-py3-none-any.whl",
	        "7e47c5933730079101141d67b8edc0f4bcff5b70a8eee41b9fa333637cc1bb80e40f2654e6081a5f05caa3652fae4e6bdd89f02a03835a61b970a43fcdb613d9",
	        3363
	);
}
static void snarf_hat_3365(void) 
{
	snarf_construct_hat("/usr/share/python-wheels/pip-21.2.3-py3-none-any.whl",
	        "ef71c4e2e08385b18548b2e4875aa0c1a6af21e478deabb3888a99f850835e50f19cd8d7824e1baa9875305021315998a5eb61bee82d8135d6129b7175516967",
	        3364
	);
}
static void snarf_hat_3366(void) 
{
	snarf_construct_hat("/usr/share/swtpm/swtpm-create-user-config-files",
	        "9206fd2a59fd628a425acabfa5bac7ecfadae70d00240f66f0ed781c957e0ebee58ca0806bc74d63a423575d851f27b4f5f68731318ad4465e5e60c4a6ef9860",
	        3365
	);
}
static void snarf_hat_3367(void) 
{
	snarf_construct_hat("/usr/share/swtpm/swtpm-localca",
	        "b141187c8a81fc67c697e66e76d63818a01f7afdd91ae327dfec2100143eb4f93cd682e3be5b2a2fc0c31c2a1b49d29b976c80bc68a9afbc789a8b205e0dba60",
	        3366
	);
}
static void snarf_hat_3368(void) 
{
	snarf_construct_hat("/usr/share/system-config-printer/pysmb.py",
	        "390c0e8d44181c845e90faa96e967d89c3d9271ad79cc7736577aa713954b8375e12a9c70da3ecf88fd8808719bbdf837b5124bcd0059735045af85a1dd6e978",
	        3367
	);
}
static void snarf_hat_3369(void) 
{
	snarf_construct_hat("/usr/share/system-config-printer/scp-dbus-service.py",
	        "daf0084497e2f9a5b97a6547736565612c0403ba3262a7f25465a22960ecc0497753e674997ff923c5edbebb28724d2504ad17affaec36d9234b9896dcfdeca9",
	        3368
	);
}
static void snarf_hat_3370(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/apps/gmalloc_watch.stp",
	        "72cdfc9e8a87f9deb97c30a6db20578f7c28a76300b7133d13937f9557e5fd3cfd6ecb3dfe2b0d028d842ea76fa5d9f724c9b231bad9b8c0f7e4842da3e8977e",
	        3369
	);
}
static void snarf_hat_3371(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/apps/libguestfs_log.stp",
	        "1d88654849e0c2add83ff021b9ede95283921bfae59d4fb4b98cf6a64ca12bbe4c00e36a4e002e489aa1d8a056b5d94e254c19768c47bda544040ae9b4d6d265",
	        3370
	);
}
static void snarf_hat_3372(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/apps/php-trace.stp",
	        "cf56cbe9baa1be277ea78e06c6eaa7b1dd6fe534612c49b9af09d2c012531ba54d1f1620ce876928083493c11f673732f6ce416cda2b0e7816a72349df6560a7",
	        3371
	);
}
static void snarf_hat_3373(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/apps/stap_time.stp",
	        "870edd3eb8477e3b8f6be229d14de468e0ed935ff35b488da1e5930488169a8a0c43b483731ecba188df15d7ab585ea70f99cec184bb4632202c0ae26fea95b7",
	        3372
	);
}
static void snarf_hat_3374(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/alias_suffixes.stp",
	        "b48394ac49347b5565df86fc86aa0c357a2ec54d9a1b396b573346f6d2fa32c33903a5693f306e15d90a1883b4c2ceece95d52b2d054b11a770811adff723e2d",
	        3373
	);
}
static void snarf_hat_3375(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/also_ran.stp",
	        "ba5f59679c2964f369094c79a376f0a81b4585a4a3c1d0ee3b91c203e62cd0626b4496470a7eafcc81b73f70e261022707b0f3cfb4f00ccc39f1a55ed6137922",
	        3374
	);
}
static void snarf_hat_3376(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/ansi_colors.stp",
	        "5a9b1cd1a9233028e790384bce8b1c725ed0611c9a721f4d0bc72f50187c7f72905448640ecb8f8d51d0521b04e678131bc0d5549391cfdecc3f179312665c80",
	        3375
	);
}
static void snarf_hat_3377(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/ansi_colors2.stp",
	        "de6dc7b14dfc83b0ba1891263526b0601434da985834cc59ecf09898fc09ccc1331a3a6c90e3ad957037b5974d52da928b4531e6034cb85b7e6b00b44fb99dd6",
	        3376
	);
}
static void snarf_hat_3378(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/badname.stp",
	        "708fca140270c1a21364fae7b3a250803463094194bc3dcf63f94aa13879b90440c34f6eb12e98b028b1c7a8bd4ea35bc08aa14355155537008504ae57a39d6d",
	        3377
	);
}
static void snarf_hat_3379(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/callgraph.stp",
	        "6fd5caae13e56d3dd0f6e9f6c66bd5cfb12c7de1ef5a2c6ab5d88f74566770e47af41d449f2cefeb23d2068d6f37a4701b7304f43575dc2fce9ecdd66b723883",
	        3378
	);
}
static void snarf_hat_3380(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/cpu_throttle.stp",
	        "6cee954ceaeb032862fc91d6aaefe7142cf86b3ede44c08fb88119f9a02afeafdc81e3b09222bf09e9aa40bf92b1e702b10927d698fada54fe312e17befc1428",
	        3379
	);
}
static void snarf_hat_3381(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/eventcount.stp",
	        "cd0719de09edd8f6e608179ed7d0dd8543970c76f478999d48d15ebf62c6cd900d9183fe319043db15b997c1d6901b07acaebd4d4de09d4cd6bd949d022042df",
	        3380
	);
}
static void snarf_hat_3382(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/func_time_stats.stp",
	        "87c76235eb9e290801010800a729a7be639dff66dfd2cbe5dea8372c38c656a9b472c95212f66a2b198604f2ddef3ca7d1f4747d0ece9e825c4de44538e565b3",
	        3381
	);
}
static void snarf_hat_3383(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/grapher.stp",
	        "ba6b25da4ed297eb2386551b7a64395e82283212e29dbaac6b7fdd281f1775204470d71793b38c40f4994c203d2dbfb6fb3876c009ad5c49fa500cde038f7914",
	        3382
	);
}
static void snarf_hat_3384(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/graphs.stp",
	        "9e4943b5e6cfc8a3649d07304a7ca15a63d4990d86d575174013f470a129530d1f4feff9d2b15506ec9e55a7745f7a296b08a97a90f4337eab42ac047d7e92ca",
	        3383
	);
}
static void snarf_hat_3385(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/helloworld.stp",
	        "4c37b40d812940cf6569f666e74d6dda771f2181be00f28b7c84718b1cd647a2fa60a1912cfcfd3c49b8740c203d4540d953bd4c151beab165f8528c3d15ac13",
	        3384
	);
}
static void snarf_hat_3386(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/key.stp",
	        "10ed12894bb1d22dc8cd726dda897c5581c6afec0a2e3e0bb03f1e3da0c161ad55f7f0a2c6a501e2528f74c8672ead2fc8dccdd5aca093d75b693d4394ecbbe1",
	        3385
	);
}
static void snarf_hat_3387(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/keyhack.stp",
	        "4669962a664fb4053238a32d01d3741e6d90adbd176b4d663236d249b21464cd9c54ceb40cd8f0c75f4a3b0d27e1993f843d9b207d9ab2f12424d5a33841da84",
	        3386
	);
}
static void snarf_hat_3388(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/measureinterval.stp",
	        "dd12294bb14bec250cd7b170d7832a80e7c9b2014152244bbfd454f5a9699bba8010d80b1aba63451f3edffa6fd306a55c45d19094950d3645abb0068a20e980",
	        3387
	);
}
static void snarf_hat_3389(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/para-callgraph-verbose.stp",
	        "de45a6a8467faefea9e27fec639a3c0c8fc0ba86ea2aa214a289bc1c216b1615b30fefe011dac18e49340d884ef245e4d7771b9189b467ec21a3cfc6e78eb916",
	        3388
	);
}
static void snarf_hat_3390(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/para-callgraph.stp",
	        "846b5cbf99d6a18257ee5d130cb24c5ad10d3b12899643e1b92a94d723448f066c8b5c38422d17dbb23daa1e72692b8951ddce6b5c61ead52792f4c320bba078",
	        3389
	);
}
static void snarf_hat_3391(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/regex.stp",
	        "24822d7aa79ee9706cef925b9f186c370ff10da2597d966e0af7bd14b34433505958707eea09befc38c93532715b4808f51cf1166e23d2637b0bac3acbbc91e4",
	        3390
	);
}
static void snarf_hat_3392(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/sizeof.stp",
	        "67feb9b6757a6e2ffed702d45516c39c095eece049b3f1f89cf8c48ad1b1b03fb0a13b379453848b74c01038a0d66d0aac19c73b54a8546bf2dd8b08a355684f",
	        3391
	);
}
static void snarf_hat_3393(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/socket-events.stp",
	        "a696b853ad0d780fe0f3c3bf776049122fe66d8e70e79d28f8f53020a905e8fa65fdbe6f269ccf4be8c9603e14429f476e8b4fe5bb2cba86b4f01c8467ca8b7c",
	        3392
	);
}
static void snarf_hat_3394(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/stopwatches.stp",
	        "3c3252fb42c1963f7a943a99ca123e5ebc8cb76f333e5454b38e0ba8fe25ba203382bf5acd4fd7635782631832f7b2ead039131e279d3baad83fca12407710e7",
	        3393
	);
}
static void snarf_hat_3395(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/tcl-funtop.stp",
	        "0ce68c98b18df91d19046175c437c2ebad55d2597e584b3fc39c1c8cd449c107f21023ff2d37ec2be91f41aec98d9869bf64e7cb0955b64a8215594671c8fc79",
	        3394
	);
}
static void snarf_hat_3396(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/tcl-trace.stp",
	        "fd039642d1968cc136f096761c7b957eb8914ad74aee8840a10172e7369c6e877c11ee9256dda5435ffc4c2a4fe52fe5b77979b401c7c8a0ecd0a3ebf72462d9",
	        3395
	);
}
static void snarf_hat_3397(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/general/watchdog.stp",
	        "a5065ef8fbcf82721bd10fc8efb12c3df61386a4fb323af30a88ae8b02335efc6d21fe9046ec363f548fe456a163d00f258ced2c6f818e33430c7fd8aa4cf4bc",
	        3396
	);
}
static void snarf_hat_3398(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/interrupt/interrupts-by-dev.stp",
	        "cef6d6a68765d151254bcf938900ebbbc316bfcddeff721b6594aa01d389c5b4f229f4201f220c6e872c60f0a7f031d7b5f814c605969a28ea64046e556a4068",
	        3397
	);
}
static void snarf_hat_3399(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/interrupt/scf.stp",
	        "8e395bedfeaf206d0f84c54da12db904fa5556465b1f99976c5a4e325e5f69bbba59d1bc915f9abd3e93c823be44976580845c71a19b5ff8ddfc5082fbb1088c",
	        3398
	);
}
static void snarf_hat_3400(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/capture_ssl_master_secrets.stp",
	        "a7ab1c57cf0983322ba6f5f31422d64b3c52c402910b557c9a04f834c7185c5636a7572bd42a971c0aef887ab048733abb36a26f45b5353eb2c9efc20ce620d6",
	        3399
	);
}
static void snarf_hat_3401(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/deviceseeks.stp",
	        "cdf9794f7cfb740e52bd9d7d061bc8351d0bffef919d44346e33c0959a1ee12435546a556711c54ae0327fe35e2eec6d3e7939694e1e4070b4d62028909d5ac5",
	        3400
	);
}
static void snarf_hat_3402(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/disktop.stp",
	        "926a0df6f5a3f428b6f1ab1f0f0c3056d3b3e146710d58d57fcf75b3292a74e1ea16d4957e7113c39a1cb2ceb2813e68cfd984e0590ff852796a1b1fbdd24a7e",
	        3401
	);
}
static void snarf_hat_3403(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/eatmydata.stp",
	        "c0bbc05864b3addc737d4a68e09a4c8f9973a5cef5bf4acf6cb57fcb56b3401f5ceb6c52e3d85a2b2708b4a265ef7f330ce266a8a8e3e54df557e91673eda950",
	        3402
	);
}
static void snarf_hat_3404(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/enospc.stp",
	        "7f4ce54898291a1ef124b0bc532b8c4f1148675918ed924b529a280d4b150e34610d5f256c4e8dddc184133864f21c9780844bcfe04edc029c23b8f5042040e9",
	        3403
	);
}
static void snarf_hat_3405(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/inodewatch.stp",
	        "ef37f6c764edcd19672eb97f781ad7ecf05f31e93072bc7dff0da89e1c2d036525212d7df7a08847d5ccec0d7272b8af90b0453006fca482e58da26fa1587919",
	        3404
	);
}
static void snarf_hat_3406(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/inodewatch2.stp",
	        "03bfc68bf17c9ff9ea015fc465efa5e64c300aa007e7b4c410fb3307b460739cca7c30c9f2d9da0471a17ac559acfa21c8633775a26e88da33b8e1f887e6b3f4",
	        3405
	);
}
static void snarf_hat_3407(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/io_submit.stp",
	        "eedd310a0ae20e9151300a7572742a97e69c7865cbca48a5a9048dba68a300f349507879420559caa43b71a1bb97927cc06496792213ffc039b09a3bef66d5a5",
	        3406
	);
}
static void snarf_hat_3408(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/ioblktime.stp",
	        "981e114e47587387cdf480d79382e9dec95b00d3af149adce0e0615b49db10b9135d8730ca574b469f35863e2c883ba3e43b821a5c175b26daea3f0b9d5e07cf",
	        3407
	);
}
static void snarf_hat_3409(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/iodevstats.stp",
	        "ac1f36ad13cd55f11bac947fd40f5e1d8ce5c32a9b19e47a0ce93072757fef8442baa7845a0ebf965c1138573d5e9f228b04b9f822964ca47c698801834b0030",
	        3408
	);
}
static void snarf_hat_3410(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/iostat-scsi.stp",
	        "64cbf90a4d7d7acc41ddb734e67da7921ea606e510f3e64b9f2266540a2d0ae3444d1a20a038387f18b768cf7a51d4953c5c091d76a94ecfe115451c4bbddc5b",
	        3409
	);
}
static void snarf_hat_3411(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/iostats.stp",
	        "59f944f7c0910cf7d03f836e47d01fe4e07aa85fbaf6dcbac09c5062849b9bebc4bfb6ad99a31928f7a455fea0c66688e39e415c4e2fdfce94cdbb0357bf3e38",
	        3410
	);
}
static void snarf_hat_3412(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/iotime.stp",
	        "16f0c164a54662b1032e54a0baff010a69b5f6bb278fffafd17e349510f2a283fd394a9e380cdd9aa2f8b3cb39ea4cb1379a543a8f8687b126f43bec6684b7ad",
	        3411
	);
}
static void snarf_hat_3413(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/iotop.stp",
	        "d4a3f029144b72fc8f521fc52a516e8922c60a2d9811c532c813c74be6dc77931738f69ea05be8c6a71ecc1328a0377a226d24e25ee11ae2bda00ea855fce0d0",
	        3412
	);
}
static void snarf_hat_3414(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/mbrwatch.stp",
	        "ee5c61b5e82887852a5fffb06abe9215643a63aa2597d281589638de569c80112f3a2f30e7b39a5dcda3f43b285f86ab9a81d8025a2682257a27e4df9a4a4d25",
	        3413
	);
}
static void snarf_hat_3415(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/nfs_func_users.stp",
	        "e30fe5013c76f31a85cf669b4cd85539876059a8c77246c5036ae2f29941e05053fee6a273d5d5a86538ad93ae3b78aecf1c0e0269021b4ec5742f1aa9e91624",
	        3414
	);
}
static void snarf_hat_3416(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/slowvfs.stp",
	        "6d185388dfc86d8cbc749955ebd71b71fcf897e54d255e9729e9e23dd403b684a691a64e66bc79a5080c42a7523caff12af4094372a59c235f3f50a98fd823a1",
	        3415
	);
}
static void snarf_hat_3417(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/traceio.stp",
	        "035737e8e21a39c7e9c043be52f5ffde0e8c45828b920b2df534ac61436dd0668ad94fcc9e4d2b39ef4d81f68cefae335bf42aab90038e796762c78c0e4866c0",
	        3416
	);
}
static void snarf_hat_3418(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/traceio2.stp",
	        "dab8a1bf3301815cd189dc84fff743bc0add06b431e09dff969c75f4c6d8a0c1f28d980aa9868aaf932785efa7adcc092eaf48c8c814a5adac31e5c8c32bcb25",
	        3417
	);
}
static void snarf_hat_3419(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/io/ttyspy.stp",
	        "0efa0794c51b8bc865a3baaa01e3e833a0560c06afc676cfa5cb22ccb684d32d3d4dd0f32bdd2d4b81157216da0a6709b9b1870f37256c9d182345fe4225204a",
	        3418
	);
}
static void snarf_hat_3420(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/locks/bkl.stp",
	        "c77455449eb53a24568e69b4c0ef5550696235290c1246d52f5139f64730cadeda0abc9a396d1188a4b0676a37662fe9d4d86a440210e3d14cf0685e902f295c",
	        3419
	);
}
static void snarf_hat_3421(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/locks/bkl_stats.stp",
	        "1bc175119ed1713b816433d80d267b171ae7db0e38e3ebbd8cce1a45aa0f47cb030f5e5c153b387c91abe904ffab58573e5041c5813b31357d254dc00fd3521f",
	        3420
	);
}
static void snarf_hat_3422(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/accept2close-nd.stp",
	        "101ab7e1866ec147147a3cc54f3b13d71d9a8fe240926b9d370820e231c40b72af778eaa32022078aea53a5e4b6a3f79415346be36ceab9261894fbe2494dc1f",
	        3421
	);
}
static void snarf_hat_3423(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/biolatency-nd.stp",
	        "3ab9b207fe822d0f13e33d2d56ec378f7fdf08a7712d787d0ed7b1d6f7709fa13a9abf7ae97e03d837be99ef51af8696d31d1f4ca2f104ba1ae9da20983e53a2",
	        3422
	);
}
static void snarf_hat_3424(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/bitesize-nd.stp",
	        "0b6937fc1b5f89a2d83a8c3d0f2b49c84b4a6abb1517526556eb6167670030067961d3cc4a80a0d56a397017d5ff67149c35f2a0a8d579e5f84fa3379e0b63f9",
	        3423
	);
}
static void snarf_hat_3425(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/execsnoop-nd.stp",
	        "cf18b072b129439e00b16060f10fbb0057df1da65803cbc1de01aab45c121b30fc9ac327f882fe714899bb6463b15228848f762f42c477392928fbe6173df1cc",
	        3424
	);
}
static void snarf_hat_3426(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/fslatency-nd.stp",
	        "946acd330f653a140531eed4f23a8b5256bd129920f99b601267f7fd27c8c36d0950da5c310e45c5f13bb748c7baf0f518048d07ff392a39a9cf43f3d94c7685",
	        3425
	);
}
static void snarf_hat_3427(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/fsslower-nd.stp",
	        "663cfb44fbae6fb4da15a5c75e4b84f981e065328fff4f12e88b64dd45ed195dbf6aa13b1da5aa1feae402140795a8ef1e02aa28249d1b461463fd74f6601eb2",
	        3426
	);
}
static void snarf_hat_3428(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/killsnoop-nd.stp",
	        "22a822603fe28cc4103a61eb190c18b0e37e1e6f3b605d257fc3ff09210683d6548ac8f1f5e524decd4de9310539b6edfc699cb287b924d663b3388699de5b59",
	        3427
	);
}
static void snarf_hat_3429(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/opensnoop-nd.stp",
	        "7391f393c6cf8989c826de7ea2ee6c1082139e1742f3f11948ae940247afc497392a05fd4163aceb60610a171582dfb68d56f0e937fed7531424316c1c815ac4",
	        3428
	);
}
static void snarf_hat_3430(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/rwtime-nd.stp",
	        "4f2e07e3f3ecbe8cf9108285e0460366bfa53fd67298052edad208c6a2634b9485d0ab6656caa5cead9bbd62498c8c2fb632888a7bf0a64e9f953450845609b7",
	        3429
	);
}
static void snarf_hat_3431(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/lwtools/syscallbypid-nd.stp",
	        "a2e163c6acf0bde608fe61871b25f0760cea166bf26911df3aecde0423a0bb4312478e00dd11246ad4f127c880d72277f371c96c1feb1bf032916a4f26d41738",
	        3430
	);
}
static void snarf_hat_3432(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/cachestat.stp",
	        "533b727b1996ccc917073126f65a26da05eadff18ac21a92b6228cfec38b0045da8b79e043344cfd378ea1674545e0ab45cf7102681967593ce252355faf1c7b",
	        3431
	);
}
static void snarf_hat_3433(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/glibc-malloc.stp",
	        "8a118fb1d894272bb2f1d8fbc0c53a40ac8404d6801f7f5f3fb4fb6d4e5413ab1000f000e76c0d46acd5c7bb2012b4190833f074b8b33089926802df2b51d57e",
	        3432
	);
}
static void snarf_hat_3434(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hugepage_clear_delays.stp",
	        "008510602f22fd98d1c5f5d35724892e95fc1dc47552c19507f6af4dd514de7acd686d28dca2ba2c9aa808c691f38e2959b60cc39822b54d172df6f90114bb26",
	        3433
	);
}
static void snarf_hat_3435(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hugepage_collapse.stp",
	        "2b7978759ded329e3691a8145bffa3fa1dab8719bb67ebde3a9898c146a1093b194f71dd6ee58cb80431446e4de8cedbef3666efab3428d5796472a380ec2b22",
	        3434
	);
}
static void snarf_hat_3436(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hugepage_cow_delays.stp",
	        "a431a29c3505d33e0c23f57ee907c69ca79ad28437ffcfd9c402b8cce63c35712db1b23f719432f1c2c47f7df6251f610fe16aae8f79cc8099ea283229629db2",
	        3435
	);
}
static void snarf_hat_3437(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hugepage_split.stp",
	        "a9f6dbefa949da66dfc573d1a224bfdcd8a2b67d68d8bdc2fac10646414ded27f9fa5aff5d8cfad0e3f20a18dc9ae18d3f3ab6d43912080a4940e3f0b0279de5",
	        3436
	);
}
static void snarf_hat_3438(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hw_watch_addr.stp",
	        "b754eac7a92046d8c695229b31eb10b0dc3bf8f3c12683f9030a0cce543f994fc537d49e21176b9dd403e402cf33488f523bcd042808ad3cbe2c112d22c0a172",
	        3437
	);
}
static void snarf_hat_3439(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/hw_watch_sym.stp",
	        "c2ba20a8b8d49fe27d57d39e4aa0c70491a7794bef859dfec60552484b0ac3a92ccb5fa4df92e4c73392fb7432c23e92fd301a4e3e5c1ba32fed1ce329aa9336",
	        3438
	);
}
static void snarf_hat_3440(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/kmalloc-top",
	        "f83f06278444dc8c01b15c625e7b853366396247320d342174675a26f93fd98734ad5f97ef65bc3409ecf9f0f793eb72dcf0a73321f84c9cb7286bb8baf8ae28",
	        3439
	);
}
static void snarf_hat_3441(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/last_100_frees.stp",
	        "fb575a54075f195d97306dc273aa61f595cb007d257d965c0088fb753798ac3b044df2cb2ac270050d4c938738d71b29585ab91cbcaef303146d48a357d4b070",
	        3440
	);
}
static void snarf_hat_3442(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/mmanonpage.stp",
	        "30c82f005ab40a99d7f362782f51b3ae73665308f0a12feff126fec585eee664f048ae28626951fa5a853ecf9dd76148721596592f5deae419de1e8f5bc0721e",
	        3441
	);
}
static void snarf_hat_3443(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/mmfilepage.stp",
	        "fa4218a849459ebe96c2c073e5ad52ce87d331e33c38e4f2632563c66e1933533d550ac2905522460d65c4c114b9014558bada5bc6707e87a44ff732d70db835",
	        3442
	);
}
static void snarf_hat_3444(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/mmreclaim.stp",
	        "64642e56eee9d3adf4cb7fb1746e14a6f73566dbc3d9e3fb8632a0aa5144dc4a340556b9ec61fce80c1d93db18483c74a56e53e347677772ea91708685aebd4c",
	        3443
	);
}
static void snarf_hat_3445(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/mmwriteback.stp",
	        "4af1074024bdf7f30b1bc8a04c2126f74c4dbe004a8f71d71357263e5db87f99691b47cf755dc4334dfc489a25df91bcf116fd6a39de36540ea2e47736edeec3",
	        3444
	);
}
static void snarf_hat_3446(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/numa_faults.stp",
	        "36dfaa4280930084e3e61f237139b48d5030ffbe1815020123148e677d56341a5a33ac656980198f774720bc4be01ab063da34e652dbcc528487d88f59dbbcef",
	        3445
	);
}
static void snarf_hat_3447(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/overcommit.stp",
	        "705677f95e352230a2386efce5d33c0f857a0fd076616f1b2cb94815f142534fcec10a41e6dfc60316fc1233e112b8c985f348e37cc889ff9e7e6fe6641ae654",
	        3446
	);
}
static void snarf_hat_3448(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/pfaults.stp",
	        "3cc0e020fad01a387a3979138fbab894efc4d8a37f754c1d954e487af9e2123d7a58e191b7f1c5664fbf8eab7f7ccb488d1bcd028d14505ad2f8bfc267a90a19",
	        3447
	);
}
static void snarf_hat_3449(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/memory/vm.tracepoints.stp",
	        "543f61afc78be9c791e9324e19883f09eeaa12359e701c2ecf2e1b46806cde7d7bf550c0412d0a56d40d7875a436443a85e33556d562afa1cf8720a180d45f80",
	        3448
	);
}
static void snarf_hat_3450(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/autofs4.stp",
	        "7d63091f78d8cc77a2b94fce9cf37b3adcbb85dad583bbb8822ef8b026cf3e982c6f8e096e089367b8f3dfaf6386c5d1abdf746982fa8f9cd50e6390e74647e8",
	        3449
	);
}
static void snarf_hat_3451(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/connect_stat.stp",
	        "2b5928d5694a3be0047d3cd5754508a6af3a465aff3e2c61a7e508e1e8433931e5b640d6954ecb344ab7c4c5b2264c652305589251327bd235e30d141597448b",
	        3450
	);
}
static void snarf_hat_3452(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/dropwatch.stp",
	        "baa6132955f7c1fdeb35f33f351f014018477c886418801da7b0e56e1658c4d363f53691101a8620d3316ea8f4c977f191f5e7b078ab419acc763c52e47c221d",
	        3451
	);
}
static void snarf_hat_3453(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/netdev.stp",
	        "3304be98e161c845ab8575c22ffd48994c77ad0aff54f2c850031186e68ebec4b02017537d6b27d55a43729a6b47984e31929da65e6db8990c5efcdc5236c018",
	        3452
	);
}
static void snarf_hat_3454(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/netfilter_drop.stp",
	        "12c5325a3baa03e78b74e93edbebbb7bbfe26f84d6364f0a8a49a1b103ad9525e5f71cbd5a38e22b0da17d6563d71438c9cc1e6d2de0008bf8adeb514b328d35",
	        3453
	);
}
static void snarf_hat_3455(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/netfilter_summary.stp",
	        "ef398d9f94e9bf516f7d80cc6bce0beb3716fa25d6e8e8d94573c5414250c22669a9b03d882d4b4fa2653307da09339dc32b68d9ec4bf4a3ae1a3bfa39e51099",
	        3454
	);
}
static void snarf_hat_3456(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/nettop.stp",
	        "6f912e3c3b1257ec0f0e107d38c3f9a9a5737e6f3358f8b5bf46d88ee6b8f638e5299b1f0ad3fd47fd27b2f80391776994f59f59902cc71a33f2e7edb67311fc",
	        3455
	);
}
static void snarf_hat_3457(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/nfsd-recent.stp",
	        "848eed7016e10f596f6d1dbeef4e93ccf0bca32559f315f446f529c5b4d6859cb78b8a165e6d52f33b58f1143d7790a4849a9f8a059f6db379b9dc040f16d338",
	        3456
	);
}
static void snarf_hat_3458(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/nfsd_unlink.stp",
	        "135d0d7084e933b9b40d00cacc8c03e578b423417dfcba5af75333a7f1a1a3fda7ada81cd4e2469b803f4a9e5b21874f427bd09b76684085163204269cb727f2",
	        3457
	);
}
static void snarf_hat_3459(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/nfsdtop.stp",
	        "3f86f8ee021177f0900929a999a164edffe22a5dfe0ec144e8bb236a4af8585fe6fe99726d1d416b3599c719c623af927dc7fcb9945c33970378ee5f368057cf",
	        3458
	);
}
static void snarf_hat_3460(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/packet_contents.stp",
	        "068bece618c9e0f6eaa5b0aa81096e1b315ed72e6d2a97050e0c884b908e2e094e611d119e011bd070409dadf3f2f6dca297d42bba25b466a5924c49b7dc9fad",
	        3459
	);
}
static void snarf_hat_3461(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/sk_stream_wait_memory.stp",
	        "a780e9f59d9e82ccaef7cc08bfde121c29323c1c4e42eec327e284c4f0f4ac61c1924db1033c59658d12e6bf117bbd79e54a67f4e5fdb017c1e6cbd31d0803e8",
	        3460
	);
}
static void snarf_hat_3462(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/socket-trace.stp",
	        "94a949e206bf1c07790fb7173ab580bf85a4c570e0fdd123dfd98f09fed69c2337755bfa406672163a5d6aeb071cb6d03848bcc727f14e97ebd1b11d09bd748d",
	        3461
	);
}
static void snarf_hat_3463(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/socktop",
	        "96ab2a78a0a4ee9a7c1593a8f6b54a0c17cacbd38323a7840da46f027ae05b246f86bb58bb83060a420b01024b1e218c507d1cc35a37088239251b88db81e5c2",
	        3462
	);
}
static void snarf_hat_3464(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/tcp_connections.stp",
	        "6123c66f60d4f3133b332573b9ebf4ea0b7d4f5802019dc42dbe26501d3eaae072a159901a550fa6cb86ab2a44a357ad487cf082c8c1149552c87632d954e9b1",
	        3463
	);
}
static void snarf_hat_3465(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/tcp_init_cwnd.stp",
	        "29c57e39256f0bf28157885feba4daa37f0f503d914a1c5e9c3432ebd9143a004c16bbbcea8e42eccad8fc628f94f8e3c5f778486aa86bb0a31b35a39d070208",
	        3464
	);
}
static void snarf_hat_3466(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/tcp_trace.stp",
	        "fba8cff971cd69327385bb14c8e121e132eba925e3626f3c32eb661841ebd2b1db59e863d094d9ec6869e2e4c269ea323602c1f7b8f84859da6a7c91221d2da4",
	        3465
	);
}
static void snarf_hat_3467(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/tcpdumplike.stp",
	        "29135942d2d8dd90e70ff86e2722a45e7ef89e7834eca9240704e4bec9d39a3c2b7681d04cfabd9da383a7575ca08842a104d8109646abae1a3cdfa3b66fb6ea",
	        3466
	);
}
static void snarf_hat_3468(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/network/tcpipstat.stp",
	        "4d4f1241597d6c47e3853c2a370a104a248a9c4414136ca9c10c178af2b4421c45eb708bd42544ff8e92f18fc5811da56fdc1d717590c9faa84552ddd252afe8",
	        3467
	);
}
static void snarf_hat_3469(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/auditbt.stp",
	        "9166a800a000ee3cbf3dd23950c5b1c72b1650a98b65e59ebcacc56c9d816f9ec914eb22d109d5c95e1ac4c7ffd1ae61631a31db1e17fda383834538d8fddb79",
	        3468
	);
}
static void snarf_hat_3470(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/chng_cpu.stp",
	        "e7f343b2b6108bab687e170311ed81c6c4014f3137b89dbc893f2c300e85e815bd3f5c1918fbc23c3b303b3666471be935ce103f7ac61e477570fc386738a81d",
	        3469
	);
}
static void snarf_hat_3471(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/cycle_thief.stp",
	        "62f4de0d7a07c0e9bb8949dc42b05b37a8a13a69c0f92699055d5172e69c0623f5418c4a321c227196b71c6e9710226696882a77023263bbdd9b450a1f2e1626",
	        3470
	);
}
static void snarf_hat_3472(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/errsnoop.stp",
	        "2dd1187acb6ded32fcf9a3fe30bca4ef7545296a0b0e81bd454385704a000bdabaa827a742e6740ba6f69634656cecb410526c3db14e3f2b0d7c163376bc5729",
	        3471
	);
}
static void snarf_hat_3473(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/forktracker.stp",
	        "e1f3e91fb76f498b1665087fb88a858c06b7e5bed5595e4f6784511500d84b5a21027995e50839ed88bed5b773dea50484b83e4205c401a0d1b5e4a027a08085",
	        3472
	);
}
static void snarf_hat_3474(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/futexes.stp",
	        "8b2a84089355085902382473bffc89aae2d2f4a92cca80320c784fbd31873af17af64d2c9cf88b4d97aaedaaecc1bdf240866a6bee2de95d37e64e15e7edb99f",
	        3473
	);
}
static void snarf_hat_3475(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/ltrace.stp",
	        "aac563a5c92bc26eecaa9cde36051d57de07977a97412ad37f07ab3310964f657a23f6ef1149d40a5067d6e1f797c119252009cba581c94ad345fa49e3f1daea",
	        3474
	);
}
static void snarf_hat_3476(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/migrate.stp",
	        "1942c2f4cb9bae7ee9fa33a920303acb28740071a6aec2d6327d005cb07b56ca7508d714f4e2732beb691d51802b31e70460bec2d75ae19c5c80b0dd56296e55",
	        3475
	);
}
static void snarf_hat_3477(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/mutex-contention.stp",
	        "8d37e1a3edc0a9c122bf4de2538ba891ce3e18193ee64832b2f30068e024809d09c7854043538b2f34af40b0f5e733d39589ca9cc57c6f6688b2bc82abd1188f",
	        3476
	);
}
static void snarf_hat_3478(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/noptrace.stp",
	        "0fe273ceb6b765ce9f2bcff1984f6cce422dfe0cb9ce0f101047cb6a715a96369c9cea930a8d088076a6e0e9bb1819ee53e7c6d5457fa640e29b789c3db451d9",
	        3477
	);
}
static void snarf_hat_3479(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/pfiles.stp",
	        "ef6662928577b11454829dcadc1ba951c3bfbfc22ef06f2a0c0ec9c26e7593115a25df252380ae3704c942fd7b671dd9ff3391ac35db00c93aa7965e0a966db9",
	        3478
	);
}
static void snarf_hat_3480(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/plimit.stp",
	        "b23839befca67315b26216d3be7d883b2e69ecb1c77f1708ca92ab5be45762b5aa6cf7d04b313356df2a76f15ee2eaefdcf8d3df324e80036d926e0c96eda078",
	        3479
	);
}
static void snarf_hat_3481(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/proc_snoop.stp",
	        "38b2aff5a5d51510eb8512ebdbd2a49e5c5ed1d624af788945358b4f25ace5f72b020a9493c0c03d5f4e528ee0eb11a50439bcaf359fb101ba9bef0909022d17",
	        3480
	);
}
static void snarf_hat_3482(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/proctop.stp",
	        "64a4009ddc38fed00f0b8eac83dcb49542af26f11647ec886d435ecbc8f46cd260add51961ebcbe635a05fb66d75b18e059f05848c4269030c8d17031b34ad4c",
	        3481
	);
}
static void snarf_hat_3483(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/psig.stp",
	        "9b5ce7336e8224c480a0008f3c3efee9222a28e6feab1e1800f73c4dcaffb6a0cedb26e2a041c7b3819a3f745f099b1fb0ea9d034b1f97ba7c6bc60e23493ba4",
	        3482
	);
}
static void snarf_hat_3484(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/pstrace_exec.stp",
	        "1d2122c909e7f46c2e4edeb52147875e6486eefc4e4b913ff2b3a846229e32f0a24b01969b317fd967a3542a1931be440729ffbc371d6d2bbdd6e4de95810b75",
	        3483
	);
}
static void snarf_hat_3485(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/pstree.stp",
	        "ffa32329c621e24887d4e7f4c73fcc41e367021ac5001670b1e0efc432ac10849abf817ecb19ece4b450b051d728e3f57206fd3d7f29d98fc51a7334cee0c6f5",
	        3484
	);
}
static void snarf_hat_3486(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/rlimit_nofile.stp",
	        "4848949cf9b8e2c55a6062d2899719c11be24643b5653a93d50e4348896438f32b95f2a28ab29ef625b1e621cef9aea99d9339e688f69e11c27bf33cae59bcf0",
	        3485
	);
}
static void snarf_hat_3487(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/schedtimes.stp",
	        "c59d9209776d2e4ad07fd7e350528d5cac18fcb45258332a5ccc25dee7b01647fcd858b49e1d4ed6f1bca14ba3791d9e2a27c63d5612ff417a4b761eaa946180",
	        3486
	);
}
static void snarf_hat_3488(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/semop-watch.stp",
	        "9f306aedbd96edb1ab6c04ca05f8609f728077b6fda497f06f695e5dc50a6e0c7d72b2db5dba4656730bc37c48b8f6185d07673ae0bb30ce0852e809098be42b",
	        3487
	);
}
static void snarf_hat_3489(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sig_by_pid.stp",
	        "387ebb47112d2b40da8d8d52fd896e432a31074c40425f45871e6afaaed3df4bb77c4bac98f15fa659a8b63c45a6279b2a50a9e9c1d6ba769c8fc0aee2980db6",
	        3488
	);
}
static void snarf_hat_3490(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sig_by_proc.stp",
	        "6eda88ecc753c28b4b5b1a40ed1643d60880d75f0dd741709094578d9afecd8b613f418d6a7aaffa18693c2fbcf029680dc867da20fe4b11d7e6b5e0e7a45215",
	        3489
	);
}
static void snarf_hat_3491(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sigkill.stp",
	        "d272ff758a7af41cf4350a90b2f8cd7c878b492de277a07637dfb00d88abd8a43b0a71a344d278593bfeb15b8a27171b1b69bc76f9e2494faf25675794ea0c7f",
	        3490
	);
}
static void snarf_hat_3492(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sigmon.stp",
	        "93713a22e626383f2b5b45904434dc8f9f574571c42b3ee26c186a0cdd28bb4ddb8dfed02135b1d498d7edcc001e4a6a36fbd0b208419ada0e5df11ddb7c2838",
	        3491
	);
}
static void snarf_hat_3493(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sleepingBeauties.stp",
	        "91f955215a76ba7b3c34e6428e3b12a7549c0989c9a0b1e2ca650ee387f8f3ac5bec13b872cfb3c76b55b4ad997a0f64db0bf21ae476c83c0085a6b5c29daf53",
	        3492
	);
}
static void snarf_hat_3494(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/sleeptime.stp",
	        "026517deb29738a558261ca70c1685f32092bf2106c0147f0624601a64e0fd62bb5e8e8f1c791700ca3a458436270b9b5de3f7a22fecb7d7f5ce105b47a84aa2",
	        3493
	);
}
static void snarf_hat_3495(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/spawn_seeker.stp",
	        "2ba9341dcf905884195fd71c7edb08b3c798009ca1ed3f0b0a47c1786122469e9d4ad6813b799830f74c55696087c83b01f36de7e5efb808a16fed703bfbadb8",
	        3494
	);
}
static void snarf_hat_3496(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/strace.stp",
	        "2ff94f95daadc4620117aa155e01ac1ec33ccbc2470b3d1eb18a5967126e8c02ed9c2085d238c28388b68ad0f4b33c8d2e7c3590eb5da71df26c5083edcd1ed4",
	        3495
	);
}
static void snarf_hat_3497(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/syscalls_by_pid.stp",
	        "eaee0434b1587252056ac2fbfe28573d71a3c27894b156fbcb7ec255d22b9b757fbfffc9b0f96e7187cfad149de8856aced1c3f9c46b1dda3675f150d4f84008",
	        3496
	);
}
static void snarf_hat_3498(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/syscalls_by_proc.stp",
	        "93febb550f65501f1e711e098f4b177167c0f67f3a582f00fceb4105cb3fd70c3479a3fe378bf26eefa6a1dc26606cd2a98c2bf840a741432c74d09496d1fedc",
	        3497
	);
}
static void snarf_hat_3499(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/syscalltimes",
	        "a359e9c41e1864951cd1360fce8c60f0ff3edeb6338afdf402e55c7b6ac85f6d4696fc7e80eb2f161121cbcddcb3a48460f56efeefa158535fe1c05c1f1fa918",
	        3498
	);
}
static void snarf_hat_3500(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/thread-business.stp",
	        "9bb66d99d0495d117e6b4b3bfc19f98b7e73f389a91048e0455eb667417644be4803f1f33f5dc71ba212449f1e01b30086e5eaa0af7c778425ec9d888cc2a52d",
	        3499
	);
}
static void snarf_hat_3501(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/threadstacks.stp",
	        "ae77e8a1ab8395c96d709299a8bb795eaf61a97228fbb48ee2e9af14c4a770a9ffe8259921694bcad4d8e526f3c89ca8c8860958aae2c931bba26593c07df9e2",
	        3500
	);
}
static void snarf_hat_3502(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/process/wait4time.stp",
	        "09a598f8cb4f8c1b77cecdf8a0d9e1a67fe2f676bfacc74a766d3abc75c762e0ea71887786611460209d3e81b68a1d0523043cb5953a1c6cc3627c4909ca00fb",
	        3501
	);
}
static void snarf_hat_3503(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/container_check.stp",
	        "4465790b62a5d7782b568c0f6aadff6a76a8d88e4668ecf22bdd5ca12ddd38c8c51e3c24ebc6d267c9c09353408cbffa885e3b1bd7b7a4bcfe6c1cde075c6ddc",
	        3502
	);
}
static void snarf_hat_3504(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/errno.stp",
	        "58774cdbf818846a8c1fc7d33a8d45ec6930a7067fdfcac2e4d3a11e79e97337e8a038d490cab08c941c967d8f5bfff718b4036452e3045dc96fb20504d521d7",
	        3503
	);
}
static void snarf_hat_3505(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/fileline-profile.stp",
	        "8d9681e28d63be2118e071f65db1a9eded5158fb33f613fd9a756728e8eba9364d57c932e339cb3f04f0c6444a19f04ccfa98c89c1a5bd5bbfc0b2f06753655c",
	        3504
	);
}
static void snarf_hat_3506(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/fntimes.stp",
	        "b3fe8cddc8f8c630fe0f91ac2c046134e5094545b7f2b91bb32ef84b11ca4fc4b5344e951bfc987ec8e9b7b5ed1bf6f0919a5dba43c3e6b44659b3692907c7ec",
	        3505
	);
}
static void snarf_hat_3507(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/functioncallcount.stp",
	        "efed68b76a1c9dbad6019e9750f365b5116e94e9d17c25443d8cd9deb3b730a7e5001eed98862e7b67d052be8ab28d604094e3b27056ef6c01097c885ca0cc0d",
	        3506
	);
}
static void snarf_hat_3508(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/graphcall.stp",
	        "4623b649db6c0dcfe974e735cb99bfc0010a5f2ce1a74e29f394ad7b0b57ee17a2a25ce32b1e7194f5bd8d8cd157f1506bb78d61871505d0ca28306e66a7eb98",
	        3507
	);
}
static void snarf_hat_3509(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/ioctl_handler.stp",
	        "8cec1e2b3a697689b64560c82ed8848295d285c2b633005227421786bf2253c2e2e41b39452ccc290a34b25ad9f0535ae6c6dc31eb26ef585da979f314dcfc95",
	        3508
	);
}
static void snarf_hat_3510(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/latencytap.stp",
	        "afd098392f0fd7b1d0c9f634abb873a7c3b5b6bfbff390d3e663d136f0be9285e4cc3d378290be67b19923e802fbd9e07e19787b9ba3cec8f7bba54670ba5e1a",
	        3509
	);
}
static void snarf_hat_3511(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/linetimes.stp",
	        "1ea058b68677d79135942aa3ab35861597cd235c616988f5f720f7a0fc0ccaf8f67552cb012d1c09b4ba39fd5c4504e344c53189c770584445faa2f958c29df5",
	        3510
	);
}
static void snarf_hat_3512(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/perf.stp",
	        "61fba9921bfb409672b139c55c0877c66706310068ee8be0379e4bd8dd48998d699f97123dcb03355ed7f9798ffc5eb1d31385ea3bfdf7aacafdd1163677b087",
	        3511
	);
}
static void snarf_hat_3513(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/periodic.stp",
	        "b77f4706ecd5b473e4f3ee1a3cab9bd5c210649f223800c0f64a9952d76f0e88ba02ec6515f5ad51884867d34222121d9562ea55adb7a92841eeaaade71829cf",
	        3512
	);
}
static void snarf_hat_3514(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/pf2.stp",
	        "86e0bace2d045edae96b071a40f39077d85b2ccbec6ac68189e3c166294eb1295844c29f2bc8c3712007cf395f1310236014eea332ee12708e3dc13e319a948b",
	        3513
	);
}
static void snarf_hat_3515(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/pf3.stp",
	        "03ff378ae3e3e18f451b9323263a9de6d54908fea82576f330ab8f806f434757c1a79ed6d7e6188e564f5aca97b13aa4ac484a5866f35985a99fb6d9ac975baf",
	        3514
	);
}
static void snarf_hat_3516(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/pf4.stp",
	        "54cad99629c154a9523faa00137851e833511b6dc335ea95da0926b0d2be27d5d822871c0ec2435e0238b895806fa4bde89fd4c2cec8408b0e4a80a33dde8496",
	        3515
	);
}
static void snarf_hat_3517(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/sched_switch.stp",
	        "8ddb0d3ffe00b4ff44ce69d6ebecfb8160dd9cf48eeffc7f8500df5c11309d08dd05b7b71c5476a6b4a4488dc5c52841576c925b786a7dc183dabd3d84acc046",
	        3516
	);
}
static void snarf_hat_3518(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/syscallerrorsbypid.stp",
	        "60222641aeaf83be8b33ecb2214d0d1a2bee8ca919a6b8fb49069c246706f3e0bf28ba9079dcbc534e89b96ad29b2645b143a60825525839122e98cdb01ebc57",
	        3517
	);
}
static void snarf_hat_3519(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/syscalllatency.stp",
	        "4238f0f612ccd015a5310a2c2283a8fe00e8d3e0b74890e8479cba111e663dd12cf65a51e3c14fa0807a8e6604670168dbc1b2209a25f161a3c7f98b5e8b1a90",
	        3518
	);
}
static void snarf_hat_3520(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/syscallsbypid.stp",
	        "d2364140bc9590f3d37420cd72d5e0321f7abcc9a6c889d7aef946dedaee18e1f5dcf69433341b98ad76e4c7ec588a7044dbabef25de88621c4e0378f1b06565",
	        3519
	);
}
static void snarf_hat_3521(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/syscallsrw.stp",
	        "07065e60f3ff8814ab215dac0f7cfb31aec2ac54f68f5d1d3e9485befd7d8181e9284f3a34dba588c8266911d535070977113e2f3e36056be59ec11a0a67328f",
	        3520
	);
}
static void snarf_hat_3522(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/thread-times.stp",
	        "1ddec5f3a9f63c7cf5ac554ac2601a489b77b8a87570ffffe74f9bc844ee007d1516a220562ed2dd8fc89fe1b705bdc29d19c2e44d09137126ce936469fb8a79",
	        3521
	);
}
static void snarf_hat_3523(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/timeout.stp",
	        "c391170cafebc052277f699898754f829584afad5e5ee189ad74585423420ef3f66dc0860071bf6ef1274f260075965338b235f6a4b5e6f8e30aa6294827c597",
	        3522
	);
}
static void snarf_hat_3524(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/topsys.stp",
	        "27a5db8d21f549a33142c78840ea689a886009a4e39df468f0d04ea2952bdb18ea99730deded135e6c0f655ff89c64df493e3c7d813b7eee57f88b38d2698634",
	        3523
	);
}
static void snarf_hat_3525(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/profiling/ucalls.stp",
	        "397e97bcd9f74bb1095927d8467b1a35f19e6cc66a66be5a5495d8a13ebfde6880495e3e4ef097e7df86c99b3619f8e04af9910854af31f97c371fb30ef70fcf",
	        3524
	);
}
static void snarf_hat_3526(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/stapgames/block.stp",
	        "ccde956047a54bc8848a63125daf98c7149ad2d4754df3b1d7f5b48bc5a67869d0e12b222b8fcde0644a6286e473fb5fc5cc111dc3ccf159cfc588ca9c753021",
	        3525
	);
}
static void snarf_hat_3527(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/stapgames/eater.stp",
	        "6d74f34d30aad661bdf8c61e314158498727362b05d756b1ae401ad1cd289271e0fbcbe947fef3349128aca64f558c5a52b501c09df477d37b291a87bd19dde2",
	        3526
	);
}
static void snarf_hat_3528(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/stapgames/lifegame.stp",
	        "1fbdb525dc794753295248844ab90426dac1bcf9def8bed87fa164ff51e3443f14860bb49ddfb6596bcda26af35a85fd55f3adea670f265cb1e19a0dbee7d3ba",
	        3527
	);
}
static void snarf_hat_3529(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/stapgames/pingpong.stp",
	        "c446d0717d39a0f85ddf43b2867048bfd9b967cfe07f561342cce0a2176d7d9bb42a904abd3d6d2f2ac8a3b64e1e1de70db6297131f44630360183b1a463406b",
	        3528
	);
}
static void snarf_hat_3530(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/virtualization/kvm_service_time.stp",
	        "b1481a08bfcd134e889aa6a9369b168b5beeb166421d1ccc9f14934f9f8e6aed9034e7d054b509ab28eedce22e81d61b369f5fadf850b3ff78a3d43f822fe298",
	        3529
	);
}
static void snarf_hat_3531(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/virtualization/qemu_count.stp",
	        "f27e1107d038d4f5ed7616353175d84faae8a72828e5dfe4b98f2ac2c9b5d2a43c66fb54d39000f77cae31c6d6f31da4bbaec9f0091091270994a9df663ccf11",
	        3530
	);
}
static void snarf_hat_3532(void) 
{
	snarf_construct_hat("/usr/share/systemtap/examples/virtualization/qemu_io.stp",
	        "a3c4bb1183c730e3434808e70fc83bad56926a15c7c223ac9308b26c7d1185b9033babede7d62b260ee89c446600d06b11442ef503930bd595133029f04a0182",
	        3531
	);
}
static void snarf_hat_3533(void) 
{
	snarf_construct_hat("/usr/share/vim/vim82/macros/less.sh",
	        "9d2409f7286a9d052fdedbe45c6d2c00fa9604a7446d24fc51aa22c0707b7b64ebd03a7410b5aab3f85081483cd2691c18786e0a330b5d6f16a6cd8e74e83f4d",
	        3532
	);
}
static void snarf_hat_3534(void) 
{
	snarf_construct_hat("/usr/share/icu/69.1/install-sh",
	        "0e034cf65ca969366b2836a378c5e19c42aaaf9eebcb077297a84e0437a3c9015c490e6cb5f40bfb8c01af4aac300e297b50f82cbc7db3e9be1c3a499ba675fe",
	        3533
	);
}
static void snarf_hat_3535(void) 
{
	snarf_construct_hat("/usr/share/icu/69.1/mkinstalldirs",
	        "c893de080818db7bc244296284b9b5ac9f1ee3448646d5106863c2e240d5edc2b4376b7e2fcef09fa00bf8f8a3660ace3e52a113d67c2c150738355a904b0b1f",
	        3534
	);
}
static void snarf_hat_3536(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/HashTool.efi",
	        "c9d73f93c4443b2c4da4a36301ce9ea5a68c625ffd498e4ddfbb7f706fca5e3e2ad5e188357819bf924c0dfe50624e567e77dbd84b459df5c4a3727e3a061363",
	        3535
	);
}
static void snarf_hat_3537(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/HelloWorld.efi",
	        "0ae6c24c25a07823c6b4f20949d7a20ae58fc764c97e9748dc78d0ec02b4c685ca2f1a6eca6f6230bd6a0802aa9277dc0019494f486b04cc49317ac1f50115c7",
	        3536
	);
}
static void snarf_hat_3538(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/KeyTool.efi",
	        "85213870b14bd1c42fb05b26415e32f5ec10df083151652d558bc6e2e350f814bd372c631bd0f3b2ebe5de0b7421e23c3e6bc1798a2f8861a3fa81dda63fcefb",
	        3537
	);
}
static void snarf_hat_3539(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/Loader.efi",
	        "f919c81f933d57ef7f48e6ef90dab7c31760a3e073c01a9b5a3f9c354c93a5d555a12887af9394938dd4578747797a374f771049af42cea8777e2b97aac52347",
	        3538
	);
}
static void snarf_hat_3540(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/LockDown.efi",
	        "4693803854cb1f4f15858e1e947ac41e04e0865ea7807547219288744c91392c6a374abc05ce7105bd72ea386cd4b5990b366a8d341615688b23ba4583290b83",
	        3539
	);
}
static void snarf_hat_3541(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/ReadVars.efi",
	        "dcbf3b4cb3d38c7ae800c755645912cfe1b8d3840992ec48dce1d755fba4f8afb253811afa7e499fd12a7720dc7a1aaff26ca3af87074291fec1310ce2cef370",
	        3540
	);
}
static void snarf_hat_3542(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/SetNull.efi",
	        "9456ac469fefadf4eef6bf61fde7350795ef90b6068b7e260251a41256364bef45ca0c816cf8ccd0630b2e28f6c1cdab011b5f4af2d5604ca21805fc5beec0d9",
	        3541
	);
}
static void snarf_hat_3543(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/ShimReplace.efi",
	        "2497ed0830963141eb1d48cb3ee211db03351cc5c86382c7fd9acf2b8221130b26eda32506c599ee2b5ccbf04a67a07690354d6d3c701e4d67d3aa4d974cfb3d",
	        3542
	);
}
static void snarf_hat_3544(void) 
{
	snarf_construct_hat("/usr/share/efitools/efi/UpdateVars.efi",
	        "6873e37e5ca70bbc0b4dfffcb1d363f921a9cfb0e72e81857194ad45d8498af0fed3b630e8083e5db7b98b10494f54f1acb7f5db4ef763d65c7748314474b399",
	        3543
	);
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

static void snarf_init(void)
{
//##########TEMPLATE_PARM_SP##################################################=>
	snarf_hat_1();
	snarf_hat_2();
	snarf_hat_3();
	snarf_hat_4();
	snarf_hat_5();
	snarf_hat_6();
	snarf_hat_7();
	snarf_hat_8();
	snarf_hat_9();
	snarf_hat_10();
	snarf_hat_11();
	snarf_hat_12();
	snarf_hat_13();
	snarf_hat_14();
	snarf_hat_15();
	snarf_hat_16();
	snarf_hat_17();
	snarf_hat_18();
	snarf_hat_19();
	snarf_hat_20();
	snarf_hat_21();
	snarf_hat_22();
	snarf_hat_23();
	snarf_hat_24();
	snarf_hat_25();
	snarf_hat_26();
	snarf_hat_27();
	snarf_hat_28();
	snarf_hat_29();
	snarf_hat_30();
	snarf_hat_31();
	snarf_hat_32();
	snarf_hat_33();
	snarf_hat_34();
	snarf_hat_35();
	snarf_hat_36();
	snarf_hat_37();
	snarf_hat_38();
	snarf_hat_39();
	snarf_hat_40();
	snarf_hat_41();
	snarf_hat_42();
	snarf_hat_43();
	snarf_hat_44();
	snarf_hat_45();
	snarf_hat_46();
	snarf_hat_47();
	snarf_hat_48();
	snarf_hat_49();
	snarf_hat_50();
	snarf_hat_51();
	snarf_hat_52();
	snarf_hat_53();
	snarf_hat_54();
	snarf_hat_55();
	snarf_hat_56();
	snarf_hat_57();
	snarf_hat_58();
	snarf_hat_59();
	snarf_hat_60();
	snarf_hat_61();
	snarf_hat_62();
	snarf_hat_63();
	snarf_hat_64();
	snarf_hat_65();
	snarf_hat_66();
	snarf_hat_67();
	snarf_hat_68();
	snarf_hat_69();
	snarf_hat_70();
	snarf_hat_71();
	snarf_hat_72();
	snarf_hat_73();
	snarf_hat_74();
	snarf_hat_75();
	snarf_hat_76();
	snarf_hat_77();
	snarf_hat_78();
	snarf_hat_79();
	snarf_hat_80();
	snarf_hat_81();
	snarf_hat_82();
	snarf_hat_83();
	snarf_hat_84();
	snarf_hat_85();
	snarf_hat_86();
	snarf_hat_87();
	snarf_hat_88();
	snarf_hat_89();
	snarf_hat_90();
	snarf_hat_91();
	snarf_hat_92();
	snarf_hat_93();
	snarf_hat_94();
	snarf_hat_95();
	snarf_hat_96();
	snarf_hat_97();
	snarf_hat_98();
	snarf_hat_99();
	snarf_hat_100();
	snarf_hat_101();
	snarf_hat_102();
	snarf_hat_103();
	snarf_hat_104();
	snarf_hat_105();
	snarf_hat_106();
	snarf_hat_107();
	snarf_hat_108();
	snarf_hat_109();
	snarf_hat_110();
	snarf_hat_111();
	snarf_hat_112();
	snarf_hat_113();
	snarf_hat_114();
	snarf_hat_115();
	snarf_hat_116();
	snarf_hat_117();
	snarf_hat_118();
	snarf_hat_119();
	snarf_hat_120();
	snarf_hat_121();
	snarf_hat_122();
	snarf_hat_123();
	snarf_hat_124();
	snarf_hat_125();
	snarf_hat_126();
	snarf_hat_127();
	snarf_hat_128();
	snarf_hat_129();
	snarf_hat_130();
	snarf_hat_131();
	snarf_hat_132();
	snarf_hat_133();
	snarf_hat_134();
	snarf_hat_135();
	snarf_hat_136();
	snarf_hat_137();
	snarf_hat_138();
	snarf_hat_139();
	snarf_hat_140();
	snarf_hat_141();
	snarf_hat_142();
	snarf_hat_143();
	snarf_hat_144();
	snarf_hat_145();
	snarf_hat_146();
	snarf_hat_147();
	snarf_hat_148();
	snarf_hat_149();
	snarf_hat_150();
	snarf_hat_151();
	snarf_hat_152();
	snarf_hat_153();
	snarf_hat_154();
	snarf_hat_155();
	snarf_hat_156();
	snarf_hat_157();
	snarf_hat_158();
	snarf_hat_159();
	snarf_hat_160();
	snarf_hat_161();
	snarf_hat_162();
	snarf_hat_163();
	snarf_hat_164();
	snarf_hat_165();
	snarf_hat_166();
	snarf_hat_167();
	snarf_hat_168();
	snarf_hat_169();
	snarf_hat_170();
	snarf_hat_171();
	snarf_hat_172();
	snarf_hat_173();
	snarf_hat_174();
	snarf_hat_175();
	snarf_hat_176();
	snarf_hat_177();
	snarf_hat_178();
	snarf_hat_179();
	snarf_hat_180();
	snarf_hat_181();
	snarf_hat_182();
	snarf_hat_183();
	snarf_hat_184();
	snarf_hat_185();
	snarf_hat_186();
	snarf_hat_187();
	snarf_hat_188();
	snarf_hat_189();
	snarf_hat_190();
	snarf_hat_191();
	snarf_hat_192();
	snarf_hat_193();
	snarf_hat_194();
	snarf_hat_195();
	snarf_hat_196();
	snarf_hat_197();
	snarf_hat_198();
	snarf_hat_199();
	snarf_hat_200();
	snarf_hat_201();
	snarf_hat_202();
	snarf_hat_203();
	snarf_hat_204();
	snarf_hat_205();
	snarf_hat_206();
	snarf_hat_207();
	snarf_hat_208();
	snarf_hat_209();
	snarf_hat_210();
	snarf_hat_211();
	snarf_hat_212();
	snarf_hat_213();
	snarf_hat_214();
	snarf_hat_215();
	snarf_hat_216();
	snarf_hat_217();
	snarf_hat_218();
	snarf_hat_219();
	snarf_hat_220();
	snarf_hat_221();
	snarf_hat_222();
	snarf_hat_223();
	snarf_hat_224();
	snarf_hat_225();
	snarf_hat_226();
	snarf_hat_227();
	snarf_hat_228();
	snarf_hat_229();
	snarf_hat_230();
	snarf_hat_231();
	snarf_hat_232();
	snarf_hat_233();
	snarf_hat_234();
	snarf_hat_235();
	snarf_hat_236();
	snarf_hat_237();
	snarf_hat_238();
	snarf_hat_239();
	snarf_hat_240();
	snarf_hat_241();
	snarf_hat_242();
	snarf_hat_243();
	snarf_hat_244();
	snarf_hat_245();
	snarf_hat_246();
	snarf_hat_247();
	snarf_hat_248();
	snarf_hat_249();
	snarf_hat_250();
	snarf_hat_251();
	snarf_hat_252();
	snarf_hat_253();
	snarf_hat_254();
	snarf_hat_255();
	snarf_hat_256();
	snarf_hat_257();
	snarf_hat_258();
	snarf_hat_259();
	snarf_hat_260();
	snarf_hat_261();
	snarf_hat_262();
	snarf_hat_263();
	snarf_hat_264();
	snarf_hat_265();
	snarf_hat_266();
	snarf_hat_267();
	snarf_hat_268();
	snarf_hat_269();
	snarf_hat_270();
	snarf_hat_271();
	snarf_hat_272();
	snarf_hat_273();
	snarf_hat_274();
	snarf_hat_275();
	snarf_hat_276();
	snarf_hat_277();
	snarf_hat_278();
	snarf_hat_279();
	snarf_hat_280();
	snarf_hat_281();
	snarf_hat_282();
	snarf_hat_283();
	snarf_hat_284();
	snarf_hat_285();
	snarf_hat_286();
	snarf_hat_287();
	snarf_hat_288();
	snarf_hat_289();
	snarf_hat_290();
	snarf_hat_291();
	snarf_hat_292();
	snarf_hat_293();
	snarf_hat_294();
	snarf_hat_295();
	snarf_hat_296();
	snarf_hat_297();
	snarf_hat_298();
	snarf_hat_299();
	snarf_hat_300();
	snarf_hat_301();
	snarf_hat_302();
	snarf_hat_303();
	snarf_hat_304();
	snarf_hat_305();
	snarf_hat_306();
	snarf_hat_307();
	snarf_hat_308();
	snarf_hat_309();
	snarf_hat_310();
	snarf_hat_311();
	snarf_hat_312();
	snarf_hat_313();
	snarf_hat_314();
	snarf_hat_315();
	snarf_hat_316();
	snarf_hat_317();
	snarf_hat_318();
	snarf_hat_319();
	snarf_hat_320();
	snarf_hat_321();
	snarf_hat_322();
	snarf_hat_323();
	snarf_hat_324();
	snarf_hat_325();
	snarf_hat_326();
	snarf_hat_327();
	snarf_hat_328();
	snarf_hat_329();
	snarf_hat_330();
	snarf_hat_331();
	snarf_hat_332();
	snarf_hat_333();
	snarf_hat_334();
	snarf_hat_335();
	snarf_hat_336();
	snarf_hat_337();
	snarf_hat_338();
	snarf_hat_339();
	snarf_hat_340();
	snarf_hat_341();
	snarf_hat_342();
	snarf_hat_343();
	snarf_hat_344();
	snarf_hat_345();
	snarf_hat_346();
	snarf_hat_347();
	snarf_hat_348();
	snarf_hat_349();
	snarf_hat_350();
	snarf_hat_351();
	snarf_hat_352();
	snarf_hat_353();
	snarf_hat_354();
	snarf_hat_355();
	snarf_hat_356();
	snarf_hat_357();
	snarf_hat_358();
	snarf_hat_359();
	snarf_hat_360();
	snarf_hat_361();
	snarf_hat_362();
	snarf_hat_363();
	snarf_hat_364();
	snarf_hat_365();
	snarf_hat_366();
	snarf_hat_367();
	snarf_hat_368();
	snarf_hat_369();
	snarf_hat_370();
	snarf_hat_371();
	snarf_hat_372();
	snarf_hat_373();
	snarf_hat_374();
	snarf_hat_375();
	snarf_hat_376();
	snarf_hat_377();
	snarf_hat_378();
	snarf_hat_379();
	snarf_hat_380();
	snarf_hat_381();
	snarf_hat_382();
	snarf_hat_383();
	snarf_hat_384();
	snarf_hat_385();
	snarf_hat_386();
	snarf_hat_387();
	snarf_hat_388();
	snarf_hat_389();
	snarf_hat_390();
	snarf_hat_391();
	snarf_hat_392();
	snarf_hat_393();
	snarf_hat_394();
	snarf_hat_395();
	snarf_hat_396();
	snarf_hat_397();
	snarf_hat_398();
	snarf_hat_399();
	snarf_hat_400();
	snarf_hat_401();
	snarf_hat_402();
	snarf_hat_403();
	snarf_hat_404();
	snarf_hat_405();
	snarf_hat_406();
	snarf_hat_407();
	snarf_hat_408();
	snarf_hat_409();
	snarf_hat_410();
	snarf_hat_411();
	snarf_hat_412();
	snarf_hat_413();
	snarf_hat_414();
	snarf_hat_415();
	snarf_hat_416();
	snarf_hat_417();
	snarf_hat_418();
	snarf_hat_419();
	snarf_hat_420();
	snarf_hat_421();
	snarf_hat_422();
	snarf_hat_423();
	snarf_hat_424();
	snarf_hat_425();
	snarf_hat_426();
	snarf_hat_427();
	snarf_hat_428();
	snarf_hat_429();
	snarf_hat_430();
	snarf_hat_431();
	snarf_hat_432();
	snarf_hat_433();
	snarf_hat_434();
	snarf_hat_435();
	snarf_hat_436();
	snarf_hat_437();
	snarf_hat_438();
	snarf_hat_439();
	snarf_hat_440();
	snarf_hat_441();
	snarf_hat_442();
	snarf_hat_443();
	snarf_hat_444();
	snarf_hat_445();
	snarf_hat_446();
	snarf_hat_447();
	snarf_hat_448();
	snarf_hat_449();
	snarf_hat_450();
	snarf_hat_451();
	snarf_hat_452();
	snarf_hat_453();
	snarf_hat_454();
	snarf_hat_455();
	snarf_hat_456();
	snarf_hat_457();
	snarf_hat_458();
	snarf_hat_459();
	snarf_hat_460();
	snarf_hat_461();
	snarf_hat_462();
	snarf_hat_463();
	snarf_hat_464();
	snarf_hat_465();
	snarf_hat_466();
	snarf_hat_467();
	snarf_hat_468();
	snarf_hat_469();
	snarf_hat_470();
	snarf_hat_471();
	snarf_hat_472();
	snarf_hat_473();
	snarf_hat_474();
	snarf_hat_475();
	snarf_hat_476();
	snarf_hat_477();
	snarf_hat_478();
	snarf_hat_479();
	snarf_hat_480();
	snarf_hat_481();
	snarf_hat_482();
	snarf_hat_483();
	snarf_hat_484();
	snarf_hat_485();
	snarf_hat_486();
	snarf_hat_487();
	snarf_hat_488();
	snarf_hat_489();
	snarf_hat_490();
	snarf_hat_491();
	snarf_hat_492();
	snarf_hat_493();
	snarf_hat_494();
	snarf_hat_495();
	snarf_hat_496();
	snarf_hat_497();
	snarf_hat_498();
	snarf_hat_499();
	snarf_hat_500();
	snarf_hat_501();
	snarf_hat_502();
	snarf_hat_503();
	snarf_hat_504();
	snarf_hat_505();
	snarf_hat_506();
	snarf_hat_507();
	snarf_hat_508();
	snarf_hat_509();
	snarf_hat_510();
	snarf_hat_511();
	snarf_hat_512();
	snarf_hat_513();
	snarf_hat_514();
	snarf_hat_515();
	snarf_hat_516();
	snarf_hat_517();
	snarf_hat_518();
	snarf_hat_519();
	snarf_hat_520();
	snarf_hat_521();
	snarf_hat_522();
	snarf_hat_523();
	snarf_hat_524();
	snarf_hat_525();
	snarf_hat_526();
	snarf_hat_527();
	snarf_hat_528();
	snarf_hat_529();
	snarf_hat_530();
	snarf_hat_531();
	snarf_hat_532();
	snarf_hat_533();
	snarf_hat_534();
	snarf_hat_535();
	snarf_hat_536();
	snarf_hat_537();
	snarf_hat_538();
	snarf_hat_539();
	snarf_hat_540();
	snarf_hat_541();
	snarf_hat_542();
	snarf_hat_543();
	snarf_hat_544();
	snarf_hat_545();
	snarf_hat_546();
	snarf_hat_547();
	snarf_hat_548();
	snarf_hat_549();
	snarf_hat_550();
	snarf_hat_551();
	snarf_hat_552();
	snarf_hat_553();
	snarf_hat_554();
	snarf_hat_555();
	snarf_hat_556();
	snarf_hat_557();
	snarf_hat_558();
	snarf_hat_559();
	snarf_hat_560();
	snarf_hat_561();
	snarf_hat_562();
	snarf_hat_563();
	snarf_hat_564();
	snarf_hat_565();
	snarf_hat_566();
	snarf_hat_567();
	snarf_hat_568();
	snarf_hat_569();
	snarf_hat_570();
	snarf_hat_571();
	snarf_hat_572();
	snarf_hat_573();
	snarf_hat_574();
	snarf_hat_575();
	snarf_hat_576();
	snarf_hat_577();
	snarf_hat_578();
	snarf_hat_579();
	snarf_hat_580();
	snarf_hat_581();
	snarf_hat_582();
	snarf_hat_583();
	snarf_hat_584();
	snarf_hat_585();
	snarf_hat_586();
	snarf_hat_587();
	snarf_hat_588();
	snarf_hat_589();
	snarf_hat_590();
	snarf_hat_591();
	snarf_hat_592();
	snarf_hat_593();
	snarf_hat_594();
	snarf_hat_595();
	snarf_hat_596();
	snarf_hat_597();
	snarf_hat_598();
	snarf_hat_599();
	snarf_hat_600();
	snarf_hat_601();
	snarf_hat_602();
	snarf_hat_603();
	snarf_hat_604();
	snarf_hat_605();
	snarf_hat_606();
	snarf_hat_607();
	snarf_hat_608();
	snarf_hat_609();
	snarf_hat_610();
	snarf_hat_611();
	snarf_hat_612();
	snarf_hat_613();
	snarf_hat_614();
	snarf_hat_615();
	snarf_hat_616();
	snarf_hat_617();
	snarf_hat_618();
	snarf_hat_619();
	snarf_hat_620();
	snarf_hat_621();
	snarf_hat_622();
	snarf_hat_623();
	snarf_hat_624();
	snarf_hat_625();
	snarf_hat_626();
	snarf_hat_627();
	snarf_hat_628();
	snarf_hat_629();
	snarf_hat_630();
	snarf_hat_631();
	snarf_hat_632();
	snarf_hat_633();
	snarf_hat_634();
	snarf_hat_635();
	snarf_hat_636();
	snarf_hat_637();
	snarf_hat_638();
	snarf_hat_639();
	snarf_hat_640();
	snarf_hat_641();
	snarf_hat_642();
	snarf_hat_643();
	snarf_hat_644();
	snarf_hat_645();
	snarf_hat_646();
	snarf_hat_647();
	snarf_hat_648();
	snarf_hat_649();
	snarf_hat_650();
	snarf_hat_651();
	snarf_hat_652();
	snarf_hat_653();
	snarf_hat_654();
	snarf_hat_655();
	snarf_hat_656();
	snarf_hat_657();
	snarf_hat_658();
	snarf_hat_659();
	snarf_hat_660();
	snarf_hat_661();
	snarf_hat_662();
	snarf_hat_663();
	snarf_hat_664();
	snarf_hat_665();
	snarf_hat_666();
	snarf_hat_667();
	snarf_hat_668();
	snarf_hat_669();
	snarf_hat_670();
	snarf_hat_671();
	snarf_hat_672();
	snarf_hat_673();
	snarf_hat_674();
	snarf_hat_675();
	snarf_hat_676();
	snarf_hat_677();
	snarf_hat_678();
	snarf_hat_679();
	snarf_hat_680();
	snarf_hat_681();
	snarf_hat_682();
	snarf_hat_683();
	snarf_hat_684();
	snarf_hat_685();
	snarf_hat_686();
	snarf_hat_687();
	snarf_hat_688();
	snarf_hat_689();
	snarf_hat_690();
	snarf_hat_691();
	snarf_hat_692();
	snarf_hat_693();
	snarf_hat_694();
	snarf_hat_695();
	snarf_hat_696();
	snarf_hat_697();
	snarf_hat_698();
	snarf_hat_699();
	snarf_hat_700();
	snarf_hat_701();
	snarf_hat_702();
	snarf_hat_703();
	snarf_hat_704();
	snarf_hat_705();
	snarf_hat_706();
	snarf_hat_707();
	snarf_hat_708();
	snarf_hat_709();
	snarf_hat_710();
	snarf_hat_711();
	snarf_hat_712();
	snarf_hat_713();
	snarf_hat_714();
	snarf_hat_715();
	snarf_hat_716();
	snarf_hat_717();
	snarf_hat_718();
	snarf_hat_719();
	snarf_hat_720();
	snarf_hat_721();
	snarf_hat_722();
	snarf_hat_723();
	snarf_hat_724();
	snarf_hat_725();
	snarf_hat_726();
	snarf_hat_727();
	snarf_hat_728();
	snarf_hat_729();
	snarf_hat_730();
	snarf_hat_731();
	snarf_hat_732();
	snarf_hat_733();
	snarf_hat_734();
	snarf_hat_735();
	snarf_hat_736();
	snarf_hat_737();
	snarf_hat_738();
	snarf_hat_739();
	snarf_hat_740();
	snarf_hat_741();
	snarf_hat_742();
	snarf_hat_743();
	snarf_hat_744();
	snarf_hat_745();
	snarf_hat_746();
	snarf_hat_747();
	snarf_hat_748();
	snarf_hat_749();
	snarf_hat_750();
	snarf_hat_751();
	snarf_hat_752();
	snarf_hat_753();
	snarf_hat_754();
	snarf_hat_755();
	snarf_hat_756();
	snarf_hat_757();
	snarf_hat_758();
	snarf_hat_759();
	snarf_hat_760();
	snarf_hat_761();
	snarf_hat_762();
	snarf_hat_763();
	snarf_hat_764();
	snarf_hat_765();
	snarf_hat_766();
	snarf_hat_767();
	snarf_hat_768();
	snarf_hat_769();
	snarf_hat_770();
	snarf_hat_771();
	snarf_hat_772();
	snarf_hat_773();
	snarf_hat_774();
	snarf_hat_775();
	snarf_hat_776();
	snarf_hat_777();
	snarf_hat_778();
	snarf_hat_779();
	snarf_hat_780();
	snarf_hat_781();
	snarf_hat_782();
	snarf_hat_783();
	snarf_hat_784();
	snarf_hat_785();
	snarf_hat_786();
	snarf_hat_787();
	snarf_hat_788();
	snarf_hat_789();
	snarf_hat_790();
	snarf_hat_791();
	snarf_hat_792();
	snarf_hat_793();
	snarf_hat_794();
	snarf_hat_795();
	snarf_hat_796();
	snarf_hat_797();
	snarf_hat_798();
	snarf_hat_799();
	snarf_hat_800();
	snarf_hat_801();
	snarf_hat_802();
	snarf_hat_803();
	snarf_hat_804();
	snarf_hat_805();
	snarf_hat_806();
	snarf_hat_807();
	snarf_hat_808();
	snarf_hat_809();
	snarf_hat_810();
	snarf_hat_811();
	snarf_hat_812();
	snarf_hat_813();
	snarf_hat_814();
	snarf_hat_815();
	snarf_hat_816();
	snarf_hat_817();
	snarf_hat_818();
	snarf_hat_819();
	snarf_hat_820();
	snarf_hat_821();
	snarf_hat_822();
	snarf_hat_823();
	snarf_hat_824();
	snarf_hat_825();
	snarf_hat_826();
	snarf_hat_827();
	snarf_hat_828();
	snarf_hat_829();
	snarf_hat_830();
	snarf_hat_831();
	snarf_hat_832();
	snarf_hat_833();
	snarf_hat_834();
	snarf_hat_835();
	snarf_hat_836();
	snarf_hat_837();
	snarf_hat_838();
	snarf_hat_839();
	snarf_hat_840();
	snarf_hat_841();
	snarf_hat_842();
	snarf_hat_843();
	snarf_hat_844();
	snarf_hat_845();
	snarf_hat_846();
	snarf_hat_847();
	snarf_hat_848();
	snarf_hat_849();
	snarf_hat_850();
	snarf_hat_851();
	snarf_hat_852();
	snarf_hat_853();
	snarf_hat_854();
	snarf_hat_855();
	snarf_hat_856();
	snarf_hat_857();
	snarf_hat_858();
	snarf_hat_859();
	snarf_hat_860();
	snarf_hat_861();
	snarf_hat_862();
	snarf_hat_863();
	snarf_hat_864();
	snarf_hat_865();
	snarf_hat_866();
	snarf_hat_867();
	snarf_hat_868();
	snarf_hat_869();
	snarf_hat_870();
	snarf_hat_871();
	snarf_hat_872();
	snarf_hat_873();
	snarf_hat_874();
	snarf_hat_875();
	snarf_hat_876();
	snarf_hat_877();
	snarf_hat_878();
	snarf_hat_879();
	snarf_hat_880();
	snarf_hat_881();
	snarf_hat_882();
	snarf_hat_883();
	snarf_hat_884();
	snarf_hat_885();
	snarf_hat_886();
	snarf_hat_887();
	snarf_hat_888();
	snarf_hat_889();
	snarf_hat_890();
	snarf_hat_891();
	snarf_hat_892();
	snarf_hat_893();
	snarf_hat_894();
	snarf_hat_895();
	snarf_hat_896();
	snarf_hat_897();
	snarf_hat_898();
	snarf_hat_899();
	snarf_hat_900();
	snarf_hat_901();
	snarf_hat_902();
	snarf_hat_903();
	snarf_hat_904();
	snarf_hat_905();
	snarf_hat_906();
	snarf_hat_907();
	snarf_hat_908();
	snarf_hat_909();
	snarf_hat_910();
	snarf_hat_911();
	snarf_hat_912();
	snarf_hat_913();
	snarf_hat_914();
	snarf_hat_915();
	snarf_hat_916();
	snarf_hat_917();
	snarf_hat_918();
	snarf_hat_919();
	snarf_hat_920();
	snarf_hat_921();
	snarf_hat_922();
	snarf_hat_923();
	snarf_hat_924();
	snarf_hat_925();
	snarf_hat_926();
	snarf_hat_927();
	snarf_hat_928();
	snarf_hat_929();
	snarf_hat_930();
	snarf_hat_931();
	snarf_hat_932();
	snarf_hat_933();
	snarf_hat_934();
	snarf_hat_935();
	snarf_hat_936();
	snarf_hat_937();
	snarf_hat_938();
	snarf_hat_939();
	snarf_hat_940();
	snarf_hat_941();
	snarf_hat_942();
	snarf_hat_943();
	snarf_hat_944();
	snarf_hat_945();
	snarf_hat_946();
	snarf_hat_947();
	snarf_hat_948();
	snarf_hat_949();
	snarf_hat_950();
	snarf_hat_951();
	snarf_hat_952();
	snarf_hat_953();
	snarf_hat_954();
	snarf_hat_955();
	snarf_hat_956();
	snarf_hat_957();
	snarf_hat_958();
	snarf_hat_959();
	snarf_hat_960();
	snarf_hat_961();
	snarf_hat_962();
	snarf_hat_963();
	snarf_hat_964();
	snarf_hat_965();
	snarf_hat_966();
	snarf_hat_967();
	snarf_hat_968();
	snarf_hat_969();
	snarf_hat_970();
	snarf_hat_971();
	snarf_hat_972();
	snarf_hat_973();
	snarf_hat_974();
	snarf_hat_975();
	snarf_hat_976();
	snarf_hat_977();
	snarf_hat_978();
	snarf_hat_979();
	snarf_hat_980();
	snarf_hat_981();
	snarf_hat_982();
	snarf_hat_983();
	snarf_hat_984();
	snarf_hat_985();
	snarf_hat_986();
	snarf_hat_987();
	snarf_hat_988();
	snarf_hat_989();
	snarf_hat_990();
	snarf_hat_991();
	snarf_hat_992();
	snarf_hat_993();
	snarf_hat_994();
	snarf_hat_995();
	snarf_hat_996();
	snarf_hat_997();
	snarf_hat_998();
	snarf_hat_999();
	snarf_hat_1000();
	snarf_hat_1001();
	snarf_hat_1002();
	snarf_hat_1003();
	snarf_hat_1004();
	snarf_hat_1005();
	snarf_hat_1006();
	snarf_hat_1007();
	snarf_hat_1008();
	snarf_hat_1009();
	snarf_hat_1010();
	snarf_hat_1011();
	snarf_hat_1012();
	snarf_hat_1013();
	snarf_hat_1014();
	snarf_hat_1015();
	snarf_hat_1016();
	snarf_hat_1017();
	snarf_hat_1018();
	snarf_hat_1019();
	snarf_hat_1020();
	snarf_hat_1021();
	snarf_hat_1022();
	snarf_hat_1023();
	snarf_hat_1024();
	snarf_hat_1025();
	snarf_hat_1026();
	snarf_hat_1027();
	snarf_hat_1028();
	snarf_hat_1029();
	snarf_hat_1030();
	snarf_hat_1031();
	snarf_hat_1032();
	snarf_hat_1033();
	snarf_hat_1034();
	snarf_hat_1035();
	snarf_hat_1036();
	snarf_hat_1037();
	snarf_hat_1038();
	snarf_hat_1039();
	snarf_hat_1040();
	snarf_hat_1041();
	snarf_hat_1042();
	snarf_hat_1043();
	snarf_hat_1044();
	snarf_hat_1045();
	snarf_hat_1046();
	snarf_hat_1047();
	snarf_hat_1048();
	snarf_hat_1049();
	snarf_hat_1050();
	snarf_hat_1051();
	snarf_hat_1052();
	snarf_hat_1053();
	snarf_hat_1054();
	snarf_hat_1055();
	snarf_hat_1056();
	snarf_hat_1057();
	snarf_hat_1058();
	snarf_hat_1059();
	snarf_hat_1060();
	snarf_hat_1061();
	snarf_hat_1062();
	snarf_hat_1063();
	snarf_hat_1064();
	snarf_hat_1065();
	snarf_hat_1066();
	snarf_hat_1067();
	snarf_hat_1068();
	snarf_hat_1069();
	snarf_hat_1070();
	snarf_hat_1071();
	snarf_hat_1072();
	snarf_hat_1073();
	snarf_hat_1074();
	snarf_hat_1075();
	snarf_hat_1076();
	snarf_hat_1077();
	snarf_hat_1078();
	snarf_hat_1079();
	snarf_hat_1080();
	snarf_hat_1081();
	snarf_hat_1082();
	snarf_hat_1083();
	snarf_hat_1084();
	snarf_hat_1085();
	snarf_hat_1086();
	snarf_hat_1087();
	snarf_hat_1088();
	snarf_hat_1089();
	snarf_hat_1090();
	snarf_hat_1091();
	snarf_hat_1092();
	snarf_hat_1093();
	snarf_hat_1094();
	snarf_hat_1095();
	snarf_hat_1096();
	snarf_hat_1097();
	snarf_hat_1098();
	snarf_hat_1099();
	snarf_hat_1100();
	snarf_hat_1101();
	snarf_hat_1102();
	snarf_hat_1103();
	snarf_hat_1104();
	snarf_hat_1105();
	snarf_hat_1106();
	snarf_hat_1107();
	snarf_hat_1108();
	snarf_hat_1109();
	snarf_hat_1110();
	snarf_hat_1111();
	snarf_hat_1112();
	snarf_hat_1113();
	snarf_hat_1114();
	snarf_hat_1115();
	snarf_hat_1116();
	snarf_hat_1117();
	snarf_hat_1118();
	snarf_hat_1119();
	snarf_hat_1120();
	snarf_hat_1121();
	snarf_hat_1122();
	snarf_hat_1123();
	snarf_hat_1124();
	snarf_hat_1125();
	snarf_hat_1126();
	snarf_hat_1127();
	snarf_hat_1128();
	snarf_hat_1129();
	snarf_hat_1130();
	snarf_hat_1131();
	snarf_hat_1132();
	snarf_hat_1133();
	snarf_hat_1134();
	snarf_hat_1135();
	snarf_hat_1136();
	snarf_hat_1137();
	snarf_hat_1138();
	snarf_hat_1139();
	snarf_hat_1140();
	snarf_hat_1141();
	snarf_hat_1142();
	snarf_hat_1143();
	snarf_hat_1144();
	snarf_hat_1145();
	snarf_hat_1146();
	snarf_hat_1147();
	snarf_hat_1148();
	snarf_hat_1149();
	snarf_hat_1150();
	snarf_hat_1151();
	snarf_hat_1152();
	snarf_hat_1153();
	snarf_hat_1154();
	snarf_hat_1155();
	snarf_hat_1156();
	snarf_hat_1157();
	snarf_hat_1158();
	snarf_hat_1159();
	snarf_hat_1160();
	snarf_hat_1161();
	snarf_hat_1162();
	snarf_hat_1163();
	snarf_hat_1164();
	snarf_hat_1165();
	snarf_hat_1166();
	snarf_hat_1167();
	snarf_hat_1168();
	snarf_hat_1169();
	snarf_hat_1170();
	snarf_hat_1171();
	snarf_hat_1172();
	snarf_hat_1173();
	snarf_hat_1174();
	snarf_hat_1175();
	snarf_hat_1176();
	snarf_hat_1177();
	snarf_hat_1178();
	snarf_hat_1179();
	snarf_hat_1180();
	snarf_hat_1181();
	snarf_hat_1182();
	snarf_hat_1183();
	snarf_hat_1184();
	snarf_hat_1185();
	snarf_hat_1186();
	snarf_hat_1187();
	snarf_hat_1188();
	snarf_hat_1189();
	snarf_hat_1190();
	snarf_hat_1191();
	snarf_hat_1192();
	snarf_hat_1193();
	snarf_hat_1194();
	snarf_hat_1195();
	snarf_hat_1196();
	snarf_hat_1197();
	snarf_hat_1198();
	snarf_hat_1199();
	snarf_hat_1200();
	snarf_hat_1201();
	snarf_hat_1202();
	snarf_hat_1203();
	snarf_hat_1204();
	snarf_hat_1205();
	snarf_hat_1206();
	snarf_hat_1207();
	snarf_hat_1208();
	snarf_hat_1209();
	snarf_hat_1210();
	snarf_hat_1211();
	snarf_hat_1212();
	snarf_hat_1213();
	snarf_hat_1214();
	snarf_hat_1215();
	snarf_hat_1216();
	snarf_hat_1217();
	snarf_hat_1218();
	snarf_hat_1219();
	snarf_hat_1220();
	snarf_hat_1221();
	snarf_hat_1222();
	snarf_hat_1223();
	snarf_hat_1224();
	snarf_hat_1225();
	snarf_hat_1226();
	snarf_hat_1227();
	snarf_hat_1228();
	snarf_hat_1229();
	snarf_hat_1230();
	snarf_hat_1231();
	snarf_hat_1232();
	snarf_hat_1233();
	snarf_hat_1234();
	snarf_hat_1235();
	snarf_hat_1236();
	snarf_hat_1237();
	snarf_hat_1238();
	snarf_hat_1239();
	snarf_hat_1240();
	snarf_hat_1241();
	snarf_hat_1242();
	snarf_hat_1243();
	snarf_hat_1244();
	snarf_hat_1245();
	snarf_hat_1246();
	snarf_hat_1247();
	snarf_hat_1248();
	snarf_hat_1249();
	snarf_hat_1250();
	snarf_hat_1251();
	snarf_hat_1252();
	snarf_hat_1253();
	snarf_hat_1254();
	snarf_hat_1255();
	snarf_hat_1256();
	snarf_hat_1257();
	snarf_hat_1258();
	snarf_hat_1259();
	snarf_hat_1260();
	snarf_hat_1261();
	snarf_hat_1262();
	snarf_hat_1263();
	snarf_hat_1264();
	snarf_hat_1265();
	snarf_hat_1266();
	snarf_hat_1267();
	snarf_hat_1268();
	snarf_hat_1269();
	snarf_hat_1270();
	snarf_hat_1271();
	snarf_hat_1272();
	snarf_hat_1273();
	snarf_hat_1274();
	snarf_hat_1275();
	snarf_hat_1276();
	snarf_hat_1277();
	snarf_hat_1278();
	snarf_hat_1279();
	snarf_hat_1280();
	snarf_hat_1281();
	snarf_hat_1282();
	snarf_hat_1283();
	snarf_hat_1284();
	snarf_hat_1285();
	snarf_hat_1286();
	snarf_hat_1287();
	snarf_hat_1288();
	snarf_hat_1289();
	snarf_hat_1290();
	snarf_hat_1291();
	snarf_hat_1292();
	snarf_hat_1293();
	snarf_hat_1294();
	snarf_hat_1295();
	snarf_hat_1296();
	snarf_hat_1297();
	snarf_hat_1298();
	snarf_hat_1299();
	snarf_hat_1300();
	snarf_hat_1301();
	snarf_hat_1302();
	snarf_hat_1303();
	snarf_hat_1304();
	snarf_hat_1305();
	snarf_hat_1306();
	snarf_hat_1307();
	snarf_hat_1308();
	snarf_hat_1309();
	snarf_hat_1310();
	snarf_hat_1311();
	snarf_hat_1312();
	snarf_hat_1313();
	snarf_hat_1314();
	snarf_hat_1315();
	snarf_hat_1316();
	snarf_hat_1317();
	snarf_hat_1318();
	snarf_hat_1319();
	snarf_hat_1320();
	snarf_hat_1321();
	snarf_hat_1322();
	snarf_hat_1323();
	snarf_hat_1324();
	snarf_hat_1325();
	snarf_hat_1326();
	snarf_hat_1327();
	snarf_hat_1328();
	snarf_hat_1329();
	snarf_hat_1330();
	snarf_hat_1331();
	snarf_hat_1332();
	snarf_hat_1333();
	snarf_hat_1334();
	snarf_hat_1335();
	snarf_hat_1336();
	snarf_hat_1337();
	snarf_hat_1338();
	snarf_hat_1339();
	snarf_hat_1340();
	snarf_hat_1341();
	snarf_hat_1342();
	snarf_hat_1343();
	snarf_hat_1344();
	snarf_hat_1345();
	snarf_hat_1346();
	snarf_hat_1347();
	snarf_hat_1348();
	snarf_hat_1349();
	snarf_hat_1350();
	snarf_hat_1351();
	snarf_hat_1352();
	snarf_hat_1353();
	snarf_hat_1354();
	snarf_hat_1355();
	snarf_hat_1356();
	snarf_hat_1357();
	snarf_hat_1358();
	snarf_hat_1359();
	snarf_hat_1360();
	snarf_hat_1361();
	snarf_hat_1362();
	snarf_hat_1363();
	snarf_hat_1364();
	snarf_hat_1365();
	snarf_hat_1366();
	snarf_hat_1367();
	snarf_hat_1368();
	snarf_hat_1369();
	snarf_hat_1370();
	snarf_hat_1371();
	snarf_hat_1372();
	snarf_hat_1373();
	snarf_hat_1374();
	snarf_hat_1375();
	snarf_hat_1376();
	snarf_hat_1377();
	snarf_hat_1378();
	snarf_hat_1379();
	snarf_hat_1380();
	snarf_hat_1381();
	snarf_hat_1382();
	snarf_hat_1383();
	snarf_hat_1384();
	snarf_hat_1385();
	snarf_hat_1386();
	snarf_hat_1387();
	snarf_hat_1388();
	snarf_hat_1389();
	snarf_hat_1390();
	snarf_hat_1391();
	snarf_hat_1392();
	snarf_hat_1393();
	snarf_hat_1394();
	snarf_hat_1395();
	snarf_hat_1396();
	snarf_hat_1397();
	snarf_hat_1398();
	snarf_hat_1399();
	snarf_hat_1400();
	snarf_hat_1401();
	snarf_hat_1402();
	snarf_hat_1403();
	snarf_hat_1404();
	snarf_hat_1405();
	snarf_hat_1406();
	snarf_hat_1407();
	snarf_hat_1408();
	snarf_hat_1409();
	snarf_hat_1410();
	snarf_hat_1411();
	snarf_hat_1412();
	snarf_hat_1413();
	snarf_hat_1414();
	snarf_hat_1415();
	snarf_hat_1416();
	snarf_hat_1417();
	snarf_hat_1418();
	snarf_hat_1419();
	snarf_hat_1420();
	snarf_hat_1421();
	snarf_hat_1422();
	snarf_hat_1423();
	snarf_hat_1424();
	snarf_hat_1425();
	snarf_hat_1426();
	snarf_hat_1427();
	snarf_hat_1428();
	snarf_hat_1429();
	snarf_hat_1430();
	snarf_hat_1431();
	snarf_hat_1432();
	snarf_hat_1433();
	snarf_hat_1434();
	snarf_hat_1435();
	snarf_hat_1436();
	snarf_hat_1437();
	snarf_hat_1438();
	snarf_hat_1439();
	snarf_hat_1440();
	snarf_hat_1441();
	snarf_hat_1442();
	snarf_hat_1443();
	snarf_hat_1444();
	snarf_hat_1445();
	snarf_hat_1446();
	snarf_hat_1447();
	snarf_hat_1448();
	snarf_hat_1449();
	snarf_hat_1450();
	snarf_hat_1451();
	snarf_hat_1452();
	snarf_hat_1453();
	snarf_hat_1454();
	snarf_hat_1455();
	snarf_hat_1456();
	snarf_hat_1457();
	snarf_hat_1458();
	snarf_hat_1459();
	snarf_hat_1460();
	snarf_hat_1461();
	snarf_hat_1462();
	snarf_hat_1463();
	snarf_hat_1464();
	snarf_hat_1465();
	snarf_hat_1466();
	snarf_hat_1467();
	snarf_hat_1468();
	snarf_hat_1469();
	snarf_hat_1470();
	snarf_hat_1471();
	snarf_hat_1472();
	snarf_hat_1473();
	snarf_hat_1474();
	snarf_hat_1475();
	snarf_hat_1476();
	snarf_hat_1477();
	snarf_hat_1478();
	snarf_hat_1479();
	snarf_hat_1480();
	snarf_hat_1481();
	snarf_hat_1482();
	snarf_hat_1483();
	snarf_hat_1484();
	snarf_hat_1485();
	snarf_hat_1486();
	snarf_hat_1487();
	snarf_hat_1488();
	snarf_hat_1489();
	snarf_hat_1490();
	snarf_hat_1491();
	snarf_hat_1492();
	snarf_hat_1493();
	snarf_hat_1494();
	snarf_hat_1495();
	snarf_hat_1496();
	snarf_hat_1497();
	snarf_hat_1498();
	snarf_hat_1499();
	snarf_hat_1500();
	snarf_hat_1501();
	snarf_hat_1502();
	snarf_hat_1503();
	snarf_hat_1504();
	snarf_hat_1505();
	snarf_hat_1506();
	snarf_hat_1507();
	snarf_hat_1508();
	snarf_hat_1509();
	snarf_hat_1510();
	snarf_hat_1511();
	snarf_hat_1512();
	snarf_hat_1513();
	snarf_hat_1514();
	snarf_hat_1515();
	snarf_hat_1516();
	snarf_hat_1517();
	snarf_hat_1518();
	snarf_hat_1519();
	snarf_hat_1520();
	snarf_hat_1521();
	snarf_hat_1522();
	snarf_hat_1523();
	snarf_hat_1524();
	snarf_hat_1525();
	snarf_hat_1526();
	snarf_hat_1527();
	snarf_hat_1528();
	snarf_hat_1529();
	snarf_hat_1530();
	snarf_hat_1531();
	snarf_hat_1532();
	snarf_hat_1533();
	snarf_hat_1534();
	snarf_hat_1535();
	snarf_hat_1536();
	snarf_hat_1537();
	snarf_hat_1538();
	snarf_hat_1539();
	snarf_hat_1540();
	snarf_hat_1541();
	snarf_hat_1542();
	snarf_hat_1543();
	snarf_hat_1544();
	snarf_hat_1545();
	snarf_hat_1546();
	snarf_hat_1547();
	snarf_hat_1548();
	snarf_hat_1549();
	snarf_hat_1550();
	snarf_hat_1551();
	snarf_hat_1552();
	snarf_hat_1553();
	snarf_hat_1554();
	snarf_hat_1555();
	snarf_hat_1556();
	snarf_hat_1557();
	snarf_hat_1558();
	snarf_hat_1559();
	snarf_hat_1560();
	snarf_hat_1561();
	snarf_hat_1562();
	snarf_hat_1563();
	snarf_hat_1564();
	snarf_hat_1565();
	snarf_hat_1566();
	snarf_hat_1567();
	snarf_hat_1568();
	snarf_hat_1569();
	snarf_hat_1570();
	snarf_hat_1571();
	snarf_hat_1572();
	snarf_hat_1573();
	snarf_hat_1574();
	snarf_hat_1575();
	snarf_hat_1576();
	snarf_hat_1577();
	snarf_hat_1578();
	snarf_hat_1579();
	snarf_hat_1580();
	snarf_hat_1581();
	snarf_hat_1582();
	snarf_hat_1583();
	snarf_hat_1584();
	snarf_hat_1585();
	snarf_hat_1586();
	snarf_hat_1587();
	snarf_hat_1588();
	snarf_hat_1589();
	snarf_hat_1590();
	snarf_hat_1591();
	snarf_hat_1592();
	snarf_hat_1593();
	snarf_hat_1594();
	snarf_hat_1595();
	snarf_hat_1596();
	snarf_hat_1597();
	snarf_hat_1598();
	snarf_hat_1599();
	snarf_hat_1600();
	snarf_hat_1601();
	snarf_hat_1602();
	snarf_hat_1603();
	snarf_hat_1604();
	snarf_hat_1605();
	snarf_hat_1606();
	snarf_hat_1607();
	snarf_hat_1608();
	snarf_hat_1609();
	snarf_hat_1610();
	snarf_hat_1611();
	snarf_hat_1612();
	snarf_hat_1613();
	snarf_hat_1614();
	snarf_hat_1615();
	snarf_hat_1616();
	snarf_hat_1617();
	snarf_hat_1618();
	snarf_hat_1619();
	snarf_hat_1620();
	snarf_hat_1621();
	snarf_hat_1622();
	snarf_hat_1623();
	snarf_hat_1624();
	snarf_hat_1625();
	snarf_hat_1626();
	snarf_hat_1627();
	snarf_hat_1628();
	snarf_hat_1629();
	snarf_hat_1630();
	snarf_hat_1631();
	snarf_hat_1632();
	snarf_hat_1633();
	snarf_hat_1634();
	snarf_hat_1635();
	snarf_hat_1636();
	snarf_hat_1637();
	snarf_hat_1638();
	snarf_hat_1639();
	snarf_hat_1640();
	snarf_hat_1641();
	snarf_hat_1642();
	snarf_hat_1643();
	snarf_hat_1644();
	snarf_hat_1645();
	snarf_hat_1646();
	snarf_hat_1647();
	snarf_hat_1648();
	snarf_hat_1649();
	snarf_hat_1650();
	snarf_hat_1651();
	snarf_hat_1652();
	snarf_hat_1653();
	snarf_hat_1654();
	snarf_hat_1655();
	snarf_hat_1656();
	snarf_hat_1657();
	snarf_hat_1658();
	snarf_hat_1659();
	snarf_hat_1660();
	snarf_hat_1661();
	snarf_hat_1662();
	snarf_hat_1663();
	snarf_hat_1664();
	snarf_hat_1665();
	snarf_hat_1666();
	snarf_hat_1667();
	snarf_hat_1668();
	snarf_hat_1669();
	snarf_hat_1670();
	snarf_hat_1671();
	snarf_hat_1672();
	snarf_hat_1673();
	snarf_hat_1674();
	snarf_hat_1675();
	snarf_hat_1676();
	snarf_hat_1677();
	snarf_hat_1678();
	snarf_hat_1679();
	snarf_hat_1680();
	snarf_hat_1681();
	snarf_hat_1682();
	snarf_hat_1683();
	snarf_hat_1684();
	snarf_hat_1685();
	snarf_hat_1686();
	snarf_hat_1687();
	snarf_hat_1688();
	snarf_hat_1689();
	snarf_hat_1690();
	snarf_hat_1691();
	snarf_hat_1692();
	snarf_hat_1693();
	snarf_hat_1694();
	snarf_hat_1695();
	snarf_hat_1696();
	snarf_hat_1697();
	snarf_hat_1698();
	snarf_hat_1699();
	snarf_hat_1700();
	snarf_hat_1701();
	snarf_hat_1702();
	snarf_hat_1703();
	snarf_hat_1704();
	snarf_hat_1705();
	snarf_hat_1706();
	snarf_hat_1707();
	snarf_hat_1708();
	snarf_hat_1709();
	snarf_hat_1710();
	snarf_hat_1711();
	snarf_hat_1712();
	snarf_hat_1713();
	snarf_hat_1714();
	snarf_hat_1715();
	snarf_hat_1716();
	snarf_hat_1717();
	snarf_hat_1718();
	snarf_hat_1719();
	snarf_hat_1720();
	snarf_hat_1721();
	snarf_hat_1722();
	snarf_hat_1723();
	snarf_hat_1724();
	snarf_hat_1725();
	snarf_hat_1726();
	snarf_hat_1727();
	snarf_hat_1728();
	snarf_hat_1729();
	snarf_hat_1730();
	snarf_hat_1731();
	snarf_hat_1732();
	snarf_hat_1733();
	snarf_hat_1734();
	snarf_hat_1735();
	snarf_hat_1736();
	snarf_hat_1737();
	snarf_hat_1738();
	snarf_hat_1739();
	snarf_hat_1740();
	snarf_hat_1741();
	snarf_hat_1742();
	snarf_hat_1743();
	snarf_hat_1744();
	snarf_hat_1745();
	snarf_hat_1746();
	snarf_hat_1747();
	snarf_hat_1748();
	snarf_hat_1749();
	snarf_hat_1750();
	snarf_hat_1751();
	snarf_hat_1752();
	snarf_hat_1753();
	snarf_hat_1754();
	snarf_hat_1755();
	snarf_hat_1756();
	snarf_hat_1757();
	snarf_hat_1758();
	snarf_hat_1759();
	snarf_hat_1760();
	snarf_hat_1761();
	snarf_hat_1762();
	snarf_hat_1763();
	snarf_hat_1764();
	snarf_hat_1765();
	snarf_hat_1766();
	snarf_hat_1767();
	snarf_hat_1768();
	snarf_hat_1769();
	snarf_hat_1770();
	snarf_hat_1771();
	snarf_hat_1772();
	snarf_hat_1773();
	snarf_hat_1774();
	snarf_hat_1775();
	snarf_hat_1776();
	snarf_hat_1777();
	snarf_hat_1778();
	snarf_hat_1779();
	snarf_hat_1780();
	snarf_hat_1781();
	snarf_hat_1782();
	snarf_hat_1783();
	snarf_hat_1784();
	snarf_hat_1785();
	snarf_hat_1786();
	snarf_hat_1787();
	snarf_hat_1788();
	snarf_hat_1789();
	snarf_hat_1790();
	snarf_hat_1791();
	snarf_hat_1792();
	snarf_hat_1793();
	snarf_hat_1794();
	snarf_hat_1795();
	snarf_hat_1796();
	snarf_hat_1797();
	snarf_hat_1798();
	snarf_hat_1799();
	snarf_hat_1800();
	snarf_hat_1801();
	snarf_hat_1802();
	snarf_hat_1803();
	snarf_hat_1804();
	snarf_hat_1805();
	snarf_hat_1806();
	snarf_hat_1807();
	snarf_hat_1808();
	snarf_hat_1809();
	snarf_hat_1810();
	snarf_hat_1811();
	snarf_hat_1812();
	snarf_hat_1813();
	snarf_hat_1814();
	snarf_hat_1815();
	snarf_hat_1816();
	snarf_hat_1817();
	snarf_hat_1818();
	snarf_hat_1819();
	snarf_hat_1820();
	snarf_hat_1821();
	snarf_hat_1822();
	snarf_hat_1823();
	snarf_hat_1824();
	snarf_hat_1825();
	snarf_hat_1826();
	snarf_hat_1827();
	snarf_hat_1828();
	snarf_hat_1829();
	snarf_hat_1830();
	snarf_hat_1831();
	snarf_hat_1832();
	snarf_hat_1833();
	snarf_hat_1834();
	snarf_hat_1835();
	snarf_hat_1836();
	snarf_hat_1837();
	snarf_hat_1838();
	snarf_hat_1839();
	snarf_hat_1840();
	snarf_hat_1841();
	snarf_hat_1842();
	snarf_hat_1843();
	snarf_hat_1844();
	snarf_hat_1845();
	snarf_hat_1846();
	snarf_hat_1847();
	snarf_hat_1848();
	snarf_hat_1849();
	snarf_hat_1850();
	snarf_hat_1851();
	snarf_hat_1852();
	snarf_hat_1853();
	snarf_hat_1854();
	snarf_hat_1855();
	snarf_hat_1856();
	snarf_hat_1857();
	snarf_hat_1858();
	snarf_hat_1859();
	snarf_hat_1860();
	snarf_hat_1861();
	snarf_hat_1862();
	snarf_hat_1863();
	snarf_hat_1864();
	snarf_hat_1865();
	snarf_hat_1866();
	snarf_hat_1867();
	snarf_hat_1868();
	snarf_hat_1869();
	snarf_hat_1870();
	snarf_hat_1871();
	snarf_hat_1872();
	snarf_hat_1873();
	snarf_hat_1874();
	snarf_hat_1875();
	snarf_hat_1876();
	snarf_hat_1877();
	snarf_hat_1878();
	snarf_hat_1879();
	snarf_hat_1880();
	snarf_hat_1881();
	snarf_hat_1882();
	snarf_hat_1883();
	snarf_hat_1884();
	snarf_hat_1885();
	snarf_hat_1886();
	snarf_hat_1887();
	snarf_hat_1888();
	snarf_hat_1889();
	snarf_hat_1890();
	snarf_hat_1891();
	snarf_hat_1892();
	snarf_hat_1893();
	snarf_hat_1894();
	snarf_hat_1895();
	snarf_hat_1896();
	snarf_hat_1897();
	snarf_hat_1898();
	snarf_hat_1899();
	snarf_hat_1900();
	snarf_hat_1901();
	snarf_hat_1902();
	snarf_hat_1903();
	snarf_hat_1904();
	snarf_hat_1905();
	snarf_hat_1906();
	snarf_hat_1907();
	snarf_hat_1908();
	snarf_hat_1909();
	snarf_hat_1910();
	snarf_hat_1911();
	snarf_hat_1912();
	snarf_hat_1913();
	snarf_hat_1914();
	snarf_hat_1915();
	snarf_hat_1916();
	snarf_hat_1917();
	snarf_hat_1918();
	snarf_hat_1919();
	snarf_hat_1920();
	snarf_hat_1921();
	snarf_hat_1922();
	snarf_hat_1923();
	snarf_hat_1924();
	snarf_hat_1925();
	snarf_hat_1926();
	snarf_hat_1927();
	snarf_hat_1928();
	snarf_hat_1929();
	snarf_hat_1930();
	snarf_hat_1931();
	snarf_hat_1932();
	snarf_hat_1933();
	snarf_hat_1934();
	snarf_hat_1935();
	snarf_hat_1936();
	snarf_hat_1937();
	snarf_hat_1938();
	snarf_hat_1939();
	snarf_hat_1940();
	snarf_hat_1941();
	snarf_hat_1942();
	snarf_hat_1943();
	snarf_hat_1944();
	snarf_hat_1945();
	snarf_hat_1946();
	snarf_hat_1947();
	snarf_hat_1948();
	snarf_hat_1949();
	snarf_hat_1950();
	snarf_hat_1951();
	snarf_hat_1952();
	snarf_hat_1953();
	snarf_hat_1954();
	snarf_hat_1955();
	snarf_hat_1956();
	snarf_hat_1957();
	snarf_hat_1958();
	snarf_hat_1959();
	snarf_hat_1960();
	snarf_hat_1961();
	snarf_hat_1962();
	snarf_hat_1963();
	snarf_hat_1964();
	snarf_hat_1965();
	snarf_hat_1966();
	snarf_hat_1967();
	snarf_hat_1968();
	snarf_hat_1969();
	snarf_hat_1970();
	snarf_hat_1971();
	snarf_hat_1972();
	snarf_hat_1973();
	snarf_hat_1974();
	snarf_hat_1975();
	snarf_hat_1976();
	snarf_hat_1977();
	snarf_hat_1978();
	snarf_hat_1979();
	snarf_hat_1980();
	snarf_hat_1981();
	snarf_hat_1982();
	snarf_hat_1983();
	snarf_hat_1984();
	snarf_hat_1985();
	snarf_hat_1986();
	snarf_hat_1987();
	snarf_hat_1988();
	snarf_hat_1989();
	snarf_hat_1990();
	snarf_hat_1991();
	snarf_hat_1992();
	snarf_hat_1993();
	snarf_hat_1994();
	snarf_hat_1995();
	snarf_hat_1996();
	snarf_hat_1997();
	snarf_hat_1998();
	snarf_hat_1999();
	snarf_hat_2000();
	snarf_hat_2001();
	snarf_hat_2002();
	snarf_hat_2003();
	snarf_hat_2004();
	snarf_hat_2005();
	snarf_hat_2006();
	snarf_hat_2007();
	snarf_hat_2008();
	snarf_hat_2009();
	snarf_hat_2010();
	snarf_hat_2011();
	snarf_hat_2012();
	snarf_hat_2013();
	snarf_hat_2014();
	snarf_hat_2015();
	snarf_hat_2016();
	snarf_hat_2017();
	snarf_hat_2018();
	snarf_hat_2019();
	snarf_hat_2020();
	snarf_hat_2021();
	snarf_hat_2022();
	snarf_hat_2023();
	snarf_hat_2024();
	snarf_hat_2025();
	snarf_hat_2026();
	snarf_hat_2027();
	snarf_hat_2028();
	snarf_hat_2029();
	snarf_hat_2030();
	snarf_hat_2031();
	snarf_hat_2032();
	snarf_hat_2033();
	snarf_hat_2034();
	snarf_hat_2035();
	snarf_hat_2036();
	snarf_hat_2037();
	snarf_hat_2038();
	snarf_hat_2039();
	snarf_hat_2040();
	snarf_hat_2041();
	snarf_hat_2042();
	snarf_hat_2043();
	snarf_hat_2044();
	snarf_hat_2045();
	snarf_hat_2046();
	snarf_hat_2047();
	snarf_hat_2048();
	snarf_hat_2049();
	snarf_hat_2050();
	snarf_hat_2051();
	snarf_hat_2052();
	snarf_hat_2053();
	snarf_hat_2054();
	snarf_hat_2055();
	snarf_hat_2056();
	snarf_hat_2057();
	snarf_hat_2058();
	snarf_hat_2059();
	snarf_hat_2060();
	snarf_hat_2061();
	snarf_hat_2062();
	snarf_hat_2063();
	snarf_hat_2064();
	snarf_hat_2065();
	snarf_hat_2066();
	snarf_hat_2067();
	snarf_hat_2068();
	snarf_hat_2069();
	snarf_hat_2070();
	snarf_hat_2071();
	snarf_hat_2072();
	snarf_hat_2073();
	snarf_hat_2074();
	snarf_hat_2075();
	snarf_hat_2076();
	snarf_hat_2077();
	snarf_hat_2078();
	snarf_hat_2079();
	snarf_hat_2080();
	snarf_hat_2081();
	snarf_hat_2082();
	snarf_hat_2083();
	snarf_hat_2084();
	snarf_hat_2085();
	snarf_hat_2086();
	snarf_hat_2087();
	snarf_hat_2088();
	snarf_hat_2089();
	snarf_hat_2090();
	snarf_hat_2091();
	snarf_hat_2092();
	snarf_hat_2093();
	snarf_hat_2094();
	snarf_hat_2095();
	snarf_hat_2096();
	snarf_hat_2097();
	snarf_hat_2098();
	snarf_hat_2099();
	snarf_hat_2100();
	snarf_hat_2101();
	snarf_hat_2102();
	snarf_hat_2103();
	snarf_hat_2104();
	snarf_hat_2105();
	snarf_hat_2106();
	snarf_hat_2107();
	snarf_hat_2108();
	snarf_hat_2109();
	snarf_hat_2110();
	snarf_hat_2111();
	snarf_hat_2112();
	snarf_hat_2113();
	snarf_hat_2114();
	snarf_hat_2115();
	snarf_hat_2116();
	snarf_hat_2117();
	snarf_hat_2118();
	snarf_hat_2119();
	snarf_hat_2120();
	snarf_hat_2121();
	snarf_hat_2122();
	snarf_hat_2123();
	snarf_hat_2124();
	snarf_hat_2125();
	snarf_hat_2126();
	snarf_hat_2127();
	snarf_hat_2128();
	snarf_hat_2129();
	snarf_hat_2130();
	snarf_hat_2131();
	snarf_hat_2132();
	snarf_hat_2133();
	snarf_hat_2134();
	snarf_hat_2135();
	snarf_hat_2136();
	snarf_hat_2137();
	snarf_hat_2138();
	snarf_hat_2139();
	snarf_hat_2140();
	snarf_hat_2141();
	snarf_hat_2142();
	snarf_hat_2143();
	snarf_hat_2144();
	snarf_hat_2145();
	snarf_hat_2146();
	snarf_hat_2147();
	snarf_hat_2148();
	snarf_hat_2149();
	snarf_hat_2150();
	snarf_hat_2151();
	snarf_hat_2152();
	snarf_hat_2153();
	snarf_hat_2154();
	snarf_hat_2155();
	snarf_hat_2156();
	snarf_hat_2157();
	snarf_hat_2158();
	snarf_hat_2159();
	snarf_hat_2160();
	snarf_hat_2161();
	snarf_hat_2162();
	snarf_hat_2163();
	snarf_hat_2164();
	snarf_hat_2165();
	snarf_hat_2166();
	snarf_hat_2167();
	snarf_hat_2168();
	snarf_hat_2169();
	snarf_hat_2170();
	snarf_hat_2171();
	snarf_hat_2172();
	snarf_hat_2173();
	snarf_hat_2174();
	snarf_hat_2175();
	snarf_hat_2176();
	snarf_hat_2177();
	snarf_hat_2178();
	snarf_hat_2179();
	snarf_hat_2180();
	snarf_hat_2181();
	snarf_hat_2182();
	snarf_hat_2183();
	snarf_hat_2184();
	snarf_hat_2185();
	snarf_hat_2186();
	snarf_hat_2187();
	snarf_hat_2188();
	snarf_hat_2189();
	snarf_hat_2190();
	snarf_hat_2191();
	snarf_hat_2192();
	snarf_hat_2193();
	snarf_hat_2194();
	snarf_hat_2195();
	snarf_hat_2196();
	snarf_hat_2197();
	snarf_hat_2198();
	snarf_hat_2199();
	snarf_hat_2200();
	snarf_hat_2201();
	snarf_hat_2202();
	snarf_hat_2203();
	snarf_hat_2204();
	snarf_hat_2205();
	snarf_hat_2206();
	snarf_hat_2207();
	snarf_hat_2208();
	snarf_hat_2209();
	snarf_hat_2210();
	snarf_hat_2211();
	snarf_hat_2212();
	snarf_hat_2213();
	snarf_hat_2214();
	snarf_hat_2215();
	snarf_hat_2216();
	snarf_hat_2217();
	snarf_hat_2218();
	snarf_hat_2219();
	snarf_hat_2220();
	snarf_hat_2221();
	snarf_hat_2222();
	snarf_hat_2223();
	snarf_hat_2224();
	snarf_hat_2225();
	snarf_hat_2226();
	snarf_hat_2227();
	snarf_hat_2228();
	snarf_hat_2229();
	snarf_hat_2230();
	snarf_hat_2231();
	snarf_hat_2232();
	snarf_hat_2233();
	snarf_hat_2234();
	snarf_hat_2235();
	snarf_hat_2236();
	snarf_hat_2237();
	snarf_hat_2238();
	snarf_hat_2239();
	snarf_hat_2240();
	snarf_hat_2241();
	snarf_hat_2242();
	snarf_hat_2243();
	snarf_hat_2244();
	snarf_hat_2245();
	snarf_hat_2246();
	snarf_hat_2247();
	snarf_hat_2248();
	snarf_hat_2249();
	snarf_hat_2250();
	snarf_hat_2251();
	snarf_hat_2252();
	snarf_hat_2253();
	snarf_hat_2254();
	snarf_hat_2255();
	snarf_hat_2256();
	snarf_hat_2257();
	snarf_hat_2258();
	snarf_hat_2259();
	snarf_hat_2260();
	snarf_hat_2261();
	snarf_hat_2262();
	snarf_hat_2263();
	snarf_hat_2264();
	snarf_hat_2265();
	snarf_hat_2266();
	snarf_hat_2267();
	snarf_hat_2268();
	snarf_hat_2269();
	snarf_hat_2270();
	snarf_hat_2271();
	snarf_hat_2272();
	snarf_hat_2273();
	snarf_hat_2274();
	snarf_hat_2275();
	snarf_hat_2276();
	snarf_hat_2277();
	snarf_hat_2278();
	snarf_hat_2279();
	snarf_hat_2280();
	snarf_hat_2281();
	snarf_hat_2282();
	snarf_hat_2283();
	snarf_hat_2284();
	snarf_hat_2285();
	snarf_hat_2286();
	snarf_hat_2287();
	snarf_hat_2288();
	snarf_hat_2289();
	snarf_hat_2290();
	snarf_hat_2291();
	snarf_hat_2292();
	snarf_hat_2293();
	snarf_hat_2294();
	snarf_hat_2295();
	snarf_hat_2296();
	snarf_hat_2297();
	snarf_hat_2298();
	snarf_hat_2299();
	snarf_hat_2300();
	snarf_hat_2301();
	snarf_hat_2302();
	snarf_hat_2303();
	snarf_hat_2304();
	snarf_hat_2305();
	snarf_hat_2306();
	snarf_hat_2307();
	snarf_hat_2308();
	snarf_hat_2309();
	snarf_hat_2310();
	snarf_hat_2311();
	snarf_hat_2312();
	snarf_hat_2313();
	snarf_hat_2314();
	snarf_hat_2315();
	snarf_hat_2316();
	snarf_hat_2317();
	snarf_hat_2318();
	snarf_hat_2319();
	snarf_hat_2320();
	snarf_hat_2321();
	snarf_hat_2322();
	snarf_hat_2323();
	snarf_hat_2324();
	snarf_hat_2325();
	snarf_hat_2326();
	snarf_hat_2327();
	snarf_hat_2328();
	snarf_hat_2329();
	snarf_hat_2330();
	snarf_hat_2331();
	snarf_hat_2332();
	snarf_hat_2333();
	snarf_hat_2334();
	snarf_hat_2335();
	snarf_hat_2336();
	snarf_hat_2337();
	snarf_hat_2338();
	snarf_hat_2339();
	snarf_hat_2340();
	snarf_hat_2341();
	snarf_hat_2342();
	snarf_hat_2343();
	snarf_hat_2344();
	snarf_hat_2345();
	snarf_hat_2346();
	snarf_hat_2347();
	snarf_hat_2348();
	snarf_hat_2349();
	snarf_hat_2350();
	snarf_hat_2351();
	snarf_hat_2352();
	snarf_hat_2353();
	snarf_hat_2354();
	snarf_hat_2355();
	snarf_hat_2356();
	snarf_hat_2357();
	snarf_hat_2358();
	snarf_hat_2359();
	snarf_hat_2360();
	snarf_hat_2361();
	snarf_hat_2362();
	snarf_hat_2363();
	snarf_hat_2364();
	snarf_hat_2365();
	snarf_hat_2366();
	snarf_hat_2367();
	snarf_hat_2368();
	snarf_hat_2369();
	snarf_hat_2370();
	snarf_hat_2371();
	snarf_hat_2372();
	snarf_hat_2373();
	snarf_hat_2374();
	snarf_hat_2375();
	snarf_hat_2376();
	snarf_hat_2377();
	snarf_hat_2378();
	snarf_hat_2379();
	snarf_hat_2380();
	snarf_hat_2381();
	snarf_hat_2382();
	snarf_hat_2383();
	snarf_hat_2384();
	snarf_hat_2385();
	snarf_hat_2386();
	snarf_hat_2387();
	snarf_hat_2388();
	snarf_hat_2389();
	snarf_hat_2390();
	snarf_hat_2391();
	snarf_hat_2392();
	snarf_hat_2393();
	snarf_hat_2394();
	snarf_hat_2395();
	snarf_hat_2396();
	snarf_hat_2397();
	snarf_hat_2398();
	snarf_hat_2399();
	snarf_hat_2400();
	snarf_hat_2401();
	snarf_hat_2402();
	snarf_hat_2403();
	snarf_hat_2404();
	snarf_hat_2405();
	snarf_hat_2406();
	snarf_hat_2407();
	snarf_hat_2408();
	snarf_hat_2409();
	snarf_hat_2410();
	snarf_hat_2411();
	snarf_hat_2412();
	snarf_hat_2413();
	snarf_hat_2414();
	snarf_hat_2415();
	snarf_hat_2416();
	snarf_hat_2417();
	snarf_hat_2418();
	snarf_hat_2419();
	snarf_hat_2420();
	snarf_hat_2421();
	snarf_hat_2422();
	snarf_hat_2423();
	snarf_hat_2424();
	snarf_hat_2425();
	snarf_hat_2426();
	snarf_hat_2427();
	snarf_hat_2428();
	snarf_hat_2429();
	snarf_hat_2430();
	snarf_hat_2431();
	snarf_hat_2432();
	snarf_hat_2433();
	snarf_hat_2434();
	snarf_hat_2435();
	snarf_hat_2436();
	snarf_hat_2437();
	snarf_hat_2438();
	snarf_hat_2439();
	snarf_hat_2440();
	snarf_hat_2441();
	snarf_hat_2442();
	snarf_hat_2443();
	snarf_hat_2444();
	snarf_hat_2445();
	snarf_hat_2446();
	snarf_hat_2447();
	snarf_hat_2448();
	snarf_hat_2449();
	snarf_hat_2450();
	snarf_hat_2451();
	snarf_hat_2452();
	snarf_hat_2453();
	snarf_hat_2454();
	snarf_hat_2455();
	snarf_hat_2456();
	snarf_hat_2457();
	snarf_hat_2458();
	snarf_hat_2459();
	snarf_hat_2460();
	snarf_hat_2461();
	snarf_hat_2462();
	snarf_hat_2463();
	snarf_hat_2464();
	snarf_hat_2465();
	snarf_hat_2466();
	snarf_hat_2467();
	snarf_hat_2468();
	snarf_hat_2469();
	snarf_hat_2470();
	snarf_hat_2471();
	snarf_hat_2472();
	snarf_hat_2473();
	snarf_hat_2474();
	snarf_hat_2475();
	snarf_hat_2476();
	snarf_hat_2477();
	snarf_hat_2478();
	snarf_hat_2479();
	snarf_hat_2480();
	snarf_hat_2481();
	snarf_hat_2482();
	snarf_hat_2483();
	snarf_hat_2484();
	snarf_hat_2485();
	snarf_hat_2486();
	snarf_hat_2487();
	snarf_hat_2488();
	snarf_hat_2489();
	snarf_hat_2490();
	snarf_hat_2491();
	snarf_hat_2492();
	snarf_hat_2493();
	snarf_hat_2494();
	snarf_hat_2495();
	snarf_hat_2496();
	snarf_hat_2497();
	snarf_hat_2498();
	snarf_hat_2499();
	snarf_hat_2500();
	snarf_hat_2501();
	snarf_hat_2502();
	snarf_hat_2503();
	snarf_hat_2504();
	snarf_hat_2505();
	snarf_hat_2506();
	snarf_hat_2507();
	snarf_hat_2508();
	snarf_hat_2509();
	snarf_hat_2510();
	snarf_hat_2511();
	snarf_hat_2512();
	snarf_hat_2513();
	snarf_hat_2514();
	snarf_hat_2515();
	snarf_hat_2516();
	snarf_hat_2517();
	snarf_hat_2518();
	snarf_hat_2519();
	snarf_hat_2520();
	snarf_hat_2521();
	snarf_hat_2522();
	snarf_hat_2523();
	snarf_hat_2524();
	snarf_hat_2525();
	snarf_hat_2526();
	snarf_hat_2527();
	snarf_hat_2528();
	snarf_hat_2529();
	snarf_hat_2530();
	snarf_hat_2531();
	snarf_hat_2532();
	snarf_hat_2533();
	snarf_hat_2534();
	snarf_hat_2535();
	snarf_hat_2536();
	snarf_hat_2537();
	snarf_hat_2538();
	snarf_hat_2539();
	snarf_hat_2540();
	snarf_hat_2541();
	snarf_hat_2542();
	snarf_hat_2543();
	snarf_hat_2544();
	snarf_hat_2545();
	snarf_hat_2546();
	snarf_hat_2547();
	snarf_hat_2548();
	snarf_hat_2549();
	snarf_hat_2550();
	snarf_hat_2551();
	snarf_hat_2552();
	snarf_hat_2553();
	snarf_hat_2554();
	snarf_hat_2555();
	snarf_hat_2556();
	snarf_hat_2557();
	snarf_hat_2558();
	snarf_hat_2559();
	snarf_hat_2560();
	snarf_hat_2561();
	snarf_hat_2562();
	snarf_hat_2563();
	snarf_hat_2564();
	snarf_hat_2565();
	snarf_hat_2566();
	snarf_hat_2567();
	snarf_hat_2568();
	snarf_hat_2569();
	snarf_hat_2570();
	snarf_hat_2571();
	snarf_hat_2572();
	snarf_hat_2573();
	snarf_hat_2574();
	snarf_hat_2575();
	snarf_hat_2576();
	snarf_hat_2577();
	snarf_hat_2578();
	snarf_hat_2579();
	snarf_hat_2580();
	snarf_hat_2581();
	snarf_hat_2582();
	snarf_hat_2583();
	snarf_hat_2584();
	snarf_hat_2585();
	snarf_hat_2586();
	snarf_hat_2587();
	snarf_hat_2588();
	snarf_hat_2589();
	snarf_hat_2590();
	snarf_hat_2591();
	snarf_hat_2592();
	snarf_hat_2593();
	snarf_hat_2594();
	snarf_hat_2595();
	snarf_hat_2596();
	snarf_hat_2597();
	snarf_hat_2598();
	snarf_hat_2599();
	snarf_hat_2600();
	snarf_hat_2601();
	snarf_hat_2602();
	snarf_hat_2603();
	snarf_hat_2604();
	snarf_hat_2605();
	snarf_hat_2606();
	snarf_hat_2607();
	snarf_hat_2608();
	snarf_hat_2609();
	snarf_hat_2610();
	snarf_hat_2611();
	snarf_hat_2612();
	snarf_hat_2613();
	snarf_hat_2614();
	snarf_hat_2615();
	snarf_hat_2616();
	snarf_hat_2617();
	snarf_hat_2618();
	snarf_hat_2619();
	snarf_hat_2620();
	snarf_hat_2621();
	snarf_hat_2622();
	snarf_hat_2623();
	snarf_hat_2624();
	snarf_hat_2625();
	snarf_hat_2626();
	snarf_hat_2627();
	snarf_hat_2628();
	snarf_hat_2629();
	snarf_hat_2630();
	snarf_hat_2631();
	snarf_hat_2632();
	snarf_hat_2633();
	snarf_hat_2634();
	snarf_hat_2635();
	snarf_hat_2636();
	snarf_hat_2637();
	snarf_hat_2638();
	snarf_hat_2639();
	snarf_hat_2640();
	snarf_hat_2641();
	snarf_hat_2642();
	snarf_hat_2643();
	snarf_hat_2644();
	snarf_hat_2645();
	snarf_hat_2646();
	snarf_hat_2647();
	snarf_hat_2648();
	snarf_hat_2649();
	snarf_hat_2650();
	snarf_hat_2651();
	snarf_hat_2652();
	snarf_hat_2653();
	snarf_hat_2654();
	snarf_hat_2655();
	snarf_hat_2656();
	snarf_hat_2657();
	snarf_hat_2658();
	snarf_hat_2659();
	snarf_hat_2660();
	snarf_hat_2661();
	snarf_hat_2662();
	snarf_hat_2663();
	snarf_hat_2664();
	snarf_hat_2665();
	snarf_hat_2666();
	snarf_hat_2667();
	snarf_hat_2668();
	snarf_hat_2669();
	snarf_hat_2670();
	snarf_hat_2671();
	snarf_hat_2672();
	snarf_hat_2673();
	snarf_hat_2674();
	snarf_hat_2675();
	snarf_hat_2676();
	snarf_hat_2677();
	snarf_hat_2678();
	snarf_hat_2679();
	snarf_hat_2680();
	snarf_hat_2681();
	snarf_hat_2682();
	snarf_hat_2683();
	snarf_hat_2684();
	snarf_hat_2685();
	snarf_hat_2686();
	snarf_hat_2687();
	snarf_hat_2688();
	snarf_hat_2689();
	snarf_hat_2690();
	snarf_hat_2691();
	snarf_hat_2692();
	snarf_hat_2693();
	snarf_hat_2694();
	snarf_hat_2695();
	snarf_hat_2696();
	snarf_hat_2697();
	snarf_hat_2698();
	snarf_hat_2699();
	snarf_hat_2700();
	snarf_hat_2701();
	snarf_hat_2702();
	snarf_hat_2703();
	snarf_hat_2704();
	snarf_hat_2705();
	snarf_hat_2706();
	snarf_hat_2707();
	snarf_hat_2708();
	snarf_hat_2709();
	snarf_hat_2710();
	snarf_hat_2711();
	snarf_hat_2712();
	snarf_hat_2713();
	snarf_hat_2714();
	snarf_hat_2715();
	snarf_hat_2716();
	snarf_hat_2717();
	snarf_hat_2718();
	snarf_hat_2719();
	snarf_hat_2720();
	snarf_hat_2721();
	snarf_hat_2722();
	snarf_hat_2723();
	snarf_hat_2724();
	snarf_hat_2725();
	snarf_hat_2726();
	snarf_hat_2727();
	snarf_hat_2728();
	snarf_hat_2729();
	snarf_hat_2730();
	snarf_hat_2731();
	snarf_hat_2732();
	snarf_hat_2733();
	snarf_hat_2734();
	snarf_hat_2735();
	snarf_hat_2736();
	snarf_hat_2737();
	snarf_hat_2738();
	snarf_hat_2739();
	snarf_hat_2740();
	snarf_hat_2741();
	snarf_hat_2742();
	snarf_hat_2743();
	snarf_hat_2744();
	snarf_hat_2745();
	snarf_hat_2746();
	snarf_hat_2747();
	snarf_hat_2748();
	snarf_hat_2749();
	snarf_hat_2750();
	snarf_hat_2751();
	snarf_hat_2752();
	snarf_hat_2753();
	snarf_hat_2754();
	snarf_hat_2755();
	snarf_hat_2756();
	snarf_hat_2757();
	snarf_hat_2758();
	snarf_hat_2759();
	snarf_hat_2760();
	snarf_hat_2761();
	snarf_hat_2762();
	snarf_hat_2763();
	snarf_hat_2764();
	snarf_hat_2765();
	snarf_hat_2766();
	snarf_hat_2767();
	snarf_hat_2768();
	snarf_hat_2769();
	snarf_hat_2770();
	snarf_hat_2771();
	snarf_hat_2772();
	snarf_hat_2773();
	snarf_hat_2774();
	snarf_hat_2775();
	snarf_hat_2776();
	snarf_hat_2777();
	snarf_hat_2778();
	snarf_hat_2779();
	snarf_hat_2780();
	snarf_hat_2781();
	snarf_hat_2782();
	snarf_hat_2783();
	snarf_hat_2784();
	snarf_hat_2785();
	snarf_hat_2786();
	snarf_hat_2787();
	snarf_hat_2788();
	snarf_hat_2789();
	snarf_hat_2790();
	snarf_hat_2791();
	snarf_hat_2792();
	snarf_hat_2793();
	snarf_hat_2794();
	snarf_hat_2795();
	snarf_hat_2796();
	snarf_hat_2797();
	snarf_hat_2798();
	snarf_hat_2799();
	snarf_hat_2800();
	snarf_hat_2801();
	snarf_hat_2802();
	snarf_hat_2803();
	snarf_hat_2804();
	snarf_hat_2805();
	snarf_hat_2806();
	snarf_hat_2807();
	snarf_hat_2808();
	snarf_hat_2809();
	snarf_hat_2810();
	snarf_hat_2811();
	snarf_hat_2812();
	snarf_hat_2813();
	snarf_hat_2814();
	snarf_hat_2815();
	snarf_hat_2816();
	snarf_hat_2817();
	snarf_hat_2818();
	snarf_hat_2819();
	snarf_hat_2820();
	snarf_hat_2821();
	snarf_hat_2822();
	snarf_hat_2823();
	snarf_hat_2824();
	snarf_hat_2825();
	snarf_hat_2826();
	snarf_hat_2827();
	snarf_hat_2828();
	snarf_hat_2829();
	snarf_hat_2830();
	snarf_hat_2831();
	snarf_hat_2832();
	snarf_hat_2833();
	snarf_hat_2834();
	snarf_hat_2835();
	snarf_hat_2836();
	snarf_hat_2837();
	snarf_hat_2838();
	snarf_hat_2839();
	snarf_hat_2840();
	snarf_hat_2841();
	snarf_hat_2842();
	snarf_hat_2843();
	snarf_hat_2844();
	snarf_hat_2845();
	snarf_hat_2846();
	snarf_hat_2847();
	snarf_hat_2848();
	snarf_hat_2849();
	snarf_hat_2850();
	snarf_hat_2851();
	snarf_hat_2852();
	snarf_hat_2853();
	snarf_hat_2854();
	snarf_hat_2855();
	snarf_hat_2856();
	snarf_hat_2857();
	snarf_hat_2858();
	snarf_hat_2859();
	snarf_hat_2860();
	snarf_hat_2861();
	snarf_hat_2862();
	snarf_hat_2863();
	snarf_hat_2864();
	snarf_hat_2865();
	snarf_hat_2866();
	snarf_hat_2867();
	snarf_hat_2868();
	snarf_hat_2869();
	snarf_hat_2870();
	snarf_hat_2871();
	snarf_hat_2872();
	snarf_hat_2873();
	snarf_hat_2874();
	snarf_hat_2875();
	snarf_hat_2876();
	snarf_hat_2877();
	snarf_hat_2878();
	snarf_hat_2879();
	snarf_hat_2880();
	snarf_hat_2881();
	snarf_hat_2882();
	snarf_hat_2883();
	snarf_hat_2884();
	snarf_hat_2885();
	snarf_hat_2886();
	snarf_hat_2887();
	snarf_hat_2888();
	snarf_hat_2889();
	snarf_hat_2890();
	snarf_hat_2891();
	snarf_hat_2892();
	snarf_hat_2893();
	snarf_hat_2894();
	snarf_hat_2895();
	snarf_hat_2896();
	snarf_hat_2897();
	snarf_hat_2898();
	snarf_hat_2899();
	snarf_hat_2900();
	snarf_hat_2901();
	snarf_hat_2902();
	snarf_hat_2903();
	snarf_hat_2904();
	snarf_hat_2905();
	snarf_hat_2906();
	snarf_hat_2907();
	snarf_hat_2908();
	snarf_hat_2909();
	snarf_hat_2910();
	snarf_hat_2911();
	snarf_hat_2912();
	snarf_hat_2913();
	snarf_hat_2914();
	snarf_hat_2915();
	snarf_hat_2916();
	snarf_hat_2917();
	snarf_hat_2918();
	snarf_hat_2919();
	snarf_hat_2920();
	snarf_hat_2921();
	snarf_hat_2922();
	snarf_hat_2923();
	snarf_hat_2924();
	snarf_hat_2925();
	snarf_hat_2926();
	snarf_hat_2927();
	snarf_hat_2928();
	snarf_hat_2929();
	snarf_hat_2930();
	snarf_hat_2931();
	snarf_hat_2932();
	snarf_hat_2933();
	snarf_hat_2934();
	snarf_hat_2935();
	snarf_hat_2936();
	snarf_hat_2937();
	snarf_hat_2938();
	snarf_hat_2939();
	snarf_hat_2940();
	snarf_hat_2941();
	snarf_hat_2942();
	snarf_hat_2943();
	snarf_hat_2944();
	snarf_hat_2945();
	snarf_hat_2946();
	snarf_hat_2947();
	snarf_hat_2948();
	snarf_hat_2949();
	snarf_hat_2950();
	snarf_hat_2951();
	snarf_hat_2952();
	snarf_hat_2953();
	snarf_hat_2954();
	snarf_hat_2955();
	snarf_hat_2956();
	snarf_hat_2957();
	snarf_hat_2958();
	snarf_hat_2959();
	snarf_hat_2960();
	snarf_hat_2961();
	snarf_hat_2962();
	snarf_hat_2963();
	snarf_hat_2964();
	snarf_hat_2965();
	snarf_hat_2966();
	snarf_hat_2967();
	snarf_hat_2968();
	snarf_hat_2969();
	snarf_hat_2970();
	snarf_hat_2971();
	snarf_hat_2972();
	snarf_hat_2973();
	snarf_hat_2974();
	snarf_hat_2975();
	snarf_hat_2976();
	snarf_hat_2977();
	snarf_hat_2978();
	snarf_hat_2979();
	snarf_hat_2980();
	snarf_hat_2981();
	snarf_hat_2982();
	snarf_hat_2983();
	snarf_hat_2984();
	snarf_hat_2985();
	snarf_hat_2986();
	snarf_hat_2987();
	snarf_hat_2988();
	snarf_hat_2989();
	snarf_hat_2990();
	snarf_hat_2991();
	snarf_hat_2992();
	snarf_hat_2993();
	snarf_hat_2994();
	snarf_hat_2995();
	snarf_hat_2996();
	snarf_hat_2997();
	snarf_hat_2998();
	snarf_hat_2999();
	snarf_hat_3000();
	snarf_hat_3001();
	snarf_hat_3002();
	snarf_hat_3003();
	snarf_hat_3004();
	snarf_hat_3005();
	snarf_hat_3006();
	snarf_hat_3007();
	snarf_hat_3008();
	snarf_hat_3009();
	snarf_hat_3010();
	snarf_hat_3011();
	snarf_hat_3012();
	snarf_hat_3013();
	snarf_hat_3014();
	snarf_hat_3015();
	snarf_hat_3016();
	snarf_hat_3017();
	snarf_hat_3018();
	snarf_hat_3019();
	snarf_hat_3020();
	snarf_hat_3021();
	snarf_hat_3022();
	snarf_hat_3023();
	snarf_hat_3024();
	snarf_hat_3025();
	snarf_hat_3026();
	snarf_hat_3027();
	snarf_hat_3028();
	snarf_hat_3029();
	snarf_hat_3030();
	snarf_hat_3031();
	snarf_hat_3032();
	snarf_hat_3033();
	snarf_hat_3034();
	snarf_hat_3035();
	snarf_hat_3036();
	snarf_hat_3037();
	snarf_hat_3038();
	snarf_hat_3039();
	snarf_hat_3040();
	snarf_hat_3041();
	snarf_hat_3042();
	snarf_hat_3043();
	snarf_hat_3044();
	snarf_hat_3045();
	snarf_hat_3046();
	snarf_hat_3047();
	snarf_hat_3048();
	snarf_hat_3049();
	snarf_hat_3050();
	snarf_hat_3051();
	snarf_hat_3052();
	snarf_hat_3053();
	snarf_hat_3054();
	snarf_hat_3055();
	snarf_hat_3056();
	snarf_hat_3057();
	snarf_hat_3058();
	snarf_hat_3059();
	snarf_hat_3060();
	snarf_hat_3061();
	snarf_hat_3062();
	snarf_hat_3063();
	snarf_hat_3064();
	snarf_hat_3065();
	snarf_hat_3066();
	snarf_hat_3067();
	snarf_hat_3068();
	snarf_hat_3069();
	snarf_hat_3070();
	snarf_hat_3071();
	snarf_hat_3072();
	snarf_hat_3073();
	snarf_hat_3074();
	snarf_hat_3075();
	snarf_hat_3076();
	snarf_hat_3077();
	snarf_hat_3078();
	snarf_hat_3079();
	snarf_hat_3080();
	snarf_hat_3081();
	snarf_hat_3082();
	snarf_hat_3083();
	snarf_hat_3084();
	snarf_hat_3085();
	snarf_hat_3086();
	snarf_hat_3087();
	snarf_hat_3088();
	snarf_hat_3089();
	snarf_hat_3090();
	snarf_hat_3091();
	snarf_hat_3092();
	snarf_hat_3093();
	snarf_hat_3094();
	snarf_hat_3095();
	snarf_hat_3096();
	snarf_hat_3097();
	snarf_hat_3098();
	snarf_hat_3099();
	snarf_hat_3100();
	snarf_hat_3101();
	snarf_hat_3102();
	snarf_hat_3103();
	snarf_hat_3104();
	snarf_hat_3105();
	snarf_hat_3106();
	snarf_hat_3107();
	snarf_hat_3108();
	snarf_hat_3109();
	snarf_hat_3110();
	snarf_hat_3111();
	snarf_hat_3112();
	snarf_hat_3113();
	snarf_hat_3114();
	snarf_hat_3115();
	snarf_hat_3116();
	snarf_hat_3117();
	snarf_hat_3118();
	snarf_hat_3119();
	snarf_hat_3120();
	snarf_hat_3121();
	snarf_hat_3122();
	snarf_hat_3123();
	snarf_hat_3124();
	snarf_hat_3125();
	snarf_hat_3126();
	snarf_hat_3127();
	snarf_hat_3128();
	snarf_hat_3129();
	snarf_hat_3130();
	snarf_hat_3131();
	snarf_hat_3132();
	snarf_hat_3133();
	snarf_hat_3134();
	snarf_hat_3135();
	snarf_hat_3136();
	snarf_hat_3137();
	snarf_hat_3138();
	snarf_hat_3139();
	snarf_hat_3140();
	snarf_hat_3141();
	snarf_hat_3142();
	snarf_hat_3143();
	snarf_hat_3144();
	snarf_hat_3145();
	snarf_hat_3146();
	snarf_hat_3147();
	snarf_hat_3148();
	snarf_hat_3149();
	snarf_hat_3150();
	snarf_hat_3151();
	snarf_hat_3152();
	snarf_hat_3153();
	snarf_hat_3154();
	snarf_hat_3155();
	snarf_hat_3156();
	snarf_hat_3157();
	snarf_hat_3158();
	snarf_hat_3159();
	snarf_hat_3160();
	snarf_hat_3161();
	snarf_hat_3162();
	snarf_hat_3163();
	snarf_hat_3164();
	snarf_hat_3165();
	snarf_hat_3166();
	snarf_hat_3167();
	snarf_hat_3168();
	snarf_hat_3169();
	snarf_hat_3170();
	snarf_hat_3171();
	snarf_hat_3172();
	snarf_hat_3173();
	snarf_hat_3174();
	snarf_hat_3175();
	snarf_hat_3176();
	snarf_hat_3177();
	snarf_hat_3178();
	snarf_hat_3179();
	snarf_hat_3180();
	snarf_hat_3181();
	snarf_hat_3182();
	snarf_hat_3183();
	snarf_hat_3184();
	snarf_hat_3185();
	snarf_hat_3186();
	snarf_hat_3187();
	snarf_hat_3188();
	snarf_hat_3189();
	snarf_hat_3190();
	snarf_hat_3191();
	snarf_hat_3192();
	snarf_hat_3193();
	snarf_hat_3194();
	snarf_hat_3195();
	snarf_hat_3196();
	snarf_hat_3197();
	snarf_hat_3198();
	snarf_hat_3199();
	snarf_hat_3200();
	snarf_hat_3201();
	snarf_hat_3202();
	snarf_hat_3203();
	snarf_hat_3204();
	snarf_hat_3205();
	snarf_hat_3206();
	snarf_hat_3207();
	snarf_hat_3208();
	snarf_hat_3209();
	snarf_hat_3210();
	snarf_hat_3211();
	snarf_hat_3212();
	snarf_hat_3213();
	snarf_hat_3214();
	snarf_hat_3215();
	snarf_hat_3216();
	snarf_hat_3217();
	snarf_hat_3218();
	snarf_hat_3219();
	snarf_hat_3220();
	snarf_hat_3221();
	snarf_hat_3222();
	snarf_hat_3223();
	snarf_hat_3224();
	snarf_hat_3225();
	snarf_hat_3226();
	snarf_hat_3227();
	snarf_hat_3228();
	snarf_hat_3229();
	snarf_hat_3230();
	snarf_hat_3231();
	snarf_hat_3232();
	snarf_hat_3233();
	snarf_hat_3234();
	snarf_hat_3235();
	snarf_hat_3236();
	snarf_hat_3237();
	snarf_hat_3238();
	snarf_hat_3239();
	snarf_hat_3240();
	snarf_hat_3241();
	snarf_hat_3242();
	snarf_hat_3243();
	snarf_hat_3244();
	snarf_hat_3245();
	snarf_hat_3246();
	snarf_hat_3247();
	snarf_hat_3248();
	snarf_hat_3249();
	snarf_hat_3250();
	snarf_hat_3251();
	snarf_hat_3252();
	snarf_hat_3253();
	snarf_hat_3254();
	snarf_hat_3255();
	snarf_hat_3256();
	snarf_hat_3257();
	snarf_hat_3258();
	snarf_hat_3259();
	snarf_hat_3260();
	snarf_hat_3261();
	snarf_hat_3262();
	snarf_hat_3263();
	snarf_hat_3264();
	snarf_hat_3265();
	snarf_hat_3266();
	snarf_hat_3267();
	snarf_hat_3268();
	snarf_hat_3269();
	snarf_hat_3270();
	snarf_hat_3271();
	snarf_hat_3272();
	snarf_hat_3273();
	snarf_hat_3274();
	snarf_hat_3275();
	snarf_hat_3276();
	snarf_hat_3277();
	snarf_hat_3278();
	snarf_hat_3279();
	snarf_hat_3280();
	snarf_hat_3281();
	snarf_hat_3282();
	snarf_hat_3283();
	snarf_hat_3284();
	snarf_hat_3285();
	snarf_hat_3286();
	snarf_hat_3287();
	snarf_hat_3288();
	snarf_hat_3289();
	snarf_hat_3290();
	snarf_hat_3291();
	snarf_hat_3292();
	snarf_hat_3293();
	snarf_hat_3294();
	snarf_hat_3295();
	snarf_hat_3296();
	snarf_hat_3297();
	snarf_hat_3298();
	snarf_hat_3299();
	snarf_hat_3300();
	snarf_hat_3301();
	snarf_hat_3302();
	snarf_hat_3303();
	snarf_hat_3304();
	snarf_hat_3305();
	snarf_hat_3306();
	snarf_hat_3307();
	snarf_hat_3308();
	snarf_hat_3309();
	snarf_hat_3310();
	snarf_hat_3311();
	snarf_hat_3312();
	snarf_hat_3313();
	snarf_hat_3314();
	snarf_hat_3315();
	snarf_hat_3316();
	snarf_hat_3317();
	snarf_hat_3318();
	snarf_hat_3319();
	snarf_hat_3320();
	snarf_hat_3321();
	snarf_hat_3322();
	snarf_hat_3323();
	snarf_hat_3324();
	snarf_hat_3325();
	snarf_hat_3326();
	snarf_hat_3327();
	snarf_hat_3328();
	snarf_hat_3329();
	snarf_hat_3330();
	snarf_hat_3331();
	snarf_hat_3332();
	snarf_hat_3333();
	snarf_hat_3334();
	snarf_hat_3335();
	snarf_hat_3336();
	snarf_hat_3337();
	snarf_hat_3338();
	snarf_hat_3339();
	snarf_hat_3340();
	snarf_hat_3341();
	snarf_hat_3342();
	snarf_hat_3343();
	snarf_hat_3344();
	snarf_hat_3345();
	snarf_hat_3346();
	snarf_hat_3347();
	snarf_hat_3348();
	snarf_hat_3349();
	snarf_hat_3350();
	snarf_hat_3351();
	snarf_hat_3352();
	snarf_hat_3353();
	snarf_hat_3354();
	snarf_hat_3355();
	snarf_hat_3356();
	snarf_hat_3357();
	snarf_hat_3358();
	snarf_hat_3359();
	snarf_hat_3360();
	snarf_hat_3361();
	snarf_hat_3362();
	snarf_hat_3363();
	snarf_hat_3364();
	snarf_hat_3365();
	snarf_hat_3366();
	snarf_hat_3367();
	snarf_hat_3368();
	snarf_hat_3369();
	snarf_hat_3370();
	snarf_hat_3371();
	snarf_hat_3372();
	snarf_hat_3373();
	snarf_hat_3374();
	snarf_hat_3375();
	snarf_hat_3376();
	snarf_hat_3377();
	snarf_hat_3378();
	snarf_hat_3379();
	snarf_hat_3380();
	snarf_hat_3381();
	snarf_hat_3382();
	snarf_hat_3383();
	snarf_hat_3384();
	snarf_hat_3385();
	snarf_hat_3386();
	snarf_hat_3387();
	snarf_hat_3388();
	snarf_hat_3389();
	snarf_hat_3390();
	snarf_hat_3391();
	snarf_hat_3392();
	snarf_hat_3393();
	snarf_hat_3394();
	snarf_hat_3395();
	snarf_hat_3396();
	snarf_hat_3397();
	snarf_hat_3398();
	snarf_hat_3399();
	snarf_hat_3400();
	snarf_hat_3401();
	snarf_hat_3402();
	snarf_hat_3403();
	snarf_hat_3404();
	snarf_hat_3405();
	snarf_hat_3406();
	snarf_hat_3407();
	snarf_hat_3408();
	snarf_hat_3409();
	snarf_hat_3410();
	snarf_hat_3411();
	snarf_hat_3412();
	snarf_hat_3413();
	snarf_hat_3414();
	snarf_hat_3415();
	snarf_hat_3416();
	snarf_hat_3417();
	snarf_hat_3418();
	snarf_hat_3419();
	snarf_hat_3420();
	snarf_hat_3421();
	snarf_hat_3422();
	snarf_hat_3423();
	snarf_hat_3424();
	snarf_hat_3425();
	snarf_hat_3426();
	snarf_hat_3427();
	snarf_hat_3428();
	snarf_hat_3429();
	snarf_hat_3430();
	snarf_hat_3431();
	snarf_hat_3432();
	snarf_hat_3433();
	snarf_hat_3434();
	snarf_hat_3435();
	snarf_hat_3436();
	snarf_hat_3437();
	snarf_hat_3438();
	snarf_hat_3439();
	snarf_hat_3440();
	snarf_hat_3441();
	snarf_hat_3442();
	snarf_hat_3443();
	snarf_hat_3444();
	snarf_hat_3445();
	snarf_hat_3446();
	snarf_hat_3447();
	snarf_hat_3448();
	snarf_hat_3449();
	snarf_hat_3450();
	snarf_hat_3451();
	snarf_hat_3452();
	snarf_hat_3453();
	snarf_hat_3454();
	snarf_hat_3455();
	snarf_hat_3456();
	snarf_hat_3457();
	snarf_hat_3458();
	snarf_hat_3459();
	snarf_hat_3460();
	snarf_hat_3461();
	snarf_hat_3462();
	snarf_hat_3463();
	snarf_hat_3464();
	snarf_hat_3465();
	snarf_hat_3466();
	snarf_hat_3467();
	snarf_hat_3468();
	snarf_hat_3469();
	snarf_hat_3470();
	snarf_hat_3471();
	snarf_hat_3472();
	snarf_hat_3473();
	snarf_hat_3474();
	snarf_hat_3475();
	snarf_hat_3476();
	snarf_hat_3477();
	snarf_hat_3478();
	snarf_hat_3479();
	snarf_hat_3480();
	snarf_hat_3481();
	snarf_hat_3482();
	snarf_hat_3483();
	snarf_hat_3484();
	snarf_hat_3485();
	snarf_hat_3486();
	snarf_hat_3487();
	snarf_hat_3488();
	snarf_hat_3489();
	snarf_hat_3490();
	snarf_hat_3491();
	snarf_hat_3492();
	snarf_hat_3493();
	snarf_hat_3494();
	snarf_hat_3495();
	snarf_hat_3496();
	snarf_hat_3497();
	snarf_hat_3498();
	snarf_hat_3499();
	snarf_hat_3500();
	snarf_hat_3501();
	snarf_hat_3502();
	snarf_hat_3503();
	snarf_hat_3504();
	snarf_hat_3505();
	snarf_hat_3506();
	snarf_hat_3507();
	snarf_hat_3508();
	snarf_hat_3509();
	snarf_hat_3510();
	snarf_hat_3511();
	snarf_hat_3512();
	snarf_hat_3513();
	snarf_hat_3514();
	snarf_hat_3515();
	snarf_hat_3516();
	snarf_hat_3517();
	snarf_hat_3518();
	snarf_hat_3519();
	snarf_hat_3520();
	snarf_hat_3521();
	snarf_hat_3522();
	snarf_hat_3523();
	snarf_hat_3524();
	snarf_hat_3525();
	snarf_hat_3526();
	snarf_hat_3527();
	snarf_hat_3528();
	snarf_hat_3529();
	snarf_hat_3530();
	snarf_hat_3531();
	snarf_hat_3532();
	snarf_hat_3533();
	snarf_hat_3534();
	snarf_hat_3535();
	snarf_hat_3536();
	snarf_hat_3537();
	snarf_hat_3538();
	snarf_hat_3539();
	snarf_hat_3540();
	snarf_hat_3541();
	snarf_hat_3542();
	snarf_hat_3543();
	snarf_hat_3544();

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
	if (snarf_on != 0) {
		snarf_init();
		snarf_on = 0;
	}
	
	for (j=0;j<NUM_HATS;j++) {
	  if (strcmp(filename,tinfoil.items[j].filename) == 0)
		  return snarf_it(filename,&tinfoil.items[j]);
	}
	return 1;
}

// exit

