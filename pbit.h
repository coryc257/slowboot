#ifndef _LINUX_PBIT_H
#define _LINUX_PBIT_H
typedef struct pbit_container {
	int rs;
	int status;
	int ms;
	int dead;
	int ls;
} pbit;

#define PBIT_DST 0xBAAAAAAA
#define PBIT_DED 0x5555555D
#define PBIT_YES 0x55552AAA
#define PBIT_NO 0x81083C1
#define PBIT_ERR 0xFFFFFFFF

static void pbit_check_fail(pbit *pc);
static void pbit_check_setup(pbit *pc);
static void pbit_check_success(pbit *pc);
static int pbit_check(pbit *pc);
#endif
