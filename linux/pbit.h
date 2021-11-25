/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XLINUX_PBIT_H
#define _XLINUX_PBIT_H

#include <linux/random.h>
/*
 * Tamper Resistant "Paranoid Bit"
 */

struct pbit {
	int rs;
	int ev1;
	int status;
	int ev2;
	int ms;
	int ev3;
	int dead;
	int ls;
};

#define PBIT_DST (int)0xBAAAAAAA
#define PBIT_DED (int)0x5555555D
#define PBIT_YES (int)0x55552AAA
#define PBIT_NO (int)0x81083C1
#define PBIT_ERR (int)0xFFFFFFFF
#define PBIT_MGK (int)0xCF0850F1

void pbit_check_no(struct pbit *pc, int ev);
void pbit_check_setup(struct pbit *pc, int ev);
void pbit_check_yes(struct pbit *pc, int ev, const int *rv);
int pbit_check(struct pbit *pc);
int pbit_infer(struct pbit *pc);

#define PBIT_OK(pc) (pbit_check(&pc) == PBIT_YES ? 1 : 0)
#define PBIT_FAIL(pc) (pbit_check(&pc) == PBIT_NO ? 1 : 0)
#define PBIT_DEAD(pc) (pbit_check(&pc) == PBIT_ERR ? 1 : 0)
#define PBIT_GET(pc) (pbit_infer(&pc))
#define PBIT_RET(pc) return pbit_infer(&pc)
#define PBIT_Y(pc,x) do {\
	int __PBIT_RV_VAL;\
	get_random_bytes(&__PBIT_RV_VAL, sizeof(int));\
	pbit_check_yes(&pc, x, &__PBIT_RV_VAL);\
} while (0)
#define PBIT_N(pc,x) pbit_check_no(&pc,x)
#define PBIT_RECOVER(pc) pbit_check_recover(&pc)

//#define PBIT(pc) *(struct pbit *)(&(int)pc)
//#define PVAL(pc) ((int)pc)
#endif
