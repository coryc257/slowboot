// SPDX-License-Identifier: GPL-2.0
#include <linux/gs_pbit.h>

/*
 * Copyright Cory Craig <gs.cory.craig@gmail.com> 2021
 *
 * 'Paranoid Bit'
 *
 * The pbit data type should provide a mitigation for rowhammer as well
 * as other situations where the processor/memory cannot be trusted completely
 * such as unintentional or intentional radiation energizing a bit(s)
 * This can be useful when you set a status for a permission check and then
 * have cleanup to perform and an attacker my try to flip a status variable
 */

/*
 * Set the status to NO
 * @pc: paranoid bit
 */
void pbit_check_no(struct pbit *pc, int ev)
{
	if (!pc)
		return;
	pc->status = PBIT_DST;
	pc->dead = PBIT_DED;
	pc->ls = PBIT_NO;
	pc->ms = PBIT_NO;
	pc->rs = PBIT_NO;
	pc->ev1 = ev;
	pc->ev2 = ev;
	pc->ev3 = ev;
}
/*
 * Initialize the state to ERR
 * @pc: paranoid bit
 */
void pbit_check_setup(struct pbit *pc, int ev)
{
	if (!pc)
		return;
	pc->status = PBIT_DST;
	pc->dead = PBIT_DED;
	pc->ls = PBIT_YES;
	pc->ms = PBIT_ERR;
	pc->rs = PBIT_NO;
	pc->ev1 = ev;
	pc->ev2 = ev;
	pc->ev3 = ev;
}

/*
 * Set the status to YES
 * @pc: paranoid bit
 */
void pbit_check_yes(struct pbit *pc, int ev, const int *rv)
{
	if (!pc)
		return;
	if(rv)
		pc->dead = *rv;
	else
		pc->dead = PBIT_MGK;
	pc->status = pc->dead;
	pc->ls = PBIT_YES;
	pc->ms = PBIT_YES;
	pc->rs = PBIT_YES;
	pc->ev1 = ev;
	pc->ev2 = ev;
	pc->ev3 = ev;
}

/*
 * Check current status of paranoid bit, any alterations since a set status
 * should return a PBIT_ERR
 * @pc: paranoid bit
 */
int pbit_check(struct pbit *pc)
{
	struct pbit pc_copy;
	if (!pc)
		return PBIT_ERR;
	pc_copy = *pc;
	if (pc_copy.status == pc_copy.dead && pc_copy.ls == PBIT_YES
	    && pc_copy.ms == PBIT_YES && pc_copy.rs == PBIT_YES
	    && pc_copy.status != PBIT_ERR && pc_copy.ev1 == pc_copy.ev2
	    && pc_copy.ev1 == pc_copy.ev3) {
		*pc = pc_copy;
		return PBIT_YES;
	}
	else if (pc_copy.status == PBIT_DST && pc_copy.dead == PBIT_DED
		 && pc_copy.ls == PBIT_NO && pc_copy.ms == PBIT_NO
		 && pc_copy.rs == PBIT_NO && pc_copy.ev1 == pc_copy.ev2
		 && pc_copy.ev1 == pc_copy.ev3) {
		*pc = pc_copy;
		return PBIT_NO;
	}
	*pc = pc_copy;
	return PBIT_ERR;
}

/*
 * Infer the value out of the pbit, failure is always -EINVAL
 * @pc: paranoid bit
 */
int pbit_infer(struct pbit *pc)
{
	struct pbit pc_copy;
	pc_copy = *pc;
	switch(pbit_check(&pc_copy)) {
	case PBIT_ERR:
		return PBIT_ERR;
		break;
	default:
		*pc = pc_copy;
		return pc_copy.ev2;
		break;
	}
}

/*
 * Attempt to recover the value, sets pbit value to PBIT_ERR
 * @pc: paranoid bit
 */
void pbit_check_recover(struct pbit *pc)
{
	struct pbit pc_copy;
	pc_copy = *pc;
	if (pc_copy.ev1 == pc_copy.ev2 && pc_copy.ev3 == pc_copy.ev1)
		pbit_check_setup(&pc_copy, pc_copy.ev1);
	else if (pc_copy.ev1 == pc_copy.ev2 || pc_copy.ev1 == pc_copy.ev3)
		pbit_check_setup(&pc_copy, pc_copy.ev1);
	else if (pc_copy.ev2 == pc_copy.ev3)
		pbit_check_setup(&pc_copy, pc_copy.ev3);
	else
		pbit_check_setup(&pc_copy, PBIT_ERR);
	*pc = pc_copy;
}
