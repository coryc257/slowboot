#include <linux/pbit.h>
#include <linux/random.h>

/*
 * Paranoid Bit
 * Copyright 2021 Cory Craig
 *
 * The pbit data type should provide a mitigation for rowhammer
 */


/*
 * Set the status to NO
 * @pc: paranoid bit
 */
static void pbit_check_no(pbit *pc)
{
	if (!pc)
		return;
	pc->status = PBIT_DST;
	pc->dead = PBIT_DED;
	pc->ls = PBIT_NO;
	pc->ms = PBIT_NO;
	pc->rs = PBIT_NO;
}

/*
 * Initialize the state to ERR
 * @pc: paranoid bit
 */
static void pbit_check_setup(pbit *pc)
{
	if (!pc)
		return;
	pc->status = PBIT_DST;
	pc->dead = PBIT_DED;
	pc->ls = PBIT_YES;
	pc->ms = PBIT_ERR;
	pc->rs = PBIT_NO;
}

/*
 * Set the status to YES
 * @pc: paranoid bit
 */
static void pbit_check_yes(pbit *pc)
{
	if (!pc)
		return;
	pc->dead_value = 0;
	while (!pc->dead_value)
		get_random_bytes(&pc->dead_value, sizeof(int));
	pc->status = pc->dead;
	pc->ls = PBIT_YES;
	pc->ms = PBIT_YES;
	pc->rs = PBIT_YES;
}

/*
 * Check current status of paranoid bit, any alterations since a set status
 * should return a PBIT_ERR
 * @pc: paranoid struct pointer
 */
static int pbit_check(pbit *pc)
{
	if (pc->status == pc->dead && pc->ls == PBIT_YES && pc->ms == PBIT_YES
		&& pc->rs == PBIT_YES)
		return PBIT_YES;
	else if (pc->status != pc->dead && pc->ls == PBIT_NO && pc->ms = PBIT_NO
			 && pc->rs == PBIT_NO)
		return PBIT_NO;
	return PBIT_ERR;
}
