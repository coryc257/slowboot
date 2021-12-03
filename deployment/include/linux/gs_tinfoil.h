/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X_GS_TINFOIL_H
#define _X_GS_TINFOIL_H

#include <linux/gs_tinfoil_slowboot.h>

#ifdef CONFIG_TINFOIL
void tinfoil_verify(void)
{
	__gs_tinfoil_verify();
}
#else
void tinfoil_verify(void)
{

}
#endif

#endif
