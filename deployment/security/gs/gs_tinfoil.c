// SPDX-License-Identifier: GPL-2.0
/*
 * GS Tinfoil Pre Init Integrity Check
 * Copyright (C) 2021 Cory Craig
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/gs_tinfoil.h>

/*
 * Verify boot files chaining off a trusted kernel
 * There should be an LSM hook for this to avoid
 * conditional compilation
 */
int tinfoil_verify(void)
{
	if (IS_ENABLED(CONFIG_TINFOIL))
		return __gs_tinfoil_verify();
	return 0;
}
