# SPDX-License-Identifier: GPL-2.0
#
# Makefile for building the GS Security Items
#
# This enables generic apis other modules may choose to use
obj-$(CONFIG_GS_BASE) += gs_pbit.o gs_tinfoil_slowboot.o

# This enables the LSM hook
ifdef CONFIG_TINFOIL
obj-y += gs_tinfoil_internal.o
endif

# This enables creation of the gs_slowboot.ko module
ifdef CONFIG_SLOWBOOT
obj-m += gs_slowboot.o
endif
