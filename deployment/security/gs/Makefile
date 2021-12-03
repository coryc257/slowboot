# SPDX-License-Identifier: GPL-2.0
#
# Makefile for building the GS Security Items
#
obj-$(CONFIG_GS_BASE) += gs_pbit.o gs_tinfoil_slowboot.o

ifdef CONFIG_TINFOIL
obj-y += gs_tinfoil_internal.o
endif

ifdef CONFIG_SLOWBOOT
obj-m += gs_slowboot.o
endif
