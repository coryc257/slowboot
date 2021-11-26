PWD	:= $(shell pwd)
obj-m	+= slowboot.o
slowboot-objs := gs_tinfoil_slowboot.o x_pbit.o template_slowboot.o
#obj-m += rsa_test.o
EXTRA_CFLAGS:= -DSLOWBOOT_MODULE=1
default:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
all:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

