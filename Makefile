PWD	:= $(shell pwd)
obj-m	+= slowboot.o
#obj-m += rsa_test.o
EXTRA_CFLAGS = -O0 -D"SLOWBOOT_MODULE=1"
default:
	make -e -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
all:
	make -e -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

