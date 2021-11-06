PWD	:= $(shell pwd)
obj-m	+= slowboot.o
#obj-m += rsa_test.o

default:
	make -e CPPFLAGS=-O0 -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
all:
	make -e CPPFLAGS=-O0 -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

