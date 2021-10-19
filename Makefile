PWD	:= $(shell pwd)
obj-m	+= slowboot.o

all:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
	make -C /usr/lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

