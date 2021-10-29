OVERLAY_DIR=../module
#DRIVER = chacha_poly_driver.ko

ifneq ($(KERNELRELEASE),)
	chacha_poly_driver-y := \
		chacha_poly_drv.o
	obj-m += chacha_poly_driver.o
else

PWD := $(shell pwd)
KDIR := $(PWD)/../linux

default:
	$(MAKE) -C $(KDIR) ARCH=riscv SUBDIRS=$(PWD) modules

#copy:
#	cp $(DRIVER) $(OVERLAY_DIR)

endif

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd

#cat /proc/modules
#mknod /dev/simple-driver c  237 0
#major number
