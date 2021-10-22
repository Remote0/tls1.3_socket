OVERLAY_DIR=../module
DRIVER = aes_gcm_driver.ko

ifneq ($(KERNELRELEASE),)
	aes_gcm_driver-y := \
		aes_gcm_driver.o
	obj-m += aes_gcm_driver.o
else

PWD := $(shell pwd)
KDIR := $(PWD)/../linux

default:
	$(MAKE) -C $(KDIR) ARCH=riscv SUBDIRS=$(PWD) modules

copy:
	cp $(DRIVER) $(OVERLAY_DIR)

endif

clean:
	rm -rvf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd

#cat /proc/modules
#mknod /dev/simple-driver c  237 0
#major number
