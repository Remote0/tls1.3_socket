linux_module_srcdir := $(abspath .)/testdriver
crypto_module_srcdir := $(abspath .)/crypto_driver

linux_srcdir := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/linux.build
uec_root := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/overlay/root

linux_module_wrkdir := $(abspath .)/testdriver_build
linux_module := $(linux_module_wrkdir)/testdriver.ko

buildroot_rootfs_overlay_dir := $(abspath .)/module
ISA ?= rv64gc
ABI ?= lp64d
CC := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/riscv64/bin/riscv64-unknown-linux-gnu-gcc	
CFLAGS := -Wall -g -Wl,-Bstatic

#------------aes-gcm------------#
aes_gcm_module_wrkdir := $(abspath .)/aes_gcm_driver.build
aes_gcm_module := $(aes_gcm_module_wrkdir)/aes_gcm_driver.ko
#################################

#-----------Software------------#
linux_testsoft := $(linux_module_wrkdir)/testsoft
aes_gcm_testsoft := $(linux_module_wrkdir)/aes_gcm_test
#################################

aes-gcm:
	rm -rf $(aes_gcm_module_wrkdir)
	mkdir -p $(aes_gcm_module_wrkdir)
	cp -r $(crypto_module_srcdir)/* $(aes_gcm_module_wrkdir)
	$(MAKE) -C $(linux_srcdir) O=$(linux_srcdir) \
		CROSS_COMPILE=riscv64-unknown-linux-gnu- \
		ARCH=riscv \
		M=$(aes_gcm_module_wrkdir) \
		modules
	mkdir -p $(buildroot_rootfs_overlay_dir)/root
	cp $(aes_gcm_module) $(buildroot_rootfs_overlay_dir)/root
	cp $(aes_gcm_module) /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/overlay/root

# $(linux_module):
# 	rm -rf $(linux_module_wrkdir)
# 	mkdir -p $(linux_module_wrkdir)
# 	cp -r $(linux_module_srcdir)/* $(linux_module_wrkdir)
# 	$(MAKE) -C $(linux_srcdir) O=$(linux_srcdir) \
# 		CROSS_COMPILE=riscv64-unknown-linux-gnu- \
# 		ARCH=riscv \
# 		M=$(linux_module_wrkdir) \
# 		modules
# 	mkdir -p $(buildroot_rootfs_overlay_dir)/root
# 	cp $(linux_module) $(buildroot_rootfs_overlay_dir)/root
# 	cp $(linux_module) /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/overlay/root

# $(linux_module_wrkdir)/%.o: %.c
# 	$(CC) $(CFLAGS) -c -o $@ $<


# Software test

testsoft: $(linux_module_wrkdir)/testsoft.o
	$(CC) -o $(linux_module_wrkdir)/testsoft $(linux_module_wrkdir)/testsoft.o
	cp $(linux_testsoft) $(buildroot_rootfs_overlay_dir)/root

aes_gcm_test: $(linux_module_wrkdir)/aes_gcm_test.o
	$(CC) -o $(linux_module_wrkdir)/aes_gcm_test $(linux_module_wrkdir)/aes_gcm_test.o
	cp $(aes_gcm_testsoft) $(buildroot_rootfs_overlay_dir)/root
	cp $(linux_module_wrkdir)/aes_gcm_test /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/overlay/root


# Clean

clean/testdriver:
	rm -rf module/ testdriver_build/
	rm -rf $(uec_root)/testdriver.ko

clean/aes-gcm:
	rm -rf $(buildroot_rootfs_overlay_dir)/root/aes_gcm_driver.ko aes_gcm_driver.build/
	rm -rf $(uec_root)/aes_gcm_driver.ko