
aes_gcm_module_srcdir := $(abspath .)/aes_gcm_driver
chacha_poly_module_srcdir := $(abspath .)/chacha_poly_driver

linux_srcdir := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/linux.build
uec_root := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/build/overlay/root


buildroot_rootfs_overlay_dir := $(abspath .)/module
ISA ?= rv64gc
ABI ?= lp64d
CC := /home/tuankiet/Documents/Workspace/uec-hanken_keystone/riscv64/bin/riscv64-unknown-linux-gnu-gcc	
CFLAGS := -Wall -g -Wl,-Bstatic

#------------aes-gcm------------#
aes_gcm_module_wrkdir := $(abspath .)/aes_gcm_driver.build
aes_gcm_module := $(aes_gcm_module_wrkdir)/aes_gcm_driver.ko
#------------chacha-poly------------#
chacha_poly_module_wrkdir := $(abspath .)/chacha_poly_driver.build
chacha_poly_module := $(chacha_poly_module_wrkdir)/chacha_poly_driver.ko
#################################

#-----------Software------------#
chacha_poly_testsoft := $(chacha_poly_module_wrkdir)/chacha_poly_test
aes_gcm_testsoft := $(aes_gcm_module_wrkdir)/aes_gcm_test
#################################

aes-gcm:
	rm -rf $(aes_gcm_module_wrkdir)
	mkdir -p $(aes_gcm_module_wrkdir)
	cp -r $(aes_gcm_module_srcdir)/* $(aes_gcm_module_wrkdir)
	$(MAKE) -C $(linux_srcdir) O=$(linux_srcdir) \
		CROSS_COMPILE=riscv64-unknown-linux-gnu- \
		ARCH=riscv \
		M=$(aes_gcm_module_wrkdir) \
		modules
	mkdir -p $(buildroot_rootfs_overlay_dir)/root
	cp $(aes_gcm_module) $(buildroot_rootfs_overlay_dir)/root
	cp $(aes_gcm_module) $(uec_root)

chacha-poly:
	rm -rf $(chacha_poly_module_wrkdir)
	mkdir -p $(chacha_poly_module_wrkdir)
	cp -r $(chacha_poly_module_srcdir)/* $(chacha_poly_module_wrkdir)
	$(MAKE) -C $(linux_srcdir) O=$(linux_srcdir) \
		CROSS_COMPILE=riscv64-unknown-linux-gnu- \
		ARCH=riscv \
		M=$(chacha_poly_module_wrkdir) \
		modules
	mkdir -p $(buildroot_rootfs_overlay_dir)/root
	cp $(chacha_poly_module) $(buildroot_rootfs_overlay_dir)/root
	cp $(chacha_poly_module) $(uec_root)


# Software test

test-aes-gcm: $(aes_gcm_module_wrkdir)/aes_gcm_test.o $(aes_gcm_module_wrkdir)/aes_gcm_func.o
	$(CC) -o $(aes_gcm_module_wrkdir)/aes_gcm_test $(aes_gcm_module_wrkdir)/aes_gcm_test.o $(aes_gcm_module_wrkdir)/aes_gcm_func.o
	cp $(aes_gcm_testsoft) $(buildroot_rootfs_overlay_dir)/root
	cp $(aes_gcm_module_wrkdir)/aes_gcm_test $(uec_root)

test-chacha-poly: $(chacha_poly_module_wrkdir)/chacha_poly_test.o $(chacha_poly_module_wrkdir)/chacha_poly_func.o
	$(CC) -o $(chacha_poly_module_wrkdir)/chacha_poly_test $(chacha_poly_module_wrkdir)/chacha_poly_test.o $(chacha_poly_module_wrkdir)/chacha_poly_func.o
	cp $(chacha_poly_testsoft) $(buildroot_rootfs_overlay_dir)/root
	cp $(chacha_poly_module_wrkdir)/chacha_poly_test $(uec_root)

$(chacha_poly_module_wrkdir)/%.o: $(chacha_poly_module_wrkdir)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<




clean/chacha-poly:
	rm -rf $(buildroot_rootfs_overlay_dir)/root/chacha_poly_driver.ko chacha_poly_driver.build/
	rm -rf $(uec_root)/chacha_poly_driver.ko

clean/test-chacha-poly:
	rm -rf $(chacha_poly_module_wrkdir)/chacha_poly_test $(chacha_poly_module_wrkdir)/chacha_poly_test.c $(chacha_poly_module_wrkdir)/chacha_poly_test.o 
	rm -rf $(uec_root)/chacha_poly_test
	rm -rf $(buildroot_rootfs_overlay_dir)/root/chacha_poly_test 
	cp $(chacha_poly_module_srcdir)/chacha_poly_test.c $(chacha_poly_module_wrkdir)
	cp $(chacha_poly_module_srcdir)/chacha_poly_func* $(chacha_poly_module_wrkdir)
	cp $(chacha_poly_module_srcdir)/chacha_poly_regs.h $(chacha_poly_module_wrkdir)

clean/aes-gcm:
	rm -rf $(buildroot_rootfs_overlay_dir)/root/aes_gcm_driver.ko aes_gcm_driver.build/
	rm -rf $(uec_root)/aes_gcm_driver.ko


clean/test-aes-gcm:
	rm -rf $(aes_gcm_module_wrkdir)/aes_gcm_test $(aes_gcm_module_wrkdir)/aes_gcm_test.c $(aes_gcm_module_wrkdir)/aes_gcm_test.o 
	rm -rf $(uec_root)/aes_gcm_test
	rm -rf $(buildroot_rootfs_overlay_dir)/root/aes_gcm_test 
	cp $(aes_gcm_module_srcdir)/aes_gcm_test.c $(aes_gcm_module_wrkdir)
	cp $(aes_gcm_module_srcdir)/aes_gcm_func* $(aes_gcm_module_wrkdir)
	cp $(aes_gcm_module_srcdir)/aes_gcm_regs.h $(aes_gcm_module_wrkdir)