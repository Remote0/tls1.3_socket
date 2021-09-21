linux_module_wrkdir := $(abspath .)/testdriver_build
linux_module_srcdir := $(abspath .)/testdriver
linux_module := $(linux_module_wrkdir)/testdriver.ko
linux_srcdir := /home/tuankiet/Documents/Workspace/keystone/build/linux.build
buildroot_rootfs_overlay_dir := $(abspath .)/module
ISA ?= rv64gc
ABI ?= lp64d

$(linux_module):
	rm -rf $(linux_module_wrkdir)
	mkdir -p $(linux_module_wrkdir)
	cp -r $(linux_module_srcdir)/* $(linux_module_wrkdir)
	$(MAKE) -C $(linux_srcdir) O=$(linux_srcdir) \
		CROSS_COMPILE=riscv64-unknown-linux-gnu- \
		ARCH=riscv \
		M=$(linux_module_wrkdir) \
		modules
	mkdir -p $(buildroot_rootfs_overlay_dir)/root
	cp $(linux_module) $(buildroot_rootfs_overlay_dir)/root

clean:
	rm -rf module/ testdriver_build/