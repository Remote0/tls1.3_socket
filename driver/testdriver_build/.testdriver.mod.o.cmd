cmd_/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o := riscv64-unknown-linux-gnu-gcc -Wp,-MD,/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/.testdriver.mod.o.d  -nostdinc -isystem /home/tuankiet/Documents/Workspace/keystone/riscv64/bin/../lib/gcc/riscv64-unknown-linux-gnu/10.2.0/include -I/home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include -I./arch/riscv/include/generated -I/home/tuankiet/Documents/Workspace/keystone/linux/include -I./include -I/home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi -I./arch/riscv/include/generated/uapi -I/home/tuankiet/Documents/Workspace/keystone/linux/include/uapi -I./include/generated/uapi -include /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kconfig.h -include /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler_types.h -D__KERNEL__ -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Wno-format-security -std=gnu89 -mabi=lp64 -march=rv64imac -mno-save-restore -DCONFIG_PAGE_OFFSET=0xffffffe000000000 -mcmodel=medany -mstrict-align -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 -fno-allow-store-data-races -Wframe-larger-than=2048 -fno-stack-protector -Wno-unused-but-set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -g -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-stringop-truncation -Wno-zero-length-bounds -Wno-array-bounds -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -fno-strict-overflow -fno-merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -fmacro-prefix-map=/home/tuankiet/Documents/Workspace/keystone/linux/= -Wno-packed-not-aligned  -DMODULE -mno-relax  -DKBUILD_BASENAME='"testdriver.mod"' -DKBUILD_MODNAME='"testdriver"' -c -o /home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o /home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.c

source_/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o := /home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.c

deps_/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o := \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/retpoline.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler_types.h \
    $(wildcard include/config/have/arch/compiler/h.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/cc/has/asm/inline.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler_attributes.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/sysfs.h) \
    $(wildcard include/config/modules/tree/lookup.h) \
    $(wildcard include/config/livepatch.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/module/sig.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/tracepoints.h) \
    $(wildcard include/config/tree/srcu.h) \
    $(wildcard include/config/bpf/events.h) \
    $(wildcard include/config/jump/label.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/event/tracing.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
    $(wildcard include/config/constructors.h) \
    $(wildcard include/config/function/error/injection.h) \
    $(wildcard include/config/strict/module/rwx.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/types.h \
    $(wildcard include/config/have/uid16.h) \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/types.h \
  arch/riscv/include/generated/uapi/asm/types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/int-ll64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/int-ll64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi/asm/bitsperlong.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitsperlong.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/bitsperlong.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/posix_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/stddef.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/stddef.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler_types.h \
  arch/riscv/include/generated/uapi/asm/posix_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/posix_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/poison.h \
    $(wildcard include/config/illegal/pointer/value.h) \
    $(wildcard include/config/page/poisoning/zero.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/const.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/const.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/const.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/atomic/sleep.h) \
    $(wildcard include/config/preempt/rt.h) \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/panic/timeout.h) \
  /home/tuankiet/Documents/Workspace/keystone/riscv64/lib/gcc/riscv64-unknown-linux-gnu/10.2.0/include/stdarg.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/limits.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/limits.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/limits.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/linkage.h \
    $(wildcard include/config/x86.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/stringify.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/export.h \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/module/rel/crcs.h) \
    $(wildcard include/config/have/arch/prel32/relocations.h) \
    $(wildcard include/config/trim/unused/ksyms.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/linkage.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/stack/validation.h) \
    $(wildcard include/config/kasan.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/barrier.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/barrier.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kasan-checks.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/bitops.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/bits.h \
    $(wildcard include/config/cc/is/gcc.h) \
    $(wildcard include/config/gcc/version.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/bits.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/build_bug.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/bitops.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/typecheck.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/irqflags.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/processor.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/ptrace.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi/asm/ptrace.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/csr.h \
    $(wildcard include/config/riscv/m/mode.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/asm.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/__ffs.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/ffz.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/fls.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/__fls.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/fls64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/find.h \
    $(wildcard include/config/generic/find/first/bit.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/sched.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/ffs.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/hweight.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/arch_hweight.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/const_hweight.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/non-atomic.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/le.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi/asm/byteorder.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/byteorder/little_endian.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/byteorder/little_endian.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/swab.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/swab.h \
  arch/riscv/include/generated/uapi/asm/swab.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/swab.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/byteorder/generic.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bitops/ext2-atomic.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/printk.h \
    $(wildcard include/config/message/loglevel/default.h) \
    $(wildcard include/config/console/loglevel/default.h) \
    $(wildcard include/config/console/loglevel/quiet.h) \
    $(wildcard include/config/early/printk.h) \
    $(wildcard include/config/printk/nmi.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/dynamic/debug.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/init.h \
    $(wildcard include/config/strict/kernel/rwx.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kern_levels.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/kernel.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/sysinfo.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/cache.h \
  arch/riscv/include/generated/asm/div64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/div64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/stat.h \
  arch/riscv/include/generated/uapi/asm/stat.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/stat.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/stat.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/time.h \
    $(wildcard include/config/arch/uses/gettimeoffset.h) \
    $(wildcard include/config/posix/timers.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/seqlock.h \
    $(wildcard include/config/debug/lock/alloc.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/preemption.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/preempt.h \
    $(wildcard include/config/preempt/count.h) \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/trace/preempt/toggle.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  arch/riscv/include/generated/asm/preempt.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/preempt.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/thread_info.h \
    $(wildcard include/config/thread/info/in/task.h) \
    $(wildcard include/config/have/arch/within/stack/frames.h) \
    $(wildcard include/config/hardened/usercopy.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/bug.h \
    $(wildcard include/config/bug/on/data/corruption.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/bug.h \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
    $(wildcard include/config/debug/bugverbose.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/bug.h \
    $(wildcard include/config/bug.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/restart_block.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/time64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/math64.h \
    $(wildcard include/config/arch/supports/int128.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/math64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/time64.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/time.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/time_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/current.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/thread_info.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/page.h \
    $(wildcard include/config/page/offset.h) \
    $(wildcard include/config/debug/virtual.h) \
    $(wildcard include/config/flatmem.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/pfn.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/memory_model.h \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
    $(wildcard include/config/sparsemem.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/getorder.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/bottom_half.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/mmiowb.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/smp.h \
    $(wildcard include/config/up/late/init.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/errno.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/errno.h \
  arch/riscv/include/generated/uapi/asm/errno.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/errno.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/errno-base.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/cpumask.h \
    $(wildcard include/config/cpumask/offstack.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/bitmap.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
    $(wildcard include/config/fortify/source.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/string.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/string.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/atomic.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/atomic.h \
    $(wildcard include/config/generic/atomic64.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/cmpxchg.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/fence.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/atomic-fallback.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/atomic-long.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/llist.h \
    $(wildcard include/config/arch/have/nmi/safe/cmpxchg.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/smp.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/irqreturn.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/mmiowb.h \
    $(wildcard include/config/mmiowb.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/mmiowb_types.h \
  arch/riscv/include/generated/asm/percpu.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/percpu.h \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/percpu-defs.h \
    $(wildcard include/config/debug/force/weak/per/cpu.h) \
    $(wildcard include/config/amd/mem/encrypt.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/spinlock_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/spinlock_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/lockdep.h \
    $(wildcard include/config/prove/raw/lock/nesting.h) \
    $(wildcard include/config/preempt/lock.h) \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rwlock_types.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/spinlock.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rwlock.h \
    $(wildcard include/config/preempt.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/spinlock_api_smp.h \
    $(wildcard include/config/inline/spin/lock.h) \
    $(wildcard include/config/inline/spin/lock/bh.h) \
    $(wildcard include/config/inline/spin/lock/irq.h) \
    $(wildcard include/config/inline/spin/lock/irqsave.h) \
    $(wildcard include/config/inline/spin/trylock.h) \
    $(wildcard include/config/inline/spin/trylock/bh.h) \
    $(wildcard include/config/uninline/spin/unlock.h) \
    $(wildcard include/config/inline/spin/unlock/bh.h) \
    $(wildcard include/config/inline/spin/unlock/irq.h) \
    $(wildcard include/config/inline/spin/unlock/irqrestore.h) \
    $(wildcard include/config/generic/lockbreak.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rwlock_api_smp.h \
    $(wildcard include/config/inline/read/lock.h) \
    $(wildcard include/config/inline/write/lock.h) \
    $(wildcard include/config/inline/read/lock/bh.h) \
    $(wildcard include/config/inline/write/lock/bh.h) \
    $(wildcard include/config/inline/read/lock/irq.h) \
    $(wildcard include/config/inline/write/lock/irq.h) \
    $(wildcard include/config/inline/read/lock/irqsave.h) \
    $(wildcard include/config/inline/write/lock/irqsave.h) \
    $(wildcard include/config/inline/read/trylock.h) \
    $(wildcard include/config/inline/write/trylock.h) \
    $(wildcard include/config/inline/read/unlock.h) \
    $(wildcard include/config/inline/write/unlock.h) \
    $(wildcard include/config/inline/read/unlock/bh.h) \
    $(wildcard include/config/inline/write/unlock/bh.h) \
    $(wildcard include/config/inline/read/unlock/irq.h) \
    $(wildcard include/config/inline/write/unlock/irq.h) \
    $(wildcard include/config/inline/read/unlock/irqrestore.h) \
    $(wildcard include/config/inline/write/unlock/irqrestore.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/time32.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/timex.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/timex.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/param.h \
  arch/riscv/include/generated/uapi/asm/param.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/param.h \
    $(wildcard include/config/hz.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/asm-generic/param.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/timex.h \
    $(wildcard include/config/riscv/sbi.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/mmio.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/time32.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/time.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/uidgid.h \
    $(wildcard include/config/multiuser.h) \
    $(wildcard include/config/user/ns.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/highuid.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kmod.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/umh.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/gfp.h \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
    $(wildcard include/config/zone/device.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/pm/sleep.h) \
    $(wildcard include/config/contig/alloc.h) \
    $(wildcard include/config/cma.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/mmdebug.h \
    $(wildcard include/config/debug/vm.h) \
    $(wildcard include/config/debug/vm/pgflags.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/isolation.h) \
    $(wildcard include/config/zsmalloc.h) \
    $(wildcard include/config/memcg.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/compaction.h) \
    $(wildcard include/config/transparent/hugepage.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/page/extension.h) \
    $(wildcard include/config/deferred/struct/page/init.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/have/memoryless/nodes.h) \
    $(wildcard include/config/have/memblock/node/map.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/memory/hotremove.h) \
    $(wildcard include/config/have/arch/pfn/valid.h) \
    $(wildcard include/config/holes/in/zone.h) \
    $(wildcard include/config/arch/has/holes/memorymodel.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/wait.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/wait.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
    $(wildcard include/config/numa/keep/meminfo.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/nodemask.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/page-flags-layout.h \
    $(wildcard include/config/numa/balancing.h) \
    $(wildcard include/config/kasan/sw/tags.h) \
  include/generated/bounds.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/mm_types.h \
    $(wildcard include/config/have/aligned/struct/page.h) \
    $(wildcard include/config/userfaultfd.h) \
    $(wildcard include/config/swap.h) \
    $(wildcard include/config/have/arch/compat/mmap/bases.h) \
    $(wildcard include/config/membarrier.h) \
    $(wildcard include/config/aio.h) \
    $(wildcard include/config/mmu/notifier.h) \
    $(wildcard include/config/arch/want/batched/unmap/tlb/flush.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/mm_types_task.h \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/arch/enable/split/pmd/ptlock.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/auxvec.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/auxvec.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi/asm/auxvec.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rbtree.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rcupdate.h \
    $(wildcard include/config/preempt/rcu.h) \
    $(wildcard include/config/rcu/stall/common.h) \
    $(wildcard include/config/no/hz/full.h) \
    $(wildcard include/config/rcu/nocb/cpu.h) \
    $(wildcard include/config/tasks/rcu.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/tiny/rcu.h) \
    $(wildcard include/config/debug/objects/rcu/head.h) \
    $(wildcard include/config/prove/rcu.h) \
    $(wildcard include/config/rcu/boost.h) \
    $(wildcard include/config/arch/weak/release/acquire.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rcutree.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rwsem.h \
    $(wildcard include/config/rwsem/spin/on/owner.h) \
    $(wildcard include/config/debug/rwsems.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/err.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/completion.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/swait.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/uprobes.h \
    $(wildcard include/config/uprobes.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/workqueue.h \
    $(wildcard include/config/debug/objects/work.h) \
    $(wildcard include/config/freezer.h) \
    $(wildcard include/config/wq/watchdog.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/timer.h \
    $(wildcard include/config/debug/objects/timers.h) \
    $(wildcard include/config/no/hz/common.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/ktime.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/jiffies.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/jiffies.h \
  include/generated/timeconst.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/vdso/ktime.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/timekeeping.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/timekeeping32.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/debug/objects/free.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/mmu.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/page-flags.h \
    $(wildcard include/config/arch/uses/pg/uncached.h) \
    $(wildcard include/config/memory/failure.h) \
    $(wildcard include/config/idle/page/tracking.h) \
    $(wildcard include/config/thp/swap.h) \
    $(wildcard include/config/ksm.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/memory_hotplug.h \
    $(wildcard include/config/arch/has/add/pages.h) \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
    $(wildcard include/config/have/bootmem/info/node.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/notifier.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/mutex.h \
    $(wildcard include/config/mutex/spin/on/owner.h) \
    $(wildcard include/config/debug/mutexes.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/osq_lock.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/srcu.h \
    $(wildcard include/config/tiny/srcu.h) \
    $(wildcard include/config/srcu.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rcu_segcblist.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/srcutree.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rcu_node_tree.h \
    $(wildcard include/config/rcu/fanout.h) \
    $(wildcard include/config/rcu/fanout/leaf.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/topology.h \
    $(wildcard include/config/use/percpu/numa/node/id.h) \
    $(wildcard include/config/sched/smt.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/arch_topology.h \
    $(wildcard include/config/generic/arch/topology.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/percpu.h \
    $(wildcard include/config/need/per/cpu/embed/first/chunk.h) \
    $(wildcard include/config/need/per/cpu/page/first/chunk.h) \
  arch/riscv/include/generated/asm/topology.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/topology.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/sysctl.h \
    $(wildcard include/config/sysctl.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/sysctl.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/elf.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/elf.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/uapi/asm/elf.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/elf.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/uapi/linux/elf-em.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kobject.h \
    $(wildcard include/config/uevent/helper.h) \
    $(wildcard include/config/debug/kobject/release.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/sysfs.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kernfs.h \
    $(wildcard include/config/kernfs.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/idr.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/radix-tree.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/xarray.h \
    $(wildcard include/config/xarray/multi.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kconfig.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kobject_ns.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/kref.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/refcount.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/moduleparam.h \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/ppc64.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/jump_label.h \
    $(wildcard include/config/have/arch/jump/label/relative.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/rbtree_latch.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/error-injection.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/error-injection.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/tracepoint-defs.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/static_key.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/module.h \
    $(wildcard include/config/module/sections.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/asm-generic/module.h \
    $(wildcard include/config/have/mod/arch/specific.h) \
    $(wildcard include/config/modules/use/elf/rel.h) \
    $(wildcard include/config/modules/use/elf/rela.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/build-salt.h \
    $(wildcard include/config/build/salt.h) \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/elfnote.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/include/linux/vermagic.h \
  include/generated/utsrelease.h \
  /home/tuankiet/Documents/Workspace/keystone/linux/arch/riscv/include/asm/vermagic.h \

/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o: $(deps_/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o)

$(deps_/home/tuankiet/Documents/Workspace/tls1.3_socket/testdriver/testdriver_build/testdriver.mod.o):
