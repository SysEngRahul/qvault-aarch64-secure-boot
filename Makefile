# QVault build system.   make            -> firmware + tools + payloads + signed flash/pflash images
#                        make run        -> boot in QEMU        make test  -> unit + negative + QEMU integration
#                        make fuzz       -> sanitizer fuzz run  make lint | repro | tcb | manifest | sbom | gdb-demo
#                        make verify     -> everything, from clean, writes docs/VERIFICATION.md   make clean
SHELL   := /bin/bash
CROSS   ?= aarch64-linux-gnu-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
HOSTCC  ?= gcc
B       := build

MC := third_party/monocypher

FW_INC := -Iinclude -Iinclude/freestanding -Iarch/arm64 -Iboot -Ilib -Iformat -Isecurity -Istorage \
          -Irecovery -Idtb -Ibootflow -Iplatform/qemu_virt -I$(MC) -I$(B)/generated

# Firmware flags. -mstrict-align: caches/MMU are off early, unaligned access would fault.
# -mgeneral-regs-only: no FP/SIMD state to save in exception handlers.
FW_CFLAGS := -std=c11 -O2 -g -ffile-prefix-map=$(CURDIR)=. -ffreestanding -nostdlib -fno-pic -fno-pie -fno-common \
             -fno-stack-protector -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
             -march=armv8-a -mstrict-align -mgeneral-regs-only -mno-outline-atomics \
             -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Werror
FW_ASFLAGS := -march=armv8-a -Iboot
# Vendored third-party code is compiled without -Werror.
TP_CFLAGS := -std=c11 -O2 -g -ffile-prefix-map=$(CURDIR)=. -ffreestanding -nostdlib -fno-pic -fno-pie -fno-stack-protector \
             -ffunction-sections -fdata-sections -march=armv8-a -mstrict-align -mgeneral-regs-only -w

COMMON_C := lib/string.c lib/status.c lib/sha256.c lib/log.c platform/qemu_virt/uart.c \
            arch/arm64/cache.c arch/arm64/mmu.c arch/arm64/exception.c arch/arm64/debug.c platform/qemu_virt/pflash.c \
            format/image_parser.c \
            security/crypto_backend.c security/key_store.c security/image_verify.c \
            security/measurement.c security/rollback.c security/secure_boot.c \
            storage/qemu_storage.c recovery/slot_manager.c recovery/update_manager.c \
            bootflow/image_loader.c bootflow/boot_policy.c bootflow/recovery.c
TP_C     := $(MC)/monocypher.c $(MC)/monocypher-ed25519.c
ASM      := boot/vectors.S boot/exceptions.S

S1_OBJS := $(patsubst %.c,$(B)/s1/%.o,bootflow/stage1.c $(COMMON_C)) \
           $(patsubst %.c,$(B)/s1/%.o,$(TP_C)) $(patsubst %.S,$(B)/s1/%.o,boot/start.S $(ASM))
S2_OBJS := $(patsubst %.c,$(B)/s2/%.o,bootflow/stage2.c dtb/dtb_validate.c dtb/dtb_parser.c $(COMMON_C)) \
           $(patsubst %.c,$(B)/s2/%.o,$(TP_C)) $(patsubst %.S,$(B)/s2/%.o,boot/start.S $(ASM))

STAGE1_BASE := 0x40080000
STAGE2_BASE := 0x41000000
STACK_SIZE  := 0x8000

TOOLS := $(B)/tools/qvbuild $(B)/tools/qvsign $(B)/tools/qvinspect
HOST_INC := -Iinclude -Iformat -Ilib -Istorage -Iplatform/qemu_virt -I$(MC) -Itools/common
HOST_LIB := format/image_parser.c lib/sha256.c lib/status.c tools/common/qvtool.c $(TP_C)

.PHONY: FORCE all firmware tools payloads keys flash dtb run test unit negative integration fuzz clean report lint repro tcb manifest sbom gdb-demo verify
all: firmware tools payloads flash report

# ---------------------------------------------------------------- host tools
$(B)/tools/qvbuild: tools/image_builder/qvbuild.c $(HOST_LIB)
	@mkdir -p $(@D); $(HOSTCC) -std=c11 -O2 -Wall $(HOST_INC) -o $@ $^
$(B)/tools/qvsign: tools/image_signer/qvsign.c $(HOST_LIB)
	@mkdir -p $(@D); $(HOSTCC) -std=c11 -O2 -Wall $(HOST_INC) -o $@ $^
$(B)/tools/qvinspect: tools/image_inspector/qvinspect.c $(HOST_LIB)
	@mkdir -p $(@D); $(HOSTCC) -std=c11 -O2 -Wall $(HOST_INC) -o $@ $^
tools: $(TOOLS)

# ---------------------------------------------------------------- keys (never committed)
keys: $(TOOLS)
	@scripts/gen_keys.sh
keys/root.pub: $(TOOLS)
	@scripts/gen_keys.sh
# Content-based, not timestamp-based: regenerate every time, but only touch the header when the root key
# actually changed. (A timestamp rule let firmware keep a STALE root key after keys/ was swapped, producing
# firmware that rejects every image signed by the current keys.)
$(B)/generated/root_pubkey.h: keys/root.pub FORCE
	@mkdir -p $(@D); $(B)/tools/qvsign header --pub keys/root.pub --out $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv -f $@.tmp $@; fi
FORCE:

# ---------------------------------------------------------------- firmware
$(B)/s1/%.o: %.c $(B)/generated/root_pubkey.h
	@mkdir -p $(@D); $(CC) $(FW_CFLAGS) $(FW_INC) -c $< -o $@
$(B)/s2/%.o: %.c $(B)/generated/root_pubkey.h
	@mkdir -p $(@D); $(CC) $(FW_CFLAGS) $(FW_INC) -c $< -o $@
$(B)/s1/$(MC)/%.o: $(MC)/%.c
	@mkdir -p $(@D); $(CC) $(TP_CFLAGS) -I$(MC) -c $< -o $@
$(B)/s2/$(MC)/%.o: $(MC)/%.c
	@mkdir -p $(@D); $(CC) $(TP_CFLAGS) -I$(MC) -c $< -o $@
$(B)/s1/%.o: %.S
	@mkdir -p $(@D); $(CC) $(FW_ASFLAGS) -Iarch/arm64 -c $< -o $@
$(B)/s2/%.o: %.S
	@mkdir -p $(@D); $(CC) $(FW_ASFLAGS) -Iarch/arm64 -DQV_STAGE2 -c $< -o $@

LDFLAGS_COMMON := -nostdlib -static -Wl,--gc-sections -Wl,-z,max-page-size=4096 -Wl,--build-id=none \
                  -Wl,-z,noexecstack -Wl,--no-warn-rwx-segments -Tboot/linker.ld

$(B)/stage1.elf: $(S1_OBJS) boot/linker.ld
	$(CC) $(LDFLAGS_COMMON) -Wl,--defsym=QV_IMG_BASE=$(STAGE1_BASE) -Wl,--defsym=QV_STACK_SIZE=$(STACK_SIZE) \
	      -Wl,-Map=$(B)/stage1.map -o $@ $(S1_OBJS) -lgcc
$(B)/stage2.elf: $(S2_OBJS) boot/linker.ld
	$(CC) $(LDFLAGS_COMMON) -Wl,--defsym=QV_IMG_BASE=$(STAGE2_BASE) -Wl,--defsym=QV_STACK_SIZE=$(STACK_SIZE) \
	      -Wl,-Map=$(B)/stage2.map -o $@ $(S2_OBJS) -lgcc
$(B)/stage2.bin: $(B)/stage2.elf
	$(OBJCOPY) -O binary $< $@
	@test "$$($(CROSS)nm $< | awk '$$3=="_start"{print $$1}')" = "0000000041000000" || \
	  { echo "stage2 _start is not at load address"; exit 1; }
firmware: $(B)/stage1.elf $(B)/stage2.bin

# ---------------------------------------------------------------- payloads (test OS + UEFI placeholder)
$(B)/payloads/%.bin: payloads/%_stub.S
	@mkdir -p $(B)/payloads
	$(CC) -march=armv8-a -nostdlib -static -Wl,--build-id=none -Wl,-e,_start -Wl,-Ttext=$(LOADADDR_$*) \
	      -Wl,--no-warn-rwx-segments -o $(B)/payloads/$*.elf $<
	$(OBJCOPY) -O binary $(B)/payloads/$*.elf $@
LOADADDR_kernel := 0x43000000
LOADADDR_uefi   := 0x42000000
payloads: $(B)/payloads/kernel.bin $(B)/payloads/uefi.bin

# ---------------------------------------------------------------- DTB (dumped from the exact QEMU machine we run)
$(B)/virt.dtb:
	@mkdir -p $(B)
	timeout 20 qemu-system-aarch64 -M virt,dumpdtb=$(B)/virt.raw.dtb -cpu cortex-a72 -smp 1 -m 1G -nographic >/dev/null 2>&1 || true
	@test -s $(B)/virt.raw.dtb || { echo "failed to dump DTB"; exit 1; }
	# QEMU injects fresh random rng-seed/kaslr-seed on every dump => nondeterministic build input, and a
	# signed, FIXED seed would be a weak-entropy bug. Strip both (a real loader injects entropy at boot,
	# after authentication) and repack (QEMU emits a 1 MiB padded blob).
	dtc -q -I dtb -O dts $(B)/virt.raw.dtb | grep -v -E '^\s*(rng-seed|kaslr-seed) =' | dtc -q -I dts -O dtb -o $@
dtb: $(B)/virt.dtb

# ---------------------------------------------------------------- flash image (signed, simulated storage)
flash: firmware payloads tools $(B)/virt.dtb keys
	@scripts/make_flash.sh

report: firmware
	@scripts/build_report.sh > $(B)/build_report.txt && cat $(B)/build_report.txt

run: all
	@cp $(B)/flash.img.pflash $(B)/run.pflash
	@PFLASH=$(B)/run.pflash scripts/run_qemu.sh

# ---------------------------------------------------------------- tests
unit:
	@$(MAKE) -s -C tests/unit run
negative: all
	@tests/negative/run_negative.sh
integration: all
	@tests/integration/run_qemu_tests.sh
test: unit negative integration
fuzz: all
	@scripts/fuzz_dtb.sh
lint:
	@scripts/static_analysis.sh
repro:
	@scripts/repro_check.sh
tcb: firmware
	@python3 scripts/tcb_report.py
manifest: all
	@scripts/sign_manifest.sh sign && scripts/sign_manifest.sh verify
sbom: all
	@python3 scripts/gen_sbom.py && pyspdxtools -i $(B)/qvault.spdx.json && echo "SBOM: valid SPDX 2.3"
gdb-demo: all
	@scripts/gdb_demo.sh
verify:
	@scripts/verify_all.sh

clean:
	rm -rf $(B)
	$(MAKE) -s -C tests/unit clean
