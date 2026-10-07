# Host-side unit tests (native gcc, ASan+UBSan). Firmware logic is portable C, so
# parser / verifier / DTB / slot / update logic is tested off-target.
CC ?= gcc
R  := ../..
MC := $(R)/third_party/monocypher
INC := -I$(R)/include -I$(R)/format -I$(R)/lib -I$(R)/security -I$(R)/storage -I$(R)/recovery \
       -I$(R)/dtb -I$(R)/arch/arm64 -I$(R)/platform/qemu_virt -I$(MC)
CFLAGS := -std=c11 -g -O1 -Wall -Wextra -DQV_HOST_TEST -fsanitize=address,undefined -fno-sanitize-recover=all $(INC)
SRC := test_main.c mem_storage.c $(R)/format/image_parser.c $(R)/format/pe_validate.c $(R)/lib/sha256.c $(R)/lib/status.c \
       $(R)/security/crypto_backend.c $(R)/security/key_store.c $(R)/security/image_verify.c \
       $(R)/security/measurement.c $(R)/security/rollback.c $(R)/security/secure_boot.c \
       $(R)/recovery/slot_manager.c $(R)/recovery/update_manager.c \
       $(R)/dtb/dtb_validate.c $(R)/dtb/dtb_parser.c $(MC)/monocypher.c $(MC)/monocypher-ed25519.c
test_main: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)
run: test_main
	./test_main
clean:
	rm -f test_main
