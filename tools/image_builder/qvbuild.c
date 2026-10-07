#define _POSIX_C_SOURCE 200809L
/* qvbuild: create unsigned QVault images, the simulated secure store, and the flash image.
 *   qvbuild image --type stage2|uefi|kernel|dtb --version N --load A --entry A --key-id N --payload F --out F
 *   qvbuild store --stage2 N --uefi N --kernel N --out F
 *   qvbuild flash --out F --stage2a F --stage2b F --uefia F --uefib F --kernela F --kernelb F --dtba F --dtbb F */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qvtool.h"
#include "image_format.h"
#include "storage.h"
#include "memmap.h"
#include "sha256.h"

static uint32_t type_from_name(const char *s)
{
    if (!strcmp(s, "stage2")) { return QV_IMG_STAGE2; }
    if (!strcmp(s, "uefi"))   { return QV_IMG_UEFI; }
    if (!strcmp(s, "kernel")) { return QV_IMG_KERNEL; }
    if (!strcmp(s, "dtb"))    { return QV_IMG_DTB; }
    qt_die("unknown --type '%s'", s);
}

static int cmd_image(int argc, char **argv)
{
    size_t plen;
    const uint8_t *payload = qt_read_file(qt_opt(argc, argv, "--payload", ""), &plen);
    uint8_t *out;
    qv_image_header_t h;
    uint32_t type = type_from_name(qt_opt(argc, argv, "--type", ""));

    if (plen == 0 || plen > QV_MAX_PAYLOAD) { qt_die("payload size %zu out of range", plen); }
    memset(&h, 0, sizeof h);
    h.magic = QV_IMAGE_MAGIC;
    h.header_version = QV_IMAGE_HDR_VERSION;
    h.header_size = sizeof h;
    h.image_type = type;
    h.fw_version = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--version", "1"));
    h.load_addr = qt_parse_u64(qt_opt(argc, argv, "--load", "0"));
    h.entry_point = qt_parse_u64(qt_opt(argc, argv, "--entry", "0"));
    h.payload_size = (uint32_t)plen;
    h.hash_alg = QV_HASH_SHA256;
    h.sig_alg = QV_SIG_ED25519;
    h.key_id = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--key-id", "1"));
    h.key_role = qv_role_for_type(type);
    qv_sha256(payload, plen, h.payload_hash);

    out = calloc(1, QV_HEADER_SPACE + plen);
    memcpy(out, &h, sizeof h);
    memcpy(out + QV_HEADER_SPACE, payload, plen);
    qt_write_file(qt_opt(argc, argv, "--out", "out.img"), out, QV_HEADER_SPACE + plen);
    return 0;
}

/* qvbuild store: initial persistent state (written to the start of the pflash image).
 *   --stage2 N --uefi N --kernel N --dtb N        anti-rollback floors
 *   --lifecycle dev|prod                          debug policy
 *   --revoke-key ID[,ID...]                       revoked signer key IDs
 *   --revoke-payload FILE[,FILE...]               revoke by payload SHA-256 (hash of FILE's bytes) */
static int cmd_store(int argc, char **argv)
{
    qv_store_t s;
    unsigned t;
    const char *lc = qt_opt(argc, argv, "--lifecycle", "dev");
    char *list;
    unsigned n = 0;

    memset(&s, 0, sizeof s);
    s.magic = QV_STORE_MAGIC;
    s.layout_version = QV_STORE_LAYOUT;
    if (!strcmp(lc, "prod")) { s.lifecycle = QV_LIFECYCLE_PROD; }
    else if (strcmp(lc, "dev")) { qt_die("--lifecycle must be dev or prod"); }
    s.counters[QV_IMG_STAGE2] = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--stage2", "0"));
    s.counters[QV_IMG_UEFI]   = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--uefi", "0"));
    s.counters[QV_IMG_KERNEL] = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--kernel", "0"));
    s.counters[QV_IMG_DTB]    = (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--dtb", "0"));
    for (t = 1; t < QV_IMG_COUNT; t++) {          /* factory state: both slots good, A active */
        s.slots[t].active = 0;
        s.slots[t].state[0] = s.slots[t].state[1] = QV_SLOT_VALID;
    }
    list = strdup(qt_opt(argc, argv, "--revoke-key", ""));
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
        if (n >= QV_MAX_REVOKED_KEYS) { qt_die("too many revoked keys"); }
        s.revoked_key[n++] = (uint32_t)qt_parse_u64(tok);
    }
    n = 0;
    list = strdup(qt_opt(argc, argv, "--revoke-payload", ""));
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
        size_t len; uint8_t *d = qt_read_file(tok, &len);
        if (n >= QV_MAX_REVOKED_HASHES) { qt_die("too many revoked hashes"); }
        qv_sha256(d, len, s.revoked_hash[n++]);
        free(d);
    }
    qt_write_file(qt_opt(argc, argv, "--out", "store.bin"), &s, sizeof s);
    return 0;
}

static void put(uint8_t *flash, uintptr_t addr, const char *path)
{
    size_t n, off = addr - QV_FLASH_BASE;
    uint8_t *d = qt_read_file(path, &n);
    if (n > QV_SLOT_SIZE) { qt_die("%s too large for slot (%zu)", path, n); }
    memcpy(flash + off, d, n);
    free(d);
}

static int cmd_flash(int argc, char **argv)
{
    uint8_t *flash = calloc(1, QV_FLASH_TOTAL);
    put(flash, QV_FLASH_STAGE2_A, qt_opt(argc, argv, "--stage2a", ""));
    put(flash, QV_FLASH_STAGE2_B, qt_opt(argc, argv, "--stage2b", ""));
    put(flash, QV_FLASH_UEFI_A,   qt_opt(argc, argv, "--uefia", ""));
    put(flash, QV_FLASH_UEFI_B,   qt_opt(argc, argv, "--uefib", ""));
    put(flash, QV_FLASH_KERNEL_A, qt_opt(argc, argv, "--kernela", ""));
    put(flash, QV_FLASH_KERNEL_B, qt_opt(argc, argv, "--kernelb", ""));
    put(flash, QV_FLASH_DTB_A,    qt_opt(argc, argv, "--dtba", ""));
    put(flash, QV_FLASH_DTB_B,    qt_opt(argc, argv, "--dtbb", ""));
    qt_write_file(qt_opt(argc, argv, "--out", "flash.img"), flash, QV_FLASH_TOTAL);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "image")) { return cmd_image(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "store")) { return cmd_store(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "flash")) { return cmd_flash(argc, argv); }
    fprintf(stderr, "usage: qvbuild image|store|flash ...\n");
    return 2;
}
