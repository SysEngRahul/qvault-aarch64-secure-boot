/* qvinspect IMAGE [--root-pub F]   Dump a QVault image header and (optionally) verify it. */
#include <stdio.h>
#include <string.h>
#include "qvtool.h"
#include "image_format.h"
#include "sha256.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static void hex(const char *n, const uint8_t *d, size_t len)
{
    size_t i;
    printf("  %-14s ", n);
    for (i = 0; i < len; i++) { printf("%02x", d[i]); }
    printf("\n");
}

int main(int argc, char **argv)
{
    size_t il;
    const uint8_t *img;
    qv_image_header_t h;
    const uint8_t *payload = NULL;
    qv_status_t st;
    const char *rootp = qt_opt(argc, argv, "--root-pub", NULL);

    if (argc < 2) { fprintf(stderr, "usage: qvinspect IMAGE [--root-pub F]\n"); return 2; }
    img = qt_read_file(argv[1], &il);
    if (il < QV_HEADER_SPACE) { qt_die("file too small to be a QVault image"); }
    memcpy(&h, img, sizeof h);
    st = qv_image_parse(img, il, h.image_type, &h, &payload);
    if (st != QV_OK) { memcpy(&h, img, sizeof h); }
    printf("%s: %zu bytes, structural check: %s\n", argv[1], il, qv_status_str(st));
    printf("  type=%u version=%u key_id=%u role=%u\n  load=0x%llx entry=0x%llx size=%u\n",
           h.image_type, h.fw_version, h.key_id, h.key_role,
           (unsigned long long)h.load_addr, (unsigned long long)h.entry_point, h.payload_size);
    hex("payload_hash", h.payload_hash, 32);
    hex("signer_pubkey", h.signer_pubkey, 32);
    if (st == QV_OK) {
        uint8_t dg[32];
        qv_sha256(payload, h.payload_size, dg);
        printf("  payload hash : %s\n", memcmp(dg, h.payload_hash, 32) == 0 ? "MATCH" : "MISMATCH");
    }
    if (rootp && st == QV_OK) {
        size_t rl;
        uint8_t *rp = qt_read_file(rootp, &rl), msg[QV_CERT_MSG_LEN];
        qv_build_cert_msg(msg, h.key_id, h.key_role, h.signer_pubkey);
        printf("  root cert    : %s\n", crypto_ed25519_check(h.signer_cert, rp, msg, sizeof msg) == 0 ? "VALID" : "INVALID");
        printf("  signature    : %s\n", crypto_ed25519_check(h.signature, h.signer_pubkey, (uint8_t *)&h, QV_SIGNED_LEN) == 0 ? "VALID" : "INVALID");
    }
    return st == QV_OK ? 0 : 1;
}
