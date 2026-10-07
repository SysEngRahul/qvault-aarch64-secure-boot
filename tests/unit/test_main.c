#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qv_common.h"
#include "image_format.h"
#include "image_verify.h"
#include "secure_boot.h"
#include "measurement.h"
#include "rollback.h"
#include "slot_manager.h"
#include "update_manager.h"
#include "storage.h"
#include "key_store.h"
#include "sha256.h"
#include "dtb.h"
#include "pe_validate.h"
#include "memmap.h"
#include "../common/pe_sample.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

extern qv_store_t g_test_store;
static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static uint8_t root_sk[64], root_pk[32], fw_sk[64], fw_pk[32], fw_cert[64];

static void keys(void)
{
    uint8_t seed[32]; uint8_t msg[QV_CERT_MSG_LEN];
    memset(seed, 1, 32); crypto_ed25519_key_pair(root_sk, root_pk, seed);
    memset(seed, 2, 32); crypto_ed25519_key_pair(fw_sk, fw_pk, seed);
    qv_build_cert_msg(msg, 7, QV_ROLE_FIRMWARE, fw_pk);
    crypto_ed25519_sign(fw_cert, root_sk, msg, sizeof msg);
    qv_keystore_test_set_root(root_pk);
}

/* Build a signed stage2 image blob of given version/payload size into a 1 MiB slot buffer. */
static void make_image(uint8_t *slot, uint32_t ver, uint32_t psize, uint8_t fill)
{
    qv_image_header_t h;
    memset(slot, 0, 0x100000);
    memset(slot + QV_HEADER_SPACE, fill, psize);
    memset(&h, 0, sizeof h);
    h.magic = QV_IMAGE_MAGIC; h.header_version = 1; h.header_size = sizeof h;
    h.image_type = QV_IMG_STAGE2; h.fw_version = ver; h.load_addr = 0x41000000; h.entry_point = 0x41000000;
    h.payload_size = psize; h.hash_alg = 1; h.sig_alg = 1; h.key_id = 7; h.key_role = QV_ROLE_FIRMWARE;
    qv_sha256(slot + QV_HEADER_SPACE, psize, h.payload_hash);
    memcpy(h.signer_pubkey, fw_pk, 32); memcpy(h.signer_cert, fw_cert, 64);
    crypto_ed25519_sign(h.signature, fw_sk, (uint8_t *)&h, QV_SIGNED_LEN);
    memcpy(slot, &h, sizeof h);
}

static void hexcmp(const uint8_t *d, const char *hex) /* checks sha256 output vs hex */
{
    char out[65]; int i;
    for (i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", d[i]);
    CHECK(strcmp(out, hex) == 0);
}

static void test_sha256(void)
{
    uint8_t d[32]; static uint8_t big[1000000];
    qv_sha256("", 0, d);    hexcmp(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    qv_sha256("abc", 3, d); hexcmp(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    qv_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    hexcmp(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    memset(big, 'a', sizeof big); qv_sha256(big, sizeof big, d);
    hexcmp(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_ed25519_rfc8032(void)
{   /* RFC 8032 test 1: empty message */
    static const uint8_t seed[32] = {0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60};
    static const uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    uint8_t s[32], sk[64], pk[32], sig[64];
    memcpy(s, seed, 32); crypto_ed25519_key_pair(sk, pk, s);
    CHECK(memcmp(pk, pub, 32) == 0);
    crypto_ed25519_sign(sig, sk, (const uint8_t *)"", 0);
    CHECK(sig[0] == 0xe5 && sig[1] == 0x56 && sig[2] == 0x43 && sig[63] == 0x0b);
    CHECK(crypto_ed25519_check(sig, pk, (const uint8_t *)"", 0) == 0);
}

static void test_parse_and_verify(void)
{
    static uint8_t slot[0x100000], dest[0x100000];
    qv_boot_report_t rep; const uint8_t *pl; qv_image_header_t h;
    int i;

    make_image(slot, 12, 4096, 0xAB);
    memset(&g_test_store, 0, sizeof g_test_store); g_test_store.magic = QV_STORE_MAGIC; g_test_store.layout_version = QV_STORE_LAYOUT;
    g_test_store.counters[QV_IMG_STAGE2] = 12;

    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_OK);
    CHECK(rep.v.hash == QV_OK && rep.v.cert == QV_OK && rep.v.sig == QV_OK && rep.rollback == QV_OK);

    CHECK(qv_secure_boot_load(QV_IMG_KERNEL, slot, sizeof slot, dest, &rep) == QV_ERR_TYPE);   /* wrong type */

    make_image(slot, 11, 4096, 0xAB);                                  /* signed but too old */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_ERR_ROLLBACK);
    CHECK(dest[0] == 0);                                               /* scrubbed on failure */

    make_image(slot, 12, 4096, 0xAB);
    slot[QV_HEADER_SPACE + 10] ^= 1;                                   /* payload bit flip */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_ERR_HASH);

    make_image(slot, 12, 4096, 0xAB);
    slot[60] ^= 1;                                                     /* hash field (inside signed region) */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) != QV_OK);

    /* Untrusted root: signer cert made by a different root must fail. */
    make_image(slot, 12, 4096, 0xAB);
    { uint8_t seed[32], sk2[64], pk2[32]; memset(seed, 9, 32); crypto_ed25519_key_pair(sk2, pk2, seed); qv_keystore_test_set_root(pk2); }
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_ERR_CERT);
    qv_keystore_test_set_root(root_pk);

    /* Structural attacks */
    make_image(slot, 12, 4096, 1);
    CHECK(qv_image_parse(slot, 100, QV_IMG_STAGE2, &h, &pl) == QV_ERR_SIZE);               /* truncated */
    CHECK(qv_image_parse(slot, QV_HEADER_SPACE + 100, QV_IMG_STAGE2, &h, &pl) == QV_ERR_SIZE); /* payload > blob */
    { qv_image_header_t x; memcpy(&x, slot, sizeof x);
      x.payload_size = 0xFFFFFFFFu; memcpy(slot, &x, sizeof x);
      CHECK(qv_image_parse(slot, sizeof slot, QV_IMG_STAGE2, &h, &pl) == QV_ERR_SIZE);      /* integer-overflow style */
      x.payload_size = 4096; x.load_addr = 0xFFFFFFFFFFFFFFF0ULL; memcpy(slot, &x, sizeof x);
      CHECK(qv_image_parse(slot, sizeof slot, QV_IMG_STAGE2, &h, &pl) == QV_ERR_RANGE);     /* wraps address space */
      x.load_addr = 0x41000000; x.entry_point = 0x41000000 + 4096; memcpy(slot, &x, sizeof x);
      CHECK(qv_image_parse(slot, sizeof slot, QV_IMG_STAGE2, &h, &pl) == QV_ERR_RANGE);     /* entry past payload */
      x.entry_point = 0x41000002; memcpy(slot, &x, sizeof x);
      CHECK(qv_image_parse(slot, sizeof slot, QV_IMG_STAGE2, &h, &pl) == QV_ERR_RANGE);     /* misaligned entry */
      x.entry_point = 0x41000000; x.load_addr = 0x50000000; memcpy(slot, &x, sizeof x);
      CHECK(qv_image_parse(slot, sizeof slot, QV_IMG_STAGE2, &h, &pl) == QV_ERR_RANGE);     /* outside window */
    }
    /* Exhaustive single-byte header corruption: must never crash (ASan/UBSan enforce) and never verify OK. */
    make_image(slot, 12, 4096, 7);
    for (i = 0; i < (int)sizeof(qv_image_header_t); i++) {
        static uint8_t copy[0x100000];
        memcpy(copy, slot, sizeof copy); copy[i] ^= 0x01;
        CHECK(qv_secure_boot_load(QV_IMG_STAGE2, copy, sizeof copy, dest, &rep) != QV_OK);
    }
}

static void test_rollback_and_measure(void)
{
    qv_meas_state_t m; uint8_t d[32], pcr0[32]; uint32_t v;
    memset(&g_test_store, 0, sizeof g_test_store); g_test_store.magic = QV_STORE_MAGIC; g_test_store.layout_version = QV_STORE_LAYOUT;
    CHECK(qv_rollback_commit(QV_IMG_KERNEL, 5) == QV_OK);
    CHECK(qv_rollback_check(QV_IMG_KERNEL, 4) == QV_ERR_ROLLBACK);
    CHECK(qv_rollback_check(QV_IMG_KERNEL, 5) == QV_OK);
    CHECK(qv_rollback_commit(QV_IMG_KERNEL, 3) == QV_OK);              /* lowering is a no-op */
    CHECK(qv_storage_read_counter(QV_IMG_KERNEL, &v) == QV_OK && v == 5);
    CHECK(qv_storage_write_counter(QV_IMG_KERNEL, 2) == QV_ERR_ROLLBACK);

    qv_meas_init(&m); memset(d, 0x11, 32);
    CHECK(qv_meas_extend(&m, 0, "x", d) == 0);
    { uint8_t buf[64]; memset(buf, 0, 32); memcpy(buf + 32, d, 32); qv_sha256(buf, 64, pcr0); }
    CHECK(memcmp(m.pcr[0], pcr0, 32) == 0);                           /* PCR = H(0 || digest) */
    CHECK(qv_meas_extend(&m, 99, "bad", d) != 0);
}

static void host_write(uint8_t *d, const uint8_t *s, size_t n) { memcpy(d, s, n); }

static void test_slots_and_update(void)
{
    static uint8_t A[0x100000], B[0x100000], newimg[0x100000], scratch[0x100000];
    uint8_t *mem[2] = { A, B }; uint8_t order[2]; qv_slot_record_t r;
    unsigned t = QV_IMG_STAGE2, i;

    memset(&g_test_store, 0, sizeof g_test_store); g_test_store.magic = QV_STORE_MAGIC; g_test_store.layout_version = QV_STORE_LAYOUT;
    g_test_store.counters[t] = 12;
    g_test_store.slots[t].state[0] = QV_SLOT_VALID;
    make_image(A, 12, 1024, 1);

    /* Update with an older version is refused and flash is untouched. */
    make_image(newimg, 11, 1024, 2);
    CHECK(qv_update_install(t, newimg, sizeof newimg, mem, sizeof A, host_write, scratch) == QV_ERR_ROLLBACK);
    CHECK(B[0] == 0);

    /* Good update goes to inactive slot B as PENDING and becomes active. */
    make_image(newimg, 13, 1024, 2);
    CHECK(qv_update_install(t, newimg, sizeof newimg, mem, sizeof A, host_write, scratch) == QV_OK);
    qv_storage_get_slot(t, &r);
    CHECK(r.active == 1 && r.state[1] == QV_SLOT_PENDING && r.state[0] == QV_SLOT_VALID);
    CHECK(qv_slot_candidates(t, order) == 2 && order[0] == 1 && order[1] == 0);

    /* New image never proves itself: after MAX tries it is abandoned and A is used. */
    for (i = 0; i < QV_MAX_PENDING_TRIES; i++) qv_slot_begin_boot(t, 1);
    CHECK(qv_slot_candidates(t, order) == 1 && order[0] == 0);

    /* Torn update: target marked EMPTY, so even with active pointing nowhere good, B is not a candidate. */
    memset(&g_test_store.slots[t], 0, sizeof g_test_store.slots[t]);
    g_test_store.slots[t].state[0] = QV_SLOT_VALID; g_test_store.slots[t].state[1] = QV_SLOT_EMPTY;
    CHECK(qv_slot_candidates(t, order) == 1 && order[0] == 0);

    /* mark_good promotes. */
    g_test_store.slots[t].state[1] = QV_SLOT_PENDING;
    qv_slot_mark_good(t, 1); qv_storage_get_slot(t, &r);
    CHECK(r.active == 1 && r.state[1] == QV_SLOT_VALID);
}

/* ---- DTB tests: hand-built minimal tree + mutation sweep ---- */
static size_t be(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; return 4; }

static size_t build_dtb(uint8_t *b)
{   /* / { #address-cells=<2>; #size-cells=<2>; memory@40000000 { device_type="memory"; reg=<0 0x40000000 0 0x40000000>; }; } */
    static const char strs[] = "#address-cells\0#size-cells\0device_type\0reg\0";
    uint8_t st[256]; size_t n = 0, total;
    n += be(st + n, FDT_BEGIN_NODE); st[n++] = 0; st[n++] = 0; st[n++] = 0; st[n++] = 0;
    n += be(st + n, FDT_PROP); n += be(st + n, 4); n += be(st + n, 0); n += be(st + n, 2);
    n += be(st + n, FDT_PROP); n += be(st + n, 4); n += be(st + n, 15); n += be(st + n, 2);
    n += be(st + n, FDT_BEGIN_NODE); memcpy(st + n, "memory@40000000\0", 16); n += 16;
    n += be(st + n, FDT_PROP); n += be(st + n, 7); n += be(st + n, 27); memcpy(st + n, "memory\0", 7); st[n + 7] = 0; n += 8;
    n += be(st + n, FDT_PROP); n += be(st + n, 16); n += be(st + n, 39);
    n += be(st + n, 0); n += be(st + n, 0x40000000); n += be(st + n, 0); n += be(st + n, 0x40000000);
    n += be(st + n, FDT_END_NODE); n += be(st + n, FDT_END_NODE); n += be(st + n, FDT_END);
    total = 40 + 16 + n + sizeof strs;
    memset(b, 0, total);
    be(b, FDT_MAGIC); be(b + 4, (uint32_t)total); be(b + 8, 56); be(b + 12, (uint32_t)(56 + n)); be(b + 16, 40);
    be(b + 20, 17); be(b + 24, 16); be(b + 28, 0); be(b + 32, sizeof strs); be(b + 36, (uint32_t)n);
    memcpy(b + 56, st, n); memcpy(b + 56 + n, strs, sizeof strs);
    return total;
}

static void test_dtb(void)
{
    uint8_t b[512], c[512]; size_t n = build_dtb(b); uint64_t base, size; size_t i, k;
    CHECK(qv_dtb_validate(b, n) == QV_OK);
    CHECK(qv_dtb_find_memory(b, n, &base, &size) == QV_OK && base == 0x40000000ULL && size == 0x40000000ULL);
    CHECK(qv_dtb_validate(b, n - 1) == QV_ERR_DTB);                    /* truncated */
    CHECK(qv_dtb_validate(b, 20) == QV_ERR_DTB);
    CHECK(qv_dtb_validate(NULL, 100) == QV_ERR_DTB);
    memcpy(c, b, n); c[0] ^= 0xFF; CHECK(qv_dtb_validate(c, n) == QV_ERR_DTB);       /* bad magic */
    memcpy(c, b, n); be(c + 4, 0xFFFFFFF0u); CHECK(qv_dtb_validate(c, n) == QV_ERR_DTB); /* oversized total */
    memcpy(c, b, n); be(c + 36, 0xFFFFFFF0u); CHECK(qv_dtb_validate(c, n) == QV_ERR_DTB); /* struct size overflow */
    memcpy(c, b, n); c[n - 2] = 'x'; c[n - 1] = 'x'; CHECK(qv_dtb_validate(c, n) == QV_ERR_DTB);      /* unterminated string table */
    /* Every byte x several values: validation may accept or reject, but if it accepts, readers must be safe. */
    for (i = 0; i < n; i++) for (k = 0; k < 4; k++) {
        static const uint8_t v[4] = { 0x00, 0xFF, 0x7F, 0x80 };
        memcpy(c, b, n); c[i] = v[k];
        if (qv_dtb_validate(c, n) == QV_OK) { (void)qv_dtb_find_memory(c, n, &base, &size); }
    }
}


/* ---- DTB as an authenticated image type; revocation; lifecycle ---- */
static void make_typed_image(uint8_t *slot, uint32_t type, uint32_t role, uint32_t ver, uint64_t load,
                             const uint8_t *payload, uint32_t psize)
{
    qv_image_header_t h;
    uint8_t msg[QV_CERT_MSG_LEN], cert[64];
    memset(slot, 0, 0x100000);
    memcpy(slot + QV_HEADER_SPACE, payload, psize);
    memset(&h, 0, sizeof h);
    h.magic = QV_IMAGE_MAGIC; h.header_version = 1; h.header_size = sizeof h; h.image_type = type; h.fw_version = ver;
    h.load_addr = load; h.entry_point = load; h.payload_size = psize; h.hash_alg = 1; h.sig_alg = 1; h.key_id = 7; h.key_role = role;
    qv_sha256(payload, psize, h.payload_hash);
    qv_build_cert_msg(msg, 7, role, fw_pk); crypto_ed25519_sign(cert, root_sk, msg, sizeof msg);
    memcpy(h.signer_pubkey, fw_pk, 32); memcpy(h.signer_cert, cert, 64);
    crypto_ed25519_sign(h.signature, fw_sk, (uint8_t *)&h, QV_SIGNED_LEN);
    memcpy(slot, &h, sizeof h);
}

static void fresh_store(void)
{
    memset(&g_test_store, 0, sizeof g_test_store);
    g_test_store.magic = QV_STORE_MAGIC; g_test_store.layout_version = QV_STORE_LAYOUT;
}

static void test_dtb_authentication(void)
{
    static uint8_t slot[0x100000], dest[0x100000], fdt[512];
    uint8_t alt[512];
    qv_boot_report_t rep; size_t n = build_dtb(fdt);

    fresh_store();
    /* valid + authenticated */
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_DTB, 3, QV_DTB_WIN_BASE, fdt, (uint32_t)n);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_OK);
    CHECK(qv_dtb_validate(dest, rep.hdr.payload_size) == QV_OK);

    /* structurally VALID but content modified (RAM size changed) -> must fail authentication */
    memcpy(alt, fdt, n);
    { size_t i; for (i = 0; i < n; i++) { if (alt[i] == 0x40 && i > 100) { alt[i] = 0x20; break; } } }
    CHECK(qv_dtb_validate(alt, n) == QV_OK);                        /* still a well-formed tree ... */
    memcpy(slot + QV_HEADER_SPACE, alt, n);                         /* ... injected without re-signing */
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_ERR_HASH);
    CHECK(dest[0] == 0);                                            /* scrubbed */

    /* authenticated but malformed: signature fine, structure rejected (authentic != safe) */
    memcpy(alt, fdt, n); alt[0] ^= 0xFF;
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_DTB, 3, QV_DTB_WIN_BASE, alt, (uint32_t)n);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_OK);
    CHECK(qv_dtb_validate(dest, rep.hdr.payload_size) == QV_ERR_DTB);
    /* authenticated but truncated: blob shorter than the totalsize the header claims */
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_DTB, 3, QV_DTB_WIN_BASE, fdt, (uint32_t)n / 2);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_OK);
    CHECK(qv_dtb_validate(dest, rep.hdr.payload_size) == QV_ERR_DTB);

    /* a kernel-role signature must not authenticate a DTB (role separation) */
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_OS, 3, QV_DTB_WIN_BASE, fdt, (uint32_t)n);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_ERR_TYPE);
    /* load address outside the DTB window */
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_DTB, 3, 0x43000000, fdt, (uint32_t)n);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_ERR_RANGE);
    /* older than the floor */
    g_test_store.counters[QV_IMG_DTB] = 4;
    make_typed_image(slot, QV_IMG_DTB, QV_ROLE_DTB, 3, QV_DTB_WIN_BASE, fdt, (uint32_t)n);
    CHECK(qv_secure_boot_load(QV_IMG_DTB, slot, sizeof slot, dest, &rep) == QV_ERR_ROLLBACK);
}

static void test_revocation_and_lifecycle(void)
{
    static uint8_t slot[0x100000], dest[0x100000];
    qv_boot_report_t rep; uint8_t d[32];

    fresh_store(); make_image(slot, 12, 4096, 0x33);
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_OK);       /* not revoked: accepted */
    g_test_store.revoked_key[3] = 7;                                                         /* key id 7 revoked */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_ERR_REVOKED);
    CHECK(rep.v.sig == QV_OK && rep.v.cert == QV_OK && rep.v.hash == QV_OK);                 /* authentic, yet not trusted */
    CHECK(dest[0] == 0);
    g_test_store.revoked_key[3] = 8;                                                         /* different key revoked */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_OK);
    qv_sha256(slot + QV_HEADER_SPACE, 4096, d);                                              /* revoke by payload hash */
    memcpy(g_test_store.revoked_hash[5], d, 32);
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_ERR_REVOKED);
    make_image(slot, 12, 4096, 0x34);                                                        /* different payload: fine */
    CHECK(qv_secure_boot_load(QV_IMG_STAGE2, slot, sizeof slot, dest, &rep) == QV_OK);
    CHECK(qv_storage_lifecycle() == QV_LIFECYCLE_DEV);
    g_test_store.lifecycle = 1; CHECK(qv_storage_lifecycle() == QV_LIFECYCLE_PROD);
}

static void test_pe(void)
{
    uint8_t b[4096], c[4096]; size_t n = build_pe(b), i; qv_pe_info_t inf;
    CHECK(qv_pe_validate(b, n, QV_PE_MACHINE_ARM64, &inf) == QV_OK && inf.entry_rva == 0x1000 && inf.num_sections == 1);
    CHECK(qv_pe_validate(b, n, 0x8664, &inf) == QV_ERR_TYPE);                        /* wrong machine */
    CHECK(qv_pe_validate(b, 0x30, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_MAGIC);       /* truncated: DOS header */
    CHECK(qv_pe_validate(b, 0x90, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_SIZE);        /* truncated: PE headers */
    CHECK(qv_pe_validate(b, 0x500, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_SIZE);       /* section raw data past EOF */
    memcpy(c, b, n); c[0] = 'X';              CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_MAGIC);
    memcpy(c, b, n); pe_w32(c + 0x3C, 0xFFFFFFF0u); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) != QV_OK);  /* e_lfanew overflow */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 16, 0x1800); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_RANGE); /* entry outside code */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 16, 0x10);   CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_RANGE); /* entry in headers */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 56, 0x1800); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) != QV_OK);       /* SizeOfImage too small/unaligned */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 32, 3);      CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_RANGE); /* non-power-of-2 alignment */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 112 + 128 + 36, 0xE0000020); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_RANGE); /* W+X section */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 112 + 128 + 12, 0xFFFFF000); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) != QV_OK);  /* VA overflow */
    memcpy(c, b, n); pe_w32(c + 0x80 + 24 + 112 + 128 + 20, 0xFFFFFE00); CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) != QV_OK);  /* raw ptr overflow */
    memcpy(c, b, n); pe_w16(c + 0x80 + 6, 0);            CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_SIZE);  /* zero sections */
    memcpy(c, b, n); pe_w16(c + 0x80 + 6, 0xFFFF);       CHECK(qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf) == QV_ERR_SIZE);  /* too many sections */
    for (i = 0; i < n; i++) { memcpy(c, b, n); c[i] ^= 0xFF; (void)qv_pe_validate(c, n, QV_PE_MACHINE_ARM64, &inf); }          /* sanitizers watch */
    for (i = 0; i < n; i++) { (void)qv_pe_validate(b, i, QV_PE_MACHINE_ARM64, &inf); }                                       /* every truncation */
}

int main(void)
{
    keys();
    test_sha256(); test_ed25519_rfc8032(); test_parse_and_verify();
    test_rollback_and_measure(); test_slots_and_update(); test_dtb();
    test_dtb_authentication(); test_revocation_and_lifecycle(); test_pe();
    printf("unit tests: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
