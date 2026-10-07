/* qvsign: key management and image signing for the QVault hierarchy.
 *   qvsign keygen  --out PREFIX                       -> PREFIX.key (64B secret) PREFIX.pub (32B)
 *   qvsign certify --root-key F --pub F --key-id N --role fw|uefi|os|dtb --out F
 *   qvsign sign    --image F --key F --pub F --cert F --root-pub F --out F
 *   qvsign header  --pub F --out root_pubkey.h        -> C header for the firmware key store
 *   qvsign sign-blob   --in F --key F --out SIG                       (detached Ed25519 signature)
 *   qvsign verify-blob --in F --sig SIG --pub F --cert F --root-pub F --key-id N --role R
 *        -> exit 0 only if the signer key is certified by the root for that id/role AND the signature is valid */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qvtool.h"
#include "image_format.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static uint32_t role_from_name(const char *s)
{
    if (!strcmp(s, "fw"))   { return QV_ROLE_FIRMWARE; }
    if (!strcmp(s, "uefi")) { return QV_ROLE_UEFI; }
    if (!strcmp(s, "os"))   { return QV_ROLE_OS; }
    if (!strcmp(s, "dtb"))  { return QV_ROLE_DTB; }
    qt_die("unknown --role '%s'", s);
}

static void need(const uint8_t *p, size_t have, size_t want, const char *what)
{
    if (!p || have != want) { qt_die("%s must be exactly %zu bytes (got %zu)", what, want, have); }
}

static int cmd_keygen(int argc, char **argv)
{
    uint8_t seed[32], sk[64], pk[32];
    char path[512];
    const char *pre = qt_opt(argc, argv, "--out", "");
    if (!*pre) { qt_die("--out PREFIX required"); }
    qt_random(seed, sizeof seed);
    crypto_ed25519_key_pair(sk, pk, seed);          /* wipes seed */
    snprintf(path, sizeof path, "%s.key", pre); qt_write_file(path, sk, sizeof sk);
    snprintf(path, sizeof path, "%s.pub", pre); qt_write_file(path, pk, sizeof pk);
    crypto_wipe(sk, sizeof sk);
    return 0;
}

static int cmd_certify(int argc, char **argv)
{
    size_t kl, pl;
    uint8_t *rk = qt_read_file(qt_opt(argc, argv, "--root-key", ""), &kl);
    uint8_t *pk = qt_read_file(qt_opt(argc, argv, "--pub", ""), &pl);
    uint8_t msg[QV_CERT_MSG_LEN], cert[64];
    need(rk, kl, 64, "root key"); need(pk, pl, 32, "public key");
    qv_build_cert_msg(msg, (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--key-id", "1")),
                      role_from_name(qt_opt(argc, argv, "--role", "")), pk);
    crypto_ed25519_sign(cert, rk, msg, sizeof msg);
    qt_write_file(qt_opt(argc, argv, "--out", "key.cert"), cert, sizeof cert);
    crypto_wipe(rk, kl);
    return 0;
}

static int cmd_sign(int argc, char **argv)
{
    size_t il, kl, pl, cl, rl;
    uint8_t *img = qt_read_file(qt_opt(argc, argv, "--image", ""), &il);
    uint8_t *sk  = qt_read_file(qt_opt(argc, argv, "--key", ""), &kl);
    uint8_t *pk  = qt_read_file(qt_opt(argc, argv, "--pub", ""), &pl);
    const uint8_t *ct  = qt_read_file(qt_opt(argc, argv, "--cert", ""), &cl);
    uint8_t *rp  = qt_read_file(qt_opt(argc, argv, "--root-pub", ""), &rl);
    qv_image_header_t h;
    uint8_t msg[QV_CERT_MSG_LEN];

    need(sk, kl, 64, "signing key"); need(pk, pl, 32, "public key");
    need(ct, cl, 64, "certificate"); need(rp, rl, 32, "root public key");
    if (il < QV_HEADER_SPACE) { qt_die("image too small"); }

    memcpy(&h, img, sizeof h);
    if (h.magic != QV_IMAGE_MAGIC) { qt_die("not a QVault image"); }
    memcpy(h.signer_pubkey, pk, 32);
    memcpy(h.signer_cert, ct, 64);
    crypto_ed25519_sign(h.signature, sk, (const uint8_t *)&h, QV_SIGNED_LEN);

    /* Refuse to emit an image the device would reject. */
    qv_build_cert_msg(msg, h.key_id, h.key_role, pk);
    if (crypto_ed25519_check(h.signer_cert, rp, msg, sizeof msg) != 0) {
        qt_die("certificate does not match key_id/role in header (or wrong root key)");
    }
    if (crypto_ed25519_check(h.signature, pk, (const uint8_t *)&h, QV_SIGNED_LEN) != 0) {
        qt_die("signature self-check failed (key/pub mismatch?)");
    }
    memcpy(img, &h, sizeof h);
    qt_write_file(qt_opt(argc, argv, "--out", "signed.img"), img, il);
    crypto_wipe(sk, kl);
    return 0;
}

static int cmd_header(int argc, char **argv)
{
    size_t pl, i;
    const uint8_t *pk = qt_read_file(qt_opt(argc, argv, "--pub", ""), &pl);
    FILE *f = fopen(qt_opt(argc, argv, "--out", "root_pubkey.h"), "w");
    need(pk, pl, 32, "root public key");
    if (!f) { qt_die("cannot write header"); }
    fprintf(f, "/* GENERATED - root PUBLIC key (device root of trust). Contains no secrets. */\n");
    fprintf(f, "#ifndef QV_ROOT_PUBKEY_H\n#define QV_ROOT_PUBKEY_H\n#include <stdint.h>\n");
    fprintf(f, "static const uint8_t qv_root_pubkey[32] = {");
    for (i = 0; i < 32; i++) { fprintf(f, "%s0x%02x,", (i % 8) ? " " : "\n    ", pk[i]); }
    fprintf(f, "\n};\n#endif\n");
    fclose(f);
    return 0;
}

static uint8_t *read_all(const char *path, size_t *n) { return qt_read_file(path, n); }

static int cmd_sign_blob(int argc, char **argv)
{
    size_t il, kl;
    const uint8_t *in = read_all(qt_opt(argc, argv, "--in", ""), &il);
    uint8_t *sk = read_all(qt_opt(argc, argv, "--key", ""), &kl);
    uint8_t sig[64];
    need(sk, kl, 64, "signing key");
    crypto_ed25519_sign(sig, sk, in, il);
    qt_write_file(qt_opt(argc, argv, "--out", "blob.sig"), sig, sizeof sig);
    crypto_wipe(sk, kl);
    return 0;
}

static int cmd_verify_blob(int argc, char **argv)
{
    size_t il, sl, pl, cl, rl;
    const uint8_t *in = read_all(qt_opt(argc, argv, "--in", ""), &il);
    const uint8_t *sg = read_all(qt_opt(argc, argv, "--sig", ""), &sl);
    const uint8_t *pk = read_all(qt_opt(argc, argv, "--pub", ""), &pl);
    const uint8_t *ct = read_all(qt_opt(argc, argv, "--cert", ""), &cl);
    const uint8_t *rp = read_all(qt_opt(argc, argv, "--root-pub", ""), &rl);
    uint8_t msg[QV_CERT_MSG_LEN];
    need(sg, sl, 64, "signature"); need(pk, pl, 32, "public key"); need(ct, cl, 64, "certificate"); need(rp, rl, 32, "root public key");
    qv_build_cert_msg(msg, (uint32_t)qt_parse_u64(qt_opt(argc, argv, "--key-id", "0")),
                      role_from_name(qt_opt(argc, argv, "--role", "")), pk);
    if (crypto_ed25519_check(ct, rp, msg, sizeof msg) != 0) { fprintf(stderr, "VERIFY FAIL: signer key not certified by root\n"); return 1; }
    if (crypto_ed25519_check(sg, pk, in, il) != 0) { fprintf(stderr, "VERIFY FAIL: bad signature\n"); return 1; }
    printf("VERIFY OK\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "keygen"))  { return cmd_keygen(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "certify")) { return cmd_certify(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "sign"))    { return cmd_sign(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "header"))  { return cmd_header(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "sign-blob"))   { return cmd_sign_blob(argc, argv); }
    if (argc >= 2 && !strcmp(argv[1], "verify-blob")) { return cmd_verify_blob(argc, argv); }
    fprintf(stderr, "usage: qvsign keygen|certify|sign|header|sign-blob|verify-blob ...\n");
    return 2;
}
