#!/usr/bin/env bash
# Build signed A/B images, the image "flash" and the persistent-state pflash. Everything is
# overridable so tests can create rollback / revocation / tamper scenarios:
#   S2A_VER S2B_VER UA_VER UB_VER KA_VER KB_VER DA_VER DB_VER    image security versions
#   CNT_S2 CNT_UEFI CNT_KERNEL CNT_DTB                           anti-rollback floors in the store
#   KA_PAYLOAD=file                                              use another payload for kernel slot A
#   DTB_KEYDIR=dir                                               sign the DTBs with another key hierarchy
#   LIFECYCLE=dev|prod  REVOKE_KEY=id[,id]  REVOKE_PAYLOAD=file[,file]
#   OUT=path  (writes OUT and OUT.pflash)
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD=build
OUT=${OUT:-$BUILD/flash.img}
W=$(mktemp -d "$BUILD/flash.XXXXXX")
trap 'rm -rf "$W"' EXIT
Q=$BUILD/tools/qvbuild

mk() { # name type version load payload keyid [keydir]
    $Q image --type "$2" --version "$3" --load "$4" --entry "$4" --key-id "$6" --payload "$5" --out "$W/$1.unsigned"
    KEYDIR=${7:-keys} scripts/sign.sh "$2" "$W/$1.unsigned" "$W/$1.img"
}
mk s2a stage2 "${S2A_VER:-12}" 0x41000000 $BUILD/stage2.bin 1
mk s2b stage2 "${S2B_VER:-12}" 0x41000000 $BUILD/stage2.bin 1
mk ua  uefi   "${UA_VER:-5}"   0x42000000 $BUILD/payloads/uefi.bin 2
mk ub  uefi   "${UB_VER:-5}"   0x42000000 $BUILD/payloads/uefi.bin 2
mk ka  kernel "${KA_VER:-13}"  0x43000000 "${KA_PAYLOAD:-$BUILD/payloads/kernel.bin}" 3
mk kb  kernel "${KB_VER:-12}"  0x43000000 $BUILD/payloads/kernel.bin 3
mk da  dtb    "${DA_VER:-3}"   0x44000000 ${DTB:-$BUILD/virt.dtb} 4 "${DTB_KEYDIR:-keys}"
mk db  dtb    "${DB_VER:-3}"   0x44000000 ${DTB:-$BUILD/virt.dtb} 4 "${DTB_KEYDIR:-keys}"

$Q store --stage2 "${CNT_S2:-12}" --uefi "${CNT_UEFI:-5}" --kernel "${CNT_KERNEL:-12}" --dtb "${CNT_DTB:-3}" \
         --lifecycle "${LIFECYCLE:-dev}" --revoke-key "${REVOKE_KEY:-}" --revoke-payload "${REVOKE_PAYLOAD:-}" \
         --out "$W/store.bin"
$Q flash --out "$OUT" --stage2a "$W/s2a.img" --stage2b "$W/s2b.img" --uefia "$W/ua.img" --uefib "$W/ub.img" \
         --kernela "$W/ka.img" --kernelb "$W/kb.img" --dtba "$W/da.img" --dtbb "$W/db.img"
# pflash bank 1 on QEMU virt must be exactly 64 MiB; the store lives in sector 0.
rm -f "$OUT.pflash"; truncate -s 64M "$OUT.pflash"
dd if="$W/store.bin" of="$OUT.pflash" conv=notrunc status=none
echo "flash image: $OUT (+ $OUT.pflash)"
