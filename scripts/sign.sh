#!/usr/bin/env bash
# usage: sign.sh stage2|uefi|kernel|dtb UNSIGNED SIGNED     (KEYDIR=dir to use another key hierarchy)
set -euo pipefail
cd "$(dirname "$0")/.."
type=$1; in=$2; out=$3; KD=${KEYDIR:-keys}
case "$type" in stage2) role=fw;; uefi) role=uefi;; kernel) role=os;; dtb) role=dtb;; *) echo "bad type" >&2; exit 2;; esac
build/tools/qvsign sign --image "$in" --key "$KD/$role.key" --pub "$KD/$role.pub" \
    --cert "$KD/$role.cert" --root-pub "$KD/root.pub" --out "$out"
