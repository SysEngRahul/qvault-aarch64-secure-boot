#!/usr/bin/env bash
# Generate the key hierarchy into $KD/ (git-ignored):
#   root  -> certifies -> fw (Stage 2), uefi, os (kernel) signing keys
# On real hardware the root PRIVATE key lives in an HSM; only its hash is fused into the SoC.
set -euo pipefail
cd "$(dirname "$0")/.."
Q=build/tools/qvsign
KD=${KEYDIR:-keys}      # override to create e.g. an ATTACKER hierarchy for tests
mkdir -p "$KD"
umask 077
[ -f $KD/root.key ] || $Q keygen --out $KD/root
id=1
for role in fw uefi os dtb; do
    if [ ! -f "$KD/$role.key" ]; then
        $Q keygen --out "$KD/$role"
        $Q certify --root-key $KD/root.key --pub "$KD/$role.pub" --key-id "$id" --role "$role" --out "$KD/$role.cert"
    fi
    id=$((id + 1))
done
chmod 600 $KD/*.key
