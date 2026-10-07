# QVaultSecurity (EDK II) — Phase 2, not yet implemented

Planned: an EDK II DXE/application module for ArmVirtQemu that
1. reads the QVault measurement log at `0x44100000` and publishes it (e.g. as a configuration table / TCG2-style events),
2. demonstrates Secure Boot variables (PK/KEK/db/dbx) and `EFI_SECURITY2_ARCH_PROTOCOL` image authentication,
3. validates PE/COFF headers (machine, sections, entry, alignment) before launch.

Today the "UEFI" stage in the chain is `payloads/uefi_stub.S`: a **signed, measured placeholder**, so the
chain Stage1 → Stage2 → UEFI → Kernel is authenticated end-to-end while the EDK II work is pending.
