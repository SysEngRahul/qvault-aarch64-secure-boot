#include "bootflow.h"
#include "log.h"
#include "barriers.h"

void qv_recovery_halt(const char *what)
{
    qv_printf("\n[RECOVERY] %s\n", what);
    qv_printf("[RECOVERY] No bootable image remains. Entering recovery mode (halt).\n");
    for (;;) { qv_wfe(); }
}
