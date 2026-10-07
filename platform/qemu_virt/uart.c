/* PL011 polled console. QEMU's model needs no baud setup. */
#include <stdint.h>
#include "memmap.h"
#include "uart.h"

#define UARTDR   0x00U
#define UARTFR   0x18U
#define UARTCR   0x30U
#define FR_TXFF  (1U << 5)

static inline volatile uint32_t *reg(uint32_t off)
{
    return (volatile uint32_t *)(QV_UART0_BASE + off);
}

void qv_uart_init(void)
{
    *reg(UARTCR) = (1U << 0) | (1U << 8) | (1U << 9); /* UARTEN | TXE | RXE */
}

void qv_uart_putc(char c)
{
    if (c == '\n') { qv_uart_putc('\r'); }
    while (*reg(UARTFR) & FR_TXFF) { }
    *reg(UARTDR) = (uint32_t)(uint8_t)c;
}
