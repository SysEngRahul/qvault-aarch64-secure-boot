/* One script for both stages. The build passes:
 *   --defsym=QV_IMG_BASE=<load address>   --defsym=QV_STACK_SIZE=<bytes>
 * Sections are 4 KiB aligned so the MMU can give text RX, rodata RO and
 * data/bss/stack RW+XN with page granularity. */
ENTRY(_start)

SECTIONS
{
    . = QV_IMG_BASE;
    __image_start = .;

    .text : ALIGN(4096) {
        __text_start = .;
        KEEP(*(.text.start))
        *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    }

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4096);
        __rodata_end = .;
    }

    .data : ALIGN(4096) {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(8);
        __data_end = .;
    }

    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    }

    .stack (NOLOAD) : ALIGN(4096) {
        . += QV_STACK_SIZE;
        __stack_top = .;
    }
    __image_end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.gnu*) *(.interp) }
}
