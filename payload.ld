ENTRY(_start)
SECTIONS {
  . = 0x0;
  .text   : ALIGN(0x10) { *(.text._start) *(.text*) }
  .rodata : ALIGN(0x10) { *(.rodata*) }
  .data   : ALIGN(0x10) { *(.data*) }
  .bss    : ALIGN(0x10) { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
