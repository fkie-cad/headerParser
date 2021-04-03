#ifndef HEADER_PARSER_PE_MACHINE_TYPES_H
#define HEADER_PARSER_PE_MACHINE_TYPES_H

#include <stdint.h>

typedef enum PeMachineTypes {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0, // The contents of this field are assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001, // Interacts with the host and not a WOW64 guest
    IMAGE_FILE_MACHINE_I386 = 0x014c, // Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_I860 = 0x014d, // Intel 860
    IMAGE_FILE_MACHINE_I80586 = 0x014e, // Intel 80586
    IMAGE_FILE_MACHINE_R3000_BE = 0x0160, // MIPS big-endian
    IMAGE_FILE_MACHINE_R3000 = 0x0162, // MIPS little-endian
    IMAGE_FILE_MACHINE_R4000 = 0x0166, // MIPS little endian
    IMAGE_FILE_MACHINE_R10000 = 0x0168, // MIPS little endian
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169, // MIPS little-endian WCE v2
    IMAGE_FILE_MACHINE_DEC_ALPHA_AXP = 0x183, // DEC Alpha Axp (old)
    IMAGE_FILE_MACHINE_ALPHA = 0x0184, // Alpha_AXP
    IMAGE_FILE_MACHINE_SH3 = 0x1a2, // Hitachi SH3 little-endian
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3, // Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH3E = 0x01a4, // SH3E little-endian
    IMAGE_FILE_MACHINE_SH4 = 0x01a6, // Hitachi SH4 little-endian
    IMAGE_FILE_MACHINE_SH5 = 0x01a8, // Hitachi SH5
    IMAGE_FILE_MACHINE_ARM = 0x01c0, // ARM little endian
    IMAGE_FILE_MACHINE_THUMB = 0x01c2, // Thumb
    IMAGE_FILE_MACHINE_ARMNT = 0x01c4, // ARM Thumb-2 little endian
    IMAGE_FILE_MACHINE_AM33 = 0x01d3, // Matsushita AM33
    IMAGE_FILE_MACHINE_POWERPC = 0x01f0, // Power PC little endian
    IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1, // Power PC with floating point support
    IMAGE_FILE_MACHINE_IA64 = 0x200, // Intel Itanium processor family
    IMAGE_FILE_MACHINE_MIPS16 = 0x266, // MIPS16
    IMAGE_FILE_MACHINE_ALPHA64 = 0x0268, // ALPHA64
    IMAGE_FILE_MACHINE_AXP64 = 0x0284, // AXP64
    // IMAGE_FILE_MACHINE_MOTOROLA_68000 = 0x0284, // Motorola 68000 series
    IMAGE_FILE_MACHINE_MIPSFPU = 0x0366, // MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466, // MIPS16 with FPU
    IMAGE_FILE_MACHINE_TRICORE = 0x0520, // Infineon
    IMAGE_FILE_MACHINE_CEF = 0x0cef, // CEF
    IMAGE_FILE_MACHINE_EBC = 0x0ebc, // EFI byte code
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032, // RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064, // RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128, // RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64, // ARM64 little endian
    IMAGE_FILE_MACHINE_CEE = 0xC0EE, // CEE
    IMAGE_FILE_MACHINE_AMD64 = 0x8664, // AMD x64
    IMAGE_FILE_MACHINE_M32R = 0x9041, // Mitsubishi M32R little endian
} PeMachineTypes;

#endif
