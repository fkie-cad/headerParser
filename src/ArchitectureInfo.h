#ifndef HEADER_PARSER_ARCHITECTURE_INFO_H
#define HEADER_PARSER_ARCHITECTURE_INFO_H

#include <stdint.h>
#include <string.h>

#include "stringPool.h"
#include "elf/ElfInstructionSetArchitecture.h"
#include "macho/MachOCPUTypes.h"
#include "pe/PEMachineTypes.h"

#define ARCHITECTURE_NAME_LN 80

typedef struct Architecture
{
	uint32_t id;
	char name[ARCHITECTURE_NAME_LN];
} Architecture;

typedef struct ArchitectureMapEntry
{
	Architecture arch;
	uint16_t arch_id;
	uint8_t bitness;
} ArchitectureMapEntry;

ArchitectureMapEntry no_arch = { { 0, MACHINE_NONE }, 0, 0 };

//{peID, archId, bitness}
ArchitectureMapEntry pe_arch_id_mapper[] = {
//	{ {IMAGE_FILE_MACHINE_TARGET_HOST, "Interacts with the host and not a WOW64 guest"}, XX, 32 },
	{ {IMAGE_FILE_MACHINE_ALPHA, "DEC Alpha AXP"}, ARCH_ALPHA, 64 },
	{ {IMAGE_FILE_MACHINE_ALPHA64, "DEC Alpha AXP 64"}, ARCH_ALPHA, 64 },
	{ {IMAGE_FILE_MACHINE_AM33, "Matsushita AM33"}, ARCH_MATSUSHITA, 32 },
	{ {IMAGE_FILE_MACHINE_AMD64, "AMD x64"}, ARCH_INTEL, 64 },
	{ {IMAGE_FILE_MACHINE_ARM, "ARM little endian"}, ARCH_ARM, 32 },
	{ {IMAGE_FILE_MACHINE_ARM64, "ARM64 little endian"}, ARCH_ARM, 64 },
	{ {IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 little endian"}, ARCH_ARM, 32 },
	{ {IMAGE_FILE_MACHINE_AXP64, "DEC Alpha AXP 64"}, ARCH_ALPHA, 64 },
	{ {IMAGE_FILE_MACHINE_CEE, "CEE"}, ARCH_CEE, 0 },
	{ {IMAGE_FILE_MACHINE_CEF, "CEF"}, ARCH_CEF, 0 },
	{ {IMAGE_FILE_MACHINE_DEC_ALPHA_AXP, "DEC Alpha AXP 32"}, ARCH_ALPHA, 64 },
	{ {IMAGE_FILE_MACHINE_EBC, "EFI byte code"}, ARCH_EFI_BYTE_CODE, 32 },
	{ {IMAGE_FILE_MACHINE_I386, "Intel 386"}, ARCH_INTEL, 32 },
	{ {IMAGE_FILE_MACHINE_I860, "Intel i860/i486"}, ARCH_INTEL, 32 }, // ?? 64
	{ {IMAGE_FILE_MACHINE_I80586, "Intel 80586"}, ARCH_INTEL, 32 },
	{ {IMAGE_FILE_MACHINE_IA64, "Intel Itanium"}, ARCH_INTEL, 32 },
	{ {IMAGE_FILE_MACHINE_M32R, "Mitsubishi M32R little endian"}, ARCH_MITSUBISHI, 32 },
	{ {IMAGE_FILE_MACHINE_MIPS16, "MIPS16"}, ARCH_MIPS, 16 },
	{ {IMAGE_FILE_MACHINE_MIPSFPU, "MIPS with FPU"}, ARCH_MIPS, 32 },
	{ {IMAGE_FILE_MACHINE_MIPSFPU16, "MIPS16 with FPU"}, ARCH_MIPS, 16 },
	{ {IMAGE_FILE_MACHINE_POWERPC, "Power PC little endian"}, ARCH_PPC, 32 },
	{ {IMAGE_FILE_MACHINE_POWERPCFP, "Power PC with floating point support"}, ARCH_PPC, 32 },
	{ {IMAGE_FILE_MACHINE_R3000, "MIPS R3000 little-endian"}, ARCH_MIPS, 32 },
	{ {IMAGE_FILE_MACHINE_R3000_BE, "MIPS R3000 big-endian"}, ARCH_MIPS, 32 },
	{ {IMAGE_FILE_MACHINE_R4000, "MIPS R4000 little endian"}, ARCH_MIPS, 64 },
	{ {IMAGE_FILE_MACHINE_R10000, "MIPS R10000 little endian"}, ARCH_MIPS, 64 },
	{ {IMAGE_FILE_MACHINE_RISCV32, "RISC-V 32-bit address space"}, ARCH_RISC_V, 32 },
	{ {IMAGE_FILE_MACHINE_RISCV64, "RISC-V 64-bit address space"}, ARCH_RISC_V, 64 },
	{ {IMAGE_FILE_MACHINE_RISCV128, "RISC-V 128-bit address space"}, ARCH_RISC_V, 128 },
	{ {IMAGE_FILE_MACHINE_SH3, "Hitachi SH3 little-endian"}, ARCH_HITACHI, 32 },
	{ {IMAGE_FILE_MACHINE_SH3DSP, "Hitachi SH3 DSP"}, ARCH_HITACHI, 32 },
	{ {IMAGE_FILE_MACHINE_SH3E, "SH3E little-endian"}, ARCH_HITACHI, 32 },
	{ {IMAGE_FILE_MACHINE_SH4, "Hitachi SH4 little-endian"}, ARCH_HITACHI, 32 },
	{ {IMAGE_FILE_MACHINE_SH5, "Hitachi SH5"}, ARCH_HITACHI, 64 },
	{ {IMAGE_FILE_MACHINE_THUMB, "Thumb"}, ARCH_ARM, 16 },
	{ {IMAGE_FILE_MACHINE_TRICORE, "Infineon Tricore"}, ARCH_INFINEON, 32 },
	{ {IMAGE_FILE_MACHINE_WCEMIPSV2, "MIPS little-endian WCE v2"}, ARCH_MIPS, 32 },
};
const size_t pe_arch_id_mapper_size = (sizeof(pe_arch_id_mapper)/sizeof(ArchitectureMapEntry));

//{elfId, archId, bitness}
ArchitectureMapEntry elf_arch_id_mapper[] = {
	{ {EM_M32, "AT&T WE 32100"}, ARCH_ATT, 32 },
	{ {EM_SPARC, "SPARC"}, ARCH_SPARC, 64 }, // 32 ??
	{ {EM_386, "Intel 80386"}, ARCH_INTEL, 32 },
	{ {EM_68K, "Motorola 68000"}, ARCH_MOTOROLA_68K, 32 },
	{ {EM_88K, "Motorola 88000"}, ARCH_MOTOROLA_88K, 32 },
	{ {EM_IAMCU, "Intel MCU"}, ARCH_INTEL, 32 },
	{ {EM_860, "Intel 80860"}, ARCH_INTEL, 32 },  // ?? 64
	{ {EM_MIPS, "MIPS RS3000"}, ARCH_MIPS, 32 },
	{ {EM_S370, "IBM System/370 Processor"}, ARCH_IBM, 31 },
	{ {EM_MIPS_RS4_BE, "MIPS R4000"}, ARCH_MIPS, 32 },
	// 11 - 14,
	{ {EM_PARISC, "Hewlett-Packard PA-RISC"}, ARCH_PA_RISC, 32 },
	// 16,
	{ {EM_VPP500, "Fujitsu VPP500"}, ARCH_FUJITSU, 0 }, // 256 ??
	{ {EM_SPARC32PLUS, "Enhanced instruction set SPARC"}, ARCH_SPARC, 32 },
	{ {EM_960, "Intel 80960"}, ARCH_INTEL, 33 },
	{ {EM_PPC, "PowerPC"}, ARCH_PPC, 32 },
	{ {EM_PPC64, "64-bit PowerPC"}, ARCH_PPC, 64 },
	{ {EM_S390, "IBM System/390 Processor"}, ARCH_IBM, 31 }, // ?? 31/32/64
	{ {EM_SPU, "IBM SPU/SPC"}, ARCH_IBM, 128 },
	{ {EM_V800, "NEC V800"}, ARCH_NEC, 32 },
	{ {EM_FR20, "Fujitsu FR20"}, ARCH_FUJITSU, 32 },
	{ {EM_RH32, "TRW RH-32"}, ARCH_TRW, 32 },
	{ {EM_RCE, "Motorola RCE"}, ARCH_MOTOROLA, 32 },
	{ {EM_ARM, "Advanced RISC Machines ARM"}, ARCH_ARM, 32},
	{ {EM_ALPHA, "Digital Alpha"}, ARCH_ALPHA, 64 },
	{ {EM_SH, "Hitachi SH"}, ARCH_HITACHI, 32 },
	{ {EM_SPARCV9, "SPARC Version 9"}, ARCH_SPARC, 64 },
	{ {EM_TRICORE, "Siemens TriCore embedded processor"}, ARCH_SIEMENS, 32 },
	{ {EM_ARC, "Argonaut RISC Core, Argonaut Technologies Inc."}, ARCH_RISC, 32 },
	{ {EM_H8_300, "Hitachi H8/300"}, ARCH_HITACHI, 16 }, // 8/16
	{ {EM_H8_300H, "Hitachi H8/300H"}, ARCH_HITACHI, 32 }, // 16/32
	{ {EM_H8S, "Hitachi H8S"}, ARCH_HITACHI, 32 }, // 16/32
	{ {EM_H8_500, "Hitachi H8/500"}, ARCH_HITACHI, 16 }, // 8/16
	{ {EM_IA_64, "Intel IA-64 processor architecture"}, ARCH_INTEL, 64 },
	{ {EM_MIPS_X, "Stanford MIPS-X"}, ARCH_MIPS, 32 },
	{ {EM_COLDFIRE, "Motorola ColdFire"}, ARCH_MOTOROLA, 32 }, // 16/32/48
	{ {EM_68HC12, "Motorola M68HC12"}, ARCH_MOTOROLA, 16 }, // 8/16
	{ {EM_MMA, "Fujitsu MMA Multimedia Accelerator"}, ARCH_FUJITSU, 0 },
	{ {EM_PCP, "Siemens PCP"}, ARCH_SIEMENS, 0 },
	{ {EM_NCPU, "Sony nCPU embedded RISC processor"}, ARCH_RISC, 0 },
	{ {EM_NDR1, "Denso NDR1 microprocessor"}, ARCH_DENSO, 0 },
	{ {EM_STARCORE, "Motorola Star*Core processor"}, ARCH_MOTOROLA, 32 }, // ??
	{ {EM_ME16, "Toyota ME16 processor"}, ARCH_TOYOTA, 0 },
	{ {EM_ST100, "STMicroelectronics ST100 processor"}, ARCH_STM, 32 }, // 16/32
	{ {EM_TINYJ, "Advanced Logic Corp. TinyJ embedded processor family"}, ARCH_ALC, 32 },
	{ {EM_X86_64, "AMD x86-64 architecture"}, ARCH_INTEL, 64 },
	{ {EM_PDSP, "Sony DSP Processor"}, ARCH_SONY, 0 },
	{ {EM_PDP10, "Digital Equipment Corp. PDP-10"}, ARCH_DEC, 36 }, // ??
	{ {EM_PDP11, "Digital Equipment Corp. PDP-11"}, ARCH_DEC, 16 },
	{ {EM_FX66, "Siemens FX66 microcontroller"}, ARCH_SIEMENS, 0 },
	{ {EM_ST9PLUS, "STMicroelectronics ST9+ 8/16 bit microcontroller"}, ARCH_STM, 16 },
	{ {EM_ST7, "STMicroelectronics ST7 8-bit microcontroller"}, ARCH_STM, 8 },
	{ {EM_68HC16, "Motorola MC68HC16 Microcontroller"}, ARCH_MOTOROLA, 16 },
	{ {EM_68HC11, "Motorola MC68HC11 Microcontroller"}, ARCH_MOTOROLA, 8 },
	{ {EM_68HC08, "Motorola MC68HC08 Microcontroller"}, ARCH_MOTOROLA, 8 },
	{ {EM_68HC05, "Motorola MC68HC05 Microcontroller"}, ARCH_MOTOROLA, 8 },
	{ {EM_SVX, "Silicon Graphics SVx"}, ARCH_SG, 0 },
	{ {EM_ST19, "STMicroelectronics ST19 8-bit microcontroller"}, ARCH_STM, 8 },
	{ {EM_VAX, "Digital VAX"}, ARCH_DVAX, 32 },
	{ {EM_CRIS, "Axis Communications 32-bit embedded processor"}, ARCH_AXIS, 32 },
	{ {EM_JAVELIN, "Infineon Technologies 32-bit embedded processor"}, ARCH_INFINEON, 32 },
	{ {EM_FIREPATH, "Element 14 64-bit DSP Processor"}, ARCH_ELEMENT, 64 },
	{ {EM_ZSP, "LSI Logic 16-bit DSP Processor"}, ARCH_LSI, 16 },
	{ {EM_MMIX, "Donald Knuth's educational 64-bit processor"}, ARCH_KNUTH, 64 },
	{ {EM_HUANY, "Harvard University machine-independent object files"}, ARCH_HUMIOF, 0 },
	{ {EM_PRISM, "SiTera Prism"}, ARCH_SITERA, 0 },
	{ {EM_AVR, "Atmel AVR 8-bit microcontroller"}, ARCH_ATMEL, 8 },
	{ {EM_FR30, "Fujitsu FR30"}, ARCH_FUJITSU, 32 },
	{ {EM_D10V, "Mitsubishi D10V"}, ARCH_MITSUBISHI, 0 },
	{ {EM_D30V, "Mitsubishi D30V"}, ARCH_MITSUBISHI, 64 },
//		{ {EM_V850, "NEC v850"}, ARCH_xx, 0 },
	{ {EM_M32R, "Mitsubishi M32R"}, ARCH_MITSUBISHI, 32 },
	{ {EM_MN10300, "Matsushita MN10300"}, ARCH_MATSUSHITA, 32 },
	{ {EM_MN10200, "Matsushita MN10200"}, ARCH_MATSUSHITA, 0 },
	{ {EM_PJ, "picoJava"}, ARCH_PICO_JAVA, 0 }, // 32 ??
	{ {EM_OPENRISC, "OpenRISC 32-bit embedded processor"}, ARCH_RISC_OPEN, 32 },
	{ {EM_ARC_COMPACT, "ARC International ARCompact processor (aka: EM_ARC_A5)"}, ARCH_ARC, 32 },
	{ {EM_XTENSA, "Tensilica Xtensa Architecture"}, ARCH_TENSILICA, 32 },
	{ {EM_VIDEOCORE, "Alphamosaic VideoCore processor"}, ARCH_ALPHAMOSAIC, 0 },
	{ {EM_TMM_GPP, "Thomson Multimedia General Purpose Processor"}, ARCH_THOMPSON, 0 },
	{ {EM_NS32K, "National Semiconductor 32000 series"}, ARCH_NS, 0 }, // 32 ??
	{ {EM_TPC, "Tenor Network TPC processor"}, ARCH_TENOR, 0 },
	{ {EM_SNP1K, "Trebia SNP 1000 processor"}, ARCH_TREBIA, 0 },
	{ {EM_ST200, "STMicroelectronics (www.st.com) ST200 microcontroller"}, ARCH_STM, 0 },
	{ {EM_IP2K, "Ubicom IP2xxx microcontroller family"}, ARCH_UBICOM, 16 }, // 8/16
	{ {EM_MAX, "MAX Processor"}, ARCH_MAX, 0 },
	{ {EM_CR, "National Semiconductor CompactRISC microprocessor"}, ARCH_NS, 16 }, // 16 bit cr16,cr16c, 32 bit crx
	{ {EM_F2MC16, "Fujitsu F2MC16"}, ARCH_FUJITSU, 16 },
	{ {EM_MSP430, "Texas Instruments embedded microcontroller msp430"}, ARCH_TI, 16 },
	{ {EM_BLACKFIN, "Analog Devices Blackfin (DSP) processor"}, ARCH_BLACKFIN, 32 }, // 16/32
	{ {EM_SE_C33, "S1C33 Family of Seiko Epson processors"}, ARCH_EPSON, 32 },
	{ {EM_SEP, "Sharp embedded microprocessor"}, ARCH_SHARP, 0 },
	{ {EM_ARCA, "Arca RISC Microprocessor"}, ARCH_RISC, 32 },
	{ {EM_UNICORE, "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University"}, ARCH_PKU, 0 },
	{ {EM_EXCESS, "eXcess: 16/32/64-bit configurable embedded CPU"}, ARCH_EXCESS, 0 },
	{ {EM_DXP, "Icera Semiconductor Inc. Deep Execution Processor"}, ARCH_ICERA, 0 },
	{ {EM_ALTERA_NIOS2, "Altera Nios II soft-core processor"}, ARCH_ALTERA, 32 },
	{ {EM_CRX, "National Semiconductor CompactRISC CRX microprocessor"}, ARCH_NS, 32 },// 16 bit cr16,cr16c, 32 bit crx
	{ {EM_XGATE, "Motorola XGATE embedded processor"}, ARCH_MOTOROLA, 16 },
	{ {EM_C166, "Infineon C16x/XC16x processor"}, ARCH_INFINEON, 32 }, // 32 bit ARM Cortex Microcontroller : www.infineon.com
	{ {EM_M16C, "Renesas M16C series microprocessors"}, ARCH_RENESAS, 16 }, // 32/16-bit CISC microcomputer : www.renesas.com
	{ {EM_DSPIC30F, "Microchip Technology dsPIC30F Digital Signal Controller"}, ARCH_MT, 16 }, // ww1.microchip.com
	{ {EM_CE, "Freescale Communication Engine RISC core"}, ARCH_RISC, 32 }, // ??
	{ {EM_M32C, "Renesas M32C series microprocessors"}, ARCH_RENESAS, 32 },
	{ {EM_TSK3000, "Altium TSK3000 core"}, ARCH_ALTIUM, 32 }, // www.techdocs.altium.com : 32-bit RISC
	{ {EM_RS08, "Freescale RS08 embedded 77processor"}, ARCH_FREESCALE, 8 },
	{ {EM_SHARC, "Analog Devices SHARC family of 32-bit DSP processors"}, ARCH_BLACKFIN, 32 },
	{ {EM_ECOG2, "Cyan Technology eCOG2 microprocessor"}, ARCH_CYAN, 32 },
	{ {EM_SCORE7, "Sunplus S+core7 RISC processor"}, ARCH_RISC, 32 },
	{ {EM_DSP24, "New Japan Radio (NJR) 24-bit DSP Processor"}, ARCH_NJR, 24 },
	{ {EM_VIDEOCORE3, "Broadcom VideoCore III processor"}, ARCH_BROADCOM, 16 }, // ?? BCM272, BCM11181
	{ {EM_LATTICEMICO32, "RISC processor for Lattice FPGA architecture"}, ARCH_RISC, 32 },
	{ {EM_SE_C17, "Seiko Epson C17 family"}, ARCH_EPSON, 16 },
	{ {EM_TI_C6000, "The Texas Instruments TMS320C6000 DSP family"}, ARCH_TI, 32 }, //  ??
	{ {EM_TI_C2000, "The Texas Instruments TMS320C2000 DSP family"}, ARCH_TI, 32 },
	{ {EM_TI_C5500, "The Texas Instruments TMS320C55x DSP family"}, ARCH_TI, 32 }, //  ??
	{ {EM_TI_ARP32, "Texas Instruments Application Specific RISC Processor, 32bit fetch"}, ARCH_RISC, 32 }, // ??
	{ {EM_TI_PRU, "Texas Instruments Programmable Realtime Unit"}, ARCH_TI, 32 }, // ?? arm335x
	{ {EM_MMDSP_PLUS, "STMicroelectronics 64bit VLIW Data Signal Processor"}, ARCH_STM, 64 },
	{ {EM_CYPRESS_M8C, "Cypress M8C microprocessor"}, ARCH_CYPRESS, 8 },
	{ {EM_R32C, "Renesas R32C series microprocessors"}, ARCH_RENESAS, 32 },
	{ {EM_TRIMEDIA, "NXP Semiconductors TriMedia architecture family"}, ARCH_NXP, 32 }, // ??
	{ {EM_QDSP6, "QUALCOMM DSP6 Processor"}, ARCH_QUALCOMM, 32 },
	{ {EM_8051, "Intel 8051 and variants"}, ARCH_INTEL, 8 },
	{ {EM_STXP7X, "STMicroelectronics STxP7x family of configurable and extensible RISC processors"}, ARCH_RISC, 32 },
	{ {EM_NDS32, "Andes Technology compact code size embedded RISC processor family"}, ARCH_RISC, 32 }, // ??
	{ {EM_ECOG1, "Cyan Technology eCOG1X family"}, ARCH_CYAN, 16 },
//	{ {EM_ECOG1X, "Cyan Technology eCOG1X family"}, ARCH_xx, 0 },
	{ {EM_MAXQ30, "Dallas Semiconductor MAXQ30 Core Micro-controll"}, ARCH_DALLAS, 16 }, // RISC
	{ {EM_XIMO16, "New Japan Radio (NJR) 16-bit DSP Processor"}, ARCH_NJR, 16 },
	{ {EM_MANIK, "M2000 Reconfigurable RISC Microprocessor"}, ARCH_MIPS, 0 },
	{ {EM_CRAYNV2, "Cray Inc. NV2 vector architecture"}, ARCH_CRACY, 0 }, // 64 ??
	{ {EM_RX, "Renesas RX family"}, ARCH_RENESAS, 32 },
	{ {EM_METAG, "Imagination Technologies META processor architecture"}, ARCH_IMAGINATION, 32},
	{ {EM_MCST_ELBRUS, "MCST Elbrus general purpose hardware architecture"}, ARCH_MCST, 64 },
	{ {EM_ECOG16, "Cyan Technology eCOG16 family"}, ARCH_CYAN, 16 },
	{ {EM_CR16, "National Semiconductor CompactRISC CR16 16-bit microprocessor"}, ARCH_NS, 16 },
	{ {EM_ETPU, "Freescale Extended Time Processing Unit"}, ARCH_FREESCALE, 0 },
	{ {EM_SLE9X, "Infineon Technologies SLE9X core"}, ARCH_INFINEON, 16 },
	{ {EM_L10M, "Intel L10M"}, ARCH_INTEL, 0 }, // 32 ??
	{ {EM_K10M, "Intel K10M"}, ARCH_INTEL, 0 },
	{ {EM_AARCH64, "ARM 64-bit architecture (AARCH64)"}, ARCH_ARM, 64 },
	{ {EM_AVR32, "Atmel Corporation 32-bit microprocessor family"}, ARCH_ATMEL, 32 },  // RISC
	{ {EM_STM8, "STMicroeletronics STM8 8-bit microcontroller"}, ARCH_STM, 8 },
	{ {EM_TILE64, "Tilera TILE64 multicore architecture family"}, ARCH_TILERA, 0 }, // MIPS VLWI
	{ {EM_TILEPRO, "Tilera TILEPro multicore architecture family"}, ARCH_TILERA, 0 }, // 64 ??
	{ {EM_MICROBLAZE, "Xilinx MicroBlaze 32-bit RISC soft processor core"}, ARCH_RISC, 32 },
	{ {EM_CUDA, "NVIDIA CUDA architecture"}, ARCH_CUDA, 0 },
	{ {EM_TILEGX, "Tilera TILE-Gx multicore architecture family"}, ARCH_TILERA, 0 }, // 64 ??
	{ {EM_CLOUDSHIELD, "CloudShield architecture family"}, ARCH_CLOUD_SHIELD, 0 },
	{ {EM_COREA_1ST, "KIPO-KAIST Core-A 1st generation processor family"}, ARCH_KIPO, 0 }, // ?? 32
	{ {EM_COREA_2ND, "KIPO-KAIST Core-A 2nd generation processor family"}, ARCH_KIPO, 0 }, // ?? 32
	{ {EM_ARC_COMPACT2, "Synopsys ARCompact V2"}, ARCH_ARC, 32 }, // 16/32
	{ {EM_OPEN8, "Open8 8-bit RISC soft processor core"}, ARCH_RISC, 8 },
	{ {EM_RL78, "Renesas RL78 family"}, ARCH_RENESAS, 16 }, // 8/16
	{ {EM_VIDEOCORE5, "Broadcom VideoCore V processor"}, ARCH_BROADCOM, 32 }, // ??  BCM7251
	{ {EM_78KOR, "Renesas 78KOR family"}, ARCH_RENESAS, 16 },
	{ {EM_56800EX, "Freescale 56800EX Digital Signal Controller (DSC)"}, ARCH_FREESCALE, 32 },
	{ {EM_BA1, "Beyond BA1 CPU architecture"}, ARCH_BEYOND, 32 }, // beyondsemi.com
	{ {EM_BA2, "Beyond BA2 CPU architecture"}, ARCH_BEYOND, 32 },
	{ {EM_XCORE, "XMOS xCORE processor family"}, ARCH_XMOS, 32 },
	{ {EM_MCHP_PIC, "Microchip 8-bit PIC(r) family"}, ARCH_MT, 8 },
	{ {EM_INTEL205, "Reserved by Intel"}, ARCH_INTEL, 0 },
	{ {EM_INTEL206, "Reserved by Intel"}, ARCH_INTEL, 0 },
	{ {EM_INTEL207, "Reserved by Intel"}, ARCH_INTEL, 0 },
	{ {EM_INTEL208, "Reserved by Intel"}, ARCH_INTEL, 0 },
	{ {EM_INTEL209, "Reserved by Intel"}, ARCH_INTEL, 0 },
	{ {EM_KM32, "KM211 KM32 32-bit processor"}, ARCH_KM, 32 },
	{ {EM_KMX32, "KM211 KMX32 32-bit processor"}, ARCH_KM, 32 },
	{ {EM_KMX16, "KM211 KMX16 16-bit processor"}, ARCH_KM, 16 },
	{ {EM_KMX8, "KM211 KMX8 8-bit processor"}, ARCH_KM, 8 },
	{ {EM_KVARC, "KM211 KVARC processor"}, ARCH_KM, 32 },
	{ {EM_CDP, "Paneve CDP architecture family"}, ARCH_PANEVE, 0 },
	{ {EM_COGE, "Cognitive Smart Memory Processor"}, ARCH_CSMP, 0 },
	{ {EM_COOL, "Bluechip Systems CoolEngine"}, ARCH_BLUECHIP, 0 },
	{ {EM_NORC, "Nanoradio Optimized RISC"}, ARCH_RISC, 0 },
	{ {EM_CSR_KALIMBA, "CSR Kalimba architecture family"}, ARCH_CSR, 0 },
	{ {EM_Z80, "Zilog Z80"}, ARCH_ZILOG, 8 },
	{ {EM_VISIUM, "Controls and Data Services VISIUMcore processor"}, ARCH_VISUM, 0 },
	{ {EM_FT32, "FTDI Chip FT32 high performance 32-bit RISC architecture"}, ARCH_RISC, 32 },
	{ {EM_MOXIE, "Moxie processor family"}, ARCH_MOXIE, 0 }, // 32|48:16+32
	{ {EM_AMDGPU, "AMD GPU architecture"}, ARCH_AMD, 0 },
	{ {EM_RISCV, "RISC-V"}, ARCH_RISC_V, 0 },
};
const size_t elf_arch_id_mapper_size = (sizeof(elf_arch_id_mapper)/sizeof(ArchitectureMapEntry));

//{machOId, archId, bitness}
ArchitectureMapEntry mach_o_arch_id_mapper[] = {
	{ {CPU_TYPE_MC680X0, "m68k compatible CPUs"}, ARCH_MOTOROLA_68K, 32 },
	{ {CPU_TYPE_I386, "i386 and later compatible CPUs"}, ARCH_INTEL, 32},
	{ {CPU_TYPE_X86_64, "x86_64 (AMD64) compatible CPUs"}, ARCH_INTEL, 64 },
	{ {CPU_TYPE_ARM, "32-bit ARM compatible CPU"}, ARCH_ARM, 32 },
	{ {CPU_TYPE_MC88000, "m88k compatible CPUs"}, ARCH_MOTOROLA_88K, 32 },
	{ {CPU_TYPE_ARM64, "64-bit ARM compatible CPUs"}, ARCH_ARM, 64 },
	{ {CPU_TYPE_ARM64_32, "64-bit ARM compatible CPUs (running in 32-bit mode?)"}, ARCH_ARM, 64 },
	{ {CPU_TYPE_POWERPC, "PowerPC compatible CPUs"}, ARCH_PPC, 32 },
	{ {CPU_TYPE_POWERPC64, "PowerPC64 compatible CPUs\""}, ARCH_PPC, 64 },
};
const size_t mach_o_arch_id_mapper_size = (sizeof(mach_o_arch_id_mapper)/sizeof(ArchitectureMapEntry));

//{dexId, archId, bitness}
ArchitectureMapEntry dex_arch_id_mapper[] = {
	{ {0, "Dalvik dex file version xxx"}, ARCH_ANDROID, 32 },
};
const size_t dex_arch_id_mapper_size = (sizeof(dex_arch_id_mapper)/sizeof(ArchitectureMapEntry));

//{artId, archId, bitness}
ArchitectureMapEntry art_arch_id_mapper[] = {
	{ {0, "Android ART file version xxx"}, ARCH_ANDROID, 32 },
};
const size_t art_arch_id_mapper_size = (sizeof(art_arch_id_mapper)/sizeof(ArchitectureMapEntry));



ArchitectureMapEntry* getArchitecture(const uint32_t e_machine, ArchitectureMapEntry* map, const size_t size)
{
	ArchitectureMapEntry* entry;
	size_t i = 0;
	for ( i = 0; i < size; i++ )
	{
		entry = &map[i];
		if ( entry->arch.id == e_machine )
		{
			debug_info(" - architecture : %u, %s, %u, %d\n", entry->arch.id, entry->arch.name, entry->arch_id, entry->bitness);
			return entry;
		}
	}

	return &no_arch;
}

#endif
