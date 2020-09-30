#ifndef HEADER_PARSER_MACHO_CPU_TYPES_H
#define HEADER_PARSER_MACHO_CPU_TYPES_H

#include <stdint.h>

//# mask for CPUs with 64-bit architectures (when running a 64-bit ABI?)
#define CPU_ARCH_ABI64 0x01000000u

//# mask for CPUs with 64-bit architectures (when running a 32-bit ABI?)
//# @see https://github.com/Homebrew/ruby-macho/issues/113
#define CPU_ARCH_ABI32 0x02000000u

//# any CPU (unused?)
#define CPU_TYPE_ANY -1 

//# m68k compatible CPUs
#define CPU_TYPE_MC680X0 0x06 

//# i386 and later compatible CPUs
#define CPU_TYPE_I386 0x07u

//# x86_64 (AMD64) compatible CPUs
#define CPU_TYPE_X86_64 (CPU_TYPE_I386 | CPU_ARCH_ABI64) 

//# 32-bit ARM compatible CPUs
#define CPU_TYPE_ARM 0x0cu

//# m88k compatible CPUs
#define CPU_TYPE_MC88000 0xd 

//# 64-bit ARM compatible CPUs
#define CPU_TYPE_ARM64 (CPU_TYPE_ARM | CPU_ARCH_ABI64) 

//# 64-bit ARM compatible CPUs (running in 32-bit mode?)
//# @see https://github.com/Homebrew/ruby-macho/issues/113
#define CPU_TYPE_ARM64_32 (CPU_TYPE_ARM | CPU_ARCH_ABI32) 

//# PowerPC compatible CPUs
#define CPU_TYPE_POWERPC 0x12u

//# PowerPC64 compatible CPUs
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64) 

//# association of cpu types to symbol representations
//CPU_TYPES = {
//		CPU_TYPE_ANY => :any,
//		CPU_TYPE_I386 => :i386,
//		CPU_TYPE_X86_64 => :x86_64,
//		CPU_TYPE_ARM => :arm,
//		CPU_TYPE_ARM64 => :arm64,
//		CPU_TYPE_ARM64_32 => :arm64_32,
//		CPU_TYPE_POWERPC => :ppc,
//		CPU_TYPE_POWERPC64 => :ppc64,
//}.freeze

//# mask for CPU subtype capabilities
#define CPU_SUBTYPE_MASK 0xff000000 

//# 64-bit libraries (undocumented!)
//# @see http://llvm.org/docs/doxygen/html/Support_2MachO_8h_source.html
#define SUBTYPE_LIB64 0x80000000 
//
//# the lowest common sub-type for `CPU_TYPE_I386`
#define CPU_SUBTYPE_I386 3 
//
//# the i486 sub-type for `CPU_TYPE_I386`
#define SUBTYPE_486 4 
//
//# the i486SX sub-type for `CPU_TYPE_I386`
#define SUBTYPE_486SX 132 
//
//# the i586 (P5, Pentium) sub-type for `CPU_TYPE_I386`
#define CPU_SUBTYPE_586 5 
//
//# @see CPU_SUBTYPE_586
#define SUBTYPE_PENT CPU_SUBTYPE_586 
//
//# the Pentium Pro (P6) sub-type for `CPU_TYPE_I386`
#define SUBTYPE_PENTPRO 22 
//
//# the Pentium II (P6, M3?) sub-type for `CPU_TYPE_I386`
#define SUBTYPE_PENTII_M3 54 
//
//# the Pentium II (P6, M5?) sub-type for `CPU_TYPE_I386`
#define SUBTYPE_PENTII_M5 86 
//
//# the Pentium 4 (Netburst) sub-type for `CPU_TYPE_I386`
#define SUBTYPE_PENTIUM_4 10 
//
//# the lowest common sub-type for `CPU_TYPE_MC680X0`
#define CPU_SUBTYPE_MC680X0_ALL 1 
//
//# @see CPU_SUBTYPE_MC680X0_ALL
#define SUBTYPE_MC68030 CPU_SUBTYPE_MC680X0_ALL 
//
//# the 040 subtype for `CPU_TYPE_MC680X0`
#define SUBTYPE_MC68040 2 
//
//# the 030 subtype for `CPU_TYPE_MC680X0`
#define SUBTYPE_MC68030_ONLY 3 
//
//# the lowest common sub-type for `CPU_TYPE_X86_64`
#define SUBTYPE_X86_64_ALL CPU_SUBTYPE_I386 
//
//# the Haskell sub-type for `CPU_TYPE_X86_64`
#define SUBTYPE_X86_64_H 8 
//
//# the lowest common sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_ALL 0 
//
//# the v4t sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V4T 5 
//
//# the v6 sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V6 6 
//
//# the v5 sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V5TEJ 7 
//
//# the xscale (v5 family) sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_XSCALE 8 
//
//# the v7 sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7 9 
//
//# the v7f (Cortex A9) sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7F 10 
//
//# the v7s ("Swift") sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7S 11 
//
//# the v7k ("Kirkwood40") sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7K 12 
//
//# the v6m sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V6M 14 
//
//# the v7m sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7M 15 
//
//# the v7em sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V7EM 16 
//
//# the v8 sub-type for `CPU_TYPE_ARM`
#define SUBTYPE_ARM_V8 13 
//
//# the lowest common sub-type for `CPU_TYPE_ARM64`
#define SUBTYPE_ARM64_ALL 0 
//
//# the v8 sub-type for `CPU_TYPE_ARM64`
#define SUBTYPE_ARM64_V8 1 
//
//# the v8 sub-type for `CPU_TYPE_ARM64_32`
#define SUBTYPE_ARM64_32_V8 1 
//
//# the e (A12) sub-type for `CPU_TYPE_ARM64`
#define SUBTYPE_ARM64E 2 
//
//# the lowest common sub-type for `CPU_TYPE_MC88000`
#define CPU_SUBTYPE_MC88000_ALL 0 
//
//# @see CPU_SUBTYPE_MC88000_ALL
#define SUBTYPE_MMAX_JPC CPU_SUBTYPE_MC88000_ALL 
//
//# the 100 sub-type for `CPU_TYPE_MC88000`
#define SUBTYPE_MC88100 1 
//
//# the 110 sub-type for `CPU_TYPE_MC88000`
#define SUBTYPE_MC88110 2 
//
//# the lowest common sub-type for `CPU_TYPE_POWERPC`
#define CPU_SUBTYPE_POWERPC_ALL 0 
//
//# the 601 sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_601 1 
//
//# the 602 sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_602 2 
//
//# the 603 sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_603 3 
//
//# the 603e (G2) sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_603E 4 
//
//# the 603ev sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_603EV 5 
//
//# the 604 sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_604 6 
//
//# the 604e sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_604E 7 
//
//# the 620 sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_620 8 
//
//# the 750 (G3) sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_750 9 
//
//# the 7400 (G4) sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_7400 10 
//
//# the 7450 (G4 "Voyager") sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_7450 11 
//
//# the 970 (G5) sub-type for `CPU_TYPE_POWERPC`
#define SUBTYPE_POWERPC_970 100 
//
//# any CPU sub-type for CPU type `CPU_TYPE_POWERPC64`
#define SUBTYPE_POWERPC64_ALL CPU_SUBTYPE_POWERPC_ALL 
//
//# association of CPU types/subtype pairs to symbol representations in
//# (very) roughly descending order of commonness
//# @see https://opensource.apple.com/source/cctools/cctools-877.8/libstuff/arch.c
//CPU_SUBTYPES = {
//		CPU_TYPE_I386 => {
//			CPU_SUBTYPE_I386 => :i386,
//					CPU_SUBTYPE_486 => :i486,
//					CPU_SUBTYPE_486SX => :i486SX,
//					CPU_SUBTYPE_586 => :i586, # also "pentium" in arch(3)
//			CPU_SUBTYPE_PENTPRO => :i686, # also "pentpro" in arch(3)
//			CPU_SUBTYPE_PENTII_M3 => :pentIIm3,
//					CPU_SUBTYPE_PENTII_M5 => :pentIIm5,
//					CPU_SUBTYPE_PENTIUM_4 => :pentium4,
//		}.freeze,
//		CPU_TYPE_X86_64 => {
//			CPU_SUBTYPE_X86_64_ALL => :x86_64,
//					CPU_SUBTYPE_X86_64_H => :x86_64h,
//		}.freeze,
//		CPU_TYPE_ARM => {
//			CPU_SUBTYPE_ARM_ALL => :arm,
//					CPU_SUBTYPE_ARM_V4T => :armv4t,
//					CPU_SUBTYPE_ARM_V6 => :armv6,
//					CPU_SUBTYPE_ARM_V5TEJ => :armv5,
//					CPU_SUBTYPE_ARM_XSCALE => :xscale,
//					CPU_SUBTYPE_ARM_V7 => :armv7,
//					CPU_SUBTYPE_ARM_V7F => :armv7f,
//					CPU_SUBTYPE_ARM_V7S => :armv7s,
//					CPU_SUBTYPE_ARM_V7K => :armv7k,
//					CPU_SUBTYPE_ARM_V6M => :armv6m,
//					CPU_SUBTYPE_ARM_V7M => :armv7m,
//					CPU_SUBTYPE_ARM_V7EM => :armv7em,
//					CPU_SUBTYPE_ARM_V8 => :armv8,
//		}.freeze,
//		CPU_TYPE_ARM64 => {
//			CPU_SUBTYPE_ARM64_ALL => :arm64,
//					CPU_SUBTYPE_ARM64_V8 => :arm64v8,
//					CPU_SUBTYPE_ARM64E => :arm64e,
//		}.freeze,
//		CPU_TYPE_ARM64_32 => {
//			CPU_SUBTYPE_ARM64_32_V8 => :arm64_32v8,
//		}.freeze,
//		CPU_TYPE_POWERPC => {
//			CPU_SUBTYPE_POWERPC_ALL => :ppc,
//					CPU_SUBTYPE_POWERPC_601 => :ppc601,
//					CPU_SUBTYPE_POWERPC_603 => :ppc603,
//					CPU_SUBTYPE_POWERPC_603E => :ppc603e,
//					CPU_SUBTYPE_POWERPC_603EV => :ppc603ev,
//					CPU_SUBTYPE_POWERPC_604 => :ppc604,
//					CPU_SUBTYPE_POWERPC_604E => :ppc604e,
//					CPU_SUBTYPE_POWERPC_750 => :ppc750,
//					CPU_SUBTYPE_POWERPC_7400 => :ppc7400,
//					CPU_SUBTYPE_POWERPC_7450 => :ppc7450,
//					CPU_SUBTYPE_POWERPC_970 => :ppc970,
//		}.freeze,
//		CPU_TYPE_POWERPC64 => {
//			CPU_SUBTYPE_POWERPC64_ALL => :ppc64,
//# apparently the only exception to the naming scheme
//							CPU_SUBTYPE_POWERPC_970 => :ppc970_64,
//		}.freeze,
//		CPU_TYPE_MC680X0 => {
//			CPU_SUBTYPE_MC680X0_ALL => :m68k,
//					CPU_SUBTYPE_MC68030 => :mc68030,
//					CPU_SUBTYPE_MC68040 => :mc68040,
//		},
//		CPU_TYPE_MC88000 => {
//			CPU_SUBTYPE_MC88000_ALL => :m88k,
//		},
//}.freeze

#endif
