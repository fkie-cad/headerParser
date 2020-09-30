#ifndef HEADER_PARSER_ELF_OS_ABI_IDENTIFICATION_H
#define HEADER_PARSER_ELF_OS_ABI_IDENTIFICATION_H

// OS ABI identification.
typedef enum OSABIIdentification {
	ELFOSABI_NONE = 0,          // UNIX System V ABI
	ELFOSABI_HPUX = 1,          // HP-UX operating system
	ELFOSABI_NETBSD = 2,        // NetBSD
	ELFOSABI_GNU = 3,           // GNU/Linux
//	ELFOSABI_LINUX = 3,         // Historical alias for ELFOSABI_GNU.
	ELFOSABI_HURD = 4,          // GNU/Hurd
	ELFOSABI_SOLARIS = 6,       // Sun Solaris
	ELFOSABI_AIX = 7,           // IBM AIX
	ELFOSABI_IRIX = 8,          // SGI IRIX
	ELFOSABI_FREEBSD = 9,       // FreeBSD
	ELFOSABI_TRU64 = 10,        // Compaq TRU64 UNIX
	ELFOSABI_MODESTO = 11,      // Novell Modesto
	ELFOSABI_OPENBSD = 12,      // OpenBSD
	ELFOSABI_OPENVMS = 13,      // OpenVMS
	ELFOSABI_NSK = 14,          // Hewlett-Packard Non-Stop Kernel
	ELFOSABI_AROS = 15,         // Amiga Research OS
	ELFOSABI_FENIXOS = 16,      // FenixOS
	ELFOSABI_CLOUDABI = 17,     // Nuxi CloudABI
	ELFOSABI_ARM_AEABI = 64,	// ARM EABI
//	ELFOSABI_C6000_ELFABI = 64, // Bare-metal TMS320C6000
//	ELFOSABI_AMDGPU_HSA = 64,   // AMD HSA runtime
	ELFOSABI_C6000_LINUX = 65,  // Linux TMS320C6000
	ELFOSABI_ARM = 97,          // ARM
	ELFOSABI_STANDALONE = 255   // Standalone (embedded) application
} OSABIIdentification;

#endif
