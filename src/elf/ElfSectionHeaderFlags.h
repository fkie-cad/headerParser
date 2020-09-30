#ifndef HEADER_PARSER_ELF_SH_FLAGS_H
#define HEADER_PARSER_ELF_SH_FLAGS_H

struct Elf_Section_Header_Flags
{
	// The section contains data that should be writable during process execution.
	uint32_t SHF_WRITE;
	// The section occupies memory during process execution.
	// Some control sections do not reside in the memory image of an object file;
	// this attribute is off for those sections.
	uint32_t SHF_ALLOC;
	// The section contains executable machine instructions.
	uint32_t SHF_EXECINSTR;
	// The data in the section may be merged to eliminate duplication.
	// Unless the SHF_STRINGS flag is also set, the data elements in the section are of a uniform size.
	// The size of each element is specified in the section header's sh_entsize field.
	// If the SHF_STRINGS flag is also set, the data elements consist of null-terminated character strings.
	// The size of each character is specified in the section header's sh_entsize field.
	// Each element in the section is compared against other elements in sections with the same name, type and flags.
	// Elements that would have identical values at program run-time may be merged.
	// Relocations referencing elements of such sections must be resolved to the merged locations of the referenced values.
	// Note that any relocatable values, including values that would result in run-time relocations, must be analyzed to determine whether the run-time values would actually be identical.
	// An ABI-conforming object file may not depend on specific elements being merged, and an ABI-conforming link editor may choose not to merge specific elements.
	uint32_t SHF_MERGE;
	// The data elements in the section consist of null-terminated character strings.
	// The size of each character is specified in the section header's sh_entsize field.
	uint32_t SHF_STRINGS;
	// The sh_info field of this section header holds a section header table index.
	uint32_t SHF_INFO_LINK;
	// This flag adds special ordering requirements for link editors.
	// The requirements apply if the sh_link field of this section's header references another section (the linked-to section).
	// If this section is combined with other sections in the output file,
	// it must appear in the same relative order with respect to those sections,
	// as the linked-to section appears with respect to sections the linked-to section is combined with.
	uint32_t SHF_LINK_ORDER;
	// his section requires special OS-specific processing (beyond the standard linking rules) to avoid incorrect behavior.
	// If this section has either an sh_type value or contains sh_flags bits in the OS-specific ranges for those fields,
	// and a link editor processing this section does not recognize those values,
	// then the link editor should reject the object file containing this section with an error.
	uint32_t SHF_OS_NONCONFORMING;
	// This section is a member (perhaps the only one) of a section group.
	// The section must be referenced by a section of type SHT_GROUP.
	// The SHF_GROUP flag may be set only for sections contained in relocatable objects (objects with the ELF header e_type member set to ET_REL).
	// See below for further details.
	uint32_t SHF_GROUP;
	// This section holds Thread-Local Storage,
	// meaning that each separate execution flow has its own distinct instance of this data.
	// Implementations need not support this flag.
	uint32_t SHF_TLS;
	// This flag identifies a section containing compressed data.
	// SHF_COMPRESSED applies only to non-allocable sections, and cannot be used in conjunction with SHF_ALLOC.
	// In addition, SHF_COMPRESSED cannot be applied to sections of type SHT_NOBITS.
	// All relocations to a compressed section specifiy offsets to the uncompressed section data.
	// It is therefore necessary to decompress the section data before relocations can be applied.
	// Each compressed section specifies the algorithm independently.
	// It is permissible for different sections in a given ELF object to employ different compression algorithms.
	// Compressed sections begin with a compression header structure that identifies the compression algorithm.
	uint32_t SHF_COMPRESSED;
	// Bits indicating os-specific flags.
	uint32_t SHF_MASKOS;
	// Bits indicating processor-specific flags.
	uint32_t SHF_MASKPROC;
};

const struct Elf_Section_Header_Flags ElfSectionHeaderFlags = {
	.SHF_WRITE = 0x1,
	.SHF_ALLOC = 0x2,
	.SHF_EXECINSTR = 0x4,
	.SHF_MERGE = 0x10,
	.SHF_STRINGS = 0x20,
	.SHF_INFO_LINK = 0x40,
	.SHF_LINK_ORDER = 0x80,
	.SHF_OS_NONCONFORMING = 0x100,
	.SHF_GROUP = 0x200,
	.SHF_TLS = 0x400,
	.SHF_COMPRESSED = 0x800,
	.SHF_MASKOS = 0x0ff00000,
	.SHF_MASKPROC = 0xf0000000
};
#endif