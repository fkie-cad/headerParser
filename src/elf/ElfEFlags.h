#ifndef HEADER_PARSER_ELF_E_FLAGS_H
#define HEADER_PARSER_ELF_E_FLAGS_H

/**
 * IA64
 */
// The stack and heap sections are executable. If this flag is not set, code can not be executed from the stack or heap.
#define EF_IA_64_LINUX_EXECUTABLE_STACK	(0x00000001)
// All bits in this mask are reserved for operating system specific values
#define EF_IA_64_MASKOS (0x00ff000f)
// If set, the object uses the LP64 programming model. If clear, it uses th ILP32 programming model
#define EF_IA_64_ABI64 (0x00000010)
// If set, the object has been compiled witz a reduced floating point model
#define EF_IA_64_REDUCEDFP (0x00000020)
// If set, the global pointer (gp) is treated a a program-wide constant. The gp is saved and restored ony for indirect function calls
#define EF_IA_64_CONS_GP (0x00000040)
// If set, the global pointer (gp) is treated a a program-wide constant. The gp is never saved or restored across function calls.
#define EF_IA_64_NOFUNCDESC_CONS_GP (0x00000080)
// If set, the program loader is instructed to load the executable at the addresses specified in the program headers. Not ABI-conforming.
#define EF_IA_64_ABSOLUTE (0x00000100)
// The integer value formed by these eight bits identifies the architecture version.
#define EF_IA_64_ARCH (0xff000000)



#endif
