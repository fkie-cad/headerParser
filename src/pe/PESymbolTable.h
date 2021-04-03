#ifndef HEADER_PARSER_PE_SYMBOL_TALBE_H
#define HEADER_PARSER_PE_SYMBOL_TALBE_H

#include <stdint.h>

//The symbol table is an array of records, each 18 bytes long.
// Each record is either a standard or auxiliary symbol-table record.
// A standard record defines a symbol or name and has the following format.
typedef struct SYM_ENT
{
    // The name of the symbol, represented by a union of three structures. An array of 8 bytes is used if the name is not more than 8 bytes long. For more information, see Symbol Name Representation.
    char Name[8];
    // The value that is associated with the symbol. The interpretation of this field depends on SectionNumber and StorageClass. A typical meaning is the relocatable address.
    uint32_t Value;
    //	The signed integer that identifies the section, using a one-based index into the section table. Some values have special meaning, as defined in section 5.4.2, "Section Number Values."
    uint16_t SectionNumber;
    //	A number that represents type. Microsoft tools set this field to 0x20 (function) or 0x0 (not a function). For more information, see Type Representation.
    uint16_t Type;
    //	An enumerated value that represents storage class. For more information, see Storage Class.
    uint8_t StorageClass;
    //	The number of auxiliary symbol table entries that follow this record.
    uint8_t NumberOfAuxSymbols;
} SYM_ENT;

typedef struct Sym_Ent_Offsets
{
    uint8_t Name;
    uint8_t Value;
    uint8_t SectionNumber;
    uint8_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} Sym_Ent_Offsets;

static const struct Sym_Ent_Offsets SymEntOffsets = {
    .Name = 0,
    .Value = 8,
    .SectionNumber = 12,
    .Type = 14,
    .StorageClass = 16,
    .NumberOfAuxSymbols = 17
};
#endif
