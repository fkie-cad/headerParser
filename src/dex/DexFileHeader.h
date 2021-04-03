#ifndef HEADER_PARSER_DEX_DEX_FILE_HEADER_H
#define HEADER_PARSER_DEX_DEX_FILE_HEADER_H

#include <stdint.h>

#define DEX_SIGNATURE_LN 20
#define MAGIC_DEX_BYTES_FULL_LN 8

static const unsigned char MAGIC_DEX_BYTES[] = {0x64, 0x65, 0x78, 0x0A}; // dex\nxxx\0 : xxx is version info and may differ
#define MAGIC_DEX_BYTES_LN (4)
#define DEX_FILE_HEADER_SIZE (112)
#define DEX_ENDIAN_CONSTANT (0x12345678)
#define DEX_REVERSE_ENDIAN_CONSTANT (0x78563412)
#define NO_INDEX (0xffffffff)

#define ACC_PUBLIC (0x1) // public: visible everywhere
#define ACC_PRIVATE (0x2) // * private: only visible to defining class
#define ACC_PROTECTED (0x4) // * protected: visible to package and subclasses
#define ACC_STATIC (0x8) // * static: is not constructed with an outer this reference 	static: global to defining class 	static: does not take a this argument
#define ACC_FINAL (0x10) // final: not subclassable 	final: immutable after construction 	final: not overridable
#define ACC_SYNCHRONIZED (0x20) // synchronized: associated lock automatically acquired around call to this method. Note: This is only valid to set when ACC_NATIVE is also set.
#define ACC_VOLATILE (0x40) // volatile: special access rules to help with thread safety
#define ACC_BRIDGE (0x40) // bridge method, added automatically by compiler as a type-safe bridge
#define ACC_TRANSIENT (0x80) // transient: not to be saved by default serialization
#define ACC_VARARGS (0x80) // last argument should be treated as a "rest" argument by compiler
#define ACC_NATIVE (0x100) // native: implemented in native code
#define ACC_INTERFACE (0x200) // interface: multiply-implementable abstract class
#define ACC_ABSTRACT (0x400) // abstract: not directly instantiable 	  	abstract: unimplemented by this class
#define ACC_STRICT (0x800) // strictfp: strict rules for floating-point arithmetic
#define ACC_SYNTHETIC (0x1000) // not directly defined in source code 	not directly defined in source code 	not directly defined in source code
#define ACC_ANNOTATION (0x2000) // declared as an annotation class
#define ACC_ENUM (0x4000) // declared as an enumerated type 	declared as an enumerated value
//#define (unused) (0x8000)
#define ACC_CONSTRUCTOR (0x10000) // constructor method (class or instance initializer)
#define ACC_DECLARED_SYNCHRONIZED (0x20000) // declared synchronized.

// Each LEB128 encoded value consists of one to five bytes, which together represent a single 32-bit value.
// Each byte has its most significant bit set except for the final byte in the sequence, which has its most significant bit clear.
// 0xxxxxxx, 1xxxxxxx 0xxxxxxx
typedef struct leb128 {
    uint32_t val;
} uleb128,  sleb128;

//typedef enum {
//VALUE_BYTE = 0x00,
//		VALUE_SHORT = 0x02,
//		VALUE_CHAR = 0x03,
//		VALUE_INT = 0x04,
//		VALUE_LONG = 0x06,
//		VALUE_FLOAT = 0x10,
//		VALUE_DOUBLE = 0x11,
//		VALUE_STRING = 0x17,
//		VALUE_TYPE = 0x18,
//		VALUE_FIELD = 0x19,
//		VALUE_METHOD = 0x1a,
//		VALUE_ENUM = 0x1b,
//		VALUE_ARRAY = 0x1c,
//		VALUE_ANNOTATION = 0x1d,
//		VALUE_NULL = 0x1e,
//		VALUE_BOOLEAN = 0x1f
//} DexValue;

enum TYPE_CODES
{
    TYPE_HEADER_ITEM = 0x0000,
    TYPE_STRING_ID_ITEM = 0x0001,
    TYPE_TYPE_ID_ITEM = 0x0002,
    TYPE_PROTO_ID_ITEM = 0x0003,
    TYPE_FIELD_ID_ITEM = 0x0004,
    TYPE_METHOD_ID_ITEM = 0x0005,
    TYPE_CLASS_DEF_ITEM = 0x0006,
    TYPE_CALL_SITE_ID_ITEM = 0x0007,
    TYPE_METHOD_HANDLE_ITEM = 0x0008,
    TYPE_MAP_LIST = 0x1000,
    TYPE_TYPE_LIST = 0x1001,
    TYPE_ANNOTATION_SET_REF_LIST = 0x1002,
    TYPE_ANNOTATION_SET_ITEM = 0x1003,
    TYPE_CLASS_DATA_ITEM = 0x2000,
    TYPE_CODE_ITEM = 0x2001,
    TYPE_STRING_DATA_ITEM = 0x2002,
    TYPE_DEBUG_INFO_ITEM = 0x2003,
    TYPE_ANNOTATION_ITEM = 0x2004,
    TYPE_ENCODED_ARRAY_ITEM = 0x2005,
    TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006,
};

typedef struct DEXFileHeader
{
    char magic[MAGIC_DEX_BYTES_FULL_LN]; //
    uint32_t checksum; // adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
    char signature[DEX_SIGNATURE_LN]; // SHA-1 signature (hash) of the rest of the file (everything but magic, checksum, and this field); used to uniquely identify files
    uint32_t file_size; // size of the entire file (including the header), in bytes
    uint32_t header_size; // = 0x70 	size of the header (this entire section), in bytes. This allows for at least a limited amount of backwards/forwards compatibility without invalidating the format.
    uint32_t endian_tag; // = ENDIAN_CONSTANT 	endianness tag. See discussion above under "ENDIAN_CONSTANT and REVERSE_ENDIAN_CONSTANT" for more details.
    uint32_t link_size; // size of the link section, or 0 if this file isn't statically linked
    uint32_t link_off; // offset from the start of the file to the link section, or 0 if link_size == 0. The offset, if non-zero, should be to an offset into the link_data section. The format of the data pointed at is left unspecified by this document; this header field (and the previous) are left as hooks for use by runtime implementations.
    uint32_t map_off; // offset from the start of the file to the map item. The offset, which must be non-zero, should be to an offset into the data section, and the data should be in the format specified by "map_list" below.
    uint32_t string_ids_size; // count of strings in the string identifiers list
    uint32_t string_ids_off; // offset from the start of the file to the string identifiers list, or 0 if string_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the string_ids section.
    uint32_t type_ids_size; // count of elements in the type identifiers list, at most 65535
    uint32_t type_ids_off; // offset from the start of the file to the type identifiers list, or 0 if type_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the type_ids section.
    uint32_t proto_ids_size; // count of elements in the prototype identifiers list, at most 65535
    uint32_t proto_ids_off; // offset from the start of the file to the prototype identifiers list, or 0 if proto_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the proto_ids section.
    uint32_t field_ids_size; // count of elements in the field identifiers list
    uint32_t field_ids_off; // offset from the start of the file to the field identifiers list, or 0 if field_ids_size == 0. The offset, if non-zero, should be to the start of the field_ids section.
    uint32_t method_ids_size; // count of elements in the method identifiers list
    uint32_t method_ids_off; // offset from the start of the file to the method identifiers list, or 0 if method_ids_size == 0. The offset, if non-zero, should be to the start of the method_ids section.
    uint32_t class_defs_size; // count of elements in the class definitions list
    uint32_t class_defs_off; // offset from the start of the file to the class definitions list, or 0 if class_defs_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the class_defs section.
    uint32_t data_size; // Size of data section in bytes. Must be an even multiple of sizeof(uint32_t).
    uint32_t data_off; // offset from the start of the file to the start of the data section.
} DEXFileHeader;

typedef struct DexStringIdItem {
    uint32_t offset; // offset from the start of the file to the string data for this item. The offset should be to a location in the data section, and the data should be in the format specified by "string_data_item" below. There is no alignment requirement for the offset.
} DexStringIdItem;
#define DEX_SIZE_OF_STRING_ID_ITEM (sizeof(DexStringIdItem))

typedef struct DexStringDataItem {
    uleb128 utf16_size; // size of this string, in UTF-16 code units (which is the "string length" in many systems). That is, this is the decoded length of the string. (The encoded length is implied by the position of the 0 byte.)
    uint8_t* data; // a series of MUTF-8 code units (a.k.a. octets, a.k.a. bytes) followed by a byte of value 0. See "MUTF-8 (Modified UTF-8) Encoding" above for details and discussion about the data format.
} DexStringDataItem;

typedef struct DexTypeIdItem {
    uint32_t descriptor_idx; // index into the string_ids list for the descriptor string of this type. The string must conform to the syntax for TypeDescriptor, defined above.
} DexTypeIdItem;
#define DEX_SIZE_OF_TYPE_ID_ITEM (sizeof(DexTypeIdItem))

typedef struct DexProtoIdItem {
    uint32_t shorty_idx; // index into the string_ids list for the short-form descriptor string of this prototype. The string must conform to the syntax for ShortyDescriptor, defined above, and must correspond to the return type and parameters of this item.
    uint32_t return_type_idx; // index into the type_ids list for the return type of this prototype
    uint32_t parameters_off; // offset from the start of the file to the list of parameter types for this prototype, or 0 if this prototype has no parameters. This offset, if non-zero, should be in the data section, and the data there should be in the format specified by "type_list" below. Additionally, there should be no reference to the type void in the list.
} DexProtoIdItem;
#define DEX_SIZE_OF_PROTO_ID_ITEM (sizeof(DexProtoIdItem))

typedef struct DexFieldIdItem {
    uint16_t class_idx; // index into the type_ids list for the definer of this field. This must be a class type, and not an array or primitive type.
    uint16_t type_idx; // index into the type_ids list for the type of this field
    uint32_t name_idx; // index into the string_ids list for the name of this field. The string must conform to the syntax for MemberName, defined above.
} DexFieldIdItem;
#define DEX_SIZE_OF_FIELD_ID_ITEM (sizeof(DexFieldIdItem))

typedef struct DexMethodIdItem {
    uint16_t class_idx; // index into the type_ids list for the definer of this method. This must be a class or array type, and not a primitive type.
    uint16_t proto_idx; // index into the proto_ids list for the prototype of this method
    uint32_t name_idx; // index into the string_ids list for the name of this method. The string must conform to the syntax for MemberName, defined above.
} DexMethodIdItem;
#define DEX_SIZE_OF_METHOD_ID_ITEM (sizeof(DexMethodIdItem))

typedef struct DexClassDefItem {
    uint32_t class_idx; // index into the type_ids list for this class. This must be a class type, and not an array or primitive type.
    uint32_t access_flags; // access flags for the class (public, final, etc.). See "access_flags Definitions" for details.
    uint32_t superclass_idx; // index into the type_ids list for the superclass, or the constant value NO_INDEX if this class has no superclass (i.e., it is a root class such as Object). If present, this must be a class type, and not an array or primitive type.
    uint32_t interfaces_off; // offset from the start of the file to the list of interfaces, or 0 if there are none. This offset should be in the data section, and the data there should be in the format specified by "type_list" below. Each of the elements of the list must be a class type (not an array or primitive type), and there must not be any duplicates.
    uint32_t source_file_idx; // index into the string_ids list for the name of the file containing the original source for (at least most of) this class, or the special value NO_INDEX to represent a lack of this information. The debug_info_item of any given method may override this source file, but the expectation is that most classes will only come from one source file.
    uint32_t annotations_off; // offset from the start of the file to the annotations structure for this class, or 0 if there are no annotations on this class. This offset, if non-zero, should be in the data section, and the data there should be in the format specified by "annotations_directory_item" below, with all items referring to this class as the definer.
    uint32_t class_data_off; // offset from the start of the file to the associated class data for this item, or 0 if there is no class data for this class. (This may be the case, for example, if this class is a marker interface.) The offset, if non-zero, should be in the data section, and the data there should be in the format specified by "class_data_item" below, with all items referring to this class as the definer.
    uint32_t static_values_off; // offset from the start of the file to the list of initial values for static fields, or 0 if there are none (and all static fields are to be initialized with 0 or null). This offset should be in the data section, and the data there should be in the format specified by "encoded_array_item" below. The size of the array must be no larger than the number of static fields declared by this class, and the elements correspond to the static fields in the same order as declared in the corresponding field_list. The type of each array element must match the declared type of its corresponding field. If there are fewer elements in the array than there are static fields, then the leftover fields are initialized with a type-appropriate 0 or null.
} DexClassDefItem;
#define DEX_SIZE_OF_CLASS_DEF_ITEM (sizeof(DexClassDefItem))

typedef struct DexCallSiteIdItem {
    uint32_t call_site_off; // offset from the start of the file to call site definition. The offset should be in the data section, and the data there should be in the format specified by "call_site_item" below.
} DexCallSiteIdItem;
//#define DEX_SIZE_OF_METHOD_ID_ITEM (sizeof(DexMethodIdItem))

typedef struct DexMethodHandleItem {
    uint16_t method_handle_type; // type of the method handle; see table below
    uint16_t unused0; // (unused)
    uint16_t field_or_method_id; // Field or method id depending on whether the method handle type is an accessor or a method invoker
    uint16_t unused1; // (unused)
} DexMethodHandleItem;
//#define DEX_SIZE_OF_METHOD_ID_ITEM (sizeof(DexMethodIdItem))

#define METHOD_HANDLE_TYPE_STATIC_PUT 0x00 // Method handle is a static field setter (accessor)
#define METHOD_HANDLE_TYPE_STATIC_GET 0x01 // Method handle is a static field getter (accessor)
#define METHOD_HANDLE_TYPE_INSTANCE_PUT 0x02 // Method handle is an instance field setter (accessor)
#define METHOD_HANDLE_TYPE_INSTANCE_GET 0x03 // Method handle is an instance field getter (accessor)
#define METHOD_HANDLE_TYPE_INVOKE_STATIC 0x04 // Method handle is a static method invoker
#define METHOD_HANDLE_TYPE_INVOKE_INSTANCE 0x05 // Method handle is an instance method invoker
#define METHOD_HANDLE_TYPE_INVOKE_CONSTRUCTOR 0x06 // Method handle is a constructor method invoker
#define METHOD_HANDLE_TYPE_INVOKE_DIRECT 0x07 // Method handle is a direct method invoker
#define METHOD_HANDLE_TYPE_INVOKE_INTERFACE 0x08 // Method handle is an interface method invoker

typedef struct DexEncodedField {
    uleb128 field_idx_diff; // index into the field_ids list for the identity of this field (includes the name and descriptor), represented as a difference from the index of previous element in the list. The index of the first element in a list is represented directly.
    uleb128 access_flags; // access flags for the field (public, final, etc.). See "access_flags Definitions" for details.
} DexEncodedField;

typedef struct DexEncodedMethod {
    uleb128 method_idx_diff; // index into the method_ids list for the identity of this method (includes the name and descriptor), represented as a difference from the index of previous element in the list. The index of the first element in a list is represented directly.
    uleb128 access_flags; // access flags for the method (public, final, etc.). See "access_flags Definitions" for details.
    uleb128 code_off; // offset from the start of the file to the code structure for this method, or 0 if this method is either abstract or native. The offset should be to a location in the data section. The format of the data is specified by "code_item" below.
} DexEncodedMethod;

typedef struct DexTryItem {
    uint32_t start_addr; // start address of the block of code covered by this entry. The address is a count of 16-bit code units to the start of the first covered instruction.
    uint16_t insn_count; // number of 16-bit code units covered by this entry. The last code unit covered (inclusive) is start_addr + insn_count - 1.
    uint16_t handler_off; // offset in bytes from the start of the associated encoded_catch_hander_list to the encoded_catch_handler for this entry. This must be an offset to the start of an encoded_catch_handler.
} DexTryItem;

typedef struct DexEncodedTypeAddrPair {
    uleb128 type_idx; // index into the type_ids list for the type of the exception to catch
    uleb128 addr; // bytecode address of the associated exception handler
} DexEncodedTypeAddrPair;

typedef struct DexEncodedCatchHandler {
    sleb128 size; // number of catch types in this list. If non-positive, then this is the negative of the number of catch types, and the catches are followed by a catch-all handler. For example: A size of 0 means that there is a catch-all but no explicitly typed catches. A size of 2 means that there are two explicitly typed catches and no catch-all. And a size of -1 means that there is one typed catch along with a catch-all.
    DexEncodedTypeAddrPair* handlers; // [abs(size)] 	stream of abs(size) encoded items, one for each caught type, in the order that the types should be tested.
    uleb128 catch_all_addr; // (optional) 	bytecode address of the catch-all handler. This element is only present if size is non-positive.
} DexEncodedCatchHandler;

typedef struct DexEncodedCatchHandlerList {
    uleb128 size; // size of this list, in entries
    DexEncodedCatchHandler* list; // [handlers_size] actual list of handler lists, represented directly (not as offsets), and concatenated sequentially
} DexEncodedCatchHandlerList;

typedef struct DexCodeItem {
    uint16_t registers_size; // the number of registers used by this code
    uint16_t ins_size; // the number of words of incoming arguments to the method that this code is for
    uint16_t outs_size; // the number of words of outgoing argument space required by this code for method invocation
    uint16_t tries_size; // the number of try_items for this instance. If non-zero, then these appear as the tries array just after the insns in this instance.
    uint32_t debug_info_off; // offset from the start of the file to the debug info (line numbers + local variable info) sequence for this code, or 0 if there simply is no information. The offset, if non-zero, should be to a location in the data section. The format of the data is specified by "debug_info_item" below.
    uint32_t insns_size; // size of the instructions list, in 16-bit code units
    uint16_t* insns; // [insns_size] actual array of bytecode. The format of code in an insns array is specified by the companion document Dalvik bytecode. Note that though this is defined as an array of ushort, there are some internal structures that prefer four-byte alignment. Also, if this happens to be in an endian-swapped file, then the swapping is only done on individual ushorts and not on the larger internal structures.
    uint16_t padding; // (optional) = 0 two bytes of padding to make tries four-byte aligned. This element is only present if tries_size is non-zero and insns_size is odd.
    DexTryItem* tries; // [tries_size] (optional) array indicating where in the code exceptions are caught and how to handle them. Elements of the array must be non-overlapping in range and in order from low to high address. This element is only present if tries_size is non-zero.
    DexEncodedCatchHandlerList* handlers; // (optional) bytes representing a list of lists of catch types and associated handler addresses. Each try_item has a byte-wise offset into this structure. This element is only present if tries_size is non-zero.
} DexCodeItem;

typedef struct DexClassDataItem {
    uleb128 static_fields_size; // the number of static fields defined in this item
    uleb128 instance_fields_size; // the number of instance fields defined in this item
    uleb128 direct_methods_size; // the number of direct methods defined in this item
    uleb128 virtual_methods_size; // the number of virtual methods defined in this item
    DexEncodedField* static_fields; // the defined static fields, represented as a sequence of encoded elements. The fields must be sorted by field_idx in increasing order.
    DexEncodedField* instance_fields; // the defined instance fields, represented as a sequence of encoded elements. The fields must be sorted by field_idx in increasing order.
    DexEncodedMethod* direct_methods; // the defined direct (any of static, private, or constructor) methods, represented as a sequence of encoded elements. The methods must be sorted by method_idx in increasing order.
    DexEncodedMethod* virtual_methods; // the defined virtual (none of static, private, or constructor) methods, represented as a sequence of encoded elements. This list should not include inherited methods unless overridden by the class that this item represents. The methods must be sorted by method_idx in increasing order. The method_idx of a virtual method must not be the same as any direct method.
} DexClassDataItem;
//#define DEX_SIZE_OF_CLASS_DATA_ITEM (sizeof(DexClassDataItem))

typedef struct DexMapItem {
    uint16_t type;
    uint16_t unused;
    uint32_t size;
    uint32_t offset;
} DexMapItem;
#define DEX_SIZE_OF_MAP_ITEM (sizeof(DexMapItem))

typedef struct DexMapList {
    uint32_t size;
    DexMapItem* map_item_list;
} DexMapList;

#endif