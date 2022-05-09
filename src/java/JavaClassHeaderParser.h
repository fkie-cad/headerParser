#ifndef HEADER_PARSER_JAVA_JAVA_CLASS_HEADER_PARSER_H
#define HEADER_PARSER_JAVA_JAVA_CLASS_HEADER_PARSER_H

struct JavaClassHeader {
    uint32_t magic_number;
    uint16_t minor_version;
    uint16_t major_version;
    //uint16_t constant_pool_count;
    //cp_info constant_pool[constant_pool_count - 1];
    //uint16_t access_flags;
    //uint16_t this_class;
    //uint16_t super_class;
    //uint16_t interfaces_count;
    //uint16_t interfaces[interfaces_count];
    //uint16_t fields_count;
    //field_info fields[fields_count];
    //uint16_t methods_count;
    //method_info methods[methods_count];
    //uint16_t attributes_count;
    //attribute_info attributes[attributes_count];
};

#define JAVA_CLASS_MN_VERSION_OFFSET (4)
#define JAVA_CLASS_MJ_VERSION_OFFSET (6)

//"Java 1.2 //  major version 46
//"Java 1.3 // uses major version 47
//"Java 1.4 // uses major version 48
//"Java 5 // uses major version 49
//"Java 6 // uses major version 50
//"Java 7 // uses major version 51
//"Java 8 //uses major version 52
//"Java 9 // uses major version 53
//"Java 10 // uses major version 54
//"Java 11 // uses major version 55
//"Java ...
#define JAVA_MIN_MJ_VS (46)
#define JAVA_VS_STR_MAX_SIZE (16)

void parseJavaClassHeader(PHeaderData hd, PGlobalParams gp);
int JavaClass_getJavaVersionString(char* vs_str, size_t start_file_offset, size_t file_size, unsigned char* block_l);
uint16_t JavaClass_getJavaVersion(size_t start_file_offset, size_t file_size, unsigned char* block_l);
int JavaClass_getJavaVersionStringV(uint16_t version, char* vs_str);

void parseJavaClassHeader(PHeaderData hd, PGlobalParams gp)
{
    // freed in freeInnerHeaderData
    char* vs_str = calloc(1, JAVA_VS_STR_MAX_SIZE);
    JavaClass_getJavaVersionString(vs_str, gp->file.start_offset, gp->file.size, gp->block_large);

    hd->headertype = HEADER_TYPE_JAVA_CLASS;
    hd->CPU_arch = ARCH_JAVA;
    hd->Machine = vs_str;
}

int JavaClass_getJavaVersionString(char* vs_str, size_t start_file_offset, size_t file_size, unsigned char* block_l)
{
    uint16_t version = JavaClass_getJavaVersion(start_file_offset, file_size, block_l);
    JavaClass_getJavaVersionStringV(version, vs_str);
    return 0;
}

uint16_t JavaClass_getJavaVersion(size_t start_file_offset, size_t file_size, unsigned char* block_l)
{
    if ( start_file_offset + 8 > file_size ) return 0;

    return swapUint16(*((uint16_t*) &block_l[JAVA_CLASS_MJ_VERSION_OFFSET]));
}

int JavaClass_getJavaVersionStringV(uint16_t version, char* vs_str)
{
    int vs = version - JAVA_MIN_MJ_VS + 2;
    memset(vs_str, 0, JAVA_VS_STR_MAX_SIZE);
    if (vs < 2)
    {
        snprintf(vs_str, JAVA_VS_STR_MAX_SIZE, "unknown");
    }
    else if ( vs < 5)
    {
        snprintf(vs_str, JAVA_VS_STR_MAX_SIZE, "Java 1.%u", vs);
    }
    else if ( vs > 100 ) // arbitrary max value
    {
        snprintf(vs_str, JAVA_VS_STR_MAX_SIZE, "unknown");
    }
    else
    {
        snprintf(vs_str, JAVA_VS_STR_MAX_SIZE, "Java %u", vs);
    }
    vs_str[JAVA_VS_STR_MAX_SIZE - 1] = 0;
    return 0;
}

#endif
