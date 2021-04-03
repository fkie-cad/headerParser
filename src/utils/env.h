#ifndef ENV_H
#define ENV_H

#include <stdint.h>



#if defined(__linux__) || defined(__linux) || defined(linux)
    #define _LINUX
#endif



//#if _WIN32 || _WIN64
//    #if _WIN64
//        #define _64BIT
//    #else
//        #define _32BIT
//    #endif
//#endif
//
//// Check GCC
//#if __GNUC__
//    #if __x86_64__ || __ppc64__
//        #define _64BIT
//    #else
//        #define _32BIT
//    #endif
//#endif

//#if sizeof(size_t) == 4
#if UINTPTR_MAX == 0xffffffff
    #define _32BIT
//#elif sizeof(size_t) == 8
#elif UINTPTR_MAX == 0xffffffffffffffff
    #define _64BIT
#else
    #define _0BIT
#endif

#endif