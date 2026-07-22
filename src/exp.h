#ifndef EXP_H
#define EXP_H

#if defined(HP_EXPORTS)
    #if defined(_MSC_VER) 
        #define HP_API __declspec(dllexport) // Microsoft  
    #elif defined(__GNUC__) 
        #define HP_API __attribute__((visibility("default"))) // GCC 
    #endif
#else
    #define HP_API 
#endif

#endif
