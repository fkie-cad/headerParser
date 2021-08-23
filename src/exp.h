#ifndef EXP_H
#define EXP_H

#if defined(__linux__) || defined(__linux) || defined(linux) || defined(__APPLE__)
    #define HP_API
#elif defined(HP_EXPORTS)
    #define HP_API __declspec(dllexport)
#else
    #define HP_API 
#endif

#endif
