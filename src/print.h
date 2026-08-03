#ifndef PRINT_H
#define PRINT_H

#ifdef __GNUC__
#define FORCEINLINE __attribute__((always_inline)) inline
#endif

#define HEX_CHAR_WIDTH(__hcw_v__, __hcw_w__) \
{ \
    uint8_t _hcw_w_ = 0x10; \
    for ( uint8_t _i_ = 0x38; _i_ > 0; _i_-=8 ) \
    { \
        if ( ! ((uint8_t)(__hcw_v__ >> _i_)) ) \
            _hcw_w_ -= 2; \
        else \
            break; \
    } \
    __hcw_w__ = _hcw_w_; \
}

#ifdef DEBUG_PRINT
#define debug_info(...) { printf("[d] "); printf(__VA_ARGS__); }
#define DPrint(...) { printf("[d] "); printf(__VA_ARGS__); }
#define FEnter() printf("[>] %s()\n", __func__);
#define FLeave() printf("[<] %s()\n", __func__);

FORCEINLINE 
void DPrintMemCol8(void* _b_, size_t _s_, size_t _a_)
{
    uint64_t _hw_v_ = _a_ + (_s_);
    uint8_t _hw_w_ = 0x10;
    HEX_CHAR_WIDTH(_hw_v_, _hw_w_);

    for ( size_t _i_ = 0; _i_ < (size_t)(_s_); _i_+=0x10 )
    {
        size_t _end_ = (_i_+0x10<(_s_))?(_i_+0x10):((size_t)(_s_));
        uint32_t _gap_ = (_i_+0x10<=(_s_)) ? 0 : (uint32_t)((0x10+_i_-(size_t)(_s_))*3);
        printf("%.*zx  ", _hw_w_, (((size_t)_a_)+_i_));
        
        for ( size_t _j_ = _i_, _k_=0; _j_ < _end_; _j_++, _k_++ )
        {
            printf("%02x", ((uint8_t*)_b_)[_j_]);
            printf("%c", (_k_==7?'-':' '));
        }
        for ( uint32_t _j_ = 0; _j_ < _gap_; _j_++ )
        {
            printf(" ");
        }
        printf("  ");
        for ( size_t _j_ = _i_; _j_ < _end_; _j_++ )
        {
            if ( ((uint8_t*)_b_)[_j_] < 0x20 || ((uint8_t*)_b_)[_j_] > 0x7E || ((uint8_t*)_b_)[_j_] == 0x25 )
            {
                printf(".");
            } 
            else
            {
                printf("%c", ((uint8_t*)_b_)[_j_]);
            }
        }
        printf("\n");
    }
}
#else
#define debug_info(...)
#define DPrint(...)
#define FEnter()
#define FLeave()
#define DPrintMemCol8(_b_, _s_, _o_)
#endif


#ifdef INFO_PRINT
#define IPrint(...) { printf(__VA_ARGS__); }
#else
#define IPrint(...)
#endif


#ifdef ERROR_PRINT
#define EPrint(...) \
                { printf("ERROR: "); \
                printf(__VA_ARGS__); }
#else
#define EPrint(...)    
#endif


#ifdef VERBOSE_MODE
#define header_info(...) { fprintf(stdout, __VA_ARGS__); }
#define header_error(...) { fprintf(stdout, __VA_ARGS__); }
#define prog_error(...) { fprintf(stderr, __VA_ARGS__); }
#else
#define header_info(...)    
#define header_error(...)    
#define prog_error(...)    
#endif

#endif 
