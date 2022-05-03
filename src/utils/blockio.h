#ifndef BLOCK_IO_H
#define BLOCK_IO_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../Globals.h"
#include "common_fileio.h"


/**
 * Check space left in file, depending on offset and needed size.
 *
 * @param rel_offset size_t
 * @param abs_offset size_t
 * @param needed uint16_t
 * @param file_size size_t
 * @return uint8_t bool success value
 */
static uint8_t checkFileSpace(size_t rel_offset,
                              size_t abs_offset,
                              size_t needed,
                              size_t file_size);

/**
 * Check space left in large block, depending on offset and needed size.
 * If block_large is too small, read in new bytes starting form offset and adjust abs_file_offset and rel_offset.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param block_l  unsigned char[BLOCKSIZE_LARGE]
 * @param file_name  const char*
 * @return uint8_t bool success value
 */
static uint8_t checkLargeBlockSpace(size_t* rel_offset,
                                    size_t* abs_offset,
                                    size_t needed,
                                    unsigned char* block_l,
                                    FILE* fp);

/**
 * Check space left in standard block, depending on offset and needed size.
 * If block_standard is too small, read in new bytes starting form offset and adjust abs_file_offset.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed uint16_t
 * @param block_s unsigned char[BLOCKSIZE]
 * @param file_name const char*
 * @return uint8_t bool success value
 */
static uint8_t checkStandardBlockSpace(size_t* rel_offset,
                                       size_t* abs_offset,
                                       size_t needed,
                                       unsigned char* block_s,
                                       FILE* fp);

/**
 * Check space left in large block, depending on offset and needed size.
 * If block_large is too small, read in new bytes into block_standard.
 * abs_file_offset is not adjusted.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param block_s unsigned char[BLOCKSIZE]
 * @param file_name const char*
 * @return uint8_t 0: failed, 1: nothing happend (enough space), 2: block_standard filled.
 */
static uint8_t readStandardBlockIfLargeBlockIsExceeded(size_t rel_offset,
                                                       size_t abs_offset,
                                                       size_t needed,
                                                       unsigned char* block_s,
                                                       FILE* fp);





/**
 * Check space left in file, depending on offset and needed size.
 *
 * @param rel_offset size_t
 * @param abs_offset size_t
 * @param needed uint16_t
 * @param file_size size_t
 * @return uint8_t bool success value
 */
uint8_t checkFileSpace(size_t rel_offset,
                       size_t abs_offset,
                       size_t needed,
                       size_t file_size)
{
    if ( abs_offset + rel_offset + needed > file_size )
    {
        return 0;
    }

    return 1;
}

/**
 * Check space left in large block, depending on offset and needed size.
 * If block_large is too small, read in new bytes starting form offset and adjust abs_file_offset and rel_offset.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param block_l  unsigned char[BLOCKSIZE_LARGE]
 * @param file_name  const char*
 * @return uint8_t bool success value
 */
uint8_t checkLargeBlockSpace(size_t* rel_offset,
                             size_t* abs_offset,
                             size_t needed,
                             unsigned char* block_l,
                             FILE* fp)
{
    size_t r_size = 0;
    if ( needed > BLOCKSIZE_LARGE )
    {
        return false;
    }
    if ( *rel_offset + needed > BLOCKSIZE_LARGE )
    {
        *abs_offset += *rel_offset;
//		r_size = readCustomBlock(file_name, *abs_offset, BLOCKSIZE_LARGE, block_l);
        r_size = readFile(fp, *abs_offset, BLOCKSIZE_LARGE, block_l);
        if ( r_size == 0 )
        {
//			prog_error("ERROR: 1 reading block failed.\n");
            return false;
        }
        if ( needed > r_size )
        {
//			debug_info("INFO: needed more than may be read.\n");
//			return 0;
        }
        *rel_offset = 0;
    }
    return true;
}

/**
 * Check space left in standard block, depending on offset and needed size.
 * If block_standard is too small, read in new bytes starting form offset and adjust abs_file_offset.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed uint16_t
 * @param block_s unsigned char[BLOCKSIZE]
 * @param file_name const char*
 * @return uint8_t bool success value
 */
uint8_t checkStandardBlockSpace(size_t* rel_offset,
                                size_t* abs_offset,
                                size_t needed,
                                unsigned char* block_s,
                                FILE* fp)
{
    size_t r_size = 0;
    if ( *rel_offset + needed > BLOCKSIZE )
    {
        *abs_offset += *rel_offset;
//		r_size = readCustomBlock(file_name, *abs_offset, BLOCKSIZE, block_s);
        r_size = readFile(fp, *abs_offset, BLOCKSIZE, block_s);
        if ( r_size == 0 )
        {
//			prog_error("ERROR: 1 reading block failed.\n");
            return 0;
        }
        if ( needed > r_size )
        {
//			prog_error("ERROR: needed bounds out of file size.\n");
            return 0;
        }
        *rel_offset = 0;
    }
    return 1;
}

/**
 * Check space left in large block, depending on offset and needed size.
 * If block_large is too small, read in new bytes into block_standard.
 * abs_file_offset is not adjusted.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param block_s unsigned char[BLOCKSIZE]
 * @param file_name const char*
 * @return uint8_t 0: failed, 1: nothing happend (enough space), 2: block_standard filled.
 */
uint8_t readStandardBlockIfLargeBlockIsExceeded(size_t rel_offset,
                                                size_t abs_offset,
                                                size_t needed,
                                                unsigned char* block_s,
                                                FILE* fp)
{
    size_t r_size = 0;
    if ( rel_offset + needed > BLOCKSIZE_LARGE )
    {
//		r_size = readCustomBlock(file_name, abs_offset+rel_offset, BLOCKSIZE, block_s);
        r_size = readFile(fp, abs_offset+rel_offset, BLOCKSIZE, block_s);
        if ( r_size == 0 )
            return 0;
        return 2;
    }
    return 1;
}

#endif