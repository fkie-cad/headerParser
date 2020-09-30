#ifndef BLOCK_IO_H
#define BLOCK_IO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../Globals.h"
#include "../../src/utils/common_fileio.h"



static uint8_t checkFileSpace(uint64_t rel_offset, uint64_t abs_offset, uint16_t needed, const char* label);
static uint8_t checkLargeBlockSpace(uint64_t* rel_offset, uint64_t* abs_offset, uint16_t needed, const char* label);
static uint8_t checkStandardBlockSpace(uint64_t* rel_offset, uint64_t* abs_offset, uint16_t needed, const char* label);
static uint8_t readStandardBlockIfLargeBlockIsExceeded(uint64_t rel_offset, uint64_t abs_offset, uint16_t needed, const char* label);



/**
 * Check space left in file, depending on offset and needed size.
 *
 * @param rel_offset size_t
 * @param abs_offset size_t
 * @param needed  uint16_t
 * @param label char* (error)
 * @return uint8_t bool success value
 */
uint8_t checkFileSpace(uint64_t rel_offset, uint64_t abs_offset, uint16_t needed, const char* label)
{
	if ( abs_offset + rel_offset + needed > file_size )
	{
//		prog_error("ERROR: %s offset (%lu) > file_size (%u)\n" ,
//			   label, abs_offset + rel_offset + needed, file_size);
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
 * @param label char* (debug)
 * @return uint8_t bool success value
 */
uint8_t checkLargeBlockSpace(uint64_t* rel_offset, uint64_t* abs_offset, uint16_t needed, const char* label)
{
	size_t r_size = 0;
	if ( *rel_offset + needed > BLOCKSIZE_LARGE )
	{
		*abs_offset += *rel_offset;
		r_size = readLargeBlock(file_name, *abs_offset);
		if ( r_size == 0 )
		{
//			prog_error("ERROR: 1 reading block failed.\n");
			return 0;
		}
		if ( needed > r_size )
		{
//			debug_info("INFO: needed more than may be read.\n");
//			return 0;
		}
		*rel_offset = 0;
	}
	return 1;
}

/**
 * Check space left in standard block, depending on offset and needed size.
 * If block_standard is too small, read in new bytes starting form offset and adjust abs_file_offset.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param label char* (debug)
 * @return uint8_t bool success value
 */
uint8_t checkStandardBlockSpace(uint64_t* rel_offset, uint64_t* abs_offset, uint16_t needed, const char* label)
{
	size_t r_size = 0;
	if ( *rel_offset + needed > BLOCKSIZE )
	{
		*abs_offset += *rel_offset;
		r_size = readBlock(file_name, *abs_offset);
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
 * @param label char* (debug)
 * @return uint8_t 0: failed, 1: nothing happend (enough space), 2: block_standard filled.
 */
uint8_t readStandardBlockIfLargeBlockIsExceeded(uint64_t rel_offset, uint64_t abs_offset, uint16_t needed, const char* label)
{
	size_t r_size = 0;
	if ( rel_offset + needed > BLOCKSIZE_LARGE )
	{
		r_size = readBlock(file_name, abs_offset+rel_offset);
		if ( r_size == 0 )
			return 0;
		return 2;
	}
	return 1;
}

#endif