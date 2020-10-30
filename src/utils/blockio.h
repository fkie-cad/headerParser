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



static uint8_t checkFileSpace(uint64_t rel_offset,
							  uint64_t abs_offset,
							  uint16_t needed,
							  size_t file_size);

static uint8_t checkLargeBlockSpace(uint64_t* rel_offset,
									uint64_t* abs_offset,
									uint16_t needed,
									unsigned char* block_l,
									const char* file_name);

static uint8_t checkStandardBlockSpace(uint64_t* rel_offset,
									   uint64_t* abs_offset,
									   uint16_t needed,
									   unsigned char* block_s,
									   const char* file_name);

static uint8_t readStandardBlockIfLargeBlockIsExceeded(uint64_t rel_offset,
													   uint64_t abs_offset,
													   uint16_t needed,
													   unsigned char* block_s,
													   const char* file_name);



/**
 * Check space left in file, depending on offset and needed size.
 *
 * @param rel_offset size_t
 * @param abs_offset size_t
 * @param needed uint16_t
 * @param file_size size_t
 * @return uint8_t bool success value
 */
uint8_t checkFileSpace(uint64_t rel_offset,
					   uint64_t abs_offset,
					   uint16_t needed,
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
uint8_t checkLargeBlockSpace(uint64_t* rel_offset,
							 uint64_t* abs_offset,
							 uint16_t needed,
							 unsigned char* block_l,
							 const char* file_name)
{
	size_t r_size = 0;
	if ( *rel_offset + needed > BLOCKSIZE_LARGE )
	{
		*abs_offset += *rel_offset;
//		r_size = readLargeBlock(file_name, *abs_offset);
		r_size = readCustomBlock(file_name, *abs_offset, BLOCKSIZE_LARGE, block_l);
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
 * @param needed uint16_t
 * @param block_s unsigned char[BLOCKSIZE]
 * @param file_name const char*
 * @return uint8_t bool success value
 */
uint8_t checkStandardBlockSpace(uint64_t* rel_offset,
								uint64_t* abs_offset,
								uint16_t needed,
								unsigned char* block_s,
								const char* file_name)
{
	size_t r_size = 0;
	if ( *rel_offset + needed > BLOCKSIZE )
	{
		*abs_offset += *rel_offset;
//		r_size = readBlock(file_name, *abs_offset);
		r_size = readCustomBlock(file_name, *abs_offset, BLOCKSIZE, block_s);
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
uint8_t readStandardBlockIfLargeBlockIsExceeded(uint64_t rel_offset,
												uint64_t abs_offset,
												uint16_t needed,
												unsigned char* block_s,
												const char* file_name)
{
	size_t r_size = 0;
	if ( rel_offset + needed > BLOCKSIZE_LARGE )
	{
//		r_size = readBlock(file_name, abs_offset+rel_offset);
		r_size = readCustomBlock(file_name, abs_offset+rel_offset, BLOCKSIZE, block_s);
		if ( r_size == 0 )
			return 0;
		return 2;
	}
	return 1;
}

#endif