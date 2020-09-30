#ifndef COMMON_FILEIO_H
#define COMMON_FILEIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../Globals.h"

// Contains : lowlevel fileio support.

static size_t getSize(const char* finame);
static size_t readBlock(const char* finame, size_t begin);
static size_t readLargeBlock(const char* finame, size_t begin);
static size_t readCharArrayFile(const char* finame, unsigned char ** pData, size_t begin, size_t stopAt);
static size_t readFile(FILE* fi, size_t begin, size_t size, unsigned char* data);
static size_t readCustomBlock(const char* finame, size_t offset, size_t size, unsigned char* data);
static uint8_t dirExists(const char* path);

// Get file size.
// Returns actual size in bytes.
size_t getSize(const char* finame)
{
    // Read in file
    FILE * fi;
    size_t pos=0,Filesize=0;
    fi = fopen (finame, "rb" );

    if (!fi)
	{
//		prog_error("File %s does not exist.\n",finame);
		return 0;
	}

    pos = ftell(fi);
    fseek(fi,0,SEEK_END);
    Filesize = ftell(fi);
    fseek(fi,pos,SEEK_SET);
    fclose(fi);

    // prog_error("Filesize: 0x%x (dez. %d)\n",Filesize,Filesize);

    return Filesize;
}

//// Read data into canonical 'standard block' type.
size_t readBlock(const char* finame, size_t begin)
{
    FILE * fi;
    size_t n=0;

    // Read I/O
    fi = fopen (finame, "rb" );
    if (!fi)
	{
		printf("File %s does not exist.\n",finame);
		return 0;
	}

    if (begin)
    {
        fseek(fi,begin,SEEK_SET);
    }

    n = fread(block_standard,1,BLOCKSIZE,fi);
    fclose(fi);

    return n;
}

// Read data into canonical 'large block' type.
size_t readLargeBlock(const char* finame, size_t begin)
{
    FILE * fi;
    size_t n=0;

    // Read I/O
    fi = fopen (finame, "rb" );
    if (!fi)
	{
//		prog_error("File \"%s\" does not exist.\n",finame);
		return 0;
	}
    
    if (begin)
    {
        fseek(fi,begin,SEEK_SET);
    }

    n = fread(block_large,1,BLOCKSIZE_LARGE,fi);
    fclose(fi);

    return n;
}

// Uses MALLOC.
// Caller is responsible for freeing this!
size_t readCharArrayFile(const char* finame, unsigned char ** pData, size_t begin, size_t stopAt)
{
    FILE * fi;
    unsigned char * data = NULL;
    size_t Filesize=0, n=0;
    
    Filesize = getSize(finame);

    // Check Filesize == 0.
    if (!Filesize) 
    {
//		prog_error("File %s is a null (0 bytes) file.\n",finame);
        return 0;
    }
    
    if (begin >= Filesize) 
    {
//		prog_error("Start offset '0x%x' is beyond filesize 0x%x!\n", begin,Filesize);
        return 0;
    }
    if (stopAt > Filesize)
    {
//		prog_error("End offset '0x%x' is beyond filesize 0x%x!\n", begin,Filesize);
//        return 0;
		stopAt = Filesize;
    }
    
    // 'begin' defaults to zero and 'stopAt' defaults to Filesize.
    
    if (stopAt)
    {
        if (begin)
        {
            // Allright
            if (begin < stopAt) Filesize = stopAt - begin;
            
            // User provided us with nonsense. Use something sane instead.
            else Filesize = stopAt;
        }
        else Filesize = stopAt;  // Allright as well
    }
            
    if ((begin) && (!(stopAt)))
    {
        Filesize -= begin;
    }

    // Check Filesize == 0.
    if (!Filesize) 
    {
//		prog_error("Filesize is 0 after using offset begin: 0x%x and stop: 0x%x.\n",begin,stopAt);
        return 0;
    }

    // Allocate space
    data = (unsigned char *) malloc(Filesize);
    if (!data) 
    {
//		prog_error("Malloc failed.\n");
        return 0;
    }

    memset(data,0,Filesize);

    // Read I/O
    fi = fopen(finame, "rb" );
    if (!fi)
	{
//		prog_error("File %s does not exist.\n",finame);
		return 0;
	}
        
    if (begin)
    {
        fseek(fi,begin,SEEK_SET);
    }

    n = fread(data,1,Filesize,fi);
    fclose(fi);

    *pData = data;

    return n; 
    // returns read data points (char's in this case)
}

size_t readFile(FILE* fi, size_t begin, size_t size, unsigned char* data)
{
	size_t n = 0;

	if ( begin )
	{
		fseek(fi, begin, SEEK_SET);
	}

	n = fread(data, 1, size, fi);

	return n;
}

/**
 * Read data from file into data allocated block[size].
 *
 * @param finame
 * @param offset
 * @param size
 * @param data
 * @return
 */
size_t readCustomBlock(const char* finame, size_t offset, size_t size, unsigned char* data)
{
	FILE * fi;
	size_t n = 0;
	
	fi = fopen (finame, "rb");
	if (!fi)
		return 0;
	
	if ( offset )
		fseek(fi, offset, SEEK_SET);

	n = fread(data, 1, size, fi);
	fclose(fi);

	return n;
}

uint8_t dirExists(const char* path)
{
	struct stat s;
	if ( stat(path, &s) == 0 )
	{
		if ( s.st_mode & S_IFDIR )
			return 1;
	}

	return 0;
}

#endif