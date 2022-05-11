#ifndef COMMON_FILEIO_H
#define COMMON_FILEIO_H

#include <stdlib.h>
#include <stdint.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../Globals.h"

// Contains : lowlevel fileio support.

//// Get file size.
//// Returns actual size in bytes.
//static size_t getSize(const char* finame);

static size_t getSizeFP(FILE* fi);

//// Uses MALLOC.
//// Caller is responsible for freeing this!
//static size_t readCharArrayFile(const char* finame, uint8_t ** pData, size_t begin, size_t stopAt);

/**
 * Read from fi at begin size bytes into data[size]
 *
 * @param fi
 * @param begin
 * @param size
 * @param data
 * @return
 */
static size_t readFile(FILE* fi, size_t begin, size_t size, uint8_t* data);

/**
 * Read from fi at begin size bytes into data**
 * (Caller is responsible for allocation)
 *
 * @param fi FILE* opened FILE*
 * @param begin size_t offset into file
 * @param size size_t size to read
 * @param data uint8_t**
 * @return size_t number of read bytes
 */
static size_t readFileA(FILE* fi, size_t begin, size_t size, uint8_t** data);

///**
// * Read from finame at offset size bytes into data[size]
// *
// * @param finame
// * @param offset
// * @param size
// * @param data
// * @return
// */
//static size_t readCustomBlock(const char* finame, size_t offset, size_t size, uint8_t* data);

///**
// * Check if dir exists.
// * 
// * @param path The path to check
// * @return 1 : true, or 0 : false
// */
//static uint8_t dirExists(const char* path);




//// Get file size.
//// Returns actual size in bytes.
//size_t getSize(const char* finame)
//{
//    // Read in file
//    FILE * fi;
//    size_t pos=0,Filesize=0;
//    int s;
//    int errsv;
//    errno = 0;
//    fi = fopen (finame, "rb" );
//    errsv = errno;
//    if (!fi)
//    {
//        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, finame);
//        return 0;
//    }
//
//    pos = ftell(fi);
//    errno = 0;
//    s = fseek(fi,0,SEEK_END);
//    errsv = errno;
//    if ( s != 0 )
//    {
//        printf("ERROR (0x%x): FSeek in \"%s\".\n", errsv, finame);
//        Filesize = 0;
//        goto clean;
//    }
//    errno = 0;
//    Filesize = ftell(fi);
//    errsv = errno;
//    if ( errsv != 0 )
//    {
//        printf("ERROR (0x%x): FTell in \"%s\".\n", errsv, finame);
//        if ( errsv == 0x16 )
//        {
//            printf("The file may be too big.\n");
//        }
//        Filesize = 0;
//    }
//    fseek(fi,pos,SEEK_SET);
//
//    clean:
//    fclose(fi);
//
//    return Filesize;
//}

size_t getSizeFP(FILE* fi)
{
    size_t pos=0,Filesize=0;
//    int errsv;
//    errno = 0;
    if (!fi)
    {
        printf("ERROR (0x%x): Passed file pointer is NULL.\n", 1);
        return 0;
    }

    pos = ftell(fi);
    fseek(fi,0,SEEK_END);
    Filesize = ftell(fi);
    fseek(fi,pos,SEEK_SET);

    return Filesize;
}

//// Uses MALLOC.
//// Caller is responsible for freeing this!
//size_t readCharArrayFile(const char* finame, uint8_t ** pData, size_t begin, size_t stopAt)
//{
//    FILE * fi;
//    uint8_t * data = NULL;
//    size_t Filesize=0, n=0;
//    int errsv;
//
//    Filesize = getSize(finame);
//
//    // Check Filesize == 0.
//    if (!Filesize)
//    {
////		prog_error("File %s is a null (0 bytes) file.\n",finame);
//        return 0;
//    }
//
//    if (begin >= Filesize)
//    {
////		prog_error("Start offset '0x%x' is beyond filesize 0x%x!\n", begin,Filesize);
//        return 0;
//    }
//    if (stopAt > Filesize)
//    {
////		prog_error("End offset '0x%x' is beyond filesize 0x%x!\n", begin,Filesize);
////        return 0;
//        stopAt = Filesize;
//    }
//
//    // 'begin' defaults to zero and 'stopAt' defaults to Filesize.
//
//    if (stopAt)
//    {
//        if (begin)
//        {
//            // Allright
//            if (begin < stopAt) Filesize = stopAt - begin;
//
//            // User provided us with nonsense. Use something sane instead.
//            else Filesize = stopAt;
//        }
//        else Filesize = stopAt;  // Allright as well
//    }
//
//    if ((begin) && (!(stopAt)))
//    {
//        Filesize -= begin;
//    }
//
//    // Check Filesize == 0.
//    if (!Filesize)
//    {
////		prog_error("Filesize is 0 after using offset begin: 0x%x and stop: 0x%x.\n",begin,stopAt);
//        return 0;
//    }
//
//    // Allocate space
//    data = (uint8_t *) malloc(Filesize);
//    if (!data)
//    {
////		prog_error("Malloc failed.\n");
//        return 0;
//    }
//
//    memset(data,0,Filesize);
//
//    // Read I/O
//    errno = 0;
//    fi = fopen(finame, "rb" );
//    errsv = errno;
//    if (!fi)
//    {
//        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, finame);
//        return 0;
//    }
//
//    if (begin)
//    {
//        fseek(fi,begin,SEEK_SET);
//    }
//
//    n = fread(data,1,Filesize,fi);
//    fclose(fi);
//
//    *pData = data;
//
//    return n;
//}

/**
 * Read from fi at begin size bytes into data[size]
 *
 * @param fi
 * @param begin
 * @param size
 * @param data
 * @return
 */
size_t readFile(FILE* fi, size_t begin, size_t size, uint8_t* data)
{
    size_t n = 0;

    fseek(fi, begin, SEEK_SET);

    n = fread(data, 1, size, fi);

    return n;
}

/**
 * Read from fi at begin size bytes into data**
 * (Caller is responsible for allocation)
 *
 * @param fi FILE* opened FILE*
 * @param begin size_t offset into file
 * @param size size_t size to read
 * @param data uint8_t**
 * @return size_t number of read bytes
 */
size_t readFileA(FILE* fi, size_t begin, size_t size, uint8_t** data)
{
    size_t n = 0;

    *data = (uint8_t*) malloc(size);
    if (!(*data))
    {
//		prog_error("Malloc failed.\n");
        return 0;
    }

//	if ( begin )
    {
        fseek(fi, begin, SEEK_SET);
    }

    n = fread(*data, 1, size, fi);

    return n;
}

///**
// * Read from finame at offset size bytes into data[size]
// *
// * @param finame
// * @param offset
// * @param size
// * @param data
// * @return
// */
//size_t readCustomBlock(const char* finame, size_t offset, size_t size, uint8_t* data)
//{
//    FILE * fi;
//    size_t n = 0;
//    int errsv;
//    errno = 0;
//    fi = fopen (finame, "rb");
//    errsv = errno;
//    if (!fi)
//    {
//        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, finame);
//        return 0;
//    }
//
//    if ( offset )
//        fseek(fi, offset, SEEK_SET);
//
//    n = fread(data, 1, size, fi);
//    fclose(fi);
//
//    return n;
//}

//uint8_t dirExists(const char* path)
//{
//    struct stat s;
//    if ( stat(path, &s) == 0 )
//    {
//        if ( s.st_mode & S_IFDIR )
//            return 1;
//    }
//
//    return 0;
//}


#endif