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



size_t getSizeFP(FILE* fi);

size_t readFile(FILE* fi, size_t begin, size_t size, uint8_t* data);

static size_t readFileA(FILE* fi, size_t begin, size_t size, uint8_t** data);

//static size_t readCustomBlock(const char* finame, size_t offset, size_t size, uint8_t* data);

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
    size_t pos=0;
    size_t file_size=0;
    int s = 0;

//    int errsv;
//    errno = 0;
    if ( !fi )
    {
        EPrint("Passed file pointer is NULL. (0x%x)\n", 1);
        return 0;
    }

    pos = ftell(fi);

    s = fseek(fi, 0, SEEK_END);
    if ( s != 0)
        return 0;
    
    file_size = ftell(fi);
    
    s = fseek(fi, pos, SEEK_SET);
    if ( s != 0)
        return 0;

    return file_size;
}

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
    int s = 0;

    s = fseek(fi, begin, SEEK_SET);
    if ( s != 0)
        return 0;

    n = fread(data, 1, size, fi);

    return n;
}

/**
 * Read from fi at begin size bytes into data**
 * 
 * Allacates a buffer.
 * Caller is responsible for freeing it.
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
    int s = 0;

    *data = (uint8_t*) malloc(size);
    if ( !(*data) )
    {
        return 0;
    }

	if ( begin )
    {
        s = fseek(fi, begin, SEEK_SET);
        if ( s != 0)
            return 0;
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
