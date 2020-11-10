#ifndef SHARED_FIFO_H
#define SHARED_FIFO_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

/**
 * FIFO
 * vs 1.0.0
 */

//#define FIFO_ENTRY_HEADER_SIZE_32 (12)
//#define FIFO_ENTRY_HEADER_SIZE_64 (24)


typedef struct FifoEntryData {
    size_t size;
    unsigned char bytes[1];
} FifoEntryData, * PFifoEntryData;

typedef struct FifoEntry {
   struct FifoEntry* next;
   FifoEntryData data;
} FifoEntry, * PFifoEntry;

typedef struct Fifo {
    struct FifoEntry* front;
    struct FifoEntry* head;
    size_t size;
    size_t entry_header_size; // size of data header (next + size)
} Fifo, *PFifo;

/**
 * Initialize Fifo internals.
 * 
 * @return bool success
 */
bool Fifo_init(PFifo fifo);

/**
 * Clears and frees all elements in the fifo,
 * but does not free the fifo object itself.
 * 
 * @param fifo PFofo the fifo
 * @return bool success
 */
bool Fifo_clear(PFifo fifo);

/**
 * Clears and frees all elements in the fifo,
 * and frees the fifo object itself.
 * 
 * @param fifo PFofo the fifo
 * @return bool success
 */
bool Fifo_destroy(PFifo fifo);

/**
 * Push data onto Fifo.
 * 
 * @param fifo PFofo the fifo
 * @param data void*
 * @param size size_t size of the data
 */
size_t Fifo_push(PFifo fifo, const void* data, size_t data_size);

/**
 * Check if Fifo is empty.
 * 
 * @param fifo PFofo the fifo
 * @return bool result
 */
bool Fifo_empty(PFifo fifo);

/**
 * Get size of Fifo.
 * 
 * @param fifo PFofo the fifo
 * @return size_t result
 */
size_t Fifo_size(PFifo fifo);

/**
 * Get (pointer to) front element of Fifo.
 * 
 * @param fifo PFofo the fifo
 */
PFifoEntryData Fifo_front(PFifo fifo);

/**
 * Pop front element from Fifo.
 * 
 * @param fifo PFofo the fifo
 */
bool Fifo_pop_front(PFifo fifo);

/**
 * Print Fifo.
 * 
 * @param fifo PFofo the fifo
 */
void Fifo_print(PFifo fifo);

#endif
