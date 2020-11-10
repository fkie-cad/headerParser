#include <errno.h>
#include <stdio.h>

#include "Fifo.h"



static void FifoEntry_print(PFifoEntry e);



bool Fifo_init(PFifo fifo)
{
	fifo->front = NULL;
	fifo->head = NULL;
    fifo->size = 0;
    fifo->entry_header_size = 2 * sizeof(size_t);

    return true;
}

bool Fifo_clear(PFifo fifo)
{
    PFifoEntry act = fifo->front;
    PFifoEntry tmp = NULL;
	
    while ( act != NULL )
    {
		tmp = act;
		act = act->next;
        free(tmp);
    }
	
    memset(fifo, 0, sizeof(fifo));

    return true;
}

bool Fifo_destroy(PFifo fifo)
{
    Fifo_clear(fifo);
    free(fifo);

    return true;
}

size_t Fifo_push(PFifo fifo, const void* data, size_t data_size)
{
    errno = 0;
    PFifoEntry entry = (PFifoEntry)malloc(fifo->entry_header_size+data_size);
    int errsv = errno;
    if (!entry)
    {
        printf("ERROR (0x%x): malloc failed\n", errsv);
        return 0;
    }
    memset(entry, 0, fifo->entry_header_size + data_size);
    memcpy(entry->data.bytes, data, data_size);
	
	entry->data.size = data_size;
	entry->next = NULL;
		
	if ( fifo->size == 0 )
	{
		fifo->front = entry;
        //fifo->front->last = NULL;
	}
	else
	{
		fifo->head->next = entry;
		//entry->last = fifo->head;
	}
	
	fifo->head = entry;
    fifo->size++;

    return fifo->size;
}

bool Fifo_empty(PFifo fifo)
{
    return fifo->size == 0;
}

size_t Fifo_size(PFifo fifo)
{
    return fifo->size;
}

PFifoEntryData Fifo_front(PFifo fifo)
{
    if (fifo->size == 0)
        return NULL;

    return &(fifo->front->data);
}

bool Fifo_pop_front(PFifo fifo)
{
	PFifoEntry f;
    if (fifo->size == 0)
    {
        return false;
    }

	f = fifo->front;
	fifo->front = f->next;
    //if ( f->next != NULL)
	    //f->next->last = NULL;

    free(f);

    fifo->size--;
    
	return true;
}

void Fifo_print(PFifo fifo)
{
    PFifoEntry e = fifo->front;
    printf("{");
    while (e != NULL)
    {
        FifoEntry_print(e);
        e = e->next;
        if (e != NULL)
            printf(", ");
    }
    printf("}\n");
}

void FifoEntry_print(PFifoEntry e)
{
    size_t i;
    printf("{next: 0x%p, data: {size: 0x%zu, bytes: ", e->next, e->data.size);
    for (i = 0; i < e->data.size; i++)
        printf("%02x|", e->data.bytes[i]);
    printf("}");
}
