
#include "util-timeouts.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>




#define TICKS_PER_SECOND 16384

/**
 * Convert the external time into an internal timestamp, the count of the
 * number of 'ticks'. A tick is roughly 1/16k of a second, or roughly
 * 61-microseconds. We treat nanoseconds here as a 30-bit
 * number (1024*1024*1024) instead of a decimal number
 * (1000 * 1000 * 1000) to avoid doing integer division. This means
 * that every second, we'll have a slight period of inactivity at
 * the boundary instead of smooth actiivity.
 */
static uint64_t
timestamp_from_tv(uint64_t secs, long nanosec)
{
    return (secs << 14ULL) + (nanosec>>16ULL);
}


/**
 * The timeout system is a circular ring. We move an index around the 
 * ring. At each slot in the ring is a linked-list of all entries at
 * that time index. Because the ring can wrap, not everything at a given
 * entry will be the same timestamp. Therefore, when doing the timeout
 * logic at a slot, we have to doublecheck the actual timestamp, and skip
 * those things that are further in the future.
 */
struct Timeouts {
    /**
     * This index is a monotonically increasing number, modulus the mask.
     * Every time we check timeouts, we simply move it foreward in time.
     */
    uint64_t last_timestamp;

    /**
     * The number of slots is a power-of-2, so the mask is just this
     * number minus 1
     */
    unsigned mask;

    /**
     * The ring of entries.
     */
    struct TimeoutEntry *slots[1024*1024];
    
    /**
     * Incremented every time we add one, and decremented every time we remove one
     */
    size_t outstanding;
};




/***************************************************************************
 ***************************************************************************/
struct Timeouts *
timeouts_create(uint64_t now, long nanosec)
{
    uint64_t timestamp = timestamp_from_tv(now, nanosec);
    struct Timeouts *timeouts;

    /*
     * Allocate memory and initialize it to zero
     */
    timeouts = calloc(1, sizeof(*timeouts));
    if (timeouts == NULL)
        abort();
    
    /*
     * We just mask off the low order bits to determine wrap. I'm using
     * a variable here because one of these days I'm going to make
     * the size of the ring dynamically adjustable depending upon
     * the speed of the scan.
     */
    timeouts->mask = sizeof(timeouts->slots)/sizeof(timeouts->slots[0]) - 1;

    /*
     * Set the index to the current time. Note that this timestamp is
     * the 'time_t' value multiplied by the number of ticks-per-second,
     * where 'ticks' is something I've defined for scanning. Right now
     * I hard-code in the size of the ticks, but eventually they'll be
     * dynamically resized depending upon the speed of the scan.
     */
    timeouts->last_timestamp = timestamp;


    return timeouts;
}


void
timeout_unlink(struct TimeoutEntry *entry)
{
    /* If nothing to do, return immediately */
    if (entry->prev == 0 && entry->next == 0)
        return;
    
    /* Set parent's pointer to point to child */
    *(entry->prev) = entry->next;
    
    /* Set child's pointer to point to parent */
    if (entry->next)
        entry->next->prev = entry->prev;
    
    /* Zero out our own data */
    entry->next = 0;
    entry->prev = 0;
    entry->timestamp = 0;
}


void
timeouts_add(struct Timeouts *timeouts, struct TimeoutEntry *entry,
             size_t offset, uint64_t secs, long nanosecs)
{
    uint64_t timestamp = timestamp_from_tv(secs, nanosecs);
    unsigned index;

    /* Unlink from wherever the entry came from */
    timeout_unlink(entry);

    /* Initialize the new entry */
    entry->timestamp = timestamp;
    entry->offset = (unsigned)offset;

    /* Link it into it's new location */
    index = timestamp & timeouts->mask;
    entry->next = timeouts->slots[index];
    timeouts->slots[index] = entry;
    entry->prev = &timeouts->slots[index];
    if (entry->next)
        entry->next->prev = &entry->next;
}


void *
timeouts_remove_older(struct Timeouts *timeouts, uint64_t secs, long nanosec)
{
    uint64_t now;
    uint64_t timestamp;
    struct TimeoutEntry *entry = NULL;
    
    /* Convert the external time into our internal tick-count */
    now = timestamp_from_tv(secs, nanosec);
 
    /* Starting from the last timestamp we checked, move forward
     * in time checking timeouts until we reach the current time */
    for (timestamp = timeouts->last_timestamp; timestamp < now; timestamp++) {
        size_t index;
        
        /* Convert the timestamp into a table index. Basically, we are hashing
         * the timestamp -- but the hash is simply based upon the least
         * significant bits of the timestamp. */
        index = timestamp & timeouts->mask;
        
        /* Get the 'head' of the linked list at the specified bucket/slot  */
        entry = timeouts->slots[index];

        /* enumerate through the linked list until we either reach the end,
         * or reach an entry that needs to expire */
        while (entry && entry->timestamp > now)
            entry = entry->next;
        if (entry)
            break;
    }
    
    /* Remember the last timestamp we checked */
    timeouts->last_timestamp = timestamp;

    if (entry == NULL) {
        /* we've caught up to the current time, and there's nothing
         * left to timeout, so return NULL */
        return NULL;
    }
    
    /* Remove this record from the system  */
    timeout_unlink(entry);

    /* return a pointer to the structure holding this entry */
    return ((char*)entry) - entry->offset;
}


void
timeouts_destroy(struct Timeouts *ctx)
{
    /* We have no special memory to free, other than our main structure,
     * because timeout-entries aren't malloc()ed, but are assumed to live
     * inside a data structure that the caller is already responsible for.
     * If the caller really needs, they should call the remove() function
     * with a timestamp far in the future to remove everything. */
    free(ctx);
}

