/*
 Author: Robert Graham
 License: MIT
 
 Event timeout

 This is for a user-mode TCP stack. We need to mark timeouts in the
 future when we'll re-visit a connection/tcb. For example, when we
 send a packet, we need to resend it in the future in case we don't
 get a response.

 This design creates a large "ring" of timeouts, and then cycles
 again and again through the ring. It's terribly inefficient if
 the number of timeouts are fewer than 100 per second, or greater
 than 10 million per second.
 
 The granularity/precision of the ticks is about 100,000 per
 second. I keep adjusting the granularity internally whenever
 I want more/less precision.

 NOTE: A big feature of this system is that the structure that tracks
 the timeout is actually held within the TCB structure, so that
 there isn't a separate memory allocation for the timeout.

 NOTE: a recurring bug is that the TCP code removes a TCB from the
 timeout ring and forgets to put it back somewhere else. Since the
 TCB is cleaned up on a timeout, such TCBs never get cleaned up,
 leading to a memory leak. I keep fixing this bug, then changing the
 code and causing the bug to come back again.
 
 NOTE: the notion of "time" is EXTERNAL to this module. Thus, it can
 be used with packet-capture files, where the notion of time comes
 from the packets instead of the wall-clock.
 */
#ifndef UTIL_TIMEOUTS_H
#define UTIL_TIMEOUTS_H
#include <stdint.h>
#include <stddef.h>

struct Timeouts;


/**
 * The intent of this structure is that it be contained within
 * the data structure of the thing the timeout is tracking,
 * so that it doesn't rerequire a separate memory allocation.
 */
struct TimeoutEntry {
    /**
     * An opaque high resolution timestamp. Timestamps are
     * given using seconds/nanoseconds, but the module may
     * represent them internally with less precision. In practice,
     * it's around microsecond resolution.
     */
    uint64_t timestamp;

    /** We build a doubly-linked list so that we can remove a
     * member from the middle of the list. */
    struct TimeoutEntry *next;
    struct TimeoutEntry **prev;

    /** The timeout entry is never allocated by itself, but instead
     * lives inside another data structure. This stores the value of
     * 'offsetof()', so given a pointer to this structure, we can find
     * the original structure that contains it */
    size_t offset;
};

/**
 * Removes the timeout from the linked-list of timeouts.
 */
void
timeout_unlink(struct TimeoutEntry *entry);


/**
 * Create a timeout subsystem.
 * @param now
 *      The current timestamp indicating "now" when the thing starts,
 *      or time(0).
 * @param nanosec
 *      The number of nanoseconds since the start of the current
 *      second. Often just zero since we rarely care about exact
 *      timings when creating the module..
 *
 */
struct Timeouts *
timeouts_create(uint64_t now, long nanosec);

void
timeouts_destroy(struct Timeouts *ctx);

/**
 * Insert the timeout 'entry' into the future location in the timeout
 * ring, as determined by the timestamp. This must be removed either
 * with 'timeout_remove()' at the normal time, or "timeout_unlink()'
 * on cleanup.
 * @param timeouts
 *      A ring of timeouts, with each slot corresponding to a specific
 *      time in the future.
 * @param entry
 *      The entry that we are going to insert into the ring. If it's
 *      already in the ring, it'll be removed from the old location
 *      first before inserting into the new location.
 * @param offset
 *      The 'entry' field above is part of an existing structure. This
 *      tells the offset_of() from the begining of that structure. 
 *      In other words, this tells us the pointer to the object that
 *      that is the subject of the timeout.
 * @param expires_secs
 *      The timestamp when this eent is to expire.
 * @param expires_nanosec
 *      The number of nanoseconsd combined to form the timestamp.
 */
void
timeouts_add(struct Timeouts *timeouts, struct TimeoutEntry *entry,
                  size_t offset, uint64_t expires_secs, long expires_nanosec);

/**
 * Remove an object from the timestamp system that is older than than
 * the specified timestamp. This function must be called repeatedly
 * until it returns NULL to remove all the objects that are older
 * than the given timestamp.
 * @param timeouts
 *      A ring of timeouts. We'll walk the ring until we've caught
 *      up with the current time.
 * @param secs
 *      All events older than this timestamp.
 * @param nanosec
 *      Combined with secs to form the timestamp
 * @return
 *      an object older than the specified timestamp, or NULL
 *      if there are no more objects to be found
 */
void *
timeouts_remove_older(struct Timeouts *timeouts, uint64_t secs, long nanosec);



#endif
