#include "util-timeouts.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

enum UnitTestParameters {
    /* This is the maximum amount of time the test can run, before
     * generating an error. This should be set to the smallest number
     * that will allow the test to succeed. */
    MAX_TEST_TIME = 20,

    /* This is the number of timeout items we'll be creating, larger
     * numbers will mean the test will take longer */
    MAX_ITEMS = 10000,

    /* Teh maximum number of outstanding items. Our test is done by
     * mixing insertions with removals. In my casual observation, we
     * never get more than about 450 outstaning entries with the
     * timings I've currently set. This tuning parameter thus
     * should never be exceeded. */
    MAX_OUTSTANDING = 500,
};

struct MyStruct {
    struct timespec created;
    struct timespec expired;
    struct TimeoutEntry timeout;
};

enum {MILLISECOND = 1000000ULL, BILLION=1000000000ULL};

/**
 * Subtract the second timestampf from the first, and return the number
 * of nanoseconds, as a 64-it number.
 */
static int64_t
_diff(struct timespec *t1, struct timespec *t2)
{
    int64_t x1 = t1->tv_sec * 1000000000ULL + t1->tv_nsec;
    int64_t x2 = t2->tv_sec * 1000000000ULL + t2->tv_nsec;
    return x1 - x2;
}

/**
 * Custom LCG rand() function to replace built-in rand(), grabbed from
 * MUSL rand() function.
 */
static unsigned
_rand(uint64_t *seed)
{
    *seed = 6364136223846793005ULL * (*seed) + 1ULL;
    return (*seed)>>33;
}


int main(int argc, char *argv[])
{
    time_t test_start_time;
    struct Timeouts *ctx;
    struct timespec one_millisecond = {0, MILLISECOND};
    size_t outstanding = 0;
    uint64_t seed = time(0);
    size_t item_count = 0;
    int i;
    unsigned is_debug = 0;
    
    fprintf(stderr, "[ ] timeouts: test started\n");

    /* Parse some command-line parameters */
    for (i=1; i<argc; i++) {
        if (strcmp(argv[i], "-d") == 0)
            is_debug = 1;
    }
    
    /* Remember when we started this. We need to be done within
     * ~20 seconds for this test to pass */
    test_start_time = time(0);

    /* Create a timeouts structure */
    ctx = timeouts_create(test_start_time, 0);

    
    for (;;) {
        struct timespec now;
        struct MyStruct *x;

        /* We must end within a certain amoutn of time, or we've
         * hit some sort of infinite loop and can't end */
        if (time(0) > test_start_time + MAX_TEST_TIME) {
            fprintf(stderr, "[-] test taking too long, outstanding=%u\n", (unsigned)outstanding);
            return 1;
        }
        
        /* Add up to "MAX_ITEMS" to the timeout subsystem, after which
         * we'll skip this step and simply age out items. Note that we are
         * mixing insertions with removals here, instead of doing a test where
         * we add a bunch of timeouts, then remove a bunch of timeouts. */
        if (item_count < MAX_ITEMS) {
            
            /* Allocate memory for this item */
            x = calloc(1, sizeof(*x));
            
            /* Record the timestamp when it was created */
            clock_gettime(CLOCK_REALTIME, &now);
            memcpy(&x->created, &now, sizeof(now));
            memcpy(&x->expired, &now, sizeof(now));

            /* Generate a random timestamp in the future when this will expire.
             * This timestamp will be at least 100-milliseconds in the future,
             * plus a random amount up to 1-second. Thus, the maximum time
             * in the future is 1.1-second. */
            x->expired.tv_nsec += _rand(&seed) % BILLION +  100 * MILLISECOND;
            while (x->expired.tv_nsec > BILLION) {
                x->expired.tv_nsec -= BILLION;
                x->expired.tv_sec += 1;
            }
            
            
            /* Insert this entry into out timeouts subystem  */
            timeouts_add(ctx,
                         &x->timeout,
                         offsetof(struct MyStruct, timeout),
                         x->expired.tv_sec,
                         x->expired.tv_nsec);
            item_count++;
            
            /* This number is increment every time we add something,
             * and decremented every time we remove something */
            outstanding++;
        }
       
        /* Now age out old entries */
        for (;;) {
            
            /* Get the current time */
            clock_gettime(CLOCK_REALTIME, &now);
            
            /* Remove an entry that is older than this time. */
            x = timeouts_remove_older(ctx, now.tv_sec, (unsigned)now.tv_nsec);
            if (x == NULL)
                break;
              
            /* Print a debugging message when debugging */
            if (is_debug)
                printf("[%u] %lld-ms\n", (unsigned)outstanding, _diff(&now, &x->expired)/(1000*1000));
            
            /* It should be impossible that the 'expired' timestamp should
             * ever be in the future, it should only be possible to exist in
             * the past. */
            if (_diff(&now, &x->expired) < 0) {
                fprintf(stderr, "[-] impossible, expired item in future: %lld-milliseconds\n",
                        _diff(&now, &x->expired)/(1000*1000));
                return 1;
            }
            
            /* Free the memory that was allocated */
            free(x);
            
            /* This number is increment every time we add something,
             * and decremented every time we remove something */
            outstanding--;
        }
        
        /* Do a very short sleep before adding the next item. */
        nanosleep(&one_millisecond, 0);
        
        /* Test the max-outstanding. With the original tuning parameters,
         * I never see mroe than 450 outstanding. */
        if (outstanding > MAX_OUTSTANDING) {
            fprintf(stderr, "[-] too many outstanding %u\n", (unsigned)outstanding);
            return 1;
        }

        /* When we've removed everything, we are done */
        if (outstanding == 0)
            break;
    }
    
    /* Now destroy the structure, for when tracking memory usage */
    timeouts_destroy(ctx);
    fprintf(stderr, "[+] timeouts: test successful\n");
    return 0;
}


