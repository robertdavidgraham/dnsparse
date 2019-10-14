/*
 Author: Robert Graham
 License: MIT
 Dependencies: util-hashmap util-timeouts
 
 TCP reassembler
 
 This is a simple module for reassembling TCP streams. It's intended
 for live packet capture (using the libpcap library) or reading packets
 from a file (using either libpcap or util-pcapfile).
 
 It's not terribly efficient.
 
*/
#ifndef UTIL_TCPREASM_H
#define UTIL_TCPREASM_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct tcpreasm_ctx_t;

struct tcpreasm_connkey_t;

/**
 * Create a reassembler.
 * @param userdata_size
 *      The size of a userdata structure that will be allocated for every stream, returned
 *      with the 'insert' call, initially set to all zeroes. This is an optimization that saves
 *      on memory allocations, allocating this memory along with the TCB.
 * @param cleanup
 *      A callback function that will be called for each TCP connection's userdata. The caller
 *      should free up any resources held by this connection. Note that the callback doesn't
 *      free the userdata itself, that this is handled by the subystem. Instead, the callback
 *      should free any data pointed to by the custom userdata. If no cleanup is necessary,
 *      then this can be NULL.
 * @param started
 *      The timestamp when packet capture started, which should be the first packet in
 *      the file. This is used to initialize the timeouts subsystem.
 */
struct tcpreasm_ctx_t *
tcpreasm_create(size_t userdata_size, void (*cleanup)(void *userdata), time_t started, unsigned default_timeout);


/**
 * Destroy a reassembly subystem, freeing all memory.
 */
void tcpreasm_destroy(struct tcpreasm_ctx_t *ctx);

/**
 * Process any timeouts necessary for this connection.
 */
size_t tcpreasm_timeouts(struct tcpreasm_ctx_t *ctx, time_t secs, long nanosec);

/**
 * Holds the results tcp_insert_packet(), to tell us whether we can read the packet
 * contents.
 */
struct tcpreasm_tuple_t {
    struct tcpreasm_connkey_t *conn;
    size_t available;
    void *userdata;
    struct tcpreasm_ctx_t *ctx;
};

/**
 * Insert a packet into the TCP stream.
 * @return
 *      A tuple consising of a handle to this connection, the number of available bytes that can be
 *      read, and handle to the opaque data structure for the user.
 */
struct tcpreasm_tuple_t
tcpreasm_packet(struct tcpreasm_ctx_t *ctx, const unsigned char *buf, size_t length, time_t secs, long nanosecs);


/**
 * Reads bytes from the TCP stream. Analogous to read()/recv() on a socket.
 * @param stream
 *      A handle to the TCP stream, returned from tcpreasm_insert_packet().
 * @param buf
 *      A bufer where the reassembled bytes will be written.
 * @param length
 *      The requested number of bytes to read. If not all the bytes are available, then
 *      fewer bytes will be returned.
 * @return
 *      0 if nothing available to read, or the number of bytes successfully read, up to length.
 *      If fewer bytes are available than the requested number, then all bytes will be returned.
 *      Note that more bytes may exist in the reassembly buffers that aren't contiguous, but
 *      they won't be available for reading yet, and won't be returned until the missing bytes
 *      arrive.
 */
size_t
tcpreasm_read(struct tcpreasm_tuple_t *stream, unsigned char *buf, size_t length);

#endif

