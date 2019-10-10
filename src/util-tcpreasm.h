#ifndef UTIL_TCPREASM_H
#define UTIL_TCPREASM_H
#include <stddef.h>
#include <stdint.h>

struct tcpreasm_ctx_t;

struct tcpreasm_connkey_t;

/**
 * Create a subsystem for reassembling TCP streams.
 * @param userdata_size
 *      The size of a userdata structure that will be allocated for every stream, returned
 *      with the 'insert' call, initially set to all zeroes.
 * @param cleanup
 *      A callback function that will be called for each TCP connection's userdata. The caller
 *      should free up any resources held by this connection. Note that the callback doesn't
 *      free the userdata itself, that this is handled by the subystem. Instead, the callback
 *      should free any data pointed to by the custom userdata. If no cleanup is necessary,
 *      then this can be NULL.
 */
struct tcpreasm_ctx_t *
tcpreasm_create(size_t userdata_size, void (*cleanup)(void *userdata), unsigned secs, unsigned usecs);


/**
 * Destroy a reassembly subystem, freeing all memory.
 */
void tcpreasm_destroy(struct tcpreasm_ctx_t *ctx);

/**
 * Do any timeouts necessary for this connection.
 */
size_t tcpreasm_timeouts(struct tcpreasm_ctx_t *ctx, void (*cleanup)(void *userdata), uint64_t timestamp);

struct tcpreasm_handle_t {
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
struct tcpreasm_handle_t
tcpreasm_insert_packet(struct tcpreasm_ctx_t *ctx, const unsigned char *buf, size_t length, unsigned secs, unsigned usecs);


/**
 * Reads bytes from the TCP stream..
 */
size_t tcpreasm_read(struct tcpreasm_handle_t *stream, unsigned char *buf, size_t length);

#endif

