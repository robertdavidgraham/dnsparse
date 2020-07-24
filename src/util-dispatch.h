/*
    A simple dispatcher.
 
    This is a simple wrapper for the 'poll()' or 'select()' feature
    of the sockets API, portable accross Linux, macOS, Windows, and
    other operating systems that support the 'sockets' API.
 
    This is an 'edge-triggered' API. In other words, while poll()/select()
    are inherently 'level-triggered', this API will immediately execute
    the triggered function (like send or recv) and deliver the results.
    In other words, the caller never calls 'recv()' themselves, but
    instead accepts incoming data from the subsystem.
 
    Objects tracked by the system are referenced by a 'handle', which
    is an integer starting from around 0, with a value of -1 to indicate
    an invalid value. In other words, the semantics are the same as
    with sockets/file-descriptors. But is not such a descriptor, but
    an index into it's own internal tables. The value of this handle
    is almost guaranteed to not be the same as the socket/file-descriptor
    of the underlying object.
 */
#ifndef UTIL_DISPATCH_H
#define UTIL_DISPATCH_H
#include <stddef.h>
#include <stdint.h>

typedef struct dispatcher dispatcher;
typedef struct dispatchevent dpevent;

/* A good default 'wait' parameter to send to the dispatch function */
#define TEN_MILLISECONDS (10ULL*1000ULL*1000ULL)

enum {
    /* This will never be used */
    DISPATCH_NOTHING,
        
    /* The TCP connection has been closed. This is the last call the
     * dispatcher will make. This is an appropriate time for the
     * programmer to free the callback-data structure */
    DISPATCH_CLOSED,
    
    /* An error happened. */
    DISPATCH_ERROR,

    /* The connection is in progress. If no error, this is always
     * the first event from dispatch_connect(). */
    DISPATCH_CONNECTING,

    /* The connection has succeeded. The socket is now ready for
     * reading/writing. */
    DISPATCH_CONNECTED,
    
    /* A new connection was created on a listening socket.*/
    DISPATCH_ACCEPTED,
    
    /* A timer expired */
    DISPATCH_WAIT_EXPIRED,
    
    /* The server is now listening */
    DISPATCH_LISTENING,
    
    /* The TCP connection was adopted */
    DISPATCH_ADOPTED,
    
    DISPATCH_RECEIVED,
    DISPATCH_SENT,
    DISPATCH_SEND_AVAILABLE,

};

enum {
    DISPATCH_SUCCESS,
    DISPATCH_ERR_UNKNOWN,
    DISPATCH_ERR_GETADDRINFO,
    DISPATCH_ERR_SOCKET,
    DISPATCH_ERR_BIND,
    DISPATCH_ERR_LISTEN,
    DISPATCH_ERR_CONNECT,
    DISPATCH_ERR_NONBLOCKING,
};

typedef void (*dispatch_callback)(dispatcher *d, int handle, dpevent *e, void *cbdata);

struct dispatchevent {
    int type;
    
    union {
        struct {
            const void *buf;
            size_t length;
        } *read;
        struct {
            struct sockaddr *sa;
            size_t sa_length;
            int fd;
        } *accept;
        struct {
            struct sockaddr *sa;
            size_t sa_length;
        } *listening;
        struct {
            int error_code;
        } *error;
    };
    
    /** Socket  or file handle for the associated resource. */
    int fd;
    char opaque[];
};

/**
 * Create an instance of this subsystem.
 */
dispatcher *
dispatch_create(void);

/**
 * Destroy a dispatcher subsystem and free all resources. Pending
 * things will be sent DISPATCH_CLOSE events..
 */
void
dispatch_destroy(dispatcher *d);

/**
 * Dispatch any triggered events.
 * @param nanoseconds
 *      A period to wait for incoming events before giving up and returning.
 *      We recommend TEN_MILLISECONDS as a good value here.
 */
int
dispatch_dispatch(dispatcher *d, uint64_t nanoseconds);


/**
 * Start a TCP connection to the target address/port.
 * @triggers
 *  DISPATCH_ERROR if the connection fails.
 *  DISPATCH_CONNECTING if the connection process started successfully.
 *  DISPATCH_CONNECTED if the connection succeeds.
 */
int
dispatch_connect(dispatcher *d, dispatch_callback cb, void *userdata, const char *addr, unsigned port, unsigned protocol);

/**
 * Listen for incoming TCP connections, setting up a server socket.
 * @triggers
 *  DISPATCH_ERROR if failed to creating the listener.
 *  DISPATCH_LISTENING if successful creating the listerner.
 *  DISPATCH_ACCEPTED whenever an incoming TCP connection arrives.
 */
int
dispatch_listen(dispatcher *d, dispatch_callback cb, void *userdata, const char *addr, unsigned port, unsigned protocol);

/**
 * Adopts a socket descriptor, adding it to the system, so that read/writes can be
 * dispatched. This can be used for any socket, but is most often used in
 * servers, where the callback that handles an "accept()" will use this function
 * to adopt the newly created TCP connection.
 */
int
dispatch_adopt(dispatcher *d, dispatch_callback cb, void *userdata, int fd, struct sockaddr *sa, size_t sa_length);

/**
 * Send data to the other side. If the kernel rejects the send because of lack of buffers
 * available, then this function will buffer the data in userspace and send at a later
 * time when it can, at which point it'll callback with a DISPATCH_SENT event. This
 * can also be called at any time with a socket that was created outside the system
 * in order to add it to this system.
 */
int
dispatch_send_buffered(dispatcher *d, int handle, const void *buf, size_t length, size_t *sent);

/**
 * Send data to the other side of the connection. If the kernel rejects the send because
 * of lack of buffers, then this function will return the length of data that could be successfully
 * sent. When new buffers become available, DISPATCH_SEND_AVAILABLE will be triggered.
 */
int
dispatch_send_partial(dispatcher *d, int handle, const void *buf, size_t length, size_t *sent);

/**
 * Asks the dispatcher to close the object. This will call 'close()' on the
 * socket (if there one) and free any resources. The final thing this
 * function will do before returning is dispatch a DISPATCH_CLOSED event
 * before forgetting completely about the object.
 */
int
dispatch_close(dispatcher *d, int handle);

/**
 * Wait the indicated number of nanoseconds, after which DISPATCH_TIMEOUT will trigger.
 */
int
dispatch_wait(dispatcher *d, dispatch_callback cb, void *userdata, uint64_t nanoseconds);

/**
 * Set a timeout to trigger the specified nanoseconds into the future.
 */
void
dispatch_timeout(dispatcher *d, int handle, uint64_t nanoseconds);

/**
 * Create a 'timer' object.
 */
int
dispatch_timer(dispatcher *d, dispatch_callback cb, void *userdata);

/**
 * Create an object that will trigger when signals occur.
 */
int
dispatch_signal(dispatcher *d, int sig, dispatch_callback cb, void *userdata);

/**
 * Get the address for this end of the connection.
 */
void
dispatch_getsockname(dispatcher *d, int handle, char *addr, size_t addr_length, unsigned *port);

/**
 * Get the address for the other side of the connection.
 */
void
dispatch_getpeername(dispatcher *d, int handle, char *addr, size_t addr_length, unsigned *port);

/**
 * Run a self-test of 
 */
int
dispatch_selftest(void);

#endif

