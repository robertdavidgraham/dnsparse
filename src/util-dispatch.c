#include "util-dispatch.h"
#include "util-timeouts.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include <unistd.h>

//#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <sys/resource.h>

enum {
    My_None,
    My_Waiting,
    My_Connecting,
    My_Listening,
    My_Closing,
    My_Established,
};

struct my_connection
{
    struct my_connection *_next;
    
    /* What kind of event record this is, such as My_Listening or My_Connecting */
    int connection_type;
    
    /* The externally visible handle to this structure, which will
     * be the index into the d->conns array */
    int external_handle;
    
    /* The internal handle to the pollfd list */
    size_t pollfd_index;

    /* The callback the user registered that will be called when
     * events happen. */
    dispatch_callback cb;
    
    /* The opaque (to us) data that the user registered to be returned
     * to them on every callback */
    void *cbdata;

    struct sockaddr_storage sa;
    socklen_t sa_addrlen;
    
    struct {
        char *data;
        size_t length;
    } buffered;
    
    struct TimeoutEntry timeout;
};


struct dispatcher
{
    struct pollfd *pollist;
    int *listx;
    size_t pollcount;
    size_t max;

    struct my_connection **connections;
    size_t connection_count;
    
    /* The head of free connection records*/
    struct my_connection *connections_free;
    
    /* If errors occured during 'dispatch', then we add the connection to
     * this list, so that after dispatching is done, we can go back and close
     * all the events */
    struct my_connection *connections_closing;

    /* The max number of connections as determined by system limits,
     * after which point connection attempts will fail. */
    size_t max_limit;
    
    struct Timeouts *to;
    
    /* The numbero of timeouts we are waiting on */
    size_t timeout_count;
};


void
dispatch_getsockname(dispatcher *d, int handle, char *addr, size_t addr_length, unsigned *port)
{
    struct my_connection *c;
    int fd;
    struct sockaddr_storage sa;
    socklen_t sa_addrlen = sizeof(sa);
    int err;
    char portsz[64];
    
    /* Make sure the external handle is valid */
    if (handle < 0 || d->connection_count <= handle) {
        fprintf(stderr, "[-] getsockname(-1) programming error\n");
        goto fail;
    }
    
    /* Get the connection record */
    c = d->connections[handle];
    
    /* Make sure the socket is valid */
    if (c->pollfd_index >= d->pollcount) {
        fprintf(stderr, "[-] getsockname(-1) programming error\n");
        goto fail;
    }
    fd = d->pollist[c->pollfd_index].fd;
    if (fd == -1) {
        fprintf(stderr, "[-] getsockname(-1) on closed socket\n");
        goto fail;
    }
    
    /* Attempt to get the name from the operating system */
    err = getsockname(fd, (struct sockaddr *)&sa, &sa_addrlen);
    if (err) {
        fprintf(stderr, "[-] getsockname(): %s\n", strerror(errno));
        goto fail;
    }
    
    /* Format the address into a string */
    err = getnameinfo(  (struct sockaddr *)&sa, sa_addrlen,
                        addr, (socklen_t)addr_length,
                        portsz, sizeof(portsz),
                        NI_NUMERICHOST | NI_NUMERICSERV);
    if (err) {
        fprintf(stderr, "[-] getnameinfo(): %s\n", gai_strerror(err));
        goto fail;
    }
    if (port)
        *port = atoi(portsz);
    return;
    
fail:
    snprintf(addr, addr_length, "(err)");
    if (port)
        *port = (unsigned)-1;
}

void
dispatch_getpeername(dispatcher *d, int handle, char *addr, size_t addr_length, unsigned *port)
{
    struct my_connection *c;
    int fd;
    struct sockaddr_storage sa;
    socklen_t sa_addrlen = sizeof(sa);
    int err;
    char portsz[64];
    
    /* Make sure the external handle is valid */
    if (handle < 0 || d->connection_count <= handle) {
        fprintf(stderr, "[-] getsockname(-1) programming error\n");
        goto fail;
    }
    
    /* Get the connection record */
    c = d->connections[handle];
    
    /* Make sure the socket is valid */
    if (c->pollfd_index >= d->pollcount) {
        fprintf(stderr, "[-] getsockname(-1) programming error\n");
        goto fail;
    }
    fd = d->pollist[c->pollfd_index].fd;
    if (fd == -1) {
        fprintf(stderr, "[-] getsockname(-1) on closed socket\n");
        goto fail;
    }
    
    /* Attempt to get the name from the operating system */
    err = getpeername(fd, (struct sockaddr *)&sa, &sa_addrlen);
    if (err) {
        if (errno == ENOTCONN && c->sa_addrlen) {
            memcpy(&sa, &c->sa, c->sa_addrlen);
            sa_addrlen = c->sa_addrlen;
        } else {
            fprintf(stderr, "[-] getpeername(): %s\n", strerror(errno));
            goto fail;
        }
    }
    
    /* Format the address into a string */
    err = getnameinfo(  (struct sockaddr *)&sa, sa_addrlen,
                        addr, (socklen_t)addr_length,
                        portsz, sizeof(portsz),
                        NI_NUMERICHOST | NI_NUMERICSERV);
    if (err) {
        fprintf(stderr, "[-] getnameinfo(): %s\n", gai_strerror(err));
        goto fail;
    }
    if (port)
        *port = atoi(portsz);
    return;
    
fail:
    snprintf(addr, addr_length, "(err)");
    if (port)
        *port = (unsigned)-1;
}

static void
_dispatch_event(dispatcher *d, struct my_connection *c, int event_type, ...)
{
    union {
        struct {
            int error_code;
        } error;
        struct {
            const void *buf;
            size_t length;
        } read;
        struct {
            struct sockaddr *sa;
            size_t sa_length;
            int fd;
        } accept;
    } event_data;
    struct dispatchevent e = {0};
    va_list marker;
    
    va_start(marker, event_type);
    
    e.type = event_type;
    
    if (c->pollfd_index < d->pollcount)
        e.fd = d->pollist[c->pollfd_index].fd;
    
    switch (event_type) {
        case DISPATCH_ACCEPTED:
            event_data.accept.fd = va_arg(marker, int);
            event_data.accept.sa = va_arg(marker, struct sockaddr *);
            event_data.accept.sa_length = va_arg(marker, size_t);
            e.accept = (void*)&event_data.accept;
            c->connection_type = My_Established;
            c->cb(d, c->external_handle, &e, c->cbdata);
            break;
            
        case DISPATCH_RECEIVED:
            e.fd = d->pollist[c->pollfd_index].fd;
            e.read = (void*)&event_data.read;
            event_data.read.buf = va_arg(marker, const unsigned char *);
            event_data.read.length = va_arg(marker, size_t);
            c->connection_type = My_Established;
            c->cb(d, c->external_handle, &e, c->cbdata);
            break;
            
        case DISPATCH_ERROR:
            event_data.error.error_code = va_arg(marker, int);
            e.error = (void*)&event_data.error;
            c->connection_type = My_None;
            c->cb(d, c->external_handle, &e, c->cbdata);
            break;
            
        case DISPATCH_WAIT_EXPIRED:
            c->connection_type = My_None;
            c->cb(d, c->external_handle, &e, c->cbdata);
            break;

        case DISPATCH_CONNECTED:
        case DISPATCH_CLOSED:
        case DISPATCH_SENT:
        case DISPATCH_SEND_AVAILABLE:
        case DISPATCH_ADOPTED:
        case DISPATCH_LISTENING:
        case DISPATCH_CONNECTING:
            c->cb(d, c->external_handle, &e, c->cbdata);
            break;

        default:
            fprintf(stderr, "[-] unknown event type\n");
            break;
    }
    va_end(marker);
    
}

/**
 * Marks a connection as "closed". Does not actually close it yet, but marks for
 * being closed a little bit later. While processing the results from a poll(),
 * connections are marked closed, and then only after that loop is done
 * will they actually be closed and cleaned up.
 */
static void
_mark_closed(dispatcher *d, struct my_connection *c)
{
    c->connection_type = My_Closing;
    c->_next = d->connections_closing;
    d->connections_closing = c;
}

int
dispatch_close(dispatcher *d, int external_handle)
{
    struct my_connection *c;
    
    /* Verify input parameters */
    if (d == 0)
        return -1;
    if (external_handle < 0 || d->connection_count < external_handle)
        return -1;
    
    c = d->connections[external_handle];
    _mark_closed(d, c);
    return 0;
}

struct dispatcher *
dispatch_create(void)
{
    struct dispatcher *d;

    /* Create a blank subsystem */
    d = calloc(1, sizeof(*d));
    if (d == NULL)
        abort();
    
    d->to = timeouts_create(time(0), 0);

    return d;
}



int is_decimal(const char *str)
{
    size_t i;
    for (i=0; str[i]; i++) {
        if (!isdigit(str[i]))
            return 0;
    }
    return 1;
}

int index_of(const char *str, char c)
{
    int i;
    for (i=0; str[i]; i++) {
        if (str[i] == c)
            return i;
    }
    return -1;
}

int rindex_of(const char *str, char c)
{
    int result = -1;
    int i;
    for (i=0; str[i]; i++) {
        if (str[i] == c)
            result = i;
    }
    return result;
}

/**
 * Split a URL-type address into 'hostname' and 'port' parts
 * localhost:80 -> "localhost" and "80"
 * [::1]:1024 -> "::1" and "1024"
 */
void split_address(const char *name, char **r_addr, char **r_port)
{
    char *addr = NULL;
    size_t addrlen;
    char *port = NULL;
    size_t portlen;
    size_t namelen = strlen(name);

    if (is_decimal(name)) {
        addr = NULL;
        port = strdup(name);
    } else if (index_of(name, ':') && index_of(name, ':') == rindex_of(name, ':')) {
        addrlen = index_of(name, ':');;
        portlen = namelen - addrlen - 1;
        addr = malloc(addrlen + 1);
        memcpy(addr, name, addrlen + 1);
        addr[addrlen] = '\0';
        port = malloc(portlen + 1);
        memcpy(port, name + addrlen + 1, portlen + 1);
        port[portlen] = '\0';
    } else if (name[0] == '[' && strchr(name+1, ']')) {
        addrlen = index_of(name, ']') - 1;
        addr = malloc(addrlen + 1);
        memcpy(addr, name + 1, addrlen + 1);
        addr[addrlen] = '\0';
        if (rindex_of(name, ':') > addrlen) {
            portlen = namelen - rindex_of(name, ':') - 1;
            port = malloc(portlen + 1);
            memcpy(port, name + rindex_of(name, ':') + 1, portlen + 1);
            port[portlen] = '\0';
        } else
            port = NULL;
    } else {
        addr = strdup(name);
        port = NULL;
    }

    *r_addr = addr;
    *r_port = port;
}

static struct my_connection *
dispatch_new(struct dispatcher *d, dispatch_callback cb, void *cbdata, int type)
{
    struct my_connection *c;
    
    /* Allocate a "connection" record.
     * This either reuses old memory (from a freed list), or it allcoates
     * new memory.
     */
    if (d->connections_free) {
        c = d->connections_free;
        d->connections_free = c->_next;
    } else {
        c = malloc(sizeof(*c));
        memset(c, 0xa3, sizeof(*c));
        c->external_handle = (int)d->connection_count;
        memset(&c->timeout, 0, sizeof(c->timeout));
        
        /* Append to list of connections */
        d->connection_count += 1;
        d->connections = realloc(d->connections, d->connection_count * sizeof(*d->connections));
        d->connections[c->external_handle] = c;
        
    }
    assert(c->timeout.next == 0);
    c->_next = 0;
    c->connection_type = type;
    c->buffered.length = 0;
    c->cb = cb;
    c->cbdata = cbdata;
    return c;
}

static struct my_connection *
dispatcher_add(struct dispatcher *d, int fd, struct sockaddr *sa, socklen_t sa_addrlen, dispatch_callback cb, void *cbdata, int type)
{
    struct my_connection *c;
    
    c = dispatch_new(d, cb, cbdata, type);
    c->sa_addrlen = sa_addrlen;
    memcpy(&c->sa, sa, sa_addrlen);
    
    /* Allocate a "pollfd" record. This has to be in a non-sparse memory,
     * so we are going to just use the last free entry on the end of the list
     * if available, or expand the size of the list if not. */
    if (d->pollcount + 1 >= d->max) {
        d->pollist = realloc(d->pollist, (d->pollcount + 1) * sizeof(*d->pollist));
        if (d->pollist == NULL)
            abort();
        d->listx = realloc(d->listx, (d->pollcount + 1) * sizeof(*d->listx));
        if (d->listx == NULL)
            abort();
    }
        
    /* add to the poll() list, set for reading */
    c->pollfd_index = d->pollcount;
    d->listx[d->pollcount] = c->external_handle;
    d->pollist[d->pollcount].fd = fd;
    d->pollist[d->pollcount].events = POLLIN; /* every entry is always POLLIN */
    d->pollist[d->pollcount].revents = 0;
    d->pollcount += 1;
    return c;
}

int
dispatch_adopt(dispatcher *d, dispatch_callback cb, void *cbdata, int fd, struct sockaddr *sa, size_t sa_length)
{
    struct my_connection *c;
    
    c = dispatcher_add(d, fd, sa, (socklen_t)sa_length, cb, cbdata, My_Established);
    
    /* Tell the callback that the connection was adopted. This is largely redundant,
     * as the progrmamer can easily do anything before calling 'dispatch_adopt()'
     * that they could do in response to this event. However, it's often more
     * convenient to put this processing here in the callback rather than
     * elsewhere. */
    _dispatch_event(d, c, DISPATCH_ADOPTED);
    
    return c->external_handle;
}

void
dispatcher_remove_at(struct dispatcher *d, size_t pollfd_index)
{
    size_t end;
    struct my_connection *c;
    
    /* Get the connection entry */
    c = d->connections[d->listx[pollfd_index]];
    
    /* Call the callback for this, telling it that it's about to be destroyed */
    _dispatch_event(d, c, DISPATCH_CLOSED);
    
    /* close the socket if it's still open */
    if (d->pollist[pollfd_index].fd > 0) {
        close(d->pollist[pollfd_index].fd);
        d->pollist[pollfd_index].fd = -1;
    }

    /* For efficiency, move the last entry at the end of the 'pollfd' list
     * to this spot in the list, so that the list stays compact instead
     * of becoming sparse. */
    end = d->pollcount - 1;
    if (end > pollfd_index) {
        memcpy(&d->pollist[pollfd_index], &d->pollist[end], sizeof(d->pollist[0]));
        memcpy(&d->listx[pollfd_index], &d->listx[end], sizeof(d->listx[0]));
        d->connections[d->listx[pollfd_index]]->pollfd_index = pollfd_index;
    }
    d->pollcount--;
    
    /* put this "connection" record on the free list, so that the next
     * time we need one, we can just reuse this one */
    c->_next = d->connections_free;
    d->connections_free = c;
}

void dispatch_destroy(struct dispatcher *d)
{
    while (d->pollcount)
        dispatcher_remove_at(d, d->pollcount-1);

    free(d->pollist);
    free(d->listx);
    while (d->connection_count) {
        d->connection_count--;
        free(d->connections[d->connection_count]);
    }
    free(d->connections);
}


/**
 * Parse a string containing an address (like 8.8.8.8 or 2610:a1:1018::5)
 * into an internal "addrinfo" structure.
 */
static struct addrinfo *
_parse_address(const char *addr, unsigned port, int is_server)
{
    char portsz[64];
    struct addrinfo hints = {0};
    struct addrinfo *ai = 0;
    int err;
    
    /* Convert the integer into a string, because wants this
     * as a string. */
    snprintf(portsz, sizeof(portsz), "%u", port);
    
    /* Create a hints structure that will allow us to get an
     * address suitable for connection with either IPv4 or IPv6.
     * No DNS lookups will happen here, only parsing of an IPv4
     * or IPv6 address specifed as a string into a sockaddr struct */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    if (is_server)
        hints.ai_flags |= AI_PASSIVE;
    
    /* Do the conversion */
    err = getaddrinfo(addr, portsz, &hints, &ai);
    if (err) {
        fprintf(stderr, "[-] getaddrinfo(): %s\n", gai_strerror(err));
        return NULL;
    }
    assert(ai != NULL);
    return ai;
}

static int
_set_nonblocking(int fd)
{
#if defined(FIONBIO)
    {
        int yes = 1;
        int err;
        
        err = ioctl(fd, FIONBIO, (char *)&yes);
        if (err) {
            fprintf(stderr, "[-] ioctl(FIONBIO): %s\n", strerror(errno));
            return -1;
        }
    }
#elif defined(O_NONBLOCK) && defined(F_SETFL)
    {
        int flag;
        flag = fcntl(fd, F_GETFL, 0);
        flag |= O_NONBLOCK;
        fcntl(fd, F_SETFL,  flag);
    }
#else
    fprintf(stderr, "[-] non-blocking not set\n");
#endif
    return 0;
}

int
dispatch_wait(dispatcher *d, dispatch_callback cb, void *cbdata, uint64_t nanoseconds)
{
    struct my_connection *c;
    struct timespec ts;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += nanoseconds/(1000ULL*1000ULL*1000ULL);
    ts.tv_nsec += nanoseconds % (1000ULL*1000ULL*1000ULL);
    
    c = dispatch_new(d, cb, cbdata, My_Waiting);
    
    timeouts_add(d->to, &c->timeout, offsetof(struct my_connection, timeout), ts.tv_sec, ts.tv_nsec);
    d->timeout_count++;
    
    return c->external_handle;
}

int
dispatch_connect(dispatcher *d, dispatch_callback cb, void *cbdata, const char *addr, unsigned port, unsigned protocol)
{
    int fd = -1;
    int err;
    struct addrinfo *ai = NULL;
    struct my_connection *c = NULL;
    int error_code = 0;

    assert(protocol == 6);
    assert(port < 65536);
    
    /* Convert the address string and port number into sockets structure */
    ai = _parse_address(addr, port, 0);
    if (ai == NULL) {
        error_code = DISPATCH_ERR_GETADDRINFO;
        goto fail;
    }

    /* Create a socket */
    fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd == -1) {
        error_code = DISPATCH_ERR_SOCKET;
        fprintf(stderr, "[-] socket(): %d: %s\n", errno, strerror(errno));
        switch (errno) {
            case EMFILE:
                fprintf(stderr, "[-] files=%d, use 'ulimit -n %d' to raise\n", (int)d->pollcount, (int)d->max);;
                break;
        }
        goto fail;
    }

    /* Make it non-blocking, so that 'connect()' returns immediately
     * instead of blocking. We don't need this for other functions
     * like recv() or send(), because we always test the socket for
     * readiness instead. */
    err = _set_nonblocking(fd);
    if (err) {
        error_code = DISPATCH_ERR_NONBLOCKING;
        goto fail;
    }
    
    /* Add to our poll list */
    c = dispatcher_add(d, fd, (struct sockaddr *)ai->ai_addr, ai->ai_addrlen, cb, cbdata, My_Connecting);
    
    /* 
     * Initiate the TCP connection process.
     */
    err = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (err && (errno == EWOULDBLOCK || errno == EINPROGRESS)) {
        /* EXPECTED result. This isn't an error, but simply telling us that
         * the connection is in progress. We'll need to poll() to see when
         * the connection completes */
        d->pollist[c->pollfd_index].events = POLLOUT;

        /* At this point, though, the socket should be in a state where we
         * can grab the the local IP address and port that the system chose
         * to make the connection from */
        _dispatch_event(d, c, DISPATCH_CONNECTING);
    } else if (err == 0) {
        /* This is unexpected/abnormal, but happens sometimes when connecting
         * to localhost, because it doesn't need to wait for packets from the
         * network, because it's all internal to the kernel. */
        d->pollist[c->pollfd_index].events = 0;
        _dispatch_event(d, c, DISPATCH_CONNECTING);
        c->connection_type = My_None;
        _dispatch_event(d, c, DISPATCH_CONNECTED);
    } else {
        
        /* This shouldn't happen. If there is a network problem such that we
         * cannot connect, then the fault should show when we poll for the
         * connection later. No error should happen at this point, unless there
         * is some sort of system error, like out-of-memory */
        fprintf(stderr, "[-] connect([%s]:%u): %d: %s\n",
            addr,
            port,
            errno,
            strerror(errno));
        _mark_closed(d, c);
        goto fail;
    }

    /* Return the index in our array as a handle that can be used
     * by the caller */
    return c->external_handle; /* success */

fail:
    if (fd > 0)
        close(fd);
    freeaddrinfo(ai);
    _dispatch_event(d, c, DISPATCH_ERROR, error_code);
    _dispatch_event(d, c, DISPATCH_CLOSED);
    return -1; /* failure */
}

int
dispatch_listen(dispatcher *d, dispatch_callback cb, void *cbdata, const char *addr, unsigned port, unsigned protocol)
{
    int fd = -1;
    int err;
    struct addrinfo *ai = NULL;
    struct my_connection *c = NULL;
    int error_code = 0;

    assert(protocol == 6 || protocol == 17);
    assert(port < 65536);
    
    
    /* Convert the address string and port number into sockets structure */
    ai = _parse_address(addr, port, 1);
    if (ai == NULL) {
        error_code = DISPATCH_ERR_GETADDRINFO;
        goto fail;
    }

    /* Create a socket */
    fd = socket(ai->ai_family, (protocol==6)?SOCK_STREAM:SOCK_DGRAM, 0);
    if (fd == -1) {
        error_code = DISPATCH_ERR_SOCKET;
        fprintf(stderr, "[-] socket(): %d: %s\n", errno, strerror(errno));
        switch (errno) {
            case EMFILE:
                fprintf(stderr, "[-] files=%d, use 'ulimit -n %d' to raise\n", (int)d->pollcount, (int)d->max);;
                break;
        }
        goto fail;
    }
    
    /* Bind the desired port */
    err = bind(fd, ai->ai_addr, ai->ai_addrlen);
    if (err) {
        error_code = DISPATCH_ERR_SOCKET;
        fprintf(stderr, "[-] bind([%s]:%u: %s\n", addr, port, strerror(errno));
        goto fail;
    }

    /* Make it non-blocking */
    err = _set_nonblocking(fd);
    if (err) {
        error_code = DISPATCH_ERR_NONBLOCKING;
        goto fail;
    }

    /* Make it listening */
    err = listen(fd, 5);
    if (err) {
        error_code = DISPATCH_ERR_LISTEN;
        fprintf(stderr, "[-] bind([%s]:%u: %s\n", addr, port, strerror(errno));
        goto fail;
    }
    
    /* Add to our poll list */
    c = dispatcher_add(d, fd, (struct sockaddr *)ai->ai_addr, ai->ai_addrlen, cb, cbdata, My_Listening);
    if (c == NULL) {
        error_code = DISPATCH_ERR_UNKNOWN;
        goto fail;
    }

    /* Tell the callback that we are successfully listening */
    _dispatch_event(d, c, DISPATCH_LISTENING);

    /* Return the index in our array as a handle that can be used
     * by the caller */
    return c->external_handle; /* success */

fail:
    if (fd > 0)
        close(fd);
    freeaddrinfo(ai);
    _dispatch_event(d, c, DISPATCH_ERROR, error_code);
    _dispatch_event(d, c, DISPATCH_CLOSED);
    return -1; /* failure */
}

/**
 * Go through the list of pending closes and do the closing. These were connections
 * added by '_dispatch_close()', either during the execution of 'dispatch_dispatch()'
 * or at some other time, such as when the user attempts to send on a bad socket.
 * This is called at the start and end of every call to 'dispatch_dispatch()'.
 */
static void
_dispatch_close_list(struct dispatcher *d)
{
    while (d->connections_closing) {
        struct my_connection *c;
        
        /* remove from the linked list */
        c = d->connections_closing;
        d->connections_closing = c->_next;
        c->_next = 0;
        
        /* remove pollfd list, which will also call 'close()' on the
         * socket. */
        dispatcher_remove_at(d, c->pollfd_index);
    }
}

int
_dispatch_timeouts(struct dispatcher *d)
{
    struct timespec ts;
    
    /* Get the current timestamp. Anything set to expire before this
     * time will be processed */
    clock_gettime(CLOCK_REALTIME, &ts);
    
    /* Continue processing timestamps until there are none older than
     * the current timestamp */
    for (;;) {
        struct my_connection *c;
    
        /* Get the next expired item */
        c = timeouts_remove_older(d->to, ts.tv_sec, ts.tv_nsec);
        if (c == NULL)
            break;
        
        /* Notify the callback of the expiration and close out the event */
        _dispatch_event(d, c, DISPATCH_WAIT_EXPIRED);
        _dispatch_event(d, c, DISPATCH_CLOSED);

        /* Free the connection object */
        c->_next = d->connections_free;
        d->connections_free = c;
        d->timeout_count--;
    }
    
    return 0;
}

static int
dispatch_poll_hangup(struct dispatcher *d, struct my_connection *c)
{
    /* other side hungup (i.e. sent FIN, closed socket) */
    switch (c->connection_type) {
        case My_Waiting:
            fprintf(stderr, "[-] impossible\n");
            _mark_closed(d, c);
            break;
        case My_Connecting:
            fprintf(stderr, "[-] connection refused\n");
            _mark_closed(d, c);
            break;
        case My_Listening:
            fprintf(stderr, "[-] impossible\n");
            _mark_closed(d, c);
            break;
        case My_Established:
            fprintf(stderr, "[+] connection closed gracefully\n");
            _mark_closed(d, c);
            break;
        default:
            fprintf(stderr, "[-] impossible\n");
            _mark_closed(d, c);
            break;
    }
    return 0;
}

static int
dispatch_poll_error(struct dispatcher *d, struct my_connection *c, int fd)
{
    int err;
    int opt;
    socklen_t opt_len;
    
    /* Retrieve the error code associated with the socket */
    opt_len = sizeof(opt);
    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
    if (err) {
        /* should never happen! */
        fprintf(stderr, "[-] getsockopt(): %s\n", strerror(errno));
    }

    switch (c->connection_type) {
        case My_Established:
            fprintf(stderr, "[-] poll error\n");
            _mark_closed(d, c);
            break;
        default:
            fprintf(stderr, "[-] impossible\n");
            _mark_closed(d, c);
            break;
    }
    return 0;

}

static int
dispatch_poll_recv(struct dispatcher *d, struct my_connection *c, int fd)
{
    char buf[4096];
    ssize_t length;
        
    /* Data is ready to receive */
    length = recv(fd, buf, sizeof(buf), 0);
    if (length == 0 ) {
        /* Shouldn't be possible, should've got POLLHUP instead */
        fprintf(stderr, "[-] RECV(): %s\n", "CONNECTION CLOSED");
        _mark_closed(d, c);
    } else if (length < 0) {
        fprintf(stderr, "[-] RECV(): %s\n", strerror(errno));
        _mark_closed(d, c);
    } else {
        _dispatch_event(d, c, DISPATCH_RECEIVED, buf, length);
    }
    
    return 0;
}


static int
dispatch_poll_accept(struct dispatcher *d, struct my_connection *c, int fd)
{
    int fd2;
    struct sockaddr_storage sa;
    socklen_t sa_length = sizeof(sa);
    
    /* Do the actual accept on the socket */
    fd2 = accept(fd, (struct sockaddr *)&sa, &sa_length);
    if (fd2 == -1) {
        fprintf(stderr, "[-] accept(): error: %s\n",
                strerror(errno));
        return -1;
    }
    
    /* Send the information to the callback */
    _dispatch_event(d, c, DISPATCH_ACCEPTED, fd2, &sa, sa_length);
    return 0;
}

static int
dispatch_poll_send(struct dispatcher *d, struct my_connection *c, int fd)
{
    if (c->buffered.length) {
        ssize_t bytes_sent;
        
        bytes_sent = send(fd, c->buffered.data, c->buffered.length, 0);
        if (bytes_sent < 0) {
            /* might've reset connection between poll() and send() */
            fprintf(stderr, "[-] SEND(): %s\n", strerror(errno));
            _mark_closed(d, c);
        } else if (bytes_sent < c->buffered.length) {
            size_t offset = bytes_sent;
            size_t diff = c->buffered.length - bytes_sent;
            memmove(c->buffered.data, c->buffered.data + offset, diff);
            c->buffered.length -= diff;
        } else {
            c->buffered.length = 0;
            c->connection_type = My_None;
            _dispatch_event(d, c, DISPATCH_SENT);
        }
    } else {
        c->connection_type = My_None;
        _dispatch_event(d, c, DISPATCH_SEND_AVAILABLE);
    }

    return 0;
}



int
dispatch_dispatch(struct dispatcher *d, uint64_t nanoseconds)
{
    int timeout = (int)(nanoseconds / (1000 * 1000));
    size_t i;
    int count;

    /* Dispatch timeouts */
    _dispatch_timeouts(d);
    
    /* First do any necessary cleanup of connections that need
     * to be closed. */
    _dispatch_close_list(d);
    
    if (d->pollcount == 0)
        goto good;
    
    /* wait for incoming event on any connection */
    count = poll(d->pollist, (int)d->pollcount, timeout);
    if (count < 0) {
        switch (errno) {
            case EINTR:
                /* a normal condition tha means a signal happened that
                 * caused the dispatcher to exit early. There's some more
                 * complicated things we could do to handle this, but we
                 * are just going to do the simplest thing and return
                 * back to the caller, in case they want to immediately
                 * do something to handle the signal. */
                goto good;
            default:
                goto fail;
        }
    }
    if (count == 0)
        goto good;

    /* Process all the sockets  */
    for (i=0; i<d->pollcount; i++) {
        struct my_connection *c = d->connections[d->listx[i]];
        struct pollfd *p = &d->pollist[i];
        
        /* Only process sockets that have events waiting */
        if (p->revents == 0)
            continue;
        
        if ((p->revents & POLLERR) != 0) {
            /* An error has occurred on this TCP connection, like a RST */
            dispatch_poll_error(d, c, p->fd);
            
            /* Close the connection if an error occurs */
            _mark_closed(d, c);
            
            /* this overrides any other event that might be pending */
            continue;
        }
        
        if ((p->revents & POLLHUP) != 0) {
            /* The TCP connection has been closed*/
            dispatch_poll_hangup(d, c);
            
            _mark_closed(d, c);
            
            /* Don't process any more events on this socket */
            continue;
        }
        
        
        if ((p->revents & POLLIN) != 0) {
            switch (c->connection_type) {
                case My_Connecting:
                    c->connection_type = My_None;
                    _dispatch_event(d, c, DISPATCH_CONNECTED);
                    break;
                case My_Listening:
                    dispatch_poll_accept(d, c, p->fd);
                    break;
                case My_Established:
                    dispatch_poll_recv(d, c, p->fd);
                    break;
                default:
                    fprintf(stderr, "[-] unknown poll condition\n");
            }
        }
        
        if ((p->revents & POLLOUT) != 0) {
            p->events &= ~POLLOUT;
            switch (c->connection_type) {
                case My_Connecting:
                    c->connection_type = My_Established;
                    p->events |= POLLIN;
                    _dispatch_event(d, c, DISPATCH_CONNECTED);
                    break;
                case My_Listening:
                    p->events |= POLLOUT;
                    dispatch_poll_accept(d, c, p->fd);
                    break;
                case My_Established:
                    dispatch_poll_send(d, c, p->fd);
                    if (c->buffered.length)
                        p->events |= POLLOUT;
                    break;
                default:
                    fprintf(stderr, "[-] unknown poll condition\n");
            }
        }
    }

    /* Lastly, do the actual closing of things that were marked for closing
     * above. */
    _dispatch_close_list(d);

good:
    /* This is the number of things still left to do */
    return (int)d->pollcount + (int)d->timeout_count;

fail:
    /* If we reach this code, it's because 'poll()' returned an error.
     * This should never happen. But if it does happen, the likely cause
     * is that we've run out of resources, such as memory or socket handles.*/
    fprintf(stderr, "[-] poll(): %s\n", strerror(errno));
    switch (errno) {
        case EINVAL:
            fprintf(stderr, "max file descriptor reached? nfds=%d\n", (int)d->pollcount);
            {
                struct rlimit rl;
                getrlimit(RLIMIT_NOFILE, &rl);
                fprintf(stderr, "rlimit cur=%u max=%u\n", (unsigned)rl.rlim_cur, (unsigned)rl.rlim_max);
            }
            break;
    }
    return 0;
}


int
dispatch_send_buffered(dispatcher *d, int external_handle, const void *buf, size_t length, size_t *sent)
{
    struct my_connection *c = d->connections[external_handle];
    struct pollfd *p = &d->pollist[c->pollfd_index];
    ssize_t bytes_sent;
    
    /* If there is already buffered data pending, then don't do anything
     * but append to the end of our buffer. */
    if (c->buffered.length) {
        c->buffered.data = realloc(c->buffered.data, c->buffered.length + length);
        memcpy(c->buffered.data + c->buffered.length,
               buf,
               length);
        c->buffered.length += length;
        if (sent)
            *sent = 0;
        p->events |= POLLOUT;
        return 0;
    }
    
    /* Attempt to send data */
    bytes_sent = send(p->fd, buf, length, 0);
    
    /* Do different things, depending on the results */
    if (bytes_sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        /* Expected result. We are using a non-blocking socket, so
         * one expected result is that this will return such a
         * result. */
        *sent = 0;
        return 0;
    } else if (bytes_sent < 0) {
        /* Unexpected result. We need to simply close the connection and
         * return an error */
        _mark_closed(d, c);
        return -1;
    } else if (bytes_sent == length) {
        /* We successfully sent all the data requested. Therefore, we don't
         * need to buffer anything. We just return this indication. */
        if (sent)
            *sent = (size_t)bytes_sent;
        _dispatch_event(d, c, DISPATCH_SENT);
        return 0;
    } else {
        /* We were unable to sned all the data requested. Therefore, we are going
         * to buffer the data to send at a later point in time. */
        size_t diff = length - bytes_sent;
        size_t offset = bytes_sent;
        
        c->buffered.data = realloc(c->buffered.data, diff);
        if (c->buffered.data == NULL) {
            /* out-of-memory
             * We are are going to attempt to recover by closing the connection */
            _mark_closed(d, c);
            return -1;
        }
        
        memcpy(c->buffered.data, buf + offset, diff);
        p->events |= POLLOUT;
        return 0;
    }

}

struct selftest_globals {
    unsigned is_wait_succeeded:1;
    unsigned error_count;
};

/**
 * A callback structure to hold the results from the various self-tests.
 */
struct selftest_data {
    struct {
        char buf[16];
        size_t count;
    } receiving;
    char hostaddr[64];
    unsigned hostport;
    char peeraddr[64];
    unsigned peerport;
};

void _selftest_wait_cb(dispatcher *d, int handle, dpevent *e, void *cbdata)
{
    struct selftest_data *data = (struct selftest_data *)cbdata;
    
    switch (e->type) {
        case DISPATCH_WAIT_EXPIRED:
            data->is_wait_succeeded = 1;
            break;
        case DISPATCH_CLOSED:
            free(data);
            break;
        default:
            data->error_count++;
            printf("unknown event type = %u\n", e->type);
            break;
    }
    return;
}

void _selftest_server_cb(dispatcher *d, int handle, dpevent *e, void *cbdata)
{
    ta *data = (struct selftest_data *)cbdata;
    
    dispatch_getsockname(d, handle, hostaddr, sizeof(hostaddr), &hostport);
    dispatch_getpeername(d, handle, peeraddr, sizeof(peeraddr), &peerport);

    switch (e->type) {
        case DISPATCH_ADOPTED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: server connected\n",
                    peeraddr, peerport,
                    hostaddr, hostport
                    );
            break;
        case DISPATCH_RECEIVED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: server received: %.*s\n",
                    peeraddr, peerport,
                    hostaddr, hostport,
                    (unsigned)e->read->length, e->read->buf
                    );
            dispatch_send_buffered(d, handle, "HELLO-2\n", 7, 0);
            break;
        case DISPATCH_SENT:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: server sent\n",
                    peeraddr, peerport,
                    hostaddr, hostport
                    );
            break;
        case DISPATCH_CLOSED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: server closed\n",
                    peeraddr, peerport,
                    hostaddr, hostport
                    );
            break;
        default:
            printf("server event = %u\n", e->type);
    }
}

void _selftest_client_cb(dispatcher *d, int handle, dpevent *e, void *cbdata)
{
    char hostaddr[64];
    unsigned hostport;
    char peeraddr[64];
    unsigned peerport;
    dispatch_getsockname(d, handle, hostaddr, sizeof(hostaddr), &hostport);
    dispatch_getpeername(d, handle, peeraddr, sizeof(peeraddr), &peerport);

    switch (e->type) {
        case DISPATCH_CONNECTING:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: client connecting\n",
                    hostaddr, hostport,
                    peeraddr, peerport);
            break;
        case DISPATCH_CONNECTED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: client connected\n",
                    hostaddr, hostport,
                    peeraddr, peerport);
            dispatch_send_buffered(d, handle, "HELLO-1\n", 7, 0);
            break;
        case DISPATCH_SENT:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: client sent\n",
                    hostaddr, hostport,
                    peeraddr, peerport);
            break;
        case DISPATCH_RECEIVED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: client received: %.*s\n",
                    hostaddr, hostport,
                    peeraddr, peerport,
                    (unsigned)e->read->length, e->read->buf
                    );
            dispatch_close(d, handle);
            break;

        case DISPATCH_CLOSED:
            fprintf(stderr, "[+] [%s]:%u --> [%s]:%u: client closed\n",
                    hostaddr, hostport,
                    peeraddr, peerport
                    );
            break;
        
        default:
            printf("client event = %u\n", e->type);
    }
}

void _selftest_accept_cb(dispatcher *d, int handle, dpevent *e, void *cbdata)
{
    char hostaddr[64];
    unsigned hostport;
    
    switch (e->type) {
        case DISPATCH_LISTENING:
            dispatch_getsockname(d, handle, hostaddr, sizeof(hostaddr), &hostport);
            fprintf(stderr, "[+] [%s]:%u: server listening\n", hostaddr, hostport);
            break;
        case DISPATCH_ACCEPTED:
            dispatch_adopt(d, _selftest_server_cb, 0, e->accept->fd, e->accept->sa, e->accept->sa_length);
            break;
        default:
            printf("unknown event type = %u\n", e->type);
            break;
    }
    return;
}

int
dispatch_selftest(void)
{
    struct dispatcher *d;
    int x;
    char hostaddr[64] = "";
    unsigned hostport = 0;
    struct selftest_data data = {0};
    
    /* Create a dispatch subsystem */
    d = dispatch_create();
    if (d == NULL)
        return 1; /* failure */
    
    /* Create an object that we'll wait upon */
    x = dispatch_wait(d, _selftest_wait_cb, &data, 100*1000*1000);
    if (x < 0)
        goto fail;
    
    /* Create a listening server socket */
    x = dispatch_listen(d, _selftest_accept_cb, &data, "127.0.0.1", 0, 6);
    if (x < 0)
        goto fail;
    dispatch_getsockname(d, x, hostaddr, sizeof(hostaddr), &hostport);

    x = dispatch_connect(d, _selftest_client_cb, &data, hostaddr, hostport, 6);
    if (x < 0)
        goto fail;

    /* continue dispatching events until there are none left */
    while (dispatch_dispatch(d, TEN_MILLISECONDS))
        ;
    
    dispatch_destroy(d);
    
    /* Make sure conditions were successfully reached during the test */
    if (!data.is_wait_succeeded) {
        fprintf(stderr, "[-] dispatch_wait() failed\n");
        return 1;
    }
    return 0; /* success */
    
fail:
    dispatch_destroy(d);
    return 1; /* fail */
}
