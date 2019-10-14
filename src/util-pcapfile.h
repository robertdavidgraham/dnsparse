/* Copyright (c) 2007 by Robert David Graham, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef UTIL_PCAPFILE_H
#define UTIL_PCAPFILE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <time.h>

/**
 * This opaque structure represents the context for reading/writing the
 * files. It is created with a call tp pcapfile_openread() or pcapfile_openwrite(),
 * and then cleaned up wit ha cal to pcapfile_close().
 */
struct pcapfile_ctx_t;

/**
 * The "data link" tells use how to start decoding the first bytes in a packet. For
 * example, if Etherent, then the first 6 bytes of every packet will be the destination
 * Ethernet address. These values are defined externally and redefined here.
 */
enum {
    LINKTYPE_NULL = 0,
    
    /* Ethernet, by far the most common datalink type */
    LINKTYPE_ETHERNET = 1,
    
    /* No datalink, starts with IP header */
    LINKTYPE_RAW = 101,
    
    /* WiFi, without "radiotap" header. */
    LINKTYPE_IEEE802_11 = 105,
    
    /* WiFi, with "Prism" header instead of "radiotap" */
    LINKTYPE_PRISM_HEADER = 119,
    
    /* WiFi, with "radiotap" header. */
    LINKTYPE_IEEE802_11_RADIO = 127
};


/**
 * Opens a file for reading. A context handle is returned which will be
 * supplied to pcapfile_readframe(). In addition, the linktype is returned
 * that tells how to start parsing the first bytes of a frame.
 */
struct pcapfile_ctx_t *
pcapfile_openread(const char *filename, int *linktype, time_t *secs, long *usecs);

/**
 * Writes a packet to a file created with pcapfile_openwrite().
 * @return
 *  0 on success.
 *  Any other value on failure.
 */
int pcapfile_writeframe(
	struct pcapfile_ctx_t *ctx,
	const void *buffer, 
	size_t buffer_size,
	unsigned original_length, 
	unsigned time_sec, 
	unsigned time_usec
	);

struct pcapfile_ctx_t *pcapfile_openwrite(const char *capfilename, int linktype);
struct pcapfile_ctx_t *pcapfile_openappend(const char *capfilename, int linktype);

unsigned pcapfile_percentdone(struct pcapfile_ctx_t *ctx);

const char *pcapfile_datalink_name(int linktype);

/**
 * Set a "maximum" size for a file. When the current file fills up with data,
 * it will close that file and open a new one, then continue to write
 * from that point on in the new file.
 */
void pcapfile_set_max(struct pcapfile_ctx_t *capfile, unsigned max_megabytes, unsigned max_files);

/**
 * Read a single frame from the file.
 * @param ctx
 *      A handle to a file returned from pcapfile_openread().
 * @param buf
 *      Receives a pointer to the buffer holding the packet.
 * @return
 *  0 on success, or any other value on failure.
 */
int pcapfile_readframe(
	struct pcapfile_ctx_t *ctx,
	time_t *secs,
	long *usecs,
	size_t *original_length,
	size_t *captured_length,
	const unsigned char **buf
	);


void pcapfile_close(struct pcapfile_ctx_t *handle);

#ifdef __cplusplus
}
#endif
#endif /*__PCAPFILE_H*/
