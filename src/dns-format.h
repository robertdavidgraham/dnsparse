/*
    dns-format

    Formats DNS RR records into canonical format.
*/
#ifndef DNS_FORMAT
#define DNS_FORMAT
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>

/* Defined in "dns-parse.h". */
struct dnsrrdata_t;


/**
 * Format the rdata in the same way that you'd need as input into a zone file.
 * If there is an error, either parsing the resource record, or if there is
 * not enough output buffer space, then "( err )" is copied to the output
 * buffer instead.
 *
 * @param rr
 *      One of the resource records from the DNS packet. Presumably, we'll
 *      enumerate each record in the response one-by-one.
 * @param dst
 *      Where we are writing the output.
 * @param dst_length
 *      The number of bytes we can write in the output.
 */
int
dns_format_rdata(const struct dnsrrdata_t *rr, char *dst, size_t dst_length);

/**
 * Format the data in generic RR format. This is the format to use for
 * unknown RR types, such as when a server software is too old to support
 * newer types.
 */
int
dns_format_rdata_generic(const unsigned char *src, size_t length, char *dst, size_t dst_length);


#ifdef __cplusplus
}
#endif
#endif
