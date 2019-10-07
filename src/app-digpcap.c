#include "util-pcapfile.h"
#include "util-packet.h"
#include "dns-parse.h"
#include "dns-format.h"
#include <stdio.h>
#include <stdlib.h>


struct dns_t *_process_dns(const unsigned char *buf, size_t length, struct dns_t *dns)
{
    size_t i;
    int err;
    
    /* Decode DNS */
    dns = dns_parse(buf,
                    length,
                    0,
                    dns);
    if (dns == NULL || dns->error_code)
        return dns;
    
    /* Process all the records in the DNS packet */
    for (i=0; i<dns->answer_count + dns->nameserver_count + dns->additional_count; i++) {
        const struct dnsrrdata_t *rr = &dns->answers[i];
        char output[65536];

        /* FIXME: remove this */
        if (rr->rtype == DNS_T_OPT)
            continue; /* skip EDNS0 records */

        /* Format the resource record */
        err = dns_format_rdata(rr, output, sizeof(output));
        if (err)
            continue;

        /* Print in DIG format (i.e. zonefile format) */
        printf("%s%-23s %u\tIN\t%-7s %s\n",
            (rr->section == 0) ? ";" : "",
             rr->name,
             rr->ttl,
             dns_name_from_rrtype(rr->rtype), output);
    }
    
    return dns;
}

void _process_file(const char *filename)
{
    struct pcapfile_ctx_t *ctx;
    int linktype = 0;
    unsigned char *buf;
    unsigned sizeof_buf = 128 * 1024;
    struct dns_t *recycle = NULL;
    size_t frame_number = 0;
    
    /* Allocate a large buffer */
    buf = malloc(sizeof_buf);
    if (buf == NULL) {
        fprintf(stderr, "[-] out-of-memory\n");
        exit(1);
    }
    
    ctx = pcapfile_openread(filename, &linktype);
    if (ctx == NULL) {
        fprintf(stderr, "[-] error: %s\n", filename);
        return;
    }
    fprintf(stderr, "[+] %s (%s)\n", filename, pcapfile_datalink_name(linktype));
    
    /*
     * Process all the packets read from the file
     */
    for (;;) {
        unsigned time_secs;
        unsigned time_usecs;
        unsigned original_length;
        unsigned captured_length;
        int err;
        struct packetdecode_t decode;
        
        /* Read the next packet */
        err = pcapfile_readframe(ctx, &time_secs, &time_usecs, &original_length, &captured_length, buf, sizeof_buf);
        if (err)
            break;
        frame_number++;
        
        /* Decode the packet headers */
        err = packet_decode(buf, captured_length, linktype, &decode);
        if (err)
            continue;
        
        /* Make sure this a UDP */
        if (decode.ip_protocol == 17 && decode.port_src == 53) {
            recycle = _process_dns(buf + decode.app_offset, decode.app_length, recycle);
        }
        
        if (decode.ip_protocol == 6 && decode.port_src == 53) {
            /* FIXME: add TCP stream processing here */
        }
    }
    
    dns_parse_free(recycle);
    pcapfile_close(ctx);
}


int main(int argc, char *argv[])
{
    int i;
    
    if (argc <= 1) {
        fprintf(stderr, "[-] no files specified\n");
        return 1;
    }
    
    for (i=1; i<argc; i++) {
        _process_file(argv[i]);
    }
    
    return 0;
}
