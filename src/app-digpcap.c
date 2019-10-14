#include "util-pcapfile.h"
#include "util-packet.h"
#include "util-tcpreasm.h"
#include "dns-parse.h"
#include "dns-format.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>


/**
 * Handle a TCP packet, either UDP packet read from the stream, or a reassembled TCP payload.
 */
static struct dns_t *
_process_dns(const unsigned char *buf, size_t length, struct dns_t *dns)
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
        printf("%s%-23s %-7u IN\t%-7s %s\n",
            (rr->section == 0) ? ";" : "",
             rr->name,
             rr->ttl,
             dns_name_from_rrtype(rr->rtype), output);
    }
    
    return dns;
}

/**
 * On TCP, DNS request/responses are prefixed by a two-byte length field
 */
struct dnstcp
{
    int state;
    unsigned short pdu_length;
};

/**
 * Read in the packet-capture file and process all the records.
 */
static void
_process_file(const char *filename)
{
    struct pcapfile_ctx_t *ctx;
    int linktype = 0;
    struct dns_t *recycle = NULL;
    size_t frame_number = 0;
    struct tcpreasm_ctx_t *tcpreasm = 0;
    time_t secs;
    long usecs;
    
    
    /* Open the packet capture file  */
    ctx = pcapfile_openread(filename, &linktype, &secs, &usecs);
    if (ctx == NULL) {
        fprintf(stderr, "[-] error: %s\n", filename);
        return;
    } else {
        time_t now = secs;
        struct tm *tm = gmtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(stderr, "[+] %s (%s) %s \n", filename, pcapfile_datalink_name(linktype), timestamp);
    }
    
    /* Create a subsystem for reassembling TCP streams */
    tcpreasm = tcpreasm_create(sizeof(struct dnstcp), 0, secs, 60);

    
    /*
     * Process all the packets read from the file
     */
    for (;;) {
        time_t time_secs;
        long time_usecs;
        size_t original_length;
        size_t captured_length;
        const unsigned char *buf;
        int err;
        struct packetdecode_t decode;
        
        /* Read the next packet */
        err = pcapfile_readframe(ctx, &time_secs, &time_usecs, &original_length, &captured_length, &buf);
        if (err)
            break;
        frame_number++;
        
        /* Decode the packet headers */
        err = packet_decode(buf, captured_length, linktype, &decode);
        if (err)
            continue;
        
        /* If not DNS, then ignore this packet */
        if (decode.port_src != 53)
            continue;
        
        /* If UDP, then decode this payload*/
        if (decode.ip_protocol == 17) {
            recycle = _process_dns(buf + decode.app_offset, decode.app_length, recycle);
        }
        
        /* If TCP, then reassemble the stream into a packet */
        if (decode.ip_protocol == 6) {
            struct tcpreasm_tuple_t ins;
            
            ins = tcpreasm_packet(tcpreasm, /* reassembler */
                                         buf + decode.ip_offset, /* IP+TCP+payload */
                                         decode.ip_length,
                                         time_secs,             /* timestamp */
                                         time_usecs * 1000);
            if (ins.available) {
                struct dnstcp *d = (struct dnstcp *)ins.userdata;
                if (d->state == 0) {
                    if (ins.available >= 2) {
                        unsigned char foo[2];
                        size_t count;
                        d->state = 1;
                        count = tcpreasm_read(&ins, foo, 2);
                        d->pdu_length = foo[0]<<8 | foo[1];
                    }
                }
                if (d->state == 1) {
                    if (d->pdu_length <= ins.available) {
                        unsigned char tmp[65536];
                        size_t count;
                        count = tcpreasm_read(&ins, tmp, d->pdu_length);
                        if (count == d->pdu_length) {
                            recycle = _process_dns(tmp, count, recycle);
                            d->state = 0;
                        }
                    }
                }

            }

            /* Process any needed timeouts */
            tcpreasm_timeouts(tcpreasm, time_secs, time_usecs * 1000);
            
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
