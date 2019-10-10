/*
    Demonstrates using the 'resolv' library to do DNS lookups for records
    other than IP addresses. This is commonly used to lookup MX and SPF
    records for emails, for example.
*/
#include "dns-parse.h"
#include "dns-format.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <resolv.h>
#include <netdb.h>

struct dig_options {
    unsigned rtype;
    char *filename;
    unsigned is_short:1;
    char **hostnames;
    size_t hostname_count;
};

/**
 * Return the name of the opcode, so that we can print it
 * @param opcode
 *      One of the opcodes defined in RFCs, such as 0 for QUERY.
 * @return the name corresponding to the value
 */
const char *
_opcode_name(unsigned opcode)
{
    static char buf[64];
    switch (opcode) {
        case 0: return "QUERY"; /* it's always this */
        case 1: return "IQUERY";
        case 2: return "STATUS";
        case 4: return "NOTIFY";
        case 5: return "UPDATE";
        default:
            snprintf(buf, sizeof(buf), "%u", opcode);
            return buf;
    }
}

/**
 * Return the name of the response-code, so that we can print it
 * @param rcode
 *      One of the response codes defined in RFCs, such as 0 for NOERROR.
 *      This can be an extended rcode from EDNS0.
 * @return the name corresponding to the value
 */
const char *
_rcode_name(unsigned rcode)
{
    static char buf[64];
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default:
            snprintf(buf, sizeof(buf), "%u", rcode);
            return buf;
    }
}

/**
 * Decode the DNS response, and print it out to the command in
 * the 'presentation' format (the format servers use to read in
 * records from a text file). This output is similar to the `dig`
 * program.
 */
static int
_print_long_results(const struct dns_t *dns, unsigned ellapsed_milliseconds, size_t length)
{
    static const size_t sizeof_output = 1024 * 1024;
    char *output = malloc(sizeof_output);
    size_t i;
    int is_printed_header;
    
    printf(";; Got answer:\n");

    /* Print the DIG-style header information */
    printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n",
           _opcode_name(dns->flags.opcode),
           _rcode_name(dns->flags.rcode),
           dns->flags.xid);
    /*
     15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   Rcode   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    */
    printf(";; flags:%s%s%s%s%s%s%s%s; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
           dns->flags.is_response?" qr":"",
           dns->flags.is_authoritative?" aa":"",
           dns->flags.is_truncated?" tc":"",
           dns->flags.is_recursion_desired?" rd":"",
           dns->flags.is_recursion_available?" ra":"",
           dns->flags.is_Z?" z":"",
           dns->flags.is_authentic?" ad":"",
           dns->flags.is_checking_disabled?" cd":"",
           (unsigned)dns->query_count,
           (unsigned)dns->answer_count,
           (unsigned)dns->nameserver_count,
           (unsigned)dns->additional_count
           );

    /* If EDNS0, print that information */
    if (dns->flags.edns0.offset) {
        printf(";; OPT PSEUDOSECTION:\n");
        printf("; EDNS: version: %u, flags:; udp: %u\n",
               dns->flags.edns0.version,
               dns->flags.edns0.udp_payload_size);
    }
    
    /* QUESTION */
    if (dns->query_count)
        printf(";; QUESTION SECTION:\n");
    for (i=0; i<dns->query_count; i++) {
        dnsrrdata_t *rr = &dns->queries[i];

        printf(";%-23s \t%s\t%-7s %s\n",
            rr->name,
            (rr->rclass==1)?"IN":"??",
            dns_name_from_rrtype(rr->rtype),
            "");
    }

    /* ANSWER */
    if (dns->answer_count)
        printf("\n;; ANSWER SECTION:\n");
    for (i=0; i<dns->answer_count; i++) {
        dnsrrdata_t *rr = &dns->answers[i];
        if (rr->rclass != 1)
            continue;
        dns_format_rdata(rr, output, sizeof_output);
        printf("%-23s %u\t%s\t%-7s %s\n",
                rr->name,
                rr->ttl,
                "IN",
                dns_name_from_rrtype(rr->rtype),
                output);

    }

    /* AUTHORITY */
    if (dns->nameserver_count)
        printf("\n;; AUTHORITY SECTION:\n");
    for (i=0; i<dns->nameserver_count; i++) {
        dnsrrdata_t *rr = &dns->nameservers[i];
        if (rr->rclass != 1)
            continue;
        dns_format_rdata(rr, output, sizeof_output);
        printf("%-23s %u\t%s\t%-7s %s\n",
            rr->name,
            rr->ttl,
            "IN",
            dns_name_from_rrtype(rr->rtype),
            output);
    }

    /* ADDITIONAL */
    is_printed_header = 0;
    for (i=0; i<dns->additional_count; i++) {
        dnsrrdata_t *rr = &dns->additional[i];
        if (rr->rclass != 1)
            continue;
        if (rr->rtype == 41)
            continue; /* skip EDNS0 */
        if (is_printed_header++ == 0)
            printf("\n;; ADITIONAL SECTION:\n");
        dns_format_rdata(rr, output, sizeof_output);
        printf("%-23s %u\t%s\t%-7s %s\n",
                rr->name,
                rr->ttl,
                "IN",
                dns_name_from_rrtype(rr->rtype),
                output);
    }

    printf("\n");
    printf(";; Query time: %u msec\n", ellapsed_milliseconds);
    printf(";; MSG SIZE  recvd: %u\n", (unsigned)length);
    return 0;
}


/**
 * Add a hostname to the list that we'll be looking up.
 */
static void
_hostname_add(struct dig_options *options, const char *hostname)
{
    options->hostnames = realloc(options->hostnames, sizeof(hostname) * (options->hostname_count + 1));
    options->hostnames[options->hostname_count] = strdup(hostname);
    options->hostname_count++;
}

static void
_hostnames_free(struct dig_options *options)
{
    size_t i;
    for (i=0; i<options->hostname_count; i++)
        free(options->hostnames[i]);
    free(options->hostnames);
}

/**
 * Parse the command-line arguments into flags for this program.
 * @param argc
 *      The same parameter as in main(), the total number of command-line parameters
 * @param argv
 *      The same as in main(), the list of command-line parameters, starting
 *      with the name of the program.
 * @return a structure containing parsed arguments
 */
static struct dig_options
_parse_commandline(int argc, char *argv[])
{
    struct dig_options options = {0};
    int i;
    for (i=1; i<argc; i++) {
        if (argv[i][0] == '-') {
        } else if (dns_rrtype_from_name(argv[i]) != -1) {
            if (options.rtype) {
                fprintf(stderr, "[-] only one record type can be specified\n");
                fprintf(stderr, "[-] the value '%s' was already specified\n", dns_name_from_rrtype(options.rtype));
                fprintf(stderr, "[-] the second value '%s' is rejected\n", argv[i]);
                exit(1);
            }
            options.rtype = dns_rrtype_from_name(argv[i]);
        } else {
            _hostname_add(&options, argv[i]);
        }
    }
    
    return options;
}

static void
_do_lookup(const struct dig_options *options, const char *hostname)
{
    unsigned char buf[65536];
    int result;
    struct dns_t *dns;
    int rtype;
    
    /* If no rtype specified, default to 1 for "A" records */
    if (options->rtype)
        rtype = options->rtype;
    else
        rtype = 1;


    /* Do the name resolution. This will block and take a long while */
    errno = 0;
    result = res_search(hostname, 1, rtype, buf, sizeof(buf));
    if (result < 0) {
        fprintf(stderr, "[-] res_search(): error: %s\n", hstrerror(h_errno));
        return;
    }

    /* Parse the DNS response */
    dns = dns_parse(buf, result, 0, 0);
    if (dns == NULL || dns->error_code != 0) {
        printf(";; failed to parse result\n");
        dns_parse_free(dns);
        return;
    }


    /* Now decode the result */
    _print_long_results(dns, 60, result);

    dns_parse_free(dns);
}

int main(int argc, char *argv[])
{
    struct dig_options options;
    size_t i;

    /* Initialize the built-in DNS resolver library */
    res_init();
    _res.options |= RES_USE_EDNS0;
    _res.options |= RES_USE_DNSSEC;

    /* Grab parameters from the command line */
    options = _parse_commandline(argc, argv);
    
    /* If long-mode, print program info */
    if (!options.is_short) {
        printf("\n; <<>> DiG ..not! <<>> %s", options.rtype?dns_name_from_rrtype(options.rtype):"");
        for (i=0; i<options.hostname_count; i++) {
            printf(" %s", options.hostnames[i]);
        }
        printf("\n");
        printf(";; global options: +cmd\n");
    }
    
    /* Do all the hostnames */
    for (i=0; i<options.hostname_count; i++) {
        _do_lookup(&options, options.hostnames[i]);
    }
    
    _hostnames_free(&options);
    return 0;
}

