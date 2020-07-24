/*

 */
#include "util-dispatch.h"
#include "dns-parse.h"
#include "dns-format.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <netdb.h>

static void _callback(dispatcher *d, int handle, struct dispatchevent *event, void *cbdata);

enum {
    Disconnected,
    Connecting,
    SentQuery,
    Connected,
};

/**
 * Holds information about a particular DNS server.
 */
struct my_resolver {
    const char *addr;
    unsigned port;
    size_t connection_count;
    size_t query_count;
};

/**
 * Holds the callback data for a single connection to a server.
 */
struct my_callback_data {
    /* The dispatcher handle for this connection, which we will
     * use for sending/receiving data */
    int handle;
    
    struct my_callback_data *next;
    
    struct my_resolver *server;
    unsigned state;
    struct dig_run *run;
    
    /* The length of the response given in the first 2-bytes
     * on TCP */
    size_t pdu_length;
    
    /* Buffers the response data on TCP in case it doesn't
     * all arrive in one packet */
    unsigned char *buf;
    
    /* The current length of partial received data */
    size_t buf_length;
    
    char query_name[256];
    int query_rrtype;
    int query_rrclass;
};

/**
 * Holds the configuration parsed from the command-line.
 */
struct configuration {
    /* The DNS RR-type like A, AAAA, SOA, MX, CNAME, and so on */
    int rrtype;
    
    /* the DNS RR-class, like IN or CHAOS */
    int rrclass;
    
    /* The filename where we are reading names from */
    char *filename;
    
    /* Whether we should have terse/brief output instead of long output */
    unsigned is_short:1;
    
    /** Maximum number of TCP connections to each
     * server. */
    size_t max_connections_per_server;
};


struct dig_run {
    struct my_resolver *resolvers;
    size_t resolver_count;
    
    size_t outstanding_count;
    
    struct my_callback_data *available;
    
    struct dispatcher *dispatcher;
};

/**
 * Create several connection objects per server.
 */
void _digrun_expand_resolvers(struct dig_run *run, size_t connections_per_node)
{
    size_t i;
    
    for (i=0; i<connections_per_node; i++) {
        size_t j;
        for (j=0; j<run->resolver_count; j++) {
            struct my_callback_data *cbdata;
            
            cbdata = calloc(1, sizeof(*cbdata));
            cbdata->run = run;
            cbdata->server = &run->resolvers[i];
            cbdata->next = run->available;
            run->available = cbdata;
        }
    }
}

static int
_digrun_has_opening(const struct dig_run *run)
{
    return run->available != NULL;
}

static size_t
_format_name(unsigned char *buf, size_t original_offset, size_t buf_max, const char *name)
{
    size_t name_offset = 0;
    size_t name_max = strlen(name);
    size_t buf_offset = original_offset;
    
    for (;;) {
        size_t len;
        
        /* Find length of next label */
        for (len=0; name_offset + len < name_max && name[name_offset + len] != '.'; len++)
            ;

        /* Stop once we reach the end of the name */
        if (len == 0)
            break;
        
        /* Labels have a max length of 63 bytes */
        if (len > 63)
            goto fail;
        
        /* Copy over the label */
        if (buf_offset + len + 1 > buf_max)
            goto fail;
        buf[buf_offset++] = len;
        memcpy(buf + buf_offset, name + name_offset, len);
        buf_offset += len;
        name_offset += len;
        name_offset += (name[name_offset] == '.');
    }
    
    
    /* Add the final terminating label */
    if (buf_offset + 1 > buf_max)
        goto fail;
    buf[buf_offset++] = 0x00;
    
    /* Return the length of the name, which will be at least one
     * byte for any successful result, or zero bytes for failure */
    return buf_offset - original_offset;
    
fail:
    if (buf_max)
        buf[0] = 0x00;
    return 0;
}

static void
_send_query(dispatcher *d, struct my_callback_data *cbdata)
{
    unsigned char buf[4096];
    size_t offset = 14;
    static const unsigned char header[] =
        "\x00\x00" /* TCP length */
        "\x00\x00" /* XID */
    "\x01\x00" /* flags = query */
    "\x00\x01" /* qdcount = 1 */
    "\x00\x00"
    "\x00\x00"
    "\x00\x01"; /* answer count = 1 */
    size_t len;
    
    memcpy(buf, header, 14);
    
    /* append the query record */
    offset = 14;
    len = _format_name(buf, offset, sizeof(buf), cbdata->query_name);
    if (len == 0)
        goto fail;
    offset += len;
    if (offset + 4 > sizeof(buf))
        goto fail;
    else {
        buf[offset++] = (unsigned char)(cbdata->query_rrtype >> 8);
        buf[offset++] = (unsigned char)(cbdata->query_rrtype >> 0);
        buf[offset++] = (unsigned char)(cbdata->query_rrclass >> 8);
        buf[offset++] = (unsigned char)(cbdata->query_rrclass >> 0);
    }
    
    /* append the EDNS0 record */
    if (offset + 11 > sizeof(buf))
        goto fail;
    else {
        memcpy(buf + offset, "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00", 11);
        offset += 11;
    }
    
    dispatch_send_buffered(d, cbdata->handle, buf, offset, 0);
    cbdata->state = SentQuery;
    
fail:
    return;
}

static int
_digrun_resolve(struct dig_run *run, const char *name, int rrtype, int rrclass)
{
    struct my_callback_data *cbdata;
    assert(run->available);
    
    /* Get the head of the free list */
    cbdata = run->available;
    run->available = cbdata->next;
    
    /* Copy over the query name */
    strlcpy(cbdata->query_name, name, sizeof(cbdata->query_name));
    cbdata->query_rrtype = rrtype;
    cbdata->query_rrclass = rrclass;
    
    /* If already connected, send the query */
    if (cbdata->state == Connected) {
        _send_query(run->dispatcher, cbdata);
    } else {
        cbdata->handle = dispatch_connect(run->dispatcher, _callback, cbdata, cbdata->server->addr, cbdata->server->port, 6);
        cbdata->state = Connecting;
    }
    
    return 0;
}

static struct dig_run *
_digrun_create(size_t max_servers)
{
    struct dig_run *run;
    
    run = calloc(1, sizeof(*run));
    if (run == NULL)
        abort();
    
    /* create an instance of our polling object */
    run->dispatcher = dispatch_create();
    
    return run;
}

/**
 * Adds the named DNS resolver to our list of resolvers that we can query.
 * @param resolver_name
 *      The name of the resolver. This can be an IP address like "1.1.1.1" or "2606:4700:4700::1111",
 *      or it can be a name like "one.one.one.one", in which case we'll do a DNS lookup on the name.
 *      In this case, all the returned results will be added to our list, so calling this function with a
 *      single name may add multiple servers to our list.
 * @param port
 *      This should be 53.
 */
int
_digrun_add_resolver(struct dig_run *run, const char *resolver_name, unsigned port)
{
    struct addrinfo *list;
    struct addrinfo *ai;
    int err;
    char portsz[64];
    
    snprintf(portsz, sizeof(portsz), "%u", port);
    
    /* Resolve the name of the resolver into one or more IP addresses. If the
     * name is just an IP address, then it'll just parse that IP address. If
     * it's an actual name, then we'll do a DNS lookup on it. */
    err = getaddrinfo(resolver_name, portsz, NULL, &list);
    if (err) {
        fprintf(stderr, "[-] getaddrinfo(%s): %s\n", resolver_name, gai_strerror(err));
        return -1;
    }
    
    /* Add all the results to our list of servers. If this is a DNS lookup, then
     * multiple results may be returned. */
    for (ai=list; ai; ai = ai->ai_next) {
        char addr[256];
        unsigned addrport;
        size_t i;
        struct my_resolver *r;
        
        /* Convert the IP address back into a string. Our internal standard form
         * is to represent IP addresses as human readable strings, so that we
         * have a common format that represents both IPv4 and IPv6 addresses. */
        err = getnameinfo(ai->ai_addr,
                          ai->ai_addrlen,
                          addr,
                          sizeof(addr),
                          portsz,
                          sizeof(portsz),
                          NI_NUMERICHOST|NI_NUMERICSERV);
        addrport = atoi(portsz);
        
        /* Ignore duplicate addresses. For a given address (and port), we only add
         * it once to our internal list, even if for some reason, multipel are given.
         * This is needed because on some platforms, getaddrinfo() returns the same
         * IP address multiple times for no reason I can figure out. */
        for (i=0; i<run->resolver_count; i++) {
            if (strcmp(addr, run->resolvers[i].addr) == 0 && run->resolvers[i].port == addrport)
                break;
        }
        if (i < run->resolver_count)
            continue;
        
        /* Append to our list */
        run->resolvers = realloc(run->resolvers, (run->resolver_count + 1) * sizeof(run->resolvers[0]));
        if (run->resolvers == NULL)
            abort();
        r = &run->resolvers[run->resolver_count++];
        memset(r, 0, sizeof(*r));
        r->addr = strdup(addr);
        r->port = addrport;
    }

    return 0;
}

/**
  * Some public resolvers.
 */
const char *
public_resolvers[] = {
    "one.one.one.one", /* 1.1.1.1 cloudflare */
    "odvr.nic.cz",
    "dns.digitale-gesellschaft.ch",
    "dns1.dnscrypt.ca",
    "dns2.dnscrypt.ca",
    "public-dns-a.dns.sb",
    "public-dns-b.dns.sb",
    "resolver1.dns.watch",
    "resolver2.dns.watch",
    "80.80.80.80", /* Freenom */
    "80.80.81.81", /* Freenom */
    "dns.google.com", /* 8.8.8.8 */
    "156.154.70.5", /* Neustar */
    "156.154.71.5", /* Neustar */
    "2610:a1:1018::5", /* Neustar */
    "2610:a1:1019::5", /* Neustar */
    "dns-nosec.quad9.net",
    "anycast.censurfridns.dk",
    "unicast.censurfridns.dk",
    "recpubns1.nstld.net",
    "recpubns2.nstld.net",
    "dns.yandex.ru",
    "secondary.dns.yandex.ru",
    0
};

const unsigned char dnsquery[] =
"\x00\x1C"
"\xc9\xff\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x01\x00" \
"\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";



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

static int
_process_response(struct my_callback_data *x)
{
    struct dns_t *dns;
    
    dns = dns_parse(x->buf, x->buf_length, 0, 0);
    if (dns == NULL || dns->error_code) {
        fprintf(stderr, "[-] err parsing DNS response\n");
        goto fail;
    }
    
    _print_long_results(dns, 1, x->buf_length);
    
    
fail:
    dns_parse_free(dns);
    return 0;
}

static int
_process_stream(struct my_callback_data *x, const unsigned char *buf, size_t length)
{
    size_t offset = 0;
    size_t count;
    
    while (offset < length)
    switch (x->state) {
        case 0:
            x->pdu_length = buf[offset++] << 8;
            x->state++;
            break;
        case 1:
            x->pdu_length |= buf[offset++];
            x->state++;
            break;
        case 2:
            count = x->pdu_length - x->buf_length;
            if (count > length - offset)
                count = length - offset;
            x->buf = realloc(x->buf, x->buf_length + count);
            if (x->buf == NULL)
                abort();
            memcpy(x->buf + x->buf_length, buf + offset, count);
            x->buf_length += count;
            offset += count;
            if (x->buf_length >= x->pdu_length) {
                _process_response(x);
                x->state = 0;
            } else
                return 1;
            break;
    }
    
    return 0;
}

static void
_callback(dispatcher *d, int handle, struct dispatchevent *event, void *cbdata)
{
    struct my_callback_data *data = (struct my_callback_data *)cbdata;

    switch (data->state) {
        case Disconnected:
            /* Called by myself rather than the dispatcher, so this parameter
             * should be NULL */
            data->state = Connecting;
            dispatch_connect(d, _callback, data, data->server->addr, data->server->port, 6);
            break;
        case Connecting:
            switch (event->type) {
                case DISPATCH_ERROR:
                    fprintf(stderr, "[-] [%s]:%u: connect error\n", data->server->addr, data->server->port);
                    break;
                case DISPATCH_CLOSED:
                    data->state = Disconnected;
                    data->handle = dispatch_wait(d, _callback, data, 10ULL * 1000ULL * 1000ULL * 1000ULL);
                    break;
                case DISPATCH_CONNECTED:
                    dispatch_send_buffered(d, handle, dnsquery, sizeof(dnsquery)-1, 0);
                    data->state = SentQuery;
                    break;
                default:
                    fprintf(stderr, "[-] unknown event\n");
                    break;
            }
            break;
        case SentQuery:
            switch (event->type) {
                case DISPATCH_ERROR:
                    fprintf(stderr, "[-] [%s]:%u: receive error\n", data->server->addr, data->server->port);
                    break;
                case DISPATCH_CLOSED:
                    data->state = Disconnected;
                    data->handle = dispatch_wait(d, _callback, data, 10ULL * 1000ULL * 1000ULL * 1000ULL);
                    break;
                case DISPATCH_RECEIVED:
                {
                    int x;
                    
                    x = _process_stream(cbdata, event->read->buf, event->read->length);
                }
                    break;
                case DISPATCH_SENT:
                    data->state = SentQuery;
                    break;
                default:
                    fprintf(stderr, "[-] unknown event\n");
                    break;
            }
            break;
        default:
            break;
            
    }
}

static struct configuration
_parse_commandline(int argc, char *argv[])
{
    struct configuration options = {0};
    int i;
    for (i=1; i<argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'f':
                    if (argv[i][2]) {
                        options.filename = strdup(argv[i] + 2);
                    } else if (i + 1 < argc) {
                        options.filename = strdup(argv[++i]);
                    } else {
                        fprintf(stderr, "[-] missing parameter\n");
                        exit(1);
                    }
                    break;
                default:
                    fprintf(stderr, "[-] uknown option: -%c\n", argv[i][1]);
                    exit(1);
            }
        } else if (dns_rrtype_from_name(argv[i]) != -1) {
            if (options.rrtype) {
                fprintf(stderr, "[-] only one record type can be specified\n");
                fprintf(stderr, "[-] the value '%s' was already specified\n", dns_name_from_rrtype(options.rrtype));
                fprintf(stderr, "[-] the second value '%s' is rejected\n", argv[i]);
                exit(1);
            }
            options.rrtype = dns_rrtype_from_name(argv[i]);
        }
    }
    
    return options;
}

int main(int argc, char *argv[])
{
    struct dispatcher *d = NULL;
    struct configuration options;
    FILE *fp;
    struct dig_run *run;
    size_t i;
    
    dispatch_selftest();
    
    /* Ignore the send() problem */
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    /*
     * Parse the configuration
     */
    options = _parse_commandline(argc, argv);
    if (options.filename == NULL) {
        fprintf(stderr, "[-] needs filename on command-line, use '-f <filename>'\n");
        exit(1);
    }
    fp = fopen(options.filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[-] %s: %s\n", options.filename, strerror(errno));
        exit(1);
    }
    if (options.rrtype == 0)
        options.rrtype = 1; /* A record default */
    if (options.rrclass == 0)
        options.rrclass = 1; /* IN clas by default */
    
    /* Create the main program object */
    run = _digrun_create(10);
    for (i=0; public_resolvers[i]; i++) {
        _digrun_add_resolver(run, public_resolvers[i], 53);
    }
    _digrun_expand_resolvers(run, 10);
    
    

    
    for (;;) {
        while (fp && _digrun_has_opening(run)) {
            char line[1024];
            char *p;
            unsigned char tmp[256];
            size_t tmplen;
            
            /* Get the next line of input */
            p = fgets(line, sizeof(line), fp);
            if (p == NULL) {
                fclose(fp);
                fp = NULL;
                break;
            }
            
            /* Trim whitespace */
            while (*line && isspace(*line))
                memmove(line, line+1, strlen(line));
            while (*line && isspace(line[strlen(line)-1]))
                line[strlen(line)-1] = '\0';
            
            /* Skip blank lines and comments */
            if (*line == '\0' || ispunct(*line))
                continue;
            
            /* Skip invalid names */
            tmplen = _format_name(tmp, 0, sizeof(tmp), line);
            if (tmplen == 0)
                continue;

            _digrun_resolve(run, line, options.rrtype, options.rrclass);
        
        }
        dispatch_dispatch(d, 100*1000*1000);
    }
    

    

    dispatch_destroy(d);
    return 0;
}
