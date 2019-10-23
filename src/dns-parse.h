/*
    parse-dns

    A simple utility for parsing DNS response packets. This takes
    a packet and returns parsed results.
 
*/
#ifndef PARSE_DNS
#define PARSE_DNS
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>


/**
 * DNS error codes in the flags.rcode field of the parsed response. These match
 * external definitions found in RFCs. Values below 16 are found in the original
 * DNS header, while larger values are constructed from the EDNS0 field.
 */
enum {
    DNS_R_NOERROR       = 0,
    DNS_R_FORMERR       = 1,  /* Format Error                     [RFC1035] */
    DNS_R_SERVFAIL      = 2,  /* Server Failure                   [RFC1035] */
    DNS_R_NXDOMAIN      = 3,  /* Non-Existent Domain              [RFC1035] */
    DNS_R_NOTIMP        = 4,  /* Not Implemented                  [RFC1035] */
    DNS_R_REFUSED       = 5,  /* Query Refused                    [RFC1035] */
    DNS_R_YXDOMAIN      = 6,  /* Name Exists when it should't     [RFC2136] */
    DNS_R_YXRRSET       = 7,  /* RR Set Exists when it should't   [RFC2136] */
    DNS_R_NXRRSET       = 8,  /* RR Set that should exist does't  [RFC2136] */
    DNS_R_NOTAUTH       = 9,  /* Not Authorized                   [RFC2845] */
    DNS_R_NOTZONE       = 10, /* Name not contained in zone       [RFC2136] */
    DNS_R_BADSIG        = 16, /* TSIG Signature Failure           [RFC2845] */
    DNS_R_BADKEY        = 17, /* Key not recognized               [RFC2845] */
    DNS_R_BADTIME       = 18, /* Signature out of time window     [RFC2845] */
    DNS_R_BADMODE       = 19, /* Bad TKEY Mode                    [RFC2930] */
    DNS_R_BADNAME       = 20, /* Duplicate key name               [RFC2930] */
    DNS_R_BADALG        = 21, /* Algorithm not supported          [RFC2930] */
    DNS_R_BADTRUNC      = 22, /* Bad Truncation                   [RFC4635] */
};

/**
 * The value of the flags.opcode field. These are externally defined in RFCs and
 * match the values found in the packet.
 */
enum {
    DNS_OP_QUERY        = 0,
    DNS_OP_IQUERY       = 1,
    DNS_OP_STATUS       = 2,
    DNS_OP_NOTIFY       = 4, /* NS_NOTIFY_OP */
    DNS_OP_UPDATE       = 5, /* NS_UPDATE_OP */
};

enum {
    DNS_T_A         = 1,
    DNS_T_NS        = 2,
    DNS_T_CNAME     = 5,
    DNS_T_SOA       = 6,
    DNS_T_PTR       = 12,
    DNS_T_HINFO     = 13,
    DNS_T_MX        = 15,
    DNS_T_TXT       = 16,
    DNS_T_RP        = 17,
    //DNS_T_SIG       = 24,
    //DNS_T_KEY       = 25,
    DNS_T_AAAA      = 28,
    DNS_T_SRV       = 33,
    DNS_T_NAPTR     = 35,
    DNS_T_CERT      = 37,
    DNS_T_OPT       = 41,
    DNS_T_DS        = 43,
    DNS_T_SSHFP     = 44,
    DNS_T_RRSIG     = 46,
    DNS_T_NSEC      = 47,
    DNS_T_DNSKEY    = 48,
    DNS_T_NSEC3     = 50,
    DNS_T_NSEC3PARAM = 51,
    DNS_T_TLSA      = 52,
    DNS_T_SPF       = 99,
    //DNS_T_AXFR      = 252,
    //DNS_T_ANY       = 255,
    DNS_T_CAA       = 257,
};

/**
 * This represents the header information in a DNS packet, mostly the flags
 * field.
 */
typedef struct dnsflags_t
{
    /* The response code, matching the values DNS_R_xxxx values defined
     * above. This is the external value extracted from the packet. Values
     * larger than 16 are reconstructed from the EDNS0 field */
    unsigned rcode;
    
    /* The opcode extracted from the packet, which for the purposes of
     * this module, should always DNS_OP_QUERY -- this a response toa
     * a query. */
    unsigned short opcode;
    
    /* The value of the transaction identifier field. This is meaningless
     * as far as we are concerned, just extracted from teh response
     * and reported here. */
    unsigned short xid;
    
    /* QR flag
     * 0 = query
     * 1 = response
     * For the purposes of this module, everything is a response, so
     * the value of this flag will always be 1. */
    unsigned is_response:1;
    
    /* AA - Authoritative Answer
     * Whether the data is from an authoritative nameserver */
    unsigned is_authoritative:1;
    
    /* TC - Truncated Response
     * A flag from the server when the response won't fit in UDP
     * packet, telling you that you need to repeat the query over
     * TCP. When using the resolv library function res_query(),
     * it'll repeat the request for you over TCP. In other words,
     * the resonse it gives you should never have this flag set. */
    unsigned is_truncated:1;
    
    /* RD - Recursion Desired flag */
    unsigned is_recursion_desired:1;
    
    /* RA - Recursion Available flag */
    unsigned is_recursion_available:1;
    
    /* Z - the unused/reserved flag that should always be zero */
    unsigned is_Z:1;
    
    /* AD - Authentic Data    [RFC4035][RFC6840][RFC Errata 4924] */
    unsigned is_authentic:1;
    
    /* CD - Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927] */
    unsigned is_checking_disabled:1;
    
    struct {
        /* The offset from the start of the packet where we'll
         * find the EDNS0 resource-record */
        size_t offset;
        
        /* The value of the [rdlength] field of the EDNS0 RR,
         * meaning the length of the contents. This is often
         * zero. */
        unsigned short rdlength;
        
        /* The UDP payload size advertised by EDNS0 */
        unsigned short udp_payload_size;
        
        /* The value of the extended rcode field. Programs
         * an ignore this, as this value will be folded into
         * the [rcode] field above */
        unsigned short extended_rcode;
        
        /* The value of the [version] advertised by ENDS0, which
         * should be zero. */
        unsigned char version;
        
        /* The value of the reserved portions of this field */
        unsigned short zero;
        
        /* A flag indicating whether DNSSEC features should be
         * enabled on reading/writing packets. */
        unsigned is_dnssec:1;
    } edns0;
} dnsflags_t;

/**
 * In a resource-record, this represents a binary buffer, such as a DNSKEY or a TXT
 * field. It typically represents raw binary data copied directly from the packet.
 */
typedef struct dnsrrbuf_t {
    const unsigned char *buf;
    size_t length;
} dnsrrbuf_t;

/**
 * A resource record contains a [name] for which the record applies,
 * and a [rtype] for the record. It also contains a [rclass] and [ttl].
 * Following this is a huge union that depends upon the [rtype] field
 * for identifying what it is.
 */
typedef struct dnsrrdata_t
{
    /* A nul-terminated string representing the name for this record.
     * This is a fully-qualified domain-name (FQDN) ending in a period.
     * If it's the root zone, then this is ".". A typical example of the value
     * for this field would be "www.google.com.". */
    const unsigned char *name;
    
    /* The [type] field in a resource-record, like A, MX, SOA, CNAME, and
     * so on. This is the descriminator for the big union down below.
     * This could be one of the enumerations above (DNS_T_xxxx), but the
     * value is that which was parsed from the packet, and may be unknown
     * to this program.
     */
    unsigned short rtype;
    
    /* The [class] field within resource-records. It's renamed [rclass] because the
     * word "class" is a keyword in some programming languages. The value should
     * always be '1', for the 'IN' class. Chaos 'CH', Hesiod, and other classes aren't
     * supported.
     */
    unsigned short rclass;
    
    /* The [ttl] field. This is just parsed from the packet and passed on through
     * without being examined.
     */
    unsigned int ttl;
    
    /* Which section (0=DNS_query, 1=DNS_answer, 2=DNS_nameserver, 3
     * 3=DNS_additional) that this record belongs in.
     */
    int section;
        
    /**
     * The offset from the start of the responsse payload where the [rdata] portion begins.
     * This is so that the programmer can do their own decoding of this field if they want.
     */
    size_t rdoffset;
    
    /**
     * The value of the [rdlength] field from the packet, used with [rdoffset] when the programmer
     * wants to look at the raw binary data of the packet.
     */
    size_t rdlength;
    
    /**
     * Set when this module understands the contents of this resource-record and has decoded
     * it as one of the union members below. If this flag is not set, then the programmer should
     * not use the unions below -- even if it looks like it should work. This guards against
     * a mismatch between this header file and a binary library. In other wrods, if the [rtype]
     * is 5, meaning CNAME, but if this flag isn't set, then the user of this library should not
     * attempt to read the CNAME union field. In such case, the programmer will have to
     * work with [rdoffset] and [rdlength] fields and decode the binary themselves.
     */
    unsigned is_rtype_known:1;

    /* This union is descriminated by the [rtype] field. It contains
     * a breakdown of all the records. */
    union {
        
        /* A (1) - IPv4 address - rfc1035 */
        struct {
            unsigned ipv4;
        } a;
            
        /* NS (2) - Name Server - rfc1035*/
        struct {
            const unsigned char *name;
        } ns;
            
        /* CNAME (5) - Cannonical Name - rfc1035*/
        struct {
            const unsigned char *name;
        } cname;
          
         /* SOA (6) - Start of Zone Authority - rfc1035 */
        struct {
            const unsigned char *mname;
            const unsigned char *rname;
            unsigned serial;
            unsigned refresh;
            unsigned retry;
            unsigned expire;
            unsigned minimum;
        } soa;
            
        /* PTR (12) - poitner (reverse) */
        struct {
            const unsigned char *name;
        } ptr;

        /* HINFO (13) - host info - rfc883 */
        struct {
            struct dnsrrbuf_t cpu;
            struct dnsrrbuf_t os;
        } hinfo;

        /* MX (15) - Mail Exchange - rfc974,rfc1035,rfc7505,rfc5321#section-5,rfc2181#section-10.3 */
        struct {
            const unsigned char *name;
            unsigned short priority;
        } mx;
        
        /* TXT (16) - text - rfc1035 */
        struct {
            size_t count;
            struct dnsrrbuf_t *array;
        } txt;
        
        /* RP (17) - responsible person - rfc1183 */
        struct {
            const unsigned char *mbox_dname;
            const unsigned char *txt_dname;
        } rp;
        
        /* AAAA (28) - IPv6 - rfc3596 */
        struct {
            unsigned char ipv6[16];
        } aaaa;
        
        /* SRV (33) - service */
        struct {
            unsigned short priority;
            unsigned short weight;
            unsigned short port;
            const unsigned char *name;
        } srv;

        /* NAPTR (35) - Naming Authority Pointer - rfc3403 */
        struct {
            unsigned short order;
            unsigned short preference;
            struct dnsrrbuf_t flags;
            struct dnsrrbuf_t service;
            struct dnsrrbuf_t regexp;
            const unsigned char *replacement;
        } naptr;

        /* RRSIG (46) - Resource Record Signature - rfc4034 */
        struct {
            const unsigned char *name;
            unsigned short type;
            unsigned char algorithm;
            unsigned char labels;
            unsigned ttl;
            unsigned expiration;
            unsigned inception;
            unsigned short keytag;
            const unsigned char *sig;
            size_t length;
        } rrsig;

        /* DNSKEY (48) - DNS key - rfc4034 */
        struct {
            unsigned short flags;
            unsigned char protocol;
            unsigned char algorithm;
            const unsigned char *publickey;
            size_t length;
        } dnskey;

        /* NSEC (50) */
        struct {
            const unsigned char *name;
            unsigned short *types;
            unsigned char types_count;
        } nsec;

        /* NSEC3PARAM (51) */
        struct {
            unsigned char algorithm;
            unsigned char flags;
            unsigned short iterations;
            size_t salt_length;
            const unsigned char *salt;
        } nsec3param;
            
        /* CAA (257) - Certification Authority Authorization - rfc6844 */
        struct {
            unsigned char flags;
            unsigned char taglength;
            char tag[257];
            const unsigned char *value;
            size_t length;
        } caa;
        

        struct {
            const unsigned char *buf;
            size_t length;
        } unknown;
    };
} dnsrrdata_t;

enum {
    DNS_success = 0,
    DNS_out_of_memory = 1, /* out of memory */
    DNS_input_overflow = 2, /* attempted to read too much data */
    DNS_input_bad = 3, /* well formatted, but bad value */
    DNS_programming_error = 4, /* programming error */
};

typedef struct dns_t {
    /* An internal parameter representing the current amount
     * used by this result, which may be less than the max size.
     * Used when recyling the same memory for multiple DNS responses.
     * This is guranteed to be the first parameter of the structure
     * for use by the custom memory allocators. */
    size_t _current_size;

    /* An internal parameter representing the total amount of
     * memory used by this result. Used when recycling the
     * same memory for multiple DNS responses. */
    size_t _max_size;
    
    /* Contains info for the memory allocator */
    struct {
        unsigned is_prealloc:1;
        unsigned is_postalloc:1;
        void *arena;
        void *(*myrealloc)(void*,size_t,void*);
    } mem;
    
    /* If an error happens, then this contains the error code,
     * such as DNS_input_overflow or DNS_input_bad. Otherwise,
     * this is 0 for success. Not that in practice, if there's
     * an out-of-memory error, then this won't have that value,
     * because the entire structure will be freed. That error
     * is signaled by the function returning NULL instead of
     * this structure */
    int error_code;
    
    /* If there was an error parsing resource-records, this
     * indicates which resource-record was in error. */
    unsigned error_index;

    /* This contains the flags from the DNS header. */
    struct dnsflags_t flags;

    /* This reflects the number of elements in each section.
     * There should only ever be a single query, and the
     * user of this module is probably only interested in the
     * answers. */
    size_t query_count;
    size_t answer_count;
    size_t nameserver_count;
    size_t additional_count;
    
    /* Pointers to the relevent sections. */
    dnsrrdata_t *queries;
    dnsrrdata_t *answers;
    dnsrrdata_t *nameservers;
    dnsrrdata_t *additional;
} dns_t;

/**
 * Parses a DNS response packet and returns an array of decoded records.
 * Callers will be particularly interested in the `answers`.
 * The memory returned must be freed with a matching call to `dns_parse_free()`.
 * However, the memory can be recycled by passing the returned result of
 * one call to subsequent call, which wipes out the previous contents
 * and replaces them with new contents.
 * @param buf
 *     The bytes of a DNS response packet, either raw from the network,
 *     or through such APIs as `res_search()` or `res_query()`.
 * @param length
 *     The number of bytes in the buffer pointed to by `buf`.
 * @param flags
 *      Flags of the form DNS_F_xxxx
 * @param recycled
 *     A previous result from this function, allowing the memory to be reused
 *     for the new request, for efficiency, to avoid expensive allocations.
 *     If the recycled memory is too small, it'll be automatically freed.
 */

struct dns_t *
dns_parse(const unsigned char *buf, size_t length, unsigned flags, struct dns_t *recycled);

/**
 * Allows the programmer to use a custom memory allocator. This shoudl be called
 * before calling dns_parse() to recreate an object that can be passed in as the
 * 'recylced' parameter.
 */
struct dns_t *
dns_parse_allocator(void *(*myrealloc)(void*,size_t,void*arena), void *arena, size_t padding);

/**
  * Frees the result from `dns_parse()`.
  * @param dns
  *     A result returned from dns_parse(). This can be NULL, in which case
  *     this function does nothing.
 */
void
dns_parse_free(struct dns_t *dns);

/**
 * Given a rr-type like "A" or "CNAME" or "MX", return the integer value 
 * corresponding to that name. Both the inputs and outputs to this
 * function are the external values defined in RFCs.
 */
int dns_rrtype_from_name(const char *name);

/**
 * Given an rr-type, return it's name, like "A" for 1 or "MX" for 5. Both
 * the inputs and outputs to this function are the external values defined
 * in RFCs.
 */
const char *dns_name_from_rrtype(int value);

/**
  * Runs some quick tests that don't consume much memory or CPU,
  * to validate some internal functions that don't bloat executables using
  * this module.
  * @return 0 on success, 1 on failure.
 */
int dns_quicktest(void);


#ifdef __cplusplus
}
#endif
#endif
