/*
    dns-parse

    Parses commonly found DNS records, Can be used in many places,
    but most commonly with `resolv.h`, the (incomplete) resolver
    built into many libraries.
 */
#include "dns-parse.h"
#include <assert.h>
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <stdlib.h>
#include <errno.h>

enum {DNS_query, DNS_answer, DNS_nameserver, DNS_additional};

#if defined(_MSCVER) || defined(HAVE_MEMCPY_S)
#define _memcpy_s memcpy_s
#else
int
_memcpy_s(void *dst, size_t sizeof_dst, const void *src, size_t count)
{
    if (dst == NULL)
        return EINVAL;
    else if (src == NULL) {
        memset(dst, 0, sizeof_dst);
        return EINVAL;
    } else if (sizeof_dst < count) {
        memset(dst, 0, sizeof_dst);
        return ERANGE;
    } else {
        memcpy(dst, src, count);
        return 0;
    }
}
#endif

/**
 * Like 'calloc()', but uses the custom memory allocator. WARNING: this uses 'realloc()'
 * underneath, which invalidates all previous allocataions. Thus, we do do two passes
 * through the packet, once in 'prealloc' phase where we allocate memory but don't
 * copy anything into it, then a second phase where we can copy into memory that
 * won't be reallocated underneath us.
 */
static void *
_calloc(struct dns_t **dns, size_t count, size_t size)
{
#define MAXNUM ((size_t)1 << (sizeof(size_t)*4))
    size_t total;
    void *result;

    /* Align 16-byte bounary */
    while (size & 0xF)
        size++;
    
    /* If (*dns) is already NULL, then we've encountered some error,
     * such as a previous allocation failing due to a memory allocation
     * error. Therefore, return NULL instead of trying to allocate */
    if (dns == NULL || *dns == NULL)
        return NULL;
    
    /* Make sure we don't overflow. If an overflow is detected, then
     * we are going to return NULL to signal an error */
    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX/size) {
            return NULL;
        }
    }
    total = count * size;
    if ((*dns)->_current_size + total < total)
        return NULL;
    
    /* Do the actual reallocation. Note that if our block of memory
     * is already big enough, then we won't need to grow our memory
     * segment. */
    if ((*dns)->_current_size + total > (*dns)->_max_size) {
        
        /* This should never happen in phase 2, only in phase 1 */
        assert((*dns)->mem.is_postalloc == 0);
        
        (*dns)->_max_size = (*dns)->_current_size + total;
    }
    
    /* Return the new memory */
    result = (char*)(*dns) + (*dns)->_current_size;
    (*dns)->_current_size += total;
    
    if ((*dns)->mem.is_prealloc)
        return (void*)~0;
    else
        return result;
}

/**
 * A writeable stream, that we call '_append_byte()' to check for buffer-overflow
 */
struct streamw_t {
    unsigned char *buf;
    size_t offset;
    size_t length;
    unsigned is_error;
};

/**
 * A readable stream that we constantly verify that we don't read past the end of the
 * packet.
 */
struct streamr_t {
    const unsigned char *buf;
    size_t offset;
    size_t length;
    unsigned is_error;
};

/**
 * Writes character onto the end of a buffer. Used to copy DNS names while checking
 * for buffer overflows.
 */
static void
_append_byte(struct streamw_t *s, unsigned char c)
{
    if (s->offset < s->length)
        s->buf[s->offset++] = c;
    else
        s->is_error = DNS_programming_error;
}

/**
 * Append a decimal integer. Used when creating the TYPE# generic
 * string for unknown rr-types.
 */
static void
_append_number(unsigned char *dst, size_t dst_offset, size_t sizeof_dst, unsigned long long n)
{
    char tmp[64];
    size_t tmp_offset = 0;
    struct streamw_t s = {dst, dst_offset, sizeof_dst, 0};

    /* Create temporary string */
    while (n >= 10) {
        unsigned digit = n % 10;
        n /= 10;
        tmp[tmp_offset++] = '0' + digit;
    }
    tmp[tmp_offset++] = '0' + n; /* the final digit, may be zero */

    /* Copy the result backwards */
    while (tmp_offset)
        _append_byte(&s, tmp[--tmp_offset]);
    _append_byte(&s, '\0');
}

static const unsigned char *
_next_skip(struct streamr_t *src, size_t count)
{
    const unsigned char *result = src->buf + src->offset;
    if (src->offset + count > src->length) {
        src->offset = src->length;
        src->is_error = DNS_input_overflow;
    } else
        src->offset += count;
    return result;
} 

/**
 * Reads next 8-bit number and moves offset forward
 */
static unsigned char
_next_uint8(struct streamr_t *s)
{
    if (s->offset < s->length)
        return s->buf[s->offset++];
    else {
        s->is_error = DNS_input_overflow;;
        return 0;
    }
}

/**
 * Reads next 16-bit big-endian number and moves offset forward
 */
static unsigned short 
_next_uint16(struct streamr_t *s)
{
    unsigned short result;
    
    result = _next_uint8(s) << 8;
    result |= _next_uint8(s);
    
    return result;
}

/**
 * Reads next 32-bit big-endian number and moves offset forward
 */
static unsigned
_next_uint32(struct streamr_t *s)
{
    unsigned result;
    
    result = _next_uint16(s) << 16;
    result |= _next_uint16(s);
    
    return result;
}


/**
 * Reads next chunk of data.
 */
static int
_next_memcpy(struct streamr_t *src, void *dst, size_t dst_length, size_t count, unsigned is_copyable)
{
    /* If there's not enough source bytes, then this is a parsing error */
    if (src->offset + count > src->length) {
        src->offset = src->length;
        src->is_error = DNS_input_overflow;
        return DNS_input_overflow;
    }
    
    /* If there's not enough destination bytes, this is a programming error.
     * The programmer should already have verified there is enough bytes
     * before attempting this copy. */
    if (count > dst_length || dst == NULL) {
        return DNS_programming_error;
    }
    
    if (is_copyable) {
        _memcpy_s(dst, dst_length, src->buf + src->offset, count);
        if (count < dst_length)
            ((char*)dst)[count] = '\0'; /* nul-terminate all copies, if possible */
    }
    
    _next_skip(src, count);
    return src->is_error;
}

/**
 * Reads a TXT <character-string>, which a 1-byte length field followed by the raw binary contents.
 * in theory, it should be human-readable text, but in practice, it's often machine readable strings
 */
static int
_next_charstring(struct streamr_t *src, const unsigned char **dst, size_t *dst_length, struct dns_t **dns)
{
    unsigned is_copyable = (*dns)->mem.is_postalloc;
    size_t len;
    unsigned char *tmp;
    
    /* Get the length of the next field */
    len = _next_uint8(src);
    if (src->is_error)
        return src->is_error;
    
    /* If the length is greater than remaining data, this is an
     * error */
    if (src->offset + len > src->length) {
        src->offset = src->length;
        src->is_error = DNS_input_overflow;
        return src->is_error;
    }
    
    /* Allocate space for the buffer. Remember, in pass#1 no allocation
     * happens (only records length), only on pass#2 does it happen */
    tmp = _calloc(dns, 1, len + 1);
    if (tmp == NULL)
        return DNS_out_of_memory;
    
    /* If pass#2, then do the actual copy */
    if (is_copyable) {
        _memcpy_s(tmp, len + 1, src->buf + src->offset, len);
        tmp[len] = '\0'; /* always nul-terminate these strings */
        *dst = tmp;
        *dst_length = len;
    }
    
    /* Update the input to point past this field */
    _next_skip(src, len);
    
    return src->is_error;
}

/**
 * Used internally to skip a 'name', either before the RDATA, or within the RDATA.
 * This walks the series of labels in a name, ending either with the label 0x00,
 * or the label 0xCxx. It doesn't follow compressed/recursive names, as it's 
 * skipping the bytes HERE in the packet, not following them elsewhere
 */
static int 
_skip_name(struct streamr_t *src)
{
    while (!src->is_error) {
        unsigned char c;
        
        /* get the tag/length byte*/
        c = _next_uint8(src);
        
        if (c == 0x00) {
            /* The last label ending a name */
            break;
        } else if (c <= 0x3F) {
            /* Length of this label */
            _next_skip(src, c);
        } else if ((c & 0xC0) == 0xC0) {
            /* Compression, so move one byte forward */
            _next_uint8(src);
            break;
        } else {
            /* unknown tag */
            src->is_error = DNS_input_bad;
            break;
        }
    }
    return src->is_error;
}

/**
 * Skip the resource-record, to get to the next resource-record. This is called
 * after _skip_name() to skip the name attached before the
 */
static int
_skip_rr(struct streamr_t *src, int is_query)
{
    size_t rdlength;
    
    /* skip [class] and [type] fields */
    _next_uint32(src);
    if (src->is_error)
        return DNS_input_overflow;
    
    /* Query records have only the frist two fields, but no
     * contents, so stop processing here. Only continue processing
     * for 'answer', 'nameserver', and 'additional' records */
    if (is_query)
        return 0;
    
    /* skip [ttl] field */
    _next_uint32(src);

    /* get the [rdlength] field */
    rdlength = _next_uint16(src);
    
    /* skip the [rdata] field */
    _next_skip(src, rdlength);
    return src->is_error;
}


/**
 * Internal function for copying a name. It's called with two different
 * variations, one when it's the name before the resource-record,
 * and one when it's the RDATA within the resource-record.
 * When the name is within the RDATA section, name compression
 * can point outside the RDATA field into the general packet.
 */
static int
_next_domainname(struct streamr_t *rdata, struct streamr_t packet, unsigned char *name_buf, size_t name_length)
{
    struct streamr_t src = *rdata;
    struct streamw_t name = {name_buf, 0, name_length, 0};
    size_t recursion_count = 0;
    int err;
    size_t count = 0;
    
    /* We work from a copy of the [rdata] pointer below, but for output,
     * we skip the name. The reason is name compression. Here in the
     * [rdata] field, it may be only two bytes (often 0xc0 0x0c) of
     * compression, but later many more bytes located elsehwere */
    err = _skip_name(rdata);
    if (err)
        return err;
    
    /* For each label... */
    for (;;) {
        size_t len;

        /* get the tag/length field */
        len = _next_uint8(&src);
        if (src.is_error)
            return src.is_error;
        
        if (len == 0) {
            /* This is the last [label] in the [domainame]. A [FQDN] fully
             * qualified domain name always ends in a dot. */
            _append_byte(&name, '.');
            break;
        } else if (len <= 0x3F) {
            /* this is a [label length] field */
            size_t i;
            
            /* Put a dot '.' between labels after the first */
            if (count)
                _append_byte(&name, '.');

            count += 1 + len;
            if (count + 1 > 255)
                return src.is_error = DNS_input_overflow;

            /* Copy over the bytes one byte one. Binary/special bytes need
             * to be escaped. */
            for (i=0; i<len; i++) {
                unsigned char c;
                
                c = _next_uint8(&src);
                if (src.is_error)
                    return DNS_input_overflow;
                
                /* While [hostnames] have restrictions to just alphanumeric and
                 * dot/dash, [domainnames] themselves can contain any binary data.
                 * Therefore, here we escape any binary data. We also escape things
                 * that would affect parsing of the names, like the dot when it
                 * appears within a label, or the escape character itself. */
                if (c == '.' || c == '\\' || c == '\"' || c < 32 || 126 < c)
                    _append_byte(&name, '\\');
                
                /* append this byte to the name */
                _append_byte(&name, c);
            }
            
        } else if ((len & 0xC0) == 0xC0) {
            /* This is name [compression]. Instead of a 1-byte length, it's a
             * two byte number that indicates the offset from the start fo the
             * packet that we need to jump to. */
            unsigned char len2;
            
            /* Get the second byte of the two-byte length field */
            len2 = _next_uint8(&src);
            if (src.is_error)
                return DNS_input_overflow;

            /* Reset which buffer we are looking at. We were looking at just
             * the RDATA field, now we need to expand this to look at the entire
             * DNS payload */
            src.buf = packet.buf;
            src.length = packet.length;
            src.offset = (len & 0x3F) << 8 | len2;
            
            /* Peek ahead looking for recursion */
            if (src.offset + 1 > src.length)
                return DNS_input_overflow;
            if ((src.buf[src.offset] & 0xC0) == 0xC0) {
                if (++recursion_count > 4) {
                    return DNS_input_bad;
                }
            }
        } else {
            /* Bad [tag]. There are only 4 combinations that this could be,
             * where 0b00...... is the [length], and 0b11...... is the
             * [compression]. There was a spec for an [tag] with value
             * 0b10......, but that was deprecated.*/
            return DNS_input_bad;
        }
    }
        
    /* We need to nul-terminate the string */
    _append_byte(&name, '\0');
    
    /* Test whether there was an internal buffer overflow. This is
     * due to a programming mistake, not bad input. */
    if (name.is_error)
        return DNS_programming_error;

    return 0;
}

/**
 * Extracts a (compressed) DNS name from the packet, converting to a
 * nul-temrinated string, and allocating bytes to contain it. Because of name
 * compression, processing can jump from outside the current source stream
 * to somewhere else i nthe packet.
 * @param src
 *      The stream where we are reading sequential fields. This is
 *      either the domain-name in front fo the resource-record, or
 *      somewhere within the RDATA portion of the resource-record,
 *      in which case reading outside the RDATA field will
 *      cause an error.
 * @param packet
 *      A stream representing the entire packet. This is because
 *      This is becauase name compression can jump outside
 *      the current field into the entire packet.
 * @param dst
 *      An out parameter that receives the domain-name as a nul-terminates string.
 * @param dns
 *      This represents the allocator from which we are getting memory.
 */
static int
_copy_domainname(struct streamr_t *src, struct streamr_t packet, const unsigned char **dst, struct dns_t **dns)
{
    unsigned char tmpname[256];
    size_t name_length;
    int err;
    unsigned char *newname;
    
    /* Force the name to be NULL in case of parsing errors later */
    if ((*dns)->mem.is_postalloc)
        *dst = NULL;
    
    /* First, copy the name into a temporary buffer */
    err = _next_domainname(src, packet, tmpname, sizeof(tmpname));
    if (err) {
        src->is_error = err;
        return err;
    }
    name_length = strlen((char*)tmpname) + 1;
        
    /* Now allocate a new buffer for the name and copy it over */
    newname = _calloc(dns, 1, name_length);
    if (newname == NULL || *dns == NULL)
        return DNS_out_of_memory;
    
    /* Now assign the field */
    if ((*dns)->mem.is_postalloc) {
        _memcpy_s(newname, name_length, tmpname, name_length);
        *dst = newname;
    }
    
    /* success */
    return 0;
}



static int
_parse_flags(struct dns_t *dns, const unsigned char *buf, size_t length)
{
    struct streamr_t packet = {buf, 0, length, 0};
    struct dnsflags_t *flags = &dns->flags;
    size_t additional_index;
    unsigned xx;
    size_t i;

    memset(flags, 0, sizeof(*flags));

    /* Parse the fixed-length header */
    flags->xid = _next_uint16(&packet); /* XID */
    xx = _next_uint16(&packet);
    
    /*
     15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   Rcode   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    */
    flags->is_response = (xx >> 15) & 1;
    flags->opcode = (xx >> 11) & 0x0f;
    flags->is_authoritative = (xx >> 10) & 1;
    flags->is_truncated = (xx >> 9) & 1;
    flags->is_recursion_desired = (xx >> 8) & 1;
    flags->is_recursion_available = (xx >> 7) & 1;
    flags->is_Z = (xx >> 6) & 1;
    flags->is_authentic = (xx >> 5) & 1;
    flags->is_checking_disabled = (xx >> 4) & 1;

    dns->query_count = _next_uint16(&packet);
    dns->answer_count = _next_uint16(&packet);
    dns->nameserver_count = _next_uint16(&packet);
    dns->additional_count = _next_uint16(&packet);
    
    /*
     * Go down the list of resource-records looking for an EDNS0
     * option. This means we are going to walk the entire list of 
     * resource-records twice, once right now, and again later when
     * the caller walks the list.
     *
     * RFC 6891: "The OPT RR MAY be placed anywhere within the 
     * additional data section."
     * RFC 6891: "it MUST be the only OPT RR in that message"
     */
   
    /* Skip all the records until the "additional" section */
    additional_index = dns->query_count + dns->answer_count + dns->nameserver_count;
    for (i=0; i<additional_index && !packet.is_error; i++) {
        _skip_name(&packet);
        _skip_rr(&packet, i < dns->query_count);
    }
    
    /* Read the additional section for all EDNS0 records */
    for (i=0; i<dns->additional_count && !packet.is_error; i++) {
        /* Make sure there's enough space for minimal name/header*/
        if (packet.offset + 6 > packet.length)
            return DNS_input_overflow;
        
        /* If we have a root label 0x00 ... */
        if (packet.buf[packet.offset] == 0x00) {
            unsigned short rtype = packet.buf[packet.offset + 1]<<8 | packet.buf[packet.offset+2];
            
            if (rtype == 41) {
                /* we have an EDNS0 record */
                if (flags->edns0.offset) {
                    /* Multiple EDNS0, which is not allowed per RFC6891 6.1.1. */
                    return DNS_input_overflow;
                } else {
                    flags->edns0.offset = packet.offset;
                }
            }
        }
        
        /* If multiple 'additional' records, keep processing them until
         * we find an EDNS0 record or reach the end of the list */
        _skip_name(&packet);
        _skip_rr(&packet, 0);
    }

    /* If there was an error parsing the header, such as there not
     * being 12 bytes of the header, or there not being enough bytes
     * for all the records, then indicate it here. NOTE: that we don't
     * stop*/
    if (packet.is_error) {
        dns->error_code = packet.is_error;
        return packet.is_error;
    }
    
    /* If we found an EDNS0 record, parse it */
    if (flags->edns0.offset) {
        unsigned x;
        
        /* reset the offset */
        packet.offset = flags->edns0.offset;
        _skip_name(&packet);
        _next_uint16(&packet);
        
        /* At this point, we've already validated that we can't go
         * past the end of the packet */
        flags->edns0.udp_payload_size = _next_uint16(&packet);
        x = _next_uint8(&packet);
        flags->edns0.extended_rcode = x<<4 | flags->rcode;
        flags->edns0.version = _next_uint8(&packet);
        x = _next_uint8(&packet);
        flags->edns0.is_dnssec = ((x & 0x80) != 0);
    }


    if (packet.is_error)
        return DNS_programming_error;
    else
        return 0;
}




struct dnstypes {
    const char *name;
    int value;
};

static const struct dnstypes dnstypes[] = {
    {"A", DNS_T_A}, /* 1 */
    {"NS", DNS_T_NS}, /* 2 */
    {"MD", 3},
    {"MF", 4},
    {"CNAME", DNS_T_CNAME}, /* 5 */
    {"SOA", DNS_T_SOA}, /* 6 */
    {"MB", 7},
    {"MG", 8},
    {"MR", 9},
    {"NULL", 10},
    {"WKS", 11},
    {"PTR", DNS_T_PTR}, /* 12 */
    {"HINFO", DNS_T_HINFO}, /* 13 */
    {"MINFO", 14},
    {"MX", DNS_T_MX}, /* 15 */
    {"TXT", DNS_T_TXT}, /* 16 */
    {"RP", DNS_T_RP}, /* 17 */
    {"AFSDB", 18},
    {"X25", 19},
    {"ISDN", 20},
    {"RT", 21},
    {"NSAP", 22},
    {"NSAP-PTR", 23},
    {"SIG", 24},
    {"KEY", 25},
    {"PX", 26},
    {"GPOS", 27},
    {"AAAA", DNS_T_AAAA}, /* 28 */
    {"LOC", 29},
    {"NXT", 30},
    {"EID", 31},
    {"NIMLOC", 32},
    {"SRV", DNS_T_SRV}, /* 33 */
    {"ATMA", 34},
    {"NAPTR", DNS_T_NAPTR}, /* 35 */
    {"KX", 36},
    {"CERT", DNS_T_CERT}, /* 37 */
    {"A6", 38},
    {"DNAME", 39},
    {"SINK", 40},
    {"OPT", DNS_T_OPT}, /* 41 */
    {"APL", 42},
    {"DS", DNS_T_DS}, /* 43 */
    {"SSHFP", DNS_T_SSHFP}, /* 44 */
    {"IPSECKEY", 45},
    {"RRSIG", DNS_T_RRSIG}, /* 46 */
    {"NSEC", DNS_T_NSEC}, /* 47 */
    {"DNSKEY", DNS_T_DNSKEY}, /* 48 */
    {"DHCID", 49},
    {"NSEC3", DNS_T_NSEC3}, /* 50 */
    {"NSEC3PARAM", DNS_T_NSEC3PARAM}, /* 51 */
    {"TLSA", DNS_T_TLSA}, /* 52 */
    {"SMIMEA", 53},
    //{"Unassigned", 54},
    {"HIP", 55},
    {"NINFO", 56},
    {"RKEY", 57},
    {"TALINK", 58},
    {"CDS", 59},
    {"CDNSKEY", 60},
    {"OPENPGPKEY", 61},
    {"CSYNC", 62},
    {"ZONEMD", 63},
    //{"Unassigned", 64-98},
    {"SPF", DNS_T_SPF}, /* 99 */
    {"UINFO", 100},
    {"UID", 101},
    {"GID", 102},
    {"UNSPEC", 103},
    {"NID", 104},
    {"L32", 105},
    {"L64", 106},
    {"LP", 107},
    {"EUI48", 108},
    {"EUI64", 109},
    //{"Unassigned", 110-248},
    {"TKEY", 249},
    {"TSIG", 250},
    {"IXFR", 251},
    {"AXFR", 252},
    {"MAILB", 253},
    {"MAILA", 254},
    {"ANY", 255},
    {"URI", 256},
    {"CAA", 257},
    {"AVC", 258},
    {"DOA", 259},
    {"AMTRELAY", 260},
    //{"Unassigned", 261-32767},
    {"TA", 32768},
    {"DLV", 32769},
    {0,0}
};

int
dns_rrtype_from_name(const char *name)
{
    size_t i;
    
    if (name == NULL)
        return -1;
    
    /* The name may be of the generic form "TYPEnnn", in which case we need to parse
     * the number instead of looking up the name */
    if (strlen(name) > 4 && (memcmp(name, "TYxPE",4) == 0 || memcmp(name, "\x54\x59\x50\x45", 4) ==0)) {
        int result = 0;
        for (i=4; name[i]; i++) {
            char c = name[i];
            if ('0' <= c && c <= '9')
                c -= '0'; /* when specified in the internal character set */
            else if (0x30 <= c && c <= 0x39)
                c -= 0x30; /* when external character set on EBDIC systems */
            else
                return -1;
            result = result * 10 + c;
            if (result > 65535)
                return -1;
        }
        return result;
    }

    /* Otherwise, assume a string that we have too lookup */
    for (i=0; dnstypes[i].name; i++) {
        if (strcmp(name, dnstypes[i].name) == 0)
            return dnstypes[i].value;
    }
    
    /* Not found, so return an error */
    return -1;
}

const char *
dns_name_from_rrtype(int value)
{
#ifdef __gnuc__
    /* The following variable needs to be thread-local storage */
    __thread
#endif
    static unsigned char tmp[64];
    size_t i;
    
    /* If it exists in our list, return that */
    for (i=0; dnstypes[i].name; i++) {
        if (value == dnstypes[i].value)
            return dnstypes[i].name;
    }

    /* According to RFC 3597, unknown types are represented
     * with TYPEn, where n is the value */
    //snprintf(tmp, sizeof(tmp), "TYPE%d", value);
    _memcpy_s(tmp, sizeof(tmp), "TYPE", 5);
    _append_number(tmp, 4, sizeof(tmp), value);

    return (const char*)tmp;
}


static int
_copy_uint8(struct streamr_t *src, unsigned char*dst, unsigned is_copyable)
{
    unsigned char x =_next_uint8(src);
    if (is_copyable)
        *dst = x;
    return src->is_error;
}

static int
_copy_uint16(struct streamr_t *src, unsigned short*dst, unsigned is_copyable)
{
    unsigned short x = _next_uint16(src);
    if (is_copyable)
        *dst = x;
    return src->is_error;
}

static int
_copy_uint32(struct streamr_t *src, unsigned *dst, unsigned is_copyable)
{
    unsigned x = _next_uint32(src);
    if (is_copyable)
        *dst = x;
    return 0;
}

static int
_copy_bytes(struct streamr_t *src, const unsigned char **dst, size_t *dst_length, size_t len, struct dns_t **mem)
{
    unsigned char *tmp;
        
    tmp = _calloc(mem, 1, len + 1);

    if ((*mem)->mem.is_postalloc) {
        _memcpy_s(tmp, len + 1, src->buf + src->offset, len);
        tmp[len] = '\0'; /* always nul-termiante in case of text */
        *dst = tmp;
        *dst_length = len;
    }
    _next_skip(src, len);
    return src->is_error;
}

size_t _next_save(const struct streamr_t *src)
{
    return src->offset;
}
void _next_restore(struct streamr_t *src, size_t old_offset)
{
    src->offset = old_offset;
}


static int
_parse_resource_record(struct dns_t **dns, size_t rindex, unsigned short rtype, struct streamr_t packet, struct streamr_t rdata)
{
    struct dnsrrdata_t *rr = NULL;
    size_t len;
    unsigned is_copyable = (*dns)->mem.is_postalloc;
    
    if (is_copyable) {
        rr = &(*dns)->queries[rindex];
        rr->rtype = rtype;
        rr->rclass = 1;
    }
    
    
    /* Ignore EDNS0 */
    if (rtype == 41)
        return 0;
    
    switch (rtype) {
        case DNS_T_A: /* IPv4 address */
            _copy_uint32(&rdata, &rr->a.ipv4, is_copyable);
            break;
        case DNS_T_NS: /* name server */
            /* A single DNS name. This may be a compressed or partially-compressed
            * name.
            *   google.com IN NS ns2.google.com.
            */
            _copy_domainname(&rdata, packet, &rr->ns.name, dns);
            break;
        case DNS_T_CNAME: /* canonical name */
            _copy_domainname(&rdata, packet, &rr->cname.name, dns);
            break;
        case DNS_T_SOA: /* Start of zone Authority */
            /* A typical SOA record, two DNS names (possibly compressed)
            * followed by five integers
            *   google.com    IN SOA ns1.google.com dns-admin.google.com 268869309 900 900 1800 60
            *   twitter.com. IN    SOA    ns1.p26.dynect.net. zone-admin.dyndns.com. 2007142997 3600 600 604800 60
            */
            _copy_domainname(&rdata, packet, &rr->soa.mname, dns);
            _copy_domainname(&rdata, packet, &rr->soa.rname, dns);
            _copy_uint32(&rdata, &rr->soa.serial, is_copyable);
            _copy_uint32(&rdata, &rr->soa.refresh, is_copyable);
            _copy_uint32(&rdata, &rr->soa.retry, is_copyable);
            _copy_uint32(&rdata, &rr->soa.expire, is_copyable);
            _copy_uint32(&rdata, &rr->soa.minimum, is_copyable);
            break;
        case DNS_T_PTR: /* pointer (reverse lookup) */
            _copy_domainname(&rdata, packet, &rr->ptr.name, dns);
            break;
        case DNS_T_HINFO: /* host info */
            _next_charstring(&rdata, &rr->hinfo.cpu.buf, &rr->hinfo.cpu.length, dns);
            _next_charstring(&rdata, &rr->hinfo.os.buf, &rr->hinfo.os.length, dns);
            break;
        case DNS_T_MX: /* mail exchnage*/
            /* a number (priority) followed by the DNS name of the server that handles
             * email for the domain
             *  gmail.com.        2625    IN    MX    5 gmail-smtp-in.l.google.com.
             *  gmail.com.        2625    IN    MX    40 alt4.gmail-smtp-in.l.google.com.
             *  gmail.com.        2625    IN    MX    30 alt3.gmail-smtp-in.l.google.com.
             *  gmail.com.        2625    IN    MX    10 alt1.gmail-smtp-in.l.google.com.
             *  gmail.com.        2625    IN    MX    20 alt2.gmail-smtp-in.l.google.com.*/
            _copy_uint16(&rdata, &rr->mx.priority, is_copyable);
            _copy_domainname(&rdata, packet, &rr->mx.name, dns);
            break;
        case DNS_T_SPF: /* SPF - same as text */
        case DNS_T_TXT: /* text records
            *  mozilla.org.        60    IN    TXT    "yandex-verification"
            *  mozilla.org.        60    IN    TXT    "google-site-verification=Lo_B34AJAe70BQVNF1Fo1zGGJudPmw9bLTnP2C8lV-s"
            *  mozilla.org.        60    IN    TXT    "v=spf1 include:_spf.mozilla.com include:_spf.google.com ~all"
            */
            /* There can be multiple fields, each starting with a length byte followed by
             * up to 256 bytes of content */
        {
            struct streamr_t tmp = rdata;
            size_t count = 0;
            struct dnsrrbuf_t *array;
            size_t j;
            
            /* First, count the number of <character-string> fields within the <rdata>.
             * We need to allocate this number of pointers to the text fields. */
            while (tmp.offset < tmp.length) {
                len = _next_uint8(&tmp);
                _next_skip(&tmp, len);
                count++;
            }
            
            /* Now allocate the array. */
            array = _calloc(dns, sizeof(array[0]), count);
            
            /* Copy over the strings */
            for (j=0; j<count; j++) {
                unsigned char *tmp;
                
                /* Each TXT <character-string> is a one-byte [length] field
                 * followed by that number of binary bytes */
                len = _next_uint8(&rdata);
                
                /* Allocate a buffer for those characters */
                tmp = _calloc(dns, 1, len + 1);
                
                /* Copy those bytes into the buffer */
                _next_memcpy(&rdata, tmp, len+1, len, is_copyable);
                
                /* If second pass, actually set the values */
                if (is_copyable) {
                    array[j].buf = tmp;
                    array[j].length = len;
                }
            }
            
            /* If second pass, actually set the values */
            if (is_copyable) {
                rr->txt.array = array;
                rr->txt.count = count;
            }
        }
            break;

        case DNS_T_RP: /* Responsible Person */
            _copy_domainname(&rdata, packet, &rr->rp.mbox_dname, dns);
            _copy_domainname(&rdata, packet, &rr->rp.txt_dname, dns);
            break;

        case DNS_T_AAAA: /* IPv6 address */
            _next_memcpy(&rdata, rr->aaaa.ipv6, sizeof(rr->aaaa.ipv6), 16, is_copyable);
            break;

        case DNS_T_NAPTR: /* Naming Authority Pointer for SIP[RFC 2915]  */
            _copy_uint16(&rdata, &rr->naptr.order, is_copyable);
            _copy_uint16(&rdata, &rr->naptr.preference, is_copyable);
            _next_charstring(&rdata, &rr->naptr.flags.buf, &rr->naptr.flags.length, dns);
            _next_charstring(&rdata, &rr->naptr.service.buf, &rr->naptr.service.length, dns);
            _next_charstring(&rdata, &rr->naptr.regexp.buf, &rr->naptr.regexp.length, dns);
            _copy_domainname(&rdata, packet, &rr->naptr.replacement, dns);
            break;
                
        case DNS_T_RRSIG: /* Resource Record Signature for DNSSEC */
            _copy_uint16(&rdata, &rr->rrsig.type, is_copyable);
            _copy_uint8(&rdata, &rr->rrsig.algorithm , is_copyable);
            _copy_uint8(&rdata, &rr->rrsig.labels, is_copyable);
            _copy_uint32(&rdata, &rr->rrsig.ttl, is_copyable);
            _copy_uint32(&rdata, &rr->rrsig.expiration, is_copyable);
            _copy_uint32(&rdata, &rr->rrsig.inception, is_copyable);
            _copy_uint16(&rdata, &rr->rrsig.keytag, is_copyable);
            _copy_domainname(&rdata, packet, &rr->rrsig.name, dns);
            len = rdata.length - rdata.offset; /* all remaining bytes in rdata field */
            _copy_bytes(&rdata, &rr->rrsig.sig, &rr->rrsig.length, len, dns);
            break;
        
        case DNS_T_NSEC: /* NSEC */
        {
            unsigned short types[65536];
            size_t types_count = 0;
            unsigned short *tmp;
            
            _copy_domainname(&rdata, packet, &rr->nsec.name, dns);
            
            while (rdata.offset < rdata.length) {
                unsigned char window = _next_uint8(&rdata);
                unsigned count = _next_uint8(&rdata);
                size_t j;
                for (j=0; j<count; j++) {
                    int k;
                    unsigned char bits = _next_uint8(&rdata);
                    
                    for (k=7; k>=0; k--) {
                        if (bits & (1<<k)) {
                            unsigned short xtype = window<<8 | (j * 8 + (7 - k));
                            types[types_count++] = xtype;
                        }
                    }
                }
            }
            if (rdata.is_error)
                break;
            
            tmp = _calloc(dns, sizeof(*tmp), types_count);

            if (is_copyable) {
                size_t j;
                rr->nsec.types_count = types_count;
                for (j=0; j<types_count; j++)
                    tmp[j] = types[j];
                rr->nsec.types = tmp;
                
            }
        }
            break;
        
        case DNS_T_DNSKEY: /* DNSKEY */
            _copy_uint16(&rdata, &rr->dnskey.flags, is_copyable);
            _copy_uint8(&rdata, &rr->dnskey.protocol, is_copyable);
            _copy_uint8(&rdata, &rr->dnskey.algorithm, is_copyable);
            len = rdata.length - rdata.offset; /* all remaining bytes */
            _copy_bytes(&rdata, &rr->dnskey.publickey, &rr->dnskey.length, len, dns);
            break;
        case DNS_T_NSEC3PARAM: /* NSEC3PARAM */
            _copy_uint8(&rdata, &rr->nsec3param.algorithm, is_copyable);
            _copy_uint8(&rdata, &rr->nsec3param.flags, is_copyable);
            _copy_uint16(&rdata, &rr->nsec3param.iterations, is_copyable);
            len = _next_uint8(&rdata);
            _copy_bytes(&rdata, &rr->nsec3param.salt, &rr->nsec3param.salt_length, len, dns);
            break;

        case DNS_T_CAA: /* CAA - certficate authority */
            _copy_uint8(&rdata, &rr->caa.flags, is_copyable);
            
            len = _next_uint8(&rdata);
            _next_memcpy(&rdata, rr->caa.tag, sizeof(rr->caa.tag), len, is_copyable);
            if (is_copyable)
                rr->caa.taglength = len;
            
            len = rdata.length - rdata.offset; /* all remaining bytes */
            _copy_bytes(&rdata, &rr->caa.value, &rr->caa.length, len, dns);
            break;
        default:
            len = rdata.length; /* all bytes in the resource-record */
            _copy_bytes(&rdata, &rr->unknown.buf, &rr->unknown.length, len, dns);
            return 0;
    }
    if (rdata.is_error || rdata.offset > rdata.length)
        return DNS_input_overflow; /* failure */
    else
        return 0; /* success */
}

/**
 * Implements the default allocator, which is just a call to the
 * standard library calls of realloc() and free().
 */
static void *
_default_realloc(void *p, size_t newsize, void *arena)
{
    (void)arena;
    if (newsize == 0) {
        free(p);
        return NULL;
    } else {
        return realloc(p, newsize);
    }
}


static void
_parse_records(struct dns_t **dns, const unsigned char *buf, size_t length, unsigned options)
{
    struct streamr_t packet = {buf, 0, length, 0};
    size_t i;
    size_t query_count;
    size_t answer_count;
    size_t nameserver_count;
    size_t additional_count;
    size_t total_record_count;
    struct dnsrrdata_t *records;

    /* FIXME: don't use this parameter yet, but I will */
    (void)options;
    
    /* skip xid and flags field, as those were parsed in pass#0 */
    (*dns)->flags.xid = _next_uint16(&packet);
    _next_uint16(&packet);
    
    /* grab the number of records in each section */
    query_count = _next_uint16(&packet);
    answer_count = _next_uint16(&packet);
    nameserver_count = _next_uint16(&packet);
    additional_count = _next_uint16(&packet);
    total_record_count = query_count + answer_count + nameserver_count + additional_count;
    
    if (packet.is_error) {
        (*dns)->error_code = packet.is_error;
        return;
    }

    /* Allocate all the records as a single array, then subdivide
     * that array for each section. */
    records =_calloc(dns, total_record_count, sizeof(records[0]));
    if ((*dns)->mem.is_postalloc) {
        (*dns)->query_count = query_count;
        (*dns)->queries = &records[0];
        
        (*dns)->answer_count = answer_count;
        (*dns)->answers = &records[query_count];
        
        (*dns)->nameserver_count = nameserver_count;
        (*dns)->nameservers = &records[query_count + answer_count];
        
        (*dns)->additional_count = additional_count;
        (*dns)->additional = &records[query_count + answer_count + nameserver_count];
    }
    
    /* Check to see if there was an error in the first 12 bytes */
    if (packet.is_error) {
        (*dns)->error_index = ~0;
        (*dns)->error_code = packet.is_error;
        return;
    }
    
    /* for all records in the packet ... */
    for (i=0; i<total_record_count; i++) {
        int section;
        unsigned short rtype;
        unsigned short rclass;
        unsigned ttl = 0;
        int err;
        dnsrrdata_t *rr = &(*dns)->queries[i];
        
        /* Remember the index for the resource-record in case of error */
        (*dns)->error_index = (unsigned)i;

        /* Figure out which section we are in */
        if (i < query_count)
            section = DNS_query;
        else if (i < query_count + answer_count)
            section = DNS_answer;
        else if (i < query_count + answer_count + nameserver_count)
            section = DNS_nameserver;
        else
            section = DNS_additional;

        /* First, get the name. This may be either the full name, or a compressed name.
         * Either way, we fully extract it and validate it. */
        err = _copy_domainname(&packet, packet, &rr->name, dns);
        if (err) {
            (*dns)->error_code = err;
            return;
        }

        /* Get the resource-record header */
        rtype = _next_uint16(&packet);
        rclass = _next_uint16(&packet);
         
        /* If not a short query-record, parse the contents of the
         * longer answer-records in the rest of the sections. */
        if (section != DNS_query && rtype != 41) {
            struct streamr_t rdata = {0};
            unsigned rdlength;
            
            /* Get the rest of the resource-record header */
            ttl = _next_uint32(&packet);
            rdlength = _next_uint16(&packet);

            /* Only support Internet class, unless it's the EDNS0 field */
            if (rclass != 1 && rtype != 41) {
                if (err) {
                    (*dns)->error_code = DNS_input_bad;
                    return;
                }
            }

            /* create a 'slice' of the packet data */
            rdata.length = rdlength;
            rdata.buf = packet.buf + packet.offset;
            rdata.offset = 0;
            
            /* Parse the individual record */
            err = _parse_resource_record(dns, i, rtype, packet, rdata);
            if (err) {
                (*dns)->error_code = err;
                return;
            }

            /* Skip the rdata field */
            _next_skip(&packet, rdata.length);
            
            if (packet.is_error) {
                (*dns)->error_code = packet.is_error;
                return;
            }
        }

        if ((*dns)->mem.is_postalloc) {

            rr->section = section;
            rr->rtype = rtype;
            rr->rclass = rclass;
            rr->ttl = ttl;
        }
    }
}

struct dns_t *
dns_parse_allocator(void *(*myrealloc)(void*,size_t,void*), void *arena, size_t padding)
{
    struct dns_t *result;

    /* Allow the user to supply NULL, in which case we'll use the
     * default allocator in the system */
    if (myrealloc == NULL)
        myrealloc = _default_realloc;
    
    /* First, call the custom allocator to allocate enough memory
     * for the basic structure */
    result = myrealloc(0, sizeof(*result) + padding, arena);
    if (result == NULL)
        return NULL;
    
    /* Initialize everything to zero */
    memset(result, 0, sizeof(*result));
    
    /* Save for later when we need more memory or to free memory */
    result->mem.myrealloc = myrealloc;
    result->mem.arena = arena;

    result->_current_size = sizeof(*result);
    result->_max_size = sizeof(*result) + padding;
    return result;
}

struct dns_t *
dns_parse(const unsigned char *buf, size_t length, unsigned options, struct dns_t *recycled)
{
    struct dns_t tmp0 = {0};
    struct dns_t *pass1 = &tmp0;
    struct dns_t *result = 0;
    

    /* PASS#0
     * Parse the header, and look for an EDNS0 record near the end
     * of the packet, which may inform us how we should handle
     * resource-record content on subsequent passes. */
    _parse_flags(pass1, buf, length);
    
    /* PASS#1
     * Parse all the resource-records to discover the amount of memory
     * that we need to allocate for them.
     */
    //memset(pass1, 0, sizeof(*pass1));
    pass1->mem.is_prealloc = 1;
    pass1->_current_size = sizeof(*pass1);
    pass1->_max_size = sizeof(*pass1);
    _parse_records(&pass1, buf, length, options);
    
    /* Now that we've calculated the amount of memory we need, do the
     * allocation. If the user has given us a custom allocator, then
     * we'll use that, otherwise, we'll use the standard 'realloc()'
     * function. */
    if (recycled && recycled->_max_size > pass1->_max_size) {
        result = recycled;
    } else if (recycled) {
        result = recycled->mem.myrealloc(recycled, pass1->_max_size, recycled->mem.arena);
    } else
        result = dns_parse_allocator(0, 0, pass1->_max_size - sizeof(*result));
    if (result == NULL)
        return NULL;
    
    _memcpy_s(&result->flags, sizeof(result->flags), &pass1->flags, sizeof(pass1->flags));
    result->_current_size = sizeof(*result);
    result->_max_size = pass1->_max_size;
    result->error_code = 0;
    result->mem.is_prealloc = 0;
    result->mem.is_postalloc = 1;
    
    /* PASS#2
     * Now parse the queries and store the results in the memory we've
     * just allocated. */
    _parse_records(&result, buf, length, options);
    
    return result;
}

void
dns_parse_free(struct dns_t *dns)
{
    if (dns == NULL)
        return;
    if (dns->mem.myrealloc)
        dns->mem.myrealloc(dns, 0, dns->mem.arena);
    else
        free(dns);
}


int dns_quicktest(void)
{
    static const unsigned char packet00[] =
    "\x12\x34"
    "\x81\x80"
    "\x00\x01" /* one query */
    "\x00\x01" /* one response */
    "\x00\x00" /* zero ns records */
    "\x00\x00" /* zero addition records */
    "\x03" "www" "\x07" "example" "\x03" "com" "\x00"
    "\x00\x01\x00\x01" /* class=IN type=A */
    "\xc0\x0c" /* compressed name back to start */
    "\x00\x01\x00\x01" /* type=A class=IN*/
    "\x41\x42\x43\x44" /* TTL */
    "\x00\x04" /* four bytes */
    "\x0a\x01\x02\x03";
    int is_error;
    
    
    /* Force an attempted buffer-overflow, which should generate an error */
    {
        char buf[5];
        struct streamr_t s = {(unsigned char*)"abcdefg", 0, 7, 0};
        is_error = _next_memcpy(&s, buf, sizeof(buf), 6, 1);
        if (is_error == 0)
            return 1;
    }
    
    if (dns_rrtype_from_name("TXT") != 16)
        return 1;
    if (dns_rrtype_from_name("fail") != -1)
        return 1;
    if (strcmp(dns_name_from_rrtype(1234), "TYPE1234") != 0)
        return 1;
    if (strcmp(dns_name_from_rrtype(1), "A") != 0)
        return 1;

    
    
    /* Test a GOOD result, that the module is working as intended to produce
     * an expected result. */
    {
        struct dns_t *dns;
        
        dns = dns_parse(packet00, sizeof(packet00)-1, 0, 0);
        if (dns == NULL || dns->error_code != 0) {
            return 1;
        }

        /* Now do the same thing, but this time re-using the buffer */
        dns = dns_parse(packet00, sizeof(packet00)-1, 0, 0);
        if (dns == NULL || dns->error_code != 0) {
            return 1;
        }
    }
    
    
    /* all tests succeeded */
    return 0;
}
