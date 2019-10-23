/*
    Formats resource records in standard "presentation" format.
    This is the format for DNS zone-files. In other words,
    an entry for an IP address looks like:
        foo.example.com  60  IN  A  192.168.1.102
    This module does the last part, converting an "A" record from
    a 4-byte integer to a standard IPv4 address.
 */
#include "dns-format.h"
#include "dns-parse.h"
#include <string.h>
#include <time.h>

/**
 * Holds the output string, so that we can append to it without
 * overflowing buffers. The _append_xxx() functions below append
 * to this string.
 */
typedef struct stream_t {
    char *buf;
    size_t offset;
    size_t length;
} stream_t;

/**
 * Append a character to the output string. All the other _append_xxx()
 * functions call this one, so this is the only one where a
 * buffer-overflow can occur.
 */
static void
_append_char(stream_t *out, char c)
{
    if (out->offset < out->length)
        out->buf[out->offset++] = c;

    /* keep the string nul terminated as we build it */
    if (out->offset < out->length)
        out->buf[out->offset] = '\0';
}

/**
 * Append a NUL-terminated string.
 */
static void
_append_string(stream_t *out, const void *src)
{
    size_t i;
    for (i = 0; ((const char*)src)[i]; i++)
        _append_char(out, ((const char *)src)[i]);
}

/**
 * Append a decimal integer.
 */
static void
_append_decimal(stream_t *out, unsigned long long n)
{
    char tmp[64];
    size_t tmp_offset = 0;

    /* Create temporary string */
    while (n >= 10) {
        unsigned digit = n % 10;
        n /= 10;
        tmp[tmp_offset++] = '0' + digit;
    }
    
    /* the final digit, may be zero */
    tmp[tmp_offset++] = (unsigned char)('0' + n);

    /* Copy the result backwards */
    while (tmp_offset)
        _append_char(out, tmp[--tmp_offset]);
}

/**
 * Append a decimal integer, with leading zeroes as necessary to
 * fit the minimum number of digits. This is used when printing
 * things like months or seconds in timestamps, so that
 * September is month 09 instead of month 9 -- a min_digits of 2.
 */
static void
_append_decimal2(stream_t *out, unsigned long long n, size_t min_digits)
{
    char tmp[64];
    size_t tmp_offset = 0;

    /* Create temporary string */
    while (n >= 10) {
        unsigned digit = n % 10;
        n /= 10;
        tmp[tmp_offset++] = '0' + digit;
        min_digits--;
    }
    
    /* final digit, may be zero */
    tmp[tmp_offset++] = (unsigned char)('0' + n);
    min_digits--;
    while (min_digits-- && tmp_offset < sizeof(tmp) - 1)
        tmp[tmp_offset++] = '0';

    /* Copy the result backwards */
    while (tmp_offset)
        _append_char(out, tmp[--tmp_offset]);
}

/**
 * Format a (time_t) value in the form: YYYYMMDDHHmmSS. This is special
 * format used in DNS, distinguishable from standard integers by the fact
 * it's longer than possible with a 32-bit number.
 */
static void
_append_decimaltime(stream_t *out, unsigned long long n)
{
    static const unsigned rough_y2k = 30 * 365 * 24 * 60 * 60;
    time_t t;
    struct tm *tm;

    /* Y2038 bug (epocalypse): The RRSIG spec defines this as a 32-bit
     * number, which will obviously overflow in 2038. I don't know what
     * will happen with this. Presumably, it'll just wrap. Therefore,
     * let's add some wrapping logic here. If the time stamp is less
     * than Y2K (an arbitrarily chosen boundary), then assume it's
     * wrapped. This should give us until 2068 before we have trouble. */
    if (n < rough_y2k)
        n += (1ULL << 32ULL);
    t = (time_t)n;

    tm = gmtime(&t);

    if (tm == NULL)
        _append_decimal(out, n);
    else {
        _append_decimal(out, tm->tm_year + 1900);
        _append_decimal2(out, tm->tm_mon + 1, 2);
        _append_decimal2(out, tm->tm_mday, 2);
        _append_decimal2(out, tm->tm_hour, 2);
        _append_decimal2(out, tm->tm_min, 2);
        _append_decimal2(out, tm->tm_sec, 2);
    }
}

/**
 * Append a string of hex characters
 */
static void
_append_hexdump(stream_t *out, const unsigned char *buf, size_t length)
{
    size_t i;
    static const char hex[] = "0123456789ABCDEF";
    for (i = 0; i < length; i++) {
        _append_char(out, hex[buf[i] >> 4]);
        _append_char(out, hex[buf[i] & 0xF]);
        ;
    }
}

/**
 * Encode the string using BASE64.
 * By default, this adds a space every 42 bytes of input, to match how `dig`
 * formats the output.
 */
static void
_append_base64(stream_t *out, const unsigned char *src, size_t sizeof_src)
{
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz"
                             "0123456789"
                             "+/";
    size_t i = 0;

    /* encode every 3 bytes of source into 4 bytes of destination text */
    while (i + 3 <= sizeof_src) {
        unsigned n;

        /* convert the chars */
        n = src[i] << 16 | src[i + 1] << 8 | src[i + 2];
        _append_char(out, b64[(n >> 18) & 0x3F]);
        _append_char(out, b64[(n >> 12) & 0x3F]);
        _append_char(out, b64[(n >> 6) & 0x3F]);
        _append_char(out, b64[(n >> 0) & 0x3F]);
        i += 3;

        if (i && i % 42 == 0)
            _append_char(out, ' ');
    }

    /* If the source text isn't an even multiple of 3 characters, then we'll
     * have to append a '=' or '==' to the output to compensate */
    if (i + 2 <= sizeof_src) {
        unsigned n = src[i] << 16 | src[i + 1] << 8;
        _append_char(out, b64[(n >> 18) & 0x3F]);
        _append_char(out, b64[(n >> 12) & 0x3F]);
        _append_char(out, b64[(n >> 6) & 0x3F]);
        _append_char(out, '=');
    } else if (i + 1 <= sizeof_src) {
        unsigned n = src[i] << 16;
        _append_char(out, b64[(n >> 18) & 0x3F]);
        _append_char(out, b64[(n >> 12) & 0x3F]);
        _append_char(out, '=');
        _append_char(out, '=');
    }
}

/**
 * Formats the IPv6 address. We use our own custom function to avoid
 * complicated dependencies, but also to fit the above paradigm when
 * appending strings.
 */
static void
_append_ipv6(stream_t *out, const unsigned char *ipv6)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    int is_ellision = 0;

    /* An IPv6 address is pritned as a series of 2-byte hex words
     * separated by colons :, for a total of 16-bytes */
    for (i = 0; i < 16; i += 2) {
        unsigned n = ipv6[i] << 8 | ipv6[i + 1];

        /* Handle the ellision case. A series of words with a value
         * of 0 can be removed completely, replaced by an extra colon */
        if (n == 0 && !is_ellision) {
            is_ellision = 1;
            while (i < 16 && ipv6[i + 2] == 0 && ipv6[i + 3] == 0)
                i += 2;
            _append_char(out, ':');

            /* test for all-zero address, in which case the output
             * will be "::". */
            if (i == 14)
                _append_char(out, ':');
            continue;
        }

        /* Print the colon between numbers. Fence-post alert: only colons
         * between numbers are printed, not at the beginning or end of the
         * stirng */
        if (i)
            _append_char(out, ':');

        /* Print the digits. Leading zeroes are not printed */
        if (n >> 12)
            _append_char(out, hex[(n >> 12) & 0xF]);
        if (n >> 8)
            _append_char(out, hex[(n >> 8) & 0xF]);
        if (n >> 4)
            _append_char(out, hex[(n >> 4) & 0xF]);
        _append_char(out, hex[(n >> 0) & 0xF]);
    }
}

/**
 * Like ctype's isprint(), but the charset is ASCII, because the external
 * network is defined to be ASCII, while the internal charset isn't always
 * ASCII. For example, IBM mainframes still use EBCDIC, so the value of
 * the constant 'A' in code isn't 0x41. Thus, while isalpha('A') is always
 * true, isalpha(0x41) changes depending upon the internal charset.
 */
static int
_isprint(int c)
{
    return (c >= 32 && c <= 126);
}

/**
 * Whether the entire string is alphanumberic. Like elsewhere,
 * this deals with actual ASCII that might appear on the wire,
 * rather than some local character set.
 */
static int
_is_all_alnum(const unsigned char *str, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        unsigned char c = str[i];

        /* is digit */
        if (0x30 <= c && c <= 0x39)
            continue;

        /* is upper */
        if (0x41 <= c && c <= 0x5a)
            continue;

        /* is lower */
        if (0x61 <= c && c <= 0x7a)
            continue;

        /* something else */
        return 0;
    }
    return 1;
}

/**
 * Convert an external character that is in ASCII into an internal character
 * set, which on IBM mainframes may be EBCDIC.
 */
static char
_print(unsigned char c)
{
    static const char ascii[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ' ', '!', '\"', '#',
        '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
        '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[',
        '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
        'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'x', 'y', 'z', '{', '|', '}', '~', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    return ascii[c];
}

/**
 * Strings in DNS have a special format.
 */
static void
_append_dnstring(
    const unsigned char *str, size_t count, stream_t *out, int is_quoted)
{
    size_t i;

    /* In DNS, "<character-string>" may or may not be quoted. If it contains
     * only letters/digits, then it doesn't need quotes, otherwise it does.
     * In some cases, like TXT records, we always want to quote it anyway.
     * In other fields, we expected the contents to not be quoted,
     * like CAA tag strings. */
    if (!is_quoted) {
        if (!_is_all_alnum(str, count) || count == 0)
            is_quoted = 1;
    }

    if (is_quoted)
        _append_char(out, '\"');

    for (i = 0; i < count; i++) {
        unsigned char c = str[i];

        if (c == '\"' || c == '\\') {
            /* quotes and backslashes need to be escaped */
            _append_char(out, '\\');
            _append_char(out, c);
        } else if (!_isprint(c)) {
            /* non-printable characters need to be printed as escaped octal */
            _append_char(out, '\\');
            _append_char(out, '0' + (c >> 6));
            _append_char(out, '0' + ((c >> 3) & 0x7));
            _append_char(out, '0' + (c & 0x7));
        } else {
            _append_char(out, _print(c));
        }
    }

    if (is_quoted)
        _append_char(out, '\"');
}

/* declared in `dns-format.h` */
int
dns_format_rdata(const struct dnsrrdata_t *rr, char *dst, size_t dst_length)
{
    stream_t out[1];
    size_t i;

    /* Initialize this object for appending characters to the output buffer
     * without overflowing */
    out->buf = dst;
    out->offset = 0;
    out->length = dst_length;

    /*
     * Format the field according to RFC 1035 specification for how zone
     * files should format these fields.
     */
    switch (rr->rtype) {
    case DNS_T_A: /* A */
        /* Four bytes of an IPv4 address
         *  google.com	A	IN	64.233.185.100
         */
        {
            unsigned ip = rr->a.ipv4;
            _append_decimal(out, (ip >> 24) & 0xFF);
            _append_char(out, '.');
            _append_decimal(out, (ip >> 16) & 0xFF);
            _append_char(out, '.');
            _append_decimal(out, (ip >> 8) & 0xFF);
            _append_char(out, '.');
            _append_decimal(out, (ip >> 0) & 0xFF);
        }
        break;

    case DNS_T_NS: /* NS - name server */
        /* A single DNS name. This may be a compressed or partially-compressed
         * name.
         *   google.com IN NS ns2.google.com.
         */
        _append_string(out, rr->ns.name);
        break;

    case DNS_T_CNAME: /* CNAME - canonical name */
        _append_string(out, rr->cname.name);
        break;

    case DNS_T_SOA: /* SOA - Start of zone Authority  */
        _append_string(out, rr->soa.mname);
        _append_char(out, ' ');
        _append_string(out, rr->soa.rname);
        _append_char(out, ' ');

        _append_decimal(out, rr->soa.serial);
        _append_char(out, ' ');
        _append_decimal(out, rr->soa.refresh);
        _append_char(out, ' ');
        _append_decimal(out, rr->soa.retry);
        _append_char(out, ' ');
        _append_decimal(out, rr->soa.expire);
        _append_char(out, ' ');
        _append_decimal(out, rr->soa.minimum);
        break;
            
    case DNS_T_PTR: /* PTR - pointer (reverse lookup) */
        _append_string(out, rr->ptr.name);
        break;
            
    case DNS_T_HINFO: /* RFC 1035 - HINFO - Host Info. */
        _append_dnstring(rr->hinfo.cpu.buf, rr->hinfo.cpu.length, out, 0);
        _append_char(out, ' ');
        _append_dnstring(rr->hinfo.os.buf, rr->hinfo.os.length, out, 0);
        break;

    case DNS_T_MX: /* MX - mail exhchange*/
        _append_decimal(out, rr->mx.priority);
        _append_char(out, ' ');
        _append_string(out, rr->mx.name);
        break;

    case DNS_T_SPF: /* SPF - same as text */
    case DNS_T_TXT: /* TXT - text records */
        for (i = 0; i < rr->txt.count; i++) {
            /* Put a space in front of every field, except the first one */
            if (i > 0) {
                _append_char(out, ' ');
            }

            /* Copy over all the characters. Special characters need to
             * be escaped. */
            _append_dnstring(
                rr->txt.array[i].buf, rr->txt.array[i].length, out, 1);
        }
        break;

    case DNS_T_RP: /* RP - Responsible Person */
        _append_string(out, rr->rp.mbox_dname);
        _append_char(out, ' ');
        _append_string(out, rr->rp.txt_dname);
        break;

    case DNS_T_AAAA: /* AAAA - an IPv6 address */
        _append_ipv6(out, rr->aaaa.ipv6);
        break;

    case DNS_T_SRV:
        _append_decimal(out, rr->srv.priority);
        _append_char(out, ' ');
        _append_decimal(out, rr->srv.weight);
        _append_char(out, ' ');
        _append_decimal(out, rr->srv.port);
        _append_char(out, ' ');
        _append_string(out, rr->srv.name);
        break;

    case DNS_T_NAPTR: /* RFC 2915 - NAPTR - Naming Authority Pointer for SIP */
        _append_decimal(out, rr->naptr.order);
        _append_char(out, ' ');
        _append_decimal(out, rr->naptr.preference);
        _append_char(out, ' ');
        _append_dnstring(rr->naptr.flags.buf, rr->naptr.flags.length, out, 1);
        _append_char(out, ' ');
        _append_dnstring(rr->naptr.service.buf, rr->naptr.service.length, out, 1);
        _append_char(out, ' ');
        _append_dnstring(rr->naptr.regexp.buf, rr->naptr.regexp.length, out, 1);
        _append_char(out, ' ');
        _append_string(out, rr->naptr.replacement);
        break;
            
    case DNS_T_DS:
    case DNS_T_CDS:
        _append_decimal(out, rr->ds.key_tag);
        _append_char(out, ' ');

        _append_decimal(out, rr->ds.algorithm);
        _append_char(out, ' ');

        _append_decimal(out, rr->ds.digest_type);
        _append_char(out, ' ');

        _append_hexdump(out, rr->ds.digest, rr->ds.length);
        break;

    case DNS_T_SSHFP:
        _append_decimal(out, rr->sshfp.algorithm);
        _append_char(out, ' ');

        _append_decimal(out, rr->sshfp.fp_type);
        _append_char(out, ' ');

        _append_hexdump(out, rr->sshfp.fingerprint, rr->sshfp.length);
        break;

    case DNS_T_RRSIG: /*  */
        _append_string(out, dns_name_from_rrtype(rr->rrsig.type));
        _append_char(out, ' ');

        _append_decimal(out, rr->rrsig.algorithm);
        _append_char(out, ' ');

        _append_decimal(out, rr->rrsig.labels);
        _append_char(out, ' ');

        _append_decimal(out, rr->rrsig.ttl);
        _append_char(out, ' ');

        _append_decimaltime(out, rr->rrsig.expiration);
        _append_char(out, ' ');

        _append_decimaltime(out, rr->rrsig.inception);
        _append_char(out, ' ');

        _append_decimal(out, rr->rrsig.keytag);
        _append_char(out, ' ');

        _append_string(out, rr->rrsig.name);
        _append_char(out, ' ');

        _append_base64(out, rr->rrsig.sig, rr->rrsig.length);
        break;
            
    case DNS_T_NSEC:
        _append_string(out, rr->nsec.name);
        {
            size_t j;
            for (j=0; j<rr->nsec.types_count; j++) {
                _append_char(out, ' ');
                _append_string(out, dns_name_from_rrtype(rr->nsec.types[j]));
            }
        }
        break;

    case DNS_T_DNSKEY:
    case DNS_T_CDNSKEY:
        _append_decimal(out, rr->dnskey.flags);
        _append_char(out, ' ');

        _append_decimal(out, rr->dnskey.protocol);
        _append_char(out, ' ');

        _append_decimal(out, rr->dnskey.algorithm);
        _append_char(out, ' ');

        _append_base64(out, rr->dnskey.publickey, rr->dnskey.length);
        break;

    case DNS_T_NSEC3PARAM:
        _append_decimal(out, rr->nsec3param.algorithm);
        _append_char(out, ' ');

        _append_decimal(out, rr->nsec3param.flags);
        _append_char(out, ' ');

        _append_decimal(out, rr->nsec3param.iterations);
        _append_char(out, ' ');

        if (rr->nsec3param.salt_length == 0) {
            _append_string(out, "\"-\"");
        } else {
            _append_hexdump(
                out, rr->nsec3param.salt, rr->nsec3param.salt_length);
        }
        break;

    case DNS_T_CAA: /* certficate authority */
        _append_decimal(out, rr->caa.flags);
        _append_char(out, ' ');

        _append_dnstring(
            (const unsigned char *)rr->caa.tag, rr->caa.taglength, out, 0);
        _append_char(out, ' ');

        _append_dnstring(rr->caa.value, rr->caa.length, out, 0);
        break;

    default:
        return dns_format_rdata_generic(rr->unknown.buf, rr->unknown.length, dst, dst_length);
    }

    return 0;
}

/* declared in `dns-format.h` */
int
dns_format_rdata_generic(const unsigned char *src, size_t length, char *dst, size_t dst_length)
{
    stream_t out[1];

    /* Initialize this object for appending characters to the output buffer
     * without overflowing */
    out->buf = dst;
    out->offset = 0;
    out->length = dst_length;

    /* RFC 3597 - Handling of Unknown DNS RR Types
     *   According to this RFC, if we don't know the specific format for
     *   the type, we can dump it as "\#" string, followed by the length,
     *   followed by hex. For example a IN A record (an IPv4 address)
     *   can be represented as:
     *       CLASS1 TYPE1 \# 4 0A000001
     */
    _append_char(out, '\\');
    _append_char(out, '#');
    _append_char(out, ' ');
    _append_decimal(out, length);
    _append_char(out, ' ');
    _append_hexdump(out, src, length);

    if (out->offset >= out->length)
        return -1;
    else
        return 0;
}
