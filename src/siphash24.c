/*
   SipHash reference C implementation

   Written in 2012 by
   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#include "siphash24.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)            \
    (p)[0] = (uint8_t)((v) >> 0);  \
    (p)[1] = (uint8_t)((v) >> 8);  \
    (p)[2] = (uint8_t)((v) >> 16); \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)              \
    U32TO8_LE((p), (uint32_t)((v))); \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                              \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8)             \
        | ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) \
        | ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) \
        | ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND(v0, v1, v2, v3) \
    {                            \
        v0 += v1;                \
        v1 = ROTL(v1, 13);       \
        v1 ^= v0;                \
        v0 = ROTL(v0, 32);       \
        v2 += v3;                \
        v3 = ROTL(v3, 16);       \
        v3 ^= v2;                \
        v0 += v3;                \
        v3 = ROTL(v3, 21);       \
        v3 ^= v0;                \
        v2 += v1;                \
        v1 = ROTL(v1, 17);       \
        v1 ^= v2;                \
        v2 = ROTL(v2, 32);       \
    }

/* SipHash-2-4 */
static uint64_t
crypto_auth(const unsigned char *buf,
    unsigned long long length, const unsigned char *key)
{
    /* "somepseudorandomlygeneratedbytes" */
    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;
    uint64_t b;
    uint64_t k0 = U8TO64_LE(key);
    uint64_t k1 = U8TO64_LE(key + 8);
    const uint8_t *end = buf + length - (length % sizeof(uint64_t));
    const int remaining_bytes = length & 7;

    b = ((uint64_t)length) << 56;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    /* Process input as a series of 64-bit integers, mixing
     * into the state variables */
    for (; buf != end; buf += 8) {
        uint64_t m;
        m = U8TO64_LE(buf);
        v3 ^= m;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= m;
    }

    /* Extract the remaining bytes as a 64-bit integer */
    switch (remaining_bytes) {
    case 7:
        b |= ((uint64_t)buf[6]) << 48;
        /* fall through */
    case 6:
        b |= ((uint64_t)buf[5]) << 40;
        /* fall through */
    case 5:
        b |= ((uint64_t)buf[4]) << 32;
        /* fall through */
    case 4:
        b |= ((uint64_t)buf[3]) << 24;
        /* fall through */
    case 3:
        b |= ((uint64_t)buf[2]) << 16;
        /* fall through */
    case 2:
        b |= ((uint64_t)buf[1]) << 8;
        /* fall through */
    case 1:
        b |= ((uint64_t)buf[0]);
        /* fall through */
    case 0:
        break;
    }

    /* Do the last (often incomplete) chunk of data */
    v3 ^= b;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= b;
    
    /* Finalize */
    v2 ^= 0xff;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    /* Convert the finalized state to the output number */
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t
siphash24(const void *in, size_t inlen, const uint64_t key[2])
{
    uint64_t result;

    result = crypto_auth((const unsigned char *)in, inlen,
        (const unsigned char *)&key[0]);

    return result;
}

/*
   SipHash-2-4 output with
   k = 00 01 02 ...
   and
   in = (empty string)
   in = 00 (1 byte)
   in = 00 01 (2 bytes)
   in = 00 01 02 (3 bytes)
   ...
   in = 00 01 02 ... 3e (63 bytes)
*/
static const uint64_t vectors[64] = { 0x726fdb47dd0e0e31, 0x74f839c593dc67fd,
    0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d, 0xcf2794e0277187b7,
    0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3,
    0xf4b32f46226bada7, 0x751e8fbc860ee5fb, 0x14ea5627c0843d90,
    0xf723ca908e7af2ee, 0xa129ca6149be45e5, 0x3f2acc7f57c29bdb,
    0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88,
    0xa80c038ccd5ccec8, 0xb8ad50c6f649af94, 0xbce192de8a85b8ea,
    0x17d835b85bbb15f3, 0x2f2e6163076bcfad, 0xde4daaaca71dc9a5,
    0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238,
    0x15e034d40fa197ae, 0x314dffbe0815a3b4, 0x027990f029623981,
    0xcadcd4e59ef40c4d, 0x9abfd8766a33735c, 0x0e3ea96b5304a7d0,
    0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510,
    0xd06c98cd5c0975eb, 0xe612a3cb9ecba951, 0xc766e62cfcadaf96,
    0xee64435a9752fe72, 0xa192d576b245165a, 0x0a8787bf8ecb74b2,
    0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013,
    0x6606d7e446282b93, 0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3,
    0xe51b38608ef25f57, 0x958a324ceb064572 };

static int
test_vectors(void)
{
    uint8_t buf[64];
    uint8_t key[16];
    size_t i;
    int is_okay = 1;

    for (i = 0; i < 16; ++i)
        key[i] = (uint8_t)i;

    for (i = 0; i < sizeof(buf); ++i) {
        uint64_t hash;

        buf[i] = (uint8_t)i;

        hash = crypto_auth(buf, i, key);

        if (hash != vectors[i]) {
            printf("test vector failed for %d bytes\n", (int)i);
            is_okay = 0;
        }
    }

    return is_okay;
}

int
siphash24_selftest(void)
{
    if (test_vectors())
        return 0; /* success */
    else
        return 1; /* failure */
}
