#ifndef UTIL_SIPHASH24_H
#define UTIL_SIPHASH24_H
#include <stdint.h>
#include <stddef.h>

uint64_t siphash24(const void *buf, size_t length, const uint64_t key[2]);

/**
 * Unit-test this module.
 * @return
 *      0 on success, a positive integer otherwise.
 */
int siphash24_selftest(void);

#endif
