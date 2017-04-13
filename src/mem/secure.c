/**
 * @file mem/secure.c  Secure memory functions
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <re_types.h>
#include <re_mem.h>


#define DEBUG_MODULE "mem"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/**
 * Compare two byte strings in constant time.
 *
 * @param s1 First byte string
 * @param s2 Second byte string
 * @param n  Number of bytes
 *
 * @return a negative number if argument errors
 *         0 if both byte strings matching
 *         a positive number if not matching
 */
int secure_compare(const volatile uint8_t *volatile s1,
		   const volatile uint8_t *volatile s2,
		   size_t n)
{
	uint8_t val = 0;

	if (!s1 || !s2 || !n)
		return -1;

	while (n--)
		val |= *s1++ ^ *s2++;

	return val;
}


void secure_memclear(volatile uint8_t *volatile p, size_t n)
{
	if (!p || !n)
		return;

	while (n--)
		*p++ = 0;
}
