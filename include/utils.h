/**
 * Useful utilities not covered in other files.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/17/2018
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>

/* Check if a value is within a region */
#define CONTAINS( val, start, len ) (start <= val && val < (start + len))

/* Rounding for positive values and positive power-of-2 sizes */
#define ROUND_DOWN( val, size ) ((val) & -(size))
#define ROUND_UP( val, size ) ROUND_DOWN((val) + ((size)-1), size)

#define PAGESZ 4096UL

/* Align symbol definition to page boundary */
#define PAGE_ALIGNED __attribute__((aligned(PAGESZ)))

/* Page rounding */
#define PAGE_DOWN( val ) ROUND_DOWN(val, PAGESZ)
#define PAGE_UP( val ) ROUND_UP(val, PAGESZ)

/* Calculate page-aligned length from non-aligned address and length */
#define PAGE_ALIGN_LEN( addr, len ) (PAGE_UP(addr + len) - PAGE_DOWN(addr))

/* Mask to only keep page offset bits (i.e., keep lower bits) */
#define PAGE_OFFSET_BITS( addr ) (addr & (PAGESZ-1))

#endif /* _UTILS_H */

