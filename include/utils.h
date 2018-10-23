/**
 * Useful utilities not covered in other files.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/17/2018
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>

#define PAGESZ 4096UL

#define PAGE_ALIGNED __attribute__((aligned(PAGESZ)))

/* Page rounding */
#define PAGE_DOWN( val ) ((val) & -PAGESZ)
#define PAGE_UP( val ) PAGE_DOWN((val) + (PAGESZ-1))

/* Calculate page-aligned length from non-aligned address and length */
#define PAGE_ALIGN_LEN( addr, len ) (PAGE_UP(addr + len) - PAGE_DOWN(addr))

#endif /* _UTILS_H */

