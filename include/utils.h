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

#endif /* _UTILS_H */

