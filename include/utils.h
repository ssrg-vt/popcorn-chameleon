/**
 * Useful utilities not covered in other files.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/17/2018
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <sys/types.h>

#include "types.h"

extern pid_t masterPID;

/*
 * Check if a value is within the region [start, start+len).  Note that all
 * values must either be signed integers or must be within a signed 64-bit
 * integer range.
 */
#define CONTAINS_ABOVE( val, start, len ) \
  ((int64_t)(start) <= (int64_t)(val) && \
   (int64_t)(val) < ((int64_t)(start) + (int64_t)(len)))

/*
 * Check if a value is within the region (start-len, start].  Note that all
 * values must either be signed integers or must be within a signed 64-bit
 * integer range.
 */
#define CONTAINS_BELOW( val, start, len ) \
  ((int64_t)(val) <= (int64_t)(start) && \
   (int64_t)(val) > ((int64_t)(start) - (int64_t)(len)))

/* Rounding for positive values and positive power-of-2 sizes */
#define ROUND_DOWN( val, size ) ((val) & -(size))
#define ROUND_UP( val, size ) ROUND_DOWN((val) + ((size)-1), size)

/* Mask all but unaligned bits for a given alignment */
#define MASK_ALIGNED( val, align ) (val & (align-1))

/* Return true if a value is at a specified alignment or false otherwise */
#define ALIGNED( val, align ) !MASK_ALIGNED(val, align)

#define PAGESZ 4096UL

/* Align symbol definition to page boundary */
#define PAGE_ALIGNED __attribute__((aligned(PAGESZ)))

/* Page rounding */
#define PAGE_DOWN( val ) ROUND_DOWN(val, PAGESZ)
#define PAGE_UP( val ) ROUND_UP(val, PAGESZ)

/* Calculate page-aligned length from non-aligned address and length */
#define PAGE_ALIGN_LEN( addr, len ) (PAGE_UP(addr + len) - PAGE_DOWN(addr))

/* Mask to only keep page offset bits (i.e., keep lower bits) */
#define PAGE_OFFSET_BITS( addr ) MASK_ALIGNED(addr, PAGESZ)

/*
 * Perform an expression (probably a C library or system call), masking EINTR
 * errors caused by SIGINT signals.
 *
 * Note: assumes the expressions returns 0 upon successfully completing
 */
#define MASK_INT( ... ) \
  ({ \
    int ret; \
    do { ret = __VA_ARGS__; } while(ret && errno == EINTR); \
    ret; \
  })

namespace chameleon {

/**
 * Binary search over a contiguous array of records.  Returns the index of the
 * matching record, or the record directly to the right in a sorted ordering if
 * no record matches.  Slightly more flexible than STL's binary search as users
 * can directly define the matching function, meaning it can be used to search
 * for values where the records have a range, e.g., a code range corresponding
 * to a function.
 *
 * Note: the records must have been previously sorted.
 *
 * @template T record type
 * @template V value type
 * @template matches the matching function
 * @template lessThan return whether the value would be in a record to the left
 *                    of a given record in a sorted ordering
 * @param records the array of records
 * @param nrecords number of records in the array
 * @param val the value to search for
 * @return the index of the matching record, the next highest record in the
 *         sorted ordering if no record matches, or -1 if there's no match and
 *         no record to the right
 */
template<typename T,
         typename V,
         bool (*matches)(const T *, const V),
         bool (*lessThan)(const T *, const V)>
static ssize_t findRight(const T *records, ssize_t nrecords, const V val) {
  ssize_t low = 0, high = nrecords - 1, mid;
  if(high < 0) return -1;
  do {
    mid = (high + low) / 2;
    if(matches(&records[mid], val)) return mid;
    else if(lessThan(&records[mid], val)) high = mid - 1;
    else low = mid + 1;
  } while(high >= low);

  // Didn't find the record, return the next highest one if available
  if(lessThan(&records[mid], val)) return mid;
  else if(mid < nrecords - 1) return mid + 1;
  else return -1;
}

/**
 * Sleep until somebody wakes people waiting on the key.  Returns immediately
 * if *key != val, i.e., somebody has already changed val.
 *
 * @param key key used to identify waiting threads
 * @param val value to check to see if thread should sleep
 * @return a return code describing the outcome
 */
ret_t syncWait(int *key, int val);

/**
 * Wake any threads waiting (sleeping) on key.
 * @param key key used to identify waiting threads
 * @return a return code describing the outcome
 */
ret_t syncWake(int *key);

}

#endif /* _UTILS_H */

