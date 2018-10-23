/**
 * Utilities to make userfaultfd bearable.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/14/2018
 */

#ifndef _USERFAULTFD_H
#define _USERFAULTFD_H

#include <unistd.h>

namespace chameleon {
namespace uffd {

/**
 * Perform the userfaultfd API handshake with the kernel.  If arguments are
 * non-null, store the features & ioctls supported by the kernel.
 * @param fd userfaultfd file descriptor
 * @param features (OPTIONAL) a pointer to features bitmask to be populated
 * @param ioctls (OPTIONAL) a pointer to ioctls bitmask to be populated
 * @return true if handshake was successful or false otherwise
 */
bool api(int fd, uint64_t *features, uint64_t *ioctls);

/**
 * Register a memory region for fault handling.  If not already page aligned &
 * page sized, rounds addr down and len up to the nearest page size.
 * @param fd userfaultfd file descriptor
 * @param addr starting address of virtual memory region
 * @param len length of virtual memory region
 * @return true if successfully registered or false otherwise
 */
bool registerRegion(int fd, uintptr_t addr, uint64_t len);

/**
 * Handle a fault by copying a user-supplied buffer into the faulting page.
 *
 * Note: the user-supplied buffer *must* be at least a page in size
 *
 * @param fd userfaultfd file descriptor
 * @param src the source of the copy, i.e., address of the buffer containing
 *            data to copy into the faulting page
 * @param dest the destination of the copy, i.e., the address of the page in
 *             the application that cause the fault
 * @return true if successfully copied or false otherwise
 */
bool copy(int fd, uintptr_t src, uintptr_t dest);

}
}

#endif /* _USERFAULTFD_H */

