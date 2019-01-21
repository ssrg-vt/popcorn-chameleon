#include <sys/ioctl.h>
#include <linux/userfaultfd.h>

#include "log.h"
#include "userfaultfd.h"
#include "utils.h"

using namespace chameleon;

#define MASK( bm, feat ) ((bm) & (feat) ? 1 : 0)

static inline void printFeatures(uint64_t features) {
  // From the manpages (ioctl_userfaultfd):
  //   "For Linux kernel versions before 4.11 ... zero (i.e., no feature bits)
  //    is placed in the features field by the kernel upon return from ioctl."
  DEBUGMSG("features (0x" << std::hex << features << "):" << std::endl);
  DEBUGMSG("  UFFD_FEATURE_PAGEFAULT_FLAG_WP: "
           << MASK(features, UFFD_FEATURE_PAGEFAULT_FLAG_WP) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_EVENT_FORK: "
           << MASK(features, UFFD_FEATURE_EVENT_FORK) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_EVENT_REMAP: "
           << MASK(features, UFFD_FEATURE_EVENT_REMAP) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_EVENT_REMOVE: "
           << MASK(features, UFFD_FEATURE_EVENT_REMOVE) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_MISSING_HUGETLBFS: "
           << MASK(features, UFFD_FEATURE_MISSING_HUGETLBFS) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_MISSING_SHMEM: "
           << MASK(features, UFFD_FEATURE_MISSING_SHMEM) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_EVENT_UNMAP: "
           << MASK(features, UFFD_FEATURE_EVENT_UNMAP) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_SIGBUS: "
           << MASK(features, UFFD_FEATURE_SIGBUS) << std::endl);
  DEBUGMSG("  UFFD_FEATURE_THREAD_ID: "
           << MASK(features, UFFD_FEATURE_THREAD_ID) << std::endl);
}

static inline void printIoctls(uint64_t ioctls) {
  DEBUGMSG("ioctls (0x" << std::hex << ioctls << "):" << std::endl);
  DEBUGMSG("  UFFDIO_API: " << MASK(ioctls, 1UL << _UFFDIO_API) << std::endl);
  DEBUGMSG("  UFFDIO_REGISTER: " << MASK(ioctls, 1UL << _UFFDIO_REGISTER)
           << std::endl);
  DEBUGMSG("  UFFDIO_UNREGISTER: " << MASK(ioctls, 1UL << _UFFDIO_UNREGISTER)
           << std::endl);
  DEBUGMSG("  UFFDIO_WAKE: " << MASK(ioctls, 1UL << _UFFDIO_WAKE)
           << std::endl);
  DEBUGMSG("  UFFDIO_COPY: " << MASK(ioctls, 1UL << _UFFDIO_COPY)
           << std::endl);
  DEBUGMSG("  UFFDIO_ZEROPAGE: " << MASK(ioctls, 1UL << _UFFDIO_ZEROPAGE)
           << std::endl);
}

bool uffd::api(int fd, uint64_t *features, uint64_t *ioctls) {
  struct uffdio_api api;

  api.api = UFFD_API;
  api.features = 0;
  if(ioctl(fd, UFFDIO_API, &api) == -1 || api.api != UFFD_API) return false;
  if(features) *features = api.features;
  if(ioctls) *ioctls = api.ioctls;

  DEBUG(
    DEBUGMSG("requested userfaultfd API: " << UFFD_API
             << ", kernel responded: " << api.api << std::endl);
    DEBUG_VERBOSE(
      printFeatures(api.features);
      printIoctls(api.ioctls);
    )
  )

  return true;
}

bool uffd::registerRegion(int fd, uintptr_t addr, uint64_t len) {
  struct uffdio_register ctrl;

  ctrl.range.start = PAGE_DOWN(addr);
  ctrl.range.len = PAGE_ALIGN_LEN(addr, len);
  ctrl.mode = UFFDIO_REGISTER_MODE_MISSING;
  ctrl.ioctls = 0;
  if(ioctl(fd, UFFDIO_REGISTER, &ctrl) == -1) return false;

  DEBUG(
    DEBUGMSG("registered 0x" << std::hex << ctrl.range.start << " - "
             << ctrl.range.start + ctrl.range.len << " (size=" << std::dec
             << ctrl.range.len << ")" << std::endl);
    DEBUG_VERBOSE(printIoctls(ctrl.ioctls));
  )

  return true;
}

bool uffd::copy(int fd, uintptr_t src, uintptr_t dest) {
  struct uffdio_copy copy;
  copy.src = src;
  copy.dst = dest;
  copy.len = PAGESZ;
  copy.mode = 0;
  if(ioctl(fd, UFFDIO_COPY, &copy) == -1) return false;
  return true;
}

