/**
 * class CodeTransformer
 *
 * Implements reading & transforming code as read in through the userfaulfd
 * mechanism.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/15/2018
 */

#ifndef _TRANSFORM_H
#define _TRANSFORM_H

#include <thread>

#include "binary.h"
#include "types.h"
#include "userfaultfd.h"

namespace chameleon {

class CodeTransformer {
public:
  /**
   * Construct a code transformer with a userfaultfd file descriptor.  Does not
   * initialize the transformer; users must call initialize().
   *
   * @param bin name of binary containing transformation metadata
   * @param uffd a userfaultfd file descriptor
   */
  CodeTransformer(const char *bin, int uffd) : binary(bin), uffd(uffd) {}
  CodeTransformer() = delete;

  /**
   * Initialize the code transformer object.
   * @return a return code describing the outcome
   */
  ret_t initialize();

private:
  /* Binary containing transformation metadata */
  Binary binary;

  /* userfaultfd file descriptor */
  int uffd;

  /* Thread responsible for reading & responding to page faults */
  std::thread faultHandler;
};

}

#endif /* _TRANSFORM_H */

