#include "types.h"

using namespace chameleon;

const char *chameleon::retText(ret_t retcode) {
  switch(retcode) {
  default: return "(unknown)";
  case Success: return "success";
#define X(code, desc) case code: return desc;
  BINARY_RETCODES
  PROCESS_RETCODES
  TRANSFORM_RETCODES
#undef X
  }
}

