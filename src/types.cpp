#include "types.h"

using namespace chameleon;

const char *chameleon::retText(ret_t retcode) {
  switch(retcode) {
  default: return "(unknown)";
  case Success: return "success";
#define X(code, desc) case code: return desc;
  PROCESS_RETCODES
#undef X
  }
}

