#include <thread>

#include "log.h"
#include "transform.h"
#include "userfaultfd.h"

using namespace chameleon;

static void handleFaultsAsync(CodeTransformer *CT) {
  
}

ret_t CodeTransformer::initialize() {
  ret_t retcode;
  if((retcode = binary.initialize()) != ret_t::Success) return retcode;
  const Binary::Section &code = binary.getCodeSection();

  if(!uffd::api(uffd, nullptr, nullptr)) return ret_t::UffdHandshakeFailed;
  /*if(!uffd::registerRegion(uffd, code.address(), code.size()))
    return ret_t::UffdRegisterFailed;
  faultHandler = std::thread(handleFaultsAsync, this);*/

  return ret_t::Success;
}

