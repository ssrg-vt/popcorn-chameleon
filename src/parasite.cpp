// Note: compel headers are not compatible with C++ iostream header, do *not*
// include log.h!
#include <unistd.h>
#include <cassert>
extern "C" {
#include <compel/compel.h>
}

#pragma GCC diagnostic ignored "-Wnarrowing"
#include "chameleon-parasite.h"
#include "parasite.h"

using namespace chameleon;

struct parasite_ctl *parasite::initialize(int pid) {
  struct parasite_ctl *ctx = nullptr;
  struct infect_ctx *ictx;

  ctx = compel_prepare(pid);
  if(ctx) {
    ictx = compel_infect_ctx(ctx);
    assert(ictx && "No infect context for prepared parasite");
    ictx->log_fd = STDERR_FILENO;
  }

  return ctx;
}

ret_t
parasite::infect(struct parasite_ctl *ctx, size_t nthreads) {
  // TODO need to define the argument size
  chameleon_parasite_setup_c_header(ctx);
  if(compel_infect(ctx, nthreads, 0)) return ret_t::CompelInfectFailed;
  else return ret_t::Success;
}

ret_t parasite::syscall(struct parasite_ctl *ctx, long syscall,
                        long a1, long a2, long a3, long a4, long a5, long a6) {
  // TODO implement
  return ret_t::Success;
}

