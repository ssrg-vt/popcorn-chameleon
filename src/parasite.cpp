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
  chameleon_parasite_setup_c_header(ctx);
  if(compel_infect(ctx, nthreads, sizeof(parasiteArgs)))
    return ret_t::CompelInfectFailed;
  else return ret_t::Success;
}

int parasite::stealUFFD(struct parasite_ctl *ctx) {
  int uffd;
  if(compel_rpc_call(GET_UFFD, ctx) ||
     compel_util_recv_fd(ctx, &uffd) ||
     compel_rpc_sync(GET_UFFD, ctx)) return -1;
  return uffd;
}

ret_t parasite::cure(struct parasite_ctl **ctx)
{
  if(compel_cure(*ctx) == 0) {
    ctx = nullptr;
    return ret_t::Success;
  }
  else return ret_t::CompelCureFailed;
}

ret_t parasite::syscall(struct parasite_ctl *ctx, long syscall, long &sysRet,
                        long a1, long a2, long a3, long a4, long a5, long a6) {
  int ret = compel_syscall(ctx, syscall, &sysRet, a1, a2, a3, a4, a5, a6);
  return ret == 0 ? ret_t::Success : ret_t::CompelSyscallFailed;
}

uintptr_t parasite::infectAddress(struct parasite_ctl *ctx) {
  struct infect_ctx *ictx = compel_infect_ctx(ctx);
  if(ictx) return ictx->syscall_ip;
  else return 0;
}

