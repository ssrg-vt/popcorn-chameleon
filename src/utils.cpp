#include <cerrno>
#include <syscall.h>
#include <unistd.h>
#include <linux/futex.h>

#include "utils.h"

using namespace chameleon;

ret_t chameleon::syncWait(int *key, int val) {
  int ret = syscall(SYS_futex, key, FUTEX_WAIT, val, nullptr, nullptr, 0);
  if(ret && ret != EAGAIN) return ret_t::FutexFailed;
  else return ret_t::Success;
}

ret_t chameleon::syncWake(int *key) {
  if(syscall(SYS_futex, key, FUTEX_WAKE, INT32_MAX)) return ret_t::FutexFailed;
  else return ret_t::Success;
}

