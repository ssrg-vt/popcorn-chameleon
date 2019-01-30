#include <cstring>
#include <unistd.h>
#include <sys/syscall.h>

#include "alarm.h"
#include "log.h"

using namespace chameleon;

static void *alarmLoop(void *rawArgs) {
  int sig;
  sigset_t alarmSig;
  struct Alarm::handlerArgs *args = (struct Alarm::handlerArgs *)rawArgs;
  pid_t me = syscall(SYS_gettid);
  ret_t code = ret_t::Success;

  // Allow the alarm object to cancel the thread at any point
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

  // Unblock SIGALRM & notify main thread we're ready
  sigemptyset(&alarmSig);
  sigaddset(&alarmSig, SIGALRM);
  if(sigprocmask(SIG_UNBLOCK, &alarmSig, nullptr))
    __atomic_store_n(&args->finished, true, __ATOMIC_RELEASE);
  if(sem_post(&args->init) || args->finished)
    return (void *)ret_t::AlarmHandlerStartFailed;

  DEBUGMSG("chameleon thread " << me << " is handling alarms" << std::endl);

  while(!__atomic_load_n(&args->finished, __ATOMIC_ACQUIRE)) {
    if(sigwait(&alarmSig, &sig) || sig != SIGALRM) {
      code = ret_t::AlarmHandlerWaitFailed;
      break;
    }

    DEBUGMSG_VERBOSE(me << ": handling alarm" << std::endl);
    args->callback(args->callbackData);
  }

  return (void *)code;
}

ret_t Alarm::initAlarmSignaling() {
  sigset_t mask;
  struct sigaction sa;
  static auto sigHandler = [](int signal){};

  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  if(sigprocmask(SIG_BLOCK, &mask, &sa.sa_mask)) {
    DEBUGMSG("could not block alarm signal in main thread: " << strerror(errno)
             << std::endl);
    return ret_t::AlarmInitFailed;
  }

  sa.sa_handler = sigHandler;
  if(sigaction(SIGALRM, &sa, nullptr)) {
    DEBUGMSG("could not register alarm signal handler: " << strerror(errno)
             << std::endl);
    return ret_t::AlarmInitFailed;
  }

  return ret_t::Success;
}

void Alarm::clearFields() {
  set = false;
  period = 0;
  args.finished = false;
  args.callback = nullptr;
  args.callbackData = nullptr;
}

ret_t
Alarm::initialize(uint64_t milli, AlarmFunc callback, void *callbackData) {
  struct sigevent se;

  if(!milli || !callback) {
    DEBUGMSG("specified alarm with 0 us period or null callback" << std::endl);
    return ret_t::InvalidAlarm;
  }

  memset(&se, 0, sizeof(struct sigevent));

  // Set up a timer for SIGALRM
  se.sigev_notify = SIGEV_SIGNAL;
  se.sigev_signo = SIGALRM;
  if(timer_create(CLOCK_MONOTONIC, &se, &t)) {
    DEBUGMSG("could not instantiate timer");
    return ret_t::AlarmInitFailed;
  }

  if(sem_init(&args.init, 0, 0)) {
    timer_delete(t);
    DEBUGMSG("could not initalize alarm thread semaphore" << std::endl);
    return ret_t::AlarmInitFailed;
  }

  period = milli;
  args.callback = callback;
  args.callbackData = callbackData;
  return ret_t::Success;
}

static inline void milli2Timespec(uint64_t milli, struct timespec &ts) {
  uint64_t nano = milli * 1000000;
  ts.tv_sec = nano / 1000000000UL;
  ts.tv_nsec = nano % 1000000000UL;
}

ret_t Alarm::start() {
  struct itimerspec ts;
  union {
    void *p;
    ret_t code;
  } ret;

  // Create thread & wait for it to unblock alarm signal
  if(pthread_create(&handler, nullptr, alarmLoop, &args)) {
    DEBUGMSG("could not instantiate alarm handling thread" << std::endl);
    return ret_t::AlarmStartFailed;
  }

  if(sem_wait(&args.init)) {
    DEBUGMSG("could not wait for thread to unblock alarm signal" << std::endl);
    pthread_cancel(handler);
    pthread_join(handler, nullptr);
    return ret_t::AlarmStartFailed;
  }
  else if(__atomic_load_n(&args.finished, __ATOMIC_ACQUIRE)) {
    // The thread couldn't initialize and exited
    pthread_join(handler, &ret.p);
    DEBUGMSG("alarm handler couldn't initialize: " << retText(ret.code)
             << std::endl);
    return ret_t::AlarmStartFailed;
  }

  milli2Timespec(period, ts.it_value);
  milli2Timespec(period, ts.it_interval);
  if(timer_settime(t, 0, &ts, nullptr)) {
    DEBUGMSG("could not set periodic timer: " << strerror(errno) << std::endl);
    pthread_cancel(handler);
    pthread_join(handler, nullptr);
    return ret_t::AlarmStartFailed;
  }

  DEBUGMSG("alarm period is " << period << " ms" << std::endl);

  set = true;
  return ret_t::Success;
}

ret_t Alarm::stop() {
  struct itimerspec ts;
  union {
    void *p;
    ret_t code;
  } ret;

  if(set) {
    // Set the flag telling the handler to exit.  Let the alarm keep going
    // until the thread exits, otherwise we may race with the thread calling
    // sigwait() leading to deadlock.
    __atomic_store_n(&args.finished, true, __ATOMIC_RELEASE);
    pthread_kill(handler, SIGALRM); // Kick it in case of a long wait period
    if(pthread_join(handler, &ret.p)) {
      DEBUGMSG("could not join alarm thread" << std::endl);
      return ret_t::AlarmStopFailed;
    }

    if(ret.code != ret_t::Success)
      WARN("Alarm thread returned an error: " << retText(ret.code) << std::endl);

    // Stop & delete timer
    milli2Timespec(0, ts.it_value);
    milli2Timespec(0, ts.it_interval);
    if(timer_settime(t, 0, &ts, nullptr) || timer_delete(t)) {
      DEBUGMSG("could not stop/delete periodic timer: "
               << strerror(errno) << std::endl);
      return ret_t::AlarmStopFailed;
    }

    if(sem_destroy(&args.init)) return ret_t::AlarmStopFailed;
  }

  clearFields();
  return ret_t::Success;
}

