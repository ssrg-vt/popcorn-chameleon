/**
 * Periodic alarm functionality for Chameleon.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 1/30/2019
 */

#ifndef _ALARM_H
#define _ALARM_H

#include <csignal>
#include <ctime>
#include <pthread.h>
#include <semaphore.h>

#include "types.h"

namespace chameleon {

/**
 * class Alarm
 *
 * Implement creating, triggering and destroying periodic alarms.  Alarms are
 * handled in a dedicated thread and call user-supplied functions.
 *
 * Note: currently Alarm only supports a single periodic alarm -- don't
 * instantiate/start more than one!
 */
class Alarm {
public:
  /* Callback invoked when alarm triggers */
  typedef void (*AlarmFunc)(void *data);

  /* Arguments passed to alarm handling thread */
  struct handlerArgs {
    sem_t init;
    bool finished;
    AlarmFunc callback;
    void *callbackData;
  };

  /**
   * Prepare the application for alarm signalling by changing the alarm
   * signal's disposition and masking the alarm signal to avoid accidentally
   * delivering alarms to non-alarm-handling threads.  Threads handling alarms
   * will unblock the alarm signal for their own masks.
   *
   * Note: should be called before spawning any other threads, as they'll
   * inherit the signal mask!
   *
   * @return a return code describing the outcome
   */
  static ret_t initAlarmSignaling();

  Alarm() { clearFields(); }
  ~Alarm() { stop(); }

  /**
   * Initialize a periodic alarm.  Does *not* start the alarm; users must call
   * start().
   *
   * @param milli alarm period in milliseconds
   * @param callback function invoked when the alarm triggers
   * @param callbackData data supplied to the callback
   * @return a return code describing the outcome
   */
  ret_t initialize(uint64_t milli, AlarmFunc callback, void *callbackData);

  /**
   * Start the alarm.  Alarm will trigger periodically and call the callback
   * passed to initialize() until users call stop().
   *
   * @return a return code describing the outcome
   */
  ret_t start();

  /**
   * Stop the alarm and clean up the alarm handler.
   * @return a return code describing the outcome
   */
  ret_t stop();

private:
  /* Is the alarm set & running? */
  bool set;

  /* POSIX timer handle & interval */
  timer_t t;
  uint64_t period; /* in milliseconds */

  /* Thread dedicated to handling alarm signals and other required info */
  pthread_t handler;
  handlerArgs args;

  /**
   * Reset implementation-internal fields.
   */
  void clearFields();
};

}

#endif /* _ALARM_H */

