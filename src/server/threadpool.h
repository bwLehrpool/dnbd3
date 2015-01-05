#ifndef _THREADPOOL_H_
#define _THREADPOOL_H_

#include "../types.h"

/**
 * Initialize the thread pool. This must be called before using
 * threadpool_run, and must only be called once.
 * @param maxIdleThreadCount maximum number of idle threads in the pool
 * @return true if initialized successfully
 */
bool threadpool_init(int maxIdleThreadCount);

/**
 * Run a thread using the thread pool.
 * @param startRoutine function to run in new thread
 * @param arg argument to pass to thead
 * @return true if thread was started
 */
bool threadpool_run(void *(*startRoutine)(void *), void *arg);

#endif

