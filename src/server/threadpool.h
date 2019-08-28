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
 * Shut down threadpool.
 * Only call if it has been initialized before.
 */
void threadpool_close();

/**
 * Block until all threads spawned have exited
 */
void threadpool_waitEmpty();

/**
 * Run a thread using the thread pool.
 * @param startRoutine function to run in new thread
 * @param arg argument to pass to thead
 * @return true if thread was started
 */
bool threadpool_run(void *(*startRoutine)(void *), void *arg);

#endif

