#ifndef _SIGNAL_H_
#define _SIGNAL_H_

#define SIGNAL_OK (0)
#define SIGNAL_TIMEOUT (-2)
#define SIGNAL_ERROR (-1)

/**
 * Create a new signal fd (eventfd), nonblocking.
 * @return >= 0 on success, which is the fd; < 0 on error
 */
int signal_new();

/**
 * Trigger the given signal, so a wait or clear call will succeed.
 * @return SIGNAL_OK on success, SIGNAL_ERROR on error
 */
int signal_call(int signalFd);

/**
 * Wait for given signal, with an optional timeout.
 * If timeout == 0, just poll once.
 * If timeout < 0, wait forever.
 * @return > 0 telling how many times the signal was called,
 *    SIGNAL_TIMEOUT if the timeout was reached,
 *    SIGNAL_ERROR if some error occured
 */
int signal_wait(int signalFd, int timeoutMs);

/**
 * Clears any pending signals on this signal fd.
 * @return number of signals that were pending,
 *    SIGNAL_ERROR if some error occured
 */
int signal_clear(int signalFd);

/**
 * Close the given signal.
 */
void signal_close(int signalFd);

#endif

