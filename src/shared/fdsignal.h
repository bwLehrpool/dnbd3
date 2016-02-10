#ifndef _FD_SIGNAL_H_
#define _FD_SIGNAL_H_

#define SIGNAL_OK (0)
#define SIGNAL_TIMEOUT (-2)
#define SIGNAL_ERROR (-1)

typedef struct _dnbd3_signal dnbd3_signal_t;

/**
 * Create a new signal, nonblocking.
 * @return NULL on error, pointer to dnbd3_signal_t on success.
 */
dnbd3_signal_t* signal_new();

/**
 * Create a new signal, blocking.
 * @return NULL on error, pointer to dnbd3_signal_t on success.
 */
dnbd3_signal_t* signal_newBlocking();

/**
 * Trigger the given signal, so a wait or clear call will succeed.
 * @return SIGNAL_OK on success, SIGNAL_ERROR on error
 */
int signal_call(const dnbd3_signal_t* const signal);

/**
 * Wait for given signal, with an optional timeout.
 * If timeout == 0, just poll once.
 * If timeout < 0, wait forever.
 * @return > 0 telling how many times the signal was called,
 *    SIGNAL_TIMEOUT if the timeout was reached,
 *    SIGNAL_ERROR if some error occured
 */
int signal_wait(const dnbd3_signal_t* const signal, int timeoutMs);

/**
 * Clears any pending signals on this signal.
 * @return number of signals that were pending,
 *    SIGNAL_ERROR if some error occured
 */
int signal_clear(const dnbd3_signal_t* const signal);

/**
 * Close the given signal.
 */
void signal_close(const dnbd3_signal_t* const signal);

/**
 * Get a file descriptor for the given signal that can be
 * waited on using poll or similar.
 * @return -1 if the signal is invalid
 */
int signal_getWaitFd(const dnbd3_signal_t* const signal);

#endif
