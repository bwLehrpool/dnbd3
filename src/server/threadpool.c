#include "globals.h"
#include "helper.h"
#include "threadpool.h"
#include "signal.h"
#include "locks.h"
#include <pthread.h>


typedef struct _entry_t {
	struct _entry_t *next;
	pthread_t thread;
	int signalFd;
	void *(*startRoutine)(void *);
	void * volatile arg;
} entry_t;

static void *threadpool_worker(void *entryPtr);

static pthread_attr_t threadAttrs;

static int maxIdleThreads = -1;
static entry_t *pool = NULL;
static pthread_spinlock_t poolLock;

bool threadpool_init(int maxIdle)
{
	if ( maxIdle < 0 || maxIdleThreads >= 0 ) return false;
	maxIdleThreads = maxIdle;
	spin_init( &poolLock, PTHREAD_PROCESS_PRIVATE );
	pthread_attr_init( &threadAttrs );
	pthread_attr_setdetachstate( &threadAttrs, PTHREAD_CREATE_DETACHED );
	return true;
}

bool threadpool_run(void *(*startRoutine)(void *), void *arg)
{
	spin_lock( &poolLock );
	entry_t *entry = pool;
	if ( entry != NULL ) pool = entry->next;
	spin_unlock( &poolLock );
	if ( entry == NULL ) {
		entry = (entry_t*)malloc( sizeof(entry_t) );
		entry->signalFd = signal_new();
		if ( entry->signalFd < 0 ) {
			printf( "[WARNING] Could not create signalFd for new thread pool thread\n" );
			return false;
		}
		if ( 0 != thread_create( &(entry->thread), &threadAttrs, threadpool_worker, (void*)entry ) ) {
			printf( "[WARNING] Could not create new thread for thread pool\n" );
			signal_close( entry->signalFd );
			free( entry );
			return false;
		}
		printf( "[DEBUG] Thread created!\n" );
	}
	entry->next = NULL;
	entry->startRoutine = startRoutine;
	entry->arg = arg;
	signal_call( entry->signalFd );
	return true;
}

/**
 * This is a worker thread of our thread pool.
 */
static void *threadpool_worker(void *entryPtr)
{
	blockNoncriticalSignals();
	entry_t *entry = (entry_t*)entryPtr;
	while ( !_shutdown ) {
		// Wait for signal from outside that we have work to do
		int ret = signal_wait( entry->signalFd, -1 );
		if ( ret > 0 ) {
			if ( entry->startRoutine == NULL ) {
				printf( "[DEBUG] Worker woke up but has no work to do!\n" );
				continue;
			}
			// Start assigned work
			(*entry->startRoutine)( entry->arg );
			// Reset vars for safety
			entry->startRoutine = NULL;
			entry->arg = NULL;
			// Put thread back into pool if there are less than maxIdleThreds threads, just die otherwise
			int threadCount = 0;
			spin_lock( &poolLock );
			entry_t *ptr = pool;
			while ( ptr != NULL ) {
				threadCount++;
				ptr = ptr->next;
			}
			if ( threadCount >= maxIdleThreads ) {
				spin_unlock( &poolLock );
				signal_close( entry->signalFd );
				free( entry );
				printf(" [DEBUG] Thread killed!\n" );
				return NULL;
			}
			entry->next = pool;
			pool = entry;
			spin_unlock( &poolLock );
			setThreadName( "[pool]" );
		} else {
			printf( "[DEBUG] Unexpected return value %d for signal_wait in threadpool worker!\n", ret );
		}
	}
	return NULL;
}

