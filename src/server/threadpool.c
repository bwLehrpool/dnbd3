#include "threadpool.h"
#include "globals.h"
#include "helper.h"
#include "locks.h"

typedef struct _entry_t {
	struct _entry_t *next;
	pthread_t thread;
	dnbd3_signal_t* signal;
	void *(*startRoutine)(void *);
	void * arg;
} entry_t;

static void *threadpool_worker(void *entryPtr);

static pthread_attr_t threadAttrs;

static int maxIdleThreads = -1;
static atomic_int currentIdleThreads = 0;
static entry_t *pool = NULL;
static pthread_spinlock_t poolLock;

bool threadpool_init(int maxIdle)
{
	if ( maxIdle < 0 || maxIdleThreads >= 0 ) return false;
	pthread_spin_init( &poolLock, PTHREAD_PROCESS_PRIVATE );
	maxIdleThreads = maxIdle;
	pthread_attr_init( &threadAttrs );
	pthread_attr_setdetachstate( &threadAttrs, PTHREAD_CREATE_DETACHED );
	return true;
}

void threadpool_close()
{
	_shutdown = true;
	if ( maxIdleThreads < 0 ) return;
	pthread_spin_lock( &poolLock );
	maxIdleThreads = -1;
	entry_t *ptr = pool;
	pool = NULL;
	currentIdleThreads = 0;
	pthread_spin_unlock( &poolLock );
	while ( ptr != NULL ) {
		entry_t *current = ptr;
		ptr = ptr->next;
		signal_call( current->signal );
	}
	pthread_spin_destroy( &poolLock );
}

bool threadpool_run(void *(*startRoutine)(void *), void *arg)
{
	pthread_spin_lock( &poolLock );
	entry_t *entry = pool;
	if ( entry != NULL ) {
		pool = entry->next;
		currentIdleThreads--;
	}
	pthread_spin_unlock( &poolLock );
	if ( entry == NULL ) {
		entry = (entry_t*)malloc( sizeof(entry_t) );
		if ( entry == NULL ) {
			logadd( LOG_WARNING, "Could not alloc entry_t for new thread\n" );
			return false;
		}
		entry->signal = signal_newBlocking();
		if ( entry->signal == NULL ) {
			logadd( LOG_WARNING, "Could not create signal for new thread pool thread\n" );
			free( entry );
			return false;
		}
		if ( 0 != thread_create( &(entry->thread), &threadAttrs, threadpool_worker, (void*)entry ) ) {
			logadd( LOG_WARNING, "Could not create new thread for thread pool\n" );
			signal_close( entry->signal );
			free( entry );
			return false;
		}
	}
	entry->next = NULL;
	entry->startRoutine = startRoutine;
	entry->arg = arg;
	signal_call( entry->signal );
	return true;
}

/**
 * This is a worker thread of our thread pool.
 */
static void *threadpool_worker(void *entryPtr)
{
	blockNoncriticalSignals();
	entry_t *entry = (entry_t*)entryPtr;
	for ( ;; ) {
		// Wait for signal from outside that we have work to do
		int ret = signal_clear( entry->signal );
		if ( _shutdown ) break;
		if ( ret > 0 ) {
			if ( entry->startRoutine == NULL ) {
				logadd( LOG_ERROR, "Worker woke up but has no work to do!" );
				exit( 1 );
			}
			// Start assigned work
			(*entry->startRoutine)( entry->arg );
			// Reset vars for safety
			entry->startRoutine = NULL;
			entry->arg = NULL;
			if ( _shutdown ) break;
			// Put thread back into pool if there are less than maxIdleThreds threads, just die otherwise
			if ( currentIdleThreads >= maxIdleThreads )
				break;
			// Race condition as we checked before locking, but worst case we have a couple
			// too many threads idling around. At least the count stays accurate.
			setThreadName( "[pool]" );
			pthread_spin_lock( &poolLock );
			currentIdleThreads++;
			entry->next = pool;
			pool = entry;
			pthread_spin_unlock( &poolLock );
		} else {
			logadd( LOG_DEBUG1, "Unexpected return value %d for signal_wait in threadpool worker!", ret );
		}
	}
	signal_close( entry->signal );
	free( entry );
	return NULL;
}

