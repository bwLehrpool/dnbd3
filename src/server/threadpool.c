#include "threadpool.h"
#include "globals.h"
#include "helper.h"
#include "locks.h"

typedef struct _entry_t {
	pthread_t thread;
	dnbd3_signal_t* signal;
	void *(*startRoutine)(void *);
	void * arg;
	const char *name;
} entry_t;

static void *threadpool_worker(void *entryPtr);

static pthread_attr_t threadAttrs;
static atomic_int maxIdleThreads = -1;
static _Atomic(entry_t *) *pool = NULL;
static atomic_int activeThreads = 0;

bool threadpool_init(int maxIdle)
{
	if ( maxIdle < 0 )
		return false;
	int exp = -1;
	if ( !atomic_compare_exchange_strong( &maxIdleThreads, &exp, maxIdle ) )
		return false;
	pool = malloc( maxIdle * sizeof(*pool) );
	for ( int i = 0; i < maxIdle; ++i ) {
		atomic_init( &pool[i], NULL );
	}
	pthread_attr_init( &threadAttrs );
	pthread_attr_setdetachstate( &threadAttrs, PTHREAD_CREATE_DETACHED );
	return true;
}

void threadpool_close()
{
	int max = atomic_exchange( &maxIdleThreads, -1 );
	if ( max <= 0 )
		return;
	for ( int i = 0; i < max; ++i ) {
		entry_t *cur = pool[i];
		if ( cur != NULL && atomic_compare_exchange_strong( &pool[i], &cur, NULL ) ) {
			signal_call( cur->signal );
		}
	}
}

void threadpool_waitEmpty()
{
	if ( activeThreads == 0 )
		return;
	do {
		sleep( 1 );
		logadd( LOG_INFO, "Threadpool: %d threads still active", (int)activeThreads );
	} while ( activeThreads != 0 );
}

bool threadpool_run(void *(*startRoutine)(void *), void *arg, const char *name)
{
	if ( unlikely( _shutdown ) ) {
		logadd( LOG_MINOR, "Cannot submit work to threadpool while shutting down!" );
		return false;
	}
#ifdef DEBUG
	if ( unlikely( startRoutine == NULL ) ) {
		logadd( LOG_ERROR, "Trying to queue work for thread pool with NULL startRoutine" );
		return false; // Or bail out!?
	}
#endif
	entry_t *entry = NULL;
	for ( int i = 0; i < maxIdleThreads; ++i ) {
		entry = atomic_exchange( &pool[i], NULL );
		if ( entry != NULL ) {
			break;
		}
	}
	if ( unlikely( entry == NULL ) ) {
		entry = malloc( sizeof(entry_t) );
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
			logadd( LOG_WARNING, "Could not create new thread for thread pool (%d active)\n", (int)activeThreads );
			signal_close( entry->signal );
			free( entry );
			return false;
		}
		activeThreads++;
	}
	entry->startRoutine = startRoutine;
	entry->arg = arg;
	entry->name = name;
	atomic_thread_fence( memory_order_release );
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
	int ret;
	for ( ;; ) {
keep_going:;
		// Wait for signal from outside that we have work to do
		ret = signal_clear( entry->signal );
		atomic_thread_fence( memory_order_acquire );
		if ( _shutdown )
			break;
		if ( ret <= 0 ) {
			logadd( LOG_DEBUG1, "Unexpected return value %d for signal_wait in threadpool worker!", ret );
			continue;
		}
#ifdef DEBUG
		if ( entry->startRoutine == NULL ) {
			logadd( LOG_ERROR, "Worker woke up but has no work to do!" );
			exit( 1 );
		}
		if ( entry->name != NULL ) {
			setThreadName( entry->name );
		}
#endif
		// Start assigned work
		(*entry->startRoutine)( entry->arg );
		// Reset vars for safety
		entry->startRoutine = NULL;
		entry->arg = NULL;
		atomic_thread_fence( memory_order_release );
		if ( _shutdown )
			break;
		// Put thread back into pool
		setThreadName( "[pool]" );
		for ( int i = 0; i < maxIdleThreads; ++i ) {
			entry_t *exp = NULL;
			if ( atomic_compare_exchange_weak( &pool[i], &exp, entry ) ) {
				goto keep_going;
			}
		}
		// Reaching here means pool is full; just let the thread exit
		break;
	}
	setThreadName( "[dead]" );
	signal_close( entry->signal );
	free( entry );
	activeThreads--;
	return NULL;
}

