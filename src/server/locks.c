/*
 * locks.c
 *
 *  Created on: 16.07.2013
 *      Author: sr
 */

#include "locks.h"
#include "helper.h"
#include "../shared/timing.h"

#ifdef _DEBUG
#define MAXLOCKS (SERVER_MAX_CLIENTS * 2 + SERVER_MAX_ALTS + 200 + SERVER_MAX_IMAGES)
#define MAXTHREADS (SERVER_MAX_CLIENTS + 100)
#define LOCKLEN 60
typedef struct
{
	void *lock;
	ticks locktime;
	char locked;
	pthread_t thread;
	int lockId;
	char name[LOCKLEN];
	char where[LOCKLEN];
} debug_lock_t;

typedef struct
{
	pthread_t tid;
	ticks time;
	char name[LOCKLEN];
	char where[LOCKLEN];

} debug_thread_t;

int debugThreadCount = 0;

static debug_lock_t locks[MAXLOCKS];
static debug_thread_t threads[MAXTHREADS];
static int init_done = 0;
static pthread_mutex_t initdestory;
static int lockId = 0;
static pthread_t watchdog = 0;
static dnbd3_signal_t* watchdogSignal = NULL;

static void *debug_thread_watchdog(void *something);

int debug_mutex_init(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	if ( !init_done ) {
		memset( locks, 0, MAXLOCKS * sizeof(debug_lock_t) );
		memset( threads, 0, MAXTHREADS * sizeof(debug_thread_t) );
		pthread_mutex_init( &initdestory, NULL );
		init_done = 1;
	}
	int first = -1;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			logadd( LOG_ERROR, "Lock %p (%s) already initialized (%s:%d)\n", (void*)lock, name, file, line );
			exit( 4 );
		}
		if ( first == -1 && locks[i].lock == NULL ) first = i;
	}
	if ( first == -1 ) {
		logadd( LOG_ERROR, "No more free debug locks (%s:%d)\n", file, line );
		pthread_mutex_unlock( &initdestory );
		debug_dump_lock_stats();
		exit( 4 );
	}
	locks[first].lock = (void*)lock;
	locks[first].locked = 0;
	snprintf( locks[first].name, LOCKLEN, "%s", name );
	snprintf( locks[first].where, LOCKLEN, "I %s:%d", file, line );
	pthread_mutex_unlock( &initdestory );
	return pthread_mutex_init( lock, NULL );
}

int debug_mutex_lock(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_mutex_unlock( &initdestory );
	if ( l == NULL ) {
		logadd( LOG_ERROR, "Tried to lock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		debug_dump_lock_stats();
		exit( 4 );
	}
	debug_thread_t *t = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid != 0 ) continue;
		threads[i].tid = pthread_self();
		timing_get( &threads[i].time );
		snprintf( threads[i].name, LOCKLEN, "%s", name );
		snprintf( threads[i].where, LOCKLEN, "%s:%d", file, line );
		t = &threads[i];
		break;
	}
	pthread_mutex_unlock( &initdestory );
	if ( t == NULL ) {
		logadd( LOG_ERROR, "Lock sanity check: Too many waiting threads for lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	const int retval = pthread_mutex_lock( lock );
	pthread_mutex_lock( &initdestory );
	t->tid = 0;
	pthread_mutex_unlock( &initdestory );
	if ( l->locked ) {
		logadd( LOG_ERROR, "Lock sanity check: lock %p (%s) already locked at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 1;
	timing_get( &l->locktime );
	l->thread = pthread_self();
	snprintf( l->where, LOCKLEN, "L %s:%d", file, line );
	pthread_mutex_lock( &initdestory );
	l->lockId = ++lockId;
	pthread_mutex_unlock( &initdestory );
	return retval;
}

int debug_mutex_trylock(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_mutex_unlock( &initdestory );
	if ( l == NULL ) {
		logadd( LOG_ERROR, "Tried to lock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		debug_dump_lock_stats();
		exit( 4 );
	}
	debug_thread_t *t = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid != 0 ) continue;
		threads[i].tid = pthread_self();
		timing_get( &threads[i].time );
		snprintf( threads[i].name, LOCKLEN, "%s", name );
		snprintf( threads[i].where, LOCKLEN, "%s:%d", file, line );
		t = &threads[i];
		break;
	}
	pthread_mutex_unlock( &initdestory );
	if ( t == NULL ) {
		logadd( LOG_ERROR, "Lock sanity check: Too many waiting threads for %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	const int retval = pthread_mutex_trylock( lock );
	pthread_mutex_lock( &initdestory );
	t->tid = 0;
	pthread_mutex_unlock( &initdestory );
	if ( retval == 0 ) {
		if ( l->locked ) {
			logadd( LOG_ERROR, "Lock sanity check: lock %p (%s) already locked at %s:%d\n", (void*)lock, name, file, line );
			exit( 4 );
		}
		l->locked = 1;
		timing_get( &l->locktime );
		l->thread = pthread_self();
		snprintf( l->where, LOCKLEN, "L %s:%d", file, line );
		pthread_mutex_lock( &initdestory );
		l->lockId = ++lockId;
		pthread_mutex_unlock( &initdestory );
	}
	return retval;
}

int debug_mutex_unlock(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_mutex_unlock( &initdestory );
	if ( l == NULL ) {
		logadd( LOG_ERROR, "Tried to unlock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	if ( !l->locked ) {
		logadd( LOG_ERROR, "Unlock sanity check: lock %p (%s) not locked at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 0;
	l->thread = 0;
	snprintf( l->where, LOCKLEN, "U %s:%d", file, line );
	int retval = pthread_mutex_unlock( lock );
	return retval;
}

int debug_mutex_cond_wait(const char *name, const char *file, int line, pthread_cond_t *restrict cond, pthread_mutex_t *restrict lock)
{
	debug_lock_t *l = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_mutex_unlock( &initdestory );
	if ( l == NULL ) {
		logadd( LOG_ERROR, "Tried to cond_wait on uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	if ( !l->locked ) {
		logadd( LOG_ERROR, "Cond_wait sanity check: lock %p (%s) not locked at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	pthread_t self = pthread_self();
	if ( l->thread != self ) {
		logadd( LOG_ERROR, "Cond_wait called from non-owning thread for %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 0;
	l->thread = 0;
	snprintf( l->where, LOCKLEN, "CW %s:%d", file, line );
	int retval = pthread_cond_wait( cond, lock );
	if ( retval != 0 ) {
		logadd( LOG_ERROR, "pthread_cond_wait returned %d for lock %p (%s) at %s:%d\n", retval, (void*)lock, name, file, line );
		exit( 4 );
	}
	if ( l->locked != 0 || l->thread != 0 ) {
		logadd( LOG_ERROR, "Lock is not free after returning from pthread_cond_wait for %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 1;
	l->thread = self;
	timing_get( &l->locktime );
	pthread_mutex_lock( &initdestory );
	l->lockId = ++lockId;
	pthread_mutex_unlock( &initdestory );
	return retval;
}

int debug_mutex_destroy(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			if ( locks[i].locked ) {
				logadd( LOG_ERROR, "Tried to destroy lock %p (%s) at %s:%d when it is still locked\n", (void*)lock, name, file, line );
				logadd( LOG_ERROR, "Currently locked by: %s", locks[i].where );
				exit( 4 );
			}
			locks[i].lock = NULL;
			snprintf( locks[i].where, LOCKLEN, "D %s:%d", file, line );
			pthread_mutex_unlock( &initdestory );
			return pthread_mutex_destroy( lock );
		}
	}
	logadd( LOG_ERROR, "Tried to destroy non-existent lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
	exit( 4 );
}

void debug_dump_lock_stats()
{
	declare_now;
	pthread_mutex_lock( &initdestory );
	printf( "\n **** LOCKS ****\n\n" );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == NULL ) continue;
		if ( locks[i].locked ) {
			printf( "* *** %s ***\n"
					"* Where: %s\n"
					"* When: %d secs ago\n"
					"* Locked: %d\n"
					"* Serial: %d\n"
					"* Thread: %d\n", locks[i].name, locks[i].where, (int)timing_diff( &locks[i].locktime, &now ), (int)locks[i].locked, locks[i].lockId,
					(int)locks[i].thread );
		} else {
			printf( "* *** %s ***\n"
					"* Where: %s\n"
					"* Locked: %d\n", locks[i].name, locks[i].where, (int)locks[i].locked );
		}
	}
	printf( "\n **** WAITING THREADS ****\n\n" );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid == 0 ) continue;
		printf( "* *** Thread %d ***\n"
				"* Lock: %s\n"
				"* Where: %s\n"
				"* How long: %d secs\n", (int)threads[i].tid, threads[i].name, threads[i].where, (int)timing_diff( &threads[i].time, &now ) );
	}
	pthread_mutex_unlock( &initdestory );
}

static void *debug_thread_watchdog(void *something UNUSED)
{
	setThreadName( "debug-watchdog" );
	while ( !_shutdown ) {
		if ( init_done ) {
			declare_now;
			pthread_mutex_lock( &initdestory );
			for (int i = 0; i < MAXTHREADS; ++i) {
				if ( threads[i].tid == 0 ) continue;
				const uint32_t diff = timing_diff( &threads[i].time, &now );
				if ( diff > 6 && diff < 100000 ) {
					printf( "\n\n +++++++++ DEADLOCK ++++++++++++\n\n" );
					pthread_mutex_unlock( &initdestory );
					debug_dump_lock_stats();
					exit( 99 );
				}
			}
			pthread_mutex_unlock( &initdestory );
		}
		if ( watchdogSignal == NULL || signal_wait( watchdogSignal, 5000 ) == SIGNAL_ERROR ) sleep( 5 );
	}
	return NULL ;
}

#endif

void debug_locks_start_watchdog()
{
#ifdef _DEBUG
	watchdogSignal = signal_new();
	if ( 0 != thread_create( &watchdog, NULL, &debug_thread_watchdog, (void *)NULL ) ) {
		logadd( LOG_ERROR, "Could not start debug-lock watchdog." );
		return;
	}
#endif
}

void debug_locks_stop_watchdog()
{
#ifdef _DEBUG
	_shutdown = true;
	printf( "Killing debug watchdog...\n" );
	pthread_mutex_lock( &initdestory );
	signal_call( watchdogSignal );
	pthread_mutex_unlock( &initdestory );
	thread_join( watchdog, NULL );
	signal_close( watchdogSignal );
#endif
}
