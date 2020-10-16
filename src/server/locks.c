/*
 * locks.c
 *
 *  Created on: 16.07.2013
 *      Author: sr
 */

#include "locks.h"
#include "helper.h"
#include <dnbd3/shared/timing.h>

#ifdef DNBD3_SERVER_DEBUG_LOCKS
#define MAXLOCKS (SERVER_MAX_CLIENTS * 2 + SERVER_MAX_ALTS + 200 + SERVER_MAX_IMAGES)
#define MAXTHREADS (SERVER_MAX_CLIENTS + 100)
#define MAXLPT 20
#define LOCKLEN 60
typedef struct
{
	void * _Atomic lock;
	ticks locktime;
	bool _Atomic locked;
	pthread_t _Atomic thread;
	int lockId;
	int prio;
	char name[LOCKLEN];
	char where[LOCKLEN];
} debug_lock_t;

typedef struct
{
	pthread_t _Atomic tid;
	ticks time;
	char name[LOCKLEN];
	char where[LOCKLEN];
	debug_lock_t *locks[MAXLPT];
} debug_thread_t;

int debugThreadCount = 0;

static debug_lock_t locks[MAXLOCKS];
static debug_thread_t threads[MAXTHREADS];
static pthread_mutex_t initdestory = PTHREAD_MUTEX_INITIALIZER;
static int lockId = 0;

#define ULDE(...) do { \
			pthread_mutex_unlock( &initdestory ); \
			logadd( LOG_ERROR, __VA_ARGS__ ); \
			debug_dump_lock_stats(); \
			exit( 4 ); \
} while(0)

int debug_mutex_init(const char *name, const char *file, int line, pthread_mutex_t *lock, int priority)
{
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
		ULDE( "No more free debug locks (%s:%d)\n", file, line );
	}
	locks[first].lock = (void*)lock;
	locks[first].locked = false;
	locks[first].prio = priority;
	snprintf( locks[first].name, LOCKLEN, "%s", name );
	snprintf( locks[first].where, LOCKLEN, "I %s:%d", file, line );
	pthread_mutex_unlock( &initdestory );
	return pthread_mutex_init( lock, NULL );
}

int debug_mutex_lock(const char *name, const char *file, int line, pthread_mutex_t *lock, bool try)
{
	debug_lock_t *l = NULL;
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	if ( l == NULL ) {
		ULDE( "Tried to lock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
	}
	debug_thread_t *t = NULL;
	int first = -1;
	const pthread_t self = pthread_self();
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid == self ) {
			t = &threads[i];
			break;
		}
		if ( first == -1 && threads[i].tid == 0 ) {
			first = i;
		}
	}
	int idx;
	if ( t == NULL ) {
		if ( first == -1 ) {
			ULDE( "Lock sanity check: Too many waiting threads for lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		}
		t = &threads[first];
		timing_get( &t->time );
		t->tid = self;
		snprintf( t->name, LOCKLEN, "%s", name );
		snprintf( t->where, LOCKLEN, "%s:%d", file, line );
		memset( t->locks, 0, sizeof(t->locks) );
		idx = 0;
	} else {
		// Thread already has locks, check for order violation
		idx = -1;
		for (int i = 0; i < MAXLPT; ++i) {
			if ( t->locks[i] == NULL ) {
				if ( idx == -1 ) {
					idx = i;
				}
				continue;
			}
			if ( t->locks[i]->prio >= l->prio ) {
				ULDE( "Lock priority violation: %s at %s:%d (%d) when already holding %s at %s (%d)",
						name, file, line, l->prio,
						t->locks[i]->name, t->locks[i]->where, t->locks[i]->prio );
			}
			if ( t->locks[i] == l ) {
				ULDE( "Tried to recusively lock %s in the same thread. Tried at %s:%d, when already locked at %s",
						name, file, line, t->locks[i]->name );
			}
		}
		if ( idx == -1 ) {
			ULDE( "Thread %d tried to lock more than %d locks.", (int)self, (int)MAXLPT );
		}
	}
	pthread_mutex_unlock( &initdestory );
	const int retval = try ? pthread_mutex_trylock( lock ) : pthread_mutex_lock( lock );
	if ( retval == 0 ) {
		timing_get( &l->locktime );
		l->thread = self;
		snprintf( l->where, LOCKLEN, "L %s:%d", file, line );
		pthread_mutex_lock( &initdestory );
		if ( l->locked ) {
			logadd( LOG_ERROR, "Lock sanity check: lock %p (%s) already locked at %s:%d\n", (void*)lock, name, file, line );
			exit( 4 );
		}
		l->locked = true;
		t->locks[idx] = l;
		l->lockId = ++lockId;
		pthread_mutex_unlock( &initdestory );
	} else if ( !try || retval != EBUSY ) {
		logadd( LOG_ERROR, "Acquiring lock %s at %s:%d failed with error code %d", name, file, line, retval );
		debug_dump_lock_stats();
		exit( 4 );
	}
	return retval;
}

int debug_mutex_unlock(const char *name, const char *file, int line, pthread_mutex_t *lock)
{
	debug_thread_t *t = NULL;
	pthread_t self = pthread_self();
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid == self ) {
			t = &threads[i];
			break;
		}
	}
	if ( t == NULL ) {
		ULDE( "Unlock called from unknown thread for %s at %s:%d", name, file, line );
	}
	int idx = -1;
	int cnt = 0;
	for (int i = 0; i < MAXLPT; ++i) {
		if ( t->locks[i] == NULL )
			continue;
		cnt++;
		if ( t->locks[i]->lock == lock ) {
			idx = i;
		}
	}
	if ( idx == -1 ) {
		ULDE( "Unlock: Calling thread doesn't hold lock %s at %s:%d", name, file, line );
	}
	debug_lock_t *l = t->locks[idx];
	if ( l->thread != self || !l->locked ) {
		ULDE( "Unlock sanity check for lock debugger failed! Lock %s is assigned to calling thread, but lock's meta data doesn't match up at %s:%d", name, file, line );
	}
	l->locked = false;
	l->thread = 0;
	t->locks[idx] = NULL;
	if ( cnt == 1 ) {
		t->tid = 0; // No more locks held, free up slot
	}
	snprintf( l->where, LOCKLEN, "U %s:%d", file, line );
	pthread_mutex_unlock( &initdestory );
	const int retval = pthread_mutex_unlock( lock );
	if ( retval != 0 ) {
		logadd( LOG_ERROR, "pthread_mutex_unlock returned %d for %s at %s:%d", retval, name, file, line );
		exit( 4 );
	}
	return retval;
}

int debug_mutex_cond_wait(const char *name, const char *file, int line, pthread_cond_t *restrict cond, pthread_mutex_t *restrict lock)
{
	debug_lock_t *l = NULL;
	debug_thread_t *t = NULL;
	pthread_t self = pthread_self();
	pthread_mutex_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid == self ) {
			t = &threads[i];
			break;
		}
	}
	if ( t == NULL ) {
		ULDE( "Unlock called from unknown thread for %s at %s:%d", name, file, line );
	}
	int mp = 0, mpi = -1;
	for (int i = 0; i < MAXLPT; ++i) {
		if ( t->locks[i] == NULL )
			continue;
		if ( t->locks[i]->lock == lock ) {
			l = t->locks[i];
		} else if ( t->locks[i]->prio > mp ) {
			mp = t->locks[i]->prio;
			mpi = i;
		}
	}
	if ( l == NULL ) {
		ULDE( "cond_wait: Calling thread doesn't hold lock %s at %s:%d", name, file, line );
	}
	if ( l->thread != self || !l->locked ) {
		ULDE( "cond_wait: Sanity check for lock debugger failed! Lock %s is assigned to calling thread, but lock's meta data doesn't match up at %s:%d", name, file, line );
	}
	if ( mp >= l->prio ) {
		ULDE( "cond_wait: Yielding a mutex while holding another one with higher prio: %s at %s:%d (%d) while also holding %s at %s (%d)",
				name, file, line, l->prio,
				t->locks[mpi]->name, t->locks[mpi]->where, mp );
	}
	l->locked = false;
	l->thread = 0;
	snprintf( l->where, LOCKLEN, "CWU %s:%d", file, line );
	pthread_mutex_unlock( &initdestory );
	int retval = pthread_cond_wait( cond, lock );
	if ( retval != 0 ) {
		logadd( LOG_ERROR, "pthread_cond_wait returned %d for lock %p (%s) at %s:%d\n", retval, (void*)lock, name, file, line );
		exit( 4 );
	}
	if ( l->locked || l->thread != 0 ) {
		logadd( LOG_ERROR, "Lock is not free after returning from pthread_cond_wait for %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->thread = self;
	timing_get( &l->locktime );
	l->locked = true;
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
	printf( "\n **** ACTIVE THREADS ****\n\n" );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid == 0 )
			continue;
		printf( "* *** Thread %d ***\n"
				"* Lock: %s\n"
				"* Where: %s\n"
				"* How long: %d secs\n", (int)threads[i].tid, threads[i].name, threads[i].where, (int)timing_diff( &threads[i].time, &now ) );
		for (int j = 0; j < MAXLPT; ++j) {
			if ( threads[i].locks[j] == NULL )
				continue;
			printf( "  * Lock %s @ %s\n", threads[i].locks[j]->name, threads[i].locks[j]->where );
		}
	}
	pthread_mutex_unlock( &initdestory );
}

#endif
