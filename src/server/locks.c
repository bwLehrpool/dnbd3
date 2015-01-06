/*
 * locks.c
 *
 *  Created on: 16.07.2013
 *      Author: sr
 */

#include "locks.h"

#ifdef _DEBUG

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "globals.h"
#include "memlog.h"
#include "helper.h"
#include "signal.h"

#define MAXLOCKS 2000
#define MAXTHREADS 500
#define LOCKLEN 60
typedef struct
{
	void *lock;
	volatile time_t locktime;
	volatile char locked;
	pthread_t thread;
	int lockId;
	char name[LOCKLEN];
	char where[LOCKLEN];
} debug_lock_t;

typedef struct
{
	pthread_t tid;
	time_t time;
	char name[LOCKLEN];
	char where[LOCKLEN];

} debug_thread_t;

int debugThreadCount = 0;

static debug_lock_t locks[MAXLOCKS];
static debug_thread_t threads[MAXTHREADS];
static int init_done = 0;
static pthread_spinlock_t initdestory;
static volatile int lockId = 0;
static pthread_t watchdog = 0;
static int watchdogSignal = -1;

static void *debug_thread_watchdog(void *something);

int debug_spin_init(const char *name, const char *file, int line, pthread_spinlock_t *lock, int shared)
{
	if ( !init_done ) {
		memset( locks, 0, MAXLOCKS * sizeof(debug_lock_t) );
		memset( threads, 0, MAXTHREADS * sizeof(debug_thread_t) );
		pthread_spin_init( &initdestory, PTHREAD_PROCESS_PRIVATE );
		init_done = 1;
	}
	int first = -1;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			printf( "[ERROR] Lock %p (%s) already initialized (%s:%d)\n", (void*)lock, name, file, line );
			exit( 4 );
		}
		if ( first == -1 && locks[i].lock == NULL ) first = i;
	}
	if ( first == -1 ) {
		printf( "[ERROR] No more free debug locks (%s:%d)\n", file, line );
		pthread_spin_unlock( &initdestory );
		debug_dump_lock_stats();
		exit( 4 );
	}
	locks[first].lock = (void*)lock;
	locks[first].locked = 0;
	snprintf( locks[first].name, LOCKLEN, "%s", name );
	snprintf( locks[first].where, LOCKLEN, "I %s:%d", file, line );
	pthread_spin_unlock( &initdestory );
	return pthread_spin_init( lock, shared );
}

int debug_spin_lock(const char *name, const char *file, int line, pthread_spinlock_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_spin_unlock( &initdestory );
	if ( l == NULL ) {
		printf( "[ERROR] Tried to lock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		debug_dump_lock_stats();
		exit( 4 );
	}
	debug_thread_t *t = NULL;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid != 0 ) continue;
		threads[i].tid = pthread_self();
		threads[i].time = time( NULL );
		snprintf( threads[i].name, LOCKLEN, "%s", name );
		snprintf( threads[i].where, LOCKLEN, "%s:%d", file, line );
		t = &threads[i];
		break;
	}
	pthread_spin_unlock( &initdestory );
	const int retval = pthread_spin_lock( lock );
	pthread_spin_lock( &initdestory );
	t->tid = 0;
	t->time = 0;
	pthread_spin_unlock( &initdestory );
	if ( l->locked ) {
		printf( "[ERROR] Lock sanity check: lock %p (%s) already locked at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 1;
	l->locktime = time( NULL );
	l->thread = pthread_self();
	snprintf( l->where, LOCKLEN, "L %s:%d", file, line );
	pthread_spin_lock( &initdestory );
	l->lockId = ++lockId;
	pthread_spin_unlock( &initdestory );
	return retval;
}

int debug_spin_trylock(const char *name, const char *file, int line, pthread_spinlock_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_spin_unlock( &initdestory );
	if ( l == NULL ) {
		printf( "[ERROR] Tried to lock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		debug_dump_lock_stats();
		exit( 4 );
	}
	debug_thread_t *t = NULL;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXTHREADS; ++i) {
		if ( threads[i].tid != 0 ) continue;
		threads[i].tid = pthread_self();
		threads[i].time = time( NULL );
		snprintf( threads[i].name, LOCKLEN, "%s", name );
		snprintf( threads[i].where, LOCKLEN, "%s:%d", file, line );
		t = &threads[i];
		break;
	}
	pthread_spin_unlock( &initdestory );
	const int retval = pthread_spin_trylock( lock );
	pthread_spin_lock( &initdestory );
	t->tid = 0;
	t->time = 0;
	pthread_spin_unlock( &initdestory );
	if ( retval == 0 ) {
		if ( l->locked ) {
			printf( "[ERROR] Lock sanity check: lock %p (%s) already locked at %s:%d\n", (void*)lock, name, file, line );
			exit( 4 );
		}
		l->locked = 1;
		l->locktime = time( NULL );
		l->thread = pthread_self();
		snprintf( l->where, LOCKLEN, "L %s:%d", file, line );
		pthread_spin_lock( &initdestory );
		l->lockId = ++lockId;
		pthread_spin_unlock( &initdestory );
	}
	return retval;
}

int debug_spin_unlock(const char *name, const char *file, int line, pthread_spinlock_t *lock)
{
	debug_lock_t *l = NULL;
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			l = &locks[i];
			break;
		}
	}
	pthread_spin_unlock( &initdestory );
	if ( l == NULL ) {
		printf( "[ERROR] Tried to unlock uninitialized lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	if ( !l->locked ) {
		printf( "[ERROR] Unlock sanity check: lock %p (%s) not locked at %s:%d\n", (void*)lock, name, file, line );
		exit( 4 );
	}
	l->locked = 0;
	l->locktime = 0;
	l->thread = 0;
	snprintf( l->where, LOCKLEN, "U %s:%d", file, line );
	int retval = pthread_spin_unlock( lock );
	return retval;
}

int debug_spin_destroy(const char *name, const char *file, int line, pthread_spinlock_t *lock)
{
	pthread_spin_lock( &initdestory );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == lock ) {
			if ( locks[i].locked ) {
				printf( "[ERROR] Tried to destroy lock %p (%s) at %s:%d when it is still locked\n", (void*)lock, name, file, line );
				exit( 4 );
			}
			locks[i].lock = NULL;
			snprintf( locks[i].where, LOCKLEN, "D %s:%d", file, line );
			pthread_spin_unlock( &initdestory );
			return pthread_spin_destroy( lock );
		}
	}
	printf( "[ERROR] Tried to destroy non-existent lock %p (%s) at %s:%d\n", (void*)lock, name, file, line );
	exit( 4 );
}

void debug_dump_lock_stats()
{
	time_t now = time( NULL );
	pthread_spin_lock( &initdestory );
	printf( "\n **** LOCKS ****\n\n" );
	for (int i = 0; i < MAXLOCKS; ++i) {
		if ( locks[i].lock == NULL ) continue;
		if ( locks[i].locked ) {
			printf( "* *** %s ***\n"
					"* Where: %s\n"
					"* When: %d secs ago\n"
					"* Locked: %d\n"
					"* Serial: %d\n"
					"* Thread: %d\n", locks[i].name, locks[i].where, (int)(now - locks[i].locktime), (int)locks[i].locked, locks[i].lockId,
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
				"* How long: %d secs\n", (int)threads[i].tid, threads[i].name, threads[i].where, (int)(now - threads[i].time) );
	}
	pthread_spin_unlock( &initdestory );
}

static void *debug_thread_watchdog(void *something)
{
	setThreadName("debug-watchdog");
	while ( !_shutdown ) {
		if ( init_done ) {
			time_t now = time( NULL );
			pthread_spin_lock( &initdestory );
			for (int i = 0; i < MAXTHREADS; ++i) {
				if ( threads[i].tid == 0 ) continue;
				const int diff = now - threads[i].time;
				if ( diff > 6 && diff < 100000 ) {
					printf( "\n\n +++++++++ DEADLOCK ++++++++++++\n\n" );
					pthread_spin_unlock( &initdestory );
					debug_dump_lock_stats();
					exit( 99 );
				}
			}
			pthread_spin_unlock( &initdestory );
		}
		if ( watchdogSignal == -1 || signal_wait( watchdogSignal, 5000 ) == SIGNAL_ERROR ) sleep( 5 );
	}
	return NULL ;
}

#endif

void debug_locks_start_watchdog()
{
#ifdef _DEBUG
	watchdogSignal = signal_new();
	if ( 0 != thread_create( &watchdog, NULL, &debug_thread_watchdog, (void *)NULL ) ) {
		memlogf( "[ERROR] Could not start debug-lock watchdog." );
		return;
	}
#endif
}

void debug_locks_stop_watchdog()
{
#ifdef _DEBUG
	_shutdown = true;
	printf( "Killing debug watchdog...\n" );
	pthread_spin_lock( &initdestory );
	signal_call( watchdogSignal );
	pthread_spin_unlock( &initdestory );
	thread_join( watchdog, NULL );
	signal_close( watchdogSignal );
#endif
}
