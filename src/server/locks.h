#ifndef _LOCKS_H_
#define _LOCKS_H_

#include <pthread.h>

#ifdef _DEBUG

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define spin_init( lock, type ) debug_spin_init( #lock, __FILE__, __LINE__, lock, type)
#define spin_lock( lock ) debug_spin_lock( #lock, __FILE__, __LINE__, lock)
#define spin_trylock( lock ) debug_spin_trylock( #lock, __FILE__, __LINE__, lock)
#define spin_unlock( lock ) debug_spin_unlock( #lock, __FILE__, __LINE__, lock)
#define spin_destroy( lock ) debug_spin_destroy( #lock, __FILE__, __LINE__, lock)

int debug_spin_init(const char *name, const char *file, int line, pthread_spinlock_t *lock, int shared);
int debug_spin_lock(const char *name, const char *file, int line, pthread_spinlock_t *lock);
int debug_spin_trylock(const char *name, const char *file, int line, pthread_spinlock_t *lock);
int debug_spin_unlock(const char *name, const char *file, int line, pthread_spinlock_t *lock);
int debug_spin_destroy(const char *name, const char *file, int line, pthread_spinlock_t *lock);

void debug_dump_lock_stats();


#else

#define spin_init( lock, type ) pthread_spin_init(lock, type)
#define spin_lock( lock ) pthread_spin_lock(lock)
#define spin_trylock( lock ) pthread_spin_trylock(lock)
#define spin_unlock( lock ) pthread_spin_unlock(lock)
#define spin_destroy( lock ) pthread_spin_destroy(lock)

#endif

#ifdef DEBUG_THREADS

extern int debugThreadCount;
#define thread_create(thread,attr,routine,arg) (printf("[THREAD CREATE] %d @ %s:%d\n", debugThreadCount, __FILE__, (int)__LINE__), debug_thread_create(thread, attr, routine, arg))
static inline pthread_t debug_thread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg)
{
	int i;
	if (attr == NULL || pthread_attr_getdetachstate(attr, &i) != 0 || i == PTHREAD_CREATE_JOINABLE) {
		++debugThreadCount;
	}
	return pthread_create( thread, attr, start_routine, arg );
}

#define thread_detach(thread) (printf("[THREAD DETACH] %d @ %s:%d\n", debugThreadCount, __FILE__, __LINE__), debug_thread_detach(thread))
static inline int debug_thread_detach(pthread_t thread)
{
	const int ret = pthread_detach(thread);
	if (ret == 0) {
		--debugThreadCount;
	} else {
		printf("[THREAD DETACH] Tried to detach invalid thread (error %d)\n", (int)errno);
		exit(1);
	}
	return ret;
}
#define thread_join(thread,value) (printf("[THREAD JOIN] %d @ %s:%d\n", debugThreadCount, __FILE__, __LINE__), debug_thread_join(thread,value))
static inline int debug_thread_join(pthread_t thread, void **value_ptr)
{
	const int ret = pthread_join(thread, value_ptr);
	if (ret == 0) {
		--debugThreadCount;
	} else {
		printf("[THREAD JOIN] Tried to join invalid thread (error %d)\n", (int)errno);
		exit(1);
	}
	return ret;
}

#else

#define thread_create(thread,attr,routine,param)  pthread_create( thread, attr, routine, param )
#define thread_detach(thread) pthread_detach( thread )
#define thread_join(thread,value) pthread_join( thread, value )

#endif

void debug_locks_start_watchdog();
void debug_locks_stop_watchdog();

#endif /* LOCKS_H_ */
