#ifndef _LOCKS_H_
#define _LOCKS_H_

#ifdef _DEBUG

#include <pthread.h>

#define spin_init( lock, type ) debug_spin_init( #lock, __FILE__, __LINE__, lock, type)
#define spin_lock( lock ) debug_spin_lock( #lock, __FILE__, __LINE__, lock)
#define spin_unlock( lock ) debug_spin_unlock( #lock, __FILE__, __LINE__, lock)
#define spin_destroy( lock ) debug_spin_destroy( #lock, __FILE__, __LINE__, lock)

int debug_spin_init(const char *name, const char *file, int line, pthread_spinlock_t *lock, int shared);
int debug_spin_lock(const char *name, const char *file, int line, pthread_spinlock_t *lock);
int debug_spin_unlock(const char *name, const char *file, int line, pthread_spinlock_t *lock);
int debug_spin_destroy(const char *name, const char *file, int line, pthread_spinlock_t *lock);

void debug_dump_lock_stats();

#else

#define spin_init( lock, type ) pthread_spin_init(lock, type)
#define spin_lock( lock ) pthread_spin_lock(lock)
#define spin_unlock( lock ) pthread_spin_unlock(lock)
#define spin_destroy( lock ) pthread_spin_destroy(lock)

#endif

void debug_locks_start_watchdog();
void debug_locks_stop_watchdog();

#endif /* LOCKS_H_ */
