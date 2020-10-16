#include "fuse.h"
#include <dnbd3/types.h>
#include <dnbd3/shared/log.h>

#ifndef DNBD3_SERVER_FUSE

//
bool dfuse_init(const char *opts UNUSED, const char *dir UNUSED)
{
	logadd( LOG_ERROR, "FUSE: Not compiled in" );
	return false;
}

void dfuse_shutdown()
{
}

#else

#define PATHLEN (2000)
static char nullbytes[DNBD3_BLOCK_SIZE];

// FUSE ENABLED
#define FUSE_USE_VERSION 30
//
#include <dnbd3/config.h>
#include "locks.h"
#include "threadpool.h"
#include "image.h"
#include "uplink.h"
#include "reference.h"
#include "helper.h"

#include <fuse_lowlevel.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <signal.h>

#define INO_ROOT (1)
#define INO_CTRL (2)
#define INO_DIR  (3)
static const char *NAME_CTRL = "control";
static const char *NAME_DIR = "images";

typedef struct {
	fuse_req_t req;
	uint16_t rid;
	char name[PATHLEN];
} lookup_t;

static fuse_ino_t inoCounter = 10;
typedef struct _dfuse_dir {
	struct _dfuse_dir *next;
	struct _dfuse_dir *child;
	const char *name;
	uint64_t size;
	fuse_ino_t ino;
	int refcount;
	lookup_t *img;
} dfuse_entry_t;

typedef struct {
	dfuse_entry_t *entry;
	dnbd3_image_t *image;
} cmdopen_t;

static dfuse_entry_t sroot = {
	.name = "images",
	.ino = INO_DIR,
	.refcount = 2,
}, *root = &sroot;
static pthread_mutex_t dirLock;

#define INIT_NONE (0)
#define INIT_DONE (1)
#define INIT_SHUTDOWN (2)
#define INIT_INPROGRESS (3)

static struct fuse_session *fuseSession = NULL;
static struct fuse_chan *fuseChannel = NULL;
static char *fuseMountPoint = NULL;
static pthread_t fuseThreadId;
static bool haveThread = false;
static _Atomic(int) initState = INIT_NONE;
static pthread_mutex_t initLock;
static struct timespec startupTime;

static dfuse_entry_t* dirLookup(dfuse_entry_t *dir, const char *name);
static dfuse_entry_t* inoRecursive(dfuse_entry_t *dir, fuse_ino_t ino);

static void uplinkCallback(void *data, uint64_t handle, uint64_t start UNUSED, uint32_t length, const char *buffer);
static void cleanupFuse();
static void* fuseMainLoop(void *data);

static void ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fi->fh = 0;
	if ( ino == INO_CTRL ) {
		if ( ( fi->flags & 3 ) != O_WRONLY ) {
			fuse_reply_err( req, EINVAL );
		} else {
			fi->nonseekable = 1;
			fuse_reply_open( req, fi );
		}
	} else if ( ino == INO_ROOT ) {
		fuse_reply_err( req, EISDIR );
	} else {
		if ( ( fi->flags & 3 ) != O_RDONLY ) {
			fuse_reply_err( req, EINVAL );
			return;
		}
		mutex_lock( &dirLock );
		dfuse_entry_t *entry = inoRecursive( root, ino );
		if ( entry == NULL ) {
			mutex_unlock( &dirLock );
			fuse_reply_err( req, ENOENT );
		} else if ( entry->img == NULL ) {
			mutex_unlock( &dirLock );
			fuse_reply_err( req, EISDIR );
		} else if ( entry->img->rid == 0 ) {
			mutex_unlock( &dirLock );
			fuse_reply_err( req, ENOENT );
		} else {
			entry->refcount++;
			mutex_unlock( &dirLock );
			dnbd3_image_t *image = image_get( entry->img->name, entry->img->rid, true );
			if ( image == NULL ) {
				fuse_reply_err( req, ENOENT );
				mutex_lock( &dirLock );
				entry->refcount--;
				mutex_unlock( &dirLock );
			} else {
				cmdopen_t *handle = malloc( sizeof(cmdopen_t) );
				handle->entry = entry;
				handle->image = image;
				fi->fh = (uintptr_t)handle;
				fi->keep_cache = 1;
				fuse_reply_open( req, fi );
			}
		}
	}
}

static dfuse_entry_t* addImage(dfuse_entry_t **dir, const char *name, lookup_t *img)
{
	const char *slash = strchr( name, '/' );
	if ( slash == NULL ) {
		// Name portion at the end
		char *path = NULL;
		if ( asprintf( &path, "%s:%d", name, (int)img->rid ) == -1 )
			abort();
		dfuse_entry_t *entry = dirLookup( *dir, path );
		if ( entry == NULL ) {
			entry = calloc( 1, sizeof( *entry ) );
			entry->next = *dir;
			*dir = entry;
			entry->name = path;
			entry->ino = inoCounter++;
			entry->img = img;
		} else {
			free( path );
			if ( entry->img == NULL ) {
				return NULL;
			}
		}
		return entry;
	} else {
		// Dirname
		char *path = NULL;
		if ( asprintf( &path, "%.*s", (int)( slash - name ), name ) == -1 )
			abort();
		dfuse_entry_t *entry = dirLookup( *dir, path );
		if ( entry == NULL ) {
			entry = calloc( 1, sizeof( *entry ) );
			entry->next = *dir;
			*dir = entry;
			entry->name = path;
			entry->ino = inoCounter++;
		} else {
			free( path );
		}
		return addImage( &entry->child, slash + 1, img );
	}
}

static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi UNUSED)
{
	if ( ino != INO_CTRL ) {
		fuse_reply_err( req, EROFS );
		return;
	}
	if ( off != 0 ) {
		fuse_reply_err( req, ESPIPE );
		return;
	}
	if ( size >= PATHLEN ) {
		fuse_reply_err( req, ENOSPC );
		return;
	}
	size_t colon = 0;
	int rid = 0;
	for ( size_t i = 0; i < size; ++i ) {
		if ( buf[i] == '\0' || buf[i] == '\n' ) {
			if ( colon == 0 ) {
				colon = i;
			}
			break;
		}
		if ( colon != 0 ) {
			if ( !isdigit( buf[i] ) ) {
				logadd( LOG_WARNING, "FUSE: Malformed rid" );
				fuse_reply_err( req, EINVAL );
				return;
			}
			rid = rid * 10 + ( buf[i] - '0' ); // Can overflow but who cares
		} else if ( buf[i] == ':' ) {
			colon = i; // Image name starting with ':' would be broken...
		}
	}
	if ( rid < 0 || rid > 65535 ) {
		logadd( LOG_WARNING, "FUSE: Invalid rid '%d'", rid );
		fuse_reply_err( req, EINVAL );
		return;
	}
	if ( colon == 0 ) {
		colon = size;
	}
	lookup_t *lu = malloc( sizeof(lookup_t) );
	lu->rid = (uint16_t)rid;
	lu->req = req;
	if ( snprintf( lu->name, PATHLEN, "%.*s", (int)colon, buf ) == -1 ) {
		free( lu );
		fuse_reply_err( req, ENOSPC );
		return;
	}
	logadd( LOG_DEBUG1, "FUSE: Request for '%s:%d'", lu->name, (int)lu->rid );
	dnbd3_image_t *image = image_getOrLoad( lu->name, lu->rid );
	if ( image == NULL ) {
		fuse_reply_err( lu->req, ENOENT );
		free( lu );
	} else {
		mutex_lock( &dirLock );
		dfuse_entry_t *entry = addImage( &root->child, lu->name, lu );
		if ( entry != NULL ) {
			entry->size = image->virtualFilesize;
		}
		lu->rid = image->rid; // In case it was 0
		mutex_unlock( &dirLock );
		image_release( image );
		if ( entry == NULL ) {
			fuse_reply_err( lu->req, EINVAL );
			free( lu );
		} else {
			fuse_reply_write( lu->req, size );
		}
	}
}

static void ll_read( fuse_req_t req, fuse_ino_t ino UNUSED, size_t size, off_t off, struct fuse_file_info *fi )
{
	if ( fi->fh == 0 ) {
		fuse_reply_err( req, 0 );
		return;
	}
	cmdopen_t *handle = (cmdopen_t*)fi->fh;
	dnbd3_image_t *image = handle->image;
	if ( off < 0 || (uint64_t)off >= image->virtualFilesize ) {
		fuse_reply_err( req, 0 );
		return;
	}
	if ( off + size > image->virtualFilesize ) {
		size = image->virtualFilesize - off;
	}

	// Check if cached locally
	dnbd3_cache_map_t *cache = ref_get_cachemap( image );
	if ( cache != NULL ) {
		// This is a proxyed image, check if we need to relay the request...
		const uint64_t start = (uint64_t)off & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		const uint64_t end = (off + size + DNBD3_BLOCK_SIZE - 1) & ~(uint64_t)(DNBD3_BLOCK_SIZE - 1);
		if ( !image_isRangeCachedUnsafe( cache, start, end ) ) {
			ref_put( &cache->reference );
			if ( size > (uint32_t)_maxPayload ) {
				size = (uint32_t)_maxPayload;
			}
			if ( !uplink_request( image, req, &uplinkCallback, 0, off, (uint32_t)size ) ) {
				logadd( LOG_DEBUG1, "FUSE: Could not relay uncached request to upstream proxy for image %s:%d",
						image->name, image->rid );
				fuse_reply_err( req, EIO );
			}
			return; // ASYNC
		}
		ref_put( &cache->reference );
	}

	// Is cached
	size_t readSize = size;
	if ( off + readSize > image->realFilesize ) {
		if ( (uint64_t)off >= image->realFilesize ) {
			readSize = 0;
		} else {
			readSize = image->realFilesize - off;
		}
	}
	struct fuse_bufvec *vec = calloc( 1, sizeof(*vec) + sizeof(struct fuse_buf) );
	if ( readSize != 0 ) {
		// Real data from file
		vec->buf[vec->count++] = (struct fuse_buf){
			.size = readSize,
			.flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY | FUSE_BUF_FD_SEEK,
			.fd = image->readFd,
			.pos = off,
		};
	}
	if ( readSize != size ) {
		vec->buf[vec->count++] = (struct fuse_buf){
			.size = size - readSize,
			.mem = nullbytes,
			.fd = -1,
		};
	}
	fuse_reply_data( req, vec, FUSE_BUF_SPLICE_MOVE );
	free( vec );
}

static bool statInternal(fuse_ino_t ino, struct stat *stbuf)
{
	switch ( ino ) {
	case INO_ROOT:
	case INO_DIR:
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		stbuf->st_mtim = startupTime;
		break;
	case INO_CTRL:
		stbuf->st_mode = S_IFREG | 0222;
		stbuf->st_nlink = 1;
		stbuf->st_size = 0;
		clock_gettime( CLOCK_REALTIME, &stbuf->st_mtim );
		break;
	default:
		return false;
	}
	stbuf->st_ctim = stbuf->st_atim = startupTime;
	stbuf->st_uid = 0;
	stbuf->st_ino = ino;
	return true;
}

/**
 * HOLD LOCK
 */
static dfuse_entry_t* dirLookup(dfuse_entry_t *dir, const char *name)
{
	if ( dir == NULL )
		return NULL;
	for ( dfuse_entry_t *it = dir; it != NULL; it = it->next ) {
		if ( strcmp( it->name, name ) == 0 )
			return it;
	}
	return NULL;
}

static dfuse_entry_t* inoRecursive(dfuse_entry_t *dir, fuse_ino_t ino)
{
	for ( dfuse_entry_t *it = dir; it != NULL; it = it->next ) {
		logadd( LOG_DEBUG1, "ino %d is %s", (int)it->ino, it->name );
		if ( it->ino == ino )
			return it;
		if ( it->img == NULL ) {
			dir = inoRecursive( it->child, ino );
			if ( dir != NULL )
				return dir;
		}
	}
	return NULL;
}

/**
 * HOLD LOCK
 */
static void entryToStat(dfuse_entry_t *entry, struct stat *stbuf)
{
	if ( entry->img == NULL ) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = entry->size;
	}
	stbuf->st_ino = entry->ino;
	stbuf->st_uid = 0;
	stbuf->st_ctim = stbuf->st_atim = stbuf->st_mtim = startupTime;
}

static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	logadd( LOG_DEBUG2, "Lookup at ino %d for '%s'", (int)parent, name );
	if ( parent == INO_ROOT ) {
		struct fuse_entry_param e = { 0 };
		if ( strcmp( name, NAME_DIR ) == 0 ) {
			e.ino = INO_DIR;
		} else if ( strcmp( name, NAME_CTRL ) == 0 ) {
			e.ino = INO_CTRL;
			e.attr_timeout = e.entry_timeout = 3600;
		}
		if ( e.ino != 0 && statInternal( e.ino, &e.attr ) ) {
			fuse_reply_entry( req, &e );
			return;
		}
	} else {
		mutex_lock( &dirLock );
		dfuse_entry_t *dir = inoRecursive( root, parent );
		if ( dir != NULL ) {
			if ( dir->img != NULL ) {
				mutex_unlock( &dirLock );
				fuse_reply_err( req, ENOTDIR );
				return;
			}
			dfuse_entry_t *entry = dirLookup( dir->child, name );
			if ( entry != NULL ) {
				struct fuse_entry_param e = { .ino = entry->ino };
				entryToStat( entry, &e.attr );
				mutex_unlock( &dirLock );
				fuse_reply_entry( req, &e );
				return;
			}
		}
		mutex_unlock( &dirLock );
	}
	fuse_reply_err( req, ENOENT );
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add( fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino )
{
	struct stat stbuf = { .st_ino = ino };
	size_t oldsize = b->size;
	b->size += fuse_add_direntry( req, NULL, 0, name, NULL, 0 );
	b->p = ( char * ) realloc( b->p, b->size );
	fuse_add_direntry( req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size );
	return;
}

static int reply_buf_limited( fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize )
{
	if ( off >= 0 && off < (off_t)bufsize ) {
		return fuse_reply_buf( req, buf + off, MIN( bufsize - off, maxsize ) );
	}
	return fuse_reply_buf( req, NULL, 0 );
}

static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi UNUSED)
{
	if ( ino != INO_ROOT ) {
		fuse_reply_err( req, EACCES );
	} else {
		struct dirbuf b;
		memset( &b, 0, sizeof( b ) );
		dirbuf_add( req, &b, ".", INO_ROOT );
		dirbuf_add( req, &b, "..", INO_ROOT );
		dirbuf_add( req, &b, NAME_CTRL, INO_CTRL );
		dirbuf_add( req, &b, NAME_DIR, INO_DIR );
		reply_buf_limited( req, b.p, b.size, off, size );
		free( b.p );
	}
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi UNUSED)
{
	struct stat stbuf = { .st_ino = 0 };
	if ( !statInternal( ino, &stbuf ) ) {
		mutex_lock( &dirLock );
		dfuse_entry_t *entry = inoRecursive( root, ino );
		if ( entry != NULL ) {
			entryToStat( entry, &stbuf );
		}
		mutex_unlock( &dirLock );
	}
	if ( stbuf.st_ino == 0 ) {
		fuse_reply_err( req, ENOENT );
	} else {
		fuse_reply_attr( req, &stbuf, 0 );
	}
}

void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr UNUSED, int to_set UNUSED, struct fuse_file_info *fi)
{
	ll_getattr( req, ino, fi );
}

void ll_release(fuse_req_t req, fuse_ino_t ino UNUSED, struct fuse_file_info *fi)
{
	if ( fi->fh != 0 ) {
		cmdopen_t *handle = (cmdopen_t*)fi->fh;
		image_release( handle->image );
		mutex_lock( &dirLock );
		handle->entry->refcount--;
		mutex_unlock( &dirLock );
		free( handle );
	}
	fuse_reply_err( req, 0 );
}

static void uplinkCallback(void *data, uint64_t handle UNUSED, uint64_t start UNUSED, uint32_t length, const char *buffer)
{
	fuse_req_t req = (fuse_req_t)data;
	if ( buffer == NULL ) {
		fuse_reply_err( req, EIO );
	} else {
		fuse_reply_buf( req, buffer, length );
	}
}

#define DUMP(key,type) logadd( LOG_DEBUG1, "FUSE: " #key ": " type, conn->key )
void ll_init(void *userdata, struct fuse_conn_info *conn)
{
	DUMP( capable, "%u" );
	DUMP( congestion_threshold, "%u" );
	DUMP( max_background, "%u" );
	//DUMP( max_read, "%u" );
	DUMP( max_readahead, "%u" );
	DUMP( max_write, "%u" );
	DUMP( want, "%u" );
	conn->want |= FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE;
}
#undef DUMP

/* map the implemented fuse operations */
static struct fuse_lowlevel_ops fuseOps = {
	.lookup = ll_lookup,
	.getattr = ll_getattr,
	.setattr = ll_setattr,
	.readdir = ll_readdir,
	.open = ll_open,
	.release = ll_release,
	.read = ll_read,
	.write = ll_write,
	.init = ll_init,
	//.destroy = ll_destroy,
};

bool dfuse_init(const char *opts, const char *dir)
{
	int ex = INIT_NONE;
	if ( !atomic_compare_exchange_strong( &initState, &ex, INIT_INPROGRESS ) ) {
		logadd( LOG_ERROR, "Calling dfuse_init twice" );
		exit( 1 );
	}
	mutex_init( &initLock, LOCK_FUSE_INIT );
	mutex_lock( &initLock );
	mutex_init( &dirLock, LOCK_FUSE_DIR );
	clock_gettime( CLOCK_REALTIME, &startupTime );
	struct fuse_args args = FUSE_ARGS_INIT( 0, NULL );
	fuse_opt_add_arg( &args, "dnbd3fs" ); // argv[0]
	if ( opts != NULL ) {
		fuse_opt_add_arg( &args, opts );
	}
	fuse_opt_add_arg( &args, "-odefault_permissions" );
	fuse_opt_add_arg( &args, dir ); // last param is mount point
	//
	if ( fuse_parse_cmdline( &args, &fuseMountPoint, NULL, NULL ) == -1 ) {
		logadd( LOG_ERROR, "FUSE: Error parsing command line" );
		goto fail;
	}
	fuseChannel = fuse_mount( fuseMountPoint, &args );
	if ( fuseChannel == NULL ) {
		logadd( LOG_ERROR, "FUSE: Cannot mount to %s", dir );
		goto fail;
	}
	fuseSession = fuse_lowlevel_new( &args, &fuseOps, sizeof( fuseOps ), NULL );
	if ( fuseSession == NULL ) {
		logadd( LOG_ERROR, "FUSE: Error initializing fuse session" );
		goto fail;
	}
	fuse_session_add_chan( fuseSession, fuseChannel );
	if ( 0 != thread_create( &fuseThreadId, NULL, &fuseMainLoop, (void *)NULL ) ) {
		logadd( LOG_ERROR, "FUSE: Could not start thread" );
		goto fail;
	}
	haveThread = true;
	// Init OK
	mutex_unlock( &initLock );
	return true;
fail:
	cleanupFuse();
	fuse_opt_free_args( &args );
	initState = INIT_SHUTDOWN;
	mutex_unlock( &initLock );
	return false;
}

void dfuse_shutdown()
{
	if ( initState == INIT_NONE )
		return;
	for ( ;; ) {
		int ex = INIT_DONE;
		if ( atomic_compare_exchange_strong( &initState, &ex, INIT_SHUTDOWN ) )
			break; // OK, do the shutdown
		if ( ex == INIT_INPROGRESS )
			continue; // dfuse_init in progress, wait for mutex
		// Wrong state
		logadd( LOG_WARNING, "Called dfuse_shutdown without dfuse_init first" );
		return;
	}
	logadd( LOG_INFO, "Shutting down fuse mainloop..." );
	mutex_lock( &initLock );
	if ( fuseSession != NULL ) {
		fuse_session_exit( fuseSession );
	}
	if ( !haveThread ) {
		cleanupFuse();
	}
	mutex_unlock( &initLock );
	if ( haveThread ) {
		logadd( LOG_DEBUG1, "FUSE: Sending USR1 to mainloop thread" );
		pthread_kill( fuseThreadId, SIGUSR1 );
		pthread_join( fuseThreadId, NULL );
	}
}

static void* fuseMainLoop(void *data UNUSED)
{
	int ex = INIT_INPROGRESS;
	if ( !atomic_compare_exchange_strong( &initState, &ex, INIT_DONE ) ) {
		logadd( LOG_WARNING, "FUSE: Unexpected state in fuseMainLoop: %d", ex );
		return NULL;
	}
	setThreadName( "fuse" );
	logadd( LOG_INFO, "FUSE: Starting mainloop" );
	fuse_session_loop_mt( fuseSession );
	logadd( LOG_INFO, "FUSE: Left mainloop" );
	mutex_lock( &initLock );
	cleanupFuse();
	mutex_unlock( &initLock );
	return NULL;
}

static void cleanupFuse()
{
	if ( fuseChannel != NULL ) {
		fuse_session_remove_chan( fuseChannel );
	}
	if ( fuseSession != NULL ) {
		fuse_session_destroy( fuseSession );
		fuseSession = NULL;
	}
	if ( fuseMountPoint != NULL && fuseChannel != NULL ) {
		fuse_unmount( fuseMountPoint, fuseChannel );
	}
	fuseChannel = NULL;
}

#endif  // DNBD3_SERVER_FUSE
