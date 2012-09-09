/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Johann Latocha <johann@latocha.de>
 *
 * This file may be licensed under the terms of of the
 * GNU General Public License Version 2 (the ``GPL'').
 *
 * Software distributed under the License is distributed
 * on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied. See the GPL for the specific language
 * governing rights and limitations.
 *
 * You should have received a copy of the GPL along with this
 * program. If not, go to http://www.gnu.org/licenses/gpl.html
 * or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>
#include <glib.h>
#include <math.h>
#include <netinet/in.h>

#include "server.h"
#include "saveload.h"
#include "memlog.h"
#include "helper.h"

// Keep parsed config file in memory so it doesn't need to be parsed again every time it's modified
static GKeyFile *_config_handle = NULL;

static dnbd3_image_t *prepare_image(char *image_name, int rid, char *image_file, char *cache_file);
//static char* get_local_image_name(char *global_name);


void dnbd3_load_config()
{
	gint i, j;

	if (_config_handle != NULL)
	{
		printf("dnbd3_load_config() called more than once\n\n");
		exit(EXIT_FAILURE);
	}

	_config_handle = g_key_file_new();
	if (!g_key_file_load_from_file(_config_handle, _config_file_name, G_KEY_FILE_NONE, NULL))
	{
		printf("ERROR: Config file not found: %s\n", _config_file_name);
		exit(EXIT_FAILURE);
	}

	_local_namespace = g_key_file_get_string(_config_handle, "settings", "default_namespace", NULL);
	if (_local_namespace && !is_valid_namespace(_local_namespace))
	{
		memlogf("[ERROR] Ignoring default namespace: '%s' is not a valid namespace", _local_namespace);
		g_free(_local_namespace);
		_local_namespace = NULL;
	}

	srand(time(NULL));

	_ipc_password = g_key_file_get_string(_config_handle, "settings", "password", NULL);
	_cache_dir = g_key_file_get_string(_config_handle, "settings", "cache_dir", NULL);

	if (_cache_dir == NULL)
		memlogf("[WARNING] No cache dir set! Automatic replication will not work.");
	else if (access(_cache_dir, R_OK | W_OK) != 0)
		memlogf("[WARNING] Cache dir '%s' is not readable or writable", _cache_dir);

	gchar **groups = NULL;
	gsize section_count;
	groups = g_key_file_get_groups(_config_handle, &section_count);

	for (i = 0; i < section_count; i++)
	{
		// Ignore settings section
		if (strcmp(groups[i], "settings") == 0)
			continue;

		// List of trusted servers/namespaces
		if (strncmp(groups[i], "trust:", 6) == 0)
		{
			gchar *addr = g_key_file_get_string(_config_handle, groups[i], "address", NULL);
			if (addr == NULL)
				continue;
			dnbd3_trusted_server_t *server = dnbd3_get_trusted_server(addr, TRUE, groups[i]+6);
			g_free(addr);
			if (server == NULL)
				continue;
			gsize key_count;
			gchar **keys = g_key_file_get_keys(_config_handle, groups[i], &key_count, NULL);
			for (j = 0; j < key_count; ++j)
			{
				if (strcmp(keys[j], "address") == 0)
					continue;
				char *flags = g_key_file_get_string(_config_handle, groups[i], keys[j], NULL);
				g_key_file_remove_key(_config_handle, groups[i], keys[j], NULL);
				dnbd3_add_trusted_namespace(server, keys[j], flags);
				g_free(flags);
			}
			g_strfreev(keys);
			continue;
		}

		// An actual image definition

		int rid = g_key_file_get_integer(_config_handle, groups[i], "rid", NULL);
		if (rid <= 0)
		{
			memlogf("[ERROR] Invalid rid '%d' for image '%s'", rid, groups[i]);
			continue;
		}

		const time_t delsoft = g_key_file_get_int64(_config_handle, groups[i], "delete_soft", NULL);
		const time_t delhard = g_key_file_get_int64(_config_handle, groups[i], "delete_hard", NULL);
		if ((delsoft != 0 && delsoft < time(NULL)) || (delhard != 0 && delhard < time(NULL)))
		{
			memlogf("[INFO] Ignoring image '%s' as its deletion is due", groups[i]);
			continue;
		}

		char *image_file = g_key_file_get_string(_config_handle, groups[i], "file", NULL);
		char *cache_file = g_key_file_get_string(_config_handle, groups[i], "cache", NULL);

		dnbd3_image_t *image = prepare_image(groups[i], rid, image_file, cache_file);
		if (image)
		{
			_dnbd3_images = g_slist_prepend(_dnbd3_images, image);
		}

		g_free(image_file);
		g_free(cache_file);
	}

	g_strfreev(groups);
}

int dnbd3_add_image(dnbd3_image_t *image)
{
	// Lock here to prevent concurrent add calls to mess rids up. Cannot happen currently
	// as IPC clients are not threaded and they're the only place where this is called,
	// but better be safe for the future...
	pthread_spin_lock(&_spinlock);
	if (image->rid == 0)
	{
		const dnbd3_image_t *latest = dnbd3_get_image(image->config_group, 0, 0);
		if (latest)
			image->rid = latest->rid + 1;
		else
			image->rid = 1;
	}

	dnbd3_image_t *newimage = prepare_image(image->config_group, image->rid, image->file, image->cache_file);
	image = NULL;
	if (newimage)
	{
		_dnbd3_images = g_slist_prepend(_dnbd3_images, newimage);
	}
	else
	{
		pthread_spin_unlock(&_spinlock);
		return ERROR_SEE_LOG;
	}

	// Adding image was successful, write config file
	g_key_file_set_integer(_config_handle, newimage->config_group, "rid", newimage->rid);
	if (newimage->file)
		g_key_file_set_string(_config_handle, newimage->config_group, "file", newimage->file);
	if (newimage->cache_file)
		g_key_file_set_string(_config_handle, newimage->config_group, "cache", newimage->cache_file);

	pthread_spin_unlock(&_spinlock);

	const int ret = dnbd3_save_config();
	if (ret == ERROR_OK)
		memlogf("[INFO] Added new image '%s' (rid %d)", newimage->config_group, newimage->rid);
	else
		memlogf("[INFO] Added new image '%s' (rid %d), but config file could not be written (%s)", newimage->config_group, newimage->rid, _config_file_name);
	return ret;
}

int dnbd3_del_image(dnbd3_image_t *image)
{
	if (image->rid <= 0) // Require a specific rid on deletion
		return ERROR_RID;
	pthread_spin_lock(&_spinlock);
	dnbd3_image_t *existing_image = dnbd3_get_image(image->config_group, image->rid, 0);
	if(existing_image == NULL)
	{
		pthread_spin_unlock(&_spinlock);
		return ERROR_IMAGE_NOT_FOUND;
	}

	existing_image->delete_soft = 1; // TODO: Configurable.
	existing_image->delete_hard = time(NULL) + 86400; // TODO: Configurable
	g_key_file_set_int64(_config_handle, image->config_group, "delete_soft", existing_image->delete_soft);
	g_key_file_set_int64(_config_handle, image->config_group, "delete_hard", existing_image->delete_hard);

	pthread_spin_unlock(&_spinlock);
	dnbd3_exec_delete(FALSE);
	existing_image = NULL;

	const int ret = dnbd3_save_config();
	if (ret == ERROR_OK)
		memlogf("[INFO] Marked for deletion: '%s' (rid %d)", image->config_group, image->rid);
	else
		memlogf("[WARNING] Marked for deletion: '%s' (rid %d), but config file could not be written (%s)", image->config_group, image->rid, _config_file_name);
	return ret;
}

int dnbd3_save_config()
{
	pthread_spin_lock(&_spinlock);
	char *data = (char *)g_key_file_to_data(_config_handle, NULL, NULL);
	if (data == NULL)
	{
		pthread_spin_unlock(&_spinlock);
		memlogf("[ERROR] g_key_file_to_data() failed");
		return ERROR_UNSPECIFIED_ERROR;
	}

	FILE *f = fopen(_config_file_name, "w");
	if (f < 0)
	{
		pthread_spin_unlock(&_spinlock);
		g_free(data);
		return ERROR_CONFIG_FILE_PERMISSIONS;
	}
	fputs("# Do not edit this file while dnbd3-server is running\n", f);
	fputs(data, f);
	fclose(f);
	pthread_spin_unlock(&_spinlock);
	g_free(data);
	return 0;
}

dnbd3_image_t *dnbd3_get_image(char *name_orig, int rid, const char do_lock)
{
	dnbd3_image_t *result = NULL, *image;
	GSList *iterator;
	// For comparison, make sure the name is global and lowercased
	int slen;
	int islocal = (strchr(name_orig, '/') == NULL);
	if (islocal)
		slen = strlen(name_orig) + strlen(_local_namespace) + 2;
	else
		slen = strlen(name_orig) + 1;
	char name[slen];
	if (islocal)
		sprintf(name, "%s/%s", _local_namespace, name_orig);
	else
		strcpy(name, name_orig);
	strtolower(name);
	// Now find the image
	if (do_lock)
		pthread_spin_lock(&_spinlock);
	for (iterator = _dnbd3_images; iterator; iterator = iterator->next)
	{
		image = iterator->data;
		if (rid != 0) // rid was specified
		{
			if (image->rid == rid && strcmp(name, image->low_name) == 0)
			{
				result = image;
				break;
			}
		}
		else // search max. rid available
		{
			if (strcmp(name, image->low_name) == 0 && (result == NULL || result->rid < image->rid))
			{
				result = image;
			}
		}
	}
	if (do_lock)
		pthread_spin_unlock(&_spinlock);
	return result;
}

void dnbd3_handle_sigpipe(int signum)
{
	memlogf("ERROR: SIGPIPE received (%s)", strsignal(signum));
}

void dnbd3_handle_sigterm(int signum)
{
	memlogf("INFO: SIGTERM or SIGINT received (%s)", strsignal(signum));
	dnbd3_cleanup();
}

/**
 * Prepare image to be added to image list. Returns a pointer to a newly allocated image struct
 * on success, NULL otherwise.
 * Note: This function calls dnbd3_get_image without locking, so make sure you lock
 * before calling this function while the server is active.
 */
static dnbd3_image_t *prepare_image(char *image_name, int rid, char *image_file, char *cache_file)
{
	int j;
	if (image_name == NULL)
	{
		memlogf("[ERROR] Null Image-Name");
		return NULL;
	}

	char *slash = strrchr(image_name, '/');

	if (slash == NULL)
	{
		if (!is_valid_imagename(image_name))
		{
			memlogf("[ERROR] Invalid image name: '%s'", image_name);
			return NULL;
		}
		if (_local_namespace == NULL)
		{
			memlogf("[ERROR] Image '%s' has local name and no default namespace is defined; entry ignored.", image_name);
			return NULL;
		}
	}
	else
	{
		*slash = '\0';
		if (!is_valid_imagename(slash+1))
		{
			memlogf("[ERROR] Invalid image name: '%s'", slash+1);
			return NULL;
		}
		if (!is_valid_namespace(image_name))
		{
			memlogf("[ERROR] Invalid namespace: '%s'", image_name);
			*slash = '/';
			return NULL;
		}
		*slash = '/';
	}

	// Allocate image struct and zero it out by using g_new0
	dnbd3_image_t *image = g_new0(dnbd3_image_t, 1);
	if (image == NULL)
	{
		memlogf("[ERROR] Could not allocate dnbd3_image_t while reading config");
		return NULL;
	}

	if (slash == NULL)
	{
		// Local image, build global name
		image->low_name = calloc(strlen(_local_namespace) + strlen(image_name) + 2, sizeof(char));
		sprintf(image->low_name, "%s/%s", _local_namespace, image_name);
	}
	else
	{
		image->low_name = strdup(image_name);
	}

	if (dnbd3_get_image(image->low_name, rid, 0))
	{
		memlogf("[ERROR] Duplicate image in config: '%s' rid:%d", image_name, rid);
		goto error;
	}

	strtolower(image->low_name);
	image->config_group = strdup(image_name);

	image->rid = rid;
	image->relayed = (image_file == NULL || image_file == '\0');

	if (image_file && strncmp(image_file, "/dev/dnbd", 9) == 0)
	{
		printf("[BUG BUG BUG] Image file is %s\n", image_file);
		image->relayed = TRUE;
	}

	if (image->relayed)	// Image is relayed (this server acts as proxy)
	{
		if (strchr(image_name, '/') == NULL)
		{
			memlogf("[ERROR] Relayed image without global name in config: '%s'", image_name);
			goto error;
		}
		if (cache_file && *cache_file)
			image->cache_file = strdup(cache_file);
	}
	else	// Image is a local one, open file to get size
	{
		image->file = strdup(image_file);
		int fd = open(image->file, O_RDONLY);
		if (fd < 0)
		{
			memlogf("[ERROR] Image file not found: '%s'", image->file);
			goto error;
		}
		const off_t size = lseek(fd, 0, SEEK_END);
		if (size <= 0)
		{
			memlogf("[ERROR] File '%s' of image '%s' has size '%lld'. Image ignored.",
			        image->file, image_name, (long long)size);
			goto error;
		}
		image->filesize = (uint64_t)size;
		if (image->filesize & 4095)
		{
			memlogf("[WARNING] Size of image '%s' is not a multiple of 4096. Last incomplete block will be ignored!",
			        image->file);
			image->filesize &= ~(uint64_t)4095;
		}
		close(fd);
		image->working = 1;
	}

	if (image->cache_file)
	{
		// Determine size of cached image
		int fd = open(image->cache_file, O_RDONLY);
		if (fd >= 0)
		{
			const off_t size = lseek(fd, 0, SEEK_END);
			if (size > 0)
				image->filesize = (uint64_t)size;
			close(fd);
		}
		if (image->filesize & 4095)
		{
			// Cache files should always be truncated to 4kib boundaries already
			memlogf("[WARNING] Size of cache file '%s' is not a multiple of 4096. Something's fishy!", image->cache_file);
			image->filesize = 0;
		}
		else if (image->filesize > 0)
		{
			printf("[DEBUG] Size known %llu for %s\n", (unsigned long long)image->filesize, image->cache_file);
			const size_t map_len_bytes = IMGSIZE_TO_MAPBYTES(image->filesize);
			image->cache_map = calloc(map_len_bytes, sizeof(uint8_t));
			// read cache map from file
			char tmp[strlen(image->cache_file) + 5];
			strcpy(tmp, image->cache_file);
			strcat(tmp, ".map");
			fd = open(tmp, O_RDONLY);
			if (fd >= 0)
			{
				const off_t size = lseek(fd, 0, SEEK_END);
				if (size != map_len_bytes)
				{
					memlogf("[DEBUG] Cache-Map of %s is corrupted (%d != %d)", image_name, (int)size, (int)map_len_bytes);
				}
				else
				{
					lseek(fd, 0, SEEK_SET);
					read(fd, image->cache_map, map_len_bytes);
					// If the whole image is cached, mark it as working right away without waiting for an upstream server
					image->working = 1;
					for (j = 0; j < map_len_bytes - 1; ++j)
					{
						if (image->cache_map[j] != 0xFF)
						{
							image->working = 0;
							break;
						}
					}
					const int blocks_in_last_byte = (image->filesize >> 12) & 7;
					uint8_t last_byte = 0;
					if (blocks_in_last_byte == 0)
						last_byte = 0xFF;
					else
						for (j = 0; j < blocks_in_last_byte; ++j)
							last_byte |= (1 << j);
					if ((image->cache_map[map_len_bytes - 1] & last_byte) != last_byte)
						image->working = 0;
					else
						memlogf("[INFO] Instantly publishing relayed image '%s' because the local cache copy is complete", image_name);
				}
				close(fd);
			}

			/*
			 // TODO: Do this as soon as a connection to a upstream server is established
			 // open cache file
			 fd = open(_images[i].cache_file, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
			 if (fd < 1)
			 memlogf("ERROR: Could't create cache file '%s'", _images[i].cache_file);

			 if (_images[i].filesize != lseek(fd, 0, SEEK_END))
			 fallocate(fd, 0, 0, _images[i].filesize);

			 close(fd);
			 */
		}
	} // end cache_file handling
	return image;
error:
	// Free stuff. Some pointers might be zero, but calling free() on those is safe.
	free(image->cache_map);
	free(image->config_group);
	free(image->low_name);
	free(image->file);
	free(image->cache_file);
	g_free(image);
	return NULL;
}

/**
 * Iterate over all images and delete them if appropriate.
 */
void dnbd3_exec_delete(int save_if_changed)
{
	int changed = FALSE;
	const time_t now = time(NULL);
	GSList *image_iterator, *client_iterator;
	char ipstr[100];

	pthread_spin_lock(&_spinlock);
	for (image_iterator = _dnbd3_images; image_iterator; image_iterator = image_iterator->next)
	{
		dnbd3_image_t *image = image_iterator->data;
		int delete_now = TRUE;
		if (image->delete_hard != 0 && image->delete_hard < now)
		{
			// Drop all clients still using it
			for (client_iterator = _dnbd3_clients; client_iterator; client_iterator = client_iterator->next)
			{
				dnbd3_client_t *client = client_iterator->data;
				if (client->image != image)
					continue;
				// Kill client's connection
				*ipstr = '\0';
				host_to_string(&client->host, ipstr, 100);
				memlogf("[INFO] delete_hard of %s reached; dropping client %s", image->config_group, ipstr);
				const int fd = client->sock;
				client->sock = -1;
				close(fd);
				delete_now = FALSE; // Wait for all clients being actually dropped; deletion will happen on next dnbd3_exec_delete()
			}
		} // END delete_hard image
		else if (image->delete_soft != 0 && image->delete_soft < now && image->atime + 3600 < now)
		{
			// Image should be soft-deleted
			// Check if it is still in use
			for (client_iterator = _dnbd3_clients; client_iterator; client_iterator = client_iterator->next)
			{
				const dnbd3_client_t *client = client_iterator->data;
				if (client->image == image)
				{
					// Yep, still in use, keep it
					delete_now = FALSE;
					break;
				}
			}
		}
		else	// Neither hard nor soft delete, keep it
			delete_now = FALSE;
		if (delete_now)
		{
			// Image was not in use and should be deleted, free it!
			memlogf("[INFO] Freeing end-of-life image %s", image->config_group);
			changed = TRUE;
			_dnbd3_images = g_slist_remove(_dnbd3_images, image); // Remove from image list
			g_key_file_remove_group(_config_handle, image->config_group, NULL); // Also remove from config file
			// Free any allocated memory
			free(image->cache_map);
			free(image->config_group);
			free(image->low_name);
			free(image->file);
			free(image->cache_file);
			g_free(image);
			// Restart iteration as it would be messed up now
			image_iterator = _dnbd3_images;
		}
	} // END image iteration
	pthread_spin_lock(&_spinlock);

	if (changed && save_if_changed)
		dnbd3_save_config();
}

/**
 * Return pointer to trusted_server matching given address.
 * If not found and create_if_not_found is TRUE, a new entry will be created,
 * added to the list and then returned
 * Returns NULL otherwise, or if the address could not be parsed
 * !! Lock before calling this function !!
 */
dnbd3_trusted_server_t *dnbd3_get_trusted_server(char *address, char create_if_not_found, char *comment)
{
	dnbd3_trusted_server_t server;
	memset(&server, 0, sizeof(server));
	if (!parse_address(address, &server.host))
	{
		memlogf("[WARNING] Could not parse address '%s' of trusted server", address);
		return NULL;
	}
	if (server.host.type == AF_INET6)
	{
		printf("[DEBUG] Ignoring IPv6 trusted server.\n");
		return NULL;
	}
	GSList *iterator;
	for (iterator = _trusted_servers; iterator; iterator = iterator->next)
	{
		dnbd3_trusted_server_t *comp = iterator->data;
		if (is_same_server(&comp->host, &server.host))
			return comp;
	}
	if (!create_if_not_found)
		return NULL;
	char *groupname = NULL;
	if (comment == NULL)
	{
		groupname = malloc(50);
		snprintf(groupname, 50, "trust:%x%x", rand(), (int)clock());
	}
	else
	{
		const size_t len = strlen(comment) + 8;
		groupname = malloc(len);
		snprintf(groupname, len, "trust:%s", comment);
	}
	char addrbuffer[50];
	host_to_string(&server.host, addrbuffer, 50);
	g_key_file_set_string(_config_handle, groupname, "address", addrbuffer);
	dnbd3_trusted_server_t *copy = malloc(sizeof(server));
	memcpy(copy, &server, sizeof(*copy));
	copy->comment = strdup(groupname+6);
	_trusted_servers = g_slist_prepend(_trusted_servers, copy);
	free(groupname);
	return copy;
}

/**
 * Add new trusted namespace to given trusted server, using given flags.
 * Overwrites any existing entry for the given server and namespace
 * !! Lock before calling this function !!
 */
int dnbd3_add_trusted_namespace(dnbd3_trusted_server_t *server, char *namespace, char *flags)
{
	int nslen = strlen(namespace) + 1;
	char nslow[nslen];
	memcpy(nslow, namespace, nslen);
	strtolower(nslow);
	GSList *iterator;
	dnbd3_namespace_t *ns = NULL;
	for (iterator = server->namespaces; iterator; iterator = iterator->next)
	{
		dnbd3_namespace_t *cmp = iterator->data;
		if (strcmp(nslow, cmp->name) == 0)
		{
			ns = cmp;
			break;
		}
	}
	if (ns == NULL)
	{
		ns = calloc(1, sizeof(*ns));
		ns->name = strdup(nslow);
		server->namespaces = g_slist_prepend(server->namespaces, ns);
	}
	ns->auto_replicate = (flags && strstr(flags, "replicate"));
	ns->recursive = (flags && strstr(flags, "recursive"));
	size_t len = strlen(server->comment) + 7;
	char groupname[len];
	snprintf(groupname, len, "trust:%s", server->comment);
	if (ns->auto_replicate && ns->recursive)
		g_key_file_set_string(_config_handle, groupname, ns->name, "replicate,recursive");
	else if (ns->auto_replicate)
		g_key_file_set_string(_config_handle, groupname, ns->name, "replicate");
	else if (ns->recursive)
		g_key_file_set_string(_config_handle, groupname, ns->name, "recursive");
	else
		g_key_file_set_string(_config_handle, groupname, ns->name, "-");
	return TRUE;
}

/**
 * Return local image name for a global image name
 * eg. "uni-freiburg/rz/ubuntu 12.04" -> "ubuntu 12.04"
 * ONLY IF the local name space really is "uni-freiburg/rz"
 * Returns NULL otherwise
 * The returned pointer points to memory inside the passed
 * string (if not NULL), so do not modify or free
 * / <---
static char* get_local_image_name(char *global_name)
{
	if (_local_namespace == NULL)
		return NULL; // No local namespace defined, so it cannot be local
	char *first_slash = strchr(global_name, '/');
	if (first_slash == NULL)
		return global_name; // Already local
	const size_t buflen = strlen(_local_namespace) + 1;
	if (first_slash - global_name + 1 != buflen)
		return NULL; // Namespaces have different length, cannot be same
	char namespace[buflen];
	char passedname[buflen];
	strcpy(namespace, _local_namespace);
	strncpy(passedname, global_name, buflen);
	passedname[buflen] = '\0';
	strtolower(namespace);
	strtolower(passedname);
	if (strcmp(namespace, passedname) == 0)
		return global_name + buflen; // points somewhere into passed buffer
	return NULL;
} //*/
