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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "server.h"
#include "utils.h"
#include "memlog.h"

static char parse_address(char *string, uint8_t *af, uint8_t *addr, uint16_t *port);
static char is_valid_namespace(char *namespace);
static char is_valid_imagename(char *namespace);
static void strtolower(char *string);
static dnbd3_image_t *prepare_image(char *image_name, int rid, char *image_file, char *cache_file, gchar **servers, gsize num_servers);

/**
 * Parse IPv4 or IPv6 address in string representation to a suitable format usable by the BSD socket library
 * @string eg. "1.2.3.4" or "2a01::10:5", optially with port appended, eg "1.2.3.4:6666" or "2a01::10:5:6666"
 * @af will contain either AF_INET or AF_INET6
 * @addr will contain the address in network representation
 * @port will contain the port in network representation, defaulting to #define PORT if none was given
 * returns 1 on success, 0 in failure. contents of af, addr and port are undefined in the latter case
 */
static char parse_address(char *string, uint8_t *af, uint8_t *addr, uint16_t *port)
{
	struct in_addr v4;
	struct in6_addr v6;

	// Try IPv4 without port
	if (1 == inet_pton(AF_INET, string, &v4))
	{
		*af = AF_INET;
		memcpy(addr, &v4, 4);
		*port = htons(PORT);
		return 1;
	}
	// Try IPv6 without port
	if (1 == inet_pton(AF_INET6, string, &v6))
	{
		*af = AF_INET6;
		memcpy(addr, &v6, 16);
		*port = htons(PORT);
		return 1;
	}

	// Scan for port
	char *portpos = NULL, *ptr = string;
	while (*ptr)
	{
		if (*ptr == ':')
			portpos = ptr;
		++ptr;
	}
	if (portpos == NULL)
		return 0; // No port in string
	// Consider IP being surrounded by [ ]
	if (*string == '[' && *(portpos - 1) == ']')
	{
		++string;
		*(portpos - 1) = '\0';
	}
	*portpos++ = '\0';
	int p = atoi(portpos);
	if (p < 1 || p > 65535)
		return 0; // Invalid port
	*port = htons((uint16_t)p);

	// Try IPv4 with port
	if (1 == inet_pton(AF_INET, string, &v4))
	{
		*af = AF_INET;
		memcpy(addr, &v4, 4);
		return 1;
	}
	// Try IPv6 with port
	if (1 == inet_pton(AF_INET6, string, &v6))
	{
		*af = AF_INET6;
		memcpy(addr, &v6, 16);
		return 1;
	}

	// FAIL
	return 0;
}

static char is_valid_namespace(char *namespace)
{
	if (*namespace == '\0' || *namespace == '/')
		return 0; // Invalid: Length = 0 or starting with a slash
	while (*namespace)
	{
		if (*namespace != '/' && *namespace != '-' && (*namespace < 'a' || *namespace > 'z')
		   && (*namespace < 'A' || *namespace > 'Z'))
			return 0;
		++namespace;
	}
	if (*(namespace - 1) == '/')
		return 0; // Invalid: Ends in a slash
	return 1;
}

static char is_valid_imagename(char *namespace)
{
	if (*namespace == '\0' || *namespace == ' ')
		return 0; // Invalid: Length = 0 or starting with a space
	while (*namespace)
	{	// Check for invalid chars
		if (*namespace != '.' && *namespace != '-' && *namespace != ' ' && *namespace != '(' && *namespace != ')'
		   && (*namespace < 'a' || *namespace > 'z') && (*namespace < 'A' || *namespace > 'Z'))
			return 0;
		++namespace;
	}
	if (*(namespace - 1) == ' ')
		return 0; // Invalid: Ends in a space
	return 1;
}

static void strtolower(char *string)
{
	while (*string)
	{
		if (*string >= 'A' && *string <= 'Z')
			*string += 32;
		++string;
	}
}

void dnbd3_load_config()
{
	gint i;
	GKeyFile* gkf;

	if (_local_namespace != NULL || _dnbd3_images != NULL)
	{
		printf("dnbd3_load_config() called more than once\n\n");
		exit(EXIT_FAILURE);
	}

	gkf = g_key_file_new();
	if (!g_key_file_load_from_file(gkf, _config_file_name, G_KEY_FILE_NONE, NULL))
	{
		printf("ERROR: Config file not found: %s\n", _config_file_name);
		exit(EXIT_FAILURE);
	}

	_local_namespace = g_key_file_get_string(gkf, "settings", "default_namespace", NULL);
	if (_local_namespace && !is_valid_namespace(_local_namespace))
	{
		memlogf("[ERROR] Ignoring default namespace: '%s' is not a valid namespace", _local_namespace);
		g_free(_local_namespace);
		_local_namespace = NULL;
	}

	gchar **groups = NULL;
	gsize section_count;
	groups = g_key_file_get_groups(gkf, &section_count);

	for (i = 0; i < section_count; i++)
	{
		// Special group
		if (strcmp(groups[i], "settings") == 0 || strcmp(groups[i], "trusted") == 0)
		{
			continue;
		}

		// An actual image definition

		int rid = g_key_file_get_integer(gkf, groups[i], "rid", NULL);
		if (rid <= 0)
		{
			memlogf("[ERROR] Invalid rid '%d' for image '%s'", rid, groups[i]);
			continue;
		}

		char *image_file = g_key_file_get_string(gkf, groups[i], "file", NULL);
		char *cache_file = g_key_file_get_string(gkf, groups[i], "cache", NULL);
		gsize num_servers;
		gchar **servers = g_key_file_get_string_list(gkf, groups[i], "servers", &num_servers, NULL);

		pthread_spin_lock(&_spinlock);
		dnbd3_image_t *image = prepare_image(groups[i], rid, image_file, cache_file, servers, num_servers);
		if (image)
		{
			_dnbd3_images = g_slist_prepend(_dnbd3_images, image);
		}
		pthread_spin_unlock(&_spinlock);

		g_free(image_file);
		g_free(cache_file);
		g_strfreev(servers);
	}

	g_strfreev(groups);
	g_key_file_free(gkf);
}

int dnbd3_add_image(dnbd3_image_t *image)
{
	// Lock here to prevent concurrent add calls to mess rids up. Cannot happen currently
	// as IPC clients are not threaded and they're the only place where this is called,
	// but better be safe for the future...
	pthread_spin_lock(&_spinlock);
	if (image->rid == 0)
	{	// TODO: globalize image->name somewhere for this call
		const dnbd3_image_t *latest = dnbd3_get_image(image->name, image->rid, 0);
		if (latest)
			image->rid = latest->rid + 1;
		else
			image->rid = 1;
	}

	dnbd3_image_t *newimage = prepare_image(image->name, image->rid, image->file, image->cache_file, NULL, 0);
	if (newimage)
	{
		_dnbd3_images = g_slist_prepend(_dnbd3_images, image);
	}
	else
	{
		pthread_spin_unlock(&_spinlock);
		return ERROR_SEE_LOG;
	}

	// Adding image was successful, write config file
	 GKeyFile* gkf;
	 gkf = g_key_file_new();
	 if (!g_key_file_load_from_file(gkf, _config_file_name, G_KEY_FILE_NONE, NULL))
	 {
	 printf("ERROR: Config file not found: %s\n", _config_file_name);
	 exit(EXIT_FAILURE);
	 }

	 g_key_file_set_integer(gkf, image->name, "rid", image->rid);
	 g_key_file_set_string(gkf, image->name, "file", image->file);
	 //g_key_file_set_string(gkf, image->name, "servers", image->serverss); // TODO: Save servers as string
	 g_key_file_set_string(gkf, image->name, "cache", image->cache_file);

	 gchar* data = g_key_file_to_data(gkf, NULL, NULL);

	 FILE *f = fopen(_config_file_name, "w");
	 if (f >= 0)
	 {
		 fputs((char*) data, f);
		 fclose(f);
		 pthread_spin_unlock(&_spinlock);
		 g_free(data);
		 g_key_file_free(gkf);
		 memlogf("[INFO] Added new image '%s' (rid %d)", newimage->name, newimage->rid);
		 return 0;
	 }
	 pthread_spin_unlock(&_spinlock);
	 g_free(data);
	 g_key_file_free(gkf);
	 memlogf("[ERROR] Image added, but config file is not writable (%s)", _config_file_name);
	 return ERROR_SEE_LOG;
}

int dnbd3_del_image(dnbd3_image_t *image)
{
	return ERROR_IMAGE_NOT_FOUND; // TODO: Make it work with image names
	/*
	 if (image->rid == 0)
	 {
	 printf("ERROR: Delete with rid=0 is not allowed\n");
	 return ERROR_RID;
	 }

	 dnbd3_image_t* tmp = dnbd3_get_image(image->vid, image->rid);
	 if (!tmp)
	 {
	 printf("ERROR: Image not found: (%d,%d)\n", image->vid, image->rid);
	 return ERROR_IMAGE_NOT_FOUND;
	 }

	 GSList *iterator = NULL;
	 for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
	 {
	 dnbd3_client_t *client = iterator->data;
	 if (tmp == client->image)
	 {
	 printf("ERROR: Delete is not allowed, image is in use (%d,%d)\n", tmp->vid, tmp->rid);
	 return ERROR_IMAGE_IN_USE;
	 }
	 }

	 GKeyFile* gkf;
	 gkf = g_key_file_new();
	 if (!g_key_file_load_from_file(gkf, file, G_KEY_FILE_NONE, NULL))
	 {
	 printf("ERROR: Config file not found: %s\n", file);
	 exit(EXIT_FAILURE);
	 }

	 g_key_file_remove_group(gkf, tmp->group, NULL);
	 gchar* data = g_key_file_to_data(gkf, NULL, NULL);

	 FILE* f = fopen(file,"w");
	 if (f)
	 {
	 fputs((char*) data, f);
	 fclose(f);
	 g_free(data);
	 g_key_file_free(gkf);
	 // TODO: unlink image file
	 return 0;
	 }
	 else
	 {
	 g_free(data);
	 g_key_file_free(gkf);
	 printf("ERROR: Config file is not writable: %s\n", file);
	 return ERROR_CONFIG_FILE_PERMISSIONS;
	 }
	 */
}

dnbd3_image_t* dnbd3_get_image(char *name_orig, int rid, const char do_lock)
{
	dnbd3_image_t *result = NULL, *image;
	GSList *iterator;
	char name[strlen(name_orig) + 1];
	strcpy(name, name_orig);
	strtolower(name);
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
	memlogf("ERROR: SIGPIPE received!\n");
}

void dnbd3_handle_sigterm(int signum)
{
	memlogf("INFO: SIGTERM or SIGINT received!\n");
	dnbd3_cleanup();
}

/**
 * Prepare image to be added to image list. Returns a pointer to a newly allocated image struct
 * on success, NULL otherwise.
 * Note: This function calls dnbd3_get_image without locking, so make sure you lock
 * before calling this function while the server is active.
 */
static dnbd3_image_t *prepare_image(char *image_name, int rid, char *image_file, char *cache_file, gchar **servers, gsize num_servers)
{
	int j, k;
	if (image_name == NULL)
	{
		memlogf("[ERROR] Null Image-Name");
		return NULL;
	}
	if (!is_valid_imagename(image_name))
	{
		memlogf("[ERROR] Invalid image name: '%s'", image_name);
		return NULL;
	}

	if (strchr(image_name, '.') == NULL && _local_namespace == NULL)
	{
		memlogf("[ERROR] Image '%s' has local name and no default namespace is defined; entry ignored.", image_name);
		return NULL;
	}

	// Allocate image struct and zero it out by using g_new0
	dnbd3_image_t *image = g_new0(dnbd3_image_t, 1);
	if (image == NULL)
	{
		memlogf("[ERROR] Could not allocate dnbd3_image_t while reading config");
		return NULL;
	}

	if (strchr(image_name, '/') == NULL)
	{	// Local image, build global name
		image->name = calloc(strlen(_local_namespace) + strlen(image_name) + 2, sizeof(char));
		sprintf(image->name, "%s/%s", _local_namespace, image_name);
	}
	else
	{
		image->name = strdup(image_name);
	}

	if (dnbd3_get_image(image->name, rid, 0))
	{
		memlogf("[ERROR] Duplicate image in config: '%s' rid:%d", image->name, rid);
		goto error;
	}

	image->low_name = strdup(image->name);
	strtolower(image->low_name);

	image->rid = rid;
	const char relayed = (image_file == NULL || image_file == '\0');

	if (relayed)	// Image is relayed (this server acts as proxy)
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
			memlogf("[ERROR] File '%s' of image '%s' has size '%lld'. Image ignored.", image->file, image->name, (long long)size);
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

	// A list of servers that are known to also host or relay this image
	if (servers)
		for (k = 0, j = 0; j < MIN(num_servers, NUMBER_SERVERS); ++j)
		{
			if (parse_address(servers[j], &(image->servers[k].hostaddrtype), image->servers[k].hostaddr,
			   &(image->servers[k].port)))
			{
				++k;
				continue;
			}
			image->servers[k].hostaddrtype = 0;
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
		{	// Cache files should always be truncated to 4kib boundaries already
			memlogf("[WARNING] Size of cache file '%s' is not a multiple of 4096. Something's fishy!", image->cache_file);
			image->filesize = 0;
		}
		else if (image->filesize > 0)
		{
			const size_t map_len_bytes = (image->filesize + (1 << 15) - 1) >> 15;
			image->cache_map = calloc(map_len_bytes, sizeof(uint8_t));
			// read cache map from file
			// one byte in the map covers 8 4kib blocks, so 32kib per byte
			// "+ (1 << 15) - 1" is required to account for the last bit of
			// the image that is smaller than 32kib
			// this would be the case whenever the image file size is not a
			// multiple of 32kib (= the number of blocks is not dividable by 8)
			// ie: if the image is 49152 bytes and you do 49152 >> 15 you get 1,
			// but you actually need 2 bytes to have a complete cache map
			char tmp[strlen(image->cache_file) + 5];
			strcpy(tmp, image->cache_file);
			strcat(tmp, ".map");
			fd = open(tmp, O_RDONLY); // TODO: Check if map file has expected size
			if (fd >= 0)
			{
				read(fd, image->cache_map, map_len_bytes * sizeof(uint8_t));
				close(fd);
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
						last_byte = (last_byte << 1) | 1;
				if ((image->cache_map[map_len_bytes - 1] & last_byte) != last_byte)
					image->working = 0;
				else
					memlogf("[INFO] Instantly publishing relayed image '%s' because the local cache copy is complete", image->name);
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
	free(image->name);
	free(image->low_name);
	free(image->file);
	free(image->cache_file);
	g_free(image);
	return NULL;
}
