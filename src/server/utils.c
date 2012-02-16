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

#include "server.h"
#include "utils.h"

void dnbd3_load_config(char *file)
{
    int fd;
    gint i;
    GKeyFile* gkf;

    gkf = g_key_file_new();
    if (!g_key_file_load_from_file(gkf, file, G_KEY_FILE_NONE, NULL))
    {
        printf("ERROR: Config file not found: %s\n", file);
        exit(EXIT_FAILURE);
    }

    gchar **groups = NULL;
    groups = g_key_file_get_groups(gkf, &_num_images);
    _images = calloc(_num_images, sizeof(dnbd3_image_t));

    for (i = 0; i < _num_images; i++)
    {
        _images[i].file = g_key_file_get_string(gkf, groups[i], "file", NULL);
        _images[i].servers = g_key_file_get_string_list(gkf, groups[i], "servers", &_images[i].num_servers, NULL);
        _images[i].vid = g_key_file_get_integer(gkf, groups[i], "vid", NULL);
        _images[i].rid = g_key_file_get_integer(gkf, groups[i], "rid", NULL);
        _images[i].atime = 0;

        if (_images[i].num_servers > NUMBER_SERVERS)
            printf("WARN: Max allowed servers %i\n", NUMBER_SERVERS);

        fd = open(_images[i].file, O_RDONLY);
        if (fd > 0)
        {
            struct stat st;
            fstat(fd, &st);
            _images[i].filesize = st.st_size;
        }
        else
        {
            printf("ERROR: Image not found: %s\n", _images[i].file);
        }
        close(fd);
    }

    g_strfreev(groups);
    g_key_file_free(gkf);
}

void dnbd3_reload_config(char* config_file_name)
{
    GSList *iterator = NULL;
    for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
    {
        dnbd3_client_t *client = iterator->data;
        pthread_spin_lock(&client->spinlock);
        client->image = NULL;
    }
    _num_images = 0;
    free(_images);
    dnbd3_load_config(config_file_name);
    for (iterator = _dnbd3_clients; iterator; iterator = iterator->next)
    {
        dnbd3_client_t *client = iterator->data;
        pthread_spin_unlock(&client->spinlock);
    }
}

dnbd3_image_t* dnbd3_get_image(int vid, int rid)
{
    int i, max = 0;
    dnbd3_image_t *result = NULL;
    for (i = 0; i < _num_images; ++i)
    {
        if (rid != 0) // rid was specified
        {
            if (_images[i].vid == vid && _images[i].rid == rid)
                result = &_images[i];
        }
        else // search max. rid available
        {
            if (_images[i].vid == vid && _images[i].rid > max)
            {
                result = &_images[i];
                max = _images[i].rid;
            }
        }
    }
    return result;
}

void dnbd3_handle_sigpipe(int signum)
{
    printf("ERROR: SIGPIPE received!\n");
}

void dnbd3_handle_sigterm(int signum)
{
    printf("INFO: SIGTERM or SIGINT received!\n");
    dnbd3_cleanup();
}
