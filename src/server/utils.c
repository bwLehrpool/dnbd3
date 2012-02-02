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

#include "server.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>


void dnbd3_write_pid_file(pid_t pid)
{
    FILE *f = fopen(SERVER_PID_FILE, "w");
    if (f != NULL)
    {
        fprintf(f, "%i", pid);
        fclose(f);
    }
    else
    {
        printf("ERROR: Couldn't write pid file (%s).\n", SERVER_PID_FILE);
    }
}

pid_t dnbd3_read_pid_file()
{
    pid_t pid = 0;

    FILE *f = fopen(SERVER_PID_FILE, "r");
    if (f != NULL)
    {
        fscanf(f, "%i", &pid);
        fclose(f);
    }
    else
    {
        printf("ERROR: Couldn't read pid file (%s).\n", SERVER_PID_FILE);
    }

    return pid;
}

void dnbd3_delete_pid_file()
{
    if (unlink(SERVER_PID_FILE) != 0)
    {
        printf("ERROR: Couldn't delete pid file (%s).\n", SERVER_PID_FILE);
    }
}

void dnbd3_send_signal(int signum)
{
    pid_t pid = dnbd3_read_pid_file();
    if (pid != 0)
    {
        if (kill(pid, signum) != 0)
        {
            printf("ERROR: dnbd3-server is not running\n");
            dnbd3_delete_pid_file();
        }
    }
    else
    {
        printf("ERROR: dnbd3-server is not running\n");
    }
}

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
        _images[i].servers = g_key_file_get_string_list(gkf, groups[i], "servers", &_images[i].num, NULL);
        _images[i].vid = g_key_file_get_integer(gkf, groups[i], "vid", NULL);
        _images[i].rid = g_key_file_get_integer(gkf, groups[i], "rid", NULL);

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
    g_key_file_free (gkf);
}

void dnbd3_reload_config(char* config_file_name)
{
    free(_images);
    _num_images = 0;
    dnbd3_load_config(config_file_name);
}

dnbd3_image_t* dnbd3_get_image(int vid, int rid)
{
    // TODO: find better data structure
    dnbd3_image_t *result = NULL;
    int i;
    for (i = 0; i < _num_images; ++i) {
        if (_images[i].vid == vid && _images[i].rid == rid)
            result = &_images[i];

    }
    return result;
}
