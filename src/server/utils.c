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

#include "utils.h"
#include "hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

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

void dnbd3_load_config(char* config_file_name)
{
    dnbd3_ht_create();
    FILE *config_file = fopen(config_file_name, "r");

    if (config_file == NULL)
    {
        printf("ERROR: Config file not found: %s\n", config_file_name);
        exit(EXIT_FAILURE);
    }

    char line[MAX_FILE_NAME + 1 + MAX_FILE_ID];
    char* image_name = NULL;
    char* image_id = NULL;

    while (fgets(line, sizeof(line), config_file) != NULL)
    {
        sscanf(line, "%as %as", &image_name, &image_id);
        if (dnbd3_ht_insert(image_id, image_name) < 0)
        {
            printf("ERROR: Image name or ID is too big\n");
            exit(EXIT_FAILURE);
        }
    }
    fclose(config_file);
}

void dnbd3_reload_config(char* config_file_name)
{
    dnbd3_ht_destroy();
    dnbd3_load_config(config_file_name);
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
