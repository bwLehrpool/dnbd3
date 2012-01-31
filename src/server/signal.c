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

#include <stdio.h>
#include <pthread.h>

#include "server.h"
#include "utils.h"

void dnbd3_handle_sigpipe(int signum)
{
    printf("ERROR: SIGPIPE received!\n");
}

void dnbd3_handle_sighup(int signum)
{
    printf("INFO: SIGHUP received!\n");
    printf("INFO: Reloading configuration...\n");
    pthread_spin_lock(&_spinlock);
    dnbd3_reload_config(_config_file_name);
    pthread_spin_unlock(&_spinlock);
}

void dnbd3_handle_sigterm(int signum)
{
    printf("INFO: SIGTERM or SIGINT received!\n");
    dnbd3_cleanup();
}
