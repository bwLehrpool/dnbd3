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

#include <unistd.h>
#include <sys/types.h>

#include "../config.h"

#ifndef UTILS_H_
#define UTILS_H_

#define ERROR_FILE_NOT_FOUND            1
#define ERROR_IMAGE_ALREADY_EXISTS      2
#define ERROR_CONFIG_FILE_PERMISSIONS   3
#define ERROR_IMAGE_NOT_FOUND           4
#define ERROR_RID                       5
#define ERROR_IMAGE_IN_USE              6
#define ERROR_MISSING_ARGUMENT          7
#define ERROR_UNSPECIFIED_ERROR         8
#define ERROR_INVALID_XML               9
#define ERROR_UNKNOWN_COMMAND          10
#define ERROR_SEE_LOG                  11

void dnbd3_load_config(char *file);
int dnbd3_add_image(dnbd3_image_t *image, char *file);
int dnbd3_del_image(dnbd3_image_t *image, char *file);

dnbd3_image_t* dnbd3_get_image(char *name, int rid, const char do_lock);

void dnbd3_handle_sigpipe(int signum);
void dnbd3_handle_sigterm(int signum);

#endif /* UTILS_H_ */
