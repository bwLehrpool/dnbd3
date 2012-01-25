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
#include <search.h>
#include <string.h>

#include "../config.h"

char key_buf[MAX_NUMBER_IMAGES * MAX_FILE_ID];
char value_buf[MAX_NUMBER_IMAGES * MAX_FILE_NAME];

char *key_ptr = key_buf;
char *val_ptr = value_buf;

void ht_create()
{
	(void) hcreate(MAX_NUMBER_IMAGES);
}

int ht_insert(char* key, char* value)
{
	if (strlen(key) > MAX_FILE_ID) return -1;
	if (strlen(value) > MAX_FILE_NAME) return -2;

	strcpy(key_ptr, key);
	strcpy(val_ptr, value);

	ENTRY item;
	item.key = key_ptr;
	item.data = val_ptr;

	(void) hsearch(item, ENTER);

	key_ptr += strlen(key) + 1;
	val_ptr += strlen(value) + 1;

	return 0;
}

char* ht_search(char* key)
{
	ENTRY *result;

	ENTRY item;
	item.key = key;

	if ((result = hsearch(item, FIND)) != NULL)
		return result->data;
	else
		return NULL;
}
