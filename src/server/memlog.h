/*
 * This file is part of the Distributed Network Block Device 3
 *
 * Copyright(c) 2011-2012 Simon Rettberg
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

#ifndef MEMLOG_H_
#define MEMLOG_H_

void initmemlog();

/**
 * Add a line to the log
 */
void memlogf(char *text, ...);

/**
 * Return log lines, separated by \n
 * You need to free() the returned memory after use
 * Returns NULL on error
 * maxlines - Limit number of lines returned, 0 = everything
 */
char *fetchlog(int maxlines);

#endif /* MEMLOG_H_ */
