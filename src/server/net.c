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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "helper.h"
#include "server.h"
#include "saveload.h"
#include "memlog.h"
#include "../serialize.h"
#include "../config.h"


static inline char recv_request_header(int sock, dnbd3_request_t *request)
{
	int ret;
	// Read request header from socket
	if ((ret = recv(sock, request, sizeof(*request), MSG_WAITALL)) != sizeof(*request))
	{
		if (ret == 0) return 0;
		printf("[DEBUG] Error receiving request: Could not read message header (%d/%d)\n", ret, (int)sizeof(*request));
		return 0;
	}
	// Make sure all bytes are in the right order (endianness)
	fixup_request(*request);
	if (request->magic != dnbd3_packet_magic)
	{
		printf("[DEBUG] Magic in client request incorrect (cmd: %d, len: %d)\n", (int)request->cmd, (int)request->size);
		return 0;
	}
	// Payload sanity check
	if (request->cmd != CMD_GET_BLOCK && request->size > MAX_PAYLOAD)
	{
		memlogf("[WARNING] Client tries to send a packet of type %d with %d bytes payload. Dropping client.", (int)request->cmd, (int)request->size);
		return 0;
	}
#ifdef _DEBUG
	if (_fake_delay) usleep(_fake_delay);
#endif
	return 1;
}

static inline char recv_request_payload(int sock, uint32_t size, serialized_buffer_t *payload)
{
	if (size == 0)
	{
		memlogf("[BUG] Called recv_request_payload() to receive 0 bytes");
		return 0;
	}
	if (size > MAX_PAYLOAD)
	{
		memlogf("[BUG] Called recv_request_payload() for more bytes than the passed buffer could hold!");
		return 0;
	}
	if (recv(sock, payload->buffer, size, MSG_WAITALL) != size)
	{
		printf("[ERROR] Could not receive request payload of length %d\n", (int)size);
		return 0;
	}
	// Prepare payload buffer for reading
	serializer_reset_read(payload, size);
	return 1;
}

static inline char send_reply(int sock, dnbd3_reply_t *reply, void *payload)
{
	const unsigned int size = reply->size;
	fixup_reply(*reply);
	if (!payload || size == 0)
	{
		if (send(sock, reply, sizeof(dnbd3_reply_t), MSG_WAITALL) != sizeof(dnbd3_reply_t))
		{
			printf("[DEBUG] Send failed (header-only)\n");
			return 0;
		}
	}
	else
	{
		struct iovec iov[2];
		iov[0].iov_base = reply;
		iov[0].iov_len = sizeof(dnbd3_reply_t);
		iov[1].iov_base = payload;
		iov[1].iov_len = size;
		if (writev(sock, iov, 2) != sizeof(dnbd3_reply_t) + size)
		{
			printf("[DEBUG] Send failed (reply with payload of %u bytes)\n", size);
			return 0;
		}
	}
	return 1;
}

void *dnbd3_handle_query(void *dnbd3_client)
{
	dnbd3_client_t *client = (dnbd3_client_t *) (uintptr_t) dnbd3_client;
	dnbd3_request_t request;
	dnbd3_reply_t reply;

	dnbd3_image_t *image = NULL;
	int image_file = -1, image_cache = -1;

	int i, num;

	uint64_t map_y;
	char map_x, bit_mask;
	serialized_buffer_t payload;
	char *image_name;
	uint16_t rid, client_version;

	uint64_t todo_size = 0;
	uint64_t todo_offset = 0;
	uint64_t cur_offset = 0;
	uint64_t last_offset = 0;

	dnbd3_server_entry_t server_list[NUMBER_SERVERS];

	int dirty = 0;

	reply.magic = dnbd3_packet_magic;

	// Receive first packet. This must be CMD_GET_SIZE by protocol specification
	if (recv_request_header(client->sock, &request))
	{
		if (request.cmd != CMD_GET_SIZE)
		{
			printf("[DEBUG] Client sent invalid handshake (%d). Dropping Client\n", (int)request.cmd);
		}
		else
		{
			if (recv_request_payload(client->sock, request.size, &payload))
			{
				client_version = serializer_get_uint16(&payload);
				image_name = serializer_get_string(&payload);
				rid = serializer_get_uint16(&payload);
				client->is_server = serializer_get_uint8(&payload);
				if (request.size < 3 || !image_name || client_version < MIN_SUPPORTED_CLIENT)
				{
					if (client_version < MIN_SUPPORTED_CLIENT)
					{
						printf("[DEBUG] Client too old\n");
					}
					else
					{
						printf("[DEBUG] Incomplete handshake received\n");
					}
				}
				else
				{
					pthread_spin_lock(&_spinlock);
					image = dnbd3_get_image(image_name, rid, 0);
					const time_t now = time(NULL);
					if (!image)
					{
						printf("[DEBUG] Client requested non-existent image '%s' (rid:%d), rejected\n", image_name, (int)rid);
					}
					else if (!image->working)
					{
						printf("[DEBUG] Client requested non-working image '%s' (rid:%d), rejected\n", image_name, (int)rid);
					}
					else if ((image->delete_soft != 0 && image->delete_soft < now)
					         || (image->delete_hard != 0 && image->delete_hard < now))
					{
						printf("[DEBUG] Client requested end-of-life image '%s' (rid:%d), rejected\n", image_name, (int)rid);
					}
					else
					{
						serializer_reset_write(&payload);
						serializer_put_uint16(&payload, PROTOCOL_VERSION);
						serializer_put_string(&payload, image->low_name);
						serializer_put_uint16(&payload, image->rid);
						serializer_put_uint64(&payload, image->filesize);
						reply.cmd = CMD_GET_SIZE;
						reply.size = serializer_get_written_length(&payload);
						if (!send_reply(client->sock, &reply, &payload))
						{
							image = NULL;
						}
						else
						{
							image_file = open(image->file, O_RDONLY);
							if (image_file == -1)
							{
								image = NULL;
							}
							else
							{
								client->image = image;
								if (!client->is_server)
									image->atime = time(NULL); // TODO: check if mutex is needed

								if (image->cache_map && image->cache_file)
									image_cache = open(image->cache_file, O_RDWR);
							}
						}
					}
					pthread_spin_unlock(&_spinlock);
				}
			}
		}
	}

	// client handling mainloop
	if (image) while (recv_request_header(client->sock, &request))
		{
			switch (request.cmd)
			{

			case CMD_GET_BLOCK:
				if (request.offset >= image->filesize)
				{
					// Sanity check
					memlogf("[WARNING] Client requested non-existent block");
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply(client->sock, &reply, NULL);
					break;
				}
				if (request.offset + request.size > image->filesize)
				{
					// Sanity check
					memlogf("[WARNING] Client requested data block that extends beyond image size");
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply(client->sock, &reply, NULL);
					break;
				}
				if (request.size > image->filesize)
				{
					// Sanity check
					memlogf("[WARNING] Client requested data block that is bigger than the image size");
					reply.size = 0;
					reply.cmd = CMD_ERROR;
					send_reply(client->sock, &reply, NULL);
					break;
				}

				reply.cmd = CMD_GET_BLOCK;
				reply.size = request.size;
				reply.handle = request.handle;

				fixup_reply(reply);
				if (send(client->sock, &reply, sizeof(dnbd3_reply_t), MSG_MORE) != sizeof(dnbd3_reply_t))
				{
					printf("[DEBUG] Sending CMD_GET_BLOCK header failed\n");
					return 0;
				}

				if (request.size == 0) // Request for 0 bytes, done after sending header
					break;

				// caching is off
				if (image_cache == -1)
				{
					if (sendfile(client->sock, image_file, (off_t *)&request.offset, request.size) != request.size)
					{
						printf("[ERROR] sendfile failed (image to net)\n");
						close(client->sock);
						client->sock = -1;
					}
					break;
				}

				// caching is on
				dirty = 0;
				todo_size = 0;
				todo_offset = request.offset;
				cur_offset = request.offset;
				last_offset = request.offset + request.size;

				// first make sure the whole requested part is in the local cache file
				while(cur_offset < last_offset)
				{
					map_y = cur_offset >> 15; // div 32768
					map_x = (cur_offset >> 12) & 7; // (X div 4096) mod 8
					bit_mask = 0b00000001 << (map_x);

					cur_offset += 4096;

					if ((image->cache_map[map_y] & bit_mask) != 0) // cache hit
					{
						if (todo_size != 0) // fetch missing chunks
						{
							lseek(image_cache, todo_offset, SEEK_SET);
							if (sendfile(image_cache, image_file, (off_t *) &todo_offset, todo_size) != todo_size)
							{
								printf("[ERROR] sendfile failed (copy to cache 1)\n");
								close(client->sock);
								client->sock = -1;
								// Reset these so we don't update the cache map with false information
								dirty = 0;
								todo_size = 0;
								break;
							}
							todo_size = 0;
							dirty = 1;
						}
						todo_offset = cur_offset;
					}
					else
					{
						todo_size += 4096;
					}
				}

				// whole request was missing
				if (todo_size != 0)
				{
					lseek(image_cache, todo_offset, SEEK_SET);
					if (sendfile(image_cache, image_file, (off_t *) &todo_offset, todo_size) != todo_size)
					{
						printf("[ERROR] sendfile failed (copy to cache 2)\n");
						close(client->sock);
						client->sock = -1;
						break;
					}
					dirty = 1;
				}

				if (dirty) // cache map needs to be updated as something was missing locally
				{
					// set 1 in cache map for whole request
					cur_offset = request.offset;
					while(cur_offset < last_offset)
					{
						map_y = cur_offset >> 15;
						map_x = (cur_offset >> 12) & 7; // mod 8
						bit_mask = 0b00000001 << (map_x);
						image->cache_map[map_y] |= bit_mask;
						cur_offset += 4096;
					}
				}

				// send data to client
				if (sendfile(client->sock, image_cache, (off_t *) &request.offset, request.size) != request.size)
				{
					memlogf("[ERROR] sendfile failed (cache to net)\n");
					close(client->sock);
					client->sock = -1;
				}
				break;


			case CMD_GET_SERVERS:
				client->is_server = FALSE; // Only clients request list of servers
				// Build list of known working alt servers
				num = 0;
				for (i = 0; i < NUMBER_SERVERS; i++)
				{
					if (image->servers[i].host.type == 0 || image->servers[i].failures > 200) continue;
					memcpy(server_list + num++, image->servers + i, sizeof(dnbd3_server_entry_t));
				}
				reply.cmd = CMD_GET_SERVERS;
				reply.size = num * sizeof(dnbd3_server_entry_t);
				send_reply(client->sock, &reply, server_list);
				break;

			case CMD_KEEPALIVE:
				reply.cmd = CMD_KEEPALIVE;
				reply.size = 0;
				send_reply(client->sock, &reply, NULL);
				break;

			case CMD_SET_CLIENT_MODE:
				client->is_server = FALSE;
				break;

			default:
				memlogf("[ERROR] Unknown command: %d", (int)request.cmd);
				break;

			}

			// Check for messages that have been queued from another thread
			while (client->sendqueue != NULL)
			{
				dnbd3_binstring_t *message = NULL;
				pthread_spin_lock(&_spinlock);
				if (client->sendqueue != NULL)
				{
					message = client->sendqueue->data;
					client->sendqueue = g_slist_remove(client->sendqueue, message);
				}
				pthread_spin_unlock(&_spinlock);
				send_data(client->sock, message->data, message->len);
				free(message);
			}

		}
	pthread_spin_lock(&_spinlock);
	_dnbd3_clients = g_slist_remove(_dnbd3_clients, client);
	pthread_spin_unlock(&_spinlock);
	if (client->sock != -1)
		close(client->sock);
	if (image_file != -1) close(image_file);
	if (image_cache != -1) close(image_cache);
	dnbd3_free_client(client);
	pthread_exit((void *) 0);
}

int dnbd3_setup_socket()
{
	int sock;
	struct sockaddr_in server;

	// Create socket
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		memlogf("ERROR: Socket setup failure\n");
		return -1;
	}
	const int opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET; // IPv4
	server.sin_addr.s_addr = htonl(INADDR_ANY); // Take all IPs
	server.sin_port = htons(PORT); // set port number

	// Bind to socket
	if (bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
	{
		memlogf("ERROR: Bind failure\n");
		return -1;
	}

	// Listen on socket
	if (listen(sock, 100) == -1)
	{
		memlogf("ERROR: Listen failure\n");
		return -1;
	}

	return sock;
}
