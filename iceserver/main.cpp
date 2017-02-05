/* $Id: main.c 3553 2011-05-05 06:14:19Z nanang $ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <vector>

#include "pub.h"

extern "C"
{
#include "turn.h"
#include "auth.h"
}


#define REALM		"pjsip.org"
//#define TURN_PORT	PJ_STUN_TURN_PORT
#define TURN_PORT_UDP	34780
#define	SING_TRANSMIT_UDP 34781
#define TURN_PORT_TCP	34780
#define LOG_LEVEL	4

typedef struct client_addr_s
{
	struct sockaddr_in cliaddr;
	socklen_t len;
	int sockfd;

	client_addr_s()
	{
		memset(&cliaddr, 0, sizeof(cliaddr));
		len = sizeof(socklen_t);
		sockfd = 0;
	}
}client_addr_t;

typedef struct singal_info_s
{
	client_addr_t cli;
	std::string msg;
}singal_info_t;

typedef struct attr_type_value_s
{
	int type;
	std::string value;
}attr_type_value_t;

static pj_caching_pool g_cp;
static pj_bool_t g_quit = PJ_FALSE;

static void SigUsr(int signo)
{
	if (SIGUSR1 == signo)
	{
		g_quit = PJ_TRUE;
	}
}

int err(const char *title, pj_status_t status)
{
	char errmsg[PJ_ERR_MSG_SIZE];
	pj_strerror(status, errmsg, sizeof(errmsg));

	printf("%s: %s\n", title, errmsg);
	return 1;
}

static void dump_status(pj_turn_srv *srv)
{
	char addr[80];
	pj_hash_iterator_t itbuf, *it;
	pj_time_val now;
	unsigned i;

	for (i=0; i<srv->core.lis_cnt; ++i) {
	pj_turn_listener *lis = srv->core.listener[i];
	printf("Server address : %s\n", lis->info);
	}

	printf("Worker threads : %d\n", srv->core.thread_cnt);
	printf("Total mem usage: %u.%03uMB\n", (unsigned)(g_cp.used_size / 1000000),
	   (unsigned)((g_cp.used_size % 1000000)/1000));
	printf("UDP port range : %u %u %u (next/min/max)\n", srv->ports.next_udp,
	   srv->ports.min_udp, srv->ports.max_udp);
	printf("TCP port range : %u %u %u (next/min/max)\n", srv->ports.next_tcp,
	   srv->ports.min_tcp, srv->ports.max_tcp);
	printf("Clients #      : %u\n", pj_hash_count(srv->tables.alloc));

	puts("");

	if (pj_hash_count(srv->tables.alloc)==0) {
	return;
	}

	puts("#    Client addr.          Alloc addr.            Username Lftm Expy #prm #chl");
	puts("------------------------------------------------------------------------------");

	pj_gettimeofday(&now);

	it = pj_hash_first(srv->tables.alloc, &itbuf);
	i=1;
	while (it) {
	pj_turn_allocation *alloc = (pj_turn_allocation*)
					pj_hash_this(srv->tables.alloc, it);
	printf("%-3d %-22s %-22s %-8.*s %-4d %-4ld %-4d %-4d\n",
		   i,
		   alloc->info,
		   pj_sockaddr_print(&alloc->relay.hkey.addr, addr, sizeof(addr), 3),
		   (int)alloc->cred.data.static_cred.username.slen,
		   alloc->cred.data.static_cred.username.ptr,
		   alloc->relay.lifetime,
		   alloc->relay.expiry.sec - now.sec,
		   pj_hash_count(alloc->peer_table),
		   pj_hash_count(alloc->ch_table));

	it = pj_hash_next(srv->tables.alloc, it);
	++i;
	}
}

void do_registe(const std::vector<attr_type_value_t> &content)
{
	std::string guid;
	std::string local_info;

	for (std::vector<attr_type_value_t>::const_iterator iter = content.begin();
		 iter != content.end();
		 ++iter)
	{
		const attr_type_value_t& item(*iter);
		switch (item.type)
		{
		case TYPE_ATTR_GUID:
			guid = item.value;
			break;
		case TYPE_ATTR_LOCAL_INFO:
			local_info = item.value;
			break;
		default:
			break;
		}
	}
}

void do_handle_singal_info(int msg_type, const std::vector<attr_type_value_t> &content)
{
	switch (msg_type)
	{
	case MSG_TYPE_REGISTER:
		do_registe(content);
		break;
	default:
		break;
	}
}

void* handle_singal_info(void* data)
{
	assert(data != NULL);
	singal_info_t *signal_info = (singal_info_t*)data;

	unsigned i = 0;
	int msg_type = 0;
	memcpy(&msg_type, &signal_info->msg[0], sizeof(msg_type));
	i += sizeof(msg_type);

	std::vector<attr_type_value_t> vec_attrs;

	for(; i < signal_info->msg.length();)
	{
		attr_type_value_t attr;

		memcpy(&attr.type, &signal_info->msg[i], sizeof(attr.type));
		attr.type = ntohl(attr.type);
		i += sizeof(attr.type);

		int len = 0;
		memcpy(&len, &signal_info->msg[i], sizeof(len));
		len = ntohl(len);
		i += sizeof(len);

		attr.value.assign(&signal_info->msg[i], len);
		i+= len;

		vec_attrs.push_back(attr);
	}

	do_handle_singal_info(msg_type, vec_attrs);

	int ret = sendto(signal_info->cli.sockfd, "success", strlen("success"), 0, (struct sockaddr *)&signal_info->cli.cliaddr, signal_info->cli.len);
	if (ret < 0)
	{
		err("sendto error, err=%d\n", errno);
	}
}

void* thread_singal_transmit(void*)
{
	int sockfd = -1;
	struct sockaddr_in servaddr;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SING_TRANSMIT_UDP);
	bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	enum {MAX_RECV_LINE = 1024};
	char msg[MAX_RECV_LINE] = {0};

	for (;!g_quit;)
	{
		bzero(msg, MAX_RECV_LINE);

		singal_info_t *singal_info = new singal_info_t;

		int recv_len = recvfrom(sockfd, msg, MAX_RECV_LINE, 0, (struct sockaddr *)(&singal_info->cli.cliaddr), &singal_info->cli.len);
		if (recv_len < 0)
		{
			err("recv from error, errno=%d", errno);
		}

		singal_info->msg.assign(msg, recv_len);
		singal_info->cli.sockfd = sockfd;

		pthread_t t;
		pthread_create(&t, NULL, handle_singal_info, (void*)singal_info);
	}
}

int main(int argc, char* argv[])
{
	pj_bool_t DAEMON_MODE = PJ_FALSE;
	if (2 == argc && 0 == strcmp(argv[1], "-d"))
	{
		DAEMON_MODE = PJ_TRUE;
	}

	if (DAEMON_MODE && signal(SIGUSR1, SigUsr) == SIG_ERR )
	{
		return err("signal User faile.", errno);
	}

	if (DAEMON_MODE && -1 == daemon(1, 0))
	{
		return err("daemon failed.", errno);
	}

	//start singal udp listen. just used to transmit the info.
	pthread_t t_sigal;
	int ret = pthread_create(&t_sigal, NULL, thread_singal_transmit, NULL);
	if (ret != 0)
	{
		return err("create singal thread failed.", errno);
	}

	pj_turn_srv *srv = NULL;
	pj_turn_listener *listener = NULL;
	pj_status_t status;

	status = pj_init();
	if (status != PJ_SUCCESS)
	{
		return err("pj_init() error", status);
	}

	status = pjlib_util_init();
	if (status != PJ_SUCCESS)
	{
		return err("pjlib_util_init error", status);
	}

	status = pjnath_init();
	if (status != PJ_SUCCESS)
	{
		return err("pjnath_init error", status);
	}

	pj_caching_pool_init(&g_cp, NULL, 0);

	pj_turn_auth_init(REALM);

	status = pj_turn_srv_create(&g_cp.factory, &srv);
	if (status != PJ_SUCCESS)
	return err("Error creating server", status);

	status = pj_turn_listener_create_udp(srv, pj_AF_INET(), NULL,
					 TURN_PORT_UDP, 1, 0, &listener);
	if (status != PJ_SUCCESS)
	return err("Error creating UDP listener", status);

#if PJ_HAS_TCP
	status = pj_turn_listener_create_tcp(srv, pj_AF_INET(), NULL,
					 TURN_PORT_TCP, 1, 0, &listener);
	if (status != PJ_SUCCESS)
	return err("Error creating listener", status);
#endif

	status = pj_turn_srv_add_listener(srv, listener);
	if (status != PJ_SUCCESS)
	return err("Error adding listener", status);

	puts("Server is running");

	pj_log_set_level(LOG_LEVEL);

	dump_status(srv);

	while (!g_quit)
	{
		pj_thread_sleep(100);
	}

	pj_turn_srv_destroy(srv);
	pj_caching_pool_destroy(&g_cp);
	pj_shutdown();

	pthread_join(t_sigal, NULL);

	return 0;
}
