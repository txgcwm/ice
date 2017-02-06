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

typedef struct hole_info_s
{
	std::string hole_info;
	client_addr_t cli;
	time_t tm;

	hole_info_s()
	{
		tm = time(NULL);
		memset(&cli, 0, sizeof(cli));
	}
}hole_info_t;

typedef struct singal_info_s
{
	client_addr_t cli;
	std::string recv_origin_msg;
}singal_info_t;

typedef struct attr_type_value_s
{
	int type;
	std::string value;
}attr_type_value_t;

static pj_caching_pool g_cp;
static pj_bool_t g_quit = PJ_FALSE;


static std::map<std::string, hole_info_t*> *g_info_hole;
static pthread_mutex_t *g_mu_hole;

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

void do_traversal_request(const std::vector<attr_type_value_t> &content, singal_info_t* si)
{
	assert(si != NULL);

	std::string guid_answer;
	std::string guid_offer;

	for (std::vector<attr_type_value_t>::const_iterator iter = content.begin();
		 iter != content.end();
		 ++iter)
	{
		const attr_type_value_t& item(*iter);
		switch (item.type)
		{
		case TYPE_ATTR_GUID_ANSWER:
			guid_answer = item.value;
			break;
		case TYPE_ATTR_GUID_OFFER:
			guid_offer = item.value;
			break;
		default:
			break;
		}
	}

	std::string hole_answer;
	std::string hole_offer;
	client_addr_t cli_offer;

	pthread_mutex_lock(g_mu_hole);
	{
		std::map<std::string, hole_info_t*>::iterator iter = g_info_hole->find(guid_offer);
		if (iter != g_info_hole->end())
		{
			hole_offer = iter->second->hole_info;
			memcpy(&cli_offer, &iter->second->cli, sizeof(client_addr_t));
		}

		iter = g_info_hole->find(guid_answer);
		if (iter != g_info_hole->end())
		{
			hole_answer = iter->second->hole_info;
		}
	}
	pthread_mutex_unlock(g_mu_hole);

	char buff[1024] = {0};
	int offset = 0;

	int msg_type = MSG_TYPE_TRAVERSAL_RESPONSE;
	msg_type = htonl(msg_type);
	memcpy(buff + offset, &msg_type, sizeof(msg_type));
	offset += sizeof(msg_type);

	int result = 0;
	if (hole_offer.length() > 0)
	{
		result = ERROR_SUCCESS;
		result = htonl(result);
		memcpy(buff + offset, &result, sizeof(result));
		offset += sizeof(result);

		int attr = TYPE_ATTR_HOLE_INFO;
		attr = htonl(attr);
		memcpy(buff + offset, &attr, sizeof(attr));
		offset += sizeof(attr);

		int len = hole_offer.length();
		len = htonl(len);
		memcpy(buff + offset, &len, sizeof(len));
		offset += sizeof(len);

		memcpy(buff + offset, hole_offer.c_str(), hole_offer.length());
		offset += hole_offer.length();
	}
	else
	{
		result = ERROR_PEER_INFO_NOT_FOUND;
		result = htonl(result);
		memcpy(buff + offset, &result, sizeof(result));
		offset += sizeof(result);
	}

	int ret = sendto(si->cli.sockfd, buff, offset, 0, (struct sockaddr *)&si->cli.cliaddr, si->cli.len);
	if (ret < 0)
	{
		err("do_traversal_request: sendto error, err=%d\n", errno);
	}

	if (NULL != si)
	{
		delete si;
		si = NULL;
	}

	//tell peer to nego.
	if (result = ERROR_SUCCESS)
	{
		memset(buff, 0, 1024);
		offset = 0;

		msg_type = MSG_TYPE_TRAVERSAL_REQUEST;
		msg_type = htonl(msg_type);
		memcpy(buff + offset, &msg_type, sizeof(msg_type));
		offset += sizeof(msg_type);

		memcpy(buff + offset, hole_answer.c_str(), hole_answer.length());
		offset += hole_answer.length();
	}

	ret = sendto(cli_offer.sockfd, buff, offset, 0, (struct sockaddr *)&cli_offer.cliaddr, cli_offer.len);
	if (ret < 0)
	{
		err("do_traversal_request tell peer: sendto error, err=%d\n", errno);
	}
}

void do_heart(const std::vector<attr_type_value_t> &content, singal_info_t* si)
{
	assert(si != NULL);

	std::string guid;

	for (std::vector<attr_type_value_t>::const_iterator iter = content.begin();
		 iter != content.end();
		 ++iter)
	{
		const attr_type_value_t& item(*iter);
		switch (item.type)
		{
		case TYPE_ATTR_GUID_OFFER: //yes, that it is.
		case TYPE_ATTR_GUID_ANSWER:
			guid = item.value;
			break;
		default:
			break;
		}
	}

	//update the timestamp in global map
	pthread_mutex_lock(g_mu_hole);
	{
		std::map<std::string, hole_info_t*>::iterator iter = g_info_hole->find(guid);
		if (iter != g_info_hole->end())
		{
			iter->second->tm = time(NULL);
		}
	}
	pthread_mutex_unlock(g_mu_hole);

	if (NULL != si)
	{
		delete si;
		si = NULL;
	}


}

void do_registe(const std::vector<attr_type_value_t> &content, singal_info_t* si)
{
	assert(si != NULL);

	std::string guid;
	hole_info_t *hole = new hole_info_t;
	assert(hole != NULL);

	for (std::vector<attr_type_value_t>::const_iterator iter = content.begin();
		 iter != content.end();
		 ++iter)
	{
		const attr_type_value_t& item(*iter);
		switch (item.type)
		{
		case TYPE_ATTR_GUID_OFFER:  //yes, that it is.
		case TYPE_ATTR_GUID_ANSWER:
			guid = item.value;
			break;
		case TYPE_ATTR_HOLE_INFO:
			hole->hole_info = item.value;
			break;
		default:
			break;
		}
	}

	memcpy(&hole->cli, &si->cli, sizeof(si->cli));
	if (NULL != si)
	{
		delete si;
		si = NULL;
	}

	//insert into golbal map
	{
		pthread_mutex_lock(g_mu_hole);

		std::map<std::string, hole_info_t*>::iterator iter = g_info_hole->find(guid);
		//if has insert, delete it first to ensure the latest.
		if ( iter!= g_info_hole->end())
		{
			if (iter->second != NULL)
			{
				delete iter->second;
				iter->second = NULL;
			}
			g_info_hole->erase(iter);
		}

		g_info_hole->insert(std::make_pair(guid, hole));//there is a delete thread to detect if the info has timeout.

		pthread_mutex_unlock(g_mu_hole);
	}

	char buff_response[64] = {0};
	int offset = 0;
	int msg_type = MSG_TYPE_REGISTER_RESPONSE;
	msg_type = htonl(msg_type);
	memcpy(buff_response + offset, &msg_type, sizeof(msg_type));
	offset += sizeof(msg_type);
	std::string value = "0";
	int len = value.length();
	len = htonl(len);
	memcpy(buff_response + offset, &len, sizeof(len));
	offset += sizeof(len);
	memcpy(buff_response + offset, value.c_str(), value.length());
	offset += value.length();

	int ret = sendto(hole->cli.sockfd, buff_response, offset, 0, (struct sockaddr *)&hole->cli.cliaddr, hole->cli.len);
	if (ret < 0)
	{
		err("sendto error, err=%d\n", errno);
	}
}

void do_handle_singal_info(int msg_type, const std::vector<attr_type_value_t> &content, singal_info_t* si)
{
	assert(si != NULL);

	switch (msg_type)
	{
	case MSG_TYPE_REGISTER:
		do_registe(content, si);
		break;
	case MSG_TYPE_HEART:
		do_heart(content, si);
		break;
	case MSG_TYPE_TRAVERSAL_REQUEST:

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
	memcpy(&msg_type, &signal_info->recv_origin_msg[0], sizeof(msg_type));
	msg_type = ntohl(msg_type);
	i += sizeof(msg_type);

	std::vector<attr_type_value_t> vec_attrs;

	for(; i < signal_info->recv_origin_msg.length();)
	{
		attr_type_value_t attr;

		memcpy(&attr.type, &signal_info->recv_origin_msg[i], sizeof(attr.type));
		attr.type = ntohl(attr.type);
		i += sizeof(attr.type);

		int len = 0;
		memcpy(&len, &signal_info->recv_origin_msg[i], sizeof(len));
		len = ntohl(len);
		i += sizeof(len);

		attr.value.assign(&signal_info->recv_origin_msg[i], len);
		i+= len;

		vec_attrs.push_back(attr);
	}

	do_handle_singal_info(msg_type, vec_attrs, signal_info);
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

		singal_info->recv_origin_msg.assign(msg, recv_len);
		singal_info->cli.sockfd = sockfd;

		pthread_t t;
		pthread_create(&t, NULL, handle_singal_info, (void*)singal_info);
	}
}

void* thread_detect_holeinfo_timeout(void *)
{
	while (!g_quit)
	{
		time_t tnow = time(NULL);
		pthread_mutex_lock(g_mu_hole);
		{
			for (unsigned i = 0; i < g_info_hole->size(); ++i)
			{
				for (std::map<std::string, hole_info_t*>::iterator iter = g_info_hole->begin();
					 iter != g_info_hole->end();
					 ++iter)
				{
					if (tnow - iter->second->tm > 10 * 60) //10min
					{
						if (NULL != iter->second)
						{
							delete iter->second;
							iter->second = NULL;
						}

						g_info_hole->erase(iter);
						break;
					}
				}
			}
		}
		pthread_mutex_unlock(g_mu_hole);

		sleep(1);
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

	g_info_hole = new std::map<std::string, hole_info_t*>;
	assert(g_info_hole);
	g_mu_hole = new pthread_mutex_t;
	assert(g_mu_hole != NULL);
	pthread_mutex_init(g_mu_hole, NULL);

	//start singal udp listen. just used to transmit the info.
	pthread_t t_sigal;
	int ret = pthread_create(&t_sigal, NULL, thread_singal_transmit, NULL);
	if (ret != 0)
	{
		return err("create singal thread failed.", errno);
	}

	pthread_t t_detect;
	ret = pthread_create(&t_detect, NULL, thread_detect_holeinfo_timeout, NULL);
	if (ret < 0)
	{
		return err("create detect thread failed, err=%d", errno);
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
		sleep(2);
	}

	pj_turn_srv_destroy(srv);
	pj_caching_pool_destroy(&g_cp);
	pj_shutdown();

	pthread_join(t_sigal, NULL);
	pthread_join(t_detect, NULL);

	return 0;
}
