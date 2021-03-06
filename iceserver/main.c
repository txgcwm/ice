#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "turn.h"
#include "auth.h"

#define REALM			"pjsip.org"
//#define TURN_PORT	PJ_STUN_TURN_PORT
#define TURN_PORT_UDP	34780
#define TURN_PORT_TCP	34780
#define LOG_LEVEL		4


static pj_caching_pool g_cp;
static pj_bool_t g_quit = PJ_FALSE;

static void SigUsr(int signo)
{
	if (SIGUSR1 == signo) {
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

	for (i = 0; i < srv->core.lis_cnt; ++i) {
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
	i = 1;

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

int main(int argc, char* argv[])
{
	pj_bool_t DAEMON_MODE = PJ_FALSE;

	if (2 == argc && 0 == strcmp(argv[1], "-d")) {
		DAEMON_MODE = PJ_TRUE;
	}

	if (DAEMON_MODE && signal(SIGUSR1, SigUsr) == SIG_ERR ) {
		// return err("signal User faile.", errno);
	}

	if (DAEMON_MODE && -1 == daemon(1, 0)) {
		// return err("daemon failed.", errno);
	}

	pj_turn_srv *srv = NULL;
	pj_turn_listener *listener = NULL;
	pj_status_t status;

	status = pj_init();
	if (status != PJ_SUCCESS) {
		return err("pj_init() error", status);
	}

	status = pjlib_util_init();
	if (status != PJ_SUCCESS) {
		return err("pjlib_util_init error", status);
	}

	status = pjnath_init();
	if (status != PJ_SUCCESS) {
		return err("pjnath_init error", status);
	}

	pj_caching_pool_init(&g_cp, NULL, 0);

	pj_turn_auth_init(REALM);

	status = pj_turn_srv_create(&g_cp.factory, &srv);
	if (status != PJ_SUCCESS) {
		return err("Error creating server", status);
	}

	status = pj_turn_listener_create_udp(srv, pj_AF_INET(), NULL,
					 TURN_PORT_UDP, 1, 0, &listener);
	if (status != PJ_SUCCESS) {
		return err("Error creating UDP listener", status);
	}

#if PJ_HAS_TCP
	status = pj_turn_listener_create_tcp(srv, pj_AF_INET(), NULL,
					 TURN_PORT_TCP, 1, 0, &listener);
	if (status != PJ_SUCCESS) {
		return err("Error creating listener", status);
	}
#endif

	status = pj_turn_srv_add_listener(srv, listener);
	if (status != PJ_SUCCESS) {
		return err("Error adding listener", status);
	}

	puts("Server is running");

	pj_log_set_level(LOG_LEVEL);

	dump_status(srv);

	while (!g_quit) {
		pj_thread_sleep(100);
	}

	pj_turn_srv_destroy(srv);
	pj_caching_pool_destroy(&g_cp);
	pj_shutdown();

	return 0;
}
