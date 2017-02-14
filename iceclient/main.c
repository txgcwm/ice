#include <stdio.h>
#include <stdlib.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include<arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#include "pub.h"

#define THIS_FILE   "icedemo.c"

#define KA_INTERVAL 300

typedef struct addrinfo_s
{
	int sockfd;
	struct sockaddr_in addr;
}addrinfo_t;

/* Variables to store parsed remote ICE info */
typedef struct remote_info_s
{
	char		 ufrag[80];
	char		 pwd[80];
	unsigned	 comp_cnt;
	pj_sockaddr	 def_addr[PJ_ICE_MAX_COMP];
	unsigned	 cand_cnt;
	pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND];
} remote_info_t;

enum {max_buff_line = 2048};

/* This is our global variables */
typedef struct app_s
{
	/* Command line options are stored here */
	struct options
	{
	unsigned    comp_cnt;
	pj_str_t    ns;
	int	    max_host;
	pj_bool_t   regular;
	pj_str_t    stun_srv;
	pj_str_t    turn_srv;
	pj_bool_t   turn_tcp;
	pj_str_t    turn_username;
	pj_str_t    turn_password;
	pj_bool_t   turn_fingerprint;
	const char *log_file;
	pj_bool_t   console_mode;
	int role;
	pj_str_t guid_offer;
	pj_str_t guid_answer;
	} opt;

	/* Our global variables */
	pj_caching_pool	 cp;
	pj_pool_t		*pool;
	pj_thread_t		*thread;
	pj_bool_t		 thread_quit_flag;
	pj_ice_strans_cfg	 ice_cfg;
	pj_ice_strans	*icest;

	addrinfo_t addr_signal;

	remote_info_t rem;

	pj_bool_t quit;
	pj_bool_t init_success;
	pj_bool_t session_ready;
	pj_bool_t offer_can_nego;
	pj_bool_t answer_can_nego;
	pj_bool_t nego_success;
	int signal_port;
	pj_str_t signal_addr;
	char registe_info_buffer[max_buff_line];
	int len_registe_info_buffer;
	char local_info_buffer[max_buff_line];
	int len_local_info;
	char recv_original_buffer[max_buff_line];
	int len_recv_origin;
} app;

enum {max_ice_size = 10};
static app* gices[max_ice_size];
static FILE		*g_log_fhnd;

/* Utility to display error messages */
static void icedemo_perror(const char *title, pj_status_t status)
{
	char errmsg[PJ_ERR_MSG_SIZE];

	pj_strerror(status, errmsg, sizeof(errmsg));
	PJ_LOG(1,(THIS_FILE, "%s: %s", title, errmsg));
}

/* Utility: display error message and exit application (usually
 * because of fatal error.
 */
static void err_exit(app* ice, const char *title, pj_status_t status)
{
	assert(NULL != ice);
	if (status != PJ_SUCCESS) {
	icedemo_perror(title, status);
	}
	PJ_LOG(3,(THIS_FILE, "Shutting down.."));

	if (ice->icest)
	pj_ice_strans_destroy(ice->icest);

	pj_thread_sleep(500);

	ice->thread_quit_flag = PJ_TRUE;
	if (ice->thread) {
	pj_thread_join(ice->thread);
	pj_thread_destroy(ice->thread);
	}

	if (ice->ice_cfg.stun_cfg.ioqueue)
	pj_ioqueue_destroy(ice->ice_cfg.stun_cfg.ioqueue);

	if (ice->ice_cfg.stun_cfg.timer_heap)
	pj_timer_heap_destroy(ice->ice_cfg.stun_cfg.timer_heap);

	pj_caching_pool_destroy(&ice->cp);

	pj_shutdown();

	if (g_log_fhnd) {
	fclose(g_log_fhnd);
	g_log_fhnd = NULL;
	}

	exit(status != PJ_SUCCESS);
}

/*
 * This function checks for events from both timer and ioqueue (for
 * network events). It is invoked by the worker thread.
 */
static pj_status_t handle_events(app* ice, unsigned max_msec, unsigned *p_count)
{
	assert(NULL != ice);

	enum { MAX_NET_EVENTS = 1 };
	pj_time_val max_timeout = {0, 0};
	pj_time_val timeout = { 0, 0};
	unsigned count = 0, net_event_count = 0;
	int c;

	max_timeout.msec = max_msec;

	/* Poll the timer to run it and also to retrieve the earliest entry. */
	timeout.sec = timeout.msec = 0;
	c = pj_timer_heap_poll( ice->ice_cfg.stun_cfg.timer_heap, &timeout );
	if (c > 0)
	count += c;

	/* timer_heap_poll should never ever returns negative value, or otherwise
	 * ioqueue_poll() will block forever!
	 */
	pj_assert(timeout.sec >= 0 && timeout.msec >= 0);
	if (timeout.msec >= 1000) timeout.msec = 999;

	/* compare the value with the timeout to wait from timer, and use the
	 * minimum value.
	*/
	if (PJ_TIME_VAL_GT(timeout, max_timeout))
	timeout = max_timeout;

	/* Poll ioqueue.
	 * Repeat polling the ioqueue while we have immediate events, because
	 * timer heap may process more than one events, so if we only process
	 * one network events at a time (such as when IOCP backend is used),
	 * the ioqueue may have trouble keeping up with the request rate.
	 *
	 * For example, for each send() request, one network event will be
	 *   reported by ioqueue for the send() completion. If we don't poll
	 *   the ioqueue often enough, the send() completion will not be
	 *   reported in timely manner.
	 */
	do {
	c = pj_ioqueue_poll( ice->ice_cfg.stun_cfg.ioqueue, &timeout);
	if (c < 0) {
		pj_status_t err = pj_get_netos_error();
		pj_thread_sleep(PJ_TIME_VAL_MSEC(timeout));
		if (p_count)
		*p_count = count;
		return err;
	} else if (c == 0) {
		break;
	} else {
		net_event_count += c;
		timeout.sec = timeout.msec = 0;
	}
	} while (c > 0 && net_event_count < MAX_NET_EVENTS);

	count += net_event_count;
	if (p_count)
	*p_count = count;

	return PJ_SUCCESS;

}

/*
 * This is the worker thread that polls event in the background.
 */
static int icedemo_worker_thread(app* ice, void *unused)
{
	assert(NULL != ice);

	PJ_UNUSED_ARG(unused);

	while (!ice->thread_quit_flag) {
	handle_events(ice, 500, NULL);
	}

	return 0;
}

/*
 * This is the callback that is registered to the ICE stream transport to
 * receive notification about incoming data. By "data" it means application
 * data such as RTP/RTCP, and not packets that belong to ICE signaling (such
 * as STUN connectivity checks or TURN signaling).
 */
static void cb_on_rx_data(pj_ice_strans *ice_st,
			  unsigned comp_id,
			  void *pkt, pj_size_t size,
			  const pj_sockaddr_t *src_addr,
			  unsigned src_addr_len)
{
	char ipstr[PJ_INET6_ADDRSTRLEN+10];

	PJ_UNUSED_ARG(ice_st);
	PJ_UNUSED_ARG(src_addr_len);
	PJ_UNUSED_ARG(pkt);

	// Don't do this! It will ruin the packet buffer in case TCP is used!
	//((char*)pkt)[size] = '\0';

	PJ_LOG(3,(THIS_FILE, "Component %d: received %d bytes data from %s: \"%.*s\"",
		  comp_id, size,
		  pj_sockaddr_print(src_addr, ipstr, sizeof(ipstr), 3),
		  (unsigned)size,
		  (char*)pkt));
}

/*
 * This is the callback that is registered to the ICE stream transport to
 * receive notification about ICE state progression.
 */
static void cb_on_ice_complete(pj_ice_strans *ice_st,
				   pj_ice_strans_op op,
				   pj_status_t status)
{
	const char *opname =
	(op==PJ_ICE_STRANS_OP_INIT? "initialization" :
		(op==PJ_ICE_STRANS_OP_NEGOTIATION ? "negotiation" : "unknown_op"));

	if (status == PJ_SUCCESS) {
	PJ_LOG(3,(THIS_FILE, "ICE %s successful", opname));
	} else {
	char errmsg[PJ_ERR_MSG_SIZE];

	pj_strerror(status, errmsg, sizeof(errmsg));
	PJ_LOG(1,(THIS_FILE, "ICE %s failed: %s", opname, errmsg));
	pj_ice_strans_destroy(ice_st);
	unsigned i = 0;
	for (i = 0; i < max_ice_size; ++i)
	{
		if (ice_st == gices[i]->icest)
		{
			gices[i]->icest = NULL;
		}
	}
	}

	if(status == PJ_SUCCESS && op == PJ_ICE_STRANS_OP_INIT)
	{
		unsigned i = 0;
		for (i = 0; i < max_ice_size; ++i)
		{
			if (ice_st == gices[i]->icest)
			{
				gices[i]->init_success = PJ_TRUE;
			}
		}

	}

	if (status == PJ_SUCCESS && op == PJ_ICE_STRANS_OP_NEGOTIATION)
	{
		unsigned i = 0;
		for (i = 0; i < max_ice_size; ++i)
		{
			if (ice_st == gices[i]->icest)
			{
				gices[i]->nego_success = PJ_TRUE;
			}
		}
	}
}

/* log callback to write to file */
static void log_func(int level, const char *data, int len)
{
	pj_log_write(level, data, len);
	if (g_log_fhnd) {
	if (fwrite(data, len, 1, g_log_fhnd) != 1)
		return;
	}
}

/*
 * This is the main application initialization function. It is called
 * once (and only once) during application initialization sequence by
 * main().
 */
static pj_status_t icedemo_init(app* ice)
{
	assert(NULL != ice);

	pj_status_t status;

	if (ice->opt.log_file) {
	g_log_fhnd = fopen(ice->opt.log_file, "a");
	pj_log_set_log_func(&log_func);
	}

	/* Initialize the libraries before anything else */
	status = ( pj_init() );
	status = ( pjlib_util_init() );
	status = ( pjnath_init() );
	if (status != PJ_SUCCESS)
	{
		return status;
	}

	/* Must create pool factory, where memory allocations come from */
	pj_caching_pool_init(&ice->cp, NULL, 0);

	/* Init our ICE settings with null values */
	pj_ice_strans_cfg_default(&ice->ice_cfg);

	ice->ice_cfg.stun_cfg.pf = &ice->cp.factory;

	/* Create application memory pool */
	ice->pool = pj_pool_create(&ice->cp.factory, "icedemo",
				  512, 512, NULL);

	/* Create timer heap for timer stuff */
	status = ( pj_timer_heap_create(ice->pool, 100,
				&ice->ice_cfg.stun_cfg.timer_heap) );

	/* and create ioqueue for network I/O stuff */
	status = ( pj_ioqueue_create(ice->pool, 16,
				 &ice->ice_cfg.stun_cfg.ioqueue) );

	/* something must poll the timer heap and ioqueue,
	 * unless we're on Symbian where the timer heap and ioqueue run
	 * on themselves.
	 */
	status = ( pj_thread_create(ice->pool, "icedemo", &icedemo_worker_thread,
				NULL, 0, 0, &ice->thread) );

	if (status != PJ_SUCCESS)
	{
		return status;
	}

	ice->ice_cfg.af = pj_AF_INET();

	/* Create DNS resolver if nameserver is set */
	if (ice->opt.ns.slen) {
	status = ( pj_dns_resolver_create(&ice->cp.factory,
					  "resolver",
					  0,
					  ice->ice_cfg.stun_cfg.timer_heap,
					  ice->ice_cfg.stun_cfg.ioqueue,
					  &ice->ice_cfg.resolver) );

	status = ( pj_dns_resolver_set_ns(ice->ice_cfg.resolver, 1,
					  &ice->opt.ns, NULL) );
	}

	if (status != PJ_SUCCESS)
	{
		return status;
	}

	/* -= Start initializing ICE stream transport config =- */

	/* Maximum number of host candidates */
	if (ice->opt.max_host != -1)
	ice->ice_cfg.stun.max_host_cands = ice->opt.max_host;

	/* Nomination strategy */
	if (ice->opt.regular)
	ice->ice_cfg.opt.aggressive = PJ_FALSE;
	else
	ice->ice_cfg.opt.aggressive = PJ_TRUE;

	/* Configure STUN/srflx candidate resolution */
	if (ice->opt.stun_srv.slen) {
	char *pos;

	/* Command line option may contain port number */
	if ((pos=pj_strchr(&ice->opt.stun_srv, ':')) != NULL) {
		ice->ice_cfg.stun.server.ptr = ice->opt.stun_srv.ptr;
		ice->ice_cfg.stun.server.slen = (pos - ice->opt.stun_srv.ptr);

		ice->ice_cfg.stun.port = (pj_uint16_t)atoi(pos+1);
	} else {
		ice->ice_cfg.stun.server = ice->opt.stun_srv;
		ice->ice_cfg.stun.port = PJ_STUN_PORT;
	}

	/* For this demo app, configure longer STUN keep-alive time
	 * so that it does't clutter the screen output.
	 */
	ice->ice_cfg.stun.cfg.ka_interval = KA_INTERVAL;
	}

	/* Configure TURN candidate */
	if (ice->opt.turn_srv.slen) {
	char *pos;

	/* Command line option may contain port number */
	if ((pos=pj_strchr(&ice->opt.turn_srv, ':')) != NULL) {
		ice->ice_cfg.turn.server.ptr = ice->opt.turn_srv.ptr;
		ice->ice_cfg.turn.server.slen = (pos - ice->opt.turn_srv.ptr);

		ice->ice_cfg.turn.port = (pj_uint16_t)atoi(pos+1);
	} else {
		ice->ice_cfg.turn.server = ice->opt.turn_srv;
		ice->ice_cfg.turn.port = PJ_STUN_PORT;
	}

	/* TURN credential */
	ice->ice_cfg.turn.auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
	ice->ice_cfg.turn.auth_cred.data.static_cred.username = ice->opt.turn_username;
	ice->ice_cfg.turn.auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
	ice->ice_cfg.turn.auth_cred.data.static_cred.data = ice->opt.turn_password;

	/* Connection type to TURN server */
	if (ice->opt.turn_tcp)
		ice->ice_cfg.turn.conn_type = PJ_TURN_TP_TCP;
	else
		ice->ice_cfg.turn.conn_type = PJ_TURN_TP_UDP;

	/* For this demo app, configure longer keep-alive time
	 * so that it does't clutter the screen output.
	 */
	ice->ice_cfg.turn.alloc_param.ka_interval = KA_INTERVAL;
	}

	/* -= That's it for now, initialization is complete =- */
	return PJ_SUCCESS;
}


/*
 * Create ICE stream transport instance, invoked from the menu.
 */
static void icedemo_create_instance(app* ice)
{
	pj_ice_strans_cb icecb;
	pj_status_t status;

	if (ice->icest != NULL) {
	puts("ICE instance already created, destroy it first");
	return;
	}

	/* init the callback */
	pj_bzero(&icecb, sizeof(icecb));
	icecb.on_rx_data = cb_on_rx_data;
	icecb.on_ice_complete = cb_on_ice_complete;

	/* create the instance */
	status = pj_ice_strans_create("icedemo",		    /* object name  */
				&ice->ice_cfg,	    /* settings	    */
				ice->opt.comp_cnt,	    /* comp_cnt	    */
				NULL,			    /* user data    */
				&icecb,			    /* callback	    */
				&ice->icest)		    /* instance ptr */
				;
	if (status != PJ_SUCCESS)
	icedemo_perror("error creating ice", status);
	else
	PJ_LOG(3,(THIS_FILE, "ICE instance successfully created"));
}

/* Utility to nullify parsed remote info */
static void reset_rem_info(app* ice)
{
	assert(NULL != ice);
	pj_bzero(&ice->rem, sizeof(ice->rem));
}


/*
 * Destroy ICE stream transport instance, invoked from the menu.
 */
static void icedemo_destroy_instance(app* ice)
{
	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	pj_ice_strans_destroy(ice->icest);
	ice->icest = NULL;

	reset_rem_info(ice);

	PJ_LOG(3,(THIS_FILE, "ICE instance destroyed"));
}

/*
 * Create ICE session, invoked from the menu.
 */
static void icedemo_init_session(app* ice, unsigned rolechar)
{
	pj_ice_sess_role role = (pj_tolower((pj_uint8_t)rolechar)=='o' ?
				PJ_ICE_SESS_ROLE_CONTROLLING :
				PJ_ICE_SESS_ROLE_CONTROLLED);
	pj_status_t status;

	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	if (pj_ice_strans_has_sess(ice->icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: Session already created"));
	return;
	}

	status = pj_ice_strans_init_ice(ice->icest, role, NULL, NULL);
	if (status != PJ_SUCCESS)
	{
		icedemo_perror("error creating session", status);
	}
	else
	{
		PJ_LOG(3,(THIS_FILE, "ICE session created"));
		ice->session_ready = PJ_TRUE;
	}

	reset_rem_info(ice);
}


/*
 * Stop/destroy ICE session, invoked from the menu.
 */
static void icedemo_stop_session(app* ice)
{
	assert(NULL != ice);

	pj_status_t status;

	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	if (!pj_ice_strans_has_sess(ice->icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	return;
	}

	status = pj_ice_strans_stop_ice(ice->icest);
	if (status != PJ_SUCCESS)
	icedemo_perror("error stopping session", status);
	else
	PJ_LOG(3,(THIS_FILE, "ICE session stopped"));

	reset_rem_info(ice);
}

#define PRINT(...)	    \
	printed = pj_ansi_snprintf(p, maxlen - (p-buffer),  \
				   __VA_ARGS__); \
	if (printed <= 0 || printed >= (int)(maxlen - (p-buffer))) \
		return -PJ_ETOOSMALL; \
	p += printed


/* Utility to create a=candidate SDP attribute */
static int print_cand(char buffer[], unsigned maxlen,
			  const pj_ice_sess_cand *cand)
{
	char ipaddr[PJ_INET6_ADDRSTRLEN];
	char *p = buffer;
	int printed;

	PRINT("a=candidate:%.*s %u UDP %u %s %u typ ",
	  (int)cand->foundation.slen,
	  cand->foundation.ptr,
	  (unsigned)cand->comp_id,
	  cand->prio,
	  pj_sockaddr_print(&cand->addr, ipaddr,
				sizeof(ipaddr), 0),
	  (unsigned)pj_sockaddr_get_port(&cand->addr));

	PRINT("%s\n",
	  pj_ice_get_cand_type_name(cand->type));

	if (p == buffer+maxlen)
	return -PJ_ETOOSMALL;

	*p = '\0';

	return (int)(p-buffer);
}

/*
 * Encode ICE information in SDP.
 */
static int encode_session(app* ice, char buffer[], unsigned maxlen)
{
	assert(NULL != ice);

	char *p = buffer;
	unsigned comp;
	int printed;
	pj_str_t local_ufrag, local_pwd;
	pj_status_t status;

	/* Write "dummy" SDP v=, o=, s=, and t= lines */
	PRINT("v=0\no=- 3414953978 3414953978 IN IP4 localhost\ns=ice\nt=0 0\n");

	/* Get ufrag and pwd from current session */
	pj_ice_strans_get_ufrag_pwd(ice->icest, &local_ufrag, &local_pwd,
				NULL, NULL);

	/* Write the a=ice-ufrag and a=ice-pwd attributes */
	PRINT("a=ice-ufrag:%.*s\na=ice-pwd:%.*s\n",
	   (int)local_ufrag.slen,
	   local_ufrag.ptr,
	   (int)local_pwd.slen,
	   local_pwd.ptr);

	/* Write each component */
	for (comp=0; comp<ice->opt.comp_cnt; ++comp) {
	unsigned j, cand_cnt;
	pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND];
	char ipaddr[PJ_INET6_ADDRSTRLEN];

	/* Get default candidate for the component */
	status = pj_ice_strans_get_def_cand(ice->icest, comp+1, &cand[0]);
	if (status != PJ_SUCCESS)
		return -status;

	/* Write the default address */
	if (comp==0) {
		/* For component 1, default address is in m= and c= lines */
		PRINT("m=audio %d RTP/AVP 0\n"
		  "c=IN IP4 %s\n",
		  (int)pj_sockaddr_get_port(&cand[0].addr),
		  pj_sockaddr_print(&cand[0].addr, ipaddr,
					sizeof(ipaddr), 0));
	} else if (comp==1) {
		/* For component 2, default address is in a=rtcp line */
		PRINT("a=rtcp:%d IN IP4 %s\n",
		  (int)pj_sockaddr_get_port(&cand[0].addr),
		  pj_sockaddr_print(&cand[0].addr, ipaddr,
					sizeof(ipaddr), 0));
	} else {
		/* For other components, we'll just invent this.. */
		PRINT("a=Xice-defcand:%d IN IP4 %s\n",
		  (int)pj_sockaddr_get_port(&cand[0].addr),
		  pj_sockaddr_print(&cand[0].addr, ipaddr,
					sizeof(ipaddr), 0));
	}

	/* Enumerate all candidates for this component */
	cand_cnt = PJ_ARRAY_SIZE(cand);
	status = pj_ice_strans_enum_cands(ice->icest, comp+1,
					  &cand_cnt, cand);
	if (status != PJ_SUCCESS)
		return -status;

	/* And encode the candidates as SDP */
	for (j=0; j<cand_cnt; ++j) {
		printed = print_cand(p, maxlen - (unsigned)(p-buffer), &cand[j]);
		if (printed < 0)
		return -PJ_ETOOSMALL;
		p += printed;
	}
	}

	if (p == buffer+maxlen)
	return -PJ_ETOOSMALL;

	*p = '\0';
	return (int)(p - buffer);
}

static void icedemo_show_ice_auto(app* ice, char *buffer2, int *len_buff)
{
	assert(NULL != ice);

	static char buffer[1000];
	int len;

	if (ice->icest == NULL)
	{
		PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
		return;
	}

	if (pj_ice_strans_sess_is_complete(ice->icest))
	{
		puts("negotiation complete");
	}
	else if (pj_ice_strans_sess_is_running(ice->icest))
	{
		puts("negotiation is in progress");
	}
	else if (pj_ice_strans_has_sess(ice->icest))
	{
		puts("session ready");
	}
	else
	{
		puts("session not created");
	}

	if (!pj_ice_strans_has_sess(ice->icest))
	{
		puts("Create the session first to see more info");
		return;
	}

	len = encode_session(ice, buffer, sizeof(buffer));
	if (len < 0)
	{
		err_exit(ice, "not enough buffer to show ICE status", -len);
	}

	printf("Local SDP (paste this to remote host):\n"
		   "--------------------------------------\n"
		   "%s\n", buffer);

	strncpy(buffer2, buffer, len);
	*len_buff = len;

	puts("");
	puts("Remote info:\n"
		 "----------------------");
	if (ice->rem.cand_cnt==0) {
		puts("No remote info yet");
	} else {
		unsigned i;

		for (i=0; i<ice->rem.cand_cnt; ++i) {
			len = print_cand(buffer, sizeof(buffer), &ice->rem.cand[i]);
			if (len < 0)
				err_exit(ice, "not enough buffer to show ICE status", -len);

			printf("  %s", buffer);
		}
	}
}

/*
 * Show information contained in the ICE stream transport. This is
 * invoked from the menu.
 */
static void icedemo_show_ice(app* ice)
{
	static char buffer[1000];
	int len;

	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	puts("General info");
	puts("---------------");
	printf("Component count    : %d\n", ice->opt.comp_cnt);
	printf("Status             : ");
	if (pj_ice_strans_sess_is_complete(ice->icest))
	puts("negotiation complete");
	else if (pj_ice_strans_sess_is_running(ice->icest))
	puts("negotiation is in progress");
	else if (pj_ice_strans_has_sess(ice->icest))
	puts("session ready");
	else
	puts("session not created");

	if (!pj_ice_strans_has_sess(ice->icest)) {
	puts("Create the session first to see more info");
	return;
	}

	printf("Negotiated comp_cnt: %d\n",
	   pj_ice_strans_get_running_comp_cnt(ice->icest));
	printf("Role               : %s\n",
	   pj_ice_strans_get_role(ice->icest)==PJ_ICE_SESS_ROLE_CONTROLLED ?
	   "controlled" : "controlling");

	len = encode_session(ice, buffer, sizeof(buffer));
	if (len < 0)
	err_exit(ice, "not enough buffer to show ICE status", -len);

	puts("");
	printf("Local SDP (paste this to remote host):\n"
	   "--------------------------------------\n"
	   "%s\n", buffer);


	puts("");
	puts("Remote info:\n"
	 "----------------------");
	if (ice->rem.cand_cnt==0) {
	puts("No remote info yet");
	} else {
	unsigned i;

	printf("Remote ufrag       : %s\n", ice->rem.ufrag);
	printf("Remote password    : %s\n", ice->rem.pwd);
	printf("Remote cand. cnt.  : %d\n", ice->rem.cand_cnt);

	for (i=0; i<ice->rem.cand_cnt; ++i) {
		len = print_cand(buffer, sizeof(buffer), &ice->rem.cand[i]);
		if (len < 0)
		err_exit(ice, "not enough buffer to show ICE status", -len);

		printf("  %s", buffer);
	}
	}
}


static void icedemo_input_remote2(app* ice, char* msg, int msg_len)
{
	assert(msg != NULL);

	char linebuf[80];
	unsigned media_cnt = 0;
	unsigned comp0_port = 0;
	char     comp0_addr[80];
	pj_bool_t done = PJ_FALSE;

	reset_rem_info(ice);

	comp0_addr[0] = '\0';

	char* penter = msg;
	while (!done)
	{
		pj_size_t len;
		char *line;

		//from console input.
//		{
//			if (fgets(linebuf, sizeof(linebuf), stdin)==NULL)
//				break;
//		}

		{

			bzero(linebuf, 80);
			char* penter_tmp = strchr(penter, '\n');
			if (NULL == penter_tmp)
			{
				break;
			}

			memcpy(linebuf, penter, penter_tmp - penter + 1);
			penter = penter_tmp + 1;
		}

		len = strlen(linebuf);
		while (len && (linebuf[len-1] == '\r' || linebuf[len-1] == '\n'))
			linebuf[--len] = '\0';

		line = linebuf;
		while (len && pj_isspace(*line))
			++line, --len;

		if (len==0)
			break;

		/* Ignore subsequent media descriptors */
		if (media_cnt > 1)
			continue;

		switch (line[0])
		{
		case 'm':
			{
				int cnt;
				char media[32], portstr[32];

				++media_cnt;
				if (media_cnt > 1) {
					puts("Media line ignored");
					break;
				}

				cnt = sscanf(line+2, "%s %s RTP/", media, portstr);
				if (cnt != 2) {
					PJ_LOG(1,(THIS_FILE, "Error parsing media line"));
					goto on_error;
				}

				comp0_port = atoi(portstr);

			}
			break;
		case 'c':
			{
				int cnt;
				char c[32], net[32], ip[80];

				cnt = sscanf(line+2, "%s %s %s", c, net, ip);
				if (cnt != 3) {
					PJ_LOG(1,(THIS_FILE, "Error parsing connection line"));
					goto on_error;
				}

				strcpy(comp0_addr, ip);
			}
			break;
		case 'a':
			{
				char *attr = strtok(line+2, ": \t\r\n");
				if (strcmp(attr, "ice-ufrag")==0) {
					strcpy(ice->rem.ufrag, attr+strlen(attr)+1);
				} else if (strcmp(attr, "ice-pwd")==0) {
					strcpy(ice->rem.pwd, attr+strlen(attr)+1);
				} else if (strcmp(attr, "rtcp")==0) {
					char *val = attr+strlen(attr)+1;
					int af, cnt;
					int port;
					char net[32], ip[64];
					pj_str_t tmp_addr;
					pj_status_t status;

					cnt = sscanf(val, "%d IN %s %s", &port, net, ip);
					if (cnt != 3) {
						PJ_LOG(1,(THIS_FILE, "Error parsing rtcp attribute"));
						goto on_error;
					}

					if (strchr(ip, ':'))
						af = pj_AF_INET6();
					else
						af = pj_AF_INET();

					pj_sockaddr_init(af, &ice->rem.def_addr[1], NULL, 0);
					tmp_addr = pj_str(ip);
					status = pj_sockaddr_set_str_addr(af, &ice->rem.def_addr[1],
							&tmp_addr);
					if (status != PJ_SUCCESS) {
						PJ_LOG(1,(THIS_FILE, "Invalid IP address"));
						goto on_error;
					}
					pj_sockaddr_set_port(&ice->rem.def_addr[1], (pj_uint16_t)port);

				} else if (strcmp(attr, "candidate")==0) {
					char *sdpcand = attr+strlen(attr)+1;
					int af, cnt;
					char foundation[32], transport[12], ipaddr[80], type[32];
					pj_str_t tmpaddr;
					int comp_id, prio, port;
					pj_ice_sess_cand *cand;
					pj_status_t status;

					cnt = sscanf(sdpcand, "%s %d %s %d %s %d typ %s",
								 foundation,
								 &comp_id,
								 transport,
								 &prio,
								 ipaddr,
								 &port,
								 type);
					if (cnt != 7) {
						PJ_LOG(1, (THIS_FILE, "error: Invalid ICE candidate line"));
						goto on_error;
					}

					cand = &ice->rem.cand[ice->rem.cand_cnt];
					pj_bzero(cand, sizeof(*cand));

					if (strcmp(type, "host")==0)
						cand->type = PJ_ICE_CAND_TYPE_HOST;
					else if (strcmp(type, "srflx")==0)
						cand->type = PJ_ICE_CAND_TYPE_SRFLX;
					else if (strcmp(type, "relay")==0)
						cand->type = PJ_ICE_CAND_TYPE_RELAYED;
					else {
						PJ_LOG(1, (THIS_FILE, "Error: invalid candidate type '%s'",
								   type));
						goto on_error;
					}

					cand->comp_id = (pj_uint8_t)comp_id;
					pj_strdup2(ice->pool, &cand->foundation, foundation);
					cand->prio = prio;

					if (strchr(ipaddr, ':'))
						af = pj_AF_INET6();
					else
						af = pj_AF_INET();

					tmpaddr = pj_str(ipaddr);
					pj_sockaddr_init(af, &cand->addr, NULL, 0);
					status = pj_sockaddr_set_str_addr(af, &cand->addr, &tmpaddr);
					if (status != PJ_SUCCESS) {
						PJ_LOG(1,(THIS_FILE, "Error: invalid IP address '%s'",
								  ipaddr));
						goto on_error;
					}

					pj_sockaddr_set_port(&cand->addr, (pj_uint16_t)port);

					++ice->rem.cand_cnt;

					if (cand->comp_id > ice->rem.comp_cnt)
						ice->rem.comp_cnt = cand->comp_id;
				}
			}
			break;
		}
	}

	if (ice->rem.cand_cnt==0 ||
		ice->rem.ufrag[0]==0 ||
		ice->rem.pwd[0]==0 ||
		ice->rem.comp_cnt == 0)
	{
		PJ_LOG(1, (THIS_FILE, "Error: not enough info"));
		goto on_error;
	}

	if (comp0_port==0 || comp0_addr[0]=='\0') {
		PJ_LOG(1, (THIS_FILE, "Error: default address for component 0 not found"));
		goto on_error;
	} else {
		int af;
		pj_str_t tmp_addr;
		pj_status_t status;

		if (strchr(comp0_addr, ':'))
			af = pj_AF_INET6();
		else
			af = pj_AF_INET();

		pj_sockaddr_init(af, &ice->rem.def_addr[0], NULL, 0);
		tmp_addr = pj_str(comp0_addr);
		status = pj_sockaddr_set_str_addr(af, &ice->rem.def_addr[0],
				&tmp_addr);
		if (status != PJ_SUCCESS) {
			PJ_LOG(1,(THIS_FILE, "Invalid IP address in c= line"));
			goto on_error;
		}
		pj_sockaddr_set_port(&ice->rem.def_addr[0], (pj_uint16_t)comp0_port);
	}

//	PJ_LOG(3, ("icedemo.c", "Done, %d remote candidate(s) added", ice->rem.cand_cnt));

	printf(THIS_FILE, "Done, %d remote candidate(s) added", ice->rem.cand_cnt);

	return;

on_error:
	reset_rem_info(ice);
}

/*
 * Input and parse SDP from the remote (containing remote's ICE information)
 * and save it to global variables.
 */
static void icedemo_input_remote(app* ice)
{
	char linebuf[80];
	unsigned media_cnt = 0;
	unsigned comp0_port = 0;
	char     comp0_addr[80];
	pj_bool_t done = PJ_FALSE;

	puts("Paste SDP from remote host, end with empty line");

	reset_rem_info(ice);

	comp0_addr[0] = '\0';

	while (!done) {
	pj_size_t len;
	char *line;

	printf(">");
	if (stdout) fflush(stdout);

	if (fgets(linebuf, sizeof(linebuf), stdin)==NULL)
		break;

	len = strlen(linebuf);
	while (len && (linebuf[len-1] == '\r' || linebuf[len-1] == '\n'))
		linebuf[--len] = '\0';

	line = linebuf;
	while (len && pj_isspace(*line))
		++line, --len;

	if (len==0)
		break;

	/* Ignore subsequent media descriptors */
	if (media_cnt > 1)
		continue;

	switch (line[0]) {
	case 'm':
		{
		int cnt;
		char media[32], portstr[32];

		++media_cnt;
		if (media_cnt > 1) {
			puts("Media line ignored");
			break;
		}

		cnt = sscanf(line+2, "%s %s RTP/", media, portstr);
		if (cnt != 2) {
			PJ_LOG(1,(THIS_FILE, "Error parsing media line"));
			goto on_error;
		}

		comp0_port = atoi(portstr);

		}
		break;
	case 'c':
		{
		int cnt;
		char c[32], net[32], ip[80];

		cnt = sscanf(line+2, "%s %s %s", c, net, ip);
		if (cnt != 3) {
			PJ_LOG(1,(THIS_FILE, "Error parsing connection line"));
			goto on_error;
		}

		strcpy(comp0_addr, ip);
		}
		break;
	case 'a':
		{
		char *attr = strtok(line+2, ": \t\r\n");
		if (strcmp(attr, "ice-ufrag")==0) {
			strcpy(ice->rem.ufrag, attr+strlen(attr)+1);
		} else if (strcmp(attr, "ice-pwd")==0) {
			strcpy(ice->rem.pwd, attr+strlen(attr)+1);
		} else if (strcmp(attr, "rtcp")==0) {
			char *val = attr+strlen(attr)+1;
			int af, cnt;
			int port;
			char net[32], ip[64];
			pj_str_t tmp_addr;
			pj_status_t status;

			cnt = sscanf(val, "%d IN %s %s", &port, net, ip);
			if (cnt != 3) {
			PJ_LOG(1,(THIS_FILE, "Error parsing rtcp attribute"));
			goto on_error;
			}

			if (strchr(ip, ':'))
			af = pj_AF_INET6();
			else
			af = pj_AF_INET();

			pj_sockaddr_init(af, &ice->rem.def_addr[1], NULL, 0);
			tmp_addr = pj_str(ip);
			status = pj_sockaddr_set_str_addr(af, &ice->rem.def_addr[1],
							  &tmp_addr);
			if (status != PJ_SUCCESS) {
			PJ_LOG(1,(THIS_FILE, "Invalid IP address"));
			goto on_error;
			}
			pj_sockaddr_set_port(&ice->rem.def_addr[1], (pj_uint16_t)port);

		} else if (strcmp(attr, "candidate")==0) {
			char *sdpcand = attr+strlen(attr)+1;
			int af, cnt;
			char foundation[32], transport[12], ipaddr[80], type[32];
			pj_str_t tmpaddr;
			int comp_id, prio, port;
			pj_ice_sess_cand *cand;
			pj_status_t status;

			cnt = sscanf(sdpcand, "%s %d %s %d %s %d typ %s",
				 foundation,
				 &comp_id,
				 transport,
				 &prio,
				 ipaddr,
				 &port,
				 type);
			if (cnt != 7) {
			PJ_LOG(1, (THIS_FILE, "error: Invalid ICE candidate line"));
			goto on_error;
			}

			cand = &ice->rem.cand[ice->rem.cand_cnt];
			pj_bzero(cand, sizeof(*cand));

			if (strcmp(type, "host")==0)
			cand->type = PJ_ICE_CAND_TYPE_HOST;
			else if (strcmp(type, "srflx")==0)
			cand->type = PJ_ICE_CAND_TYPE_SRFLX;
			else if (strcmp(type, "relay")==0)
			cand->type = PJ_ICE_CAND_TYPE_RELAYED;
			else {
			PJ_LOG(1, (THIS_FILE, "Error: invalid candidate type '%s'",
				   type));
			goto on_error;
			}

			cand->comp_id = (pj_uint8_t)comp_id;
			pj_strdup2(ice->pool, &cand->foundation, foundation);
			cand->prio = prio;

			if (strchr(ipaddr, ':'))
			af = pj_AF_INET6();
			else
			af = pj_AF_INET();

			tmpaddr = pj_str(ipaddr);
			pj_sockaddr_init(af, &cand->addr, NULL, 0);
			status = pj_sockaddr_set_str_addr(af, &cand->addr, &tmpaddr);
			if (status != PJ_SUCCESS) {
			PJ_LOG(1,(THIS_FILE, "Error: invalid IP address '%s'",
				  ipaddr));
			goto on_error;
			}

			pj_sockaddr_set_port(&cand->addr, (pj_uint16_t)port);

			++ice->rem.cand_cnt;

			if (cand->comp_id > ice->rem.comp_cnt)
			ice->rem.comp_cnt = cand->comp_id;
		}
		}
		break;
	}
	}

	if (ice->rem.cand_cnt==0 ||
	ice->rem.ufrag[0]==0 ||
	ice->rem.pwd[0]==0 ||
	ice->rem.comp_cnt == 0)
	{
	PJ_LOG(1, (THIS_FILE, "Error: not enough info"));
	goto on_error;
	}

	if (comp0_port==0 || comp0_addr[0]=='\0') {
	PJ_LOG(1, (THIS_FILE, "Error: default address for component 0 not found"));
	goto on_error;
	} else {
	int af;
	pj_str_t tmp_addr;
	pj_status_t status;

	if (strchr(comp0_addr, ':'))
		af = pj_AF_INET6();
	else
		af = pj_AF_INET();

	pj_sockaddr_init(af, &ice->rem.def_addr[0], NULL, 0);
	tmp_addr = pj_str(comp0_addr);
	status = pj_sockaddr_set_str_addr(af, &ice->rem.def_addr[0],
					  &tmp_addr);
	if (status != PJ_SUCCESS) {
		PJ_LOG(1,(THIS_FILE, "Invalid IP address in c= line"));
		goto on_error;
	}
	pj_sockaddr_set_port(&ice->rem.def_addr[0], (pj_uint16_t)comp0_port);
	}

	PJ_LOG(3, (THIS_FILE, "Done, %d remote candidate(s) added",
		   ice->rem.cand_cnt));
	return;

on_error:
	reset_rem_info(ice);
}


/*
 * Start ICE negotiation! This function is invoked from the menu.
 */
static void icedemo_start_nego(app* ice)
{
	assert(NULL != ice);

	pj_str_t rufrag, rpwd;
	pj_status_t status;

	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	if (!pj_ice_strans_has_sess(ice->icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	return;
	}

	if (ice->rem.cand_cnt == 0) {
	PJ_LOG(1,(THIS_FILE, "Error: No remote info, input remote info first"));
	return;
	}

	PJ_LOG(3,(THIS_FILE, "Starting ICE negotiation.."));

	status = pj_ice_strans_start_ice(ice->icest,
					 pj_cstr(&rufrag, ice->rem.ufrag),
					 pj_cstr(&rpwd, ice->rem.pwd),
					 ice->rem.cand_cnt,
					 ice->rem.cand);
	if (status != PJ_SUCCESS)
	icedemo_perror("Error starting ICE", status);
	else
	PJ_LOG(3,(THIS_FILE, "ICE negotiation started"));
}


/*
 * Send application data to remote agent.
 */
static void icedemo_send_data(app* ice, unsigned comp_id, const char *data)
{
	assert(NULL != ice);

	pj_status_t status;

	if (ice->icest == NULL) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	return;
	}

	if (!pj_ice_strans_has_sess(ice->icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	return;
	}

	/*
	if (!pj_ice_strans_sess_is_complete(icedemo.icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: ICE negotiation has not been started or is in progress"));
	return;
	}
	*/

	if (comp_id<1||comp_id>pj_ice_strans_get_running_comp_cnt(ice->icest)) {
	PJ_LOG(1,(THIS_FILE, "Error: invalid component ID"));
	return;
	}

	status = pj_ice_strans_sendto(ice->icest, comp_id, data, strlen(data),
				  &ice->rem.def_addr[comp_id-1],
				  pj_sockaddr_get_len(&ice->rem.def_addr[comp_id-1]));
	if (status != PJ_SUCCESS)
	icedemo_perror("Error sending data", status);
	else
	PJ_LOG(3,(THIS_FILE, "Data sent"));
}


/*
 * Display help for the menu.
 */
static void icedemo_help_menu(void)
{
	puts("");
	puts("-= Help on using ICE and this icedemo program =-");
	puts("");
	puts("This application demonstrates how to use ICE in pjnath without having\n"
	 "to use the SIP protocol. To use this application, you will need to run\n"
	 "two instances of this application, to simulate two ICE agents.\n");

	puts("Basic ICE flow:\n"
	 " create instance [menu \"c\"]\n"
	 " repeat these steps as wanted:\n"
	 "   - init session as offerer or answerer [menu \"i\"]\n"
	 "   - display our SDP [menu \"s\"]\n"
	 "   - \"send\" our SDP from the \"show\" output above to remote, by\n"
	 "     copy-pasting the SDP to the other icedemo application\n"
	 "   - parse remote SDP, by pasting SDP generated by the other icedemo\n"
	 "     instance [menu \"r\"]\n"
	 "   - begin ICE negotiation in our end [menu \"b\"], and \n"
	 "   - immediately begin ICE negotiation in the other icedemo instance\n"
	 "   - ICE negotiation will run, and result will be printed to screen\n"
	 "   - send application data to remote [menu \"x\"]\n"
	 "   - end/stop ICE session [menu \"e\"]\n"
	 " destroy instance [menu \"d\"]\n"
	 "");

	puts("");
	puts("This concludes the help screen.");
	puts("");
}


/*
 * Display console menu
 */
static void icedemo_print_menu(void)
{
	puts("");
	puts("+----------------------------------------------------------------------+");
	puts("|                    M E N U                                           |");
	puts("+---+------------------------------------------------------------------+");
	puts("| c | create           Create the instance                             |");
	puts("| d | destroy          Destroy the instance                            |");
	puts("| i | init o|a         Initialize ICE session as offerer or answerer   |");
	puts("| e | stop             End/stop ICE session                            |");
	puts("| s | show             Display local ICE info                          |");
	puts("| r | remote           Input remote ICE info                           |");
	puts("| b | start            Begin ICE negotiation                           |");
	puts("| x | send <compid> .. Send data to remote                             |");
	puts("+---+------------------------------------------------------------------+");
	puts("| h |  help            * Help! *                                       |");
	puts("| q |  quit            Quit                                            |");
	puts("+----------------------------------------------------------------------+");
}

void* thread_signal_heart(void *data)
{
	assert(data != NULL);
	app* ice = (app*)data;

	while (!ice->quit)
	{
		int ret = sendto(ice->addr_signal.sockfd, ice->registe_info_buffer, ice->len_registe_info_buffer, 0, (struct sockaddr *)&ice->addr_signal.addr, sizeof(ice->addr_signal.addr));
		if (ret < 0)
		{
			PJ_LOG(1, (THIS_FILE, "thread_signal_heart:sendto err=%d", errno));
			break;
		}

		sleep(5);
	}
}

void do_register_response(char* data)
{
	assert(data != NULL);
	int offset = 0;

	int len = 0;
	memcpy(&len, data + offset, sizeof(len));
	len = ntohl(len);
	offset += sizeof(len);

	char value[64] = {0};
	memcpy(value, data + offset, len);
}

void do_traversal_request(app* ice, char* data)
{	
	assert(data != NULL);

	int offset = 0;

	int attr = 0;
	memcpy(&attr, data + offset, sizeof(attr));
	attr = ntohl(attr);
	offset += sizeof(attr);

	if (attr != TYPE_ATTR_HOLE_INFO)
	{
		return;
	}

	int len = 0;
	memcpy(&len, data + offset, sizeof(len));
	len = ntohl(len);
	offset += sizeof(len);

	char hole_info[1024] = {0};
	memcpy(hole_info, data + offset, len);

	icedemo_input_remote2(ice, hole_info, len);

	ice->offer_can_nego = PJ_TRUE;
}

void do_traversal_response(app* ice, char* data)
{
	assert(data != NULL);

	int offset = 0;

	int err_code = 0;
	memcpy(&err_code, data + offset, sizeof(err_code));
	err_code = ntohl(err_code);
	offset += sizeof(err_code);

	if (err_code != ERROR_SUCCESS)
	{
		PJ_LOG(1, (THIS_FILE, "do_traversal_response error: err=%d", err_code));
		return;
	}

	int attr = 0;
	memcpy(&attr, data + offset, sizeof(attr));
	attr = ntohl(attr);
	offset += sizeof(attr);

	if (attr != TYPE_ATTR_HOLE_INFO)
	{
		return;
	}

	int len = 0;
	memcpy(&len, data + offset, sizeof(len));
	len = ntohl(len);
	offset += sizeof(len);

	char hole_info[1024] = {0};
	memcpy(hole_info, data + offset, len);

	icedemo_input_remote2(ice, hole_info, len);

	ice->answer_can_nego = PJ_TRUE;
}

void* do_handle_recv_signal_info(void *data)
{
	assert(data != NULL);

	app* ice = (app*)data;

	char *msg = ice->recv_original_buffer;
	int offset = 0;

	int msg_type = 0;
	memcpy(&msg_type, msg + offset, sizeof(msg_type));
	msg_type = ntohl(msg_type);
	offset +=  sizeof(msg_type);

	switch (msg_type)
	{
	case MSG_TYPE_REGISTER_RESPONSE:
		do_register_response(msg + offset);
		break;
	case MSG_TYPE_TRAVERSAL_REQUEST: //answer-->turn-->offer
		do_traversal_request(ice, msg + offset);
		break;
	case MSG_TYPE_TRAVERSAL_RESPONSE: //turn-->answer
		do_traversal_response(ice, msg + offset);
		break;
	defalut:
		break;
	}

	if (data != NULL)
	{
		free(data);
		data = NULL;
	}
}

//msg type(4B) attr(4B) attr_len(4B) attr_content attr(4B) attr_len(4B) attr_content ...

void make_register_info(app* ice)
{
	assert(NULL != ice);

	ice->len_registe_info_buffer = 0;
	int buff_max = 2048;

	int msg_type = MSG_TYPE_REGISTER;
	msg_type = htonl(msg_type);
	memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &msg_type, sizeof(msg_type));
	ice->len_registe_info_buffer += sizeof(msg_type);
	assert(ice->len_registe_info_buffer < buff_max);
	int type_len = 0;

	int attr;
	if (0 == ice->opt.role)
	{
		attr = TYPE_ATTR_GUID_OFFER;
		attr = htonl(attr);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &attr, sizeof(attr));
		ice->len_registe_info_buffer += sizeof(attr);
		assert(ice->len_registe_info_buffer < buff_max);
		type_len = htonl(ice->opt.guid_offer.slen);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &type_len, sizeof(type_len));
		ice->len_registe_info_buffer += sizeof(type_len);
		assert(ice->len_registe_info_buffer < buff_max);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, ice->opt.guid_offer.ptr, ice->opt.guid_offer.slen);
		ice->len_registe_info_buffer += ice->opt.guid_offer.slen;
		assert(ice->len_registe_info_buffer < buff_max);
	}
	else
	{
		attr = TYPE_ATTR_GUID_ANSWER;
		attr = htonl(attr);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &attr, sizeof(attr));
		ice->len_registe_info_buffer += sizeof(attr);
		assert(ice->len_registe_info_buffer< buff_max);
		type_len = htonl(ice->opt.guid_answer.slen);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &type_len, sizeof(type_len));
		ice->len_registe_info_buffer += sizeof(type_len);
		assert(ice->len_registe_info_buffer < buff_max);
		memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, ice->opt.guid_answer.ptr, ice->opt.guid_answer.slen);
		ice->len_registe_info_buffer += ice->opt.guid_answer.slen;
		assert(ice->len_registe_info_buffer < buff_max);
	}

	attr = TYPE_ATTR_HOLE_INFO;
	attr = htonl(attr);
	memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &attr, sizeof(attr));
	ice->len_registe_info_buffer += sizeof(attr);
	assert(ice->len_registe_info_buffer < buff_max);
	type_len = htonl(ice->len_local_info);
	memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, &type_len, sizeof(type_len));
	ice->len_registe_info_buffer += sizeof(type_len);
	assert(ice->len_registe_info_buffer < buff_max);
	memcpy(ice->registe_info_buffer + ice->len_registe_info_buffer, ice->local_info_buffer, ice->len_local_info);
	ice->len_registe_info_buffer += ice->len_local_info;
	assert(ice->len_registe_info_buffer < buff_max);
}

void* thread_transmit_signal(void *data)
{
	assert (NULL != data);

	app *ice = (app*)data;

	icedemo_show_ice_auto(ice, ice->local_info_buffer, &ice->len_local_info);

	make_register_info(ice);

	//send local info to server.
	bzero(&ice->addr_signal.addr, sizeof(ice->addr_signal.addr));
	ice->addr_signal.addr.sin_family = AF_INET;
	ice->addr_signal.addr.sin_port = htons(ice->signal_port);
	inet_pton(AF_INET, ice->signal_addr.ptr, &ice->addr_signal.addr.sin_addr);

	ice->addr_signal.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ice->addr_signal.sockfd < 0)
	{
		PJ_LOG(1, (THIS_FILE, "SOCK_DGRAM error, err=%d", errno));
		return NULL;
	}

	int ret = sendto(ice->addr_signal.sockfd, ice->registe_info_buffer, ice->len_registe_info_buffer, 0, (struct sockaddr *)&ice->addr_signal.addr, sizeof(ice->addr_signal.addr));
	if (ret < 0)
	{
		PJ_LOG(1, (THIS_FILE, "thread_transmit_signal:sendto error, err=%d", errno));
		return NULL;
	}

	pthread_t t_heart;
	ret = pthread_create(&t_heart, NULL, thread_signal_heart, (void*)ice);

	while (!ice->quit)
	{
		memset(ice->recv_original_buffer, 0, max_buff_line);
		int recv_len = recvfrom(ice->addr_signal.sockfd, ice->recv_original_buffer, max_buff_line, 0, NULL, NULL);
		if (recv_len < 0)
		{
			PJ_LOG(1, (THIS_FILE, "recv from server failed,err=%d", errno));
		}

		pthread_t t;
		pthread_create(&t, NULL, do_handle_recv_signal_info, (void*)ice);
	}

	return NULL;
}

static void offer_traversal(app* ice)
{
	assert(NULL != ice);

	while (!ice->quit)
	{
		if (ice->offer_can_nego)
		{
			icedemo_start_nego(ice);
			break;
		}
		usleep(1000);
	}
}

static void answer_traversal(app* ice)
{
	assert(NULL != ice);

	char send_buffer[512] = {0};
	int offset = 0;

	int msg_type = MSG_TYPE_TRAVERSAL_REQUEST;
	msg_type = htonl(msg_type);
	memcpy(send_buffer + offset, &msg_type, sizeof(msg_type));
	offset += sizeof(msg_type);

	int attr_type = TYPE_ATTR_GUID_ANSWER;
	attr_type = htonl(attr_type);
	memcpy(send_buffer + offset, &attr_type, sizeof(attr_type));
	offset += sizeof(attr_type);

	int len = ice->opt.guid_answer.slen;
	len = htonl(len);
	memcpy(send_buffer + offset, &len, sizeof(len));
	offset += sizeof(len);

	memcpy(send_buffer + offset, ice->opt.guid_answer.ptr, ice->opt.guid_answer.slen);
	offset += ice->opt.guid_answer.slen;

	attr_type = TYPE_ATTR_GUID_OFFER;
	attr_type = htonl(attr_type);
	memcpy(send_buffer + offset, &attr_type, sizeof(attr_type));
	offset += sizeof(attr_type);

	len = ice->opt.guid_answer.slen;
	len = htonl(len);
	memcpy(send_buffer + offset, &len, sizeof(len));
	offset += sizeof(len);

	memcpy(send_buffer + offset, ice->opt.guid_offer.ptr, ice->opt.guid_offer.slen);
	offset += ice->opt.guid_offer.slen;

	int ret = sendto(ice->addr_signal.sockfd, send_buffer, offset, 0, (struct sockaddr *)&ice->addr_signal.addr, sizeof(ice->addr_signal.addr));
	if (ret < 0)
	{
		PJ_LOG(1, (THIS_FILE, "answer_request_traversal:sendto error, err=%d", errno));
		return ;
	}

	while (!ice->quit)
	{
		if (ice->answer_can_nego)
		{
			icedemo_start_nego(ice);
			break;
		}

		usleep(1000);
	}
}

static void icedemo_auto(app* ice)
{
	assert(NULL != ice);

	PJ_LOG(1,(THIS_FILE, "ice demo auto mode..."));

	ice->quit = PJ_FALSE;
	ice->init_success = PJ_FALSE;
	ice->session_ready = PJ_FALSE;
	ice->offer_can_nego = PJ_FALSE;
	ice->answer_can_nego = PJ_FALSE;
	ice->nego_success = PJ_FALSE;

	icedemo_create_instance(ice);

	int cnt = 0;
	while (!ice->init_success && ++cnt < 15 * 1000 && !ice->quit)
	{
		usleep(1000);
	}

	if (!ice->init_success)
	{
		goto end;
	}

	unsigned role = ice->opt.role == 0 ? 'o' : 'a';
	icedemo_init_session(ice, role);

	if (!ice->session_ready)
	{
		goto end;
	}

	pthread_t t_signal_transmit;
	int ret = pthread_create(&t_signal_transmit, NULL, thread_transmit_signal, NULL);
	if (ret != 0)
	{
		goto end;
	}

	if (0 == ice->opt.role)
	{
		offer_traversal(ice);
	}
	else
	{
		cnt  = 0;
		while (++cnt < 15 * 1000 && !ice->quit)
		{
			if (ice->addr_signal.sockfd > 0)
			{
				answer_traversal(ice);
				break;
			}
			usleep(1000);
		}
	}

	cnt = 0;
	while (++cnt < 15 * 1000 && !ice->quit)
	{
		if (ice->nego_success)
		{
			break;
		}
		usleep(1000);
	}

	if (!ice->nego_success)
	{
		printf("EEEEEEEEEEEEEEEEEEEE-can not nego.role=%d\n, guid=%s", ice->opt.role, ice->opt.role == 0 ? ice->opt.guid_offer.ptr : ice->opt.guid_answer.ptr);
		goto end;
	}

	//p2p success. can send data to peer now.
	char* data_offer = "++++++++++++++++++++offer-data+++++++++++++++++\0";
	char* data_answer = "-------------------answer-data----------------\0";
	while (!ice->quit)
	{
		if (0 == ice->opt.role)
		{
			icedemo_send_data(ice, 1, data_offer);
		}
		else
		{
			icedemo_send_data(ice, 1, data_answer);
		}

		sleep(10);
	}

	while (!ice->quit)
	{
		sleep(1);
	}

end:
	ice->quit = PJ_TRUE;
	icedemo_stop_session(ice);
	icedemo_destroy_instance(ice);
}
/*
 * Display program usage.
 */
static void icedemo_usage()
{
	puts("Usage: icedemo [optons]");
	printf("icedemo v%s by pjsip.org\n", pj_get_version());
	puts("");
	puts("General options:");
	puts(" --comp-cnt, -c N          Component count (default=1)");
	puts(" --nameserver, -n IP       Configure nameserver to activate DNS SRV");
	puts("                           resolution");
	puts(" --max-host, -H N          Set max number of host candidates to N");
	puts(" --regular, -R             Use regular nomination (default aggressive)");
	puts(" --log-file, -L FILE       Save output to log FILE");
	puts(" --help, -h                Display this screen.");
	puts("");
	puts("STUN related options:");
	puts(" --stun-srv, -s HOSTDOM    Enable srflx candidate by resolving to STUN server.");
	puts("                           HOSTDOM may be a \"host_or_ip[:port]\" or a domain");
	puts("                           name if DNS SRV resolution is used.");
	puts("");
	puts("TURN related options:");
	puts(" --turn-srv, -t HOSTDOM    Enable relayed candidate by using this TURN server.");
	puts("                           HOSTDOM may be a \"host_or_ip[:port]\" or a domain");
	puts("                           name if DNS SRV resolution is used.");
	puts(" --turn-tcp, -T            Use TCP to connect to TURN server");
	puts(" --turn-username, -u UID   Set TURN username of the credential to UID");
	puts(" --turn-password, -p PWD   Set password of the credential to WPWD");
	puts(" --turn-fingerprint, -F    Use fingerprint for outgoing TURN requests");
	puts("");
}


/*
 * And here's the main()
 */
int main(int argc, char *argv[])
{
	struct pj_getopt_option long_options[] = {
	{ "comp-cnt",                   1, 0, 'c'},
	{ "nameserver",		            1, 0, 'n'},
	{ "max-host",		            1, 0, 'H'},
	{ "help",			            0, 0, 'h'},
	{ "stun-srv",		            1, 0, 's'},
	{ "turn-srv",		            1, 0, 't'},
	{ "turn-tcp",		            0, 0, 'T'},
	{ "turn-username",	            1, 0, 'u'},
	{ "turn-password",	            1, 0, 'p'},
	{ "turn-fingerprint",	        0, 0, 'F'},
	{ "regular",		            0, 0, 'R'},
	{ "log-file",		            1, 0, 'L'},
	{ "console-mode",    	        0, 0, 'C'},
	{ "auto-mode",      	        0, 0, 'D'},
	{ "input-role",					1, 0, 'i'},
	{ "guid",    					1, 0, 'g'},
	{ "guid-peer",					1, 0, 'G'},
	{ "signal-addr",				1, 0, 'S'},
	{ "signal-port",				1, 0, 'P'},

	};

	int c, opt_id;
	pj_status_t status;

	app* ice = (app*) malloc(sizeof(ice));
	assert(NULL != ice);

	ice->opt.comp_cnt = 1;
	ice->opt.max_host = -1;
	memset(&ice->signal_addr, 0, sizeof(pj_str_t));
	ice->signal_port = 0;

	while((c=pj_getopt_long(argc,argv, "i:c:n:s:t:u:p:H:L:g:G:S:P:hTFRCD", long_options, &opt_id))!=-1) {
	switch (c) {
	case 'c':
		ice->opt.comp_cnt = atoi(pj_optarg);
		if (ice->opt.comp_cnt < 1 || ice->opt.comp_cnt >= PJ_ICE_MAX_COMP) {
		puts("Invalid component count value");
		return 1;
		}
		break;
	case 'n':
		ice->opt.ns = pj_str(pj_optarg);
		break;
	case 'H':
		ice->opt.max_host = atoi(pj_optarg);
		break;
	case 'h':
		icedemo_usage();
		return 0;
	case 's':
		ice->opt.stun_srv = pj_str(pj_optarg);
		break;
	case 't':
		ice->opt.turn_srv = pj_str(pj_optarg);
		break;
	case 'T':
		ice->opt.turn_tcp = PJ_TRUE;
		break;
	case 'u':
		ice->opt.turn_username = pj_str(pj_optarg);
		break;
	case 'p':
		ice->opt.turn_password = pj_str(pj_optarg);
		break;
	case 'F':
		ice->opt.turn_fingerprint = PJ_TRUE;
		break;
	case 'R':
		ice->opt.regular = PJ_TRUE;
		break;
	case 'L':
		ice->opt.log_file = pj_optarg;
		break;
	case 'C':
		ice->opt.console_mode = PJ_TRUE;
		break;
	case 'D':
		ice->opt.console_mode = PJ_FALSE;
		break;
	case 'i':
		ice->opt.role = atoi(pj_optarg);//0-offer, 1-answer
		break;
	case 'g':
		ice->opt.guid_offer = pj_str(pj_optarg);
		break;
	case 'G':
		ice->opt.guid_answer = pj_str(pj_optarg);
		break;
	case 'S':
		ice->signal_addr = pj_str(pj_optarg);
		break;
	case 'P':
		ice->signal_port = atoi(pj_optarg);
		break;
	default:
		printf("Argument \"%s\" is not valid. Use -h to see help",  argv[pj_optind]);
		return 1;
	}
	}

	if (0 == ice->signal_port || 0 == ice->signal_addr.slen)
	{
		printf("no singal addr or port? please set it .\n");
		return 1;
	}

	status = icedemo_init(ice);
	if (status != PJ_SUCCESS)
	return 1;

	if (ice->opt.console_mode)
	{

	}
	else
	{
		icedemo_auto(ice);
	}

	err_exit(ice, "Quitting..", PJ_SUCCESS);

	return 0;
}
