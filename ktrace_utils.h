#ifndef __KTRACE_UTILS_H__
#define __KTRACE_UTILS_H__

#include "ip_addr_hash.h"
#include "log.h"
#include "stats.h"
#include "ktrace_shm.h"

#include <sys/types.h>
#include <openssl/ssl.h>
#include <pcap.h>
#include <sslcap.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#define PORT_ARG_LEN USHRT_MAX + 1
#define ENVOYIP_LEN 16
#define MAX_PATH_LEN 1024
#define MAX_PWD_LEN 256
#define LOG_LEVEL_LEN 20
#define LOG_MODULE_LEN 20
#define IP_LEN 20
#define ERR_MSG 2048
#define MAX_PKT_SIZE 65535
#define HEADER_LEN 512
#define SOCK_TIMEOUT 10

#define IS_VALID_PORT(p) (((p >= -1) && (p <= USHRT_MAX )) ? 1 : 0)
#define INTERNAL_DOMAIN_LIST_SIZE 500
#define CIDR_LIST_SIZE 500
#define LISTENER_PORT_LEN 10
#define DAEMONSET "DaemonSet"
#define VPCMIRRORING "VPCMirroring"
#define WILDCARD_PORT "*"

/* KTRACE_ARGS src_type constants */
#define SRCTYPE_FILE 1
#define SCRTYPE_LIVE 2
#define ENABLE_DISABLE 7

/* A structure to place parsed command line argument */
typedef struct _KTRACE_ARGS {
  char envoy_ip[ENVOYIP_LEN]; /* Envoy IP Address */
  char keyfile[MAX_PATH_LEN]; /* SSL server's private key file path */
  char pwd[MAX_PWD_LEN];      /*Keyfile password, if present; NULL otherwise */
  char src[MAX_PATH_LEN]; /* Input source - a capture file in tcpdump format or a network interface
                             name */
  int src_type;           /* Input source type - SRCTYPE_FILE or SCRTYPE_LIVE */
  struct in_addr server_ip; /* SSL server's IP address */
  uint16_t port;            /* SSL server's port */
  char* filter_exp;         /* Filter expression for pcap filter */
  char loglevel[LOG_LEVEL_LEN]; /* Log Level */
  char log_module[LOG_MODULE_LEN]; /* Log module */
} KTRACE_ARGS;


extern char err_msg[ERR_MSG];
extern char *deployment_type;

typedef enum { NONE = -1, TCP_FROM, HTTP_FROM, SSL_FROM, TCP_TO = 5, HTTP_TO } PORTDETAILS;

typedef enum { TCP, HTTP, SSL_PROTO } PROTOCOL;

typedef enum {
  INGRESS_TCP = 0,
  INGRESS_HTTP,
  INGRESS_SSL,
  INT_INGRESS_TCP = 3,
  INT_INGRESS_HTTP,
  EGRESS_TCP = 5,
  EGRESS_HTTP,
  EGRESS_SSL,
  INT_EGRESS_TCP = 8,
  INT_EGRESS_HTTP
} LISTENER_PORT_T;


typedef struct cluster_ip {
  struct in_addr addr;
  int bits;
} CLUSTER_IP;

typedef struct KTRACE_CONFIG {
  int *ingress_ports, *egress_ports; 
  int ports_for_exper[PORT_ARG_LEN];
  int listener_ports[LISTENER_PORT_LEN];

  CLUSTER_IP *instance_ip_cidr_list, *instance_ip_except_cidr_list;
  CLUSTER_IP *internal_domain_cidr_list, *internal_domain_cidr_except_list;
  
  int no_of_internal_domain_cidr, no_of_internal_domain_except_cidr; 
  int no_of_instance_ip_cidr, no_of_instance_ip_except_cidr;

  int no_of_exclude_ingress_ports, no_of_exclude_egress_ports;
  int exclude_ingress_ports[PORT_ARG_LEN], exclude_egress_ports[PORT_ARG_LEN];

  int  standalone_mode;
  IP_ENTRY_HASH_T instances_ips_hash_table;
  IP_ENTRY_HASH_T internal_domain_ips_hash_table;
} KTRACE_CONFIG_T;

#define SESSION_CONTEXT_SOCK_NEW (-2)
#define SESSION_CONTEXT_SOCK_CLOSED (-1)

/** Additional context attached to each libdssl session */
typedef struct session_context {
  /** parent pointer to libdssl's session */
  TcpSession* sess;

  /**
   * socket fd for connection to envoy OR
   * SESSION_CONTEXT_SOCK_NEW when not yet connected
   * SESSION_CONTEXT_SOCK_CLOSED when already disconnected
   */
  int sock;
  KTRACE_CONFIG_T* ktrace_config;
} SESSION_CONTEXT;

SESSION_CONTEXT* new_session_context(TcpSession* session, KTRACE_CONFIG_T *ktrace_config);

/**
 * Retrieve pointer to structure holding program arguments
 */
KTRACE_ARGS* get_args();

/**
 *  Process the command line parameters
 */
int load_args(int argc, char** argv, KTRACE_ARGS* Args, int listener_ports[], char hostname[]);

/**
 * Print program's command line parameters help
 */
void print_usage();

char* get_port();

void get_log_string(TcpSession* sess, char* log, size_t size);

int create_connection(SESSION_CONTEXT* sess);

void close_connection(SESSION_CONTEXT* context);

void ignore_session(SESSION_CONTEXT* context);

/**
 * Wrap payload in ktrace frame and send to a socket.
 *
 * `prefix` is header without the trailing " <length>\r\n" part, eg. "SDATA", "CDATA".
 *
 * returns true whether the operation has completed successfully
 */
bool send_payload(SESSION_CONTEXT* context, const char* prefix, const u_char* pkt_payload, uint32_t pkt_size);

int set_portdetails(int* ingress, int* egress, int* ports_for_exper, int* ingress_wildcard,
                    int* egress_wildcard, int standalone_mode, char port_range_for_expr[][20], 
                    int *no_of_port_range, KTRACE_CONFIG_T *ktrace_config);

int check_ingress_traffic(IP_ENTRY_HASH_T instances_ips_hash_table, IP_ENTRY_HASH_KEY_T *iph, 
                          CLUSTER_IP cidr_list[], int no_of_cidr, 
                          CLUSTER_IP except_cidr_list[], int no_of_except_cidr,int dst_port);

int check_external_traffic(IP_ENTRY_HASH_T domain_ips_hash_table, IP_ENTRY_HASH_KEY_T *iph,
                           CLUSTER_IP cidr_list[], int no_of_cidr,
                           CLUSTER_IP except_cidr_list[], int no_of_except_cidr,int dst_port);

bool is_pcap_enabled();

int execute_command(const char *cmd, char *out_buff, size_t out_buff_len);

int is_cluster_ip(struct in_addr addr, CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr);

#endif /* __KTRACE_UTILS_H__ */
