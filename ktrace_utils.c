#include "ktrace_utils.h"

#define TRUE 1
#define FALSE 0

static char *tcp_port, *http_port, *ssl_port;
static int *ingress_port_list, *egress_port_list;
static bool pcap_enabled = true;

static KTRACE_ARGS args;
KTRACE_ARGS* get_args() { return &args; };

void print_usage(void) {
  printf("ktrace: a command-line SSL/TLS analyzer utility.\n");
  printf(
      "\nUsage: ktrace -i <interface> || -r <file> -eip <envoy IP>  -key <file> -ip <server IP> "
      "[-pwd <password>]  -tcpport <tcp src#dst port> -httpport <http src#dst port> -sslport  "
      "<tls src#0 port>");
  printf("\nInput parameters:");
  printf("\n\t-i <interface>: capture and decrypt data from network link <interface>");
  printf("\n\t-r <file>: decrypt data from pcap capture file");
  printf(
      "\n\t-loglevel: Acceptable values: debug, info, warn, error, critical. (Default critical.)");
  printf("\n\t-key: server's private key file path");
  printf("\n\t-pwd: (optional) server's private key file password, if the file is encrypted");
  printf("\n\t-ip: server IP address");
  printf("\n\t-eip: envoy IP address");
  printf(
      "\n\t-tcpport: TCP Port. multiple ports seperated by , source and destination seperated "
      "by # - (eg: 3306,3310#3306) ");
  printf(
      "\n\t-httpport: HTTP Port. multiple ports seperated by , source and destination seperated "
      "by # - (eg: 8070#80,8080) ");
  printf(
      "\n\t-sslport: SSL Port. multiple ports seperated by , source and destination seperated "
      "by # - (eg: 443,9443#0)\n");
  printf("\n\t-ingress: List of ingress listener ports.");
  printf("\n\t-egress: List of egress listener ports.");
  printf("\n\t-internal-domain: List of internal domain ip list.");
  printf("\n\t-log-path (optional)");
  printf("\n\t-log-module (optional) eg : ktrace or dns");
  printf("\n\t-pcap: packet capture disable/enable");
}

/* Command line parameter enumeration */

typedef enum ktrace_arg_token {
  invalid = -1,
  envoy_ip = 0,
  input_file,
  interface,
  loglevel,
  log_module,
  key_file,
  key_file_password,
  server_address,
  tcpport,
  httpport,
  sslport,
  ingress_list,
  egress_list,
  internal_ingress,
  internal_egress,
  klog_path,
  pcap
} KTRACE_ARG_TOKEN;

#define ARG_TOKEN_COUNT (pcap - envoy_ip + 1)

/* Command line parameters */
static const char* ArgTokens[] = {"-eip",
                                  "-r",
                                  "-i",
                                  "-loglevel",
                                  "-log-module",
                                  "-key",
                                  "-pwd",
                                  "-ip",
                                  "-tcpport",
                                  "-httpport",
                                  "-sslport",
                                  "-ingress",
                                  "-egress",
                                  "-internalingress",
                                  "-internalegress",
                                  "-log-path",
                                  "-pcap"};

/* Parse a command line parameter and return the corresponding KTRACE_ARG_TOKEN enum */
static KTRACE_ARG_TOKEN GetToken(const char* arg) {
  int i;
  for (i = 0; i < sizeof(ArgTokens) / sizeof(ArgTokens[0]); i++) {
    if (strcmp(arg, ArgTokens[i]) == 0) return (KTRACE_ARG_TOKEN)i;
  }
  return invalid;
}

void set_listener_port(int from, int to, char* ports, int listener_ports[]) {
  int i;
  char* p;
  for (i = from; i < to;) {
    p = strtok(ports, ",");
    while (p != NULL) {
      listener_ports[i++] = atoi(p);
      p = strtok(NULL, ",");
    }
  }
}

void set_pcap_config(char* enable_disable) {
  if (strcmp(enable_disable, "disable") == 0) {
    pcap_enabled = false;
  }
}

bool is_pcap_enabled() {
  return pcap_enabled;
}

/* Process the command line parameters */
int load_args(int argc, char** argv, KTRACE_ARGS* Args, int listener_ports[], char hostname[]) {
  int i = 0, len = 0;
  char token_checks[ARG_TOKEN_COUNT];
  char ingress[PORT_ARG_LEN], egress[PORT_ARG_LEN], int_ingress[PORT_ARG_LEN],
      int_egress[PORT_ARG_LEN];
  memset(token_checks, 0, sizeof(token_checks));
  memset(Args, 0, sizeof(*Args));
  char logfile[MAX_PATH_LEN] = "\0";
  char enable_disable[ENABLE_DISABLE+1];

  /*Setting log path.*/
  for (i = 1; i < argc; i += 2) {
    if (strcmp(argv[i], ArgTokens[klog_path]) == 0) {
      if (i + 1 >= argc) {
        sprintf(err_msg, "Unexpected end of command line: %s key must have a value", argv[i]);
        return -1;
      }
      strncpy(logfile, argv[i + 1], MAX_PATH_LEN);
      break;
    }
  }

  klog_init(logfile);
  /*Inital level set to trace.*/
  set_log_level(LOG_TRACE);
  set_log_module(MODULE_ALL);

  for (i = 1; i < argc; i += 2) {
    KTRACE_ARG_TOKEN token = GetToken(argv[i]);

    if (token == invalid) {
      sprintf(err_msg, "Invalid command line option specified: %s.", argv[i]);
      return -1;
    }

    if (i + 1 >= argc) {
      sprintf(err_msg, "Unexpected end of command line: %s key must have a value", argv[i]);
      return -1;
    }

    if (token == input_file || token == interface || token == key_file) {
      if (strlen(argv[i + 1]) >= MAX_PATH_LEN) {
        sprintf(err_msg,
                "File path or interface name length exceeds the "
                "maximum length expected.");
        return -1;
      }
    }

    if (token >= sizeof(token_checks) / sizeof(token_checks[0])) {
      sprintf(err_msg, "Internal error at %s, line %d", __FILE__, __LINE__);
      return -1;
    }

    if (token_checks[token]) {
      sprintf(err_msg, "Parameter %s specified more than once", argv[i]);
      return -1;
    }

    token_checks[token] = 1;

    switch (token) {
      case envoy_ip:
        strncpy(Args->envoy_ip, argv[i + 1], ENVOYIP_LEN);
        break;

      case input_file:
        strncpy(Args->src, argv[i + 1], MAX_PATH_LEN);
        Args->src_type = SRCTYPE_FILE;
        break;

      case interface:
        strncpy(Args->src, argv[i + 1], MAX_PATH_LEN);
        Args->src_type = SCRTYPE_LIVE;
        break;

      case loglevel:
        strncpy(Args->loglevel, argv[i + 1], LOG_LEVEL_LEN);
        break;

      case log_module:
        strncpy(Args->log_module, argv[i + 1], LOG_MODULE_LEN);
        break;

      case key_file:
        strncpy(Args->keyfile, argv[i + 1], MAX_PATH_LEN);
        break;

      case key_file_password:
        if (strlen(argv[i + 1]) >= MAX_PWD_LEN) {
          KLOG_CRIT(MODULE_KTRACE,"Password length exceeds the maximum length expected.");
          return -1;
        }
        strncpy(Args->pwd, argv[i + 1], MAX_PWD_LEN);
        break;

      case server_address:
        Args->server_ip.s_addr = inet_addr(argv[i + 1]);
        if (INADDR_NONE == Args->server_ip.s_addr) {
          KLOG_CRIT(MODULE_KTRACE,"Invalid IP address format '%s'", argv[i + 1]);
          return -1;
        }
        strncpy(hostname, argv[i + 1], IP_LEN);
        break;

      case tcpport:
        len = strlen(argv[i + 1]) + 1;
        tcp_port = (char*)malloc(len);
        memset(tcp_port, '\0', len);
        strncpy(tcp_port, argv[i + 1], len);
        break;

      case httpport:
        len = strlen(argv[i + 1]) + 1;
        http_port = (char*)malloc(len);
        memset(http_port, '\0', len);
        strncpy(http_port, argv[i + 1], len);
        break;

      case sslport:
        len = strlen(argv[i + 1]) + 1;
        ssl_port = (char*)malloc(len);
        memset(ssl_port, '\0', len);
        strncpy(ssl_port, argv[i + 1], len);
        break;

      case ingress_list:
        strncpy(ingress, argv[i + 1], PORT_ARG_LEN);
        set_listener_port(INGRESS_TCP, INT_INGRESS_TCP, ingress, listener_ports);
        break;

      case internal_ingress:
        strncpy(int_ingress, argv[i + 1], PORT_ARG_LEN);
        set_listener_port(INT_INGRESS_TCP, EGRESS_TCP, int_ingress, listener_ports);
        break;

      case egress_list:
        strncpy(egress, argv[i + 1], PORT_ARG_LEN);
        set_listener_port(EGRESS_TCP, EGRESS_SSL, egress, listener_ports);
        break;

      case internal_egress:
        strncpy(int_egress, argv[i + 1], PORT_ARG_LEN);
        set_listener_port(INT_EGRESS_TCP, INT_EGRESS_HTTP, int_egress, listener_ports);
        break;

      case pcap:
	set_pcap_config(strncpy(enable_disable, argv[i + 1], ENABLE_DISABLE));
        break;

      default:
        KLOG_WARN(MODULE_KTRACE,"Unknown arg token %d", token);
        break;
    }
  }

  if (token_checks[input_file] && token_checks[interface]) {
    sprintf(err_msg, "Either -i or -r parameter expected, not both");
    return -1;
  }

  if (!(token_checks[input_file] || token_checks[interface])) {
    sprintf(err_msg, "Either -i or -r parameter must be specified.");
    return -1;
  }

  return 0;
}

SESSION_CONTEXT* new_session_context(TcpSession* session, KTRACE_CONFIG_T *ktrace_config) {
  SESSION_CONTEXT* ctx = malloc(sizeof(SESSION_CONTEXT));
  if (ctx) {
    ctx->sess = session;
    ctx->sock = SESSION_CONTEXT_SOCK_NEW;
    ctx->ktrace_config = ktrace_config;
  }
  return ctx;
}

// Wrapper for send that treats partial send as it was timeout error  
ssize_t send_all(int sock, const u_char* payload, size_t len, int flags) {
  // If socket has a timeout set, it's possible that after timeout passes, some
  // bytes were already sent, and thus rc > 0 && rc < len.
  ssize_t rc = send(sock, payload, len, 0);
  KLOG_TRACE(MODULE_KTRACE,"send(%d, <payload>, %lu, %d) == %ld", sock, len, flags, rc);
  if (rc > 0 && rc < len) {
    KLOG_TRACE(MODULE_KTRACE,"treating partial send as timeout");
    rc = -1;
    errno = EWOULDBLOCK;
  }
  return rc;
}

bool send_payload(SESSION_CONTEXT* ctx, const char* prefix, const u_char* pkt_payload, uint32_t pkt_size) {
  int rc = -1;
  char header[HEADER_LEN] = {0};
  size_t header_len = snprintf(header, HEADER_LEN, "%s %d\r\n", prefix, pkt_size);

  KLOG_DEBUG(MODULE_KTRACE,"HEADER : -->%s<-- Sending payload (fd : %d )", header, ctx->sock);
  KLOG_TRACE_BUF(MODULE_KTRACE, "Sending payload data", pkt_payload, pkt_size);

  if( ( rc = send_all(ctx->sock, header, header_len, 0) ) == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      KLOG_DEBUG(MODULE_KTRACE,"send timeout");
      update_stats(STATS_ID_SEND_TIMEOUT, STATS_ACTION_INCREMENT, NULL);
    }
  }

  if( ( rc != -1 ) &&
      ( rc = send_all(ctx->sock, pkt_payload, pkt_size, 0) ) == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      KLOG_DEBUG(MODULE_KTRACE,"send timeout");
      update_stats(STATS_ID_SEND_TIMEOUT, STATS_ACTION_INCREMENT, NULL);    
    }
  }

  KLOG_DEBUG(MODULE_KTRACE,"[%p] Payload sent : status: %s",
           ctx->sess, (( rc == -1) ? "failed" : "successful"));

  return rc != -1;
}

void close_connection(SESSION_CONTEXT* ctx) {
  if (ctx->sock > 0) {
    KLOG_DEBUG(MODULE_KTRACE,"[%p] Closing envoy connection, socket: %d", ctx->sess, ctx->sock);
    close(ctx->sock);
  }
  ctx->sock = SESSION_CONTEXT_SOCK_CLOSED;
}

void ignore_session(SESSION_CONTEXT* ctx) {
  close_connection(ctx);
  KLOG_DEBUG(MODULE_KTRACE,"[%p] Disabling data callback for this libdssl session", ctx->sess);
  // Even though we're disabling the callback,
  // we still need to set the `user_data` as `ctx`,
  // as it may be needed by missing packet callback.
  SessionSetCallback(ctx->sess, NULL, NULL, NULL, ctx);
}

void get_log_string(TcpSession* sess, char* log, size_t size) {
  uint32_t src_ip = ntohl(sess->clientStream.ip_addr);
  uint32_t dst_ip = ntohl(sess->serverStream.ip_addr);

  snprintf(log, size, "Src IP: %d.%d.%d.%d Src Port: %d Dest IP: %d.%d.%d.%d Dest Port: %d",
          ((src_ip >> 24)), ((src_ip >> 16) & 0xFF), ((src_ip >> 8) & 0xFF), (src_ip & 0xFF),
          (int)sess->clientStream.port, ((dst_ip >> 24)), ((dst_ip >> 16) & 0xFF),
          ((dst_ip >> 8) & 0xFF), (dst_ip & 0xFF), (int)sess->serverStream.port);
}

int is_cluster_ip(struct in_addr addr, CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr) {
  struct in_addr net;
  int bits, i;

  //If the addr is present in the except list return true
  for (i = 0; i < no_of_except_cidr; i++) {
    net = except_cidr_list[i].addr;
    bits = except_cidr_list[i].bits;
    if (!((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - bits)))) {
      KLOG_INFO(MODULE_KTRACE,"IP %s in the except list", inet_ntoa(addr));
      return 0;
    }
  }

  for (i = 0; i < no_of_cidr; i++) {
    net = cidr_list[i].addr;
    bits = cidr_list[i].bits;
    if (!((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - bits)))) {
      return 1;
    }
  }
  return 0;
}

int check_ingress_traffic(IP_ENTRY_HASH_T instances_ips_hash_table, IP_ENTRY_HASH_KEY_T* iph, CLUSTER_IP cidr_list[], 
                          int no_of_cidr, CLUSTER_IP cidr_except_list[], int no_of_except_cidr,int dst_port) {

  if (no_of_cidr > 0) {
    if ((is_cluster_ip(iph->addr, cidr_list, no_of_cidr, cidr_except_list, no_of_except_cidr)) && 
        (ingress_port_list[dst_port] >= 1)) {
      return 1;
    }
  }

  if ((instances_ips_hash_table) &&
      (ip_hash_find(instances_ips_hash_table, iph) == IP_HASH_KEY_EXISTS) &&
      (ingress_port_list[dst_port] >= 1)) {
    return 1;
  }
  return 0;
}

int check_external_traffic(IP_ENTRY_HASH_T internal_domain_ips_hash_table, IP_ENTRY_HASH_KEY_T* iph,
                           CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP cidr_except_list[], int no_of_except_cidr, int dst_port) {
  KLOG_INFO(MODULE_KTRACE,"Egress port : %d, No Of internal domain cidr %d ", egress_port_list[dst_port], no_of_cidr );

  /* If cidr and ip both present in INTERNAL DOMAIN we need to add below condition
  int cidr_ext = 0, ip_ext = 0;
  if ( ( cidr_ext && ip_ext ) ||
       ( no_of_cidr == 0 && ip_ext == 1  ) ||
       ( !internal_domain_ips_hash_table && cidr_ext == 1) ||
       ( cidr_ext == 1 && !internal_domain_ips_hash_table && ip_ext == 0 ) ||
       ( no_of_cidr > 0 && cidr_ext == 0 && ip_ext == 1) ) {
    //External return 1;
  }*/

  if (no_of_cidr > 0) {
    if ((!is_cluster_ip(iph->addr, cidr_list, no_of_cidr, cidr_except_list, no_of_except_cidr)) && 
        (egress_port_list[dst_port] >= 1)) {
      return 1;
    }
  }

  if (internal_domain_ips_hash_table) {
    if ((ip_hash_find(internal_domain_ips_hash_table, iph) == IP_HASH_KEY_DOES_NOT_EXISTS) &&
        (egress_port_list[dst_port] >= 1)) {
      return 1;
    }
  }
  return 0;
}

int create_connection(SESSION_CONTEXT* ctx){
  struct sockaddr_in serv_addr;
  int sock = 0, listener_port = 0;
  uint32_t dst_ip = ctx->sess->serverStream.ip_addr;
  int dst_port = (int)ctx->sess->serverStream.port;

  IP_ENTRY_HASH_KEY_T iph_key;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    KLOG_ERR(MODULE_KTRACE,"Socket creation error.");
    return -1;
  }
 
  struct timeval timeout;      
  timeout.tv_sec = SOCK_TIMEOUT;
  timeout.tv_usec = 0;
  
  if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
              sizeof(timeout)) < 0) {
    KLOG_ERR(MODULE_KTRACE,"setsockopt failed\n");
    return -1;
  }

  memset(&iph_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));
  iph_key.addr.s_addr = dst_ip;
  
  KLOG_INFO(MODULE_KTRACE,"Destination ip : %s", inet_ntoa(iph_key.addr) );

  if (strcasecmp(deployment_type, DAEMONSET) == 0 || strcasecmp(deployment_type, VPCMIRRORING) == 0 ) {
    KLOG_INFO(MODULE_KTRACE,"-----------> %s DEPLOYMENT <-----------", deployment_type);
    if (ctx->ktrace_config->standalone_mode == 1) {
      listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->ingress_ports[dst_port]];;
      KLOG_INFO(MODULE_KTRACE,"Instance ip not set, sending to ingress listener %d", listener_port);
    } else {
      if ( ctx->ktrace_config->no_of_internal_domain_cidr > 0 && 
         (!is_cluster_ip(iph_key.addr, ctx->ktrace_config->internal_domain_cidr_list, ctx->ktrace_config->no_of_internal_domain_cidr,
                         ctx->ktrace_config->internal_domain_cidr_except_list, ctx->ktrace_config->no_of_internal_domain_except_cidr) ) ) {
        if ((egress_port_list[dst_port] == 1)) {
          listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->egress_ports[dst_port]];
        } else {
          KLOG_INFO(MODULE_KTRACE,"Dropping Traffic. Dest port %d not in the list of EGRESS ports", dst_port);
          return -1;
        }
      } else {
        if((ingress_port_list[dst_port] == 1)){
          listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->ingress_ports[dst_port]];;
        } else {
          KLOG_INFO(MODULE_KTRACE,"Dropping Traffic. Dest port %d not in the list of INGRESS ports", dst_port);
          return -1;
        }
      }
    }
  } else {
    if (ctx->ktrace_config->standalone_mode == 1) {
      listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->ingress_ports[dst_port]];
      KLOG_INFO(MODULE_KTRACE,"Instance ip not set, sending to ingress listener.");
    } else {
      if (check_ingress_traffic(ctx->ktrace_config->instances_ips_hash_table, &iph_key, ctx->ktrace_config->instance_ip_cidr_list, 
                                ctx->ktrace_config->no_of_instance_ip_cidr, ctx->ktrace_config->instance_ip_except_cidr_list,
                                ctx->ktrace_config->no_of_internal_domain_except_cidr, dst_port)) {
        KLOG_INFO(MODULE_KTRACE,"Ingress Traffic.");
	if( ingress_port_list[dst_port] != 2 ) {
          listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->ingress_ports[dst_port]];
	} else {
	  KLOG_DEBUG(MODULE_KTRACE,"Port : %d is excluded.", dst_port);
          return -1;
        }
      } else if (ctx->ktrace_config->no_of_internal_domain_cidr > 0 || ctx->ktrace_config->internal_domain_ips_hash_table) {

        if (check_external_traffic(ctx->ktrace_config->internal_domain_ips_hash_table, &iph_key, ctx->ktrace_config->internal_domain_cidr_list, 
                                   ctx->ktrace_config->no_of_internal_domain_cidr, ctx->ktrace_config->internal_domain_cidr_except_list,
                                   ctx->ktrace_config->no_of_internal_domain_except_cidr ,dst_port)) {
          KLOG_INFO(MODULE_KTRACE,"IP not in the internal domain list --> Egress Traffic.");
	  if( egress_port_list[dst_port] != 2 ) {
            listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->egress_ports[dst_port]];
	  } else {
	    KLOG_DEBUG(MODULE_KTRACE,"Port : %d is excluded.", dst_port);
            return -1;
	  }
        } else {
          close(sock);
          KLOG_INFO(MODULE_KTRACE,"IP is in the internal domain list, Internal traffic. Dropping Packet.");
          return -1;
        }
      } else {
        KLOG_INFO(MODULE_KTRACE,"CIDR list empty. Egress Traffic.");
        if( egress_port_list[dst_port] == 1) {
          listener_port = ctx->ktrace_config->listener_ports[ctx->ktrace_config->egress_ports[dst_port]];
        } else {
          KLOG_INFO(MODULE_KTRACE,"Egress port not set. Dropping Packet.");
          return -1;
        }
      }
    }
  }

  KLOG_DEBUG(MODULE_KTRACE,"Connecting to Listener Port : %d", listener_port);

  if (listener_port == 0) {
    KLOG_DEBUG(MODULE_KTRACE,"Listener port is : %d", listener_port);
    return -1;
  }

  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(listener_port);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, args.envoy_ip, &serv_addr.sin_addr) <= 0) {
    close(sock);
    KLOG_ERR(MODULE_KTRACE,"Invalid address/ Address not supported.");
    return -1;
  }

  if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    close(sock);
    update_stats(STATS_ID_ENVOY_CONNECTION_FAIL, STATS_ACTION_INCREMENT, NULL); 
    KLOG_ERR(MODULE_KTRACE,"Connection Failed");
    return -1;
  }

  return sock;
}

int set_port_info(int from, int to, char* str, int* total_no_of_ports, int* no_of_ingress_ports,
                  int* no_of_egress_ports, int* ingress_ports, int* egress_ports,
                  int* ports_for_exper, int* ingress_wildcard, int* egress_wildcard,
                  char port_range_for_expr[][20], int* no_of_port_range) {
  char *from_port, *to_port;
  char* s = strchr(str, '#');
  char* p = NULL;
  char* range_str = NULL;
  int port, no_of_pr_port = 0;

  char *end_str, *end_tok;

  if (s == NULL) {
    return FALSE;
  }

  int from_port_len = 0, to_port_len = 0;
  from_port_len = (s - str);
  to_port_len = (strlen(str) - (s + 1 - str));
  from_port = (char*)malloc(from_port_len + 1);
  to_port = (char*)malloc(to_port_len + 1);

  memset(from_port, '\0', from_port_len + 1);
  memset(to_port, '\0', to_port_len + 1);
  strncpy(from_port, str, from_port_len);
  strncpy(to_port, s + 1, to_port_len);

  int  i = 0, range_from = 0, range_to = 0 ;
  if (from != NONE) {
    p = strtok_r(from_port, ",", &end_str);
    while (p != NULL) {
      i = 0;
      char tmp[512] = "\0";
      snprintf(tmp, 512, "%s", p );
      range_str = strchr(p, '-');
      KLOG_DEBUG(MODULE_KTRACE,"Range : %s", p);    
      if( range_str ) {
         //Expected format "<port>-<port>"
          no_of_pr_port = sscanf(p, "%d-%d", &range_from, &range_to); 

          if (!IS_VALID_PORT(range_from) || !IS_VALID_PORT(range_to)) {
             KLOG_CRIT(MODULE_KTRACE,"Invalid port number in port range : %s ", range_str);
             p = strtok_r(NULL, ",", &end_str);
             continue;
          }

          if ( no_of_pr_port == 2 ){
            KLOG_DEBUG(MODULE_KTRACE,"Setting Port range : %d - %d", range_from, range_to);
            for( ; range_from <= range_to ; range_from++ ) {
              ingress_ports[range_from] = from;
              ingress_port_list[range_from] = 1;
            }
          } else {
            KLOG_CRIT(MODULE_KTRACE,"Invalid port number in port range");
            p = strtok_r(NULL, ",", &end_str);
             continue;
          }

          if( no_of_ingress_ports != NULL ) {
            (*no_of_ingress_ports)++;
          }

          strcpy(port_range_for_expr[(*no_of_port_range)++] ,  tmp) ;
      } else {
        KLOG_DEBUG(MODULE_KTRACE,"spilt str : in else : %s", p);
        port = atoi(p);
        if ( (strcmp(p, WILDCARD_PORT) != 0) && !IS_VALID_PORT(port)) {
          KLOG_CRIT(MODULE_KTRACE,"Invalid port number : %d", port);
          p = strtok_r(NULL, ",", &end_str);
          continue;
        }

        if ((strcmp(p, WILDCARD_PORT) == 0)) {
          if( ingress_wildcard != NULL ) { 
            *ingress_wildcard = 1;
          } else {
            KLOG_CRIT(MODULE_KTRACE,"Invalid wildcard.");
            p = strtok_r(NULL, ",", &end_str);
            continue;
          }
        } else if (port != 0) {
          ports_for_exper[(*total_no_of_ports)++] = port;
          ingress_ports[port] = from; // Ingress port and listener mapping
          ingress_port_list[port] = 1; // Ingress port 
          if( no_of_ingress_ports != NULL ) {
            (*no_of_ingress_ports)++;
          }
        }
      }
      p = strtok_r(NULL, ",", &end_str);
    }
  }

  if (to != NONE) {
    p = strtok_r(to_port, ",", &end_str);

    while (p != NULL) {
      i = 0;
      char tmp[512] = "\0";
      snprintf(tmp, 512, "%s", p );
      range_str = strchr(p, '-');
      if( range_str ) {
          no_of_pr_port = sscanf(p, "%d-%d", &range_from, &range_to);

          if (!IS_VALID_PORT(range_from) || !IS_VALID_PORT(range_to)) {
             KLOG_CRIT(MODULE_KTRACE,"Invalid port number in port range");
             p = strtok_r(NULL, ",", &end_str);
             continue;
          }

          if ( no_of_pr_port == 2 ){
            KLOG_DEBUG(MODULE_KTRACE,"Setting Port range : %d - %d", range_from, range_to);
            for( ; range_from <= range_to ; range_from++ ) {
              egress_ports[range_from] = to;
              egress_port_list[range_from] = 1;
            }
          } else {
            KLOG_CRIT(MODULE_KTRACE,"Invalid port number in port range");
            p = strtok_r(NULL, ",", &end_str);
            continue;
          }

          if( no_of_egress_ports != NULL ) {
            (*no_of_egress_ports)++;
          }
          strcpy(port_range_for_expr[(*no_of_port_range)++] ,  tmp) ;

      } else {
      port = atoi(p);
      if ( (strcmp(p, WILDCARD_PORT) != 0) && !IS_VALID_PORT(port)) {
        KLOG_CRIT(MODULE_KTRACE,"Invalid port number : %d", port);
          p = strtok_r(NULL, ",", &end_str);
          continue;
      }

      if ((strcmp(p, WILDCARD_PORT) == 0)) {
        if( egress_wildcard != NULL ) { 
          *egress_wildcard = 1;
        } else {
          KLOG_CRIT(MODULE_KTRACE,"Invalid wildcard. Exiting");
          p = strtok_r(NULL, ",", &end_str);
          continue;
        }
      } else if (port != 0) {
        ports_for_exper[(*total_no_of_ports)++] = port;
        egress_ports[port] = to;
        egress_port_list[port] = 1;
        if( no_of_egress_ports != NULL ) {
          (*no_of_egress_ports)++;
        }
      }
    }
      p = strtok_r(NULL, ",", &end_str);
    }
  }

  free(from_port);
  free(to_port);
  return TRUE;
}

int set_portdetails(int* ingress, int* egress, int* ports_for_exper, int* ingress_wildcard,
                    int* egress_wildcard, int standalone_mode, char port_range_for_expr[][20], 
                    int *no_of_port_range, KTRACE_CONFIG_T *ktrace_config) {
  int no_of_ports = 0;
  int no_of_ingress_port = 0, no_of_egress_port = 0;
  int use_default_http_port = true;
   
  ingress_port_list = (int*)calloc(PORT_ARG_LEN, sizeof(int));
  egress_port_list = (int*)calloc(PORT_ARG_LEN, sizeof(int));

  // 6395,6349#6345,6346
  if (standalone_mode == 0) {
    if ((!set_port_info(TCP_FROM, TCP_TO, tcp_port, &no_of_ports, NULL, NULL, 
                        ingress, egress, ports_for_exper, ingress_wildcard, egress_wildcard, port_range_for_expr, no_of_port_range)) ||
        (!set_port_info(HTTP_FROM, HTTP_TO, http_port, &no_of_ports, &no_of_ingress_port, &no_of_egress_port, 
                        ingress, egress, ports_for_exper, NULL, NULL, port_range_for_expr, no_of_port_range )) ||
        (!set_port_info(SSL_FROM, NONE, ssl_port, &no_of_ports, NULL, NULL, 
                        ingress, egress, ports_for_exper, NULL, NULL, port_range_for_expr, no_of_port_range ))) {
      return -1;
    }
  } else {
    if ((!set_port_info(TCP_FROM, TCP_FROM, tcp_port, &no_of_ports, NULL, NULL,
                        ingress, ingress, ports_for_exper, ingress_wildcard, egress_wildcard, port_range_for_expr, no_of_port_range)) ||
        (!set_port_info(HTTP_FROM, HTTP_FROM, http_port, &no_of_ports, &no_of_ingress_port, &no_of_egress_port,
                        ingress, ingress, ports_for_exper, NULL, NULL, port_range_for_expr, no_of_port_range )) ||
        (!set_port_info(SSL_FROM, NONE, ssl_port, &no_of_ports, NULL, NULL,
                        ingress, ingress, ports_for_exper, NULL, NULL, port_range_for_expr, no_of_port_range ))) {
      return -1;
    }
  }

  KLOG_INFO(MODULE_KTRACE,"No Of Ports : %d No of http ingress ports : %d , No of http egress ports : %d", no_of_ports, no_of_ingress_port, no_of_egress_port);


  char *tenv = NULL;
  tenv = getenv("USE_DEFAULT_HTTP_PORT");
  if ( tenv && ( strcasecmp(tenv, "false") == 0 ) ) {
    use_default_http_port = false;
  }

  KLOG_INFO(MODULE_KTRACE,"Use Default : %d", use_default_http_port );

  //Missing HTTP ports is equal to Port 80 in HTTP.
  if( no_of_ingress_port == 0 && use_default_http_port == true ) {
    KLOG_INFO(MODULE_KTRACE,"Ingress HTTP port not availble, enabling 80.");
    ingress[80] = HTTP_FROM;
    ingress_port_list[80] = 1;
    ports_for_exper[no_of_ports++] = 80;
  }

  if ( no_of_egress_port == 0 && use_default_http_port == true ) {
    KLOG_INFO(MODULE_KTRACE,"Egress HTTP port not availble, enabling 80.");
    egress[80] = HTTP_TO;
    egress_port_list[80] = 1;
    ports_for_exper[no_of_ports++] = 80;
  }

  if(*ingress_wildcard) {
    KLOG_DEBUG(MODULE_KTRACE,"Ingress Wildcard received.");
    for (int i = 0; i < PORT_ARG_LEN; i++) {
      ingress_port_list[i] = 1;
    }
  }

  if(*egress_wildcard) {
    KLOG_DEBUG(MODULE_KTRACE,"Egress Wildcard received.");
    for (int i = 0; i < PORT_ARG_LEN; i++) {
      egress_port_list[i] = 1;
    }

  }

  KLOG_DEBUG(MODULE_KTRACE,"Setting exclude ports for ingress list" );
  for (int i = 0; i < ktrace_config->no_of_exclude_ingress_ports; i++) {
    KLOG_INFO(MODULE_KTRACE,"Exclude Ingress : %d", ktrace_config->exclude_ingress_ports[i] );
    ingress_port_list[ktrace_config->exclude_ingress_ports[i]] = 2;
  }

  KLOG_DEBUG(MODULE_KTRACE,"Setting exclude ports for egress list.");
  for (int i = 0; i < ktrace_config->no_of_exclude_egress_ports; i++) {
    KLOG_INFO(MODULE_KTRACE,"Exclude egress : %d", ktrace_config->exclude_egress_ports[i] );
    egress_port_list[ktrace_config->exclude_egress_ports[i]] = 2;
  }

  return no_of_ports;
}

char* get_port() { return ssl_port; }

int execute_command(const char *cmd, char *out_buff, size_t out_buff_len)
{
    FILE* file = NULL;
    int status = -1;
    size_t offset = 0;
    char buff[4096] = {0,};

    if ( ( !cmd ) ||
         ( *cmd == '\0' ) ||
         ( !out_buff ) ||
         ( out_buff_len <= 2 ) ) {
        return -1;
    }

    file = popen(cmd, "r");

    if ( file ) {
        while ( fgets(buff, sizeof(buff) - 1, file) != NULL ) {
            if ( offset >= out_buff_len ) { break; }
            offset += snprintf(out_buff + offset, out_buff_len - offset, "%s", buff); 
        }

        status = pclose(file);
    }

    return  WEXITSTATUS(status);
}
