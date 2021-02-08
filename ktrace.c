#include "ktrace.h"
#include "log.h"
#include "ktrace_utils.h"
#include "stats.h"
#include "dns_discovery.h"
#include "telemetry.h"
#include "spurious_activity.h"

#include <assert.h>

#include <sys/mman.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>

#define MISSING_PACKET_COUNT 100
#define MISSING_PACKET_TIMEOUT 10
#define PCAP_STAT_FREQ 30

static const char IIP[] = "INSTANCE_IP";
static const char HOST_CIDR[] = "HOST_CIDR";
static const char POD_CIDR[] = "POD_CIDR";
static const char SERVICE_CIDR[] = "SERVICE_CIDR";
static const char HOST_IP[] = "HOST_IP";

static const char MODULE_KTRACE_STR[] = "ktrace";
static const char MODULE_DNS_STR[] = "dns";

static const char LOG_INFO_STR[] = "info";
static const char LOG_WARN_STR[] = "warn";
static const char LOG_ERROR_STR[] = "error";
static const char LOG_CRIT_STR[] = "critical";
static const char LOG_DEBUG_STR[] = "debug";
static const char LOG_TRACE_STR[] = "trace";

// Global Variables
IP_ENTRY_HASH_T internal_domain_ips_hash_table = NULL;
char err_msg[ERR_MSG];
static char hostname[IP_LEN];
static int ingress_wildcard, egress_wildcard;
static char* ip_str_list[MAX_INTERFACE] = {0};
static int ports_for_exper[PORT_ARG_LEN];
static int no_of_ports, no_of_mesh7_ports, max_buff_len;
static int no_of_instance_ip = 0;
static char port_range_for_expr[512][20];
static int no_of_port_range;
static time_t stat_prev_time;
static pcap_t* pcap_handle = NULL;
static struct bpf_program filter;

KTRACE_CONFIG_T ktrace_config;

static int enable_dns_telemetry = false;
static char host_ip[IP_LEN] = {0,};
static char hostInterfaceIPs[1024] = {0,};
static int event_listener_port = 0;
static int monitor_tcp_syn_attack = false;

CLUSTER_IP *service_cidr_list;
CLUSTER_IP *pod_cidr_list;
CLUSTER_IP *host_cidr_list;

CLUSTER_IP *service_cidr_except_list;
CLUSTER_IP *pod_cidr_except_list;
CLUSTER_IP *host_cidr_except_list;

static int no_of_service_cidr = 0;
static int no_of_pod_cidr = 0;
static int no_of_host_cidr = 0;

static int no_of_service_except_cidr = 0;
static int no_of_pod_except_cidr = 0;
static int no_of_host_except_cidr = 0;

static struct in_addr host_ip_addr;
char *deployment_type = "";

static MonitorSpActivityConf monitor_sp_activity_conf;

void clean_up(int signum) {
  shm_unlink(KAVACH_STATS_SHM_NAME);
  pcap_breakloop(pcap_handle);
}

/* TBD : update_pcap_stat shouldn't be called in ktrace_pkt_processor,
        A new thread (stats) should be created and update_pcap_stat
        should be called in this thread*/
int update_pcap_stat() {
  struct pcap_stat pc_stat;
  uint32_t embryonic_conn_queue_size = 0;
  uint32_t embryonic_conn_hash_table_size = 0;
  uint32_t num_of_embryonic_conn_detected = 0;
  time_t diff = 0;
  time_t stat_cur_time;
  stat_cur_time = time(NULL);
  diff = stat_cur_time - stat_prev_time;
  if (diff >= PCAP_STAT_FREQ) {
    stat_prev_time = stat_cur_time;
    if (pcap_stats(pcap_handle, &pc_stat) == -1) {
      fprintf(stderr, "Error collecting stats\n");
      return -1;
    }
    update_stats(STATS_ID_PCAP_STATS, STATS_ACTION_SET, &pc_stat);

    if ( monitor_tcp_syn_attack == true ) {
      embryonic_conn_queue_size = GetEmbryonicConnectionQueueSize();
      embryonic_conn_hash_table_size = GetEmbryonicConnectionHashTableSize();
      num_of_embryonic_conn_detected = GetNumberOfEmbryonicConnectionDetected();

      update_stats(STATS_ID_EMBRYONIC_CONN_QUEUE_SIZE, STATS_ACTION_SET, &embryonic_conn_queue_size);
      update_stats(STATS_ID_EMBRYONIC_CONN_HASH_TABLE_SIZE, STATS_ACTION_SET, &embryonic_conn_hash_table_size);
      update_stats(STATS_ID_NUM_OF_EMBRYONIC_CONN_DETECTED, STATS_ACTION_SET, &num_of_embryonic_conn_detected);
    }
  }
  return 1;
}

char* get_host_ip(void) {
  return host_ip;
}

void get_log_level(char* val, int* loglevel) {
  if (strcasecmp(val, LOG_TRACE_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_TRACE_STR);
    *loglevel = LOG_TRACE;
  } else if (strcasecmp(val, LOG_DEBUG_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_DEBUG_STR);
    *loglevel = LOG_DEBUG;
  } else if (strcasecmp(val, LOG_INFO_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_INFO_STR);
    *loglevel = LOG_INFO;
  } else if (strcasecmp(val, LOG_WARN_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_WARN_STR);
    *loglevel = LOG_WARN;
  } else if (strcasecmp(val, LOG_ERROR_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_ERROR_STR);
    *loglevel = LOG_ERROR;
  } else if (strcasecmp(val, LOG_CRIT_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_CRIT_STR);
    *loglevel = LOG_CRIT;
  } else {
    KLOG_INFO(MODULE_KTRACE,"Log level set to %s", LOG_CRIT_STR);
    *loglevel = LOG_CRIT;
  }
}

void get_log_module( char* val, int* log_module) {
  if( val == NULL ){
    KLOG_INFO(MODULE_KTRACE, "Module set to : %s", "All");
    *log_module = MODULE_ALL;
    return;
  }

  if(strcasecmp(val, MODULE_DNS_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE, "Module set to : %s", MODULE_DNS_STR);
    *log_module = MODULE_DNS;
  } else if(strcasecmp(val, MODULE_KTRACE_STR) == 0) {
    KLOG_INFO(MODULE_KTRACE, "Module set to : %s", MODULE_KTRACE_STR);
    *log_module = MODULE_KTRACE;
  } else {
    KLOG_INFO(MODULE_KTRACE, "Module set to : %s", "All");
    *log_module = MODULE_ALL;
  }
}

int get_list_size(char *str) {
  int i = 0;
  char *ip = NULL;
  ip = strtok(str, ",");
  while (ip != NULL) {
    i++;
    ip = strtok(NULL, ",");
  }

  return i;
}

int get_ip(char *ip, struct in_addr *addr, int *cidr) {
  int iplen = 0, bitlen = 0;
  char ip_addr[20], bit[4];
  char *b = NULL;

  memset(ip_addr, '\0', sizeof(ip_addr));
  memset(bit, '\0', sizeof(bit));

  if ( (!ip) || (!addr) ) {
    return -1;
  } 

  b = strchr(ip, '/');
  if (b == NULL) {
    if (inet_aton(ip, addr) == 0) {
      return -1;
    }
  } else {
    bitlen = (strlen(ip) - (b + 1 - ip));
    if (bitlen == 0) {
      return -1;
    }
    iplen = (b - ip);
    strncpy(bit, b + 1, bitlen);

    if( atoi(bit) <= 0 && atoi(bit) > 32 ) {
      KLOG_ERR(MODULE_KTRACE,"Invalid Bit length : %s", ip );
      return -1;
    }

    strncpy(ip_addr, ip, iplen);

    if (inet_aton(ip_addr, addr) == 0 ) {
      return -1;
    }

    if ( cidr ) {
      *cidr = atoi(bit);
    }
  }
  return 0;
}

/*
int set_internal_domain() {
  char* ip = NULL;
  IP_ENTRY_HASH_KEY_T i_key;
  char ip_addr[20], bit[4];
  int iplen = 0, bitlen = 0, i = 0, cidr_bit = 0;
  char* default_str = "";
  char* int_ip_list = default_str;
  char* env_internal_domain = default_str;

  memset(ip_addr, '\0', sizeof(ip_addr));
  memset(bit, '\0', sizeof(bit));

  env_internal_domain  = getenv("KTRACE_INTERNAL_DOMAIN");

  if (env_internal_domain) {
    int_ip_list = strdup(env_internal_domain);
  }

  KLOG_INFO(MODULE_KTRACE,"Ktrace Internal Domain List : %s",
           (int_ip_list == NULL) ? "KTRACE_INTERNAL_DOMAIN environment variable not found." : int_ip_list);

  ip = strtok(int_ip_list, ",");

  while (ip != NULL) {
    memset(ip_addr, '\0', sizeof(ip_addr));
    memset(bit, '\0', sizeof(bit));
    char* b = strchr(ip, '/');

    if (b == NULL) {
      memset(&i_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));

      if( get_ip(ip, &i_key.addr, &cidr_bit) == -1) {
        KLOG_ERR(MODULE_KTRACE,"Invalid domain IP : %s", ip);
        ip = strtok(NULL, ",");
        continue;
      }
      ip_hash_add(&ktrace_config.internal_domain_ips_hash_table, &i_key);
    } else {
      if( get_ip(ip, &ktrace_config.cidr_list[ktrace_config.no_of_cidr].addr, &cidr_bit) == -1) {
        KLOG_ERR(MODULE_KTRACE,"Invalid domain cidr : %s", ip);
        ip = strtok(NULL, ",");
        continue;
      }
      ktrace_config.cidr_list[ktrace_config.no_of_cidr].bits = cidr_bit;
      KLOG_INFO(MODULE_KTRACE,"CIDR : %d",ktrace_config.cidr_list[ktrace_config.no_of_cidr].bits);
      ktrace_config.no_of_cidr++;
    }
    ip = strtok(NULL, ",");
  }
  return 1;
}
*/

int set_cidr_list( const char env_var[], CLUSTER_IP **cidr_list, int *no_of_cidr) {
  char* ip = NULL;
  IP_ENTRY_HASH_KEY_T i_key;
  char ip_addr[20], bit[4];
  int iplen, bitlen, i = 0, size = 0;
  char* default_str = "";
  char* int_ip_list = default_str;
  char* env_cidr_list = default_str;

  char* c_list = default_str;

  memset(ip_addr, '\0', sizeof(ip_addr));
  memset(bit, '\0', sizeof(bit));

  KLOG_INFO(MODULE_KTRACE,"Reading env variable %s", env_var);
  env_cidr_list  = getenv(env_var);

  if (env_cidr_list) {
    int_ip_list = strdup(env_cidr_list);
    c_list = strdup(env_cidr_list);
  }

  KLOG_INFO(MODULE_KTRACE,"Value : %s", int_ip_list);
  size = get_list_size(c_list); 
  KLOG_INFO(MODULE_KTRACE,"List size : %d", size);
  size+=10;
  *cidr_list = (CLUSTER_IP *) calloc ( size,  sizeof(CLUSTER_IP) ) ; 

  ip = strtok(int_ip_list, ",");
  while (ip != NULL) {
    memset(ip_addr, '\0', sizeof(ip_addr));
    memset(bit, '\0', sizeof(bit));
    char* b = strchr(ip, '/');

    if(b == NULL) {
      KLOG_CRIT(MODULE_KTRACE,"Invalid cidr IP : %s", ip);
      ip = strtok(NULL, ",");
      continue;
    }

    bitlen = (strlen(ip) - (b + 1 - ip));

    if (bitlen == 0) {
      KLOG_CRIT(MODULE_KTRACE,"Invalid cidr.");
      ip = strtok(NULL, ",");
      continue;
    }

    iplen = (b - ip);
    strncpy(bit, b + 1, bitlen);

    if( atoi(bit) > 32 ) {
      KLOG_ERR(MODULE_KTRACE,"Invalid Bit length : %s", ip );
      ip = strtok(NULL, ",");
      continue;
    }

    strncpy(ip_addr, ip, iplen);

    if (inet_aton(ip_addr, &(*cidr_list)[i].addr) == 0) {
      KLOG_CRIT(MODULE_KTRACE,"Invalid cidr IP : %s", ip);
      ip = strtok(NULL, ",");
      continue;
    }
    (*cidr_list)[i].bits = atoi(bit);
    i++;
    ip = strtok(NULL, ",");
  }
  *no_of_cidr = i;

  KLOG_INFO(MODULE_KTRACE,"Number of cidr : %d ",*no_of_cidr);
  return 1;
}


int set_instance_ip() {
  char* ip = NULL;
  IP_ENTRY_HASH_KEY_T i_key;
  int cidr, i = 0;
  char* default_str = "";
  char* inst_str = default_str;
  char* env_inst_ip = default_str;

  env_inst_ip = getenv("INSTANCE_IP");
  if (env_inst_ip) {
    inst_str = strdup(env_inst_ip);
    snprintf(host_ip, sizeof(host_ip), "%s", env_inst_ip);
  }
  KLOG_INFO(MODULE_KTRACE,"Instance IP List : %s",
           (inst_str == NULL) ? "INSTANCE_IP environment variable not found." : inst_str);

  if (inst_str == NULL || strlen(inst_str) == 0) {
    KLOG_CRIT(MODULE_KTRACE,"INSTANCE_IP environment variable not found.");
    KLOG_ERR(MODULE_KTRACE,"*******************Standalone Mode.*******************");
    ktrace_config.standalone_mode = 1;
  }

  ip = strtok(inst_str, ",");

  while (ip != NULL) {
    
    char* b = strchr(ip, '/');
    if (b == NULL) {
      memset(&i_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));

      if( get_ip(ip, &i_key.addr, &cidr) == -1) {
        KLOG_ERR(MODULE_KTRACE,"Invalid INSTANCE_IP : %s", ip);
        ip = strtok(NULL, ",");
        continue;
      }
      ip_str_list[i] = (char*)calloc(IP_LEN, sizeof(char));
      strncpy(ip_str_list[i++], ip, IP_LEN);
      ip_hash_add(&ktrace_config.instances_ips_hash_table, &i_key);
      no_of_instance_ip++;
    } else {
      if( get_ip(ip, &ktrace_config.instance_ip_cidr_list[ktrace_config.no_of_instance_ip_cidr].addr, &cidr) == -1) {
        KLOG_ERR(MODULE_KTRACE,"Invalid INSTANCE_IP cidr : %s", ip);
        ip = strtok(NULL, ",");
        continue;
      }
      ktrace_config.instance_ip_cidr_list[ktrace_config.no_of_instance_ip_cidr].bits = cidr;
      KLOG_INFO(MODULE_KTRACE,"CIDR : %d",ktrace_config.instance_ip_cidr_list[ktrace_config.no_of_instance_ip_cidr].bits);

      ip_str_list[i] = (char*)calloc(IP_LEN, sizeof(char));
      strncpy(ip_str_list[i++], ip, IP_LEN);
      ktrace_config.no_of_instance_ip_cidr++;
    }
    ip = strtok(NULL, ",");
  }
  KLOG_INFO(MODULE_KTRACE,"Number of Instance Ip : %d", no_of_instance_ip);
  KLOG_INFO(MODULE_KTRACE,"Number of Instance Ip CIDR : %d", ktrace_config.no_of_instance_ip_cidr);
  return 1;
}

void set_exclude_ports( const char env_var[], int* ports, int* no_of_ports) {
  char* ports_str = "";
  char* port_list = "";
  char* p = "";
  int i = 0, port = 0;
  ports_str  = getenv(env_var);

  if (ports_str) {
    port_list = strdup(ports_str);
  } 

  KLOG_INFO(MODULE_KTRACE,"Exclude ports : %s",(port_list == NULL) ? "Env not found." : port_list);

  if (port_list == NULL || strlen(port_list) == 0) {
    return ;
  }

  p = strtok(port_list, ",");
  while (p != NULL) {
    port = atoi(p);
    if (!IS_VALID_PORT(port)) {
      KLOG_CRIT(MODULE_KTRACE,"Invalid port number : %d", port);
      p = strtok(NULL, ",");
      continue;
    }
 
    ports[i++] = port;
    p = strtok(NULL, ",");
  }

  *no_of_ports = i;
}

void set_host_ip() {
  char* hostip = "";
  hostip = getenv("HOST_IP");

  KLOG_INFO(MODULE_KTRACE,"HOST IP : %s", (hostip == NULL) ? "HOST IP not found." : hostip);

  if (hostip) {
    host_ip_addr.s_addr = inet_addr(hostip);
  } else {
    host_ip_addr.s_addr = 0;
  }
}

int is_in_ip_list( struct in_addr addr, const char *list_name) {
  IP_ENTRY_HASH_KEY_T iph_key;
  memset(&iph_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));
  iph_key.addr.s_addr = addr.s_addr;

  if(strcmp(list_name, IIP) == 0) {
    if ((ktrace_config.instances_ips_hash_table) &&
       (ip_hash_find(ktrace_config.instances_ips_hash_table, &iph_key) == IP_HASH_KEY_EXISTS)) {
      KLOG_TRACE(MODULE_KTRACE,"%s in %s", inet_ntoa(addr), list_name);
      return 1;
    }
    return 0;
  } 

  if (strcmp(list_name, "HOST_IP") == 0 ) {
    if(addr.s_addr == host_ip_addr.s_addr){
      KLOG_TRACE(MODULE_KTRACE,"%s is in HOST_IP", inet_ntoa(addr));
      return 1;
    }
    return 0;
  }
}

int is_in_cidr_list( struct in_addr addr, const char *list_name ) {

  if( strcmp( list_name, POD_CIDR) == 0 ) {
    if ( is_cluster_ip( addr, pod_cidr_list, no_of_pod_cidr,
                        pod_cidr_except_list, no_of_pod_except_cidr) ){
      return 1;
    }
    return 0;
  } 

  if( strcmp( list_name, HOST_CIDR) == 0 ) {
    if ( is_cluster_ip( addr, host_cidr_list, no_of_host_cidr,
                        host_cidr_except_list, no_of_host_except_cidr) ){
      return 1;
    }
    return 0;
  }  

  if( strcmp( list_name, SERVICE_CIDR) == 0 ) {
    if ( is_cluster_ip( addr, service_cidr_list, no_of_service_cidr,
                        service_cidr_except_list, no_of_host_except_cidr) ){
      return 1;
    }
    return 0;
  }  

}

int syn_work_flow( struct in_addr srcip, struct in_addr dstip) {

  KLOG_TRACE(MODULE_KTRACE,"-- SYN WORKFLOW -- Src : %d -- Dst : %d", srcip, dstip);
  KLOG_TRACE(MODULE_KTRACE,"src ip : %s ", inet_ntoa(srcip));
  KLOG_TRACE(MODULE_KTRACE,"dst ip : %s", inet_ntoa(dstip));

  if( ( is_in_ip_list( dstip, IIP) ) || ( is_in_ip_list( dstip, HOST_IP) ) ) {
    if( is_in_cidr_list(srcip, POD_CIDR ) ) {
      KLOG_TRACE(MODULE_KTRACE,"[ACCEPT] src ip %s is in %s", inet_ntoa(srcip), POD_CIDR);
      return 1;
    } else if( is_in_ip_list( srcip, HOST_IP)){
      KLOG_TRACE(MODULE_KTRACE,"[ACCEPT] src ip %s is in %s", inet_ntoa(srcip), HOST_IP);
      return 1;
    } else if( is_in_cidr_list(srcip, HOST_CIDR )) {
      KLOG_TRACE(MODULE_KTRACE,"[DROP] src ip %s is in %s", inet_ntoa(srcip), HOST_CIDR);
      return 0;
    } else {
      KLOG_TRACE(MODULE_KTRACE,"[ACCEPT] src ip %s is not in %s, %s, %s", inet_ntoa(srcip), POD_CIDR, HOST_IP, HOST_CIDR);
      return 1;
    }
  } else {
    KLOG_DEBUG(MODULE_KTRACE,"Dest ip : %s not  in %s or %s", inet_ntoa(dstip) , IIP, HOST_IP);
    //Handle SNAT condition
    if(0){
      return 1;
    } else if ( is_in_cidr_list(dstip, HOST_CIDR )) {
      KLOG_TRACE(MODULE_KTRACE,"[ACCEPT] dst ip %s is in %s", inet_ntoa(dstip), HOST_CIDR);
      return 1;
    } else if( (is_in_cidr_list(dstip, POD_CIDR )) || ( is_in_cidr_list(dstip, SERVICE_CIDR)) ) {
      KLOG_TRACE(MODULE_KTRACE,"[DROP] dst ip %s is in %s or %s", inet_ntoa(dstip), POD_CIDR, SERVICE_CIDR);
      return 0;
    } else {
      KLOG_TRACE(MODULE_KTRACE,"[ACCEPT] dst ip %s is not in %s, %s, %s", inet_ntoa(dstip), POD_CIDR, HOST_IP, SERVICE_CIDR);
      return 1;
    }
  }
}

int mirroring_callback(struct in_addr addr) {
  if( ! is_cluster_ip( addr, ktrace_config.internal_domain_cidr_list, ktrace_config.no_of_internal_domain_cidr,
                             ktrace_config.internal_domain_cidr_except_list, ktrace_config.no_of_internal_domain_except_cidr) ) {
    return 1;
  } else {
    return 0;
  }
}

int inspect_ssl_traffic_callback(CapEnv* env,
                       struct in_addr* src_ip, uint16_t src_port,
                       struct in_addr* dst_ip, uint16_t dst_port) {
  int egress_traffic = 0;
  int inspect_ssl_traffic = 0;
  IP_ENTRY_HASH_KEY_T iph_key;

  if ( ( !dst_ip ) || ( dst_port == 0 ) ) {
    return 1; // invalid param, can't take decession.
  }

  if ( ktrace_config.no_of_internal_domain_cidr > 0 ) {
    if( ! is_cluster_ip( *dst_ip,
                         ktrace_config.internal_domain_cidr_list,
                         ktrace_config.no_of_internal_domain_cidr,
                         ktrace_config.internal_domain_cidr_except_list,
                         ktrace_config.no_of_internal_domain_except_cidr) ) {
      egress_traffic = 1;
    }
  } else if ( ktrace_config.instances_ips_hash_table )  {
    memset(&iph_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));
    iph_key.addr.s_addr = dst_ip->s_addr;

    if ( ip_hash_find(ktrace_config.instances_ips_hash_table, &iph_key) != IP_HASH_KEY_EXISTS) {
      egress_traffic = 1;
    }
  }

  /*
   * In egress direction, we will always process traffic as TCP.
   *
   * In mesh7 datapath, egress SSL traffic is handled by sslproxy.
   * If egress SSL traffic is received by libdssl, it is because the port
   * is configured for egress tcp capture. So interpret the traffic as TCP.
   */
  if ( egress_traffic == 0 ) { 
    if ( ktrace_config.ingress_ports[dst_port] == SSL_FROM ) {
      inspect_ssl_traffic = 1;
    }
  }

  return inspect_ssl_traffic;
}

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, clean_up);

  int rc = 0, k;
  void *ret;
  char *tenv = NULL;

  stat_prev_time = time(NULL);
  ktrace_config.ingress_ports = (int*)calloc(PORT_ARG_LEN, sizeof(int));
  ktrace_config.egress_ports = (int*)calloc(PORT_ARG_LEN, sizeof(int));

  for (k = 0; k < PORT_ARG_LEN; k++) {
    ktrace_config.egress_ports[k] = TCP_TO;
  }

  memset(get_args(), 0, sizeof(KTRACE_ARGS));
  err_msg[0] = 0;

  if (argc < 3) {
    print_usage();
    return 0;
  }

  if (load_args(argc, argv, get_args(), ktrace_config.listener_ports, hostname) != 0) {
    if (strlen(err_msg)) {
      fprintf(stderr, "%s", err_msg);
    } else {
      print_usage();
    }
    return 1;
  }

  /*if (set_internal_domain() == -1) {
    return -1;
  }*/

  if (set_instance_ip() == -1) {
    return -1;
  }

  set_host_ip();

  set_cidr_list("KTRACE_HOST_CIDR", &host_cidr_list, &no_of_host_cidr);
  set_cidr_list("KTRACE_POD_CIDR", &pod_cidr_list, &no_of_pod_cidr);
  set_cidr_list("KTRACE_SERVICE_CIDR", &service_cidr_list, &no_of_service_cidr);
  set_cidr_list("KTRACE_INTERNAL_DOMAIN", &ktrace_config.internal_domain_cidr_list, &ktrace_config.no_of_internal_domain_cidr);

  set_cidr_list("KTRACE_HOST_EXCEPT_CIDR", &host_cidr_except_list, &no_of_host_except_cidr);
  set_cidr_list("KTRACE_POD_EXCEPT_CIDR", &pod_cidr_except_list, &no_of_pod_except_cidr);
  set_cidr_list("KTRACE_SERVICE_EXCEPT_CIDR", &service_cidr_except_list, &no_of_service_except_cidr);
  set_cidr_list("KTRACE_EXCEPT_INTERNAL_DOMAIN", &ktrace_config.internal_domain_cidr_except_list, &ktrace_config.no_of_internal_domain_except_cidr);

  KLOG_INFO(MODULE_KTRACE,"No of pod cidr : %d", no_of_pod_cidr);
  KLOG_INFO(MODULE_KTRACE,"No of service cidr : %d", no_of_service_cidr);
  KLOG_INFO(MODULE_KTRACE,"No of host cidr : %d", no_of_host_cidr);
  KLOG_INFO(MODULE_KTRACE,"HOST IP - %s", inet_ntoa(host_ip_addr));
  KLOG_INFO(MODULE_KTRACE,"Program started by User %d", getuid());

  /* Initialize OpenSSL library before using DSSL! */
  // TODO Check log level for openssl
  SSL_library_init();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  set_exclude_ports("EXCLUDE_INGRESS_PORTS", ktrace_config.exclude_ingress_ports, &ktrace_config.no_of_exclude_ingress_ports);
  set_exclude_ports("EXCLUDE_EGRESS_PORTS", ktrace_config.exclude_egress_ports, &ktrace_config.no_of_exclude_egress_ports);

  KLOG_INFO(MODULE_KTRACE,"Exclude Ingress Ports %d", ktrace_config.no_of_exclude_ingress_ports);
  KLOG_INFO(MODULE_KTRACE,"Exclude Egress Ports %d", ktrace_config.no_of_exclude_egress_ports);

  no_of_ports =
      set_portdetails(ktrace_config.ingress_ports, ktrace_config.egress_ports, ports_for_exper, 
                      &ingress_wildcard, &egress_wildcard, ktrace_config.standalone_mode,
                      port_range_for_expr, &no_of_port_range, &ktrace_config );

  if (no_of_ports == -1) {
    return -1;
  }

  if (ktrace_config.no_of_exclude_ingress_ports == 0 && (ingress_wildcard)) {
    KLOG_CRIT(MODULE_KTRACE,"EXCLUDE_INGRESS_PORTS environment variable not found. Exiting");
    //return -1;
  }

  if (ktrace_config.no_of_exclude_egress_ports == 0 &&  egress_wildcard ) {
    KLOG_CRIT(MODULE_KTRACE,"EXCLUDE_EGRESS_PORTS environment variable not found. Exiting");
    //return -1;
  }

  int i = 0;
  KLOG_DEBUG(MODULE_KTRACE,"No of Port Range : %d", no_of_port_range);
  for( i = 0; i < no_of_port_range; i++ ){
    KLOG_INFO(MODULE_KTRACE,"Port range : %s", port_range_for_expr[i]);
  }

  init_stats();


  tenv = getenv("DNS_TELEMETRY");
  if ( tenv && ( strcasecmp(tenv, "true") == 0 ) ) {
    enable_dns_telemetry = true;
  }

  if(enable_dns_telemetry == true ) { 
    init_telemetry();
  }

  dns_init();
  KLOG_DEBUG(MODULE_KTRACE,"Dns initialized.");

  tenv = getenv("MONITOR_TCP_SYN_ATTACK");
  if ( tenv && ( strcasecmp(tenv, "true") == 0 ) ) {
    monitor_tcp_syn_attack = true;
  }

  if ( monitor_tcp_syn_attack == true ) {
    memset(&monitor_sp_activity_conf, 0, sizeof(monitor_sp_activity_conf));
    monitor_sp_activity_conf.process_tcp_half_open_cb = send_spurious_activity_event;
    StartMonitoringSpuriousActivity(&monitor_sp_activity_conf);
  }

  KLOG_ERR(MODULE_KTRACE,"is pcap enabled %d", is_pcap_enabled());
  if (is_pcap_enabled() == true) {
    KLOG_ERR(MODULE_KTRACE,"calling packet_capture_handler");
    rc = packet_capture_handler(get_args());
    if (rc != 0) {
      if (strlen(err_msg)) fprintf(stderr, "%s", err_msg);
    }
  }

  if ( monitor_tcp_syn_attack == true ) {
    StopMonitoringSpuriousActivity();
  }

  /* Cleanup OpenSSL */
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  return rc;
}

/* Open libpcap adapter */
pcap_t* open_adapter(const KTRACE_ARGS* args) {
  pcap_t* retval = NULL;

  if (!args) {
    sprintf(err_msg, "Internal error at %s, line %d", __FILE__, __LINE__);
    return NULL;
  }

  switch (args->src_type) {
    case SRCTYPE_FILE:
      retval = pcap_open_offline(args->src, err_msg);
      break;

    case SCRTYPE_LIVE: {
      retval = pcap_create(args->src, err_msg);
      if (pcap_set_snaplen(retval, MAX_PKT_SIZE) != 0) {
        return NULL;
      }
      if (pcap_set_promisc(retval, 1) != 0) {
        return NULL;
      }
      if (pcap_set_timeout(retval, PCAP_CAPTURE_TIMEOUT) != 0) {
        return NULL;
      }
    } break;

    default:
      sprintf(err_msg, "Internal error at %s, line %d", __FILE__, __LINE__);
      return NULL;
  }

  return retval;
}

/* data callback routine that simply dumps the decoded data on the screen */
static void ktrace_pkt_processor(NM_PacketDir pkt_dir, void* user_data, u_char* pkt_payload,
                                 uint32_t pkt_size, DSSL_Pkt* last_packet) {
  SESSION_CONTEXT* ctx = (SESSION_CONTEXT*)user_data;
  assert(ctx);
  KLOG_TRACE(MODULE_KTRACE,"[%p] %s", ctx->sess, __func__);

  uint32_t src_ip = ntohl(ctx->sess->clientStream.ip_addr);
  uint32_t dst_ip = ntohl(ctx->sess->serverStream.ip_addr);

  if (ctx->sock == SESSION_CONTEXT_SOCK_NEW && pkt_dir == PKT_FROM_CLIENT) {
    char kflow_partial_header[HEADER_LEN] = {0};
    int sock = create_connection(ctx);
    if (sock < 0) {
      ignore_session(ctx);
      return;
    } else {
      KLOG_DEBUG(MODULE_KTRACE,"[%p] Connection created, Sock : %d", ctx->sess, sock);
      ctx->sock = sock;
    }

    snprintf(kflow_partial_header, HEADER_LEN, "KFLOW TCP4 %d.%d.%d.%d %d.%d.%d.%d %hu %hu",
             ((src_ip >> 24)), ((src_ip >> 16) & 0xFF), ((src_ip >> 8) & 0xFF), (src_ip & 0xFF),
             ((dst_ip >> 24)), ((dst_ip >> 16) & 0xFF), ((dst_ip >> 8) & 0xFF), (dst_ip & 0xFF),
             ctx->sess->clientStream.port, ctx->sess->serverStream.port);

    update_stats(STATS_ID_OPEN_CONNECTION, STATS_ACTION_INCREMENT, NULL);

    bool send_succeeded = send_payload(ctx, kflow_partial_header, pkt_payload, pkt_size);
    if (!send_succeeded) {
      ignore_session(ctx);
    }

    update_pcap_stat();
    return;
  }

  if (ctx->sock < 0) {
    return;
  }

  bool send_succeeded;
  switch (pkt_dir) {
    case PKT_FROM_CLIENT:
      send_succeeded = send_payload(ctx, "CDATA", pkt_payload, pkt_size);
      break;
    case PKT_FROM_SERVER:
      send_succeeded = send_payload(ctx, "SDATA", pkt_payload, pkt_size);
      break;
    default:
      KLOG_ERR(MODULE_KTRACE,"Unknown packet direction!");
      return;
  }

  if (!send_succeeded) {
    ignore_session(ctx);
  }
}

static int missing_packet_callback(NM_PacketDir dir, void* user_data, uint32_t pkt_seq,
                                   uint32_t pkt_size) {
  SESSION_CONTEXT* ctx = (SESSION_CONTEXT*)user_data;
  assert(ctx);
  KLOG_TRACE(MODULE_KTRACE,"[%p] %s", ctx->sess, __func__);

  KLOG_INFO(MODULE_KTRACE,"[%p] Missing packet(s) detected; missing segment size %u", ctx->sess, pkt_size);
  close_connection(ctx);
  update_stats(STATS_ID_MISSED_PKT, STATS_ACTION_INCREMENT, NULL);
  return 0; /* terminate the session */
}

/* error callback routine; prints the error on the screen */
static void error_callback_proc(void* user_data, int error_code) {
  // TcpSession* sess = (TcpSession*) user_data;
  KLOG_ERR(MODULE_KTRACE,"error code: %d", error_code);
}

static void udp_session_event_handler(CapEnv* env, const u_char* data, uint32_t len, DSSL_Pkt* pkt ) {
  output_dns(data, len, internal_domain_ips_hash_table, ktrace_config.internal_domain_cidr_list, ktrace_config.no_of_internal_domain_cidr,
                            ktrace_config.internal_domain_cidr_except_list, ktrace_config.no_of_internal_domain_except_cidr);
}

/* session event callback routine: traces opening / closing sessions; sets the callbacks */
static void session_event_handler(CapEnv* env, TcpSession* sess, char event) {
  switch (event) {
    case DSSL_EVENT_NEW_SESSION: {
      KLOG_INFO(MODULE_KTRACE,"[%p] New session", sess);
      SESSION_CONTEXT* ctx = new_session_context(sess, &ktrace_config);
      if (!ctx) {
        KLOG_ERR(MODULE_KTRACE,"Failed to allocate session context");
        break;
      }
      SessionSetCallback(sess, ktrace_pkt_processor, error_callback_proc, NULL, ctx);
      SessionSetMissingPacketCallback(sess, missing_packet_callback, MISSING_PACKET_COUNT,
                                      MISSING_PACKET_TIMEOUT);
    } break;

    case DSSL_EVENT_SESSION_CLOSING: {
      KLOG_INFO(MODULE_KTRACE,"[%p] Closing session", sess);
      SESSION_CONTEXT* ctx = (SESSION_CONTEXT*)SessionGetUserData(sess);
      if (ctx) {
        close_connection(ctx);
        free(ctx);
      }
      update_stats(STATS_ID_CLOSE_CONNECTION, STATS_ACTION_INCREMENT, NULL);
    } break;

    default:
      KLOG_ERR(MODULE_KTRACE,"ERROR: Unknown session event code (%d)", (int)event);
      break;
  }
}

/* the main processing function: opens pcap_t interface, creates and initializes
the CapEnv instance, starts the data processing and handles deinitialization sequence */
int packet_capture_handler(KTRACE_ARGS* args) {
  // pcap_t* p = NULL;
  CapEnv* env = NULL;
  char* ssl_port_array = NULL;
  int rc = 0, i, status, log_level, log_module;
  char* ssl_port_str = get_port();
  uint16_t sslport[128] = {0};
  char* p = NULL;
  int from_port_len = 0, port = 0;
  int num_ips = 0;
  char* temp_port = NULL;
  int port_exp_filter_len = 0;
  int port_range_exp_filter_len = 0; 
  int ip_filter_len = 0, port_filter_len = 0;

  /* First, open the pcap adapter */
  pcap_handle = open_adapter(args);

  status = pcap_set_buffer_size(pcap_handle, PCAP_BUFF_SIZE);
  if (status != 0) {
    KLOG_CRIT(MODULE_KTRACE,"Error setting pcap buffer");
    return -1;
  }

  status = pcap_activate(pcap_handle);
  if (status != 0) {
    KLOG_CRIT(MODULE_KTRACE,"Error opening pcap adapter");
    return -1;
  }

  if ( no_of_instance_ip ) {
    num_ips = no_of_instance_ip;
  } else if ( ktrace_config.no_of_instance_ip_cidr ) {
    num_ips = ktrace_config.no_of_instance_ip_cidr;
  }

  // Eg. ( 15 (ip) + 1 (space) + 2 (or) + 1 (space) ) = 19 + (5 (number of digits in port) + 1
  // (space) + 2 (or) + 1 (space) ) = 9, + buffer 256

  KLOG_DEBUG(MODULE_KTRACE,"Ingress wildcard : %d, Egress wildcard : %d", ingress_wildcard, egress_wildcard); 
  KLOG_DEBUG(MODULE_KTRACE,"no_of_ports : %d, no_of_port_range : %d", no_of_ports, no_of_port_range);
  max_buff_len = (IP_LEN * num_ips + 256) + (no_of_ports * 9 + 256) + (no_of_port_range * 14 + 256);
  port_exp_filter_len = (no_of_ports * 9 + 256);
  port_range_exp_filter_len = (no_of_port_range * 14 + 256);
  ip_filter_len = ( (IP_LEN * num_ips) + 256 ) ;
  port_filter_len = port_exp_filter_len + port_range_exp_filter_len ;


  char* ip_filter_exp = (char *) malloc ( ip_filter_len );
  memset(ip_filter_exp, '\0', ip_filter_len );
  char* port_range_exp = (char *) malloc (port_range_exp_filter_len);
  memset(port_range_exp, '\0', port_range_exp_filter_len);
  char* port_exp = (char *) malloc (port_exp_filter_len);
  memset(port_exp, '\0', port_exp_filter_len);
  char* port_filter_exp = (char *) malloc (port_filter_len);
  memset(port_filter_exp, '\0', port_filter_len);

  args->filter_exp = (char*)malloc(max_buff_len);
  memset(args->filter_exp, '\0', max_buff_len);

  char dns_filter[512] = "( port 53 and ( (udp and (not udp[10] & 128 = 0)) or (tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0))) ) ";

  int offset = strlen(ip_filter_exp);
  if (no_of_instance_ip > 0) {
    snprintf(ip_filter_exp + offset, ip_filter_len - offset, "( host ");
    offset = strlen(ip_filter_exp);
    for (i = 0; i < no_of_instance_ip; i++) {
      offset += snprintf(ip_filter_exp + offset, ip_filter_len - offset, "%s %s",
                         ip_str_list[i], ((i + 1) < no_of_instance_ip) ? "or " : "");
    }
    strcat(ip_filter_exp, ") ");
  } else if(ktrace_config.no_of_instance_ip_cidr > 0){
    snprintf(ip_filter_exp + offset, ip_filter_len - offset, "( net ");
    offset = strlen(ip_filter_exp);
    for (i = 0; i < ktrace_config.no_of_instance_ip_cidr; i++) {
      offset += snprintf(ip_filter_exp + offset, ip_filter_len - offset, "%s %s",
                         ip_str_list[i], ((i + 1) < ktrace_config.no_of_instance_ip_cidr) ? "or " : "");
    }
    strcat(ip_filter_exp, ") ");
  }

  if( !ingress_wildcard && !egress_wildcard ) {
    if (no_of_ports > 0) {
      offset = strlen(port_exp);
      offset += snprintf( port_exp + offset, port_exp_filter_len - offset, "( port " );

      for (i = 0; i < no_of_ports; i++) {
        offset += snprintf(port_exp + offset, port_exp_filter_len - offset, "%d %s",
                           ports_for_exper[i], ((i + 1) < no_of_ports) ? "or " : "");
      }
      strcat(port_exp, " )");
    } else if (no_of_port_range == 0 ){
      strcat(port_exp, " ( port 80 )"); 
    }

    KLOG_DEBUG(MODULE_KTRACE,"No of port range : %d", no_of_port_range);
    if (no_of_port_range > 0 ) {
      offset = strlen(port_range_exp);
      offset += snprintf( port_range_exp + offset, port_range_exp_filter_len - offset, "( portrange " );
      for (i = 0; i < no_of_port_range; i++) {
        offset += snprintf( port_range_exp + offset, port_range_exp_filter_len - offset, "%s %s",
                            port_range_for_expr[i], ((i + 1) < no_of_port_range) ? "or " : "");
      }    
      strcat(port_range_exp, " )");
    }

    offset = strlen(port_filter_exp);
    snprintf(port_filter_exp + offset, port_filter_len, " ( %s %s %s ) ", port_exp,
                 ( no_of_ports > 0 && no_of_port_range > 0 ) ? "or" : "" , port_range_exp);  

  }

  KLOG_INFO(MODULE_KTRACE," DNS FILTER : %s ", dns_filter );
  KLOG_INFO(MODULE_KTRACE," IP FITER : ->%s<-", ip_filter_exp);
  KLOG_INFO(MODULE_KTRACE," PORT FILTER : ->%s<-", port_exp);
  KLOG_INFO(MODULE_KTRACE," PORT RANGE FILTER : ->%s<-", port_range_exp);


  snprintf(args->filter_exp + 0, max_buff_len, " %s %s %s %s %s %s", 
		  ( enable_dns_telemetry == true ) ? dns_filter : "",
		  ( enable_dns_telemetry == true ) ? "or ( " : "",
		  ( !( no_of_instance_ip == 0 && ktrace_config.no_of_instance_ip_cidr == 0 ) ) ? ip_filter_exp : "",
		  ( strlen(ip_filter_exp) && strlen(port_filter_exp)) ? "and " : "",
		  port_filter_exp  ,
		  ( enable_dns_telemetry == true ) ? ") " : "") ;


  free(ip_filter_exp);
  free(port_exp);
  free(port_range_exp);
  free(port_filter_exp);

  deployment_type = getenv("DEPLOYMENT_TYPE");
  KLOG_INFO(MODULE_KTRACE,"Deployment type : %s", (deployment_type == NULL) ? "Deployment type not found." : deployment_type);

  deployment_type = (deployment_type) ? deployment_type : "";

  KLOG_INFO(MODULE_KTRACE,"Type : %s", deployment_type);
  if (strcasecmp(deployment_type, VPCMIRRORING) == 0) {
    KLOG_INFO(MODULE_KTRACE,"Setting VPC Mirroring filter.");
    strcpy( args->filter_exp, "( port 4789 )");
  }

  KLOG_INFO(MODULE_KTRACE,"Filter :: %s\n", args->filter_exp);
  if (pcap_compile(pcap_handle, &filter, args->filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    KLOG_CRIT(MODULE_KTRACE,"Bad filter - %s", pcap_geterr(pcap_handle));
    return 2;
  }

  if (pcap_setfilter(pcap_handle, &filter) == -1) {
    KLOG_CRIT(MODULE_KTRACE,"Error setting filter - %s\n", pcap_geterr(pcap_handle));
    return 2;
  }

  KLOG_INFO(MODULE_KTRACE,"************* Filter Enabled ***************");

  /* Create and initialize the CapEnv structure */
  env = CapEnvCreate(pcap_handle, 500, 0, 0, 30);
  CapEnvAddSSL_Env_Key(env, args->keyfile, args->pwd);

  char* s = strchr(ssl_port_str, '#');
  from_port_len = (s - ssl_port_str);
  ssl_port_array = (char*)malloc(from_port_len + 1);
  memset(ssl_port_array, '\0', from_port_len + 1);
  strncpy(ssl_port_array, ssl_port_str, from_port_len);

  KLOG_INFO(MODULE_KTRACE,"List of ssl ports : %s", ssl_port_array);
  i = 0;
  p = strtok(ssl_port_array, ",");
  while (p != NULL) {
    port = atoi(p);
    if (!IS_VALID_PORT(port)) {
      KLOG_CRIT(MODULE_KTRACE,"Invalid port number : %d. Exiting.", port);
      goto LEAVE;
    }

    if (port != 0) {
      sslport[i++] = port;
    }
    p = strtok(NULL, ",");
  }

  CapEnvSetSSL_Port(env, sslport, i);
  CapEnvSetInspectSSLTrafficCallback(env, inspect_ssl_traffic_callback);

  if (rc == 0) {
    CapEnvSetSessionCallback(env, session_event_handler, NULL);
    if ( enable_dns_telemetry == true ) {
       CapEnvSetDatagramCallback(env, udp_session_event_handler);
    }
  }

  env->syn_work_flow_callback = NULL;
  env->mirroring_callback = NULL;

  if(deployment_type){
    if(strcasecmp(deployment_type, DAEMONSET) == 0){
      KLOG_INFO(MODULE_KTRACE,"Setting SYN Workflow callback.");
      env->syn_work_flow_callback  = syn_work_flow;
    } else if (strcasecmp(deployment_type, VPCMIRRORING) == 0) {
      KLOG_INFO(MODULE_KTRACE,"Setting VPC Mirroring callback.");
      env->mirroring_callback  = mirroring_callback;
    }
  } else {
    deployment_type = "";
  }

  get_log_module(args->log_module, &log_module);
  set_log_module(log_module);

  get_log_level(args->loglevel, &log_level);
  set_log_level(log_level);

  if (rc == 0) {
    rc = CapEnvCapture(env);
    if (rc != 0) {
      KLOG_ERR(MODULE_KTRACE,"CapEnvCapture failed. Pcap error message:%s", pcap_geterr(pcap_handle));
    }
  }

LEAVE:
  if (env) {
    CapEnvDestroy(env);
    env = NULL;
  }

  if (pcap_handle) {
    pcap_close(pcap_handle);
    pcap_handle = NULL;
  }

  return rc;
}
