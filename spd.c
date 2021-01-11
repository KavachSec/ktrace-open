#include "ktrace.h"
#include "log.h"
#include "ktrace_utils.h"
#include "telemetry.h"

#include <sys/mman.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>

#include <linux/audit.h>
#include <ev.h>
#include "netlink.h"
#include "msg_typetabs.h"
#include "pthread.h"
#include <glib-2.0/glib.h>
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */

#include <auparse.h>

/************************************************************************************************/
/*  Note: This is POC code and will be removed                                                  */
/*                                                                                              */
/*  Limitations:                                                                                */
/*     Doesn’t consolidate all the audit message of same message-id before parsing.             */
/*     Service-cache doesn’t support processes listening on multiple ports.                     */
/*     Audit file check-point doesn’t take rollover of files, scenario into consideration.      */
/*                                                                                              */
/*  TBD:                                                                                        */
/*     Remove the added rules                                                                   */
/*     Memory map the check-point file                                                          */
/************************************************************************************************/

// TBD -- Hardcoded, needs to be removed - only for POC
#define KAVACH_SPD_APP "/opt/kavach/bin/kavach_source_process_discovery.sh"

static int spd_shutdown = 0;
static auparse_state_t* au = NULL;
static FILE* audit_file = NULL;
static FILE* audit_file_check_point = NULL;
static char audit_file_name[256] = "/var/log/audit/audit.log";
static char audit_file_name_check_point[256] = "/opt/kavach/tmp/au.cp";

static struct audit_rule_data* new_rule = NULL;
static struct auditd_event* cur_event = NULL;
static char subj[SUBJ_LEN];

static char hostInterfaceIPs[1024] = {
    0,
};

/* This is the configuration manager code */
pthread_t auditd_thread;
static pthread_mutex_t auditd_lock; // Only let one run at a time

#ifndef NETLINK_AUDIT
#define NETLINK_AUDIT 9
#endif
int auditfd = -1, pipefds[2] = {-1, -1};
struct ev_loop* lib_ev_loop;
volatile int stop = 0;
#define EV_STOP() ev_unloop(ev_default_loop(EVFLAG_AUTO), EVUNLOOP_ALL), stop = 1;

GHashTable* ServiceTable;
GHashTable* ServiceParentChildsPIDTable = NULL;
GHashTable* ServiceFailedSPDetection = NULL;
GHashTable* SendSourceConfigTable = NULL;

typedef struct audit_check_point_stat {
  struct stat stat;
  long int offset;
} audit_check_point_stat_t;
audit_check_point_stat_t au_cp_stat;

typedef struct source_service {
  int svc_port;
  char* svc_name;
} source_service_t;

#define NI_MAXHOST 1025
#define NI_MAXSERV 32
char unknown_proc_name[] = "unknown";

typedef struct syscall_metadata {
  int syscall;
  int ppid;
  int pid;
  char ip_str[NI_MAXHOST];
  unsigned int ip;
  int port;
  char proc_name[NI_MAXHOST];
} syscall_metadata_t;
syscall_metadata_t syscall_meta;

typedef struct source_connection {
  int pid;
  int ppid;
  unsigned int ip;
  char ip_str[NI_MAXHOST];
  int port;
  int svc_port;
  char svc_name[NI_MAXHOST];
} source_connection_t;

// TBD - Remove the following declaration. This are included in <libaudit.h>
// Including libaudit.h causes conflict with the KTRACE LOG.
typedef enum { WAIT_NO, WAIT_YES } rep_wait_t;
extern const char* audit_msg_type_to_name(int msg_type);
extern int audit_rule_syscallbyname_data(struct audit_rule_data* rule, const char* scall);
extern int audit_set_enabled(int fd, uint32_t enabled);
extern int audit_add_rule_data(int fd, struct audit_rule_data* rule, int flags, int action);
extern int audit_set_pid(int fd, uint32_t pid, rep_wait_t wmode);
extern int audit_rule_fieldpair_data(struct audit_rule_data** rulep, const char* pair, int flags);

/* To add a key to audit message, key field needs a watch, syscall or exe path
 * given prior to it. Even though the required syscall rules are added before adding
 * key, it fails as the internal private flag _audit_syscalladded is not set.
 * There no public API available to set this flag.
 * In case of auditctl, when key is specified the flag _audit_syscalladded is set to 1
 * if syscall rules are added prior to it, during the parsing of rule data.
 */
extern int _audit_syscalladded;

void free_source_service(source_service_t* service) {
  if (service) {
    if (service->svc_name) {
      free(service->svc_name);
    }
    free(service);
    service = NULL;
  }
}

void sanitize_proc_name(syscall_metadata_t* meta) {
  int j, proc_name_len = strlen(meta->proc_name);

  if (proc_name_len > 0) {
    for (int i = j = 0; i < proc_name_len; i++) {
      if (meta->proc_name[i] != '"') meta->proc_name[j++] = meta->proc_name[i];
    }
    meta->proc_name[j] = '\0';
  } else {
    strcpy(meta->proc_name, unknown_proc_name);
  }
}

void copy_connection(syscall_metadata_t* src, source_connection_t* connection) {
  if (connection == NULL) {
    return;
  }
  memset(connection, 0, sizeof(source_connection_t));
  connection->pid = src->pid;
  connection->ppid = src->ppid;
  connection->ip = src->ip;
  snprintf(connection->ip_str, sizeof(connection->ip_str), "%s", src->ip_str);
  connection->port = src->port;
  snprintf(connection->svc_name, sizeof(connection->svc_name), "%s", src->proc_name);
}

static void clear_syscall_metadata() {
  syscall_meta.proc_name[0] = 0;
  syscall_meta.ip = 0;
  syscall_meta.ip_str[0] = 0;
  syscall_meta.port = -1;
  syscall_meta.pid = -1;
  syscall_meta.ppid = -1;
  syscall_meta.syscall = -1;
}

static gboolean addService(int pid, syscall_metadata_t* meta) {
  int *old_pid = NULL, *new_pid = NULL;
  source_service_t *old_service = NULL, *new_service = NULL;

  new_service = (source_service_t*)malloc(sizeof(source_service_t));

  if (new_service == NULL) {
    return false;
  }
  new_service->svc_port = meta->port;
  new_service->svc_name = strdup(meta->proc_name);
  assert(strcmp(new_service->svc_name, meta->proc_name) == 0);

  /* Try looking up this key. */
  if (g_hash_table_lookup_extended(ServiceTable, &pid, (void*)&old_pid, (void*)&old_service)) {
    KLOG_DEBUG(MODULE_SPD,
        "Adding entry in ServiceTable, updting: pid: %d, "
        "new_service[svc name: %s, svc port: %d]",
        *old_pid, new_service->svc_name, new_service->svc_port);

    g_hash_table_insert(ServiceTable, old_pid, new_service);
    free_source_service(old_service);
  } else {
    new_pid = (int*)malloc(sizeof(int));
    if (new_pid == NULL) {
      free_source_service(new_service);
      return false;
    }

    *new_pid = pid;
    KLOG_DEBUG(MODULE_SPD,
        "Adding entry in ServiceTable, new: pid: %d, "
        "new_service[svc name: %s, svc port: %d]",
        *new_pid, new_service->svc_name, new_service->svc_port);

    g_hash_table_insert(ServiceTable, new_pid, new_service);
  }
}

static void deleteService(int pid) {
  int* old_pid = NULL;
  source_service_t* old_service = NULL;

  /* Try looking up this key. */
  if (g_hash_table_lookup_extended(ServiceTable, &pid, (void*)&old_pid, (void*)&old_service)) {
    g_hash_table_steal(ServiceTable, &pid);
    free(old_pid);
    free_source_service(old_service);
  }
  return;
}

static source_service_t* getService(int pid) {
  int* old_pid;
  source_service_t* old_service;

  KLOG_DEBUG(MODULE_SPD,"Get service, pid: %d", pid);

  /* Try looking up this key. */
  if (g_hash_table_lookup_extended(ServiceTable, &pid, (void*)&old_pid, (void*)&old_service)) {
    KLOG_DEBUG(MODULE_SPD,"Service found for pid: %d", pid);
    return old_service;
  }

  KLOG_DEBUG(MODULE_SPD,"Service not found for pid: %d", pid);
  return NULL;
}

static void addFailedSPDDetection(source_connection_t* connection) {
  source_connection_t* tcon = NULL;
  GSList* con_lists = NULL;
  int parent_pid = -1;
  int* tparent_pid = NULL;
  int numHashElement = 0, numListElement = 0;

  if ((!connection) || (connection->ppid <= 0)) {
    return;
  }

  parent_pid = connection->ppid;
  tcon = (source_connection_t*)calloc(1, sizeof(source_connection_t));

  if (!tcon) {
    return;
  }

  memcpy(tcon, connection, sizeof(source_connection_t));

  if (!g_hash_table_lookup_extended(ServiceFailedSPDetection, &parent_pid, (gpointer*)&tparent_pid,
                                    (gpointer*)&con_lists)) {
    tparent_pid = (int*)malloc(sizeof(int));
    *tparent_pid = parent_pid;
  }

  con_lists = g_slist_append(con_lists, tcon);
  g_hash_table_insert(ServiceFailedSPDetection, tparent_pid, con_lists);

  // TBD - remove g_slist_length, as it will  iterates over the whole list to count its elements
  KLOG_DEBUG(MODULE_SPD,
      "Added connection to failed hash table, ppid: %d, pid: %d, "
      "number hashtable entry: %d, "
      "number of conneciton(s) assoicated with this parent pid: %d",
      connection->ppid, connection->pid, g_hash_table_size(ServiceFailedSPDetection),
      g_slist_length(con_lists));
}

static void addEntryServiceParentChildsPIDTable(int parent_pid, int child_pid) {
  int* tparent_pid = NULL;
  int* tchild_pid = NULL;
  GSList* child_pids = NULL;

  if ((parent_pid <= 0) || (child_pid <= 0)) {
    return;
  }

  if (!g_hash_table_lookup_extended(ServiceParentChildsPIDTable, &parent_pid,
                                    (gpointer*)&tparent_pid, (gpointer*)&child_pids)) {
    tparent_pid = (int*)malloc(sizeof(int));
    *tparent_pid = parent_pid;
  }

  tchild_pid = (int*)malloc(sizeof(int));
  *tchild_pid = child_pid;
  child_pids = g_slist_append(child_pids, tchild_pid);
  g_hash_table_insert(ServiceParentChildsPIDTable, tparent_pid, child_pids);
}

static source_service_t* getServiceMatchAnyChild(int parent_pid, int child_pid) {
  char buff[1024] = {
      0,
  };
  char cmds[2][256];
  int status = -1;
  char* token = NULL;
  int pid = -1;
  int *tchild_pid = NULL, *tparent_pid = NULL;
  GSList* child_pids = NULL;
  GSList* iter = NULL;
  source_service_t* old_service = NULL;
  int i = 0;

  if (parent_pid <= 1) {
    return NULL;
  }

  KLOG_DEBUG(MODULE_SPD,
      "Get service matching any child of parent pid %d, skip child pid: %d, number of entries in "
      "lookup htable: %d",
      parent_pid, child_pid, g_hash_table_size(ServiceParentChildsPIDTable));

  if ((child_pids = (GSList*)g_hash_table_lookup(ServiceParentChildsPIDTable, &parent_pid)) !=
      NULL) {
    KLOG_DEBUG(MODULE_SPD,"Found parent pid %d, in cache, Number child pids in cache: %d", parent_pid,
              g_slist_length(child_pids));
    for (iter = child_pids; iter; iter = iter->next) {
      if ((int*)(iter->data)) {
        old_service = getService(*((int*)iter->data));
        if (old_service) {
          KLOG_DEBUG(MODULE_SPD,"Found service in cache:  pidpid %d, pid: %d, svc name: %s, svc port: %d",
                    parent_pid, *(int*)(iter->data), old_service->svc_name, old_service->svc_port);
          return old_service;
        }
        // TBD - if there is no service associated with this pid, then we should delete this entry
      }
    }
  }

  // Get the child thread pids of the parent
  snprintf(cmds[0], sizeof(cmds[0]), "ps -eL -q %d --no-headers --format lwp | xargs", child_pid);

  // Get the child pids of the parent
  snprintf(cmds[1], sizeof(cmds[1]), "pgrep -P %d | xargs", parent_pid);

  for (i = 0; i < 2; i++) {
    *buff = '\0';
    status = execute_command(cmds[i], buff, sizeof(buff));

    if ((status != 0) || (*buff == '\0')) {
      KLOG_DEBUG(MODULE_SPD,"Error executing of command %s, status: %d,  buff: %s", cmds[i], status, buff);
      continue;
    }

    KLOG_DEBUG(MODULE_SPD,"parent pid %d, child pid: %d, %s: [%s]", parent_pid, child_pid,
              ((i == 1) ? "child pids" : "thread pids"), buff);

    token = strtok((char*)buff, " ");

    while (token != NULL) {
      // TBD- not safe to use sscanf, need to replace
      if (sscanf(token, "%d", &pid) == 1) {
        if (pid != child_pid) {
          KLOG_DEBUG(MODULE_SPD,"Get service matching %s pid %d", ((i == 1) ? "child pids" : "thread pids"),
                    pid);
          old_service = getService(pid);

          if (old_service) {
            tchild_pid = (int*)malloc(sizeof(int));
            *tchild_pid = pid;
            child_pids = g_slist_append(child_pids, tchild_pid);
          }
        }
      }

      token = strtok(NULL, " ");
    }
  }

  if (child_pids) {
    tparent_pid = (int*)malloc(sizeof(int));
    *tparent_pid = parent_pid;
    g_hash_table_insert(ServiceParentChildsPIDTable, tparent_pid, child_pids);
    return old_service;
  }

  return NULL;
}

static unsigned char x2c(unsigned char* buf) {
  static const char AsciiArray[17] = "0123456789ABCDEF";
  char* ptr;
  unsigned char total = 0;

  ptr = strchr(AsciiArray, (char)toupper(buf[0]));
  if (ptr) total = (unsigned char)(((ptr - AsciiArray) & 0x0F) << 4);
  ptr = strchr(AsciiArray, (char)toupper(buf[1]));
  if (ptr) total += (unsigned char)((ptr - AsciiArray) & 0x0F);

  return total;
}

char* unescape(const char* buf) {
  int len, i;
  char *str, *strptr;
  const char* ptr = buf;

  /* Find the end of the name */
  if (*ptr == '(') {
    ptr = strchr(ptr, ')');
    if (ptr == NULL)
      return NULL;
    else
      ptr++;
  } else {
    while (isxdigit(*ptr)) ptr++;
  }
  str = strndup(buf, ptr - buf);

  if (*buf == '(') return str;

  /* We can get away with this since the buffer is 2 times
   * bigger than what we are putting there.
   */
  len = strlen(str);
  if (len < 2) {
    free(str);
    return NULL;
  }
  // printf("unescape [%s] len %d", str, len);
  // strptr = str;
  // for (i=0; i<len; i+=2) {
  //       printf(" %x", x2c((unsigned char *)&str[i]));
  //}

  strptr = str;
  for (i = 0; i < len; i += 2) {
    *strptr = x2c((unsigned char*)&str[i]);
    strptr++;
  }
  *strptr = 0;
  return str;
}
#define INVALID 0
unsigned int ip_to_int(const char* ip) {
  /* The return value. */
  unsigned v = 0;
  /* The count of the number of bytes processed. */
  int i;
  /* A pointer to the next digit to process. */
  const char* start;

  start = ip;
  for (i = 0; i < 4; i++) {
    /* The digit being processed. */
    char c;
    /* The value of this byte. */
    int n = 0;
    while (1) {
      c = *start;
      start++;
      if (c >= '0' && c <= '9') {
        n *= 10;
        n += c - '0';
      }
      /* We insist on stopping at "." if we are still parsing
         the first, second, or third numbers. If we have reached
         the end of the numbers, we will allow any character. */
      else if ((i < 3 && c == '.') || i == 3) {
        break;
      } else {
        return INVALID;
      }
    }
    if (n >= 256) {
      return INVALID;
    }
    v *= 256;
    v += n;
  }
  return v;
}

static int parse_sockaddr(const char* message) {
  char* str;
  const char* host;

  // printf("parse_sockaddr msg [%s]\n", message);
  str = strstr(message, "saddr=");
  if (str) {
    int len;
    struct sockaddr* saddr;

    str += 6;
    len = strlen(str) / 2;
    char* host;
    host = unescape(str);
    if (host == NULL) {
      // printf("Error: host is null. Return.\n");
      return -1;
    }
    saddr = (struct sockaddr*)host;

    if (saddr->sa_family == AF_INET) {
      // printf("AF_INET family\n");
      if (len < sizeof(struct sockaddr_in)) {
        // fprintf(stderr,
        //        "sockaddr len too short\n");
        return 1;
      }
      len = sizeof(struct sockaddr_in);
    } else if (saddr->sa_family == AF_INET6) {
      // printf("AF_INET6 family\n");
      if (len < sizeof(struct sockaddr_in6)) {
        // fprintf(stderr,
        //        "sockaddr6 len too short\n");
        return 2;
      }
      len = sizeof(struct sockaddr_in6);
    }
    char ip[NI_MAXHOST], serv[NI_MAXSERV];
    int err;
    err = getnameinfo(saddr, len, syscall_meta.ip_str, NI_MAXHOST, serv, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (!err) {
      if (saddr->sa_family == AF_INET6) {
        // TBD: v6 loopback address.
        char* v4ipstr = strstr(syscall_meta.ip_str, "::ffff:");
        if (v4ipstr != NULL) {
          v4ipstr += strlen("::ffff:");
          syscall_meta.ip = ip_to_int(v4ipstr);
          KLOG_DEBUG(MODULE_SPD,"Parsed proto [%d] v4-mapped-to-v6 IP [%s] to ip [%d] ip_str [%s]",
                    saddr->sa_family, syscall_meta.ip_str, syscall_meta.ip, v4ipstr);
          strncpy(syscall_meta.ip_str, v4ipstr, NI_MAXHOST);
        } else {
          syscall_meta.ip = ip_to_int(syscall_meta.ip_str);
          KLOG_DEBUG(MODULE_SPD,"Parsed proto [%d] v6 IP [%s] to ip [%d]", saddr->sa_family,
                    syscall_meta.ip_str, syscall_meta.ip);
        }
      } else {
        KLOG_DEBUG(MODULE_SPD,"Parsed proto [%d] IP [%s] to ip [%d]", saddr->sa_family, syscall_meta.ip_str,
                  syscall_meta.ip);
        syscall_meta.ip = ip_to_int(syscall_meta.ip_str);
      }
      syscall_meta.port = atoi(serv);
    }
    free(host);
  }

  return 0;
}

// parse audit message
static int parse_syscall(const char* message) {
  // get syscall
  char *ptr, *str, *term;
  int syscall, pid, ppid;

  KLOG_DEBUG(MODULE_SPD,"Parsing syscall message: %s", message);

  // printf("parse_syscall msg: [%s]\n", message);
  str = strstr(message, "syscall=");
  if (str == NULL) {
    return -1;
  }
  // printf("parse_syscall str: [%s]\n", str);

  ptr = str + 8;
  // printf("parse_syscall ptr: [%s]\n", ptr);
  term = strchr(ptr, ' ');
  if (term == NULL) return -1;
  *term = 0;

  // printf("parse_syscall: ptr2 [%s]\n", ptr);

  errno = 0;
  syscall = (int)strtoul(ptr, NULL, 10);
  if (errno) return -1;

  // printf("parse_syscall: syscall [%d]\n", syscall);
  syscall_meta.syscall = syscall;

  // SKIP PPID
  // NOTE: check of "term" length and handle error.
  str = strstr(term + 1, "ppid=");
  if (str == NULL) {
    return -1;
  }
  // printf("parse_pid str: [%s]\n", str);

  ptr = str + 5;
  // printf("parse_pid ptr: [%s]\n", ptr);
  term = strchr(ptr, ' ');
  if (term == NULL) return -1;
  *term = 0;
  errno = 0;
  // printf("parse_pid : ptr2 [%s]\n", ptr);
  ppid = (int)strtoul(ptr, NULL, 10);
  if (errno) return -1;
  syscall_meta.ppid = ppid;

  // GET PID

  str = strstr(term + 1, "pid=");
  if (str == NULL) {
    return -1;
  }
  // printf("parse_pid str: [%s]\n", str);

  ptr = str + 4;
  // printf("parse_pid ptr: [%s]\n", ptr);
  term = strchr(ptr, ' ');
  if (term == NULL) return -1;
  *term = 0;
  errno = 0;
  // printf("parse_pid : ptr2 [%s]\n", ptr);
  pid = (int)strtoul(ptr, NULL, 10);
  if (errno) return -1;

  // printf("parse_pid : pid [%d]\n", pid);
  syscall_meta.pid = pid;

  // NOTE: check of "term" length and handle error.

  str = strstr(term + 1, "comm=");
  if (str == NULL) {
    return -1;
  }
  // printf("parse_proc_name str: [%s]\n", str);

  ptr = str + 5;
  // printf("parse_proc_name ptr: [%s]\n", ptr);
  term = strchr(ptr, ' ');
  if (term == NULL) return -1;
  *term = 0;
  // printf("parse_proc_name: ptr2 [%s]\n", ptr);
  // syscall_meta.proc_name = strdup(ptr);
  strcpy(syscall_meta.proc_name, ptr);
  sanitize_proc_name(&syscall_meta);
  // printf("parse proc_name: [%s]\n", syscall_meta.proc_name);

  return 0;
}

/*
 * Used with sigalrm to force exit
 */
static void thread_killer(int sig) { exit(0); }

static void term_handler(struct ev_loop* loop, struct ev_signal* sig, int revents) {
  // printf("term handler\n");
  EV_STOP();
}

static void close_down(void) {
  struct sigaction sa;

  /* We are going down. Give the event thread a chance to shutdown.
     Just in case it hangs, set a timer to get us out of trouble. */
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = thread_killer;
  sigaction(SIGALRM, &sa, NULL);
}

#if 0
const char *audit_msg_type_to_name(int msg_type)
{
        return msg_type_i2s(msg_type);
}
#endif

void send_source_process_config(source_connection_t* connection) {
  char data[512] = {
      0,
  };
  char req[1024] = {
      0,
  };
  char key[1024] = {
      0,
  };
  char* tkey = NULL;
  const int tkey_max_len = 1024;
  time_t* tlast_sent_time = NULL;
  time_t diff_time = 0;

  snprintf(key, sizeof(key), "svc_name:%s#svc_port:%d#dest_ip:%s#dest_port:%d",
           connection->svc_name, connection->svc_port, connection->ip_str, connection->port);

  if (!g_hash_table_lookup_extended(SendSourceConfigTable, &key, (gpointer*)&tkey,
                                    (gpointer*)&tlast_sent_time)) {
    tkey = (char*)calloc(tkey_max_len, sizeof(char));
    snprintf(tkey, tkey_max_len, "%s", key);
    tlast_sent_time = (time_t*)calloc(1, sizeof(time_t));
    *tlast_sent_time = time(NULL);
    g_hash_table_insert(SendSourceConfigTable, tkey, tlast_sent_time);
  } else {
    diff_time = time(NULL) - (*tlast_sent_time);
    if (diff_time >= get_spd_send_interval()) {
      *tlast_sent_time = time(NULL);
      g_hash_table_insert(SendSourceConfigTable, tkey, tlast_sent_time);
    } else {
      KLOG_DEBUG(MODULE_SPD,
          "Not sending data to envoy: %s, same data was sent %ds before (threshold limit %d sec",
          key, diff_time, get_spd_send_interval());
      return;
    }
  }

  snprintf(data, sizeof(data),
           "{"
           "\"destinationIP\":\"%s\","
           "\"destinationPort\":%d,"
           "\"servicePort\":%d,"
           "\"processName\":\"%s\","
           "\"hostIP\":\"%s\","
           "\"hostInterfaceIPs\":[%s]"
           "}",
           connection->ip_str, connection->port, connection->svc_port, connection->svc_name,
           get_host_ip(), hostInterfaceIPs);

  snprintf(req, sizeof(req), "/mesh7event?eventID=MESH7_SPD_EVENT&eventData=%s", data);

  KLOG_DEBUG(MODULE_SPD,"Sending data to envoy: %s", data);

  send_to_envoy(req);
}

static void processFailedSPDConnections(int parent_pid) {
  GSList* iter = NULL;
  GSList* con_lists = NULL;
  source_service_t* svc = NULL;
  source_connection_t* connection = NULL;
  int* tparent_pid = NULL;

  if (parent_pid <= 0) {
    return;
  }

  g_hash_table_lookup_extended(ServiceFailedSPDetection, &parent_pid, (gpointer*)&tparent_pid,
                               (gpointer*)&con_lists);
  if (!con_lists) {
    return;
  }

  KLOG_DEBUG(MODULE_SPD,"Start processing previously failed SPD connecitons: ppid: %d", parent_pid);

  for (iter = con_lists; iter; iter = iter->next) {
    connection = (source_connection_t*)iter->data;

    if (connection) {
      svc = getServiceMatchAnyChild(connection->ppid, connection->pid);

      if (svc) {
        connection->svc_port = svc->svc_port;
        send_source_process_config(connection);
      }
    }
  }

  g_hash_table_steal(ServiceFailedSPDetection, &parent_pid);
  g_slist_free_full(con_lists, free);
  free(tparent_pid);
  KLOG_DEBUG(MODULE_SPD,"End of processing previously failed SPD connecitons");
}

static void parse_audit_message(int type, const char* au_msg, int au_msg_len) {
  const char* message = au_msg;
  int len = au_msg_len;

  if ((!message) || (len <= 0)) {
    return;
  }

  switch (type) {
    case 1300: // SYSCALL
      parse_syscall(message);
      KLOG_DEBUG(MODULE_SPD,"Parsed syscall %d from PID %d", syscall_meta.syscall, syscall_meta.pid);
      break;
    case 1306: // SOCKADDR
      parse_sockaddr(message);
      break;
    case 1320: // EOE
      if (syscall_meta.pid > 0) {
        switch (syscall_meta.syscall) {
          case 42: // CONNECT
            if (syscall_meta.ip != 0 && syscall_meta.port > 0) {
              source_connection_t connection;
              copy_connection(&syscall_meta, &connection);

              KLOG_DEBUG(MODULE_SPD,
                  "CONNECT syscall received for DestIP [%s] : DestPort %d from PId %d ParentPId "
                  "%d",
                  syscall_meta.ip_str, syscall_meta.port, syscall_meta.pid, connection.ppid);

              source_service_t* svc;
              svc = getService(connection.pid);
              if (svc != NULL) {
                connection.svc_port = svc->svc_port;
                strcpy(connection.svc_name, svc->svc_name);
              } else {
                KLOG_DEBUG(MODULE_SPD,"Get service for parent pid: %d", connection.ppid);
                svc = getService(connection.ppid);

                if (svc == NULL) {
                  svc = getServiceMatchAnyChild(connection.ppid, connection.pid);
                }

                if (svc != NULL) {
                  KLOG_DEBUG(MODULE_SPD,
                      "Service [%s] with service port [%d] found to be assoicated with ppid %d, "
                      "pid: %d",
                      svc->svc_name, svc->svc_port, connection.ppid, syscall_meta.pid);
                  connection.svc_port = svc->svc_port;
                  strcpy(connection.svc_name, svc->svc_name);
                } else {
                  KLOG_DEBUG(MODULE_SPD,"No Service found assoicated with ppid %d, pid: %d", connection.ppid,
                            syscall_meta.pid);
                }
              }

              if ((strcmp(syscall_meta.ip_str, "127.0.10.10") != 0) &&
                  (syscall_meta.port != get_event_listener_port()) && (syscall_meta.port != 53)) {
                if (connection.svc_port == 0) {
                  addFailedSPDDetection(&connection);
                }
                // Send SPD event.
                send_source_process_config(&connection);
              }
            } else {
              KLOG_DEBUG(MODULE_SPD,"CONNECT syscall received for invalid DestIP [%d] : DestPort %d",
                        syscall_meta.ip, syscall_meta.port);
            }
            break;
          case 49: // BIND
            if (syscall_meta.port > 0) {
              addService(syscall_meta.pid, &syscall_meta);
              KLOG_DEBUG(MODULE_SPD,"BIND syscall for Port %d by PId %d ProcName [%s]", syscall_meta.port,
                        syscall_meta.pid, syscall_meta.proc_name);

              addEntryServiceParentChildsPIDTable(syscall_meta.ppid, syscall_meta.pid);
              processFailedSPDConnections(syscall_meta.ppid);
            }
            break;
        }
      }
      clear_syscall_metadata();
      break;
  }
}

static void format_raw(const struct audit_reply* rep) {
  int len, nlen;
  const char* message;
  char unknown[32];

  if (rep == NULL) {
    return;
    // printf("REPLY is NIL... NOT HANDLING FOR NOW\n");
  }

  // type = audit_msg_type_to_name(rep->type);
  // printf(" msg type name: %s\n", type);
  if (rep->message == NULL) {
    message = "lost";
    len = 4;
  } else {
    message = rep->message;
    len = rep->len;
  }

  parse_audit_message(rep->type, message, len);
}

void on_start_source_process_discovery(void) {
  int status = -1;
  char buff[5912] = {
      0,
  };
  char* token = NULL;
  syscall_metadata_t sm;
  char spd_cmd[256] = {
      0,
  };

  // Get all the interfaces omitting loopback interface and IPv6 link-local addresses
  // TBD - revisit the parsing commands, may be there is simpler approach
  // Output: "10.142.0.2","172.18.0.1","172.17.0.1"
  status = execute_command(
      "hostname --all-ip-addresse 2> /dev/null | "
      " xargs | sed -e 's/ /\",\"/g' | "
      " awk '{ if(length($0) != 0 ) printf \"\\\"%s\\\"\", $0}' 2>/dev/null",
      buff, sizeof(buff));

  if ((status == 0) && (*buff != '\0')) {
    snprintf(hostInterfaceIPs, sizeof(hostInterfaceIPs), "%s", buff);
  }

  // Get process which are listening
  snprintf(spd_cmd, sizeof(spd_cmd), "%s --netstat", KAVACH_SPD_APP);
  *buff = '\0';
  status = execute_command(spd_cmd, buff, sizeof(buff));

  if ((status == 0) && (*buff != '\0')) {
    token = strtok((char*)buff, "\n");

    while (token != NULL) {
      memset(&sm, 0, sizeof(syscall_metadata_t));
      // TBD- not safe to use sscanf, need to replace
      // Note addService doesn handle cases where same process can listen on multiple ports.
      if (sscanf(token, "%d %s %d", &sm.pid, sm.proc_name, &sm.port) == 3) {
        KLOG_DEBUG(MODULE_SPD,"netstat: pid: %d, proc -->%s<--, port: %d\n", sm.pid, sm.proc_name, sm.port);
        addService(sm.pid, &sm);
      }

      token = strtok(NULL, "\n");
    }
  }

  // Get process which are listening from config-file
  snprintf(spd_cmd, sizeof(spd_cmd), "%s --configfile", KAVACH_SPD_APP);
  *buff = '\0';
  status = execute_command(spd_cmd, buff, sizeof(buff));

  if ((status == 0) && (*buff != '\0')) {
    token = strtok((char*)buff, "\n");

    while (token != NULL) {
      memset(&sm, 0, sizeof(syscall_metadata_t));
      // TBD- not safe to use sscanf, need to replace
      // Note addService doesn handle cases where same process can listen on multiple ports.
      if (sscanf(token, "%d %s %d", &sm.pid, sm.proc_name, &sm.port) == 3) {
        KLOG_DEBUG(MODULE_SPD,"configfile: pid: %d, proc -->%s<--, port: %d\n", sm.pid, sm.proc_name, sm.port);
        addService(sm.pid, &sm);
      }

      token = strtok(NULL, "\n");
    }
  }
}

void netlink_handler(struct ev_loop* loop, struct ev_io* io, int revents) {
  if (cur_event == NULL) {
    if ((cur_event = malloc(sizeof(*cur_event))) == NULL) {
      char emsg[DEFAULT_BUF_SZ];
      if (*subj)
        snprintf(emsg, sizeof(emsg), "op=error-halt pid=%d subj=%s res=failed", getpid(), subj);
      else
        snprintf(emsg, sizeof(emsg), "op=error-halt pid=%d res=failed", getpid());
      EV_STOP();
      close_down();
      return;
    }
    cur_event->ack_func = NULL;
  }

  memset(&cur_event->reply, 0, sizeof(struct audit_reply));
  if (audit_get_reply(auditfd, &cur_event->reply, GET_REPLY_NONBLOCKING, 0) > 0) {
    // printf("audit_get_reply ... type: %d\n", cur_event->reply.type);
    switch (cur_event->reply.type) {
      case NLMSG_NOOP:
      case NLMSG_DONE:
      case NLMSG_ERROR:
      case AUDIT_GET:
      case AUDIT_LIST_RULES:
      case AUDIT_FIRST_DAEMON ... AUDIT_LAST_DAEMON:
      case AUDIT_SIGNAL_INFO:
        break;
      default:
        // printf("default... type: %d\n", cur_event->reply.type);
        /* If type is 0, then its a network originating event */
        if (cur_event->reply.type == 0) {
          // printf("\n NETWORK ORIGINATION PKT...NOT HANDLING FOR NOW\n");
          return;
        } else if (cur_event->reply.type != AUDIT_DAEMON_RECONFIG) {
          // All other local events need formatting
          // printf("formatted event: %s\n", format_raw(&cur_event->reply));
          format_raw(&cur_event->reply);
        }
    }

  } else {
    if (errno == EFBIG) {
      // FIXME do err action
    }
  }
}

static int init_audit_files(void) {
  audit_file = NULL;
  audit_file_check_point = NULL;

  KLOG_INFO(MODULE_SPD,"Audit file: %s", audit_file_name);
  if ((audit_file = fopen(audit_file_name, "r")) == NULL) {
    KLOG_ERR(MODULE_SPD,"Error opening audit message file: %s, error: %s(%d)\n", audit_file_name,
            strerror(errno), errno);
    return 1;
  }

  return 0;
}

static void deinit_audit_files(void) {
  if (audit_file) {
    fclose(audit_file);
  }
  if (audit_file_check_point) {
    fclose(audit_file_check_point);
  }
}

static void au_file_validate_and_update_chkpoint(void) {
  struct stat statbuf;
  int reset = 0;

  if (!audit_file_check_point) {
    return;
  }

  memset(&statbuf, 0, sizeof(struct stat));
  reset = 1;

  do {
    if (stat(audit_file_name, &statbuf) != 0) {
      break;
    }

    if ((au_cp_stat.stat.st_ino != 0) && (statbuf.st_ino != au_cp_stat.stat.st_ino)) {
      break;
    }

    if (!audit_file) {
      break;
    }

    au_cp_stat.offset = ftell(audit_file);
    if (au_cp_stat.offset == -1) {
      break;
    }

    if (au_cp_stat.offset > statbuf.st_size) {
      break;
    }

    memcpy(&au_cp_stat.stat, &statbuf, sizeof(struct stat));

    reset = 0;
  } while (0);

  if (reset) {
    if (audit_file) {
      audit_file = freopen(audit_file_name, "r", audit_file);
    } else {
      audit_file = fopen(audit_file_name, "r");
    }

    memset(&au_cp_stat, 0, sizeof(audit_check_point_stat_t));
  }

  fseek(audit_file_check_point, 0, SEEK_SET);
  fwrite(&au_cp_stat, sizeof(audit_check_point_stat_t), 1, audit_file_check_point);
  fsync(fileno(audit_file_check_point));
}

/* Simple check point handling
 *  Doesn't take care of rollover messages files
 */
static int audit_file_load_check_point(void) {
  size_t nitems = 0;
  struct stat statbuf;

  if (!audit_file) {
    return 1;
  }

  memset(&au_cp_stat, 0, sizeof(audit_check_point_stat_t));
  memset(&statbuf, 0, sizeof(struct stat));

  fstat(fileno(audit_file), &statbuf);

  // TBD: memmap this file
  KLOG_INFO(MODULE_SPD,"Audit checkpoint file: %s", audit_file_name_check_point);
  if ((audit_file_check_point = fopen(audit_file_name_check_point, "r")) != NULL) {
    fseek(audit_file_check_point, 0, SEEK_SET);
    nitems = fread(&au_cp_stat, sizeof(audit_check_point_stat_t), 1, audit_file_check_point);
    KLOG_INFO(MODULE_SPD,"Audit checkpoint, number of items read: %d", nitems);
    fclose(audit_file_check_point);
    audit_file_check_point = NULL;
  }

  // freopen
  if ((audit_file_check_point = fopen(audit_file_name_check_point, "w+")) == NULL) {
    KLOG_ERR(MODULE_SPD,"Error opening audit file: %s", audit_file_name_check_point);
    return 2;
  }

  if (nitems == 0) {
    au_file_validate_and_update_chkpoint();
    return 0;
  }

  KLOG_INFO(MODULE_SPD,"Audit checkpoint data, dev: %d, inode: %d, offset: %ld", au_cp_stat.stat.st_dev,
           au_cp_stat.stat.st_ino, au_cp_stat.offset);
  if ((statbuf.st_dev != au_cp_stat.stat.st_dev) || (statbuf.st_ino != au_cp_stat.stat.st_ino) ||
      (au_cp_stat.offset > statbuf.st_size)) {
    au_file_validate_and_update_chkpoint();
    return 0;
  }

  KLOG_INFO(MODULE_SPD,"Audit checkpoint, setting offset of audit file to: %d", au_cp_stat.offset);
  fseek(audit_file, au_cp_stat.offset, SEEK_SET);

  return 0;
}

static void auparse_handle_event(auparse_state_t* au, auparse_cb_event_t cb_event_type,
                                 void* user_data) {
  int type = -1;
  const char* message = NULL;

  if (cb_event_type != AUPARSE_CB_EVENT_READY) return;

  auparse_first_record(au);

  do {
    type = auparse_get_type(au);
    message = auparse_get_record_text(au);

    if (message) {
      parse_audit_message(type, message, strlen(message));
    }

  } while (auparse_next_record(au) > 0);
}

static void au_parse_loop(void) {
  char msg[MAX_AUDIT_MESSAGE_LENGTH + 1];
  char* ret = NULL;

  while (!spd_shutdown) {
    memset(msg, 0, sizeof(msg));
    ret = fgets(msg, MAX_AUDIT_MESSAGE_LENGTH, audit_file);

    if (ret != NULL) {
      au_file_validate_and_update_chkpoint();
      auparse_feed(au, msg, strnlen(msg, MAX_AUDIT_MESSAGE_LENGTH));
    } else {
      if ((!feof(audit_file)) && (ferror(audit_file))) {
        au_file_validate_and_update_chkpoint();
      }
      clearerr(audit_file);
      sleep(1);
    }
  }
}

/*
 * This function returns -1 on error and 1 on success.
 */
// typedef enum { WAIT_NO, WAIT_YES } rep_wait_t;
#define DEFAULT_BUF_SZ 448
#define SUBJ_LEN 4097

#if 0
int audit_set_pid(int fd, uint32_t pid, rep_wait_t wmode)
{
        struct audit_status s;
        //struct audit_reply rep;
        //struct pollfd pfd[1];
        int rc;

        memset(&s, 0, sizeof(s));
        s.mask    = AUDIT_STATUS_PID;
        s.pid     = pid;
        rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
        if (rc < 0) {
                KLOG_ERR(MODULE_SPD,"Error setting audit daemon pid (%s)", strerror(-rc));
                return rc;
        }
        if (wmode == WAIT_NO)
                return 1;

        /* Now we'll see if there's any reply message. This only
           happens on error. It is not fatal if there is no message.
           As a matter of fact, we don't do anything with the message
           besides gobble it. */
/*
        pfd[0].fd = fd;
        pfd[0].events = POLLIN;
        do {
                rc = poll(pfd, 1, 100); 
        } while (rc < 0 && errno == EINTR);

        (void)audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
*/
        return 1;
}
#endif

int audit_start() {
  struct sigaction sa;
  struct rlimit limit;
  int i, c, rc;
  struct ev_io netlink_watcher;
  int au_from_netlink = 0;
  char key_val1[36] = "arch=b64";
  char key_val2[36] = "key=mesh7";

  /* Raise the rlimits in case we're being started from a shell
   * with restrictions. Not a fatal error.  */
  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;
  setrlimit(RLIMIT_FSIZE, &limit);
  setrlimit(RLIMIT_CPU, &limit);

  // TBD - include header #include <libaudit.h>, and revsolve LOG conflict
  new_rule = (struct audit_rule_data*)calloc(1, sizeof(struct audit_rule_data));
  audit_rule_fieldpair_data(&new_rule, key_val1, AUDIT_FILTER_EXIT);
  audit_rule_syscallbyname_data(new_rule, "connect");
  audit_rule_syscallbyname_data(new_rule, "bind");
  _audit_syscalladded = 1;
  audit_rule_fieldpair_data(&new_rule, key_val2, AUDIT_FILTER_EXIT);

  /* Init netlink */
  if ((auditfd = audit_open()) < 0) {
    KLOG_ERR(MODULE_SPD,"Cannot open netlink audit socket");
    return 1;
  }

  audit_set_enabled(auditfd, 1);
  audit_add_rule_data(auditfd, new_rule, AUDIT_FILTER_EXIT | AUDIT_FILTER_PREPEND, AUDIT_ALWAYS);

  /* Init the event handler thread */
  /*
          write_pid_file();
          if (lib_init_event()) {
                  if (pidfile)
                          unlink(pidfile);
                  return 1;
          }
  */

  /*
          FILE *fp;
          char path[1035];

          fp = popen("sudo netstat -tlnp | tr -s ' ' | cut -f 4,7 -d ' '", "r");
          if (fp == NULL) {
                  printf("Failed to run command\n" );
                  exit(1);
          }

          while (fgets(path, sizeof(path), fp) != NULL) {
                  printf("%s", path);
          }

          pclose(fp);
  */

  ServiceTable = g_hash_table_new(g_int_hash, g_int_equal);
  ServiceParentChildsPIDTable = g_hash_table_new(g_int_hash, g_int_equal);
  ServiceFailedSPDetection = g_hash_table_new(g_int_hash, g_int_equal);
  SendSourceConfigTable = g_hash_table_new(g_str_hash, g_str_equal);
  clear_syscall_metadata();

  on_start_source_process_discovery();

  /* Event loop */

  if (audit_set_pid(auditfd, getpid(), WAIT_YES) < 0) {
    char emsg[DEFAULT_BUF_SZ];
    if (*subj)
      snprintf(emsg, sizeof(emsg),
               "op=set-pid pid=%d uid=%u "
               "subj=%s res=failed",
               getpid(), getuid(), subj);
    else
      snprintf(emsg, sizeof(emsg),
               "op=set-pid pid=%d uid=%u "
               "res=failed",
               getpid(), getuid());
    KLOG_ERR(MODULE_SPD,"audit_set_pid failed with error: %s", emsg);
  } else {
    au_from_netlink = 1;
  }

  if (au_from_netlink == 0) {
    KLOG_INFO(MODULE_SPD,"Audit log message from file: %s", audit_file_name);

    if (init_audit_files() != 0) {
      return 2;
    }

    if (audit_file_load_check_point() != 0) {
      return 3;
    }

    if ((au = auparse_init(AUSOURCE_FEED, 0)) == NULL) {
      return 4;
    }

    auparse_add_callback(au, auparse_handle_event, NULL, NULL);
    au_parse_loop();
    auparse_flush_feed(au);
    auparse_destroy(au);
    deinit_audit_files();

    return 0;
  }

  KLOG_INFO(MODULE_SPD,"Audit log message from netlink: audit fd: %d", auditfd);
  lib_ev_loop = ev_default_loop(EVFLAG_NOENV);
  ev_io_init(&netlink_watcher, netlink_handler, auditfd, EV_READ);
  ev_io_start(lib_ev_loop, &netlink_watcher);

  struct ev_signal sigterm_watcher;
  ev_signal_init(&sigterm_watcher, term_handler, SIGTERM);
  ev_signal_start(lib_ev_loop, &sigterm_watcher);

  ev_loop(lib_ev_loop, 0);
  KLOG_INFO(MODULE_SPD,"Event loop exit");

  return 0;
}

static void* auditd_thread_main(void* arg) {
  sigset_t sigs;

  /* This is a worker thread. Don't handle signals. */
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGALRM);
  sigaddset(&sigs, SIGTERM);
  sigaddset(&sigs, SIGHUP);
  sigaddset(&sigs, SIGUSR1);
  sigaddset(&sigs, SIGUSR2);
  sigaddset(&sigs, SIGCONT);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  audit_start();

  pthread_mutex_unlock(&auditd_lock);
  return NULL;
}

int start_auditd_thread() {
  int retval, rc = 0;

  pthread_mutex_init(&auditd_lock, NULL);

  retval = pthread_mutex_trylock(&auditd_lock);

  if (retval == 0) {
    pthread_attr_t detached;
    pthread_attr_init(&detached);
    pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&auditd_thread, &detached, auditd_thread_main, NULL) < 0) {
      pthread_mutex_unlock(&auditd_lock);
      rc = 1;
    }
    pthread_attr_destroy(&detached);
  } else {
    KLOG_ERR(MODULE_SPD,"auditd thread already running.");
    rc = 1;
  }
  return rc;
}

int wait_for_audit_thread_to_terminate(void) {
  int ret = 0;

  ret = pthread_join(auditd_thread, NULL);

  return ret;
}
