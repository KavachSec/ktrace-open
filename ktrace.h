#ifndef __KTRACE_H__
#define __KTRACE_H__

struct _KTRACE_ARGS;
#define FILTER_LEN USHRT_MAX
#define PCAP_BUFF_SIZE 0x10000000 // 256MB
#define PCAP_CAPTURE_TIMEOUT 10
#define INTERNAL_DOMAIN_LIST_SIZE 500
#define CIDR_LIST_SIZE 500

#define PKT_FROM_CLIENT ePacketDirFromClient
#define PKT_FROM_SERVER ePacketDirFromServer

#define LISTENERS 5
#define HASHTABLE_SIZE 4800
#define MAX_INTERFACE 1000

/**
 * The main processing function
 *
 * opens pcap_t interface, creates and
 * initializes the CapEnv instance, starts the data processing,
 * and handles deinitialization sequence
 */
int packet_capture_handler(struct _KTRACE_ARGS* args);

int set_port_info(int from, int to, char* str, int* counter, int* ingress, int* egress,
                  int* ports_for_exper, int* wildcard);

int get_spd_send_interval(void);
char* get_host_ip(void);
#endif
