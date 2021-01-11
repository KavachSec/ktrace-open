#ifndef __STATS_H__
#define __STATS_H__

#include <pcap.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct STATSTICS {
  uint32_t open_conn;
  uint32_t close_conn;
  uint32_t missed_pkt;
  uint32_t envoy_connection_fail;
  struct pcap_stat pc_stat;
  uint32_t send_timeout;
  uint32_t embryonic_conn_queue_size;
  uint32_t embryonic_conn_hash_table_size;
  uint32_t num_of_embryonic_conn_detected;
} STATS_T;

typedef enum stats_action {
  STATS_ACTION_INCREMENT,
  STATS_ACTION_SET,
  STATS_ACTION_CLEAR
} stats_action_t;

typedef enum stats_id {
  STATS_ID_OPEN_CONNECTION,
  STATS_ID_CLOSE_CONNECTION,
  STATS_ID_MISSED_PKT,
  STATS_ID_ENVOY_CONNECTION_FAIL,
  STATS_ID_PCAP_STATS,
  STATS_ID_SEND_TIMEOUT,
  STATS_ID_EMBRYONIC_CONN_QUEUE_SIZE,
  STATS_ID_EMBRYONIC_CONN_HASH_TABLE_SIZE,
  STATS_ID_NUM_OF_EMBRYONIC_CONN_DETECTED,
} stats_id_t;


void init_stats();

typedef void (*UPDATE_STATS_FUNC )(stats_action_t action, void *stats_field, void *data);

void update_stats(stats_id_t id, stats_action_t action, void *data);


#endif /* __STATS_H__ */

