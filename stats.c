#include "stats.h"
#include "ktrace_shm.h"
#include "log.h"

#include <errno.h>

static STATS_T* stats = NULL;

static void _update_pcap_stats(stats_action_t action, void* stats_field, void* data) {
  switch(action) {
    case STATS_ACTION_SET:
      memcpy(stats_field, data, sizeof(struct pcap_stat));
      break;

    case STATS_ACTION_CLEAR:
      memset(stats_field, 0, sizeof(struct pcap_stat));
      break;
    
    case STATS_ACTION_INCREMENT:
    default:
      KLOG_INFO(MODULE_KTRACE,"Invalid action.");
      break;
  }
}

static void _update_stats(stats_action_t action, void* stats_field, void* data,
                          UPDATE_STATS_FUNC update_stats_func) {
  if (update_stats_func) {
    update_stats_func(action, stats_field, data);
    return;
  }

  switch(action) {
    case STATS_ACTION_SET:
      (*(uint32_t *)stats_field) = *(uint32_t*)data;
      break;

    case STATS_ACTION_INCREMENT:
      (*(uint32_t *)stats_field)++;
      break;

    case STATS_ACTION_CLEAR:
      (*(uint32_t *)stats_field) = 0;
      break;

    default:
      KLOG_INFO(MODULE_KTRACE,"Invalid action.");
      break;
  }
}

void update_stats(stats_id_t stats_id, stats_action_t action, void* data) {

  if( NULL == stats ){
    return;
  }

  switch (stats_id) {
    case STATS_ID_OPEN_CONNECTION:
      _update_stats(action, &stats->open_conn, NULL, NULL);
      break;
    case STATS_ID_CLOSE_CONNECTION:
      _update_stats(action, &stats->close_conn, NULL, NULL);
      break;
    case STATS_ID_MISSED_PKT:
      _update_stats(action, &stats->missed_pkt, NULL, NULL);
      break;
    case STATS_ID_ENVOY_CONNECTION_FAIL:
      _update_stats(action, &stats->envoy_connection_fail, NULL, NULL);
      break;
    case STATS_ID_PCAP_STATS:
      _update_stats(action, &stats->pc_stat, data, _update_pcap_stats);
      break;
    case STATS_ID_SEND_TIMEOUT:
      _update_stats(action, &stats->send_timeout, NULL, NULL);
      break;
    case STATS_ID_EMBRYONIC_CONN_QUEUE_SIZE:
      _update_stats(action, &stats->embryonic_conn_queue_size, data, NULL);
      break;
    case STATS_ID_EMBRYONIC_CONN_HASH_TABLE_SIZE:
      _update_stats(action, &stats->embryonic_conn_hash_table_size, data, NULL);
      break;
    case STATS_ID_NUM_OF_EMBRYONIC_CONN_DETECTED:
      _update_stats(action, &stats->num_of_embryonic_conn_detected, data, NULL);
      break;
    default:
      KLOG_INFO(MODULE_KTRACE,"Invalid action.");
      break;
  }
}

void init_stats() {
  /* the size (in bytes) of shared memory object */
  const int SIZE = sizeof(STATS_T);
  /* name of the shared memory object */
  const char* name = KAVACH_STATS_SHM_NAME;
  /* shared memory file descriptor */
  int shm_fd;
  /* create the shared memory object */
  shm_fd = shm_open(name, O_CREAT | O_RDWR | O_TRUNC, 0666);

  if (shm_fd > 0) {
    /* configure the size of the shared memory object */
    if (ftruncate(shm_fd, SIZE)) {
      KLOG_ERR(MODULE_KTRACE,"cannot change the size of shm: ftruncate failed: %s", strerror(errno));
    }
    /* memory map the shared memory object */
    stats = (STATS_T*)mmap(0, SIZE, PROT_WRITE, MAP_SHARED, shm_fd, 0);
  }
}

