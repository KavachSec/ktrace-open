#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include "ktrace_shm.h"
#include "stats.h"

int main() {
  STATS_T* stats = NULL;
  time_t timer;
  struct tm* tm_info = NULL;
  char buffer[128];
  /* the size (in bytes) of shared memory object */
  const int SIZE = sizeof(STATS_T);
  /* name of the shared memory object */
  const char* name = KAVACH_STATS_SHM_NAME;
  /* shared memory file descriptor */
  int shm_fd = -1;

  /* open the shared memory object */
  shm_fd = shm_open(name, O_RDONLY, 0666);
  if (shm_fd > 0) {
    /* memory map the shared memory object */
    stats = (STATS_T*)mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
  } else {
    printf("shm open failed.");
  }

  if (stats) {
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Z(%z) %Y", tm_info);

    /* read from the shared memory object */
    printf("Stats time                                 : %s\n", buffer);
    printf("Opened connections                         : %d\n", stats->open_conn);
    printf("Closed connections                         : %d\n", stats->close_conn);
    printf("Missed packets                             : %d\n", stats->missed_pkt);
    printf("Packet received                            : %u\n", stats->pc_stat.ps_recv);
    printf("Packet dropped                             : %u\n", stats->pc_stat.ps_drop);
    printf("Envoy connection fail                      : %u\n", stats->envoy_connection_fail);
    printf("Send timeout                               : %u\n", stats->send_timeout);
    printf("Embryonic connection queue size            : %u\n", stats->embryonic_conn_queue_size);
    printf("Embryonic connection hash table size       : %u\n", stats->embryonic_conn_hash_table_size);
    printf("Number of embryonic connection(s) detected : %u\n", stats->num_of_embryonic_conn_detected);
  }
  return 0;
}
