#ifndef __KTRACE_SHM_H__
#define __KTRACE_SHM_H__

#include <pcap.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>

#define KAVACH_STATS_SHM_NAME "KTRACE_STATS"
#ifndef SHM_MOUNT
#define SHM_MOUNT "/dev/shm/"
#endif

#endif /* __KTRACE_SHM_H__ */
