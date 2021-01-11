#include "ktrace_shm.h"

static const char shm_mount[] = SHM_MOUNT;

const char* __shm_directory(size_t* len) {
  if (len) *len = strlen(shm_mount);
  return shm_mount;
}
