#include "log.h"

int KLOG_LEVEL = 0;
int KLOG_MODULE = 0;

// TODO For multi-threading make it as local variable.
char outbuff[USHRT_MAX];
FILE* fp = NULL;

void klog_init(char* log_path) {
#ifdef LOG_STDOUT
  fp = stdout;
#else
  if ((log_path != NULL) && (*log_path != '\0')) {
    fp = fopen(log_path, "a");
    if (fp == NULL) {
      fprintf(stderr, "Error opening file : %s", log_path);
    }
  }
  fp = (fp == NULL) ? stdout : fp;
#endif
}

void set_log_level(int log_level) {
  if (log_level == LOG_CRIT) {
    KLOG_LEVEL = 1;
  }

  if (log_level == LOG_ERROR) {
    KLOG_LEVEL = 3;
  }

  if (log_level == LOG_WARN) {
    KLOG_LEVEL = 7;
  }

  if (log_level == LOG_INFO) {
    KLOG_LEVEL = 15;
  }

  if (log_level == LOG_DEBUG) {
    KLOG_LEVEL = 31;
  }

  if (log_level == LOG_TRACE) {
    KLOG_LEVEL = 63;
  }
}

void set_log_module( int module) {

  KLOG_MODULE = 0;

  if ( (module & MODULE_DNS)  == MODULE_DNS) {
    KLOG_MODULE |= MODULE_DNS;
  }
  if ( (module & MODULE_KTRACE) == MODULE_KTRACE) {
    KLOG_MODULE |= MODULE_KTRACE;
  }
  if ( (module & MODULE_ALL) == MODULE_ALL) {
    KLOG_MODULE |= MODULE_ALL;
  }
}

void klog(int level, int module, const char* fmt, ...) {
  char time_buf[64];
  time_t t = time(NULL);
  struct tm* lt = localtime(&t);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", lt);
  // memset(outbuff, '\0', sizeof(outbuff))

  va_list args;
  va_start(args, fmt);
  vsnprintf(outbuff, sizeof(outbuff) - 1, fmt, args);
  va_end(args);

  if (fp != NULL) {
    fprintf(fp, "[%s]%s", time_buf, outbuff);
    fflush(fp);
  }
}

void dump_buffer(const char* label, const unsigned char* data, int data_len) {
  int i, j;
  char time_buf[64];

  if (NULL == data) {
    data_len = 0;
  }

  if (NULL == label) {
    label = "";
  }

  if (NULL == fp) {
    return;
  }

  time_t t = time(NULL);
  struct tm* lt = localtime(&t);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", lt);

  fprintf(fp, "\n[%s]%s (%u)\n", time_buf, label, data_len);
  for (i = 0; i < data_len; i += 16) {
    fprintf(fp, "| ");
    for (j = 0; j < 16 && (i + j) < data_len; ++j) {
      fprintf(fp, "%.2x ", data[i + j] & 255);
    }
    for (; j < 16; ++j) fprintf(fp, "   ");

    fprintf(fp, "| |");
    for (j = 0; j < 16 && (i + j) < data_len; ++j) {
      if (isprint(data[i + j])) {
        fprintf(fp, "%c", data[i + j]);
      } else {
        fprintf(fp, ".");
      }
    }
    for (; j < 16; ++j) fprintf(fp, " ");
    fprintf(fp, "|\n");
  }
  fflush(fp);
}

void klog_buffer(int level, int module, const char* msg, const unsigned char* data, int data_len) {
  dump_buffer(msg, data, data_len);
}

