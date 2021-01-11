#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>

extern int KLOG_LEVEL;
extern int KLOG_MODULE;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define CODE_LOCATION __FILE__ ":" TOSTRING(__LINE__)

#define KLOG_MSG(module, level, level_str, fmt, ...) \
  do {                                                                                                     \
    if ((level == (KLOG_LEVEL & level)) && (module == (KLOG_MODULE & module)) ) {                            \
         klog(level, module,  "[%s][%s:%u] " fmt "\n", level_str,  __FILE__, __LINE__, ##__VA_ARGS__) ;    \
    }                                                                                                      \
  } while (0)

#define KLOG_BUFF_MSG(module, level, msg, data, data_len) \
  do {                                                                                                     \
    if ((level == (KLOG_LEVEL & level)) && (module == (KLOG_MODULE & module)) ) {                                \
         klog_buffer(level, module,  "[trace][" CODE_LOCATION "] " msg , data, data_len);                  \
    }                                                                                                      \
  } while (0)

#define KLOG_CRIT(module, fmt, ...) KLOG_MSG(module, LOG_CRIT, "critical", fmt, ##__VA_ARGS__) 
#define KLOG_ERR(module, fmt, ...) KLOG_MSG(module, LOG_ERROR, "error", fmt, ##__VA_ARGS__) 
#define KLOG_WARN(module, fmt, ...) KLOG_MSG(module, LOG_WARN, "warn", fmt,  ##__VA_ARGS__) 
#define KLOG_INFO(module, fmt, ...) KLOG_MSG(module, LOG_INFO, "info", fmt, ##__VA_ARGS__) 
#define KLOG_DEBUG(module, fmt, ...) KLOG_MSG(module, LOG_DEBUG, "debug", fmt, ##__VA_ARGS__) 
#define KLOG_TRACE(module, fmt, ...) KLOG_MSG(module, LOG_TRACE, "trace", fmt, ##__VA_ARGS__) 
#define KLOG_TRACE_BUF(module, msg, data, data_len) KLOG_BUFF_MSG(module, LOG_TRACE, msg, data, data_len)

enum { LOG_CRIT = 1, LOG_ERROR = 2, LOG_WARN = 4, LOG_INFO = 8, LOG_DEBUG = 16, LOG_TRACE = 32 };

enum {
    MODULE_NONE = 0x1,
    MODULE_SPD = 0x2,
    MODULE_DNS = 0x4,
    MODULE_KTRACE = 0x8,
    MODULE_ALL = 0xFF,
};

void klog_init(char* log_path);
void set_log_level(int log_level);
void set_log_module(int module_level);
void klog(int level, int module, const char* fmt, ...);
void klog_buffer(int level, int module, const char* msg, const unsigned char* data, int data_len);
void dump_buffer(const char *label, const unsigned char *data, int data_len);

#endif /* __LOG_H__ */
