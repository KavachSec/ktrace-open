#ifndef TELEMETRY_H
#define TELEMETRY_H

#include "spurious_activity.h"

#ifdef __cplusplus
extern "C" {
#endif

void init_telemetry();
int get_event_listener_port(void);
int send_to_envoy(char *data );
void send_spurious_activity_event(TcpHalfOpen *tcp_half_open);

#ifdef __cplusplus
}
#endif

#endif




