#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <glib-2.0/glib.h>

#include "telemetry.h"

#define MAXLINE    5000

static int event_listener_port = 10010;

static void get_current_timestamp(char* timestamp, size_t timestamp_len) {
  time_t ctime;
  struct tm tm;

  if ( ( !timestamp ) || ( timestamp_len == 0 ) ) {
    return;
  }

  memset(&tm, 0, sizeof(struct tm));
  time(&ctime);
  localtime_r(&ctime, &tm);

  strftime(timestamp, timestamp_len, "%Y-%m-%dT%H:%M:%SZ%Z", &tm);
}

static char* ip_addr_to_string(uint32_t ip_addr, char* buff, size_t buff_len) {
  uint32_t ip = ntohl(ip_addr);

  snprintf(buff, buff_len, "%d.%d.%d.%d",
           ((ip >> 24)), ((ip >> 16) & 0xFF),
           ((ip >> 8) & 0xFF), (ip & 0xFF));

  return buff;
}

void init_telemetry(){
  char* cport = NULL;
  int iport = 0;
  
  cport = getenv("EVENT_LISTENER_PORT");
  if(cport != NULL){
    iport = atoi(cport);
    if( iport > 0 ) {
      event_listener_port = iport;
    } 
  }
}

int get_event_listener_port(void){
  return event_listener_port;
}

int send_to_envoy(char* data ) {
  int sockfd = 0, rc = 0;
  struct sockaddr_in serv_addr;
  char sendline[MAXLINE + 1];

  if ( ( sockfd = socket(AF_INET, SOCK_STREAM, 0) ) == -1 ) {
    return -1;
  }

  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(event_listener_port);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    return -1;
  }

  // Form request
  snprintf(sendline, MAXLINE,
           "GET %s HTTP/1.0\r\n\r\n"  , data);

  rc = send(sockfd, sendline, strlen(sendline), 0);
  close(sockfd);
  return rc;
}

void send_spurious_activity_event(TcpHalfOpen* tcp_half_open) {
  char timestamp[32] = {0,};
  char payload[1024] = {0,};
  char cbuff[46] = {0,};
  char sbuff[46] = {0,};
  int plen = 0;
  gchar *encoded_data = NULL;

  if ( !tcp_half_open ) {
    return;
  }

  get_current_timestamp(timestamp, sizeof(timestamp));

  plen = snprintf(payload, sizeof(payload),
                  "{"
                        "\"evt_ctgry\": \"EMBRYONIC_CONNECTION\","
                        "\"evt_category\": \"NETWORK\","
                        "\"evt_subcategory\": \"TCP_HANDSHAKE\","
                        "\"evt_sev\":1,"
                        "\"evt_data\": {"
                            "\"source_ip\": \"%s\","
                            "\"source_port\": \"%u\","
                            "\"destination_ip\": \"%s\","
                            "\"destination_port\": \"%u\","
                            "\"count\": \"%u\","
                            "\"first_seen_time\": \"%ld\""
                        "},"
                        "\"timestamp\": \"%s\""
                  "}",
                  ip_addr_to_string(tcp_half_open->client_ip, cbuff, sizeof(cbuff)),
                  tcp_half_open->client_port,
                  ip_addr_to_string(tcp_half_open->server_ip, sbuff, sizeof(sbuff)),
                  tcp_half_open->server_port,
                  tcp_half_open->count,
                  tcp_half_open->stime,
                  timestamp);

  encoded_data = g_base64_encode((guchar *)payload, plen);
  if ( encoded_data ) {
    snprintf(payload, sizeof(payload), "/mesh7event?eventData=%s", encoded_data);
    g_free(encoded_data);
  }

  send_to_envoy(payload);

  //free(tcp_half_open);
}
