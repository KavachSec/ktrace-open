/**
 * Simple DNS Sniffer - DNS parsing / output
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <features.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <glib-2.0/glib.h>
#include "dns_discovery.h"
#include "telemetry.h"

#define MAXLINE 5000
#define MAX_IP_LEN 42
#define MAX_DNS_IP 64
/**
 * DNS header
 */
struct dnshdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((packed));

/**
 * Basic DNS record types (RFC 1035)
 */
static const char* dns_types[] = {
    "UNKN",  /* Unsupported / Invalid type */
    "A",     /* Host Address */
    "NS",    /* Authorative Name Server */
    "MD",    /* Mail Destination (Obsolete) */
    "MF",    /* Mail Forwarder   (Obsolete) */
    "CNAME", /* Canonical Name */
    "SOA",   /* Start of Authority */
    "MB",    /* Mailbox (Experimental) */
    "MG",    /* Mail Group Member (Experimental) */
    "MR",    /* Mail Rename (Experimental) */
    "NULL",  /* Null Resource Record (Experimental) */
    "WKS",   /* Well Known Service */
    "PTR",   /* Domain Name Pointer */
    "HINFO", /* Host Information */
    "MINFO", /* Mailbox / Mail List Information */
    "MX",    /* Mail Exchange */
    "TXT",   /* Text Strings */
    "AAAA"   /* IPv6 Host Address (RFC 1886) */
};

static u_char buf[BUFSIZ]; /* Label buffer */
static char dbuf[BUFSIZ];  /* Data bufffer */
static GHashTable* dnsCache;
static int dns_interval = 0;
extern int is_cluster_ip(struct in_addr addr, CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr);

/**
 * Skip a DNS label.
 *
 * \param[in] label Pointer to the label
 * \return Pointer to the byte following the label
 */
static u_char* skip_dns_label(u_char* label) {
  u_char* tmp;

  if (!label) return NULL;
  if (*label & 0xc0) return label + 2;

  tmp = label;
  while (*label) {
    tmp += *label + 1;
    label = tmp;
  }
  return label + 1;
}

/**
 * Convert a DNS label (which may contain pointers) to
 * a string by way of the given destination buffer.
 *
 * \param[in] label     Pointer to the start of the label
 * \param[in] dest      Destination buffer
 * \param[in] dest_size Destination buffer size
 * \param[in] payload   Start of the packet
 * \param[in] end       End of the packet
 * \return dest
 */
static u_char* dns_label_to_str(u_char** label, u_char* dest, size_t dest_size,
                                const u_char* payload, const u_char* end) {
  u_char *tmp, *dst = dest;

  if (!label || !*label || !dest) goto err;

  *dest = '\0';
  while (*label < end && **label) {
    if (**label & 0xc0) { /* Pointer */
      tmp = (u_char*)payload;
      tmp += ntohs(*(uint16_t*)(*label)) & 0x3fff;
      while (tmp < end && *tmp) {
        if (dst + *tmp >= dest + dest_size) goto err;
        memcpy(dst, tmp + 1, *tmp);
        dst += *tmp;
        tmp += *tmp + 1;
        if (dst > dest + dest_size) goto err;
        *dst = '.';
        dst++;
      };
      *label += 2;
    } else { /* Label */
      if ((*label + **label) >= end) goto err;
      if (**label + dst >= dest + dest_size) goto err;
      memcpy(dst, *label + 1, **label);
      dst += **label;
      if (dst > dest + dest_size) goto err;
      *label += **label + 1;
      *dst = '.';
      dst++;
    }
  }

  *(--dst) = '\0';
  return dest;
err:
  if (dest) *dest = '\0';
  return dest;
}

static int send_dns_data(char* data) {
  char req[MAXLINE] = "";
  snprintf(req, MAXLINE, "/mesh7event?eventID=MESH7_DNS_EVENT&eventData=%s", data);
  KLOG_DEBUG(MODULE_DNS,"Sending DNS data : %s", req);
  send_to_envoy(req);
}

int check_internal_ip(IP_ENTRY_HASH_T internal_domain_ips_hash_table, IP_ENTRY_HASH_KEY_T* iph,
                      CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr) {
  if (no_of_cidr > 0) {
    if ((is_cluster_ip(iph->addr, cidr_list, no_of_cidr, except_cidr_list, no_of_except_cidr))) {
      return 1;
    }
  }

  if (internal_domain_ips_hash_table) {
    if ((ip_hash_find(internal_domain_ips_hash_table, iph) == IP_HASH_KEY_EXISTS)) {
      return 1;
    }
  }
  return 0;
}

int process_dns_data(const char* data, IP_ENTRY_HASH_T internal_domain_ips_hash_table, 
                     CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr) {
  IP_ENTRY_HASH_KEY_T iph_key;
  memset(&iph_key, 0, sizeof(IP_ENTRY_HASH_KEY_T));
  struct in_addr addr;
  inet_aton(data, &addr);
  iph_key.addr = addr;

  const int tkey_max_len = 512;
  char dom_ip[512] = {
      0,
  };
  char* tkey = NULL;
  time_t* tlast_sent_time = NULL;
  time_t diff_time = 0;

  snprintf(dom_ip, tkey_max_len, "%s", data);

  KLOG_DEBUG(MODULE_DNS,"Data to check : %s", dom_ip);

  if (!check_internal_ip(internal_domain_ips_hash_table, &iph_key, cidr_list, no_of_cidr,
                                     except_cidr_list, no_of_except_cidr)) {
    if (!g_hash_table_lookup_extended(dnsCache, &dom_ip, (gpointer*)&tkey,
                                      (gpointer*)&tlast_sent_time)) {
      tkey = (char*)calloc(tkey_max_len, sizeof(char));
      snprintf(tkey, tkey_max_len, "%s", dom_ip);
      tlast_sent_time = (time_t*)calloc(1, sizeof(time_t));
      *tlast_sent_time = time(NULL);
      g_hash_table_insert(dnsCache, tkey, tlast_sent_time);
      KLOG_DEBUG(MODULE_DNS,"Inserting DNS data %s", tkey);
      return 1;
    } else {
      diff_time = time(NULL) - (*tlast_sent_time);
      if (diff_time >= dns_interval) {
        *tlast_sent_time = time(NULL);
        g_hash_table_insert(dnsCache, tkey, tlast_sent_time);
        KLOG_DEBUG(MODULE_DNS,"Updating DNS data %s", tkey);
        return 1;
      } else {
        KLOG_DEBUG(MODULE_DNS,"Not sending DNS query to envoy: %s", dom_ip);
      }
    }
  } else {
    KLOG_DEBUG(MODULE_DNS,"Internal IP : %s, Not sending to envoy", dom_ip);
  }
  return 0;
}
/**
 * Dissect a DNS payload, ignoring any malformed packets.
 *
 * \param[in] dpkt Dissected packet
 * \param[in] hdr  Pcap packet header
 * \return 1 on a fatal error, 0 otherwise.
 */
int output_dns(const u_char* payload, uint32_t payload_offset,
               IP_ENTRY_HASH_T internal_domain_ips_hash_table, CLUSTER_IP cidr_list[],
               int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr) {
  struct dnshdr* dnsh;
  u_char* tmp;
  u_char* label;
  const char* data;
  const u_char* end;
  uint16_t len, qtype = 0;
  int i, offset = 0;
  char dns_data[MAXLINE] = "";
  char dns_ips[MAX_DNS_IP][MAX_IP_LEN];
  int dns_counter = 0;

  memset(dns_ips, '\0', sizeof(dns_ips));
  end = payload + payload_offset;

  dnsh = (struct dnshdr*)(payload);
  dnsh->id = ntohs(dnsh->id);
  dnsh->flags = ntohs(dnsh->flags);
  dnsh->qdcount = ntohs(dnsh->qdcount);
  dnsh->ancount = ntohs(dnsh->ancount);
  dnsh->nscount = ntohs(dnsh->nscount);
  dnsh->arcount = ntohs(dnsh->arcount);

  /* Disregard malformed packets */
  if (!dnsh->ancount || !dnsh->qdcount) return 0;

  /* Parse the Question section */
  tmp = (u_char*)(payload + 12);
  for (i = 0; i < dnsh->qdcount; i++) {
    /* Get the first question's label and question type */
    if (!qtype) {
      label = dns_label_to_str(&tmp, buf, BUFSIZ, payload, end);
      tmp++;
      qtype = ntohs(*(uint16_t*)tmp);
      KLOG_DEBUG(MODULE_DNS,"Domain name : %s", buf);
    } else {
      if (*tmp & 0xc0)
        tmp += 2;
      else
        tmp = skip_dns_label(tmp);
    }

    /* Skip type and class */
    tmp += 4;
    if (tmp >= end) goto ret;
  }

  /* Output the answer corresponding to the question */
  if (!qtype) {
          KLOG_DEBUG(MODULE_DNS,"not Qtype ret");
          goto ret;
  }

  for (i = 0; i < dnsh->ancount; i++) {

    tmp = skip_dns_label(tmp);
    if (tmp + 10 > end) {
            goto ret;
    }
    /* Get the type, and skip class and ttl */
    len = ntohs(*(uint16_t*)tmp);
    tmp += 8;
    if (len == qtype) {
            goto parse;
    }else {
        tmp += ntohs(*(uint16_t*)tmp) + 2;
        if (tmp > end) {
             goto ret;
          }
        continue;
    }

  parse:
    /* Get the data field length */
    len = ntohs(*(uint16_t*)tmp);
    tmp += 2;

    /* Now, handle the data based on type */
    switch (qtype) {
      case 1: /* A */
        data = inet_ntop(AF_INET, tmp, dbuf, BUFSIZ);
        tmp += len;
        if (dns_counter < MAX_DNS_IP) {
          snprintf(dns_ips[dns_counter++], MAX_IP_LEN, "%s", data);
        }
        break;

      case 2:  /* NS */
      case 5:  /* CNAME */
      case 12: /* PTR */
        data = (char*)dns_label_to_str(&tmp, (u_char*)dbuf, BUFSIZ, payload, tmp + len);
        tmp += len;
        break;
      case 10: /* NULL */
        data = "NULL";
        break;
      case 15: /* MX (16-bit priority / label) */
        i = snprintf(dbuf, 7, "%u ", ntohs(*(uint16_t*)tmp));
        tmp += 2;
        data =
            (char*)dns_label_to_str(&tmp, (u_char*)(dbuf + i), BUFSIZ - i, payload, tmp + len - 2);
        data = dbuf;
        break;
      case 16: /* TXT (1 byte text length / text) */
        if (*tmp <= len && tmp + len < end) {
          memcpy(dbuf, tmp + 1, *tmp);
          dbuf[*tmp + 1] = '\0';
        } else
          *dbuf = '\0';
        data = dbuf;
        break;
      case 17: /* AAAA */
        data = inet_ntop(AF_INET6, tmp, dbuf, BUFSIZ);
        break;
      default:
        /* Ignore unhandled RR types */
        *dbuf = '\0';
        data = dbuf;
    }
  }

  offset = 0;
  *dns_data = '\0';
  i = 0;

  while(true) {
    if ( i >= dns_counter ) { break; }

    if (!process_dns_data(dns_ips[i], internal_domain_ips_hash_table, cidr_list,
                         no_of_cidr, except_cidr_list, no_of_except_cidr)) {
         i++;
         continue;
    }

    if ( *dns_data == '\0' ) {
       offset += snprintf(dns_data, MAXLINE,
                          "{\"queryType\":\"%s\",\"queryDomain\":\"%s\",\"queryData\":\"",
                          dns_types[qtype], label);
    }
    offset += snprintf(dns_data + offset, MAXLINE - offset, "%s,", dns_ips[i]);
    i++;
  }

  if ( (*dns_data != '\0' ) &&
       ((dns_data + offset - 1) < (dns_data + MAXLINE - 4))){ 
      snprintf(dns_data + offset - 1, MAXLINE - offset, "\"}");
  }else {
    goto ret;
  }

  if (*dns_data != '\0') {
    send_dns_data(dns_data);
  }

ret:
  return 0;
}

int dns_init() {
  char* dns_interval_env = NULL;
  dns_interval_env = getenv("DNS_DISCOVERY_INTERVAL");
  if (dns_interval_env) {
    dns_interval = atoi(dns_interval_env);
  }

  dns_interval = (dns_interval > 0) ? dns_interval : 60;
  KLOG_DEBUG(MODULE_DNS,"DNS Interval : %d\n", dns_interval);
  dnsCache = g_hash_table_new(g_str_hash, g_str_equal);
  KLOG_DEBUG(MODULE_DNS,"Initialised dnsCache.");
  KLOG_TRACE(MODULE_DNS,"Initialised dnsCache.Test-->");
  KLOG_INFO(MODULE_DNS,"Initialised dnsCache.info");
}
