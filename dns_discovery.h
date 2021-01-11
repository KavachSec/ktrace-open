/**
 * \file output.h
 *
 * Simple DNS Sniffer - DNS parsing / output
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef DNS_DISCOVERY_H
#define DNS_DISCOVERY_H

#include <pcap/pcap.h>
#include "ktrace_utils.h"

/**
 * Dissect a DNS payload, ignoring any malformed packets.
 *
 * \param[in] dpkt Dissected packet
 * \param[in] hdr  Pcap packet header
 * \return 1 on a fatal error, 0 otherwise.
 */

int output_dns(const u_char* payload, uint32_t payload_offset,
               IP_ENTRY_HASH_T internal_domain_ips_hash_table, CLUSTER_IP cidr_list[],
               int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr);

int check_internal_ip(IP_ENTRY_HASH_T internal_domain_ips_hash_table, IP_ENTRY_HASH_KEY_T* iph,
                      CLUSTER_IP cidr_list[], int no_of_cidr, CLUSTER_IP except_cidr_list[], int no_of_except_cidr);
// int is_cluster_ip(struct in_addr addr, CLUSTER_IP cidr_list[], int no_of_cidr);
int dns_init();
#endif /* DNS_DISCOVERY_H */
