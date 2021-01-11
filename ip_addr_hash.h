#ifndef __IP_ADDR_HASH_H__
#define __IP_ADDR_HASH_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define IP_HASH_MAX_BIT 16
#define IP_HASH_SIZE (1 << IP_HASH_MAX_BIT ) + 1
#define IP_ADDR_MASK_VALUE ( 0xFFFFFFFF << IP_HASH_MAX_BIT )

typedef struct ip_entry {
    struct ip_entry *next;
    uint32_t ip_addr;
} IP_ENTRY_T;

typedef IP_ENTRY_T** IP_ENTRY_HASH_T;

typedef struct ip_entry_hash_key {
    char *ip;
    struct in_addr addr;
    uint32_t key;
} IP_ENTRY_HASH_KEY_T;

typedef enum {
   IP_HASH_ERROR  = 0,
   IP_HASH_SUCCESS = 1,
   IP_HASH_KEY_EXISTS = 2,
   IP_HASH_KEY_DOES_NOT_EXISTS = 3
}IP_HASH_RET_STATUS;

int ip_hash_add(IP_ENTRY_HASH_T *ip_entry_hash, IP_ENTRY_HASH_KEY_T *ip_entry_hash_key);
int ip_hash_find(IP_ENTRY_HASH_T ip_entry_hash, IP_ENTRY_HASH_KEY_T *ip_entry_hash_key);
int ip_hash_free(IP_ENTRY_HASH_T *ip_entry_hash);

#endif /* __IP_ADDR_HASH_H__ */
