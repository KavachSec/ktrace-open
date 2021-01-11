#include "ip_addr_hash.h"

int _ip_hash_get_key(IP_ENTRY_HASH_KEY_T* ip_entry_hash_key) {
  if ((!ip_entry_hash_key) || ((!ip_entry_hash_key->ip) && (ip_entry_hash_key->addr.s_addr == 0))) {
    return IP_HASH_ERROR;
  }

  if ((ip_entry_hash_key->ip) && (ip_entry_hash_key->addr.s_addr == 0) &&
      (inet_aton(ip_entry_hash_key->ip, &ip_entry_hash_key->addr) == 0)) {
    return IP_HASH_ERROR;
  }

  ip_entry_hash_key->key =
      ((ip_entry_hash_key->addr.s_addr) & (IP_ADDR_MASK_VALUE)) >> IP_HASH_MAX_BIT;

  if ((ip_entry_hash_key->key >= 0) && (ip_entry_hash_key->key < IP_HASH_SIZE)) {
    return IP_HASH_SUCCESS;
  } else {
    return IP_HASH_ERROR;
  }
}

int _ip_hash_find(IP_ENTRY_HASH_T ip_entry_hash, IP_ENTRY_HASH_KEY_T* ip_entry_hash_key) {
  IP_ENTRY_T* ip_ent = NULL;

  if ((!ip_entry_hash) || (!ip_entry_hash_key) || (ip_entry_hash_key->key == 0) ||
      (ip_entry_hash_key->key >= IP_HASH_SIZE)) {
    return IP_HASH_ERROR;
  }

  ip_ent = ip_entry_hash[ip_entry_hash_key->key];

  while (ip_ent != NULL) {
    if (ip_ent->ip_addr == ip_entry_hash_key->addr.s_addr) {
      return IP_HASH_KEY_EXISTS;
    }

    ip_ent = ip_ent->next;
  }

  return IP_HASH_KEY_DOES_NOT_EXISTS;
}

int ip_hash_add(IP_ENTRY_HASH_T* ip_entry_hash, IP_ENTRY_HASH_KEY_T* ip_entry_hash_key) {
  IP_ENTRY_T* new_ip_ent = NULL;

  if ((!ip_entry_hash) || (!ip_entry_hash_key) ||
      (_ip_hash_get_key(ip_entry_hash_key) == IP_HASH_ERROR)) {
    return IP_HASH_ERROR;
  }

  if (*ip_entry_hash == NULL) {
    *ip_entry_hash = (IP_ENTRY_T**)calloc(IP_HASH_SIZE, sizeof(IP_ENTRY_T*));

    new_ip_ent = (IP_ENTRY_T*)malloc(sizeof(IP_ENTRY_T));
    new_ip_ent->ip_addr = ip_entry_hash_key->addr.s_addr;
    new_ip_ent->next = NULL;
    *(*ip_entry_hash + ip_entry_hash_key->key) = new_ip_ent;
  } else {
    // if key already exists return error
    if (_ip_hash_find(*ip_entry_hash, ip_entry_hash_key) != IP_HASH_KEY_DOES_NOT_EXISTS) {
      return IP_HASH_ERROR;
    }

    new_ip_ent = (IP_ENTRY_T*)malloc(sizeof(IP_ENTRY_T));
    new_ip_ent->ip_addr = ip_entry_hash_key->addr.s_addr;
    new_ip_ent->next = *(*ip_entry_hash + ip_entry_hash_key->key);
    *(*ip_entry_hash + ip_entry_hash_key->key) = new_ip_ent;
  }

  return IP_HASH_SUCCESS;
}

int ip_hash_find(IP_ENTRY_HASH_T ip_entry_hash, IP_ENTRY_HASH_KEY_T* ip_entry_hash_key) {
  if (_ip_hash_get_key(ip_entry_hash_key) == IP_HASH_ERROR) {
    return IP_HASH_ERROR;
  }

  return _ip_hash_find(ip_entry_hash, ip_entry_hash_key);
}

int ip_hash_free(IP_ENTRY_HASH_T* ip_entry_hash) {
  // TBD
  return IP_HASH_SUCCESS;
}
