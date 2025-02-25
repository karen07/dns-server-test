#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "array_hashmap.h"

#define PACKET_MAX_SIZE 1600
#define DOMAIN_MAX_SIZE 300
#define EXIT_WAIT_SEC 5

#define FIRST_BIT_UINT16 0x8000
#define FIRST_TWO_BITS_UINT8 0xC0

typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t quest;
    uint16_t ans;
    uint16_t auth;
    uint16_t add;
} __attribute__((packed)) dns_header_t;

typedef struct end_name {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) end_name_t;

typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;

typedef struct domain_data {
    char *domain;
    int32_t packet_size;
    char *packet;
} domain_data_t;
