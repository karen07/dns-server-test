#include "dns-server-test.h"

int32_t sended;
int32_t readed;

int32_t error_count;

array_hashmap_t domains_map_struct;

uint32_t djb33_hash_len(const char *s, size_t len)
{
    uint32_t h = 5381;
    while (*s && len--) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}

void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

#define GET_DOMAIN_OK 0
#define GET_DOMAIN_FIRST_BYTE_ERROR 1
#define GET_DOMAIN_SECOND_BYTE_ERROR 3
#define GET_DOMAIN_LAST_CH_DOMAIN_ERROR 2
#define GET_DOMAIN_MAX_JUMP_COUNT 100
#define GET_DOMAIN_JUMP_COUNT_ERROR 4
#define GET_DOMAIN_TWO_BITS_ERROR 5
#define GET_DOMAIN_CH_BYTE_ERROR 6
#define GET_DOMAIN_ADD_CH_DOMAIN_ERROR 7
#define GET_DOMAIN_NULL_CH_DOMAIN_ERROR 8

int32_t get_domain_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                               memory_t *domain)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t domain_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_FIRST_BYTE_ERROR;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (domain_len >= (int32_t)domain->max_size) {
                        return GET_DOMAIN_LAST_CH_DOMAIN_ERROR;
                    }
                    domain->data[domain_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return GET_DOMAIN_SECOND_BYTE_ERROR;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > GET_DOMAIN_MAX_JUMP_COUNT) {
                    return GET_DOMAIN_JUMP_COUNT_ERROR;
                }
            } else {
                return GET_DOMAIN_TWO_BITS_ERROR;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_CH_BYTE_ERROR;
            }
            if (domain_len >= (int32_t)domain->max_size) {
                return GET_DOMAIN_ADD_CH_DOMAIN_ERROR;
            }
            domain->data[domain_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (domain_len >= (int32_t)domain->max_size) {
        return GET_DOMAIN_NULL_CH_DOMAIN_ERROR;
    }
    domain->data[domain_len] = 0;
    domain->size = domain_len;

    return GET_DOMAIN_OK;
}

void *stat(__attribute__((unused)) void *arg)
{
    printf("Send_RPS Read_RPS Sended Readed Diff Errors\n");

    int32_t sended_old = 0;
    int32_t readed_old = 0;

    while (true) {
        sleep(1);

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("\n%02d.%02d.%04d %02d:%02d:%02d\n", tm_struct->tm_mday, tm_struct->tm_mon + 1,
               tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);
        printf("%08d %08d %06d %06d %04d %06d\n", sended - sended_old, readed - readed_old, sended,
               readed, readed - sended, error_count);

        sended_old = sended;
        readed_old = readed;
    }
}

static array_hashmap_hash domain_add_hash(const void *add_elem_data)
{
    const domain_data_t *elem = add_elem_data;
    return djb33_hash_len(elem->domain, -1);
}

static array_hashmap_bool domain_add_cmp(const void *add_elem_data, const void *hashmap_elem_data)
{
    const domain_data_t *elem1 = add_elem_data;
    const domain_data_t *elem2 = hashmap_elem_data;

    return !strcmp(elem1->domain, elem2->domain);
}

static array_hashmap_hash domain_find_hash(const void *find_elem_data)
{
    const char *elem = find_elem_data;
    return djb33_hash_len(elem, -1);
}

static array_hashmap_bool domain_find_cmp(const void *find_elem_data, const void *hashmap_elem_data)
{
    const char *elem1 = find_elem_data;
    const domain_data_t *elem2 = hashmap_elem_data;

    return !strcmp(elem1, elem2->domain);
}

void print_help(void)
{
    printf("Commands:\n"
           "  Required parameters:\n"
           "    -l  \"x.x.x.x:xx\"  Listen address\n");
}

int32_t main(int32_t argc, char *argv[])
{
    FILE *cache_fp = NULL;

    struct sockaddr_in listen_addr, client_addr;
    int32_t listen_socket;

    uint32_t client_addr_length = sizeof(client_addr);

    printf("DNS server test started\n");
    printf("Launch parameters:\n");

    listen_addr.sin_addr.s_addr = INADDR_NONE;

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-l")) {
            if (i != argc - 1) {
                printf("  Listen  \"%s\"\n", argv[i + 1]);
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    uint16_t tmp_port = 0;
                    sscanf(colon_ptr + 1, "%hu", &tmp_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_addr.sin_family = AF_INET;
                        listen_addr.sin_port = htons(tmp_port);
                        listen_addr.sin_addr.s_addr = inet_addr(argv[i + 1]);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        print_help();
        errmsg("Unknown command %s\n", argv[i]);
    }

    if (listen_addr.sin_addr.s_addr == INADDR_NONE) {
        print_help();
        errmsg("The program need correct listen IP\n");
    }

    if (listen_addr.sin_port == 0) {
        print_help();
        errmsg("The program need correct listen port\n");
    }

    cache_fp = fopen("cache.data", "r");
    if (!cache_fp) {
        errmsg("Can't open file cache.data\n");
    }

    memory_t cache_data;

    fseek(cache_fp, 0, SEEK_END);
    cache_data.size = ftell(cache_fp);
    fseek(cache_fp, 0, SEEK_SET);

    cache_data.data = (char *)malloc(cache_data.size);

    if (fread(cache_data.data, sizeof(char), cache_data.size, cache_fp) !=
        (size_t)cache_data.size) {
        errmsg("Can't read cache.data file\n");
    }

    domains_map_struct = array_hashmap_init(1000000, 1.0, sizeof(domain_data_t));
    if (domains_map_struct == NULL) {
        errmsg("No free memory for domains_map_struct\n");
    }

    array_hashmap_set_func(domains_map_struct, domain_add_hash, domain_add_cmp, domain_find_hash,
                           domain_find_cmp, domain_find_hash, domain_find_cmp);

    char *cur_pos_ptr = cache_data.data;
    char *cache_data_end = cache_data.data + cache_data.size;

    while (cur_pos_ptr < cache_data_end) {
        char *domain_data = cur_pos_ptr;
        int32_t domain_len = strlen(cur_pos_ptr);

        cur_pos_ptr += domain_len + 1;
        int32_t *packet_size = (int32_t *)cur_pos_ptr;

        domain_data_t add_elem;
        add_elem.packet = cur_pos_ptr + sizeof(int32_t);
        add_elem.packet_size = *packet_size;
        add_elem.domain = domain_data;

        array_hashmap_add_elem(domains_map_struct, &add_elem, NULL, NULL);

        cur_pos_ptr += *packet_size + sizeof(int32_t);
    }

    listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket < 0) {
        errmsg("Can't create socket %s\n", strerror(errno));
    }

    if (bind(listen_socket, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        errmsg("Can't bind to the port %s\n", strerror(errno));
    }

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from client\n");
    }

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    pthread_t stat_thread;
    if (pthread_create(&stat_thread, NULL, stat, NULL)) {
        errmsg("Can't create stat_thread\n");
    }

    if (pthread_detach(stat_thread)) {
        errmsg("Can't detach stat_thread\n");
    }

    while (true) {
        receive_msg.size = recvfrom(listen_socket, receive_msg.data, receive_msg.max_size, 0,
                                    (struct sockaddr *)&client_addr, &client_addr_length);

        readed++;

        char *cur_pos_ptr = receive_msg.data;
        char *receive_msg_end = receive_msg.data + receive_msg.size;

        // DNS HEADER
        if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
            error_count++;
            continue;
        }

        dns_header_t *header = (dns_header_t *)cur_pos_ptr;

        uint16_t first_bit_mark = FIRST_BIT_UINT16;
        uint16_t flags = ntohs(header->flags);
        if ((flags & first_bit_mark) == first_bit_mark) {
            error_count++;
            continue;
        }

        uint16_t quest_count = ntohs(header->quest);
        if (quest_count != 1) {
            error_count++;
            continue;
        }

        cur_pos_ptr += sizeof(dns_header_t);
        // DNS HEADER

        // QUE DOMAIN
        char *que_domain_start = cur_pos_ptr;
        char *que_domain_end = NULL;
        if (get_domain_from_packet(&receive_msg, que_domain_start, &que_domain_end, &que_domain) !=
            0) {
            error_count++;
            continue;
        }
        cur_pos_ptr = que_domain_end;

        domain_data_t res_elem;
        int32_t find_res;
        find_res = array_hashmap_find_elem(domains_map_struct, que_domain.data + 1, &res_elem);
        if (find_res == array_hashmap_elem_finded) {
            dns_header_t *send_header = (dns_header_t *)res_elem.packet;
            send_header->id = header->id;

            if (sendto(listen_socket, res_elem.packet, res_elem.packet_size, 0,
                       (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                errmsg("Can't send to client :%s\n", strerror(errno));
                error_count++;
            } else {
                sended++;
            }
        } else {
            error_count++;
        }
    }

    return EXIT_SUCCESS;
}
