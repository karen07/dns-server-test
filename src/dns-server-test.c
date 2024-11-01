#include "dns-server-test.h"

int32_t sended;
int32_t readed;

int32_t error_count;

const array_hashmap_t *urls_map_struct;

void print_help(void)
{
    printf("Commands:\n"
           "-listen 0.0.0.0:00            Listen address\n");
    exit(EXIT_FAILURE);
}

uint32_t djb33_hash_len(const char *s, size_t len)
{
    uint32_t h = 5381;
    while (*s && len--) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}

int32_t get_url_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                            memory_t *url)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t url_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 1;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (url_len >= (int32_t)url->max_size) {
                        return 2;
                    }
                    url->data[url_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return 3;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > 100) {
                    return 4;
                }
            } else {
                return 5;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 6;
            }
            if (url_len >= (int32_t)url->max_size) {
                return 7;
            }
            url->data[url_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (url_len >= (int32_t)url->max_size) {
        return 8;
    }
    url->data[url_len] = 0;
    url->size = url_len;

    return 0;
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

static uint32_t add_url_hash(const void *void_elem)
{
    const url_data_t *elem = void_elem;
    return djb33_hash_len(elem->url, -1);
}

static int32_t add_url_cmp(const void *void_elem1, const void *void_elem2)
{
    const url_data_t *elem1 = void_elem1;
    const url_data_t *elem2 = void_elem2;

    return !strcmp(elem1->url, elem2->url);
}

static uint32_t find_url_hash(const void *void_elem)
{
    const char *elem = void_elem;
    return djb33_hash_len(elem, -1);
}

static int32_t find_url_cmp(const void *void_elem1, const void *void_elem2)
{
    const char *elem1 = void_elem1;
    const url_data_t *elem2 = void_elem2;

    return !strcmp(elem1, elem2->url);
}

int32_t main(int32_t argc, char *argv[])
{
    FILE *cache_fp;

    uint32_t listen_ip;
    uint16_t listen_port;

    struct sockaddr_in listen_addr, client_addr;
    int32_t listen_socket;

    uint32_t client_addr_length = sizeof(client_addr);

    printf("\nDNS server test started\n");

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-listen")) {
            if (i != argc - 1) {
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &listen_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_ip = inet_addr(argv[i + 1]);
                        struct in_addr listen_ip_in_addr;
                        listen_ip_in_addr.s_addr = listen_ip;
                        printf("Listen %s:%hu\n", inet_ntoa(listen_ip_in_addr), listen_port);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if (listen_ip == 0) {
        printf("Programm need listen IP\n");
        print_help();
    }

    if (listen_port == 0) {
        printf("Programm need listen port\n");
        print_help();
    }

    printf("\n");

    cache_fp = fopen("cache.data", "r");
    if (!cache_fp) {
        printf("Error opening file cache.data\n");
        return 0;
    }

    memory_t cache_data;

    fseek(cache_fp, 0, SEEK_END);
    cache_data.size = ftell(cache_fp);
    fseek(cache_fp, 0, SEEK_SET);

    cache_data.data = (char *)malloc(cache_data.size);

    if (fread(cache_data.data, sizeof(char), cache_data.size, cache_fp) !=
        (size_t)cache_data.size) {
        printf("Can't read cache.data file\n");
        exit(EXIT_FAILURE);
    }

    urls_map_struct = init_array_hashmap(1000000, 1.0, sizeof(url_data_t));
    if (urls_map_struct == NULL) {
        printf("No free memory for urls_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(urls_map_struct, add_url_hash, add_url_cmp, find_url_hash, find_url_cmp);

    char *cur_pos_ptr = cache_data.data;
    char *cache_data_end = cache_data.data + cache_data.size;

    while (cur_pos_ptr < cache_data_end) {
        char *url_data = cur_pos_ptr;
        int32_t url_len = strlen(cur_pos_ptr);

        cur_pos_ptr += url_len + 1;
        int32_t *packet_size = (int32_t *)cur_pos_ptr;

        url_data_t add_elem;
        add_elem.packet = cur_pos_ptr + sizeof(int32_t);
        add_elem.packet_size = *packet_size;
        add_elem.url = url_data;

        array_hashmap_add_elem(urls_map_struct, &add_elem, NULL, NULL);

        cur_pos_ptr += *packet_size + sizeof(int32_t);
    }

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(listen_port);
    listen_addr.sin_addr.s_addr = listen_ip;

    listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket < 0) {
        printf("Error:Error while creating socket %s\n", strerror(errno));
        return 0;
    }

    if (bind(listen_socket, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        printf("Error:Couldn't bind to the port %s\n", strerror(errno));
        return 0;
    }

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        printf("No free memory for receive_msg from client\n");
        exit(EXIT_FAILURE);
    }

    memory_t que_url;
    que_url.size = 0;
    que_url.max_size = URL_MAX_SIZE;
    que_url.data = (char *)malloc(que_url.max_size * sizeof(char));
    if (que_url.data == 0) {
        printf("No free memory for que_url\n");
        exit(EXIT_FAILURE);
    }

    pthread_t stat_thread;
    if (pthread_create(&stat_thread, NULL, stat, NULL)) {
        printf("Can't create stat_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(stat_thread)) {
        printf("Can't detach stat_thread\n");
        exit(EXIT_FAILURE);
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

        // QUE URL
        char *que_url_start = cur_pos_ptr;
        char *que_url_end = NULL;
        if (get_url_from_packet(&receive_msg, que_url_start, &que_url_end, &que_url) != 0) {
            error_count++;
            continue;
        }
        cur_pos_ptr = que_url_end;

        url_data_t res_elem;
        int32_t find_res;
        find_res = array_hashmap_find_elem(urls_map_struct, que_url.data + 1, &res_elem);
        if (find_res == 1) {
            dns_header_t *send_header = (dns_header_t *)res_elem.packet;
            send_header->id = header->id;

            if (sendto(listen_socket, res_elem.packet, res_elem.packet_size, 0,
                       (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                printf("Can't send to client :%s\n", strerror(errno));
                error_count++;
            } else {
                sended++;
            }
        } else {
            error_count++;
        }
    }

    return 0;
}
