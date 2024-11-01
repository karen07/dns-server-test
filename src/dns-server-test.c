#include "dns-server-test.h"

void print_help(void)
{
    printf("Commands:\n"
           "-listen 0.0.0.0:00            Listen address\n");
    exit(EXIT_FAILURE);
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

memory_t get_url(memory_t *cache_data, char *url)
{
    char *cur_pos_ptr = cache_data->data;
    char *cache_data_end = cache_data->data + cache_data->size;

    memory_t res;

    while (cur_pos_ptr < cache_data_end) {
        char *url_data = cur_pos_ptr;
        int32_t url_len = strlen(cur_pos_ptr);

        cur_pos_ptr += url_len + 1;
        int32_t *packet_size = (int32_t *)cur_pos_ptr;

        if (!strcmp(url, url_data)) {
            res.data = cur_pos_ptr + sizeof(int32_t);
            res.size = *packet_size;

            return res;
        }

        cur_pos_ptr += *packet_size + sizeof(int32_t);
    }

    res.data = NULL;
    res.size = 0;

    return res;
}

int32_t main(int32_t argc, char *argv[])
{
    FILE *cache_fp;

    uint32_t listen_ip;
    uint16_t listen_port;

    struct sockaddr_in listen_addr, client_addr;
    int32_t listen_socket;

    uint32_t client_addr_length = sizeof(client_addr);

    printf("\nDNS perftest started\n");

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

    memory_t test_get;
    test_get = get_url(&cache_data, "itmaher.net");
    if (test_get.data) {
        printf("Finded itmaher.net\n");
    }

    test_get = get_url(&cache_data, "itmaher1.net");
    if (!test_get.data) {
        printf("Not Finded itmaher1.net\n");
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

    while (true) {
        receive_msg.size = recvfrom(listen_socket, receive_msg.data, receive_msg.max_size, 0,
                                    (struct sockaddr *)&client_addr, &client_addr_length);

        char *cur_pos_ptr = receive_msg.data;
        char *receive_msg_end = receive_msg.data + receive_msg.size;

        // DNS HEADER
        if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
            continue;
        }

        dns_header_t *header = (dns_header_t *)cur_pos_ptr;

        uint16_t first_bit_mark = FIRST_BIT_UINT16;
        uint16_t flags = ntohs(header->flags);
        if ((flags & first_bit_mark) == first_bit_mark) {
            continue;
        }

        uint16_t quest_count = ntohs(header->quest);
        if (quest_count != 1) {
            continue;
        }

        cur_pos_ptr += sizeof(dns_header_t);
        // DNS HEADER

        // QUE URL
        char *que_url_start = cur_pos_ptr;
        char *que_url_end = NULL;
        if (get_url_from_packet(&receive_msg, que_url_start, &que_url_end, &que_url) != 0) {
            continue;
        }
        cur_pos_ptr = que_url_end;

        memory_t send_data;
        send_data = get_url(&cache_data, que_url.data + 1);

        if (send_data.data) {
            dns_header_t *send_header = (dns_header_t *)send_data.data;
            send_header->id = header->id;

            if (sendto(listen_socket, send_data.data, send_data.size, 0,
                       (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                printf("Can't send to client :%s\n", strerror(errno));
            }
        }
    }

    printf("Min:Sec Send_RPS Read_RPS Sended Readed Diff \n");
    while (true) {
        sleep(1);

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("%d:%d\n", tm_struct->tm_min, tm_struct->tm_sec);
    }

    return 0;
}
