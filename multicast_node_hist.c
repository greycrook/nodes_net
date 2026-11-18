#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_GROUP "239.1.1.1"
#define DEFAULT_PORT 5000
#define DEFAULT_ITERATIONS 1000
#define WARMUP_ITERATIONS 100
#define MAX_NODES 10
#define WINDOW_SIZE 64
#define START_DELAY_SECONDS 10
#define RECEIVE_TIMEOUT_SECONDS 5

typedef struct __attribute__((packed)) {
    uint32_t node_id;
    uint32_t sequence;
    uint64_t value;
} Packet;

typedef struct {
    uint32_t sequence;
    uint64_t value;
    int valid;
} CachedPacket;

static uint64_t now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * 1000000ULL +
           (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t random_value(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

#define HISTOGRAM_BUCKETS 8

static void print_histogram(const uint64_t *latencies, uint32_t count) {
    static const uint64_t upper_bounds[HISTOGRAM_BUCKETS - 1] = {
        10, 25, 50, 100, 200, 500, 1000
    };
    static const char *labels[HISTOGRAM_BUCKETS] = {
        "<=10", "11-25", "26-50", "51-100",
        "101-200", "201-500", "501-1000", ">1000"
    };

    uint32_t bins[HISTOGRAM_BUCKETS] = {0};
    uint32_t max_bin = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t bin = 0;
        while (bin < HISTOGRAM_BUCKETS - 1 &&
               latencies[i] > upper_bounds[bin]) {
            bin++;
        }
        bins[bin]++;
        if (bins[bin] > max_bin) max_bin = bins[bin];
    }

    printf("\nRound-duration histogram (microseconds)\n");
    printf("Range       Count   Percent  Distribution\n");
    printf("------------------------------------------------\n");

    for (uint32_t i = 0; i < HISTOGRAM_BUCKETS; i++) {
        uint32_t bar_width = (uint32_t)(
            ((uint64_t)bins[i] * 40ULL) / max_bin
        );

        printf("%-10s %7" PRIu32 " %7.2f%%  ",
               labels[i], bins[i],
               100.0 * (double)bins[i] / (double)count);

        for (uint32_t j = 0; j < bar_width; j++) putchar('#');
        putchar('\n');
    }
}

static void die(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

static int create_multicast_socket(
    const char *group,
    int port,
    const char *interface_ip,
    struct sockaddr_in *destination
) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) die("socket");

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse)) < 0) {
        die("setsockopt(SO_REUSEADDR)");
    }

    int receive_buffer = 1024 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                   &receive_buffer, sizeof(receive_buffer)) < 0) {
        die("setsockopt(SO_RCVBUF)");
    }

    struct timeval timeout = {
        .tv_sec = RECEIVE_TIMEOUT_SECONDS,
        .tv_usec = 0
    };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) < 0) {
        die("setsockopt(SO_RCVTIMEO)");
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons((uint16_t)port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        die("bind");
    }

    struct ip_mreq membership;
    memset(&membership, 0, sizeof(membership));

    if (inet_pton(AF_INET, group, &membership.imr_multiaddr) != 1) {
        fprintf(stderr, "Invalid multicast group address: %s\n", group);
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (!IN_MULTICAST(ntohl(membership.imr_multiaddr.s_addr))) {
        fprintf(stderr, "%s is not an IPv4 multicast address\n", group);
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (interface_ip != NULL) {
        if (inet_pton(AF_INET, interface_ip,
                      &membership.imr_interface) != 1) {
            fprintf(stderr, "Invalid interface IPv4 address: %s\n",
                    interface_ip);
            close(sock);
            exit(EXIT_FAILURE);
        }
    } else {
        membership.imr_interface.s_addr = htonl(INADDR_ANY);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &membership, sizeof(membership)) < 0) {
        die("setsockopt(IP_ADD_MEMBERSHIP)");
    }

    unsigned char loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &loop, sizeof(loop)) < 0) {
        die("setsockopt(IP_MULTICAST_LOOP)");
    }

    unsigned char ttl = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   &ttl, sizeof(ttl)) < 0) {
        die("setsockopt(IP_MULTICAST_TTL)");
    }

    if (interface_ip != NULL) {
        struct in_addr outgoing_interface;
        if (inet_pton(AF_INET, interface_ip, &outgoing_interface) != 1) {
            fprintf(stderr, "Invalid outgoing interface IPv4 address\n");
            close(sock);
            exit(EXIT_FAILURE);
        }

        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
                       &outgoing_interface,
                       sizeof(outgoing_interface)) < 0) {
            die("setsockopt(IP_MULTICAST_IF)");
        }
    }

    memset(destination, 0, sizeof(*destination));
    destination->sin_family = AF_INET;
    destination->sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, group, &destination->sin_addr) != 1) {
        fprintf(stderr, "Invalid multicast group address\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

/*
 * Each node sends one datagram per round and waits until it has
 * received one datagram from every node for that same round.
 *
 * A small per-sender cache keeps packets from a slightly faster
 * node if they arrive before this node starts the next round.
 */
static int run_round(
    int sock,
    const struct sockaddr_in *destination,
    uint32_t node_id,
    uint32_t node_count,
    uint32_t sequence,
    uint64_t own_value,
    CachedPacket cache[MAX_NODES][WINDOW_SIZE],
    uint64_t *sum_out,
    uint64_t *latency_out
) {
    uint8_t received[MAX_NODES] = {0};
    uint64_t values[MAX_NODES] = {0};
    uint32_t received_count = 0;

    uint64_t start = now_us();

    Packet outgoing;
    outgoing.node_id = htonl(node_id);
    outgoing.sequence = htonl(sequence);
    outgoing.value = htobe64(own_value);

    ssize_t sent = sendto(
        sock,
        &outgoing,
        sizeof(outgoing),
        0,
        (const struct sockaddr *)destination,
        sizeof(*destination)
    );

    if (sent != (ssize_t)sizeof(outgoing)) {
        if (sent < 0) perror("sendto");
        else fprintf(stderr, "sendto: incomplete datagram\n");
        return -1;
    }

    while (received_count < node_count) {
        /* First consume any packet for this round already in the cache. */
        for (uint32_t sender = 0; sender < node_count; sender++) {
            CachedPacket *slot =
                &cache[sender][sequence % WINDOW_SIZE];

            if (!received[sender] && slot->valid &&
                slot->sequence == sequence) {
                received[sender] = 1;
                values[sender] = slot->value;
                slot->valid = 0;
                received_count++;
            }
        }

        if (received_count == node_count) break;

        Packet incoming;
        ssize_t bytes = recvfrom(sock, &incoming, sizeof(incoming),
                                 0, NULL, NULL);

        if (bytes < 0) {
            if (errno == EINTR) continue;

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr,
                        "\nTimeout on node %" PRIu32
                        ", round %" PRIu32
                        ": received %" PRIu32 "/%" PRIu32
                        " nodes\n",
                        node_id, sequence, received_count, node_count);
                return -1;
            }

            perror("recvfrom");
            return -1;
        }

        if (bytes != (ssize_t)sizeof(Packet)) continue;

        uint32_t sender = ntohl(incoming.node_id);
        uint32_t packet_sequence = ntohl(incoming.sequence);
        uint64_t value = be64toh(incoming.value);

        if (sender >= node_count) continue;
        if (packet_sequence < sequence) continue;

        if (packet_sequence - sequence >= WINDOW_SIZE) {
            fprintf(stderr,
                    "Node %" PRIu32 ": packet window exceeded "
                    "(current=%" PRIu32 ", received=%" PRIu32 ")\n",
                    node_id, sequence, packet_sequence);
            return -1;
        }

        CachedPacket *slot =
            &cache[sender][packet_sequence % WINDOW_SIZE];

        if (packet_sequence == sequence) {
            if (!received[sender]) {
                received[sender] = 1;
                values[sender] = value;
                received_count++;
            }
        } else {
            /* Save a future-round packet instead of discarding it. */
            if (!slot->valid || slot->sequence < packet_sequence) {
                slot->sequence = packet_sequence;
                slot->value = value;
                slot->valid = 1;
            }
        }
    }

    uint64_t sum = 0;
    for (uint32_t i = 0; i < node_count; i++) {
        sum += values[i];
    }

    uint64_t end = now_us();

    *sum_out = sum;
    *latency_out = end - start;
    return 0;
}

static void print_usage(const char *program) {
    printf(
        "Usage:\n"
        "  %s <node_id> <node_count> [group] [port] "
        "[iterations] [interface_ipv4]\n\n"
        "Examples:\n"
        "  %s 0 2\n"
        "  %s 1 2\n"
        "  %s 0 10 239.1.1.1 5000 1000\n"
        "  %s 0 2 239.1.1.1 5000 1000 192.168.1.10\n\n"
        "All nodes must use the same node_count, group, port and "
        "iterations.\n",
        program, program, program, program, program
    );
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 7) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char *end = NULL;

    unsigned long parsed_id = strtoul(argv[1], &end, 10);
    if (*argv[1] == '\0' || *end != '\0' || parsed_id >= MAX_NODES) {
        fprintf(stderr, "Invalid node_id (allowed: 0..9)\n");
        return EXIT_FAILURE;
    }

    unsigned long parsed_count = strtoul(argv[2], &end, 10);
    if (*argv[2] == '\0' || *end != '\0' ||
        parsed_count < 2 || parsed_count > MAX_NODES ||
        parsed_id >= parsed_count) {
        fprintf(stderr, "Invalid node_count or node_id\n");
        return EXIT_FAILURE;
    }

    const char *group = argc >= 4 ? argv[3] : DEFAULT_GROUP;

    unsigned long parsed_port = DEFAULT_PORT;
    if (argc >= 5) {
        parsed_port = strtoul(argv[4], &end, 10);
        if (*argv[4] == '\0' || *end != '\0' ||
            parsed_port < 1 || parsed_port > 65535) {
            fprintf(stderr, "Invalid UDP port\n");
            return EXIT_FAILURE;
        }
    }

    unsigned long parsed_iterations = DEFAULT_ITERATIONS;
    if (argc >= 6) {
        parsed_iterations = strtoul(argv[5], &end, 10);
        if (*argv[5] == '\0' || *end != '\0' ||
            parsed_iterations < 1 || parsed_iterations > 10000000) {
            fprintf(stderr, "Invalid iteration count\n");
            return EXIT_FAILURE;
        }
    }

    const char *interface_ip = argc >= 7 ? argv[6] : NULL;

    uint32_t node_id = (uint32_t)parsed_id;
    uint32_t node_count = (uint32_t)parsed_count;
    int port = (int)parsed_port;
    uint32_t iterations = (uint32_t)parsed_iterations;

    struct sockaddr_in destination;
    int sock = create_multicast_socket(
        group, port, interface_ip, &destination
    );

    printf("\nUDP Multicast node\n");
    printf("------------------\n");
    printf("Node ID:      %" PRIu32 "\n", node_id);
    printf("Node count:   %" PRIu32 "\n", node_count);
    printf("Group:        %s:%d\n", group, port);
    printf("Warmup:       %d rounds\n", WARMUP_ITERATIONS);
    printf("Benchmark:    %" PRIu32 " rounds\n", iterations);
    printf("Start delay:  %d seconds\n", START_DELAY_SECONDS);
    if (interface_ip != NULL) {
        printf("Interface:    %s\n", interface_ip);
    }

    CachedPacket cache[MAX_NODES][WINDOW_SIZE] = {{{0}}};

    printf("\nSocket ready. Start all other nodes now.\n");
    printf("Benchmark starts in %d seconds...\n",
           START_DELAY_SECONDS);
    sleep(START_DELAY_SECONDS);

    uint64_t rng_state =
        0x9E3779B97F4A7C15ULL ^
        ((uint64_t)node_id + 1ULL) * 0xD1B54A32D192ED03ULL;

    if (rng_state == 0) rng_state = 1;

    uint64_t result = 0;
    uint64_t latency = 0;

    printf("Warmup started...\n");

    for (uint32_t i = 0; i < WARMUP_ITERATIONS; i++) {
        uint64_t value = random_value(&rng_state);

        if (run_round(sock, &destination, node_id, node_count,
                      i, value, cache, &result, &latency) != 0) {
            fprintf(stderr, "Warmup failed at round %" PRIu32 "\n", i);
            close(sock);
            return EXIT_FAILURE;
        }
    }

    printf("Warmup completed. Benchmark started...\n");

    uint64_t *latencies = calloc(iterations, sizeof(*latencies));
    if (latencies == NULL) {
        perror("calloc");
        close(sock);
        return EXIT_FAILURE;
    }

    uint64_t total = 0;

    for (uint32_t i = 0; i < iterations; i++) {
        uint64_t value = random_value(&rng_state);
        uint32_t sequence = WARMUP_ITERATIONS + i;

        if (run_round(sock, &destination, node_id, node_count,
                      sequence, value, cache,
                      &result, &latency) != 0) {
            fprintf(stderr,
                    "Benchmark failed at round %" PRIu32 "\n",
                    sequence);
            free(latencies);
            close(sock);
            return EXIT_FAILURE;
        }

        latencies[i] = latency;
        total += latency;
    }

    qsort(latencies, iterations, sizeof(*latencies), compare_u64);

    uint64_t min = latencies[0];
    uint64_t max = latencies[iterations - 1];

    /* Median: average the two middle samples when count is even. */
    double median;
    if (iterations % 2 == 0) {
        median = ((double)latencies[iterations / 2 - 1] +
                  (double)latencies[iterations / 2]) / 2.0;
    } else {
        median = (double)latencies[iterations / 2];
    }

    /* Nearest-rank percentiles: ceil(p * N) - 1. */
    uint64_t p95_index = ((uint64_t)iterations * 95ULL + 99ULL) / 100ULL - 1ULL;
    uint64_t p99_index = ((uint64_t)iterations * 99ULL + 99ULL) / 100ULL - 1ULL;
    uint64_t p95 = latencies[p95_index];
    uint64_t p99 = latencies[p99_index];
    double average = (double)total / (double)iterations;

    printf("\nResults for node %" PRIu32 "\n", node_id);
    printf("-------------------------\n");
    printf("Average:       %.2f us\n", average);
    printf("Median:        %.2f us\n", median);
    printf("P95:           %" PRIu64 " us\n", p95);
    printf("P99:           %" PRIu64 " us\n", p99);
    printf("Min:           %" PRIu64 " us\n", min);
    printf("Max:           %" PRIu64 " us\n", max);
    printf("Last sum:      %" PRIu64 "\n", result);
    printf("P95 target:    %s (200 us)\n",
           p95 <= 200 ? "PASS" : "FAIL");

    print_histogram(latencies, iterations);

    free(latencies);
    close(sock);
    return EXIT_SUCCESS;
}
