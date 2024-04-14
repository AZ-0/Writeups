#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "wb-aes.h"

int
main(int argc, char **argv)
{
	FILE *fp;
	WB_AES_KEY key;
	uint8_t out[16];
	uint8_t in[16];

	if (argc != 2) {
		printf("Usage: %s <keys.bin>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	key.key = fp;
	key.size = 16;

	memset(in, 0, sizeof(in));
	int nbRead = read(STDIN_FILENO, in, sizeof(in));
	if (nbRead < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	wb_aes_encrypt(out, in, &key);

	for (int i = 0; i < 16; ++i) {
		printf("%02x", out[i]);
	}
	printf("\n");

	if (fclose(fp) != 0) {
		perror("fclose");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
