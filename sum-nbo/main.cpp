#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

uint32_t read_number_from_file(const char *filename) {
	FILE *file = fopen(filename, "rb");
        if (!file) {
	        fprintf(stderr, "Error: Could not open file %s\n", filename);
		exit(EXIT_FAILURE);
	}
	uint32_t num;
	size_t read_size = fread(&num, sizeof(uint32_t), 1, file);
	fclose(file);
	if (read_size != 1) {
	        fprintf(stderr, "Error: Failed to read 4 bytes from file %s\n", filename);
	        exit(EXIT_FAILURE);
        }
	return ntohl(num);
}
int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <file1> [<file2> ...]\n", argv[0]);
		return EXIT_FAILURE;
	}
	uint32_t sum = 0;
	for (int i = 1; i < argc; i++) {
		uint32_t num = read_number_from_file(argv[i]);
		printf("%u(0x%04x)%s", num, num, (i == argc - 1) ? " = " : " + ");
		sum += num;
	}
	printf("%u(0x%04x)\n", sum, sum);
	return EXIT_SUCCESS;
}
