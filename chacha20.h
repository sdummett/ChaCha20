#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// === chacha20 core === //

void print_state(uint32_t state[16]);
void print_bytes(uint8_t *block, uint8_t len);
void chacha20_block(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t keystream_block[64]);
uint8_t *chacha20_core(uint8_t key[32], uint32_t block_counter, uint8_t nonce[12], uint8_t *data, size_t data_len);

// ===================== //

#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#define DEFAULT_OUTPUT_FILE "data.chacha20"

typedef enum e_mode
{
	MODE_NONE,
	MODE_ENCRYPT,
	MODE_DECRYPT
} mode__t;

typedef struct s_program_options
{
	mode__t mode;
	const char *input_file;
	const char *output_file;
	const char *key_file;
} program_options_t;

int parse_args(int ac, char *av[], program_options_t *options);
int encrypt(program_options_t *options);

#endif
