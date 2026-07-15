#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

// === chacha20 core function === //

uint8_t *chacha20_crypt(uint8_t key[32], uint32_t block_counter, uint8_t nonce[12], uint8_t *data, size_t data_len);

// ============================== //

// === The actual program === //
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
int encrypt_decrypt(program_options_t *options);

// === Helpers === //
uint8_t *get_file_data(const char *input_file, size_t *data_len);
int get_key(const char *key_file, uint8_t key[32]);
uint8_t *read_entire_file(const char *filename, size_t *out_size);

#endif
