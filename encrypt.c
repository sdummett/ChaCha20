#include "chacha20.h"

uint8_t *read_entire_file(const char *filename, size_t *out_size)
{
	char error_msg[256];
	FILE *fp = fopen(filename, "rb"); // Open in binary mode
	if (!fp)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Opening file %s failed", filename);
		perror(error_msg);
		return NULL;
	}

	// Seek to end to find size
	if (fseek(fp, 0, SEEK_END) != 0)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Seeking file %s failed", filename);
		perror(error_msg);
		fclose(fp);
		return NULL;
	}

	long size = ftell(fp);
	if (size < 0)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Telling file %s failed", filename);
		perror(error_msg);
		fclose(fp);
		return NULL;
	}

	rewind(fp); // Go back to start of file

	uint8_t *buffer = malloc(size);
	if (!buffer)
	{
		perror("[-] Allocating memory failed");
		fclose(fp);
		return NULL;
	}

	size_t read_size = fread(buffer, 1, size, fp);
	if (read_size != (size_t)size)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Reading file %s failed", filename);
		perror(error_msg);
		free(buffer);
		fclose(fp);
		return NULL;
	}

	fclose(fp);

	if (out_size)
		*out_size = size;

	return buffer;
}

int get_key(const char *key_file, uint8_t key[32])
{
	size_t keylen;
	uint8_t *buf = read_entire_file(key_file, &keylen);
	if (!buf)
		return 0;

	if (keylen != 32)
	{
		fprintf(stderr, "The provided key must be exactly 32 bytes long.\n");
		free(buf);
		return 0;
	}

	memcpy(key, buf, keylen);
	free(buf);

	return 1;
}

uint8_t *get_file_data(const char *input_file, size_t *data_len)
{

	uint8_t *file_data = read_entire_file(input_file, data_len);
	if (!file_data)
		return NULL;

	if (*data_len == 0)
	{
		fprintf(stderr, "The provided input file must not be empty\n");
		free(file_data);
		return NULL;
	}

	return file_data;
}

int encrypt(program_options_t *options)
{
	char error_msg[256];
	uint8_t key[32];

	if (!get_key(options->key_file, key))
		return 1;

	size_t data_len;
	uint8_t *file_data = get_file_data(options->input_file, &data_len);
	if (!file_data)
		return 1;

	int fd = open(options->output_file, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (fd < 0)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Opening file %s failed", options->output_file);
		perror(error_msg);
		free(file_data);
		return 1;
	}

	// generate a random nonce
	uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
	// generate_random_nonce(nonce);

	// what about the block counter ?
	// Is it constantly starting at 1 ?
	// Is it user defined ?
	uint32_t block_counter = 1;

	// open the output file

	printf("[+] Encrypting file %s into %s\n", options->input_file, options->output_file);
	// read the file containing the file_data to encrypt
	uint8_t *ciphertext = chacha20_core(key, block_counter, nonce, file_data, data_len);
	if (!ciphertext)
	{
		fprintf(stderr, "[-] Function chacha20_core failed\n");
		free(file_data);
		return 1;
	}

	free(file_data);

	// the format of the encrypted file is:
	// |  uint8_t[12] |  uint8_t[]  |
	// |    nonce     |  ciphertext |

	int ret = write(fd, ciphertext, data_len);
	if (ret < 0)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Writing to file %s failed", options->output_file);
		perror(error_msg);
		free(ciphertext);
		exit(45);
	}

	free(ciphertext);

	return 0;
}
