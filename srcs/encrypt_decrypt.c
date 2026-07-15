#include "chacha20.h"

int encrypt_decrypt(program_options_t *options)
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
		snprintf(error_msg, sizeof(error_msg), "[-] Opening file '%s' failed", options->output_file);
		perror(error_msg);
		free(file_data);
		return 1;
	}

	uint8_t nonce[12];
	if (options->mode == MODE_DECRYPT)
	{
		if (data_len < sizeof(nonce))
		{
			fprintf(stderr, "[-] The file doesnt contain any nonce");
			free(file_data);
			return 1;
		}
		memcpy(nonce, file_data, sizeof(nonce));
		data_len -= sizeof(nonce);
	}
	else
	{
		// generate a random nonce
		srand(time(NULL));
		for (int i = 0; i < sizeof(int) * 3; i += sizeof(int))
		{
			int pseudo_random_number = rand();
			memcpy(nonce + i, &pseudo_random_number, sizeof(pseudo_random_number));
		}

		// generate_random_nonce(nonce);
	}

	// what about the block counter ?
	// Is it constantly starting at 1 ?
	// Is it user defined ?
	uint32_t block_counter = 1;

	// open the output file

	if (options->mode == MODE_ENCRYPT)
		printf("[+] Encrypting file '%s' into '%s'\n", options->input_file, options->output_file);
	else
		printf("[+] Decrypting file '%s' into '%s'\n", options->input_file, options->output_file);

	// read the file containing the file_data to encrypt
	size_t offset = 0;
	if (options->mode == MODE_DECRYPT)
		offset = sizeof(nonce);

	uint8_t *ciphertext = chacha20_crypt(key, block_counter, nonce, file_data + offset, data_len);
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

	if (options->mode == MODE_ENCRYPT)
	{
		// write the nonce
		if (write(fd, nonce, sizeof(nonce)) < 0)
		{
			snprintf(error_msg, sizeof(error_msg), "[-] Writing to file '%s' failed", options->output_file);
			perror(error_msg);
			free(ciphertext);
			return 1;
		}
	}

	if (write(fd, ciphertext, data_len) < 0)
	{
		snprintf(error_msg, sizeof(error_msg), "[-] Writing to file '%s' failed", options->output_file);
		perror(error_msg);
		free(ciphertext);
		return 1;
	}

	free(ciphertext);

	if (options->mode == MODE_ENCRYPT)
		printf("[+] Encryption done\n");
	else
		printf("[+] Decryption done\n");

	return 0;
}
