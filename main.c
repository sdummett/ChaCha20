#include "chacha20.h"

void xor(uint8_t *input_block, uint8_t *keystream_block, uint8_t *output, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		output[i] = input_block[i] ^ keystream_block[i];
	}
}

uint8_t *chacha20_core(uint8_t key[32], uint32_t block_counter, uint8_t nonce[12], uint8_t *data, size_t data_len)
{
	uint8_t *output = malloc(data_len);
	if (!output)
	{
		printf("malloc failed\n");
		return NULL;
	}

	size_t num_blocks = (data_len + 63) / 64;
	// printf("[+] number of blocks = %ld\n", num_blocks);

	for (size_t j = 0; j < num_blocks; j++)
	{
		size_t offset = j * 64;
		size_t block_len = (data_len - offset >= 64) ? 64 : (data_len - offset);
		printf("[+] block length: %ld\n", block_len);

		uint8_t keystream_block[64] = {0};
		chacha20_block(key, block_counter + j, nonce, keystream_block);
		printf("[+] Serialized block:\n");
		print_bytes(keystream_block, 64);

		// printf("\n[+] keystream:\n");
		// print_bytes(keystream, 64);

		uint8_t *block = &data[offset];
		xor(block, keystream_block, output + offset, block_len);

		// block_len = nombre d'octets à traiter dans ce bloc (utile pour le dernier bloc)
	}
	return output;
}

uint8_t *decrypt(uint8_t key[32], uint32_t block_counter, uint8_t nonce[12], uint8_t *data, size_t data_len)
{
	return chacha20_core(key, block_counter, nonce, data, data_len);
}

int main(int ac, char *av[])
{
	program_options_t options;
	if (!parse_args(ac, av, &options))
		return 1;

	if (options.mode == MODE_ENCRYPT)
	{
		return encrypt(&options);
	}
	if (options.mode == MODE_DECRYPT)
	{
		printf("[+] Decrypting file %s into %s\n", options.input_file, options.output_file);
		// decrypt();
	}

	return 0;
}
