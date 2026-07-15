#include "chacha20.h"

void chacha20_print_state(uint32_t state[16])
{
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0 && i != 0)
			printf("\n");
		printf("%08x ", state[i]);
	}
	printf("\n");
}

void chacha20_print_bytes(uint8_t *block, uint8_t len)
{
	for (uint8_t i = 0; i < len; i++)
	{
		if (i % 16 == 0 && i != 0)
			printf("\n");
		printf("%02x ", block[i]);
	}
	printf("\n");
}

static void chacha20_init_state(uint32_t constants[4], uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint32_t state[16])
{
	// The first four words (0-3) are constants
	state[0] = constants[0];
	state[1] = constants[1];
	state[2] = constants[2];
	state[3] = constants[3];

	// The next eight words (4-11) are taken from the 256-bit key by
	// reading the bytes in little-endian order, in 4-byte chunks
	for (uint8_t i = 0; i < 8; i++)
	{
		state[i + 4] = ((uint32_t)key[i * 4]) |
					   ((uint32_t)key[i * 4 + 1] << 8) |
					   ((uint32_t)key[i * 4 + 2] << 16) |
					   ((uint32_t)key[i * 4 + 3] << 24);
	}

	// Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
	// word is enough for 256 gigabytes of data
	state[12] = counter;

	// Words 13-15 are a nonce, which should not be repeated for the same
	// key.  The 13th word is the first 32 bits of the input nonce taken
	// as a little-endian integer, while the 15th word is the last 32
	// bits
	for (int i = 0; i < 3; i++)
	{
		state[i + 13] = ((uint32_t)nonce[i * 4]) |
						((uint32_t)nonce[i * 4 + 1] << 8) |
						((uint32_t)nonce[i * 4 + 2] << 16) |
						((uint32_t)nonce[i * 4 + 3] << 24);
	}
}

static void chacha20_quarter_round(uint32_t state[16], uint8_t x, uint8_t y, uint8_t z, uint8_t w)
{
	uint32_t a = state[x];
	uint32_t b = state[y];
	uint32_t c = state[z];
	uint32_t d = state[w];

	// printf("[+] Doing a quarter round on indexes: x = %u, y = %u, z = %u, w = %u\n", x, y, z, w);

	a += b; d ^= a; d = (d << 16) | (d >> (32 - 16));
	c += d; b ^= c; b = (b << 12) | (b >> (32 - 12));
	a += b; d ^= a; d = (d << 8)  | (d >> (32 - 8));
	c += d; b ^= c; b = (b << 7)  | (b >> (32 - 7));

	state[x] = a;
	state[y] = b;
	state[z] = c;
	state[w] = d;
}

static void chacha20_double_round(uint32_t state[16])
{
	chacha20_quarter_round(state, 0, 4, 8, 12);
	chacha20_quarter_round(state, 1, 5, 9, 13);
	chacha20_quarter_round(state, 2, 6, 10, 14);
	chacha20_quarter_round(state, 3, 7, 11, 15);
	chacha20_quarter_round(state, 0, 5, 10, 15);
	chacha20_quarter_round(state, 1, 6, 11, 12);
	chacha20_quarter_round(state, 2, 7, 8, 13);
	chacha20_quarter_round(state, 3, 4, 9, 14);
}

static void chacha20_xor_block(uint8_t *input_block, uint8_t *keystream_block, uint8_t *output, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		output[i] = input_block[i] ^ keystream_block[i];
	}
}

static void chacha20_add_states(uint32_t original_state[16], uint32_t working_state[16])
{
	for (uint8_t i = 0; i < 16; i++)
	{
		original_state[i] += working_state[i];
	}
}

static void chacha20_serialize_uint32_le(const uint32_t input[16], uint8_t output[64])
{
	for (int i = 0; i < 16; i++)
	{
		output[i * 4] = (uint8_t)(input[i] & 0xFF);
		output[i * 4 + 1] = (uint8_t)((input[i] >> 8) & 0xFF);
		output[i * 4 + 2] = (uint8_t)((input[i] >> 16) & 0xFF);
		output[i * 4 + 3] = (uint8_t)((input[i] >> 24) & 0xFF);
	}
}

static void chacha20_generate_block(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t keystream_block[64])
{
	uint32_t CHACHA20_CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

	uint32_t state[16] = {0};
	chacha20_init_state(CHACHA20_CONSTANTS, key, counter, nonce, state);
	// printf("[+] state:\n");
	// print_state(state);

	uint32_t working_state[16] = {0};
	memcpy(working_state, state, 64);

	// printf("\n[+] working_state: \n");
	// print_state(working_state);

	for (uint8_t i = 0; i < 10; i++)
	{
		chacha20_double_round(working_state);
	}

	// printf("\n[+] state after 20 rounds:\n");
	// print_state(working_state);

	chacha20_add_states(state, working_state);
	// printf("\n[+] state at the end of the ChaCha20 operation:\n");
	// print_state(state);

	chacha20_serialize_uint32_le(state, keystream_block);
}

uint8_t *chacha20_crypt(uint8_t key[32], uint32_t block_counter, uint8_t nonce[12], uint8_t *data, size_t data_len)
{
	uint8_t *output = malloc(data_len);
	if (!output)
		return NULL;

	size_t num_blocks = (data_len + 63) / 64;
	// printf("[+] number of blocks = %ld\n", num_blocks);

	for (size_t j = 0; j < num_blocks; j++)
	{
		size_t offset = j * 64;
		size_t block_len = (data_len - offset >= 64) ? 64 : (data_len - offset);
		// printf("[+] block length: %ld\n", block_len);

		uint8_t keystream_block[64] = {0};
		chacha20_generate_block(key, block_counter + j, nonce, keystream_block);
		// printf("[+] Serialized block:\n");
		// print_bytes(keystream_block, 64);

		// printf("\n[+] keystream:\n");
		// print_bytes(keystream, 64);

		uint8_t *block = &data[offset];
		chacha20_xor_block(block, keystream_block, output + offset, block_len);

		// block_len = nombre d'octets à traiter dans ce bloc (utile pour le dernier bloc)
	}
	return output;
}
