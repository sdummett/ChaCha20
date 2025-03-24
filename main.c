#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint32_t chacha_state[16] = {0};

void init_chacha_state(uint32_t constants[4], uint8_t key[32], uint32_t counter, uint8_t nonce[12])
{
	// The first four words (0-3) are constants
	chacha_state[0] = constants[0];
	chacha_state[1] = constants[1];
	chacha_state[2] = constants[2];
	chacha_state[3] = constants[3];

	// The next eight words (4-11) are taken from the 256-bit key by
	// reading the bytes in little-endian order, in 4-byte chunks
	for (uint8_t i = 0; i < 8; i++)
	{
		chacha_state[i + 4] = ((uint32_t)key[i * 4]) |
							  ((uint32_t)key[i * 4 + 1] << 8) |
							  ((uint32_t)key[i * 4 + 2] << 16) |
							  ((uint32_t)key[i * 4 + 3] << 24);
	}

	// Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
	// word is enough for 256 gigabytes of data
	chacha_state[12] = counter;

	// Words 13-15 are a nonce, which should not be repeated for the same
	// key.  The 13th word is the first 32 bits of the input nonce taken
	// as a little-endian integer, while the 15th word is the last 32
	// bits
	for (int i = 0; i < 3; i++)
	{
		chacha_state[i + 13] = ((uint32_t)nonce[i * 4]) |
							   ((uint32_t)nonce[i * 4 + 1] << 8) |
							   ((uint32_t)nonce[i * 4 + 2] << 16) |
							   ((uint32_t)nonce[i * 4 + 3] << 24);
	}
}

void print_state(uint32_t state[16])
{
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0)
			printf("\n");
		printf("%08x ", state[i]);
	}
	printf("\n");
}

void Qround(uint32_t state[16], uint8_t x, uint8_t y, uint8_t z, uint8_t w)
{
	uint32_t a = state[x];
	uint32_t b = state[y];
	uint32_t c = state[z];
	uint32_t d = state[w];

	// printf("[+] Doing a quarter round on indexes: x = %u, y = %u, z = %u, w = %u\n", x, y, z, w);

	a += b; d ^= a; d = (d << 16) | (d >> (32 - 16));
	c += d; b ^= c; b = (b << 12) | (b >> (32 - 12));
	a += b; d ^= a; d = (d << 8) | (d >> (32 - 8));
	c += d;	b ^= c;	b = (b << 7) | (b >> (32 - 7));

	state[x] = a;
	state[y] = b;
	state[z] = c;
	state[w] = d;
}

void inner_block(uint32_t state[16])
{
	Qround(state, 0, 4, 8, 12);
	Qround(state, 1, 5, 9, 13);
	Qround(state, 2, 6, 10, 14);
	Qround(state, 3, 7, 11, 15);
	Qround(state, 0, 5, 10, 15);
	Qround(state, 1, 6, 11, 12);
	Qround(state, 2, 7, 8, 13);
	Qround(state, 3, 4, 9, 14);
}

void add(uint32_t original_state[16], uint32_t working_state[16])
{
	for (uint8_t i = 0; i < 16; i++)
	{
		original_state[i] += working_state[i];
	}
}

void serialize_uint32_le(const uint32_t input[16], uint8_t output[64])
{
	for (int i = 0; i < 16; i++)
	{
		output[i * 4] = (uint8_t)(input[i] & 0xFF);
		output[i * 4 + 1] = (uint8_t)((input[i] >> 8) & 0xFF);
		output[i * 4 + 2] = (uint8_t)((input[i] >> 16) & 0xFF);
		output[i * 4 + 3] = (uint8_t)((input[i] >> 24) & 0xFF);
	}
}

void print_serialized_block(uint8_t block[64])
{
	for (uint8_t i = 0; i < 64; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", block[i]);
	}
	printf("\n");
}

int main()
{
	uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
	uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	uint32_t block_counter = 1;
	uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

	init_chacha_state(constants, key, block_counter, nonce);
	printf("[+] chacha_state:\n");
	print_state(chacha_state);

	uint32_t working_state[16] = {0};
	memcpy(working_state, chacha_state, 64);

	printf("[+] working_state: \n");
	print_state(working_state);

	for (uint8_t i = 0; i < 10; i++)
	{
		inner_block(working_state);
	}

	printf("[+] chacha state after 20 rounds:\n");
	print_state(working_state);

	add(chacha_state, working_state);
	printf("[+] chacha_state at the end of the ChaCha20 operation:\n");
	print_state(chacha_state);

	uint8_t serialized_block[64] = {0};
	serialize_uint32_le(chacha_state, serialized_block);
	printf("[+] serialized block:\n");
	print_serialized_block(serialized_block);

	return 0;
}
