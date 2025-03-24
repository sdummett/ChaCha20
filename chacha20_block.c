#include "chacha20.h"

void init_state(uint32_t constants[4], uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint32_t state[16])
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

void chacha20_block(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t keystream_block[64])
{
	uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

	uint32_t state[16] = {0};
	init_state(constants, key, counter, nonce, state);
	printf("[+] state:\n");
	print_state(state);

	uint32_t working_state[16] = {0};
	memcpy(working_state, state, 64);

	printf("\n[+] working_state: \n");
	print_state(working_state);

	for (uint8_t i = 0; i < 10; i++)
	{
		inner_block(working_state);
	}

	printf("\n[+] state after 20 rounds:\n");
	print_state(working_state);

	add(state, working_state);
	printf("\n[+] state at the end of the ChaCha20 operation:\n");
	print_state(state);

	serialize_uint32_le(state, keystream_block);
}
