#include "chacha20.h"

void print_state(uint32_t state[16])
{
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0 && i != 0)
			printf("\n");
		printf("%08x ", state[i]);
	}
	printf("\n");
}

void print_serialized_block(uint8_t block[64])
{
	for (uint8_t i = 0; i < 64; i++)
	{
		if (i % 16 == 0 && i != 0)
			printf("\n");
		printf("%02x ", block[i]);
	}
	printf("\n");
}
