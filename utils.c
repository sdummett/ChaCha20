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

void print_bytes(uint8_t *block, uint8_t len)
{
	for (uint8_t i = 0; i < len; i++)
	{
		if (i % 16 == 0 && i != 0)
			printf("\n");
		printf("%02x ", block[i]);
	}
	printf("\n");
}
