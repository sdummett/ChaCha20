#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void print_state(uint32_t state[16]);
void print_bytes(uint8_t *block, uint8_t len);
void chacha20_block(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t keystream_block[64]);

#endif