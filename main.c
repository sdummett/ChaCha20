#include "chacha20.h"

int main(int ac, char *av[])
{
	program_options_t options;
	if (!parse_args(ac, av, &options))
		return 1;

	if (options.mode == MODE_ENCRYPT || options.mode == MODE_DECRYPT)
	{
		return encrypt_decrypt(&options);
	}

	return 0;
}
