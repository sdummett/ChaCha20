#include "chacha20.h"

void print_help(const char *prog_name)
{
	printf("Usage:\n");
	printf("  %s -e <file> -k <key_file> [options]\n", prog_name);
	printf("  %s -d <file> -k <key_file> [options]\n\n", prog_name);

	printf("Required options:\n");
	printf("  -e, --encrypt <file>       Encrypt the specified input file\n");
	printf("  -d, --decrypt <file>       Decrypt the specified input file\n");
	printf("                             (You must choose one and only one of these two)\n");
	printf("  -k, --key <file>           Path to a 256-bit (32-byte) binary key file\n\n");

	printf("Optional parameters:\n");
	printf("  -o, --output <file>        Specify output filename (default: data.chacha20)\n");
	printf("      --help                 Display this help message\n\n");

	printf("Examples:\n");
	printf("  %s -e myfile.txt -k key.bin -o encrypted.chacha20\n", prog_name);
	printf("  %s --decrypt encrypted.chacha20 --key key.bin -o decrypted.txt\n\n", prog_name);

	printf("Notes:\n");
	printf("  - The key file must be exactly 32 bytes long.\n");
	printf("  - If the -o option is not provided, output will be written to 'data.chacha20'.\n");
}

int parse_args(int ac, char *av[], program_options_t *options)
{
	int opt;
	int option_index = 0;

	static struct option long_options[] = {
		{"encrypt", required_argument, 0, 'e'},
		{"decrypt", required_argument, 0, 'd'},
		{"key", required_argument, 0, 'k'},
		{"output", required_argument, 0, 'o'},
		{"help", no_argument, 0, 0},
		{0, 0, 0, 0}};

	options->mode = MODE_NONE;
	options->input_file = NULL;
	options->output_file = NULL;
	options->key_file = NULL;

	while ((opt = getopt_long(ac, av, "e:d:k:o:", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
		case 'e':
			if (options->mode != MODE_NONE)
			{
				fprintf(stderr, "Error: Cannot use both --encrypt and --decrypt.\n");
				return 0;
			}
			options->mode = MODE_ENCRYPT;
			options->input_file = optarg;
			break;

		case 'd':
			if (options->mode != MODE_NONE)
			{
				fprintf(stderr, "Error: Cannot use both --encrypt and --decrypt.\n");
				return 0;
			}
			options->mode = MODE_DECRYPT;
			options->input_file = optarg;
			break;

		case 'k':
			options->key_file = optarg;
			break;

		case 'o':
			options->output_file = optarg;
			break;

		case 0: // --help
			print_help(av[0]);
			return 0;

		default:
			print_help(av[0]);
			return 0;
		}
	}

	if (options->mode == MODE_NONE || options->input_file == NULL)
	{
		print_help(av[0]);
		return 0;
	}

	if (options->output_file == NULL)
	{
		options->output_file = DEFAULT_OUTPUT_FILE;
	}

	if (options->key_file == NULL)
	{
		fprintf(stderr, "Error: A key must be specified with -k or --key.\n");
		print_help(av[0]);
		return 0;
	}

	return 1;
}
