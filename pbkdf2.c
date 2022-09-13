#include "common.h"
#include <unistd.h>

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program generates a pbkdf2 derived key for cryptographic\n");
    fprintf (stdout, " Usage %s -i iterations -n slot number -s -o slot output [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -i iterations\t\tIndicates the number of iterations to perfom by the algorithm (it should be at least 500)\n");
    fprintf (stdout, "  -n slot_number\tSlot number for the associated key (5, 8, 9, 10, 11, 12, 13, 14, 15)\n");
    fprintf (stdout, "  -o output slot\tDetermines the slot where the result key will be stored (6, 8, 9, 10, 11, 12, 13, 14, 15)\n");
    fprintf (stdout, " Usage example: ./pbkdf2 -i 1000 -n 5 -o 6\n");

    exit (2);
}

/* Main program */
int main(int argc, char** argv)
{
    ATCA_STATUS status;
    char config_data[ATCA_ECC_CONFIG_SIZE];
    struct _atecc608_config config;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    int c, slot = 3, out_slot, iters;
    uint8_t key[ATCA_KEY_SIZE];
    uint8_t salt[OUTNONCE_SIZE];
    int slot_flag = 0, iter_flag = 0, out_flag = 0;

    while ((c = getopt (argc, argv, "i:n:o:h::")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                break;
	    case 'i':
                iters = atoi(optarg);
                if (iters < 500)
                {
                    fprintf(stderr, "Number of iterations need to at least 500\n");
                    return -1;
                }
		iter_flag = 1;
		break;
	    case 'n':
		slot = atoi(optarg);
		slot_flag = 1;
		break;
	    case 'o':
                out_slot = atoi(optarg);
		out_flag = 1;
		break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'i' || optopt == 'n' || optopt == 'o')
		{
                    fprintf(stderr, "Option -%c requires an argument\n", optopt);
		}
		return -2;
            default:
                fprintf(stderr, "Parameter not recognised: %c\n", c);
                fprintf(stderr, "Use argument -h for help\n");
		return -2;
	}
    }

    if (slot_flag == 0 || out_flag == 0 || iter_flag == 0)
    {
        fprintf(stderr, "You need to include all arguments for the execution of the program, check -h argument for help\n");
	return -2;
    }

    gCfg->atcai2c.bus=1;

    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCA Device\n");
        return -1;
    }
	
    /* Reads the complete device configuration zone */
    status = atcab_read_config_zone(config_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Errorreading config zone\n");
        return -1;
    }
	
    config = set_configuration(config_data);
	
    /* Generates a 32 byte random number */
    status = atcab_random(salt);
    if (status != ATCA_SUCCESS)
    {
	fprintf(stderr, "Error generating random number\n");
        return -1;
    }

    /* Calculates a PBKDF2 password hash using a stored key inside the device */
    status = atcab_pbkdf2_sha256(iters, slot, salt, OUTNONCE_SIZE, key, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating pbkdf2 password hash\n");
	return -1;
    }

    fprintf(stdout, "Key generated: ");
    print_hex_to_file(key, ATCA_KEY_SIZE, stdout);

    /* Writes data to a slot */
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, out_slot, 0, key, ATCA_KEY_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error writing bytes to the specified slot\n");
	return -1;
    }
    fprintf(stdout, "Write Success\n");
	
    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
