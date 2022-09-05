#include "common.h"
#include <unistd.h>

#define SALT_SIZE 32
#define KEY_LENGTH 32

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program generates a pbkdf2 derived key for cryptographic\n");
    fprintf (stdout, " Usage %s -i iterations -n slot number -s key size -o slot output [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -i iterations\t\tIndicates the number of iterations to perfom by the algorithm (it should be at least 1000)\n");
    fprintf (stdout, "  -n slot_number\t\tSlot number for the associated key (5, 8, 9, 10, 11, 12, 13, 14, 15)\n");
    fprintf (stdout, "  -o output slot\t\tDetermines the slot where the result key will be stored (6, 8, 9, 10, 11, 12, 13, 14, 15)\n");
    fprintf (stdout, " Usage example: ./pbkdf2 -i 1000 -n 7 -s 32 -o 5\n");

    exit (2);
}

int main(int argc, char** argv)
{
    ATCA_STATUS status;
    char config_data[CONFIG_SIZE];
    struct _atecc608_config config;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    int c, slot = 3, out_slot, iters;
    uint8_t key[KEY_LENGTH];
    uint8_t salt[SALT_SIZE];

    while ((c = getopt (argc, argv, "i:n:o:h::")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                break;
	    case 'i':
                iters = atoi(optarg);
                if (iters < 1000)
                {
                    fprintf(stderr, "Number of iterations need to at least 1000\n");
                    return -1;
                }
		break;
	    case 'n':
		slot = atoi(optarg);
		break;
	    case 'o':
                out_slot = atoi(optarg);
		break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'i' || optopt == 'n' || optopt == 'o')
		{
                    fprintf(stderr, "Option -%c requires an argument\n", optopt);
		    return -1;
		}
		break;
            default:
                fprintf(stderr, "Parameter not recognised: %c\n", c);
                fprintf(stderr, "Use argument -h for help\n");
		return -2;
	}
    }

    if (argc < 3)
    {
        fprintf(stderr, "You need to include three arguments, check -h argument for help\n");
	return -1;
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
    status = atcab_pbkdf2_sha256(iters, slot, salt, SALT_SIZE, key, KEY_LENGTH);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating pbkdf2 password hash\n");
	return -1;
    }

    fprintf(stdout, "Key generated: ");
    print_hex(key, KEY_LENGTH);

    /* Writes data to a slot */
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, out_slot, 0, key, KEY_LENGTH);
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
