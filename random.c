#include "common.h"


/* This program generates random numbers and displays them in decimal/hexadecimal format */
int main (int argc, char** argv)
{
    ATCA_STATUS status;
    uint8_t rand_out[OUTNONCE_SIZE];
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;

    gCfg->atcai2c.bus=1;

    /* Creates and initializes ATCADevice context */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCADevice\n", status);
        return -1;
    }

    /* Generates 32 byte random number from the device */
    status = atcab_random(rand_out);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating random number\n");
	return -1;
    }

    fprintf(stdout, "Generated random number: ");
    print_hex_to_file(rand_out, OUTNONCE_SIZE, stdout);

    return 0;
}
