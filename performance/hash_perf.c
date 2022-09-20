#include "../common.h"
#include "../crypto_common.h"
#include <unistd.h>
#include <time.h>


/* Main program */
int main(int argc, char** argv)
{
    ATCA_STATUS status;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    uint8_t* file_digest;
    FILE* fp = NULL;
    clock_t t_ini, t_fin;
    double secs;

    gCfg->atcai2c.bus=1;

    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCA Device\n");
        return -1;
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
	return -1;
    }

    file_digest = (uint8_t*)malloc(32*sizeof(uint8_t));
    if (file_digest == NULL)
    {
	fprintf(stderr, "Error allocating memory for signature\n");
	return -1;
    }

    t_ini = clock();

    /* Initializes SHA-256 calculation engine */
    status = atcab_sha_start();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error starting sha engine\n");
	return -1;
    }

    /* Generate hash of a file */
    file_digest = hash_file(fp);
    if (file_digest == NULL)
    {
        fprintf(stderr, "Error generating hash of file\n");
	fclose(fp);
	return -1;
    }

    t_fin = clock();

    fprintf(stdout, "Digest generated: ");
    print_hex_to_file(file_digest, 32, stdout);
    

    secs = (double)(t_fin - t_ini) / CLOCKS_PER_SEC;
    printf("%.16g milisegundos\n", secs * 1000.0);

    free(file_digest);
    fclose(fp);

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
