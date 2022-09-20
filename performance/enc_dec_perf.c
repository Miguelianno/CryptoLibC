#include "../common.h"
#include "../crypto_common.h"
#include <unistd.h>
#include <time.h>

#define FILENAME_SIZE 20
#define BUFFER_SIZE 500
#define MODE_SIZE 10


int main(int argc, char** argv)
{
    ATCA_STATUS status;
    struct atca_aes_cbc_ctx ctx; // atca_aes_cbc_ctx_t
    uint8_t aes_out[AES_DATA_SIZE];
    uint8_t plaintext[AES_DATA_SIZE];
    int op_flag = 0, text_flag = 0, file_flag = 0;
    uint8_t iv[OUTNONCE_SIZE];
    char* text = NULL;
    clock_t t_ini, t_fin;
    double secs;

    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;

    gCfg->atcai2c.bus=1;
    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error  initializing global ATCA Device\n");
        return -1;
    }

    /* Generates a 32 byte random number from the device */            
    status = atcab_random(iv);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating random number\n");
	return -1;
    }

    t_ini = clock();

    /* Initialize context for AES CBC operation */
    status = atcab_aes_cbc_init(&ctx, 5, 0 , iv);
    if (status != ATCA_SUCCESS)
    {
	fprintf(stderr, "Error initializing aes cbc\n");
	return -1;
    }
                            
    fprintf(stdout, "Trying cbc encryption\n");
    if (cbc_encryption(argv[1], text, 5, ctx) == -1)
    {
        fprintf(stderr, "Error in cbc encryption\n");
        return -1;
    }

    fprintf(stdout, "Trying cbc decryption\n");
    if (cbc_decryption("enc.txt", 5, ctx) == -1)
    {
	fprintf(stderr, "Error in cbc encryption\n");
        return -1;
    }
 
    t_fin = clock();

    secs = (double)(t_fin - t_ini) / CLOCKS_PER_SEC;
    printf("%.16g milisegundos\n", secs * 1000.0);

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
