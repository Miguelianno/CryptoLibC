#include "common.h"
#include "crypto_common.h"
#include <unistd.h>

#define FILENAME_SIZE 20
#define BUFFER_SIZE 500
#define MODE_SIZE 10

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program performs aes encryption in different modes (cbc, cbcmac, ccm, cmac, ctr and gcm)\n");
    fprintf (stdout, " Usage %s -o operation -m mode -a additional authenticated data [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -f filename\t\tIndicates the filename of the program\n");
    fprintf (stdout, "  -t text\t\tPlain text you want to encrypt\n");
    fprintf (stdout, "  -m mode\t\tChoose the encryption mode (cbc, cbcmac, ccm, cmac, ctr or gcm)\n");
    fprintf (stdout, "  -a additional authenticated data\t\tAdds additional authenticated data contained in a file (only used for ccm and gcm modes)\n");
    fprintf (stdout, "  -d additional authenticated data\t\tAdds additional authenticated data as a plain text (only used for ccm and gcm modes)\n");
    fprintf (stdout, " Usage example: ./symmetric -f example.txt -m cbc\n");

    exit (2);
}


int main(int argc, char** argv)
{
    ATCA_STATUS status;
    struct atca_aes_cbc_ctx ctx; // atca_aes_cbc_ctx_t
    uint8_t random_data[16];
    uint8_t aes_out[16];
    uint8_t plaintext[16];
    uint8_t config_data[CONFIG_SIZE];
    struct _atecc608_config config;
    int c;
    int op_flag;
    char filename[FILENAME_SIZE] = "\0";
    char filename2[FILENAME_SIZE] = "\0";
    char mode[MODE_SIZE];
    char text[BUFFER_SIZE] = "\0";
    char aad[BUFFER_SIZE] = "\0";

    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;

    gCfg->atcai2c.bus=1;
    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error  initializing global ATCA Device\n");
        exit(status);
    }
    
    /* Read the complete device configuration zone */
    status = atcab_read_config_zone(config_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading config zone\n");
        exit(status);
    }
    
    config = set_configuration(config_data);
    
    /* Generates a 32 byte random number from the device */
    status = atcab_random(random_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating random number\n");
        exit(status);
    }

    fprintf(stdout, "Generated data:\n");
    print_hex(random_data, 16);

    while ((c = getopt (argc, argv, "f:m:t:a:d:h::")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                break;
		return 1;
            case 'f':
                fprintf(stdout, "Case f (filename): %s\n", optarg);
                strcpy(filename, optarg);
                break;
            case 'm':
                fprintf(stdout, "Case m (mode): %s\n", optarg);
		strcpy(mode, optarg);
                break;
            case 't':
                fprintf(stdout, "Case t (text): %s\n", optarg);
		strcpy(text, optarg);
		break;
            case 'd':
                fprintf(stdout, "Case d (aad): %s\n", optarg);
		strcpy(aad, optarg);
		break;
            case 'a':
                 fprintf(stdout, "Case a (additional authenticated data): %s\n", optarg);
                 strcpy(filename2, optarg);
		 break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'f' || optopt == 'm' || optopt == 't' || optopt == 'd' || optopt == 'a')
		{
                    fprintf(stderr, "Option -%c requires an argument\n", optopt);
		    exit(-1);
		}
		break;
            default:
                fprintf(stderr, "Parameter not recognised: %c\n", c);
                fprintf(stderr, "Use argument -h for help\n");
		return 1;
        }
    }

    if (strcmp (mode, "cbc") == 0)
    {
        struct atca_aes_cbc_ctx ctx;
	uint8_t iv[32];

	/* Generates a 32 byte random number from the device */            
       	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}

	/* Initialize context for AES CBC operation */
	status = atcab_aes_cbc_init(&ctx, 5, 0 , iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing aes cbc\n");
	    return -1;
	}
                            
	fprintf(stdout, "Trying cbc encryption\n");
	if (cbc_encryption(filename, text, 5, 1, ctx) == -1)
	{
	    fprintf(stderr, "Error in cbc encryption\n");
            exit(status);
	}

	fprintf(stdout, "Trying cbc decryption\n");
	if (cbc_decryption("enc.txt", 5, 1, ctx) == -1)
	{
	    fprintf(stderr, "Error in cbc encryption\n");
	    exit(status);
	}
    }
    else if (strcmp (mode, "cbcmac") == 0)
    {
	struct atca_aes_cbc_ctx ctx;
	uint8_t iv[32];

	/* Generates a 32 byte random number from the device */
	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}

	/* Initialize context for AES CBC operation */
	status = atcab_aes_cbc_init(&ctx, 5, 0 , iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing aes cbc\n");
	    return -1;
	}
                            
	fprintf(stdout, "Trying cbc encryption\n");
	if (cbcmac_encryption(filename, text, 5, 1, ctx) == -1)
	{
	    fprintf(stderr, "Error in cbc encryption\n");
	    exit(status);
	}

	fprintf(stdout, "Trying cbc decryption\n");
	if (cbcmac_decryption("enc.txt", 5, 1, ctx) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    exit(status);
	}
    }
    else if (strcmp (mode, "cmac") == 0)
    {
	struct atca_aes_cbc_ctx ctx;
	uint8_t iv[32];

	/* Generates a 32 byte random number from the device */
	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
 	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}

	/* Initialize context for AES CBC operation */
	status = atcab_aes_cbc_init(&ctx, 5, 0 , iv);
	if (status != ATCA_SUCCESS)
	{ 
	    fprintf(stderr, "Error initializing aes cbc\n");
	    return -1;
	}

	fprintf(stdout, "Trying cbc encryption\n");
	if (cmac_encryption(filename, text, 5, 1, ctx) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    exit(status);
	}

	fprintf(stdout, "Trying cbc decryption\n");
	if (cmac_decryption("enc.txt", 5, 1, ctx) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    exit(status);
	}
    }
    else if (strcmp (mode, "ccm") == 0)
    {
        struct atca_aes_ccm_ctx ccm_ctx;
	uint8_t iv[32];
	uint8_t tag[16];
	uint8_t tag_size;

	fprintf(stdout, "Ccm encryption mode...\n");

	/* Generates a 32 byte random number from the device */
	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n", status);
	    return -1;
	}
            
	/* Initialize context for AES CCM operation with a random nonce */
	status = atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, 16, 16, 16);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing ccm encryption mode: %x!\n", status);
	    return -1;
	}

	if (ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in ctr encryption\n");
	    exit(status);
	}

	if (ccm_decryption("enc.txt", ccm_ctx, tag, filename2, aad) == -1)
        {
            fprintf(stderr, "Error in ctr encryption\n");
	    exit(status);
	}
    }
    else if (strcmp (mode, "gcm") == 0)
    {
        struct atca_aes_gcm_ctx gcm_ctx;
	uint8_t iv[32];
	uint8_t tag[16];
	uint8_t tag_size;
            
	fprintf(stdout, "Gcm encryption mode...\n");

	/* Generates a 32 byte random number from the device */
	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}
   
	/* Initialize context for AES GCM operation with an existing IV */
	status = atcab_aes_gcm_init(&gcm_ctx, 5, 0, iv, 32);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing gcm encryption mode\n");
	    return -1;
	}

	if (gcm_encryption(filename, text, gcm_ctx, tag, &tag_size, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in gcm encryption\n");
	    exit(status);
	}

	if (gcm_decryption("enc.txt", gcm_ctx, tag, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in gcm encryption\n");
	    exit(status);
	}
    }
    else if (strcmp (mode, "ctr") == 0)
    {
        struct atca_aes_ctr_ctx ctr_ctx;
	uint8_t iv[32];
            
	fprintf(stdout, "Ctr encryption mode...\n");
	/* Generates a 32 byte random number from the device */
	status = atcab_random(iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}

	/* Initialize context for AES CTR operation with an existing IV */
	status = atcab_aes_ctr_init(&ctr_ctx, 5, 0, 4, iv);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error generating random number\n");
	    return -1;
	}

	if (ctr_encryption(filename, text, ctr_ctx) == -1)
	{
	    fprintf(stderr, "Error in ctr encryption\n");
	    exit(status);
	}

	if (ctr_decryption("enc.txt", ctr_ctx) == -1)
	{
	    fprintf(stderr, "Error in ctr encryption\n");
	    exit(status);
	}
    }
    else if (strcmp(mode, "aes") == 0)
    {
        fprintf(stdout, "Encrypting with AES-128\n");

	if (aes_encryption(filename, text, 5) == -1)
	{
	    fprintf(stderr, "Error in ctr encryption\n");
	    exit(status);
	}

	if (aes_decryption("enc.txt", 5) == -1)
	{
	    fprintf(stderr, "Error in aes decryption\n");
	    exit(status);
	}
    }
    else 
    {
        fprintf(stderr, "Encryption mode not recognised\n");
	fprintf(stderr, "Use argument -h for help\n");
	return 1;
    }

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        exit(status);
    }

    exit(status);
}
