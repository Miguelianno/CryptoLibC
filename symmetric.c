#include "common.h"
#include "crypto_common.h"
#include <unistd.h>

#define FILENAME_SIZE 20
#define BUFFER_SIZE 500
#define MODE_SIZE 10

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program performs aes encryption in different modes (cbc, cbcmac, ccm, cmac, ctr and gcm), you can encrypt either data or text\n");
    fprintf (stdout, " Usage %s [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -f filename\t\tIndicates the filename of the program\n");
    fprintf (stdout, "  -t text\t\tPlain text you want to encrypt\n");
    fprintf (stdout, "  -m mode\t\tChoose the encryption mode (cbc, cbcmac, ccm, cmac, ctr or gcm)\n");
    fprintf (stdout, "  -a additional authenticated data\t\tAdds additional authenticated data contained in a file (only used for ccm and gcm modes)\n");
    fprintf (stdout, "  -d additional authenticated data\t\tAdds additional authenticated data as a plain text (only used for ccm and gcm modes)\n");
    fprintf (stdout, " Usage example: ./symmetric -f example.txt -m cbc\n");
    fprintf (stdout, " Usage example: ./symmetric -f example.txt -m ccm -d \"Additional authenticated data\"\n");

    exit (2);
}


int main(int argc, char** argv)
{
    ATCA_STATUS status;
    struct atca_aes_cbc_ctx ctx; // atca_aes_cbc_ctx_t
    uint8_t aes_out[AES_DATA_SIZE];
    uint8_t plaintext[AES_DATA_SIZE];
    struct _atecc608_config config;
    int c;
    int op_flag = 0, text_flag = 0, file_flag = 0;
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
        return -1;
    }
    
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
		file_flag = 1;
                break;
            case 'm':
                fprintf(stdout, "Case m (mode): %s\n", optarg);
		strcpy(mode, optarg);
		op_flag = 1;
                break;
            case 't':
                fprintf(stdout, "Case t (text): %s\n", optarg);
		strcpy(text, optarg);
		text_flag = 1;
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
		}
		return -2;
            default:
                fprintf(stderr, "Parameter not recognised: %c\n", c);
                fprintf(stderr, "Use argument -h for help\n");
		return -2;
        }
    }

    if ((text_flag == 0 && file_flag == 0) || (text_flag && file_flag) || !op_flag)
    {
        fprintf(stderr, "Error in arguments, check -h for help\n");
	return -2;
    }

    if (strcmp (mode, "cbc") == 0)
    {
        struct atca_aes_cbc_ctx ctx;
	uint8_t iv[OUTNONCE_SIZE];

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
	if (cbc_encryption(filename, text, 5, ctx) == -1)
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
    }
    else if (strcmp (mode, "cbcmac") == 0)
    {
	struct atca_aes_cbc_ctx ctx;
	uint8_t iv[OUTNONCE_SIZE];

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
	if (cbcmac_encryption(filename, text, 5, ctx) == -1)
	{
	    fprintf(stderr, "Error in cbc encryption\n");
	    return -1;
	}

	fprintf(stdout, "Trying cbc decryption\n");
	if (cbcmac_decryption("enc.txt", 5, ctx) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    return -1;
	}
    }
    else if (strcmp (mode, "cmac") == 0)
    {
	struct atca_aes_cbc_ctx ctx;
	uint8_t iv[OUTNONCE_SIZE];
	uint8_t enc_tag[ENC_SIZE];
	uint8_t dec_tag[ENC_SIZE];

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
	if (cmac_encryption(filename, text, 5, ctx, enc_tag) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    return -1;
	}

	fprintf(stdout, "Trying cbc decryption\n");
	if (cmac_decryption("enc.txt", 5, ctx, dec_tag) == -1)
	{
            fprintf(stderr, "Error in cbc encryption\n");
	    return -1;
	}

	if (memcmp(enc_tag, dec_tag, ENC_SIZE) == 0)
	{
	    fprintf(stdout, "Tag verification succesfully done!\n");
	}
	else
	{
	    fprintf(stdout, "Error in tag verification, tags don't match!\n");
	}
    }
    else if (strcmp (mode, "ccm") == 0)
    {
        struct atca_aes_ccm_ctx ccm_ctx;
	uint8_t iv[OUTNONCE_SIZE];
	uint8_t tag[AES_DATA_SIZE];
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
	status = atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, AES_DATA_SIZE, AES_DATA_SIZE, AES_DATA_SIZE);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing ccm encryption mode: %x!\n", status);
	    return -1;
	}

	if (ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in ccm encryption\n");
	    return -1;
	}

	if (ccm_decryption("enc.txt", ccm_ctx, tag, filename2, aad) == -1)
        {
            fprintf(stderr, "Error in ccm encryption\n");
	    return -1;
	}
    }
    else if (strcmp (mode, "gcm") == 0)
    {
        struct atca_aes_gcm_ctx gcm_ctx;
	uint8_t iv[OUTNONCE_SIZE];
	uint8_t tag[AES_DATA_SIZE];
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
	status = atcab_aes_gcm_init(&gcm_ctx, 5, 0, iv, OUTNONCE_SIZE);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error initializing gcm encryption mode\n");
	    return -1;
	}

	if (gcm_encryption(filename, text, gcm_ctx, tag, &tag_size, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in gcm encryption\n");
	    return -1;
	}

	if (gcm_decryption("enc.txt", gcm_ctx, tag, filename2, aad) == -1)
	{
	    fprintf(stderr, "Error in gcm encryption\n");
	    return -1;
	}
    }
    else if (strcmp (mode, "ctr") == 0)
    {
        struct atca_aes_ctr_ctx ctr_ctx;
	uint8_t iv[OUTNONCE_SIZE];
            
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
	    return -1;
	}

	if (ctr_decryption("enc.txt", ctr_ctx) == -1)
	{
	    fprintf(stderr, "Error in ctr encryption\n");
	    return -1;
	}
    }
    else if (strcmp(mode, "aes") == 0)
    {
        fprintf(stdout, "Encrypting with AES-128\n");
	if (aes_encryption(filename, text, 5) == -1)
	{
	    fprintf(stderr, "Error in aes encryption\n");
	    return -1;
	}

	if (aes_decryption("enc.txt", 5) == -1)
	{
	    fprintf(stderr, "Error in aes decryption\n");
	    return -1;
	}
    }
    else 
    {
        fprintf(stderr, "Encryption mode not recognised\n");
	fprintf(stderr, "Use argument -h for help\n");
	return -1;
    }

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
