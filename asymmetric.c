#include "common.h"
#include "crypto_common.h"
#include <unistd.h>

#define FILENAME_SIZE 25
#define BUFFER_SIZE 500
uint8_t ENC_KEY[32] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program performs asymmetric encryption by generating a shared secret");
    fprintf (stdout, " Usage %s -f filename -t text [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -f filename\t\tIndicates the filename of the program\n");
    fprintf (stdout, "  -t text\t\tPlain text you want to encrypt\n");
    fprintf (stdout, " Usage example: ./asymmetric.c -f example.txt\n");
    exit (2);
}

uint16_t get_write_key_slot(struct _atecc608_config config)
{
    uint16_t write_key_slot;

    write_key_slot = config.SlotConfig[ENCRYPTED];
    write_key_slot &= 0x000f; 

    return write_key_slot;
}

uint16_t get_read_key_slot(struct _atecc608_config config)
{
    uint16_t read_key_slot;

    read_key_slot = config.SlotConfig[ENCRYPTED];
    read_key_slot &= 0x0f00; 

    return read_key_slot;
}


/* Elliptic-curve Diffie-Hellman shared secret generation*/
ATCA_STATUS ECDH(struct _atecc608_config config)
{
    ATCA_STATUS status;
    uint8_t puba[64];
    uint8_t pubb[64];
    uint8_t pms[32];
    uint8_t secret[32];
    uint8_t rand_out[32];
    uint8_t response[4];

    uint16_t write_key_slot;
    uint32_t i;
    int ret;
    int genkey_slot = 2; 
	
    write_key_slot = get_write_key_slot(config);

    /* Generates a private key in TempKey */
    status = atcab_genkey(ATCA_TEMPKEY_KEYID, puba);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating temporary key\n");
        return status;
    }

    /* Generates a private key in the specifed slot */
    status = atcab_genkey(genkey_slot, pubb);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating key\n");
        return status;
    }

    /* ECDH command with a private key in TempKey and the premaster secret is returned in the clear */
    status = atcab_ecdh_tempkey(pubb, pms);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error performing ECDH command with a private key\n");
        return status;
    }

    /* ECDH command with a private key in a slot and the premaster secret is returned in the clear */
    status = atcab_ecdh(genkey_slot, puba, secret);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error performing ECDH command\n");
        return status;
    }

    /* Compare both independently calculated */
    if (memcmp(secret, pms, 32) == 0)
    {
        fprintf(stdout, "Success - Generated secrets match! \n");
    }
    else
    {
        fprintf(stdout, "Error in calculation\n");
	return status;
    }

    /* Returns internal device information to check if TempKey is valid for encrypted write */
    status = atcab_info_base(2, 0, response);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error info base: %x\n", status);
        return status;
    }

    if (response[0] == 0x20 && response[1] == 0x81)
    {
	/* Generates random nonce */
        status = generate_nonce(rand_out);  
	if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error in gendig: %x\n", status);
            return status;
        }

        /* Performs and encrypted write of the pms in the configured slot */
        status = atcab_write_enc(ENCRYPTED, 0, pms, ENC_KEY, write_key_slot, rand_out);
	if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error writing the secret1\n");
            return status;
        }
    }
    else {
	/* Generates random nonce */
        status = generate_nonce(rand_out);  
	if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error in gendig: %x\n", status);
            return status;
        }

	/* Performs a SHA256 on the source data with the content in TempKey */
	status = atcab_gendig(2 , 6, NULL, 0);
	if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error in gendig: %x\n", status);
            return status;
        }

	fprintf(stdout, "Premaster secret:\n");
	print_hex_to_file(pms, 32, stdout);
	
	/* Performs and encrypted write of the premaster secret in the specified slot*/
        status = atcab_write_enc(ENCRYPTED, 0, pms, ENC_KEY, write_key_slot, rand_out);
	if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error writing the secret: %x\n", status);
            return status;
        }
	fprintf(stdout, "Write encrypted succesfully done!\n");
    }

    return status;
}

int main(int argc, char** argv)
{
    ATCA_STATUS status;
    uint8_t config_data[CONFIG_SIZE];
    struct _atecc608_config config;
    uint8_t nonce[32];
    int c;
    int ret;
    char text[BUFFER_SIZE] = "\0";
    char filename[FILENAME_SIZE]= "\0";

    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;

    gCfg->atcai2c.bus=1;

    if (argc <= 1)
    {
        fprintf(stderr, "Error in arguments, use -h argument for help\n");
	exit(-1);
    }
    
    while ((c = getopt (argc, argv, "f:t:h::")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                break;
	    case 'f':
		strcpy(filename, optarg);
		break;
	    case 't':
		strcpy(text, optarg);
		break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'f' || optopt == 't')
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

    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCA Device\n");
        return -1;
    }

    /* Reads the configuration zone of the device */
    status = atcab_read_config_zone(config_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading config zone\n");
        return -1;
    }
	
    config = set_configuration(config_data);
	
    fprintf(stdout, "Generating secrets...\n");
    /* Generates the shared secret for encryption */
    status = ECDH(config);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error in ecdh generation\n");
        return -1;
    }
	
    /* Performs aes encryption with the shared secret on the file/text given */
    if (aes_encryption(filename, text, 5) == -1)
    {
	fprintf(stderr, "Error in ctr encryption\n");
	return -1;
    }

    fprintf(stdout, "Encryption succesfully done, check enc.txt\n");
    /* Performs aes decryption with the shared secret on the file/text given */
    if (aes_decryption("enc.txt", 5) == -1)
    {
	fprintf(stderr, "Error in aes decryption\n");
	return -1;
    }

    fprintf(stdout, "Decryption succesfully done, check dec.txt\n");
    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
