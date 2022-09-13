#include "common.h"
#include <unistd.h>

#define READ_SIZE 32

uint8_t ENC_KEY[32] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program write/reads bytes from the specified data slot in the data zone\n");
    fprintf (stdout, " Usage %s -n slot number [OPTIONS]\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -n slot_number\t\tSlot number to read from (8, 9, 10, 11, 12, 13, 14, 15)\n");
    fprintf (stdout, " Usage example: ./read_write -n 7\n");

    exit (2);
}

/* Reads/writes information from/to the specified slot */
int read_write(struct _atecc608_config config)
{
    ATCA_STATUS status;
    uint16_t write_key_slot;
    uint8_t write_data[OUTNONCE_SIZE];
    uint8_t read_data[READ_SIZE];
    uint8_t rand_out[OUTNONCE_SIZE];
    uint8_t ciphertext[ENC_SIZE];
    uint8_t puba[ATCA_PUB_KEY_SIZE];
    uint8_t response[ATCA_WORD_SIZE];
    int slot = 5;
    uint8_t num_in[OUTNONCE_SIZE];
	
    /* Obtener 4 bits the WriteKey (Servirá para validar y escribir datos encriptados) */
    write_key_slot = config.SlotConfig[ENCRYPTED];
    write_key_slot &= 0x000f; //Comprobar que se coge bien el valor

    fprintf(stdout, "Slot used for write/read encrypted: %d\n", write_key_slot);
    fprintf(stdout, "Generating data using RAND command\n");
    status = atcab_random(write_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating random number\n");
        return -1;
    }
	
    fprintf(stdout, "Data to be written: \n");
    print_hex_to_file(write_data, 32, stdout);

    /* Writes data to a slot */
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, CLEAR, 0, write_data, sizeof(write_data));
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error writing bytes to the device\n", status);
	return -1;
    }
    fprintf(stdout, "Write Success\n");

    /* Reading the data in the clear from slot */
    status = atcab_read_bytes_zone(ATCA_ZONE_DATA, CLEAR, 0, read_data, sizeof(read_data));
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading bytes from device\n");
	return -1;
    }

    fprintf(stdout, "Read Success\n");
    fprintf(stdout, "Read data:\n");
    print_hex_to_file(read_data, 32, stdout);

    /* Compares the data read with the written data */
    fprintf(stdout, "Verifing read data matches written data:\n");
    if (memcmp(read_data, write_data, 32) == 0)
    {
        fprintf(stdout, "Data matches\n");
    }
    else
    {
        fprintf(stdout, "Data does not match\n");
    }

    /* Writing IO protection key. This key is used as IO encryption key */
    status = atcab_write_zone(ATCA_ZONE_DATA, write_key_slot, 0, 0, ENC_KEY, 32);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading bytes from device\n");
	return -1;
    }

    /* Generates a private key in TempKey 
    status = atcab_genkey(ATCA_TEMPKEY_KEYID, puba);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating temporary key\n");
        exit(-1);
    }*/

    fprintf(stdout, "Generating data using RAND command\n");

    /* Writing a key to slot '1' through encrypted write */
    fprintf(stdout, "Encrypted Write Command: \n");

    /* Performs AES-128 operation with a key in the device */
    status = atcab_aes_encrypt(slot, 0, write_data, ciphertext);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting data: %x\n", status);
	return -1;
    }

    /* Performs AES-128 operation with a key in the device */
    status = atcab_aes_encrypt(slot, 0, &write_data[16], &ciphertext[16]);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting data: %x\n", status);
	return -1;
    }

    /* Generates random nonce */
    atcab_random(num_in);
    atcab_nonce(num_in);
    status = atcab_nonce_rand(num_in, rand_out);
    //status = generate_nonce(rand_out);  
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating nonce: %x\n", status);
        return -1;
    }

    /* Performs a SHA256 on the source data with the content in TempKey */
    status = atcab_gendig(2 , write_key_slot, NULL, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error in gendig: %x\n", status);
        return -1;
    }

    /* Performs and encrypted write of the premaster secret in the specified slot */
    status = atcab_write_enc(ENCRYPTED, 0, ciphertext, ENC_KEY, write_key_slot, rand_out);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error writing the secret: %x\n", status);
        return -1;
    }

    fprintf(stdout, "Write encrypted succesfully done!\n");
    print_hex_to_file(ciphertext, 32, stdout);

    /* Generates random nonce 
    status = generate_nonce(rand_out);  
    status = atcab_random(num_in); 
    //status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, rand_out, 32);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error in generating nonce: %x\n", status);
        exit(-1);
    }
    atcab_nonce(num_in);
    status = atcab_nonce_rand(num_in, rand_out);

    // Performs a SHA256 on the source data with the content in TempKey 
    status = atcab_gendig(2 , write_key_slot, NULL, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error in gendig: %x\n", status);
        exit(-1);
    }

    status = atcab_info_base(2, 0, response);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error info base: %x\n", status);
        exit(-1);
    }

    printf("Response: ");
    print_hex_to_file(response, 4, stdout); 
    // Reading the key in plain text from slot '10' 
    fprintf(stdout, "Encrypted Read Command: \n");
    status = atcab_read_enc(ENCRYPTED, 0, read_data, ENC_KEY, write_key_slot, rand_out);
    status = atcab_read_zone(2, 5, 0, 0, read_data, 32);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading encrypted data from the device: %x\n", status);
	exit(-1);
    }
    
    fprintf(stdout, "Readed data: ");
    print_hex_to_file(read_data, 32, stdout);*/

    /* Compare the read data to the written data *
    fprintf(stdout, "Verifing read data matches written data:\n");
    if (strcmp(read_data, write_data) == 0)
    {
        fprintf(stdout, "Data mathes\n");
    }
    else
    {
        fprintf(stdout, "Data does not match\n");
    }*/
		
    return 0;
}

/* Main program */
int main(int argc, char **argv)
{
    ATCA_STATUS status;
    bool conf_is_locked;
    bool data_is_locked;
    char config_data[ATCA_ECC_CONFIG_SIZE];
    char read_data[READ_SIZE];
    struct _atecc608_config config;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    int c, slot, slot_flag = 0;

    while ((c = getopt (argc, argv, "n:h::")) != -1)
    {
        switch (c)
        {
            case 'h':
                help(argv[0]);
                break;
	    case 'n':
		slot = atoi(optarg);
		slot_flag = 1;
		break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'n')
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

    if (slot_flag == 0)
    {
        fprintf(stderr, "Error in arguments, check -h for help\n");
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
        fprintf(stderr, "Error reading from the config zone\n");
        return -1;
    }
	
    config = set_configuration(config_data);
	
    read_write(config);

    /* Reads 32 bytes of data from a given slot in the data zone */
    status = atcab_read_zone(ATCA_ZONE_DATA, slot, 0, 0, read_data, READ_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading from data zone\n");
	return -1;
    }

    fprintf(stdout, "Data read from slot %d: ", slot);
    print_hex_to_file(read_data, READ_SIZE, stdout);
	
    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("Error releasing global ATCA Device\n");
        return -1;
    }

    return status;
}
