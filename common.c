#include "common.h"

/* Configuration for ATECC608A minus the first 16 bytes which are fixed by the factory */
uint8_t final_configuration[CONFIG_SIZE] = {
    0x01, 0x23, 0x89, 0xa6, 0x00, 0x00, 0x60, 0x02,  0x31, 0x5f, 0x94, 0x43, 0xee, 0x01, 0x51, 0x00,
    0xC0, 0x00, 0x00, 0x01, 0x85, 0x00, 0x82, 0x00,  0x85, 0x20, 0x85, 0x20, 0x85, 0x20, 0x8f, 0x46,
    0x8F, 0x0F, 0x9F, 0x8F, 0x0F, 0x0F, 0x0F, 0x0F,  0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0D, 0x1F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF,  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF7,  0x00, 0x69, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55,  0xFF, 0xFF, 0x0E, 0x60, 0x00, 0x00, 0x00, 0x00,
    0x53, 0x00, 0x53, 0x00, 0x73, 0x00, 0x73, 0x00,  0x73, 0x00, 0x38, 0x00, 0x7C, 0x00, 0x1C, 0x00,
    0x3C, 0x00, 0x1A, 0x00, 0x3C, 0x00, 0x30, 0x00,  0x3C, 0x00, 0x30, 0x00, 0x12, 0x00, 0x30, 0x00
};


ATCADevice getATCADevice()
{
    ATCADevice dev; 

    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    gCfg->atcai2c.bus=1;

    dev = newATCADevice (gCfg);
    if (dev == NULL)
    {
        fprintf(stderr, "Error retrieving ATCA Device\n");
    	return NULL;
    }
    
    return dev;
}

/* Converts a string of characters into an array of bytes */
int char_to_uint8(char* str, uint8_t* res, int size)
{
    int i;
	
    if (size <= 0 || str == NULL)
    {
        return -1;
    }

    for (i = 0; i < size; i++)
    {
       res[i] = (uint8_t)str[i];
    }
	
    return 0;
}

/* Convert a group of bytes into a string of characters */
int uint8_to_char(uint8_t* data, char* res, int size)
{
    int i = 0;
	
    if (size <= 0 || data == NULL)
    {
        return -1;
    }
	
    for (int i = 0; i < size; i++)
    {
        res[i] = (char)data[i];
    }
	
    return 0;
}

/* Returns the specified configuration */
uint8_t* get_defined_configuration()
{
    return final_configuration;
}

/* Generates a random nonce for cryptographic use */
ATCA_STATUS generate_nonce(uint8_t* rand_out)
{
    uint8_t num_in[32];
    ATCA_STATUS status;

    /* Generates a 32 byte random number */
    status = atcab_random(num_in);
    if (status != ATCA_SUCCESS)
    {
	fprintf(stderr, "Error generating random number: %x\n", status);
        return status;
    }

    /* Execute a Nonce command in pass-through mode to initialize TempKey to a specified value */
    status = atcab_nonce(num_in);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing nonce\n");
        return status;
    }

    /* Generate a random nonce combining a host nonce (num_in) and a device random number */
    status = atcab_nonce_rand(num_in, rand_out);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating nonce\n");
        return status;
    }

    return status;
}

/* Prints the values for the defined configuration */
void print_configuration(struct _atecc608_config config)
{
	
    fprintf(stdout, "0x%08x ", config.SN03);
    fprintf(stdout, "0x%08x ", config.RevNum);
    fprintf(stdout, "0x%08x ", config.SN47);
    fprintf(stdout, "0x%0x ", config.SN8);
    fprintf(stdout, "0x%0x ", config.AES_Enable);
    fprintf(stdout, "0x%0x ", config.I2C_Enable);
    fprintf(stdout, "0x%0x ", config.Reserved1);
    fprintf(stdout, "0x%0x ", config.I2C_Address);
    fprintf(stdout, "0x%0x ", config.Reserved2);
    fprintf(stdout, "0x%0x ", config.CountMatch);
    fprintf(stdout, "0x%0x ", config.ChipMode);
	
    for(int i = 0; i < N_SLOTS; i++)
    {
        fprintf(stdout, "0x%04x ", config.SlotConfig[i]);
    }
	
    for(int i = 0; i < 8; i++)
    {
        fprintf(stdout, "0x%0x ", config.Counter0[i]);
    }
	
    for(int i = 0; i < 8; i++)
    {
        fprintf(stdout, "0x%0x ", config.Counter1[i]);
    }
	
    fprintf(stdout, "0x%0x ", config.UseLock);
    fprintf(stdout, "0x%0x ", config.VolatileKeyPermission);
    fprintf(stdout, "0x%04x ", config.SecureBoot);
    fprintf(stdout, "0x%0x ", config.KdflvLoc);
    fprintf(stdout, "0x%04x ", config.KdflvStr);
	
    for(int i = 0; i < 9; i++)
    {
        fprintf(stdout, "0x%0x ", config.Reserved3[i]);
    }
	
    fprintf(stdout, "0x%0x ", config.UserExtra);
    fprintf(stdout, "0x%0x ", config.UserExtraAdd);
    fprintf(stdout, "0x%0x ", config.LockValue);
    fprintf(stdout, "0x%0x ", config.LockConfig);
    fprintf(stdout, "0x%04x ", config.SlotLocked);
    fprintf(stdout, "0x%04x ", config.ChipOptions);
    fprintf(stdout, "0x%08x ", config.X509format);

    for(int i = 0; i < N_SLOTS; i++)
    {
        fprintf(stdout, "0x%04x ", config.KeyConfig[i]);
    }

    fprintf(stdout, "\n");
}

/* Set a 32 bit field with the given data inside the device configuration in the place indicated by the index */
uint32_t set_32_field(uint8_t* data, int index)
{
    int shift =24;
    int i = 0;
    uint32_t res = 0;
    uint32_t aux = 0;

    if (data == NULL || index < 0)
    {
        return 0;
    }

    while (shift >= 0)
    {
        aux = data[index] & 0xff;
	(aux <<= shift);
	shift -= 8;
	(res |= aux);
	index++;
    }

    return res;
}

/* Set a 16 bit field with the given data inside the device configuration in the place indicated by the index */
uint16_t set_16_field(uint8_t* data, int index)
{
    int shift = 8;
    int i = 0;
    uint16_t res = 0;
    uint16_t aux = 0;

    if (data == NULL || index < 0)
    {
        return 0;
    }
    
    while (shift >= 0)
    {
        aux = data[index] & 0xff;
	(aux <<= shift);
	shift -= 8;
	(res |= aux);
	index++;
    }

    return res;
}

/* This function fills the atecc608 config struct for an easier access to its values */
struct _atecc608_config set_configuration(uint8_t* config_data)
{
    struct _atecc608_config config;
    int shift;
    int global = 0;
    ATCA_STATUS status;

    /* Reads the complete device configuration zone */
    status = atcab_read_config_zone(config_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading config zone\n");
        exit(status);
    }
	
    config.SN03 = set_32_field(config_data, global);
    global += 4;

    config.RevNum = set_32_field(config_data, global);
    global += 4;
	
    config.SN47 = set_32_field(config_data, global);
    global += 4;
	
    config.SN8 = config_data[global];
    global++;
	
    config.AES_Enable = config_data[global];
    global++;
	
    config.I2C_Enable = config_data[global];
    global++;
	
    config.Reserved1 = config_data[global];
    global++;
	
    config.I2C_Address = config_data[global];
    global++;
	
    config.Reserved2 = config_data[global];
    global++;
	
    config.CountMatch = config_data[global];
    global++;
	
    config.ChipMode = config_data[global];
    global++;
	
    for (int i = 0; i < N_SLOTS; i++)
    {
        config.SlotConfig[i] = set_16_field(config_data, global);
	global +=2;
    }
	
    for(int i = 0; i < 8; i++)
    {
        config.Counter0[i] = config_data[global];
	global++;
    }
	
    for(int i = 0; i < 8; i++)
    {
        config.Counter1[i] = config_data[global];
	global++;
    }
	
    config.UseLock = config_data[global];
    global++;
	
    config.VolatileKeyPermission = config_data[global];
    global++;
	
    config.SecureBoot = set_16_field(config_data, global);
    global+=2;
	
    config.KdflvLoc = config_data[global];
    global++;
	
    config.KdflvStr = set_16_field(config_data, global);
    global+=2;
	
    for(int i = 0; i < 9; i++)
    {
        config.Reserved3[i] = config_data[global];
	global++;
    }  
	
    config.UserExtra = config_data[global];
    global++;
	
    config.UserExtraAdd = config_data[global];
    global++;
	
    config.LockValue = config_data[global];
    global++;
	
    config.LockConfig = config_data[global];
    global++;
	
    config.SlotLocked = set_16_field(config_data, global);
    global += 2;
	
    config.ChipOptions = set_16_field(config_data, global);
    global += 2;
	
    config.X509format = set_32_field(config_data, global);
    global += 4;
	
    for (int i = 0; i < N_SLOTS; i++)
    {
        config.KeyConfig[i] = set_16_field(config_data, global);
	global +=2;
    }
		
    return config;
}

/* Returns a 16 bit value read from a file */
int read_hex_from_file(FILE* fp, uint8_t* text)
{
    int res;
    
    if (fp == NULL)
    {
        return -1;
    }
 
    res = fscanf(fp, "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X", \
		      &text[0], &text[1], &text[2], &text[3], &text[4], \
		      &text[5], &text[6], &text[7], &text[8], &text[9], \
		      &text[10], &text[11], &text[12], &text[13], &text[14], \
		      &text[15]);
    return res;
}

/* Writes a number of bytes into a file */
int print_hex_to_file(uint8_t* bin, int size, FILE* fp)
{

    if (fp == NULL || bin == NULL || size <= 0)
    {
        return -1;
    }
    
    for(int i=0; i < size; i++)
    { 
        fprintf(fp, "%X ", bin[i]);
    }
 
    fprintf(fp, "\n");
    return 1;
}

