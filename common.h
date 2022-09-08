#include "cryptoauthlib.h"


#define CLEAR 8
#define ENCRYPTED 5
#define CONFIG_SIZE 128
#define N_SLOTS 16
#define ENC_SIZE 16


ATCADevice getATCADevice();
/* Returns the specified configuration */
uint8_t* get_defined_configuration();
struct _atecc608_config set_configuration(uint8_t* config_data);
/* Converts a string of characters into an array of bytes */
int char_to_uint8(char* str, uint8_t* res, int size);
/* Writes a number of bytes into a file */
int print_hex_to_file(uint8_t* bin, int size, FILE* fp);
/* Returns a 16 bit value read from a file */
int read_hex_from_file(FILE* fp, uint8_t* text);
/* Convert a group of bytes into a string of characters */
int uint8_to_char(uint8_t* data, char* res, int size);
/* Prints the values for the defined configuration */
void print_configuration(struct _atecc608_config config);
/* Generates a random nonce for cryptographic use */
ATCA_STATUS generate_nonce(uint8_t* rand_out);
/* Set a 32 bit field with the given data inside the device configuration in the place indicated by the index */
uint32_t set_32_field(uint8_t* data, int index);
/* Set a 16 bit field with the given data inside the device configuration in the place indicated by the index */
uint16_t set_16_field(uint8_t* data, int index);


