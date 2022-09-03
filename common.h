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
uint8_t* char_to_uint8(char* str, int size);
/* Writes a number of bytes into a file */
void print_hex_to_file(uint8_t* tmp, size_t size, FILE* fo);
/* Returns a 16 bit value read from a file */
int read_hex_from_file(FILE* fp, uint8_t* text);
/* Convert a group of bytes into a string of characters */
char* uint8_to_char(uint8_t* data, int size);
/* Prints the values for the defined configuration */
void print_configuration(struct _atecc608_config config);
/* Prints a group of bytes in hexadecimal format */
void print_hex(uint8_t* bin, size_t size);
/* Generates a random nonce for cryptographic use */
ATCA_STATUS generate_nonce(uint8_t* rand_out);
