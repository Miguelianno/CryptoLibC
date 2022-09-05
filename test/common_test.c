#include <stdio.h>
#include <assert.h>
#include "common.h"

#define TEST_SMALL_SIZE 25
#define TEST_SMALL_BYTES 32
#define TEST_SMALL_BYTES 64
#define TEST_MEDIUM_SIZE 100
#define TEST_BIG_SIZE 500

/* This programs test all common functions used in the programs */

int main(int argc, char** argv)
{
    // Auxiliar values
    uint8_t test1[TEST_SMALL_SIZE];
    uint8_t test2[TEST_MEDIUM_SIZE];
    uint8_t test3[TEST_BIG_SIZE];
    ATCA_STATUS status;
    uint8_t aux[TEST_SMALL_BYTES];
    uint8_t aux1[TEST_SMALL_BYTES]
    atcab_random(aux);
    FILE* fpn == NULL;
    FILE* fp;

    fp = fopen("test.txt", "r+");
    if (fp == NULL)
    {
        fprintf(stderr, "Can't open file for testing\");
        return -1
    }

    // getATCADevice
    assert(getATCADevice() != NULL);
    fprintf(stdout, "GetATCADevice test result ---------------> \033[0;32mOK\n");

    // charToUint8
    assert(char_to_uint8(NULL, test1, TEST_SMALL_SIZE) == -1);
    assert(char_to_uint8(test2, test1, -20) == -1);
    assert(char_to_uint8(aux, test2, 32) == 0);
    fprintf(stdout, "charToUint8 test result ---------------> \033[0;32mOK\n");

    // uint8_to_char
    assert(uint8_to_char(NULL, test1, TEST_SMALL_SIZE) == -1);
    assert(uint8_to_char(aux, test2, -20) == -1);
    assert(uint8_to_char(aux, test2, 32) == 0);
    fprintf(stdout, "Uint8ToChar test result ---------------> \033[0;32mOK\n");

    // generateNonce
    assert(generate_nonce(aux1) == ATCA_SUCCESS);
    fprintf(stdout, "GenerateNonce test result ---------------> \033[0;32mOK\n");

    // set32field
    assert(set_32_field(NULL, 0) == -1);
    assert(set_32_field(aux, -4) == -1);
    assert(set_32_field(aux, 0) != -1);
    fprintf(stdout, "set32field test result ---------------> \033[0;32mOK\n");

    // set16field
    assert(set_16_field(NULL, 0) == -1);
    assert(set_16_field(aux, -4) == -1);
    assert(set_16_field(aux, 0) != -1);
    fprintf(stdout, "set16field test result ---------------> \033[0;32mOK\n");

    // readHexFromFile
    assert(read_hex_from_file(fpn, test1) <= 0);
    assert(read_hex_from_file(fp, test1) <= 0);
    fprintf(stdout, "readHexFromFile test result ---------------> \033[0;32mOK\n");
    
    // printHexToFile
    assert(print_hex_to_file(NULL, 10, fp) == -1);
    assert(print_hex_to_file(aux1, 32, fpn) == -1);
    assert(print_hex_to_file(aux1, -10, fp) == -1);
    assert(print_hex_to_file(aux1, 32, fp) == 1);
    fprintf(stdout, "printHexToFile test result ---------------> \033[0;32mOK\n");
    
    // printHex
    assert(print_hex(NULL, 10) == -1);
    assert(print_hex(aux1, -4) == -1);
    assert(print_hex(aux1, -32) == 1);
    fprintf(stdout, "printHex test result ---------------> \033[0;32mOK\n");

}
