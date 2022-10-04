#include <stdio.h>
#include <assert.h>
#include "../crypto_common.h"

#define TEST_TAG_SIZE 16
#define TEST_SMALL_BYTES 32
#define TEST_BIG_BYTES 64
#define TEST_SMALL_SIZE 25
#define TEST_MEDIUM_SIZE 100
#define TEST_BIG_SIZE 500

/* Resets the output to default color */
void reset_color()
{
    printf("\033[0m");
}

/* This programs test all crypto_common functions used in the programs */
int main(int argc, char** argv)
{
    // Auxiliar variables
    FILE* fpn = NULL;
    FILE* fp;
    FILE* fp2;
    char filename[TEST_SMALL_SIZE] = "test.txt";
    char filename2[TEST_SMALL_SIZE] = "test2.txt";
    char text[TEST_MEDIUM_SIZE] = "random data for operations and testing";
    uint8_t iv[TEST_SMALL_BYTES];
    uint8_t tag[TEST_TAG_SIZE];
    uint8_t tag1[TEST_TAG_SIZE];
    uint8_t tag2[TEST_TAG_SIZE];
    uint8_t tag3[TEST_TAG_SIZE];
    uint8_t tag4[TEST_TAG_SIZE];
    uint8_t tag_size;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    ATCA_STATUS status;
    
    fp = fopen(filename, "r+");
    if (fp == NULL)
    {
        fprintf(stderr, "Can't open file %s\n", filename);
        return -1;
    }

    fp2 = fopen(filename2, "r+");
    if (fp2 == NULL)
    {
        fprintf(stderr, "Can't open file %s\n", filename2);
        return -1;
    }

    gCfg->atcai2c.bus=1;
    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCA Device\n");
        return -1;
    }

    // hashFile
    /* Initializes SHA-256 calculation engine */
    status = atcab_sha_start();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error starting sha engine\n");
	return -1;
    }

    assert(hash_file(fpn) == NULL);
    assert(hash_file(fp) != NULL);
    fprintf(stdout, "HashFile test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // aesEncryption
    assert(aes_encryption(NULL, NULL, 0) == -1);
    assert(aes_encryption(filename, NULL, -2) == -1);
    assert(aes_encryption(NULL, text, 5) == 0);
    assert(aes_encryption(filename, text, 5) == 0);
    fprintf(stdout, "AesEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();

    // aesDecryption
    assert(aes_decryption(NULL, 0) == -1);
    assert(aes_decryption(filename, -4) == -1);
    assert(aes_decryption("enc.txt", 5) == 0);
    fprintf(stdout, "AesDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // cbcEncryption
    struct atca_aes_cbc_ctx ctx;
    
    status = atcab_random(iv);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error generating iv\n");
	return -1;
    }

    atcab_aes_cbc_init(&ctx, 5, 0 , iv);
	
    assert(cbc_encryption(NULL, NULL, 0, ctx) == -1);
    assert(cbc_encryption(NULL, text, -4, ctx) == -1);
    assert(cbc_encryption(NULL, text, 5, ctx) == 0);
    assert(cbc_encryption(filename, text, 5, ctx) == 0);
    fprintf(stdout, "cbcEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // cbcDecryption
    assert(cbc_decryption(NULL, 0, ctx) == -1);
    assert(cbc_decryption(NULL, -10, ctx) == -1);
    assert(cbc_decryption("enc.txt", 5, ctx) == 0);
    fprintf(stdout, "cbcDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // cmacEncryption
    struct atca_aes_cbc_ctx ctx1;
    uint8_t mac[TEST_TAG_SIZE];
    
    atcab_aes_cbc_init(&ctx1, 5, 0 , iv);
    
    assert(cmac_encryption(NULL, NULL, 0, ctx1, mac) == -1);
    assert(cmac_encryption(NULL, text, -4, ctx1, mac) == -1);
    assert(cmac_encryption(NULL, text, 5, ctx1, mac) == 0);
    assert(cmac_encryption(filename, text, 5, ctx1, mac) == 0);
    fprintf(stdout, "cmacEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();
     
    // cmacDecryption
    assert(cmac_decryption(NULL, 0, ctx1, mac) == -1);
    assert(cmac_decryption(NULL, -10, ctx1, mac) == -1);
    assert(cmac_decryption("enc.txt", 5, ctx1, mac) == 0);
    fprintf(stdout, "cmacDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // cbcMac operation not working yet
    
    // ctrEncryption
    struct atca_aes_ctr_ctx ctr_ctx;
    atcab_aes_ctr_init(&ctr_ctx, 5, 0, 4, iv);
    
    assert(ctr_encryption(NULL, NULL, ctr_ctx) == -1);
    assert(ctr_encryption(filename, NULL, ctr_ctx) == 0);
    assert(ctr_encryption(NULL, text, ctr_ctx) == 0);
    assert(ctr_encryption(filename, text, ctr_ctx) == 0);
    fprintf(stdout, "ctrEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // ctrDecryption
    atcab_aes_ctr_init(&ctr_ctx, 5, 0, 4, iv);
    
    assert(ctr_decryption(NULL, ctr_ctx) == -1);
    assert(ctr_decryption("enc.txt", ctr_ctx) == 0);
    fprintf(stdout, "ctrDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // ccmEncryption
    struct atca_aes_ccm_ctx ccm_ctx;
           
    atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, 16, 16, 16);
    
    assert(ccm_encryption(NULL, NULL, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == -1);
    assert(ccm_encryption(NULL, NULL, ccm_ctx, tag, &tag_size, NULL, NULL) == -1);
    assert(ccm_encryption(NULL, text, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption(filename, NULL, ccm_ctx, tag1, &tag_size, NULL, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag2, &tag_size, filename2, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag3, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag4, &tag_size, filename2, "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "ccmEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // ccmDecryption
    atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, 16, 16, 16);
    
    assert(ccm_decryption(NULL, ccm_ctx, tag, NULL, NULL) == -1);
    assert(ccm_decryption("enc.txt", ccm_ctx, tag1, NULL, NULL) == 0);
    assert(ccm_decryption("enc.txt", ccm_ctx, tag2, filename2, NULL) == 0);
    assert(ccm_decryption("enc.txt", ccm_ctx, tag3, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_decryption("enc.txt", ccm_ctx, tag4, filename2, "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "ccmDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    // gcmEncryption
    struct atca_aes_gcm_ctx gcm_ctx;
    
    atcab_aes_gcm_init(&gcm_ctx, 5, 0, iv, 32);
    
    assert(gcm_encryption(NULL, NULL, gcm_ctx, tag, &tag_size, filename2, "Additional Authenticated data for testing"));
    assert(gcm_encryption(NULL, NULL, gcm_ctx, tag, &tag_size, NULL, NULL) == -1);
    assert(gcm_encryption(filename, NULL, gcm_ctx, tag1, &tag_size, NULL, NULL) == 0);
    assert(gcm_encryption(filename, text, gcm_ctx, tag2, &tag_size, filename2, NULL) == 0);
    assert(gcm_encryption(filename, text, gcm_ctx, tag3, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(gcm_encryption(filename, text, gcm_ctx, tag4, &tag_size, filename2, "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "gcmEncryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    //gcmDecryption
    assert(gcm_decryption(NULL, gcm_ctx, tag, filename2, "Additional Authenticated data for testing") == -1);
    assert(gcm_decryption(NULL,  gcm_ctx, tag, NULL, NULL) == -1);
    assert(gcm_decryption("enc.txt", gcm_ctx, tag1, NULL, NULL) == 0);
    assert(gcm_decryption("enc.txt", gcm_ctx, tag2, filename2, NULL) == 0);
    assert(gcm_decryption("enc.txt", gcm_ctx, tag3, NULL, "Additional Authenticated data for testing") == 0);
    assert(gcm_decryption("enc.txt", gcm_ctx, tag4, filename2, "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "gcmDecryption test result ---------------> \033[0;32mOK\n");
    reset_color();
    
    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        return -1;
    }

    fclose(fp);
    fclose(fp2);

    return 0;
}
