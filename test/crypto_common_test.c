#include <stdio.h>
#include <assert.h>
#include "crypto_common.h"

#define TEST_TAG_SIZE 16
#define TEST_SMALL_SIZE 25
#define TEST_SMALL_BYTES 32
#define TEST_SMALL_BYTES 64
#define TEST_MEDIUM_SIZE 100
#define TEST_BIG_SIZE 500

/* This programs test all crypto_common functions used in the programs */

int main(int argc, char** argv)
{
    // Auxiliar variables
    FILE* fpn == NULL;
    FILE* fp;
    char filename[TEST_SMALL_SIZE] = "test.txt"
    char filename2[TEST_SMALL_SIZE] = "test2.txt"
    char text[TEST_MEDIUM_SIZE] = "random data for operations and testing"
    uint8_t iv[TEST_SMALL_BYTES];
	  uint8_t iv[TEST_SMALL_BYTES];
	  uint8_t tag[TEST_TAG_SIZE];
	  uint8_t tag_size;
    
    fp = fopen(filename, "r+");
    if (fp == NULL)
    {
        fprintf(stderr, "Can't open file for testing\");
        return -1
    }
    // hashFile
    assert(hash_file(fpn) == NULL);
    assert(hash_file(fp) != NULL);
    fprintf(stdout, "HashFile test result ---------------> \033[0;32mOK\n");
    
    // aesDecryption
    assert(aes_decryption(NULL, 0) == -1);
    assert(aes_decryption(filename, -4) == -1);
    assert(aes_decryption(filename, 0) == 0);
    fprintf(stdout, "AesDecryption test result ---------------> \033[0;32mOK\n");
    
    // aesEncryption
    assert(aes_encryption(NULL, NULL, 0) == -1);
    assert(aes_encryption(filename, NULL, 0) == 0);
    assert(aes_encryption(NULL, text, 0) == 0);
    assert(aes_encryption(filename, text, 0) == 0);
    fprintf(stdout, "AesDecryption test result ---------------> \033[0;32mOK\n");
    
    // cbcEncryption
    struct atca_aes_cbc_ctx ctx;
    
    atcab_random(iv);
	  atcab_aes_cbc_init(&ctx, 5, 0 , iv);
	
    assert(cbc_encryption(NULL, NULL, 0, 0, ctx) == -1);
    assert(cbc_encryption(NULL, text, -4, 0, ctx) == -1);
    assert(cbc_encryption(NULL, text, 0, 0, ctx) == 0);
    assert(cbc_encryption(filename, text, 0, 0, ctx) == 0);
    fprintf(stdout, "cbcEncryption test result ---------------> \033[0;32mOK\n");
    
    // cbcDecryption
    assert(cbc_decryption(NULL, 0, 0, ctx) == -1)
    assert(cbc_decryption(NULL, -10, 0, ctx) == -1)
    assert(cbc_decryption("out.txt", 0, 0, ctx) == 0)
    fprintf(stdout, "cbcDecyption test result ---------------> \033[0;32mOK\n");
    
    // cmacEncryption
    struct atca_aes_cbc_ctx ctx1;
    
	  atcab_aes_cbc_init(&ctx, 5, 0 , iv);
    
    assert(cmac_encryption(NULL, NULL, 0, 0, ctx1) == -1);
    assert(cmac_encryption(NULL, text, -4, 0, ctx1) == -1);
    assert(cmac_encryption(NULL, text, 0, 0, ctx1) == 0);
    assert(cmac_encryption(filename, text, 0, 0, ctx1) == 0);
    fprintf(stdout, "cmacEncryption test result ---------------> \033[0;32mOK\n");
     
    // cmacDecryption
    assert(cmac_decryption(NULL, 0, 0, ctx) == -1)
    assert(cmac_decryption(NULL, -10, 0, ctx) == -1)
    assert(cmac_decryption("out.txt", 0, 0, ctx) == 0)
    fprintf(stdout, "cmacDecryption test result ---------------> \033[0;32mOK\n");
    
    // cbcMac operation not working yet
    
    // ctrEncryption
    struct atca_aes_ctr_ctx ctr_ctx;
    atcab_aes_ctr_init(&ctr_ctx, 5, 0, 4, iv);
    
    assert(ctr_encryption(NULL, text, ctr_ctx) == -1);
    assert(ctr_encryption(filename, NULL, ctr_ctx) == -1);
    assert(ctr_encryption(filename, text, ctr_ctx) == 0);
    fprintf(stdout, "ctrEncryption test result ---------------> \033[0;32mOK\n");
    
    // ctrDecryption
    atcab_aes_ctr_init(&ctr_ctx, 5, 0, 4, iv);
    
    assert(ctr_decryption(NULL, ctr_ctx) == -1);
    assert(ctr_decryption("out.txt", ctr_ctx) == 0);
    fprintf(stdout, "ctrDecryption test result ---------------> \033[0;32mOK\n");
    
    // ccmEncryption
    struct atca_aes_ccm_ctx ccm_ctx;
           
    atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, 16, 16, 16);
    
    assert(ccm_encryption(NULL, NULL, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == -1);
    assert(ccm_encryption(NULL, NULL, ccm_ctx, tag, &tag_size, NULL, NULL) == -1);
    assert(ccm_encryption(NULL, text, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption(filename, NULL, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption(filename, NULL, ccm_ctx, tag, &tag_size, NULL, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, NULL, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, filename2, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, filename2, NULL) == 0);
    assert(ccm_encryption(filename, text, ccm_ctx, tag, &tag_size, filename2, "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "ccmEncryption test result ---------------> \033[0;32mOK\n");
    
    // ccmDecryption
    atcab_aes_ccm_init(&ccm_ctx, 5, 0, iv, 12, 16, 16, 16);
    
    assert(ccm_decryption(NULL, ccm_ctx, tag, NULL, NULL) == -1);
    assert(ccm_decryption("out.txt", ccm_ctx, tag, NULL, NULL) == 0);
    assert(ccm_encryption("out.txt", text, ccm_ctx, tag, &tag_size, filename2, NULL) == 0);
    assert(ccm_encryption("out.txt", text, ccm_ctx, tag, &tag_size, NULL, "Additional Authenticated data for testing") == 0);
    assert(ccm_encryption("out.txt", text, ccm_ctx, tag, &tag_size, filename2, NULL) == 0);
    assert(ccm_encryption("out.txt", text, ccm_ctx, tag, &tag_size, filename", "Additional Authenticated data for testing") == 0);
    fprintf(stdout, "ccmDecryption test result ---------------> \033[0;32mOK\n");
    
    // gcmEncryption
    struct atca_aes_gcm_ctx gcm_ctx;
    
    atcab_aes_gcm_init(&gcm_ctx, 5, 0, iv, 32);
    
    assert(gcm_encryption(NULL, NULL, gcm_ctx, tag, &tag_size, filename2, aad) == -1);
    assert(gcm_encryption(NULL, NULL, gcm_ctx, tag, &tag_size, NULL, NULL) == -1);
    assert(gcm_encryption(filename, NULL, gcm_ctx, tag, &tag_size, filename2, aad) == 0);
    assert(gcm_encryption(NULL, text, gcm_ctx, tag, &tag_size, filename2, aad) == 0);
    assert(gcm_encryption(filename, NULL, gcm_ctx, tag, &tag_size, filename2, NULL) == 0);
    assert(gcm_encryption(NULL, text, gcm_ctx, tag, &tag_size, NULL, aad) == 0);
    assert(gcm_encryption(filename, text, gcm_ctx, tag, &tag_size, filename2, aad) == 0);
    fprintf(stdout, "gcmEncryption test result ---------------> \033[0;32mOK\n");
    
    //gcmDecryption
    assert(gcm_encryption(NULL", gcm_ctx, tag, filename2, aad) == -1);
    assert(gcm_encryption(NULL,  gcm_ctx, tag, NULL, NULL) == -1);
    assert(gcm_encryption("out.txt", gcm_ctx, tag, filename2, NULL) == 0);
    assert(gcm_encryption("out.txt", gcm_ctx, tag, NULL, aad) == 0);
    assert(gcm_encryption("out.txt", gcm_ctx, tag, filename2, aad) == 0);
    fprintf(stdout, "gcmDecryption test result ---------------> \033[0;32mOK\n");
    
}
