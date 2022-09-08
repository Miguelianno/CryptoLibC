#include "cryptoauthlib.h"
#include "common.h"

/* Peforms a hash fixed string generation of the specified file */
uint8_t* hash_file(FILE* fp);
/* Performs a cbcmac operation using the key of the specified slot */
uint8_t* cbcmac(struct atca_aes_cbc_ctx ctx, int slot, uint8_t* data, int step, struct atca_aes_cbcmac_ctx cbcmac_ctx);
/* Performs a cmac operation using the key of the specified slot */
uint8_t* cmac(struct atca_aes_cbc_ctx ctx, int slot, uint8_t* data, int step);
/* Performs a cbc encryption of the data specified in filename */
int cbc_encryption(char* filename, char* text, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
/* Performs a cbc decryption of the data specified in filename */
int cbc_decryption(char* filename, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
/* Performs a ctr encryption of the data specified in filename */
int ctr_encryption(char* filename, char* text, struct atca_aes_ctr_ctx ctx);
/* Performs a ctr decryption of the data specified in filename */
int ctr_decryption(char* filename, struct atca_aes_ctr_ctx ctx);
/* Performs a ccm encryption of the data specified in filename */
int ccm_encryption(char* filename, char* text, struct atca_aes_ccm_ctx ctx, uint8_t* tag, uint8_t* tag_size, char* filename2, char* aad);
/* Performs a ccm decryption of the data specified in filename */
int ccm_decryption(char* filename, struct atca_aes_ccm_ctx ctx, uint8_t* tag, char* filename2, char* aad);
/* Performs a gcm encryption of the data specified in filename */
int gcm_encryption(char* filename, char* text, struct atca_aes_gcm_ctx ctx, uint8_t* tag, uint8_t* tag_size, char* filename2, char* aad);
/* Performs a gcm decryption of the data specified in filename */
int gcm_decryption(char* filename, struct atca_aes_gcm_ctx ctx, uint8_t* tag, char* filename2, char* aad);
/* Performs a AES-128 encryption of the data specified in filename */
int aes_encryption(char* filename, char* text, int slot);
/* Performs a AES-128 decryption of the data specified in filename */
int aes_decryption(char* filename, int slot);
/* Performs a cbcmac encryption of the data specified in filename */
int cbcmac_encryption(char* filename, char* text, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
/* Performs a cbcmac decryption of the data specified in filename */
int cbcmac_decryption(char* filename, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
/* Performs a cmac decryption of the data specified in filename */
int cmac_encryption(char* filename, char* text, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
/* Performs a cmac decryption of the data specified in filename */
int cmac_decryption(char* filename, int slot, int auth_mode, struct atca_aes_cbc_ctx ctx);
