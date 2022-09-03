#include "crypto_common.h"

#define SIGNATURE_SIZE 32
#define DATA_SIZE 64

/* Prints the cbc context structure */
void print_cbc_ctx(struct atca_aes_cbc_ctx ctx)
{

    fprintf(stdout, "Key_id: %d\n", ctx.key_id);
    fprintf(stdout, "Key_block: %d\n", ctx.key_block);
    fprintf(stdout, "Ciphertext: ");
    for (int i = 0; i < ENC_SIZE ; i++)
    {
        fprintf(stdout, "%X ", ctx.ciphertext[i]);
    }    

}

/* Prints the cbcmac context structure */
void print_cbcmac_ctx(struct atca_aes_cbcmac_ctx ctx)
{

    fprintf(stdout, "Block size: %d\n", ctx.block_size);
    fprintf(stdout, "Block: ");
    for (int i = 0; i < ENC_SIZE; i++)
    {
        fprintf(stdout, "%X ", ctx.block[i]);
    }

}

/* Prints the cmac context structure */
void print_cmac_ctx(struct atca_aes_cmac_ctx ctx)
{

    fprintf(stdout, "Block size: %d\n", ctx.block_size);
    fprintf(stdout, "Block: ");
    for (int i = 0; i < ENC_SIZE; i++)
    {
        fprintf(stdout, "%X ", ctx.block[i]);
    }

}

/* Peforms a hash fixed string generation of the specified file */
uint8_t* hash_file(FILE* fp)
{
    ATCA_STATUS status;
    int end_sha_flag = 0;
    int file_size, file_index = 0;
    uint8_t *digest;
    uint8_t message[DATA_SIZE];

    digest = (uint8_t*)malloc(SIGNATURE_SIZE*sizeof(uint8_t));
    if (digest == NULL)
    {
        fprintf(stderr, "Error allocating memory for signature\n");
	return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    if (DATA_SIZE >= file_size)
    {		
        fread(message, file_size, 1, fp);
	/* Executes SHA command to complete SHA-256 operation */
	status = atcab_sha_end(digest, file_size, message);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error finalizing sha\n");
	    exit(status);
	}
    
	end_sha_flag = 1;
    }

    fseek(fp, 0, SEEK_SET);
    while(!end_sha_flag)
    {
        file_index += DATA_SIZE;
	if (file_index < file_size)
	{	
	    fread(message, DATA_SIZE, 1, fp);
	    /* Add 64 bytes of message data to the current SHA context */
 	    status = atcab_sha_update(message);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error updating sha\n");
		exit(status);
	    }
           
	    fseek(fp, file_index, SEEK_SET);
        }
	else
	{
	    file_index -= DATA_SIZE;
	    fread(message, file_size - file_index, 1, fp);
	    /* Executes SHA command to complete SHA-256 operation */
	    status = atcab_sha_end(digest, file_size - file_index, message);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error finalizing sha\n");
	        exit(status);
	    }
			
	    end_sha_flag = 1;
        }
	strncpy(message, "\0", DATA_SIZE);
    }

    return digest;
}

/* Decrypts the information stored in the specified file with the key stored in the given slot */
int aes_decryption(char* filename, uint16_t slot){
    FILE* fi;
    FILE* fo;
    uint8_t text[ENC_SIZE];
    ATCA_STATUS status;
    char* res;
    uint8_t out[ENC_SIZE];
    char* out_file = "dec.txt";
    
    fprintf(stdout, "Decrypting file\n");
    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", filename);
        return -1;
    }
    
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
    return -1;
    }
 
    while (read_hex_from_file(fi, text) != EOF)
    {
        /* Perform an AES-128 decrypt operation with a key in the device */
        status = atcab_aes_decrypt (slot, 0, text, out);
        if (status != ATCA_SUCCESS)
        {  
            fprintf(stderr, "Error encrypting\n");
            fclose(fo);
            fclose(fi);
            return -1;
        }
               
        res = uint8_to_char(out, 16);
        fprintf(fo, "%s", res);
    }
    
    free(res);
    fclose(fo);
    fclose(fi);
    
    return 0;
}

/* Encrypts the information stored in the specified file with the key stored in the given slot */
int aes_encryption(char* filename, char* text, uint16_t slot){
    FILE* fi = NULL;
    FILE* fo;
    int i = 0, text_size;
    uint8_t str[ENC_SIZE];
    char* aux;
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "enc.txt";
    
    fprintf(stdout, "Encrypting file\n");
    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "File %s does not exist\n", filename);
            return -1;
        }
    }
    
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
        return -1;
    }
    
    aux = text;
    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_encrypt (slot, 0, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
        }
    }
    else if (strcmp(text, "\0"))
    {
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_encrypt (slot, 0, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt");
	return -1;
    }
    
    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }
    return 0;
}


/*int decrypt_file(char* filename, uint16_t slot){
	FILE* fi;
	FILE* fo;
	uint8_t str[ENC_SIZE];
	ATCA_STATUS status;
	char out[ENC_SIZE];
	char* out_file = "dec.txt";
	
	fi = fopen(filename, "r");
	if (fi == NULL)
	{
		printf("File %s does not exist\n", filename);
		return -1;
	}
	
	fo = fopen(out_file, "w");
	if (fo == NULL)
	{
		printf("File %s does not exist\n", out_file);
		return -1;
	}
	
	while (fgets(str, ENC_SIZE, fi) != NULL)
	{
		status = atcab_aes_decrypt (slot, 0, str, out);
		if (status != ATCA_SUCCESS)
		{
			printf("Error encrypting\n");
			fclose(fp);
			fclose(fi);
			return -1;
		}
		fputs(out, fo);
	}
	
	fclose(fp);
	fclose(fi);
	return 0;
}


int encrypt_file(char* filename, uint16_t slot){
	FILE* fi;
	FILE* fo;
	uint8_t str[ENC_SIZE];
	ATCA_STATUS status;
	char out[ENC_SIZE];
	char* out_file = "enc.txt";
	
	fi = fopen(filename, "r");
	if (fi == NULL)
	{
		printf("File %s does not exist\n", filename);
		return -1;
	}
	
	fo = fopen(out_file, "w");
	if (fo == NULL)
	{
		printf("File %s does not exist\n", out_file);
		return -1;
	}
	
	while (fgets(str, ENC_SIZE, fi) != NULL)
	{
		status = atcab_aes_encrypt (slot, 0, str, out);
		if (status != ATCA_SUCCESS)
		{
			printf("Error encrypting\n");
			fclose(fp);
			fclose(fi);
			return -1;
		}
		fputs(out, fo);
	}
	
	fclose(fp);
	fclose(fi);
	return 0;
}
*/

/* Performs a cbcmac operation using the key of the specified slot */
uint8_t* cbcmac(struct atca_aes_cbc_ctx ctx, int slot, uint8_t* data, int step, struct atca_aes_cbcmac_ctx cbcmac_ctx){
    ATCA_STATUS status;
    uint8_t *mac = NULL;

    /* Initialize context for AES CBC-MAC operation */
    status = atcab_aes_cbcmac_init(&cbcmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cbcmac operation: %x\n", status);
        return NULL;
    }
	
	/* Calculate AES CBC-MAC with key stored within ECC608A device */
    status = atcab_aes_cbcmac_update(&cbcmac_ctx, data, 15);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error updating cbcmac operation\n");
        return NULL;
    }

	/* Finish a CBC-MAC operation returning the CBC-MAC value */
    status = atcab_aes_cbcmac_finish(&cbcmac_ctx, mac, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
         fprintf(stderr, "Error finishing cbcmac operation: %x\n", status);
	 return NULL;
    }

    return mac;
}

/* Performs a cmac operation using the key of the specified slot */
uint8_t* cmac(struct atca_aes_cbc_ctx ctx, int slot, uint8_t* data, int step){
    struct atca_aes_cmac_ctx cmac_ctx;
    ATCA_STATUS status;
    uint8_t *cmac = NULL;

    if (step == 1)
    {
    	/* Initialize a CMAC calculation using an AES-128 key in the device */
        status = atcab_aes_cmac_init(&cmac_ctx, slot, 0);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error initializing cmac operation\n");
	        return NULL;
	    }
    }
    else if (step == 2)
    {
        /* Add data to an initialized CMAC calculation */
        status = atcab_aes_cmac_update(&cmac_ctx, data, ENC_SIZE);
        if (status != ATCA_SUCCESS)
        {
	    fprintf(stderr, "Error updating cmac operation\n");
	    return NULL;
	}
    }
    else
    {
    	/* Finish a CMAC operation returning the CMAC value */
        status = atcab_aes_cmac_finish(&cmac_ctx, cmac, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error initializing cmac operation\n");
	        return NULL;
	    }
    }

    return cmac;
}

/* Performs a cbc encryption of the data specified in filename */
int cbc_encryption(char* filename, char* text, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx)
{
    struct atca_aes_cbcmac_ctx cbcmac_ctx;
    FILE* fi = NULL;
    FILE* fo = NULL;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status = ATCA_SUCCESS;
    char out[ENC_SIZE];
    char* aux;
    char* out_file = "enc.txt";
    uint8_t mac[ENC_SIZE];
    int i = 0, text_size;
    struct atca_aes_cmac_ctx cmac_ctx;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "File %s does not exist\n", filename);
	    return -1;
        }
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }
	
    aux = text;
    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
        }
    }
    else if (strcmp(text, "\0"))
    {
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt");
	return -1;
    }

    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    return 0;
}


/* Performs a cbc encryption of the data specified in filename */
int cmac_encryption(char* filename, char* text, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx) {
    FILE* fi = NULL;
    FILE* fo = NULL;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status = ATCA_SUCCESS;
    char out[ENC_SIZE];
    char* aux;
    char* out_file = "enc.txt";
    uint8_t mac[ENC_SIZE];
    int i = 0, text_size;
    struct atca_aes_cmac_ctx cmac_ctx;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "File %s does not exist\n", filename);
	    return -1;
        }
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }
	
    /* Initialize a CMAC calculation using an AES-128 key in the device */
    status = atcab_aes_cmac_init(&cmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cmac operation\n");
	return -1;
    }
	    
    aux = text;
    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
	    /* Add data to an initialized CMAC calculation */
	    status = atcab_aes_cmac_update(&cmac_ctx, out, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error initializing cmac operation\n");
                return -1;
	    }
	}
    }
    else if (strcmp(text, "\0"))
    {
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);

	    /* Add data to an initialized CMAC calculation */
	    status = atcab_aes_cmac_update(&cmac_ctx, out, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error initializing cmac operation\n");
                return -1;
	    }
            
	    i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt");
	return -1;
    }

    /* Finish a CMAC operation returning the CMAC value */
    status = atcab_aes_cmac_finish(&cmac_ctx, mac, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cmac operation\n");
	return -1;
    }

    if (mac == NULL)
    {
        fprintf(stderr, "Error in mac operation\n");
	    return -1;
    }

    fprintf(stdout, "MAC in encryption function: ");
    print_hex(mac, 16);

    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    return 0;
}

/* Performs a cbc encryption of the data specified in filename */
int cbcmac_encryption(char* filename, char* text, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx) 
{
    struct atca_aes_cbcmac_ctx cbcmac_ctx;
    FILE* fi = NULL;
    FILE* fo = NULL;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status = ATCA_SUCCESS;
    char out[ENC_SIZE];
    char* out_file = "enc.txt";
    char* aux;
    uint8_t mac[ENC_SIZE];
    int i = 0, text_size;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "File %s does not exist\n", filename);
	    return -1;
        }
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }
	
    /* Initialize context for AES CBC-MAC operation */
    status = atcab_aes_cbcmac_init(&cbcmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cbcmac operation: %x\n", status);
	return -1;
    }

    aux = text;
    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
	    /* Add data to an initialized CMAC calculation */
	    status = atcab_aes_cbcmac_update(&cbcmac_ctx, out, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error initializing cmac operation\n");
                return -1;
	    }
	}
    }
    else if (strcmp(text, "\0"))
    {
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_cbc_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt");
	return -1;
    }

    /* Finish a CBC-MAC operation returning the CBC-MAC value */
    status = atcab_aes_cbcmac_finish(&cbcmac_ctx, mac, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cmac operation\n");
	return -1;
    }

    if (mac == NULL)
    {
        fprintf(stderr, "Error in mac operation\n");
	    return -1;
    }

    fprintf(stdout, "MAC in encryption function: ");
    print_hex(mac, 16);

    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }
    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cbc_decryption(char* filename, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx)
{
    struct atca_aes_cbcmac_ctx cbcmac_ctx;
    FILE* fi;
    FILE* fo;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "dec.txt";
    int step = 1;
    uint8_t mac[ENC_SIZE];
    char* res;
    struct atca_aes_cmac_ctx cmac_ctx;

	    printf("AQUI\n");
    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", filename);
	return -1;
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
	    printf("AQUI\n");
	/* Decrypt a block of data using CBC mode and a key within the device */
	status = atcab_aes_cbc_decrypt_block (&ctx, str, out);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
	}

	res = uint8_to_char(out, 16);
	fprintf(fo, "%s", res);
    }

    free(res);
    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cmac_decryption(char* filename, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx)
{
    FILE* fi;
    FILE* fo;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "dec.txt";
    uint8_t mac[ENC_SIZE];
    char* res;
    struct atca_aes_cmac_ctx cmac_ctx;

    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", filename);
	return -1;
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    /* Initialize a CMAC calculation using an AES-128 key in the device */
    status = atcab_aes_cmac_init(&cmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cmac operation\n");
	return -1;
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
        /* Add data to an initialized CMAC calculation */
        status = atcab_aes_cmac_update(&cmac_ctx, str, ENC_SIZE);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error updating cmac operation\n");
            return -1;
	}

	/* Decrypt a block of data using CBC mode and a key within the device */
	status = atcab_aes_cbc_decrypt_block (&ctx, str, out);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
	}

	res = uint8_to_char(out, 16);
	fprintf(fo, "%s", res);

	print_hex(str, 16);
    }

    /* Finish a CMAC operation returning the CMAC value */
    status = atcab_aes_cmac_finish(&cmac_ctx, mac, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing cmac operation\n");
	return -1;
    }

    if (mac == NULL)
    {
        fprintf(stderr, "Error in mac operation\n");
	    return -1;
    }

    fprintf(stdout, "MAC in decryption function: ");
    print_hex(mac, 16);

    free(res);
    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cbcmac_decryption(char* filename, uint16_t slot, int auth_mode, struct atca_aes_cbc_ctx ctx)
{
    struct atca_aes_cbcmac_ctx cbcmac_ctx;
    FILE* fi;
    FILE* fo;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "dec.txt";
    int step = 1;
    uint8_t mac[ENC_SIZE];
    char* res;

    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", filename);
	return -1;
    }
	
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    /* Initialize context for AES CBC-MAC operation */
    status = atcab_aes_cbcmac_init(&cbcmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cbcmac operation1: %x\n", status);
	return -1;
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
	print_hex(str, 16);
        /* Calculate AES CBC-MAC with key stored within ECC608A device */
      	status = atcab_aes_cbcmac_update(&cbcmac_ctx, str, ENC_SIZE);
  	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error updating cbcmac operation: %x\n", status);
            return -1;
	}
    
        /* Decrypt a block of data using CBC mode and a key within the device */
        status = atcab_aes_cbc_decrypt_block (&ctx, str, out);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
        }
    }
    res = uint8_to_char(out, 16);
    fprintf(fo, "%s", res);

    print_hex(str, 16);
    

    /* Finish a CBC-MAC operation returning the CBC-MAC value */
    status = atcab_aes_cbcmac_finish(&cbcmac_ctx, mac, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing cbcmac operation\n");
	return -1;
    }

    if (mac == NULL)
    {
        fprintf(stderr, "Error in mac operation\n");
	    return -1;
    }

    fprintf(stdout, "MAC in decryption function: ");
    print_hex(mac, 16);

    free(res);
    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a ctr encryption of the data specified in filename */
int ctr_encryption(char* filename, char* text, struct atca_aes_ctr_ctx ctx)
{
    FILE* fi = NULL;
    FILE* fo = NULL;
    int i = 0, text_size;
    char* aux;
    char* out_file = "enc.txt";
    uint8_t str[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    ATCA_STATUS status;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "Error opening %s\n", filename);
	    return -1;
        }
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_ctr_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
	    status = atcab_aes_ctr_increment(&ctx);
 	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error incrementing counter\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
        }
    }
    else if (strcmp(text, "\0"))
    {
        aux = text;
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

	    printf("Str: %s\n", str);
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_ctr_encrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;

	    status = atcab_aes_ctr_increment(&ctx);
 	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error incrementing counter\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt");
	return -1;
    }

    fprintf(stdout, "Finishing ctr encryption\n");
    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    return 0;
}

/* Performs a ctr decryption of the data specified in filename */
int ctr_decryption(char* filename, struct atca_aes_ctr_ctx ctx)
{
    FILE* fi;
    FILE* fo;
    char* out_file = "dec.txt";
    uint8_t str[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    char* res;
    ATCA_STATUS status;

    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "Error opening %s\n", filename);
	return -1;
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
    	/* Decrypt a block of data using CTR mode and a key within the device */
	    status = atcab_aes_ctr_decrypt_block (&ctx, str, out);
	    if (status != ATCA_SUCCESS)
	    {
            fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
        }

        res = uint8_to_char(out, 16);
        fprintf(fo, "%s", res);

        /* Increments AES CTR counter value */
	    status = atcab_aes_ctr_increment(&ctx);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error incrementing counter\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
    }

    free(res);
    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a ccm encryption of the data specified in filename */
int ccm_encryption(char* filename, char* text, struct atca_aes_ccm_ctx ctx, uint8_t* tag, uint8_t* tag_size, char* filename2, char* aad)
{
    FILE* fi = NULL;
    FILE* fi2 = NULL;
    FILE* fo;
    char* out_file = "enc.txt";
    uint8_t str[ENC_SIZE];
    int i = 0, text_size;
    char* aux;
    uint8_t out[ENC_SIZE];
    ATCA_STATUS status;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "Error opening %s\n", filename);
	    return -1;
        }
    }

    if (strcmp(filename2, "\0"))
    {
        fi2 = fopen(filename2, "r");
        if (fi2 == NULL)
        {
            fprintf(stderr, "Error opening %s\n", filename2);
	    return -1;
        }
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (strcmp(filename2, "\0"))
    {
        while (fgets(str, ENC_SIZE, fi2) != NULL)
        {
    	    /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_ccm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
            } 
        }
    }
    else if (strcmp(aad, "\0"))
    {
        while (i < strlen(aad))
	{
            strncpy(str, aad, ENC_SIZE);
    	    /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_ccm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
	    }
            i +=16;
	}
    }
    else
	/* No aad to process */

    /* Finish processing Additional Authenticated Data (AAD) using CCM mode */
    status = atcab_aes_ccm_aad_finish (&ctx);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    fclose(fi2);
	    return -1;
    }

    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_ccm_encrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
        }
    }
    else if (strcmp(text, "\0"))
    {
	aux = text;
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_ccm_encrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt\n");
    }

    status = atcab_aes_ccm_encrypt_finish (&ctx, tag, tag_size);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
    }

    fprintf(stdout, "Finishing ccm encryption\n");
    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    if (fi2 != NULL)
    {
        fclose(fi2);
    }

    return 0;
}

/* Performs a ccm decryption of the data specified in filename */
int ccm_decryption(char* filename, struct atca_aes_ccm_ctx ctx, uint8_t* tag, char* filename2, char* aad)
{
    FILE* fi;
    FILE* fi2;
    FILE* fo;
    char* out_file = "dec.txt";
    uint8_t str[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    char* res;
    int i = 0;
    ATCA_STATUS status;
    bool is_verified;

    fprintf(stdout, "Initializing ccm decryption\n");
    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "Error opening %s\n", filename);
	return -1;
    }

    if (strcmp(filename2, "\0"))
    {
        fi2 = fopen(filename2, "r");
        if (fi2 == NULL)
        {
            fprintf(stdout, "Error opening %s\n", filename2);
	    return -1;	
        }
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (strcmp(filename2, "\0"))
    {
        while (fgets(str, ENC_SIZE, fi2) != NULL)
        {
            /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_ccm_aad_update (&ctx, str,ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
            }
	}
    }
    else if (strcmp(aad, "\0"))
    {
        while (i < strlen(aad))
	{
            strncpy(str, aad, ENC_SIZE);
	    printf("STR: %s\n", str);
    	    /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_ccm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
	    }
            i +=16;
	}
    }
    else
        fprintf(stdout, "No additional authenticated data to process\n");

    /* Finish processing Additional Authenticated Data (AAD) using CCM mode */
    status = atcab_aes_ccm_aad_finish (&ctx);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    fclose(fi2);
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
    	/* Process data using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_ccm_decrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
            fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
        }
        res = uint8_to_char(out, 16);
        fprintf(fo, "%s", res);
    }
 
    /* Complete a CCM decrypt operation authenticating provided tag */
    status = atcab_aes_ccm_decrypt_finish (&ctx, tag, &is_verified);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting\n");
    	fclose(fo);
    	fclose(fi);
    	return -1;
    }

    if (is_verified)
    {
        fprintf(stdout, "TAG authentication succesfully done!\n");
    }
    else
    {
        fprintf(stderr, "Error in TAG authentication\n");
        free(res);
        fclose(fo);
        fclose(fi);
	    return -1;
    }

    free(res);
    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a gcm encryption of the data specified in filename */
int gcm_encryption(char* filename, char* text, struct atca_aes_gcm_ctx ctx, uint8_t* tag, uint8_t* tag_size, char* filename2, char* aad)
{
    FILE* fi = NULL;
    FILE* fi2 = NULL;
    FILE* fo;
    char* out_file = "enc.txt";
    uint8_t str[ENC_SIZE];
    char* aux;
    int i = 0, text_size;
    uint8_t out[ENC_SIZE];
    ATCA_STATUS status;

    if (strcmp(filename, "\0"))
    {
        fi = fopen(filename, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "Error opening %s\n", filename);
	    return -1;
        }
    }

    if (strcmp(filename2, "\0"))
    {
        fi2 = fopen(filename2, "r");
        if (fi2 == NULL)
        {  
            fprintf(stderr, "Error opening %s\n", filename2);
 	    return -1;
        }
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (strcmp(filename2, "\0"))
    {
        while (fgets(str, ENC_SIZE, fi2) != NULL)
        {
    	    /* Process Additional Authenticated Data (AAD) using GCM mode and a key within the ATECC608 device */
	    status = atcab_aes_gcm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error updating aad\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
            }
        }
    }
    else if (strcmp(aad, "\0"))
    {
        while (i < strlen(aad))
	{
            strncpy(str, aad, ENC_SIZE);
    	    /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_gcm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
	    }
            i +=16;
	}
    }
    else
        fprintf(stdout, "No additional authenticated data to process\n");
    
    aux = text;
    if (strcmp(filename, "\0"))
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_gcm_encrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
        }
    }
    else if (strcmp(text, "\0"))
    {
        while (i < strlen(text))
	{
	    text_size = strlen(text) - i;
	    if (text_size < ENC_SIZE)
	    {
	        strcpy(str, aux);
	    }	    
	    else
	    {
	        strncpy(str, aux, ENC_SIZE);
	    }

    	    /* Encrypt a block of data using CBC mode and a key within the device */
            status = atcab_aes_gcm_encrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
	    }
	    print_hex_to_file(out, ENC_SIZE, fo);
            i +=16;
	    aux += 16;
	}
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt\n");
    }

    /* Complete a GCM encrypt operation returning the authentication tag */
    status = atcab_aes_gcm_encrypt_finish (&ctx, tag, 16);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing encryption\n");
	fclose(fo);
	fclose(fi);
	return -1;
    }

    fprintf(stdout, "Finishing gcm encryption\n");
    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    if (fi2 != NULL)
    {
        fclose(fi2);
    }

    return 0;
}

/* Performs a gcm decryption of the data specified in filename */
int gcm_decryption(char* filename, struct atca_aes_gcm_ctx ctx, uint8_t* tag, char* filename2, char* aad)
{
    FILE* fi;
    FILE* fi2;
    FILE* fo;
    char* out_file = "dec.txt";
    uint8_t str[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    int i = 0;
    char* res;
    ATCA_STATUS status;
    bool is_verified;

    fprintf(stdout, "Starting gcm decryption\n");
    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "Error opening %s\n", filename);
	return -1;
    }

    if (fi2 != NULL)
    {
        fi2 = fopen(filename2, "r");
        if (fi == NULL)
        {
            fprintf(stderr, "Error opening %s\n", filename2);
	    return -1;
        }
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (strcmp(filename2, "\0"))
    {
        while (fgets(str, ENC_SIZE, fi2) != NULL)
        {
    	    /* Process Additional Authenticated Data (AAD) using GCM mode and a key within the ATECC608 device */
	    status = atcab_aes_gcm_aad_update (&ctx, str,ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
            } 
        }
    }
    if (strcmp(aad, "\0"))
    {
        while (i < strlen(aad))
	{
            strncpy(str, aad, ENC_SIZE);
    	    /* Process Additional Authenticated Data (AAD) using CCM mode and a key within the ATECC608A device */
	    status = atcab_aes_gcm_aad_update (&ctx, str, ENC_SIZE);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting\n");
	        fclose(fo);
	        fclose(fi);
	        fclose(fi2);
	        return -1;
	    }
            i +=16;
	}
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
    	/* Complete a GCM encrypt operation returning the authentication tag */
	    status = atcab_aes_gcm_decrypt_update (&ctx, str, ENC_SIZE, out);
	    if (status != ATCA_SUCCESS)
	    {
            fprintf(stderr, "Error updating decryption\n");
	        fclose(fo);
	        fclose(fi);
	        return -1;
        }
        res = uint8_to_char(out, 16);
	     
        fprintf(fo, "%s", res);
    }

    /* Complete a GCM decrypt operation verifying the authentication tag */
    status = atcab_aes_gcm_decrypt_finish (&ctx, tag, 16, &is_verified);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing encryption\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
    }

    if (is_verified)
    {
        fprintf(stdout, "TAG authentication succesfully done!\n");
    }
    else
    {
        fprintf(stderr, "Error in TAG authentication\n");
        free(res);
        fclose(fo);
        fclose(fi);
	return -1;
    }

    fprintf(stdout, "Finishing gcm encryption\n");
    fclose(fo);
    fclose(fi);

    return 0;
}

