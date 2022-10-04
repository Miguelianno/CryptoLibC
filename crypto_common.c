#include "crypto_common.h"

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
    uint8_t message[SHA_DATA_MAX];

    if (fp == NULL)
    {
        return NULL;
    } 

    digest = (uint8_t*)malloc(ATCA_SIG_SIZE*sizeof(uint8_t));
    if (digest == NULL)
    {
        fprintf(stderr, "Error allocating memory for signature\n");
	return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    if (SHA_DATA_MAX >= file_size)
    {		
        fread(message, file_size, 1, fp);
	/* Executes SHA command to complete SHA-256 operation */
	status = atcab_sha_end(digest, file_size, message);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error finalizing sha\n");
	    return NULL;
	}
    
	end_sha_flag = 1;
    }

    fseek(fp, 0, SEEK_SET);
    while(!end_sha_flag)
    {
        file_index += SHA_DATA_MAX;
	if (file_index < file_size)
	{	
	    fread(message, SHA_DATA_MAX, 1, fp);
	    /* Add 64 bytes of message data to the current SHA context */
 	    status = atcab_sha_update(message);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error updating sha\n");
		return NULL;
	    }
           
	    fseek(fp, file_index, SEEK_SET);
        }
	else
	{
	    file_index -= SHA_DATA_MAX;
	    fread(message, file_size - file_index, 1, fp);
	    /* Executes SHA command to complete SHA-256 operation */
	    status = atcab_sha_end(digest, file_size - file_index, message);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error finalizing sha\n");
	        return NULL;
	    }
			
	    end_sha_flag = 1;
        }
	strncpy(message, "\0", SHA_DATA_MAX);
    }

    return digest;
}

/* Decrypts the information stored in the specified file with the key stored in the given slot */
int aes_decryption(char* filename, int slot)
{
    FILE* fi;
    FILE* fo;
    uint8_t text[ENC_SIZE];
    ATCA_STATUS status;
    char res[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    char* out_file = "dec.txt";
    int ret;
    
    if (filename == NULL || slot < 0)
    { 
        return -1;
    }
 
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
               
        ret = uint8_to_char(out, res, ENC_SIZE);
	if (ret == -1)
	{
            fprintf(stderr, "Error converting uint to char\n");
	    return -1;
        }
        fprintf(fo, "%s", res);
    }
    
    fclose(fo);
    fclose(fi);
    
    return 0;
}

/* Encrypts the information stored in the specified file with the key stored in the given slot */
int aes_encryption(char* filename, char* text, int slot)
{
    FILE* fi = NULL;
    FILE* fo;
    int i = 0, text_size;
    uint8_t str[ENC_SIZE];
    char* aux;
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "enc.txt";
    
    /* No input to process */
    fi = fopen(filename, "r");
    if ((fi == NULL && text == NULL) || slot < 0)
    {
        return -1;
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
        return -1;
    }
    
    aux = text;
    if (fi != NULL)
    { 
        while (fgets(str, ENC_SIZE, fi) != NULL)
        {
            status = atcab_aes_encrypt (slot, 0, str, out);
	    if (status != ATCA_SUCCESS)
	    {
                fprintf(stderr, "Error encrypting: %x\n", status);
	        fclose(fo);
	        fclose(fi);
	        return -1;
            }
	     
	    print_hex_to_file(out, ENC_SIZE, fo);
        }
    }
    else if (text != NULL)
    {
	if (strcmp(text, "\0"))
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
                i += 15;
	        aux += 15;
	    }
	}
	else
	{
            fprintf(stderr, "There is no data to encrypt\n");
	    return -1;
	}
    }
    else 
    {
        fprintf(stderr, "There is no data to encrypt\n");
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
int cbc_encryption(char* filename, char* text, int slot, struct atca_aes_cbc_ctx ctx)
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

    /* No input to process */
    fi = fopen(filename, "r");
    if ((filename == NULL && text == NULL) || slot < 0)
    {
        return -1;
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }
	
    aux = text;
    if (fi != NULL)
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
    else if (text != NULL)
    {
	if (strcmp(text,"\0"))
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
                i +=15;
	        aux += 15;
	    }
	}
        else 
        {
            fprintf(stderr, "There is not data to encrypt");
	    return -1;
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
int cmac_encryption(char* filename, char* text, int slot, struct atca_aes_cbc_ctx ctx, uint8_t* mac) {
    FILE* fi = NULL;
    FILE* fo = NULL;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status = ATCA_SUCCESS;
    char out[ENC_SIZE];
    char* aux;
    char* out_file = "enc.txt";
    int i = 0, text_size;
    struct atca_aes_cmac_ctx cmac_ctx;

    /* No input to process */
    fi = fopen(filename, "r");
    if ((fi == NULL && text == NULL) || slot < 0)
    {
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
	    
    aux = text;
    if (fi != NULL)
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
    else if (text != NULL)
    {
	if (strcmp(text, "\0"))
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
            
	        i +=15;
	        aux += 15;
	    }
	}
	else
        {
            fprintf(stderr, "There is not data to encrypt");
	    return -1;
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

    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }

    return 0;
}

/* Performs a cbc encryption of the data specified in filename */
int cbcmac_encryption(char* filename, char* text, int slot, struct atca_aes_cbc_ctx ctx) 
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

    /* No input to process */
    fi = fopen(filename, "r");
    if ((fi == NULL && text == NULL) || slot < 0)
    {
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
        fprintf(stderr, "Error initializing cbcmac operation: %x\n", status);
	return -1;
    }

    aux = text;
    if (fi != NULL)
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
	        fprintf(stderr, "Error updating cbcmac operation\n");
                return -1;
	    }
	}
    }
    else if (text != NULL)
    {
	if (strcmp(text, "\0"))
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
	        status = atcab_aes_cbcmac_update(&cbcmac_ctx, out, ENC_SIZE);
	        if (status != ATCA_SUCCESS)
	        {
	            fprintf(stderr, "Error updating cbcmac operation\n");
                    return -1;
	        }
		    
                i +=15;
	        aux += 15;
	    }
	}
	else
        {
            fprintf(stderr, "There is not data to encrypt");
	    return -1;
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

    fclose(fo);
    if (fi != NULL)
    {
        fclose(fi);
    }
    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cbc_decryption(char* filename, int slot, struct atca_aes_cbc_ctx ctx)
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
    char res[ENC_SIZE];
    int ret;
    struct atca_aes_cmac_ctx cmac_ctx;
 
    if (filename == NULL || slot < 0)
    {
        return -1;
    }
    
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
	/* Decrypt a block of data using CBC mode and a key within the device */
	status = atcab_aes_cbc_decrypt_block (&ctx, str, out);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error encrypting\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
	}

        ret = uint8_to_char(out, res, ENC_SIZE);
	if (ret == -1)
	{
            fprintf(stderr, "Error converting from uint to char\n");
	    return -1;
	}
	fprintf(fo, "%s", res);
    }

    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cmac_decryption(char* filename, int slot, struct atca_aes_cbc_ctx ctx, uint8_t* mac)
{
    FILE* fi;
    FILE* fo;
    uint8_t str[ENC_SIZE];
    ATCA_STATUS status;
    char out[ENC_SIZE];
    char* out_file = "dec.txt";
    char res[ENC_SIZE];
    int ret;
    struct atca_aes_cmac_ctx cmac_ctx;
    
    if (filename == NULL || slot < 0)
    {
        return -1;
    }

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

	ret = uint8_to_char(out, res, ENC_SIZE);
	if (ret == -1)
	{
            fprintf(stderr, "Error converting from uint to char\n");
	    return -1;
	}
	fprintf(fo, "%s", res);

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

    fclose(fo);
    fclose(fi);

    return 0;
}

/* Performs a cbc decryption of the data specified in filename */
int cbcmac_decryption(char* filename, int slot, struct atca_aes_cbc_ctx ctx)
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
    char res[ENC_SIZE];
    int ret;

    if (filename == NULL || slot < 0)
    {
        return -1;
    }

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

    printf("ALO\n");
    /* Initialize context for AES CBC-MAC operation */
    status = atcab_aes_cbcmac_init(&cbcmac_ctx, slot, 0);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing cbcmac operation\n");
	return -1;
    }

    while (read_hex_from_file(fi, str) != EOF)
    {
        /* Calculate AES CBC-MAC with key stored within ECC608A device */
      	status = atcab_aes_cbcmac_update(&cbcmac_ctx, str, ENC_SIZE);
  	if (status != ATCA_SUCCESS)
	{
		printf("AQUI:\n");
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
    
        ret = uint8_to_char(out, res, ENC_SIZE);
        if (ret == -1)
        {
            fprintf(stderr, "Error converting from uint8 to char\n");
	    return -1;
        }
        fprintf(fo, "%s", res);
    }    

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

    /* No input to process */
    fi = fopen(filename, "r");
    if (fi == NULL && text == NULL)
    {
        return -1;
    }

    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (fi != NULL)
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
    else if (text != NULL)
    {
	if (strcmp(text, "\0"))
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
	        }

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
                i +=15;
	        aux += 15;

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

/* Performs a ctr decryption of the data specified in filename */
int ctr_decryption(char* filename, struct atca_aes_ctr_ctx ctx)
{
    FILE* fi;
    FILE* fo;
    char* out_file = "dec.txt";
    uint8_t str[ENC_SIZE];
    uint8_t out[ENC_SIZE];
    char res[ENC_SIZE];
    int ret;
    ATCA_STATUS status;

    if (filename == NULL)
    {
        return -1;
    }

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

        ret = uint8_to_char(out, res, ENC_SIZE);
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
    
    /* No input to process */
    fi = fopen(filename, "r");
    if (fi == NULL && text == NULL)
    {
        return -1;
    }

    fi2 = fopen(filename2, "r");
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (fi2 != NULL)
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
    else if (aad != NULL)
    {
        if (strcmp(aad, "\0"))
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

    if (fi != NULL)
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
    else if (text != NULL)
    {
	if (strcmp(text,"\0"))
	{
	    i=0;
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
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
               i +=15;
	       aux += 15;
	    }
	}
	else
        {
            fprintf(stderr, "There is not data to encrypt\n");
	    return -1;
        }
    }
    else 
    {
        fprintf(stderr, "There is not data to encrypt\n");
	return -1;
    }

    status = atcab_aes_ccm_encrypt_finish (&ctx, tag, tag_size);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error encrypting\n");
	fclose(fo);
	fclose(fi);
	return -1;
    }

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
    char res[ENC_SIZE];
    int i = 0, ret, aad_flag = 1;
    ATCA_STATUS status;
    bool is_verified;

    if (filename == NULL)
    {
        return -1;
    }

    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "Error opening %s\n", filename);
	return -1;
    }

    fi2 = fopen(filename2, "r");
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (fi2 != NULL)
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
    else if (aad != NULL)
    {
	if (strcmp(aad, "\0"))
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
    }
    else
    {
        fprintf(stdout, "No additional authenticated data to process\n");
	aad_flag = 0;
    }

    if (aad_flag)
    {
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
        ret = uint8_to_char(out, res, ENC_SIZE);
	if (ret == -1)
	{
	    fprintf(stderr, "Error converting from uint8 to char\n");
	    return -1;
	}
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

    if (!is_verified)
    {
        fprintf(stderr, "Error in TAG authentication\n");
        fclose(fo);
        fclose(fi);
	return -1;
    }

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

    /* No input to process */
    fi = fopen(filename, "r");
    if (fi == NULL && text == NULL)
    {
        return -1;
    }

    fi2 = fopen(filename2, "r");
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (fi2 != NULL)
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
    else if (aad != NULL)
    {
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
    }
    else
        fprintf(stdout, "No additional authenticated data to process\n");
    
    aux = text;
    if (fi != NULL)
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
    else if (text != NULL)
    {
	if (strcmp(text, "\0"))
	{
	    i = 0;
            while (i < strlen(text))
	    {
	        text_size = strlen(text) - i;
	        if (text_size < ENC_SIZE)
	        {
	            strcpy(str, aux);
	        }	    
	        else
	        {
	            strncpy(str, aux, ENC_SIZE-1);
		    str[ENC_SIZE-1] = 0;
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
                i +=15;
	        aux += 15;
	    }
	}
	else
        {
            fprintf(stderr, "There is no data to encrypt\n");
	    return -1;
        }
    }
    else 
    {
        fprintf(stderr, "There is no data to encrypt\n");
	return -1;
    }

    /* Complete a GCM encrypt operation returning the authentication tag */
    status = atcab_aes_gcm_encrypt_finish (&ctx, tag, ENC_SIZE);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing encryption\n");
	fclose(fo);
	fclose(fi);
	return -1;
    }

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
    char res[ENC_SIZE];
    int ret;
    ATCA_STATUS status;
    bool is_verified;

    if (filename == NULL)
    {
        return -1;
    }

    fi = fopen(filename, "r");
    if (fi == NULL)
    {
        fprintf(stderr, "Error opening %s\n", filename);
	return -1;
    }

    fi2 = fopen(filename2, "r");
    fo = fopen(out_file, "w");
    if (fo == NULL)
    {
        fprintf(stderr, "File %s does not exist\n", out_file);
	return -1;
    }

    if (fi2 != NULL)
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
    else if (aad != NULL)
    {
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
        ret = uint8_to_char(out, res, ENC_SIZE);
	if (ret == -1)
	{
            fprintf(stderr, "Error converting from uint8 to char\n");
	    return -1;
	}
	     
        fprintf(fo, "%s", res);
    }

    /* Complete a GCM decrypt operation verifying the authentication tag */
    status = atcab_aes_gcm_decrypt_finish (&ctx, tag, ENC_SIZE, &is_verified);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error finishing encryption\n");
	    fclose(fo);
	    fclose(fi);
	    return -1;
    }

    if (!is_verified)
    {
        fprintf(stderr, "Error in TAG authentication\n");
        fclose(fo);
        fclose(fi);
	return -1;
    }

    fclose(fo);
    fclose(fi);

    return 0;
}

