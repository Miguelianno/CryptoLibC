#include "common.h"
#include "crypto_common.h"
#include <unistd.h>

/* Help function for the usage of the program */ 
void help(char *program)
{
    fprintf (stdout, " This program allows you to cryptographically sign a document or a public key using a key stored in the device (one element per execution)\n");
    fprintf (stdout, " Usage %s -f filename\n", program);
    fprintf (stdout, "  -h help\t\tDisplays the help menu\n");
    fprintf (stdout, "  -f filename\t\tIndicates the filename of the document you want to sign\n");
    fprintf (stdout, "  -n slot number\tIndicates the slot number of which public key will be signed (2, 3, 4)\n");
    fprintf (stdout, "Example: ./sign_verify -f test.txt\n");

    exit (2);
}

/* Performs a digital signature with the ATCADevice */
uint8_t* sign_device(uint8_t *digest, int slot)
{
    uint8_t *signature;
    ATCA_STATUS status;
	
    signature = (uint8_t*)malloc(ATCA_SIG_SIZE*sizeof(uint8_t));
    if (signature == NULL)
    { 
        fprintf(stderr, "Error allocating memory for signature\n");
        return NULL;
    }

    /* Signs a 32-byte external message using the private key in the specified slot */
    status = atcab_sign(slot, digest, signature);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error signing message\n");
	return NULL;
    }

    return signature;
}

/* Verifies a digital signature using the ATCADevice */
bool verify_device(uint8_t *message, uint8_t *signature, uint8_t *public_key)
{
    bool is_verified;
    ATCA_STATUS status;
	
    /* ECSDA verify operation to verify a signature with all components supplied  */
    status = atcab_verify_extern(message, signature, public_key, &is_verified);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error verifyng device\n");
	return 0;
    }

    return is_verified;
}

int main(int argc, char** argv)
{
    ATCA_STATUS status;
    char config_data[ATCA_ECC_CONFIG_SIZE];
    struct _atecc608_config config;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    int slot = 2; // Slot 2, 3 and 4 stores usable public keys
    int sign_slot = -1;
    uint8_t message[ATCA_SHA_DIGEST_SIZE];
    uint8_t *digest_file;
    bool verified;
    uint8_t *file_signature;
    uint8_t key_signature[ATCA_SIG_SIZE];
    uint8_t intern_sign[SHA_DATA_MAX], pubkey[ATCA_PUB_KEY_SIZE];
    bool is_verified;
    FILE* fp = NULL;
    char *msg[SHA_DATA_MAX];
    uint8_t digest_key[SHA_DATA_MAX];
    int c, file_flag = 0, slot_flag = 0;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;

    gCfg->atcai2c.bus=1;

    while ((c = getopt (argc, argv, "f:n:h::")) != -1)
    {
        switch(c)
	{	
            case 'h':
                help(argv[0]);
                break;
            case 'f':
		fp = fopen(optarg, "r");
                if (fp == NULL)
                {
    	            fprintf(stderr, "Error opening file %s\n", optarg);
    	            return -1;
                }
		file_flag = 1;
		break;
            case 'n':
		sign_slot = atoi(optarg);
		slot_flag = 1;
		break;
	    case '?':
		/* Check unkwnown options */
		if (optopt == 'f' || optopt == 'n')
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

    if ((slot_flag == 0 && file_flag == 0) || (slot_flag && file_flag))
    {
        fprintf(stderr, "Error in arguments, check -h for help\n");
	return -2;
    }
    /* Creates a global ATCADevice object used by Basic API */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCA Device\n");
        return -1;
    }

    if (file_flag)
    {
        fprintf(stdout, "Signing file...\n");
        /* Initializes SHA-256 calculation engine */
        status = atcab_sha_start();
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error starting sha engine\n");
	    return -1;
        }

        /* Generate the digest of a given file */
        digest_file = hash_file(fp);

        fprintf(stdout, "Message digest: ");
        print_hex_to_file(digest_file, ATCA_SHA_DIGEST_SIZE, stdout);
		
        /* Calculates the public key from an existing private key in a slot */
        status = atcab_get_pubkey(slot, public_key);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error getting public key\n");
	    return -1;
        }
		
        /* Performs a digital signature from the given digest */
        file_signature = sign_device(digest_file, slot);
        if (file_signature == NULL)
        {
            fprintf(stderr, "Error signing\n");
	    return -1;
        }
		
        fprintf(stdout, "Signature: ");
        print_hex_to_file(file_signature, ATCA_SIG_SIZE, stdout);
		
        fprintf(stdout, "Verifying signature\n");
        /* Verifies the given signature with the specified public key */
        verified = verify_device(digest_file, file_signature, public_key);
        if (verified)
        {
            fprintf(stdout, "Verification succesfully done\n");
        }
        else
        {
            fprintf(stdout, "Signature verification error\n");
        }
   	
	free(file_signature);
        free(digest_file);
    }
    else
    {
        fprintf(stdout, "Generating and signing key in slot %d\n", sign_slot);
        
	/* Generates a private key in given slot and returns the public key */
        status = atcab_genkey(sign_slot, pubkey);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error generating key\n");
	    return -1;
        }

	fprintf(stdout, "Public key generated: ");
	print_hex_to_file(pubkey, ATCA_PUB_KEY_SIZE, stdout);

        /* Compute the SHA-256 digest of the public key */
        status = atcab_sha(SHA_DATA_MAX, pubkey, digest_key);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error generating digest of the public key\n");
	    return -1;
        }

	fprintf(stdout, "Digest of the public key: ");
	print_hex_to_file(digest_key, ATCA_SHA_DIGEST_SIZE, stdout);

        /* Signs the digest of the public key generated previously with the key stored in slot 3 */
        status = atcab_sign(3, digest_key, key_signature);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error signing internal message\n");
	    return -1;
        }

	fprintf(stdout, "Signature: ");
	print_hex_to_file(key_signature, ATCA_SIG_SIZE, stdout);

        /* Get the public key used for the sign operation */
        status = atcab_get_pubkey(3, public_key);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error getting public key\n");
	    return -1;
        }

        /* Validates a public key stored in a slot */
        status = atcab_verify_extern(digest_key, key_signature, public_key, &is_verified);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error validating internal public key\n");
	    return -1;
        }
    
        (is_verified) ? fprintf(stdout, "Public key verificated succesfully!\n"): fprintf(stdout, "The public key couldn't be verified\n");
    }

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stdout, "Error releasing global ATCA Device\n");
        return -1;
    }

    return 0;
}
