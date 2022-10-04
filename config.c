#include "common.h"

/* Generates a groupt of private/public key in the allowed slots */
void generate_key(struct _atecc608_config config)
{
    int i;
    ATCA_STATUS status;
    bool is_private;
    bool data_is_locked, is_locked;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
	
    for(i=0; i < N_SLOTS; i++)
    {
	/* Checks wheter the key is private or not */
	status = atcab_is_private(i, &is_private);
	if (status != ATCA_SUCCESS)
	{
	    fprintf(stderr, "Error checking if the key is private for slot %d\n", i);
	    return;
	}

        if(!is_private)
	{
	    fprintf(stdout, "Slot %d not a private key\n", i);
	    continue;
	}

	/* Checks whether the data zone is locked */
        status = atcab_is_locked(LOCK_ZONE_DATA, &data_is_locked);
	if(data_is_locked)
	{
	    /* Data zone is already locked, additional conditions apply */
	    if(! ((config.SlotConfig[i] >> 5) & 1))
	    {
	        fprintf(stdout, "GenKey is disabled for slot %d\n", i);
                continue;
	    }
			
	    /* Checks whether the slot is locked or not */
	    status = atcab_is_slot_locked(i, &is_locked);
	    if (status != ATCA_SUCCESS)
	    {
	        fprintf(stderr, "Error checking if the slot %d is locked\n", i);
	        return;
	    }

	    if (is_locked)
	    {
                fprintf(stdout, "Slot %d is locked\n", i);
	        continue;
	    }

            /* Checks if the slot requires previous authorization */ 	
	    if((config.KeyConfig[i] >> 15) &1)
	    {
	        fprintf(stdout, "Slot %d requires authorization\n", i);
                continue;
	    }
			
	    /* Checks the state of the intrusion latch */
	    if((config.KeyConfig[i] >> 4) & 1)
	    {
	        fprintf(stdout, "Slot %d requires persistent latch", i);
		continue;
	    }
        }
		
        fprintf(stdout, "Generating key pair in slot %d\n", i);
	/* Generates a new random private key in the specified slot */
        status = atcab_genkey(i, public_key);
        if(status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error generating key pair in slot %d\n", i);
	    exit(status);
        }

    } 	
}

/* Main program */
int main()
{
    ATCA_STATUS status;
    bool conf_is_locked;
    bool data_is_locked;
    char config_data[ATCA_ECC_CONFIG_SIZE];
    struct _atecc608_config config;
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    uint8_t* final_config;

    gCfg->atcai2c.bus=1;

    /* Creates and initializes ATCADevice context */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initializing global ATCADevice\n", status);
        exit(status);
    }
	
    config = set_configuration();
	
    fprintf(stdout, "Reading the lock Status:\n");

    /* Checks whether the specified zone is locked or not */
    status = atcab_is_locked(LOCK_ZONE_CONFIG, &conf_is_locked);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error checking the status of the specified zone\n");
        exit(status);
    }

    (conf_is_locked)? fprintf(stdout, "Configuration zone blocked\n"): fprintf(stdout, "Configuration zone unlocked\n");
	
    /* Checks whether the specified zone is locked or not */
    status = atcab_is_locked(LOCK_ZONE_DATA, &data_is_locked);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error checking the status of the specified zone\n");
        exit(status);
    }

    (data_is_locked)? printf("Data zone blocked\n"): printf("Data zone unlocked\n");

    if (!conf_is_locked){
	fprintf(stdout, "Locking configuration zone\n");
	/* Unconditionally locks the config zone (no CRC) */
        status = atcab_lock_config_zone();
        if (status != ATCA_SUCCESS)
	{
            fprintf(stdout, "Error locking config zone\n");
	    exit(status);
	}
        fprintf(stdout, "Configuration zone succesfully locked\n");
    }
	
    /* Checks if data zone is locked */
    if (!data_is_locked)
    {
	fprintf(stdout, "Locking data zone\n");
        generate_key(config);
	/* Unconditionally locks the data and OTP zones (no CRC)  */
	status = atcab_lock_data_zone();
	if (status != ATCA_SUCCESS)
	{
            fprintf(stderr, "Error bloqueando zona de datos\n");
            exit(status);
	}
        fprintf(stdout, "Data zone succesfully locked\n");
    }
	
    /* Generate new Keys */
    if (data_is_locked)
    {
        fprintf(stdout, "Generating new keys...\n");
        generate_key(config);	    
    }	
	
    /* Releases the global ATCA Device instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing global ATCA Device\n");
        exit(status);
    }

    exit(status);
}
