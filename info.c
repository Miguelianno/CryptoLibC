#include "common.h"


/* Prints information about the interface used for the connection between the Raspberry and the cryptoprocessor */
void print_iface_configuration(ATCAIfaceCfg *conf)
{
    fprintf(stdout, "\n-------------------- Interface configuration --------------------\n");
    fprintf(stdout, "Iface_type: %d, ", conf->iface_type);
    fprintf(stdout, "Devtype: %d, ", conf->devtype);
    fprintf(stdout, "I2c Address: %d, ", conf->atcai2c.address);
    fprintf(stdout, "I2c Bus: %d, ", conf->atcai2c.bus);
    fprintf(stdout, "Baud: %d, ", conf->atcai2c.baud);
    fprintf(stdout, "Wake delay: %d, ", conf->wake_delay);
    fprintf(stdout, "Rx retries: %d\n", conf->rx_retries);
    fprintf(stdout, "--------------------------------------------------\n");

}

/* Prints the device type from enum format to string format */
void print_device_type(ATCADeviceType dev_type)
{
    switch (dev_type)
    {
        case 0:
            fprintf(stdout, "Device type is ATSHA204A\n");
	    break;
	case 1:
	    fprintf(stdout, "Device type is ATECC108A\n");
	    break;
	case 2:
	    fprintf(stdout, "Device type is ATECC508A\n");
	    break;
	case 3:
	    fprintf(stdout, "Device type is ATECC608A\n");
	    break;
	case 4:
	    fprintf(stdout, "Device type is ATECC608B\n");
	    break;
	case 5:
	    fprintf(stdout, "Device type is ATECC608\n");
	    break;
	case 6:
	    fprintf(stdout, "Device type is ATECC206A\n");
	    break;
	case 7:
	    fprintf(stdout, "Device type is ECC204\n");
	    break;
	case 8:
	    fprintf(stdout, "Device type is TA100\n");
	    break;
	case 9:
	    fprintf(stdout, "Device type unknown\n");
	    break;
	default:
	    fprintf(stdout, "Device type not recognised\n");
	    break;
    }


}


/* This program is intended to show the main information of the cryptodevice */
void main()
{
    ATCA_STATUS status;
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    uint8_t revision[ATCA_WORD_SIZE];
    ATCADeviceType dev_type;
    uint8_t config_data[ATCA_ECC_CONFIG_SIZE];
    ATCADevice* dev; 
    bool is_locked, is_dev, state;
    char version[ATCA_SERIAL_NUM_SIZE];
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;
    int slot;
    size_t zone_size;

    dev = (ATCADevice*)malloc(sizeof(ATCADevice));
    if (dev == NULL)
    {
       fprintf(stderr, "Error initializing ATCADevice object");
       exit(-1);
    }

    gCfg->atcai2c.bus=1;
    print_iface_configuration(gCfg);

    /* Creates and initializes ATCADevice context */
    status = atcab_init_ext(dev, gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initilizing ATCADevice\n");
        exit(status);
    }

    /* Creates and initializes ATCADevice context */
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error initilizing global ATCADevice\n");
        exit(status);
    }

    /* Get the current device type */
    dev_type = atcab_get_device_type();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error getting device type\n");
        exit(status);
    }

    print_device_type(dev_type);

    /* Get the current device address */
    fprintf(stdout, "device address: %x\n", atcab_get_device_address(*dev));

    /* Checks wether the device is cryptoauth device  */
    is_dev = atcab_is_ca_device(dev_type);
    (is_dev) ? fprintf(stdout, "The device is cryptoauth device\n"): fprintf(stdout, "The device is not a cryptoauth device \n");

    /* Checks wether the device is TrustAnchor device  */
    is_dev = atcab_is_ta_device(dev_type);
    (is_dev) ? fprintf(stdout, "The device is TrustAnchor device\n"): fprintf(stdout, "The device is not a TrustAnchor device \n");

    /* Returns a version string of the device in the format of yyyymmdd */
    status = atcab_version(version);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error retrieving version of the device\n");
        exit(status);
    }
    printf("Version: %s\n", version);

    /* Returns the device revision */
    status = atcab_info(revision);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error retrieving revision number of the device: %x\n", status);
        exit(status);
    }
  
    fprintf(stdout, "Revision: ");
    print_hex_to_file(revision, ATCA_SERIAL_NUM_SIZE, stdout);

    /* Returns the serial number of the device */
    status = atcab_read_serial_number(serial_number);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stdout, "Error reading serial number\n");
        exit(status);
    }
 
    fprintf(stdout, "Serial Number: ");
    print_hex_to_file(serial_number, ATCA_SERIAL_NUM_SIZE, stdout);

    fprintf(stdout, "--------------------------------------------------\n");
    /* Gets the size of the specified zone in bytes */
    status = atcab_get_zone_size(ATCA_ZONE_CONFIG, 0, &zone_size);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error retrieving device zone size\n");
	exit(status);
    }
    fprintf(stdout, "Zone size for config zone is: %d bytes\n", zone_size);

    /* Gets the size of the specified zone in bytes */
    status = atcab_get_zone_size(ATCA_ZONE_OTP, 0, &zone_size);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error retrieving device zone size\n");
	exit(status);
    }
    fprintf(stdout, "Zone size for OTP zone is: %d bytes\n", zone_size);

    for (slot = 0; slot < N_SLOTS; slot++)
    {
        /* Gets the size of the specified zone in bytes */
        status = atcab_get_zone_size(ATCA_ZONE_DATA, slot, &zone_size);
        if (status != ATCA_SUCCESS)
        {
            fprintf(stderr, "Error retrieving device zone size\n");
	    exit(status);
        }
        fprintf(stdout, "Zone size for data zone slot %d is: %d bytes\n", slot, zone_size);
    }

    /* Get the persistent latch current state */
    status = atcab_info_get_latch(&state);
    if (status != ATCA_SUCCESS)
    {
	fprintf(stderr, "Error retrieving presistent latch state\n");
	exit(status);
    }
    (state) ? fprintf(stdout, "Persistent latch state is set\n"): fprintf(stdout, "Persistent latch state is clear\n");

    fprintf(stdout, "--------------------------------------------------\n");
    /* Reads the complete device configuration zone */
    status = atcab_read_config_zone(config_data);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading config zone\n");
        exit(status);
    }


    fprintf(stdout, "Config zone: ");
    print_hex_to_file(config_data, ATCA_ECC_CONFIG_SIZE, stdout);

    /* Reads the configuration zone to see if its locked */
    status = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading config zone status\n");
        exit(status);
    }

    fprintf(stdout, "Configuration zone is: ");
    (is_locked) ? fprintf(stdout, "Locked\n"): fprintf(stdout, "Not locked\n");
    
    /* Reads the data zone to see if its locked */
    atcab_is_locked(LOCK_ZONE_DATA, &is_locked);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error reading data zone status\n");
        exit(status);
    }

    fprintf(stdout, "Data zone is: ");
    (is_locked) ? fprintf(stdout, "Locked\n"): fprintf(stdout, "Not locked\n");

    /* Release the ATCADevice instance */
    status = atcab_release_ext(dev);
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing device\n");
        exit(status);
    }

    /* Release the global ATCADevice instance */
    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        fprintf(stderr, "Error releasing device\n");
        exit(status);
    }

    exit(status);
}
