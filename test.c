#include "common.h"

#define ATCA_HAL_I2C
#define ATCA_NO_HEAP

void main()
{
    ATCA_STATUS status;
    uint8_t revision[4];
    uint8_t randomnum[32];
    ATCAIfaceCfg *gCfg = &cfg_ateccx08a_i2c_default;


    printf("Devtype: %d\n", gCfg->devtype);
    printf("Devtype: %d\n", gCfg->atcai2c.address);
    printf("Devtype: %d\n", gCfg->atcai2c.bus);
    gCfg->atcai2c.bus=1;
    printf("Devtype: %d\n", gCfg->atcai2c.bus);
    status = atcab_init(gCfg);
    printf("Status: %d\n", status); 
    if (status != ATCA_SUCCESS)
    {
        printf("Error1\n");
        exit(status);
    }

    status = atcab_info(revision);
    if (status != ATCA_SUCCESS)
    {
        printf("Error2\n");
        exit(status);
    }

    status = atcab_random(randomnum);
    if (status != ATCA_SUCCESS)
    {
        printf("Error3\n");
        exit(status);
    }
  
    printf("Random: %d\n", randomnum);


    status = atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("Error4\n");
        exit(status);
    }

    exit(status);
}
