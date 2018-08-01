#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/aes.h>
#include <dlfcn.h>

#define LOCK "FFFFFFFF"
#define UNLOCK "ABABCDCD"
#define RELOCK "EFEFABCD"
unsigned char lockvalue[16];
unsigned char usrkey[32];

void getlockvalue_system()
{
    int i;
    void *handle = dlopen("/data/local/tmp/liboeminfo.so", RTLD_LAZY);
    void (*rmt_oeminfo_read)(int idx, int len, char* buff);
    rmt_oeminfo_read = dlsym(handle, "rmt_oeminfo_read");
    rmt_oeminfo_read(93, 16, lockvalue);
    printf("get lockvalue by system: \n");
    for(i=0;i<16;i++)
    {
        printf("%02x ", lockvalue[i]);
    }
    printf("\n");
}

void setlockvalue_system()
{
    char keys[16];
    int i;
    void *handle = dlopen("/data/local/tmp/liboeminfo.so", RTLD_LAZY);
    void (*rmt_oeminfo_write)(int idx, int len, char* buff);
    rmt_oeminfo_write= dlsym(handle, "rmt_oeminfo_write");
    printf("set lockvalue by system: \n");
    for(i=0;i<16;i++)
    {
        printf("%02x ", lockvalue[i]);
    }
    printf("\n");
    rmt_oeminfo_write(93, 16, lockvalue);
}

void readusrkey()
{
    int i;
    int nvme_fd = open("/dev/block/mmcblk0p7", O_RDONLY);
    if (nvme_fd < 0)
    {
        printf("file open error\n");
        exit(1);
    }
    char *nvme = mmap(NULL, 0x600000, PROT_READ, MAP_PRIVATE, nvme_fd, 0);
    for(i=0;i<0x600000;i+=0x10)
    {
        if(memcmp("USRKEY", nvme+i+4, 6)==0)
        {
            printf("find usrkey:");
            memcpy(usrkey, nvme+i+16+8, 32);
            break;
        }
    }
    for(i=0;i<32;i++)
    {
        if(i % 15 ==0)
        {
            printf("\n");
        }
        printf("%02x ", usrkey[i]);
    }
    printf("\n");
    close(nvme_fd);
    munmap(nvme, 0x600000);
}

void printlockstate()
{
    int i = 0;
    unsigned char temp[16];
    unsigned char iv[16];
    unsigned char *decrypt_string;
    AES_KEY aes;
    readusrkey();
    getlockvalue_system();
    memset(iv, 0, 16);
    AES_set_decrypt_key(usrkey, 128, &aes);
    AES_cbc_encrypt(lockvalue, temp, 16, &aes, iv, AES_DECRYPT); 
    if(memcmp(temp, "EFEFABCD", 8)==0)
    {
        printf("state: relocked\n");
    }
    else if(memcmp(temp, "ABABCDCD", 8)==0)
    {
        printf("state: unlocked\n");
    }
    else
    {
        printf("state: locked\n");
    }
}

void changelockstate(char *lockstate)
{
    int i = 0;
    unsigned char temp[16];
    unsigned char iv[16];
    unsigned char *decrypt_string;
    AES_KEY aes;
    readusrkey();
    getlockvalue_system();
    memset(iv, 0, 16);
    memset(temp, 0, 16);
    memcpy(temp, lockstate, 8);
    AES_set_encrypt_key(usrkey, 128, &aes);
    AES_cbc_encrypt(temp, lockvalue, 16, &aes, iv, AES_ENCRYPT); 
    setlockvalue_system();
}

int main(int argc, char *argv[])
{
    if(strcmp(argv[1], "unlock")==0)
        changelockstate(UNLOCK);
    else if(strcmp(argv[1], "lock")==0)
        changelockstate(LOCK);
    else if(strcmp(argv[1], "relock")==0)
        changelockstate(RELOCK);
    printlockstate();

    return 0;
}


