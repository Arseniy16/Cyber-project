#include <stdio.h>
#include <memory.h>
#include "aes.h"

char mode

/*********************** FUNCTION DEFINITIONS ***********************/
void print_hex(BYTE str[], int len)
{
    int idx;

    for(idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);
}

int TEST(int arg, char * mode)
{
    if (arg) printf("TEST %s - PASSED!)\n", mode);
        return 1;

    printf("TEST %s - FAILED\n", mode);
    return 0;
}

int aes_ecb_test()
{
    WORD key_schedule[60], idx;
    BYTE enc_buf[128];
    BYTE plaintext[2][16] = {
        {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
        {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
    };
    BYTE ciphertext[2][16] = {
        {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
        {0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
    };
    BYTE key[1][32] = {
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
    };
    int pass = 1;

    // Raw ECB mode.
    aes_key_setup(key[0], key_schedule, 256);

    #ifdef VERBOSE    
        printf("* ECB mode:\n");
        printf(  "Key          : ");
        print_hex(key[0], 32);
    #endif

    for(idx = 0; idx < 2; idx++) {
        aes_encrypt(plaintext[idx], enc_buf, key_schedule, 256);

        #ifdef VERBOSE
            printf("\nPlaintext    : ");
            print_hex(plaintext[idx], 16);
            printf("\n-encrypted to: ");
            print_hex(enc_buf, 16);
        #endif

        pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);
        TEST(pass, "ECB_MODE /Encryption/");

        aes_decrypt(ciphertext[idx], enc_buf, key_schedule, 256);

        #ifdef VERBOSE
            printf("\nCiphertext   : ");
            print_hex(ciphertext[idx], 16);
            printf("\n-decrypted to: ");
            print_hex(enc_buf, 16);
        #endif

        pass = pass && !memcmp(enc_buf, plaintext[idx], 16);
        TEST(pass, "ECB_MODE /Decryption/");

        printf("\n\n");
    }

    return(pass);
}

int aes_cbc_test()
{
    WORD key_schedule[60];
    BYTE enc_buf[128];
    BYTE plaintext[1][32] = {
        {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
    };
    BYTE ciphertext[1][32] = {
        {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d}
    };
    BYTE iv[1][16] = {
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
    };
    BYTE key[1][32] = {
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
    };
    int pass = 1;

    // CBC mode  
    aes_key_setup(key[0], key_schedule, 256);
    
    #ifdef VERBOSE
        printf("* CBC mode:\n");
        printf(  "Key          : ");
        print_hex(key[0], 32);
        printf("\nIV           : ");
        print_hex(iv[0], 16);
    #endif

    aes_encrypt_cbc(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);

    #ifdef VERBOSE
        printf("\nPlaintext    : ");
        print_hex(plaintext[0], 32);
        printf("\n-encrypted to: ");
        print_hex(enc_buf, 32);
        printf("\nCiphertext   : ");
        print_hex(ciphertext[0], 32);
    #endif

    pass = pass && !memcmp(enc_buf, ciphertext[0], 32);
    TEST(pass, "CBC_MODE /Encryption/");

    aes_decrypt_cbc(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);

    #ifdef VERBOSE
        printf("\nCiphertext   : ");
        print_hex(ciphertext[0], 32);
        printf("\n-decrypted to: ");
        print_hex(enc_buf, 32);
        printf("\nPlaintext   : ");
        print_hex(plaintext[0], 32);
    #endif

    pass = pass && !memcmp(enc_buf, plaintext[0], 32);
    TEST(pass, "CBC_MODE /Decryption/");

    printf("\n\n");
    return(pass);
}

int aes_ctr_test()
{
    WORD key_schedule[60];
    BYTE enc_buf[128];
    BYTE plaintext[1][32] = {
        {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
    };
    BYTE ciphertext[1][32] = {
        {0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5}
    };
    BYTE iv[1][16] = {
        {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff},
    };
    BYTE key[1][32] = {
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
    };
    int pass = 1;

    //CTR mode
    aes_key_setup(key[0], key_schedule, 256);

    #ifdef VERBOSE
        printf("* CTR mode:\n");
        printf(  "Key          : ");
        print_hex(key[0], 32);
        printf("\nIV           : ");
        print_hex(iv[0], 16);
    #endif

    aes_encrypt_ctr(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
    
    #ifdef VERBOSE
        printf("\nPlaintext    : ");
        print_hex(plaintext[0], 32);
        printf("\n-encrypted to: ");
        print_hex(enc_buf, 32);
    #endif

    pass = pass && !memcmp(enc_buf, ciphertext[0], 32);
    TEST(pass, "CTR_MODE /Encryption/");

    aes_decrypt_ctr(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);

    #ifdef VERBOSE
        printf("\nCiphertext   : ");
        print_hex(ciphertext[0], 32);
        printf("\n-decrypted to: ");
        print_hex(enc_buf, 32);
    #endif

    pass = pass && !memcmp(enc_buf, plaintext[0], 32);
    TEST(pass, "CTR_MODE /Decryption/");

    printf("\n\n");
    return(pass);
}

int aes_test()
{
    int pass = 1;

    pass = pass && aes_ecb_test();
    pass = pass && aes_cbc_test();
    pass = pass && aes_ctr_test();

    return(pass);
}

int main(int argc, char *argv[])
{
    printf("AES Tests: %s\n", aes_test() ? "SUCCEEDED" : "FAILED");

    return(0);
}
