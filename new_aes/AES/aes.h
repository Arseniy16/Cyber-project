#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdio.h>

/****************************** MACROS ******************************/
#define AES_BLOCK_SIZE 16

//colors
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;
typedef unsigned int WORD;

typedef struct KPI {
    double encryption_mean_time, encryption_std, decryption_mean_time, decryption_std;
} KPI;

typedef struct ERROR {
    double err_mean, err_std;
} ERROR;

void xor_of_two_blocks_AES(BYTE* block_1, BYTE* block_2);
void AES_time_performance(unsigned long int number_of_blocks, int option_key, int user_choice, int NumOfExperiments, KPI* AES_results);

int AES_test_error(unsigned long int number_of_blocks, int num_err, int option_key, int user_choice, int NumOfExperiments, ERROR* AES_results);

/*********************** FUNCTION DECLARATIONS **********************/
///////////////////
// AES
///////////////////
// Key setup must be done before any AES en/de-cryption functions can be used.
void aes_key_setup(const BYTE key[],          // The key, must be 128, 192, or 256 bits
                   WORD w[],                  // Output key schedule to be used later
                   int keysize);              // Bit length of the key, 128, 192, or 256

void aes_encrypt(const BYTE in[],             // 16 bytes of plaintext
                 BYTE out[],                  // 16 bytes of ciphertext
                 const WORD key[],            // From the key setup
                 int keysize);                // Bit length of the key, 128, 192, or 256

void aes_decrypt(const BYTE in[],             // 16 bytes of ciphertext
                 BYTE out[],                  // 16 bytes of plaintext
                 const WORD key[],            // From the key setup
                 int keysize);                // Bit length of the key, 128, 192, or 256

///////////////////
// Test functions
///////////////////
int aes_test();
int aes_ecb_test();
int aes_cbc_test();
int aes_ctr_test();

#endif   // AES_H