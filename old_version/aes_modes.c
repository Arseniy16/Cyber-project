#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <sys/time.h>
#include "aes.h"

#define DEBUG

/*********************** FUNCTION DEFINITIONS ***********************/

// for debug and print hex value
void print_hex(BYTE str[], int len)
{
    int idx;

    for(idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);

    return;
}

int main(void)
{
    srand(0); //init random keys and messages

    WORD key_schedule[60];

    int pass = 1;
    unsigned long int number_of_blocks;

    printf("AES_PROGRAM -> RUN\n");
    printf("Enter the length of the message (in 128 bit-blocks): ");
    scanf("%lu", &number_of_blocks);

    unsigned long int length_of_message = number_of_blocks * AES_BLOCK_SIZE; //in bytes

    BYTE* message = (BYTE*) calloc(length_of_message, sizeof(BYTE));
    BYTE* ciphertext = (BYTE*) calloc(length_of_message, sizeof(BYTE));
    BYTE* initialize_vector = (BYTE*) calloc (AES_BLOCK_SIZE, sizeof(BYTE));
    BYTE* enc_buf = (BYTE*) calloc(length_of_message, sizeof(BYTE));

    int option_key;
    do {
        printf("Choose the option for the length of the key (1 - 128 bits, 2 - 192 bits, 3 - 256 bits): ");
        scanf("%d", &option_key);
    } while((option_key > 3) || (option_key < 1));

    int length_of_key_bytes = 16 + (option_key - 1) * 8; //length of key in bytes
    int keysize = length_of_key_bytes * 8; // length of key in bits

    //debug
    printf("Key_size = %d bits\n", keysize);

    BYTE* user_key = (BYTE*) calloc (length_of_key_bytes, sizeof(BYTE));

    int user_choice;
    printf("Which mode?(1 - ECB, 2 - CBC, 3 - PCBC, 4 - CFB, 5 - OFB, 6 - CTR)\n");
    scanf("%d", &user_choice);

    int NumOfExperiments = 10;

    double* key_setup_times = (double*) calloc (NumOfExperiments, sizeof(double));
    double* encryption_times = (double*) calloc (NumOfExperiments, sizeof(double));
    double* decryption_times = (double*) calloc (NumOfExperiments, sizeof(double));

    struct timeval time_1, time_2, time_3, time_4, time_5;

    for (int i = 0; i < NumOfExperiments; i++) {
        for (int j = 0; j < length_of_message; j++) {
            message[j] = rand() % 256;
        }
        for (int j = 0; j < length_of_key_bytes; j++) {
            user_key[j] = rand() % 256;
        }

        gettimeofday(&time_1, NULL); // START OF KEY SETUP
        aes_key_setup(user_key, key_schedule, keysize);
        gettimeofday(&time_2, NULL); // END OF KEY SETUP

        #ifdef DEBUG
            printf("\nUser_key = ");
            print_hex(user_key, length_of_key_bytes);
        #endif

        switch (user_choice) {
            case 1: // ECB mode
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION
                aes_encrypt_ecb(message, length_of_message, ciphertext, key_schedule, keysize);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_ecb(ciphertext, length_of_message, enc_buf, key_schedule, keysize);
                gettimeofday(&time_5, NULL); // END OF DECRYPTION

                #ifdef DEBUG
                    printf("\nECB MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;

            case 2: // CBC mode
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION                
                aes_encrypt_cbc(message, length_of_message, ciphertext, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_cbc(ciphertext, length_of_message, enc_buf, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_5, NULL); // END OF DECRYPTION
                
                #ifdef DEBUG
                    printf("\nCBC MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;

            case 3: // PCBC mode
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }         
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION
                aes_encrypt_pcbc(message, length_of_message, ciphertext, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_pcbc(ciphertext, length_of_message, enc_buf, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_5, NULL); // END OF DECRYPTION
                
                #ifdef DEBUG
                    printf("\nECB MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;

            case 4: // CFB mode
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }  
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION
                aes_encrypt_cfb(message, length_of_message, ciphertext, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_cfb(ciphertext, length_of_message, enc_buf, key_schedule, keysize, initialize_vector);                
                gettimeofday(&time_5, NULL); // END OF DECRYPTION
                
                #ifdef DEBUG
                    printf("\nCFB MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;

            case 5: // OFB mode
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }         
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION
                aes_encrypt_ofb(message, length_of_message, ciphertext, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_ofb(ciphertext, length_of_message, enc_buf, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_5, NULL); // END OF DECRYPTION
                
                #ifdef DEBUG
                    printf("\nOFB MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;      

            case 6: // CTR mode
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                gettimeofday(&time_3, NULL); // START OF ENCRYPTION   
                aes_encrypt_ctr(message, length_of_message, ciphertext, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_4, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                aes_decrypt_ctr(ciphertext, length_of_message, enc_buf, key_schedule, keysize, initialize_vector);
                gettimeofday(&time_5, NULL); // END OF DECRYPTION
                
                #ifdef DEBUG
                    printf("\nCTR MODE - ON");
                    printf("\nMessage: ");
                    print_hex(message, length_of_message);
                    printf("\n\nCiphertext: ");
                    print_hex(ciphertext, length_of_message);
                    printf("\n\nDecryption: ");
                    print_hex(enc_buf, length_of_message);
                #endif

                break;

            default:
                printf("Error! This mode was not found!\n");
                return -1;
        }

        pass = pass && !memcmp(message, enc_buf, length_of_message);

        key_setup_times[i] = ((time_2.tv_sec - time_1.tv_sec) * 1000000 + time_2.tv_usec - time_1.tv_usec) / 1000.0;
        encryption_times[i] = ((time_4.tv_sec - time_3.tv_sec) * 1000000 + time_4.tv_usec - time_3.tv_usec) / 1000.0;
        decryption_times[i] = ((time_5.tv_sec - time_4.tv_sec) * 1000000 + time_5.tv_usec - time_4.tv_usec) / 1000.0;
    }
    
    // time_estimation
    double key_setup_total_time = 0;
    double encryption_total_time = 0;
    double decryption_total_time = 0;
    for (int k = 0; k < NumOfExperiments; k++) {
        key_setup_total_time += key_setup_times[k];
        encryption_total_time += encryption_times[k];
        decryption_total_time += decryption_times[k];
    }
    
    double key_setup_mean_time = key_setup_total_time / NumOfExperiments;
    double encryption_mean_time = encryption_total_time / NumOfExperiments;
    double decryption_mean_time = decryption_total_time / NumOfExperiments;
    
    double sum_key_setup = 0;
    double sum_encryption = 0;
    double sum_decryption = 0;

    for (int k = 0; k < NumOfExperiments; k++) {
        sum_key_setup += pow(key_setup_times[k] - key_setup_mean_time, 2);
        sum_encryption += pow(encryption_times[k] - encryption_mean_time, 2);
        sum_decryption += pow(decryption_times[k] - decryption_mean_time, 2);
    }

    double key_setup_std = sqrt(sum_key_setup / (NumOfExperiments - 1));
    double encryption_std = sqrt(sum_encryption / (NumOfExperiments - 1));
    double decryption_std = sqrt(sum_decryption / (NumOfExperiments - 1));

    // PRINT THE RESULTS
    printf("\nKey setup: %f ± %f (milliseconds)\n", key_setup_mean_time, key_setup_std);
    printf("Encryption: %f ± %f (milliseconds)\n", encryption_mean_time, encryption_std);
    printf("Decryption: %f ± %f (milliseconds)\n", decryption_mean_time, decryption_std);

    // CHECK THE RESULTS
    if (pass) printf("TESTS PASSED!!!\n");
    else printf("TESTS FAILED :(\n");

    free(message);
    free(ciphertext);
    free(initialize_vector);
    free(user_key);
    free(key_setup_times);
    free(encryption_times);
    free(decryption_times);
    free(enc_buf);

    return 0;
}