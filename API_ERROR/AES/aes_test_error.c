#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "aes.h"
#include "../api.h"

// // #define DEBUG
// // #define VERBOSE

// #ifdef DEBUG
//     #define PRINT(str) printf("%s", str)
// #else 
//     #define PRINT(str)
// #endif 


void change_message(BYTE* message, unsigned long int length_of_message, int num_err) {
    for(int i = 0; i < num_err; i++) {
        message[rand() % length_of_message] = rand() % 256;
    }

    return;
}

void xor_of_two_blocks_AES(BYTE* block_1, BYTE* block_2) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        block_1[i] ^= block_2[i];
    }

    return;
}

double check_error(BYTE* message_first, BYTE* message_second, unsigned long int length_of_message) {
    unsigned long int cnt_error = 0;
    int cnt = 0;
    int arr[length_of_message];

    for (int i = 0; i < length_of_message; i++) {
        if(message_first[i] != message_second[i]) {
            arr[cnt++] = i;
            cnt_error++;
        }
    }

    #ifdef VERBOSE
        printf("\n%sEncrypted_message:%s ", KGRN, KWHT);
        print_hex_color(message_first, length_of_message, arr, cnt_error);
        printf("\n%sError encrypted_message:%s ", KRED, KWHT);
        print_hex_color(message_second, length_of_message, arr, cnt_error);
    #endif

    printf("\nCount of error: %ld", cnt_error);
    double res = (double)cnt_error*100 / length_of_message;
    printf("\nPercentage of errors: %.2f%%\n", res);

    return res;
}

void aes_ecb_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks) {
    for (int k = 0; k < number_of_blocks; k++) {
        aes_encrypt(&message[k * AES_BLOCK_SIZE], &cyphertext[k * AES_BLOCK_SIZE], key_schedule, keysize);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

void aes_cbc_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* initialize_vector) {
    BYTE one_block[AES_BLOCK_SIZE];
    BYTE enc_buf[AES_BLOCK_SIZE];

    memcpy(one_block, &message[0], AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(one_block, initialize_vector);
    aes_encrypt(one_block, enc_buf, key_schedule, keysize);
    memcpy(&cyphertext[0], enc_buf, AES_BLOCK_SIZE);

    for (int k = 1; k < number_of_blocks; k++) {
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(one_block, enc_buf);
        aes_encrypt(one_block, enc_buf, key_schedule, keysize);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], enc_buf, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

void aes_pcbc_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* initialize_vector) {
    BYTE one_block[AES_BLOCK_SIZE];
    BYTE enc_buf[AES_BLOCK_SIZE];
    BYTE feedback[AES_BLOCK_SIZE];
    BYTE tmp_buf[AES_BLOCK_SIZE];

    memcpy(one_block, &message[0], AES_BLOCK_SIZE);
    memcpy(feedback, one_block, AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(one_block, initialize_vector);
    aes_encrypt(one_block, enc_buf, key_schedule, keysize);
    memcpy(&cyphertext[0], enc_buf, AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(feedback, enc_buf);
    
    for (int k = 1; k < number_of_blocks; k++) {
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        memcpy(tmp_buf, one_block, AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(one_block, feedback);
        aes_encrypt(one_block, enc_buf, key_schedule, keysize);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], enc_buf, AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(tmp_buf, enc_buf);
        memcpy(feedback, tmp_buf, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

#if 0
void aes_pcbc_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* initialize_vector) {
    BYTE one_block[AES_BLOCK_SIZE];
    BYTE enc_buf[AES_BLOCK_SIZE];
    BYTE feedback[AES_BLOCK_SIZE];
    
    memcpy(one_block, &message[0], AES_BLOCK_SIZE);
    memcpy(feedback, one_block, AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(one_block, initialize_vector);
    aes_encrypt(one_block, enc_buf, key_schedule, keysize);
    memcpy(&cyphertext[0], enc_buf, AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(feedback, enc_buf);
    
    for (int k = 1; k < number_of_blocks; k++) {
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(one_block, feedback);
        aes_encrypt(one_block, enc_buf, key_schedule, keysize);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], enc_buf, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}
#endif

void aes_cfb_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* initialize_vector) {
    BYTE one_block[AES_BLOCK_SIZE];
    BYTE enc_buf[AES_BLOCK_SIZE];

    aes_encrypt(initialize_vector, enc_buf, key_schedule, keysize);
    memcpy(one_block, &message[0], AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(one_block, enc_buf);
    memcpy(&cyphertext[0], one_block, AES_BLOCK_SIZE);

    for (int k = 1; k < number_of_blocks; k++) {
        aes_encrypt(one_block, enc_buf, key_schedule, keysize);
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(one_block, enc_buf);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], one_block, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

void aes_ofb_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* initialize_vector) {
    BYTE one_block[AES_BLOCK_SIZE];
    BYTE enc_buf[AES_BLOCK_SIZE];
    BYTE feedback[AES_BLOCK_SIZE];

    aes_encrypt(initialize_vector, enc_buf, key_schedule, keysize);
    memcpy(feedback, enc_buf, AES_BLOCK_SIZE);
    memcpy(one_block, &message[0], AES_BLOCK_SIZE);
    xor_of_two_blocks_AES(enc_buf, one_block);
    memcpy(&cyphertext[0], enc_buf, AES_BLOCK_SIZE);
    
    for (int k = 1; k < number_of_blocks; k++) {
        aes_encrypt(feedback, enc_buf, key_schedule, keysize);
        memcpy(feedback, enc_buf, AES_BLOCK_SIZE);
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(enc_buf, one_block);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], enc_buf, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

void aes_ctr_mode(BYTE* message, unsigned long int length_of_message, BYTE* cyphertext, WORD key_schedule[], int keysize, unsigned long int number_of_blocks, BYTE* counter) {
    BYTE enc_buf[AES_BLOCK_SIZE];
    BYTE one_block[AES_BLOCK_SIZE];

    for (int k = 0; k < number_of_blocks; k++) {
        counter[AES_BLOCK_SIZE - 2] = k / 256;
        counter[AES_BLOCK_SIZE - 1] = k % 256;
        aes_encrypt(counter, enc_buf, key_schedule, keysize);
        memcpy(one_block, &message[k * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        xor_of_two_blocks_AES(enc_buf, one_block);
        memcpy(&cyphertext[k * AES_BLOCK_SIZE], enc_buf, AES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, length_of_message);

    return;
}

void error_estimation(double result[], int NumOfExperiments, ERROR* output)
{
    // time_estimation
    double total_err = 0;
    for(int i = 0; i < NumOfExperiments; i++) {
        total_err += result[i];
    }

    double err_mean = total_err / NumOfExperiments;
    double sum_err = 0;

    for (int i = 0; i < NumOfExperiments; i++) {
        sum_err += (result[i] - err_mean)*(result[i] - err_mean);
    }

    double err_std = sqrt(sum_err / (NumOfExperiments - 1));

    output->err_mean = err_mean;
    output->err_std = err_std;

    return;
}

int AES_test_error(unsigned long int number_of_blocks, int num_err, int option_key, int user_choice, int NumOfExperiments, ERROR* AES_results) {

    srand(time(NULL));

    WORD key_schedule[60];

    // unsigned long int number_of_blocks;
    // int NumOfExperiments = 1000;
    double result[NumOfExperiments];

    printf("\n%sAES_PROGRAM -> RUN%s\n", KGRN, KWHT);

    // printf("Enter the length of the message (in 128 bit-blocks): ");
    // scanf("%lu", &number_of_blocks);

    unsigned long int length_of_message = number_of_blocks * AES_BLOCK_SIZE;
    printf("Number_of_blocks(128 bit-blocks): %lu --> length message = %lu bytes\n", number_of_blocks, length_of_message);

    BYTE enc_buf[AES_BLOCK_SIZE];
    BYTE initialize_vector[AES_BLOCK_SIZE];
    BYTE counter[AES_BLOCK_SIZE];
    // BYTE feedback[AES_BLOCK_SIZE];
    // BYTE tmp_buf[AES_BLOCK_SIZE];

    BYTE* message = (BYTE*) calloc (length_of_message, sizeof(BYTE));
    BYTE* cyphertext = (BYTE*) calloc (length_of_message, sizeof(BYTE));
    BYTE* decrypted_message = (BYTE*) calloc (length_of_message, sizeof(BYTE));
    BYTE* buf_message = (BYTE*) calloc (length_of_message, sizeof(BYTE));

    // int option_key;
    // do {
    //     printf("Choose the option for the length of the key (1 - 128 bits, 2 - 192 bits, 3 - 256 bits): ");
    //     scanf("%d", &option_key);
    // } while((option_key > 3) || (option_key < 1));

    int length_of_key_bytes = 16 + (option_key - 1) * 8; //length of key in bytes
    int keysize = length_of_key_bytes * 8; // length of key in bits
    printf("Key_size = %d bits\n", keysize);
    printf("Number of errors = %d\n", num_err);
    
    BYTE* user_key = (BYTE*) calloc (length_of_key_bytes, sizeof(BYTE));
    
    // int user_choice;
    // printf("Which mode?(1 - ECB, 2 - CBC, 3 - PCBC, 4 - CFB, 5 - OFB, 6 - CTR)\n");
    // scanf("%d", &user_choice);

    // int num_err;
    // printf("Number errors: ");
    // scanf("%d", &num_err);

    for (int i = 0; i < NumOfExperiments; i++) {
        printf("\n%sTEST #%d%s:", KBLU, i+1, KWHT);
        for (int j = 0; j < length_of_message; j++) {
            message[j] = rand() % 256;
        }
        for (int j = 0; j < length_of_key_bytes; j++) {
            user_key[j] = rand() % 256;
        }
        aes_key_setup(user_key, key_schedule, keysize);

        #ifdef DEBUG
            printf("\nUser_key = ");
            print_hex(user_key, length_of_key_bytes);
        #endif  

        switch(user_choice) {
            case 1: // ECB mode
                printf("\nECB MODE:");
                PRINT("\nNormal ECB:");
                aes_ecb_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks);
                change_message(message, length_of_message, num_err);
                PRINT("\nError ECB:");
                aes_ecb_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks);
                break;
            case 2: // CBC mode
                printf("\nCBC MODE:");
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CBC:");
                aes_cbc_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CBC:");
                aes_cbc_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks, initialize_vector);
                break;
            case 3: // PCBC mode
                printf("\nPCBC MODE:");
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal PCBC:");
                aes_pcbc_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError PCBC:");
                aes_pcbc_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks, initialize_vector);
                break;
            case 4: // CFB mode
                printf("\nCFB MODE:");
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CFB:");
                aes_cfb_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CFB:");
                aes_cfb_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks, initialize_vector);
                break;
            case 5: // OFB mode
                printf("\nOFB MODE:");
                for (int j = 0; j < AES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CFB:");
                aes_ofb_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CFB:");
                aes_ofb_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks, initialize_vector);
                break;
            case 6: // CTR mode
                printf("\nECB MODE:");
                for (int j = 0; j < AES_BLOCK_SIZE - 2; j++) { // the initialization of a counter
                    counter[j] = rand() % 256;
                }
                PRINT("\nNormal CTR:");
                aes_ctr_mode(message, length_of_message, buf_message, key_schedule, keysize, number_of_blocks, counter);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CTR:");
                aes_ctr_mode(message, length_of_message, cyphertext, key_schedule, keysize, number_of_blocks, counter);
                break;
            default:
                printf("Error! This mode was not found!\n");
                break;
        }

        result[i] = check_error(buf_message, cyphertext, length_of_message);
    }

    error_estimation(result, NumOfExperiments, AES_results);
    printf("\n%sError: %lf +- %lf %%%s\n", KRED, AES_results->err_mean, AES_results->err_std, KWHT);

    free(message);
    free(cyphertext);
    free(decrypted_message);
    free(user_key);
    free(buf_message);

    return 0;

}
