#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "des.h"
// #include "../api.h"

/****************************** MACROS ******************************/
// #define DEBUG
// #define VERBOSE
// #define MY

#ifdef DEBUG
    #define PRINT(str) printf("%s", str)
#else 
    #define PRINT(str)
#endif 

static unsigned long int sum_tests = 0;


/*********************** FUNCTION DEFINITIONS **********************/

// for debug and print hex value
void print_hex(uint8_t str[], int len) {
    int idx;

    for(idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);

    return;
}

void print_hex_color(uint8_t str[], int len, int* arr, int cnt_error) {
    int idx;
    int cnt = 0;

    for(idx = 0; idx < len; idx++) {
        if ((idx == arr[cnt]) && (cnt < cnt_error)) {
            printf("%s%02x%s", KYEL, str[idx], KWHT); 
            cnt++;
        }
        else printf("%02x", str[idx]);
    }

    return;
}

void print_debug(uint8_t* message, uint8_t* cyphertext, unsigned long int length_of_message) {
    #ifdef DEBUG
        printf("\nMessage: ");
        print_hex(message, length_of_message);
        printf("\n\nEncryption: ");
        print_hex(cyphertext, length_of_message);
    #endif

    return;
}

void change_message(uint8_t* message, unsigned long int length_of_message, int num_err) {
    for(int i = 0; i < num_err; i++) {
        message[rand() % length_of_message] = rand() % 256;
    }

    return;
}

void xor_of_two_blocks_DES(uint8_t* block_1, uint8_t* block_2) {
    for (int i = 0; i < DES_BLOCK_SIZE; i++) {
        block_1[i] ^= block_2[i];
    }
    return;
}

double check_error(uint8_t* message_first, uint8_t* message_second, unsigned long int length_of_message) {
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

void des_ecb_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks) {
    for (int k = 0; k < number_of_blocks; k++) {
        DES(&cyphertext[k * DES_BLOCK_SIZE], 'E', keys48b, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
    }
    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

    return;
}

void des_cbc_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks, uint8_t* initialize_vector) {
    uint8_t one_block[DES_BLOCK_SIZE];
    uint8_t enc_buf[DES_BLOCK_SIZE];

    memcpy(one_block, &message[0], DES_BLOCK_SIZE);
    xor_of_two_blocks_DES(one_block, initialize_vector);
    DES(enc_buf, 'E', keys48b, one_block, DES_BLOCK_SIZE);
    memcpy(&cyphertext[0], enc_buf, DES_BLOCK_SIZE);

    for (int k = 1; k < number_of_blocks; k++) {
        memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(one_block, enc_buf);
        DES(enc_buf, 'E', keys48b, one_block, DES_BLOCK_SIZE);
        memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
    }
    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

    return;
}

void des_pcbc_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks, uint8_t* initialize_vector) {
    uint8_t one_block[DES_BLOCK_SIZE];
    uint8_t enc_buf[DES_BLOCK_SIZE];
    uint8_t feedback[DES_BLOCK_SIZE];
    uint8_t tmp_buf[DES_BLOCK_SIZE];

    memcpy(one_block, &message[0], DES_BLOCK_SIZE);
    memcpy(feedback, one_block, DES_BLOCK_SIZE);
    xor_of_two_blocks_DES(one_block, initialize_vector);
    DES(enc_buf, 'E', keys48b, one_block, 8);
    memcpy(&cyphertext[0], enc_buf, DES_BLOCK_SIZE);
    xor_of_two_blocks_DES(feedback, enc_buf);

    for (int k = 1; k < number_of_blocks; k++) {
        memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
        memcpy(tmp_buf, one_block, DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(one_block, feedback);
        DES(enc_buf, 'E', keys48b, one_block, 8);
        memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(tmp_buf, enc_buf);
        memcpy(feedback, tmp_buf, DES_BLOCK_SIZE);
    }

    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

    return;
}

void des_cfb_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks, uint8_t* initialize_vector) {
    uint8_t one_block[DES_BLOCK_SIZE];
    uint8_t enc_buf[DES_BLOCK_SIZE];

    DES(enc_buf, 'E', keys48b, initialize_vector, DES_BLOCK_SIZE);
    memcpy(one_block, &message[0], DES_BLOCK_SIZE);
    xor_of_two_blocks_DES(one_block, enc_buf);
    memcpy(&cyphertext[0], one_block, DES_BLOCK_SIZE);

    for (int k = 1; k < number_of_blocks; k++) {
        DES(enc_buf, 'E', keys48b, one_block, DES_BLOCK_SIZE);
        memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(one_block, enc_buf);
        memcpy(&cyphertext[k * DES_BLOCK_SIZE], one_block, DES_BLOCK_SIZE);
    }
    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

    return;
}

void des_ofb_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks, uint8_t* initialize_vector) {
    uint8_t one_block[DES_BLOCK_SIZE];
    uint8_t enc_buf[DES_BLOCK_SIZE];
    uint8_t feedback[DES_BLOCK_SIZE];

    DES(enc_buf, 'E', keys48b, initialize_vector, DES_BLOCK_SIZE);
    memcpy(feedback, enc_buf, DES_BLOCK_SIZE);
    memcpy(one_block, &message[0], DES_BLOCK_SIZE);
    xor_of_two_blocks_DES(enc_buf, one_block);
    memcpy(&cyphertext[0], enc_buf, DES_BLOCK_SIZE);
    
    for (int k = 1; k < number_of_blocks; k++) {
        DES(enc_buf, 'E', keys48b, feedback, DES_BLOCK_SIZE);
        memcpy(feedback, enc_buf, DES_BLOCK_SIZE);
        memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(enc_buf, one_block);
        memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
    }
    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

    return;
}

void des_ctr_mode(uint8_t * cyphertext, uint8_t mode, uint64_t * keys48b, uint8_t * message, unsigned long int number_of_blocks,  uint8_t* counter) {
    uint8_t enc_buf[DES_BLOCK_SIZE];
    uint8_t one_block[DES_BLOCK_SIZE];

    for (int k = 0; k < number_of_blocks; k++) {
        counter[DES_BLOCK_SIZE - 2] = k / 256;
        counter[DES_BLOCK_SIZE - 1] = k % 256;
        DES(enc_buf, 'E', keys48b, counter, DES_BLOCK_SIZE);
        memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
        xor_of_two_blocks_DES(enc_buf, one_block);
        memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
    }
    print_debug(message, cyphertext, number_of_blocks * DES_BLOCK_SIZE);

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

int DES_test_error(unsigned long int number_of_blocks, int num_err, int user_choice, int NumOfExperiments, ERROR* DES_results) {
    srand(time(NULL));
    //-------------
    uint8_t initialize_vector[DES_BLOCK_SIZE];
    uint8_t counter[DES_BLOCK_SIZE];
    //------------

    // #ifdef MY
    //     unsigned long int number_of_blocks;
    //     int NumOfExperiments = 10;
    // #endif

    double result[NumOfExperiments];

    printf("\n%sDES_PROGRAM -> RUN%s\n", KGRN, KWHT);

    // #ifdef MY
    //     printf("Enter the length of the message (in 64 bit-blocks): ");
    //     scanf("%lu", &number_of_blocks);
    // #endif

    unsigned long int length_of_message = number_of_blocks * DES_BLOCK_SIZE;
    printf("Number_of_blocks(64 bit-blocks): %lu --> length message = %lu bytes\n", number_of_blocks, length_of_message);

    uint8_t* message = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));
    uint8_t* cyphertext = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));
    uint8_t* decrypted_message = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));
    uint8_t* buf_message = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));

    // #ifdef MY
    //     int num_err;
    //     printf("Number errors: ");
    //     scanf("%d", &num_err);
    // #endif

    int length_of_key = DES_BLOCK_SIZE;
    printf("length_of_key = %d\n", length_of_key);
    printf("Number of errors = %d\n", num_err);
    
    uint8_t user_key[DES_BLOCK_SIZE];

    // #ifdef MY
    //     int user_choice;
    //     printf("Which mode?(1 - ECB, 2 - CBC, 3 - PCBC, 4 - CFB, 5 - OFB, 6 - CTR)\n");
    //     scanf("%d", &user_choice);
    // #endif

    for (int i = 0; i < NumOfExperiments; i++) {
        printf("\n%sLOCAL_TEST #%d%s:", KBLU, i+1, KWHT);
        printf("\n%sGLOBAL_TEST #%ld%s:", KMAG, ++sum_tests, KWHT);
        for (int j = 0; j < length_of_message; j++) {
            message[j] = rand() % 256;
        }
        for (int j = 0; j < length_of_key; j++) {
            user_key[j] = rand() % 256;
        }

        uint64_t keys48b[16] = {0}; // создаются 16 ключей по 48 бит

        key_expansion( // расширение ключа
            join_8bits_to_64bits(user_key),
            keys48b
        );

        #ifdef DEBUG
            printf("\nUser_key = ");
            print_hex(user_key, length_of_key);
        #endif  

        switch(user_choice) {
            case 1: // ECB mode
                printf("\nECB MODE:");
                PRINT("\nNormal ECB:");
                des_ecb_mode(buf_message, 'E', keys48b, message, number_of_blocks);
                change_message(message, length_of_message, num_err);
                PRINT("\nError ECB:");
                des_ecb_mode(cyphertext, 'E', keys48b, message, number_of_blocks);
                break;
            case 2: // CBC mode
                printf("\nCBC MODE:");
                for (int j = 0; j < DES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CBC:");
                des_cbc_mode(buf_message, 'E', keys48b, message, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CBC:");
                des_cbc_mode(cyphertext, 'E', keys48b, message, number_of_blocks, initialize_vector);
                break;
            case 3: // PCBC mode
                printf("\nPCBC MODE:");
                for (int j = 0; j < DES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal PCBC:");
                des_pcbc_mode(buf_message, 'E', keys48b, message, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError PCBC:");
                des_pcbc_mode(cyphertext, 'E', keys48b, message, number_of_blocks, initialize_vector);
                break;
            case 4: // CFB mode
                printf("\nCFB MODE:");
                for (int j = 0; j < DES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CFB:");
                des_cfb_mode(buf_message, 'E', keys48b, message, number_of_blocks, initialize_vector);
                change_message(message, length_of_message, num_err);
                PRINT("\nError CFB:");
                des_cfb_mode(cyphertext, 'E', keys48b, message, number_of_blocks, initialize_vector);
                break;
            case 5: // OFB mode
                printf("\nOFB MODE:");
                for (int j = 0; j < DES_BLOCK_SIZE; j++) { // the initialization of an IV
                    initialize_vector[j] = rand() % 256;
                }
                PRINT("\nNormal CFB:");
                des_ofb_mode(buf_message, 'E', keys48b, message, number_of_blocks, initialize_vector);                
                change_message(message, length_of_message, num_err);
                PRINT("\nError CFB:");
                des_ofb_mode(cyphertext, 'E', keys48b, message, number_of_blocks, initialize_vector);
                break;
            case 6: // CTR mode
                printf("\nECB MODE:");
                for (int j = 0; j < DES_BLOCK_SIZE - 2; j++) { // the initialization of a counter
                    counter[j] = rand() % 256;
                }
                PRINT("\nNormal CTR:");
                des_ctr_mode(buf_message, 'E', keys48b, message, number_of_blocks, initialize_vector);                
                change_message(message, length_of_message, num_err);
                PRINT("\nError CTR:");
                des_ctr_mode(cyphertext, 'E', keys48b, message, number_of_blocks, initialize_vector);                
                break;
            default:
                printf("Error! This mode was not found!\n");
                break;
        }

        result[i] = check_error(buf_message, cyphertext, length_of_message);
    }

    error_estimation(result, NumOfExperiments, DES_results);
    printf("\n%sError: %lf +- %lf %%%s\n", KRED, DES_results->err_mean, DES_results->err_std, KWHT);

    free(message);
    free(cyphertext);
    free(decrypted_message);
    free(buf_message);

    return 0;

}
