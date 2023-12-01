#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include "des.h"
#include <sys/time.h>
#include <time.h>

int main(int argc, char* argv[]) {

    srand(0);

    uint8_t enc_buf[DES_BLOCK_SIZE];
    uint8_t one_block[DES_BLOCK_SIZE];
    uint8_t initialize_vector[DES_BLOCK_SIZE];
    uint8_t counter[DES_BLOCK_SIZE];
    uint8_t tmp_buf[DES_BLOCK_SIZE];
    uint8_t feedback[DES_BLOCK_SIZE];

    int pass = 1;

    unsigned long int number_of_blocks;
    //printf("Enter the length of the message (in 64 bit-blocks): ");
    //scanf("%lu", &number_of_blocks);
    number_of_blocks = atoi(argv[1]);

    unsigned long int length_of_message = number_of_blocks * DES_BLOCK_SIZE;

    uint8_t* message = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));
    uint8_t* cyphertext = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));
    uint8_t* decrypted_message = (uint8_t*) calloc (length_of_message, sizeof(uint8_t));

    int length_of_key = DES_BLOCK_SIZE;
    uint8_t user_key[DES_BLOCK_SIZE];

    int user_choice;
    //printf("Which mode? 1 - ECB, 2 - CBC, 3 - PCBC, 4 - CFB, 5 - OFB, 6 - CTR\n");
    //scanf("%d", &user_choice);
    user_choice = atoi(argv[2]);

    int NumOfExperiments = (int) 1e3;

    double* encryption_times = (double*) calloc (NumOfExperiments, sizeof(double));
    double* decryption_times = (double*) calloc (NumOfExperiments, sizeof(double));

    for (int i = 0; i < NumOfExperiments; i++) {
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

        struct timeval time_1, time_2, time_3;
        
        switch (user_choice) {
            case 1: // ECB mode
                gettimeofday(&time_1, NULL); // START OF ENCRYPTION

                for (int k = 0; k < number_of_blocks; k++) {
                    DES(&cyphertext[k * DES_BLOCK_SIZE], 'E', keys48b, &message[k * DES_BLOCK_SIZE], 8);
                }
                
                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION

                for (int k = 0; k < number_of_blocks; k++) {
                    DES(&decrypted_message[k * DES_BLOCK_SIZE], 'D', keys48b,  &cyphertext[k * DES_BLOCK_SIZE], 8);
                }

                gettimeofday(&time_3, NULL); // END OF DECRYPTION

                break;
            
            case 2: // CBC
                for (int j = 0; j < DES_BLOCK_SIZE; j++) {
                    initialize_vector[j] = rand() % 256;
                }

                gettimeofday(&time_1, NULL); // START OF ENCRYPTION
                
                memcpy(one_block, &message[0], DES_BLOCK_SIZE);
                xor_of_two_blocks_DES(one_block, initialize_vector);
                DES(enc_buf, 'E', keys48b, one_block, 8);
                memcpy(&cyphertext[0], enc_buf, DES_BLOCK_SIZE);

                for (int k = 1; k < number_of_blocks; k++) {
                    memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(one_block, enc_buf);
                    DES(enc_buf, 'E', keys48b, one_block, 8);
                    memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }
                
                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                
                memcpy(feedback, &cyphertext[0], DES_BLOCK_SIZE);
                DES(enc_buf, 'D', keys48b, feedback, 8);
                xor_of_two_blocks_DES(enc_buf, initialize_vector);
                memcpy(&decrypted_message[0], enc_buf, DES_BLOCK_SIZE);

                for (int k = 1; k < number_of_blocks; k++) {
                    memcpy(tmp_buf, &cyphertext[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    DES(enc_buf, 'D', keys48b, tmp_buf, 8);
                    xor_of_two_blocks_DES(enc_buf, feedback);
                    memcpy(feedback, tmp_buf, DES_BLOCK_SIZE);
                    memcpy(&decrypted_message[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }

                gettimeofday(&time_3, NULL); // END OF DECRYPTION
                
                break;

            case 3: // PCBC
                for (int j = 0; j < DES_BLOCK_SIZE; j++) {
                    initialize_vector[j] = rand() % 256;
                }

                gettimeofday(&time_1, NULL); // START OF ENCRYPTION
                
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
                
                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION

                memcpy(one_block, &cyphertext[0], DES_BLOCK_SIZE);
                memcpy(feedback, one_block, DES_BLOCK_SIZE);
                DES(enc_buf, 'D', keys48b, one_block, DES_BLOCK_SIZE);
                xor_of_two_blocks_DES(enc_buf, initialize_vector);
                memcpy(&decrypted_message[0], enc_buf, DES_BLOCK_SIZE);
                xor_of_two_blocks_DES(feedback, enc_buf);

                for (int k = 1; k < number_of_blocks; k++) {
                    memcpy(one_block, &cyphertext[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    memcpy(tmp_buf, one_block, DES_BLOCK_SIZE);
                    DES(enc_buf, 'D', keys48b, one_block, DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(enc_buf, feedback);
                    memcpy(&decrypted_message[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(tmp_buf, enc_buf);
                    memcpy(feedback, tmp_buf, DES_BLOCK_SIZE);
                }

                gettimeofday(&time_3, NULL); // END OF DECRYPTION

                break;

            case 4: // CFB
                for (int j = 0; j < DES_BLOCK_SIZE; j++) {
                    initialize_vector[j] = rand() % 256;
                }

                gettimeofday(&time_1, NULL); // START OF ENCRYPTION

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

                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                
                DES(enc_buf, 'E', keys48b, initialize_vector, DES_BLOCK_SIZE);
                memcpy(one_block, &cyphertext[0], DES_BLOCK_SIZE);
                xor_of_two_blocks_DES(enc_buf, one_block);
                memcpy(&decrypted_message[0], enc_buf, DES_BLOCK_SIZE);

                for (int k = 1; k < number_of_blocks; k++) {
                    DES(enc_buf, 'E', keys48b, one_block, DES_BLOCK_SIZE);
                    memcpy(one_block, &cyphertext[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(enc_buf, one_block);
                    memcpy(&decrypted_message[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }

                gettimeofday(&time_3, NULL); // END OF DECRYPTION

                break;

            case 5: // OFB
                for (int j = 0; j < DES_BLOCK_SIZE; j++) {
                    initialize_vector[j] = rand() % 256;
                }
                
                gettimeofday(&time_1, NULL); // START OF ENCRYPTION

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
                
                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION
                
                DES(enc_buf, 'E', keys48b, initialize_vector, DES_BLOCK_SIZE);
                memcpy(feedback, enc_buf, DES_BLOCK_SIZE);
                memcpy(one_block, &cyphertext[0], DES_BLOCK_SIZE);
                xor_of_two_blocks_DES(enc_buf, one_block);
                memcpy(&decrypted_message[0], enc_buf, DES_BLOCK_SIZE);
                
                for (int k = 1; k < number_of_blocks; k++) {
                    DES(enc_buf, 'E', keys48b, feedback, DES_BLOCK_SIZE);
                    memcpy(feedback, enc_buf, DES_BLOCK_SIZE);
                    memcpy(one_block, &cyphertext[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(enc_buf, one_block);
                    memcpy(&decrypted_message[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }
                
                gettimeofday(&time_3, NULL); // END OF DECRYPTION

                break;

            case 6: // CTR
                for (int j = 0; j < DES_BLOCK_SIZE - 2; j++) {
                    counter[j] = rand() % 256;
                }

                gettimeofday(&time_1, NULL); // START OF ENCRYPTION
                
                for (int k = 0; k < number_of_blocks; k++) {
                    counter[DES_BLOCK_SIZE - 2] = k / 256;
                    counter[DES_BLOCK_SIZE - 1] = k % 256;
                    DES(enc_buf, 'E', keys48b, counter, DES_BLOCK_SIZE);
                    memcpy(one_block, &message[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(enc_buf, one_block);
                    memcpy(&cyphertext[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }
                
                gettimeofday(&time_2, NULL); // END OF ENCRYPTION and START OF DECRYPTION

                for (int k = 0; k < number_of_blocks; k++) {
                    counter[DES_BLOCK_SIZE - 2] = k / 256;
                    counter[DES_BLOCK_SIZE - 1] = k % 256;
                    DES(enc_buf, 'E', keys48b, counter, DES_BLOCK_SIZE);
                    memcpy(one_block, &cyphertext[k * DES_BLOCK_SIZE], DES_BLOCK_SIZE);
                    xor_of_two_blocks_DES(enc_buf, one_block);
                    memcpy(&decrypted_message[k * DES_BLOCK_SIZE], enc_buf, DES_BLOCK_SIZE);
                }
                
                gettimeofday(&time_3, NULL); // END OF DECRYPTION

                break;

            default:
                printf("Error! This mode was not found!\n");
                return -1;
        }

        pass = pass && !memcmp(message, decrypted_message, length_of_message);
    
        encryption_times[i] = ((time_2.tv_sec - time_1.tv_sec) * 1000000 + time_2.tv_usec - time_1.tv_usec) / 1000.0;
        decryption_times[i] = ((time_3.tv_sec - time_2.tv_sec) * 1000000 + time_3.tv_usec - time_2.tv_usec) / 1000.0;
    }

    // time_estimation
    double encryption_total_time = 0;
    double decryption_total_time = 0;
    for (int k = 0; k < NumOfExperiments; k++) {
        encryption_total_time += encryption_times[k];
        decryption_total_time += decryption_times[k];
    }
    double encryption_mean_time = encryption_total_time / NumOfExperiments;
    double decryption_mean_time = decryption_total_time / NumOfExperiments;
    
    double sum_encryption = 0;
    double sum_decryption = 0;

    for (int k = 0; k < NumOfExperiments; k++) {
        sum_encryption += pow(encryption_times[k] - encryption_mean_time, 2);
        sum_decryption += pow(decryption_times[k] - decryption_mean_time, 2);
    }

    double encryption_std = sqrt(sum_encryption / (NumOfExperiments - 1));
    double decryption_std = sqrt(sum_decryption / (NumOfExperiments - 1));

    // PRINT THE RESULTS
    printf("Encryption: %f ± %f (milliseconds)\n", encryption_mean_time, encryption_std);
    printf("Decryption: %f ± %f (milliseconds)\n", decryption_mean_time, decryption_std);

    // CHECK THE RESULTS
    if (pass) printf("TESTS PASSED!!!\n");
    else printf("TESTS FAILED(\n");

    free(message);
    free(cyphertext);
    free(decrypted_message);

    free(encryption_times);
    free(decryption_times);

    return 0;
}