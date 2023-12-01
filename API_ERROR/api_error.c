#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <time.h>
#include "AES/aes.h"
#include "DES/des.h"
#include "api.h"

// #define DEBUG
// #define VERBOSE

#ifdef DEBUG
    #define PRINT(str) printf("%s", str)
#else 
    #define PRINT(str)
#endif 

// for debug and print hex value
void print_hex(BYTE str[], int len) {
    int idx;

    for(idx = 0; idx < len; idx++)
        printf("%02x", str[idx]);

    return;
}

void print_hex_color(BYTE str[], int len, int* arr, int cnt_error) {
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

void print_debug(BYTE* message, BYTE* cyphertext, unsigned long int length_of_message) {
    #ifdef DEBUG
        printf("\nMessage: ");
        print_hex(message, length_of_message);
        printf("\n\nEncryption: ");
        print_hex(cyphertext, length_of_message);
    #endif

    return;
}

int file_print(char* file, double mean[][10], double std[][10]) {
    FILE* fd;
    if((fd = fopen(file, "w")) == NULL) {
        perror("Error FILE!!!");
        exit(1);
    }

    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 10; j++) {
            fprintf(fd, "%lf ", mean[i][j]);
        }

        fprintf(fd, "\n");

        for (int j = 0; j < 10; j++) {
            fprintf(fd, "%lf ", std[i][j]);
        }
        fprintf(fd, "\n");
    }
    fclose(fd);

    return 0;
}

int main() 
{
    int NumOfExperiments = 10;
    unsigned long int num_blocks = 100;

    int num_err[10] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};

    // arrays for mean values
    double AES_1_encryption_mean[6][10], AES_2_encryption_mean[6][10], AES_3_encryption_mean[6][10];
    double DES_encryption_mean[6][10];
    // double Blowfish_encryption_mean[6][10];

    // arrays for std values
    double AES_1_encryption_std[6][10], AES_2_encryption_std[6][10], AES_3_encryption_std[6][10];
    double DES_encryption_std[6][10];
    double Blowfish_encryption_std[6][10];

    for (int i = 0; i < 6; i++) {
        printf("Mode: %d\n", i + 1);
        for (int j = 0; j < 10; j++) {
            printf("Number of errors(in bytes): %d\n", num_err[j]);
            
            ERROR results;
#if 0            
            // AES-1
            AES_test_error(num_blocks, num_err[j], 1, i + 1, NumOfExperiments, &results);
            AES_1_encryption_mean[i][j] = results.err_mean;
            AES_1_encryption_std[i][j] = results.err_std;

            // AES-2
            AES_test_error(num_blocks, num_err[j], 2, i + 1, NumOfExperiments, &results);
            AES_2_encryption_mean[i][j] = results.err_mean;
            AES_2_encryption_std[i][j] = results.err_std;

            // AES-3
            AES_test_error(num_blocks, num_err[j], 3, i + 1, NumOfExperiments, &results);
            AES_3_encryption_mean[i][j] = results.err_mean;
            AES_3_encryption_std[i][j] = results.err_std;
#endif
            DES_test_error(num_blocks, num_err[j], i + 1, NumOfExperiments, &results);
            DES_encryption_mean[i][j] = results.err_mean;
            DES_encryption_std[i][j] = results.err_std;

        }
    }

#if 0
            // DES
            {
                KPI results;
                DES_time_performance(2 * number_of_blocks[j], i + 1, NumOfExperiments, &results);
            
                DES_encryption_mean[i][j] = results.encryption_mean_time;
                DES_encryption_std[i][j] = results.encryption_std;
                
                DES_decryption_mean[i][j] = results.decryption_mean_time;
                DES_decryption_std[i][j] = results.decryption_std;
            }
            
            // Blowfish
            {
                KPI results;
                Blowfish_time_performance(2 * number_of_blocks[j], 56, i + 1, NumOfExperiments, &results);
            
                Blowfish_encryption_mean[i][j] = results.encryption_mean_time;
                Blowfish_encryption_std[i][j] = results.encryption_std;
                
                Blowfish_decryption_mean[i][j] = results.decryption_mean_time;
                Blowfish_decryption_std[i][j] = results.decryption_std;
            }
        }
    }
#endif

    // file_print("AES/logs/AES_1_encryption.txt", AES_1_encryption_mean, AES_1_encryption_std);
    // file_print("AES/logs/AES_2_encryption.txt", AES_2_encryption_mean, AES_2_encryption_std);
    // file_print("AES/logs/AES_3_encryption.txt", AES_3_encryption_mean, AES_3_encryption_std);
    file_print("DES/logs/DES_encryption.txt", DES_encryption_mean, DES_encryption_std);

    return 0;
} 