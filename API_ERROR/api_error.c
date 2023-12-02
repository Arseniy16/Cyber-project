#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <time.h>
// #include "AES/aes.h"
#include "DES/des.h"

// #define AES
#define DES

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
    int NumOfExperiments = 1000;
    unsigned long int num_blocks = 200; // 100 - for AES, 200 - for DES

    int num_err[10] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};

    // arrays for mean values
    double AES_1_encryption_mean[6][10], AES_2_encryption_mean[6][10], AES_3_encryption_mean[6][10];
    double DES_encryption_mean[6][10];
    // double Blowfish_encryption_mean[6][10];

    // arrays for std values
    double AES_1_encryption_std[6][10], AES_2_encryption_std[6][10], AES_3_encryption_std[6][10];
    double DES_encryption_std[6][10];
    // double Blowfish_encryption_std[6][10];

    for (int i = 0; i < 6; i++) {
        printf("Mode: %d\n", i + 1);
        for (int j = 0; j < 10; j++) {
            printf("Number of errors(in bytes): %d\n", num_err[j]);
            
            ERROR results;
// #ifdef AES            
//             // AES-1
//             AES_test_error(num_blocks, num_err[j], 1, i + 1, NumOfExperiments, &results);
//             AES_1_encryption_mean[i][j] = results.err_mean;
//             AES_1_encryption_std[i][j] = results.err_std;

//             // AES-2
//             AES_test_error(num_blocks, num_err[j], 2, i + 1, NumOfExperiments, &results);
//             AES_2_encryption_mean[i][j] = results.err_mean;
//             AES_2_encryption_std[i][j] = results.err_std;

//             // AES-3
//             AES_test_error(num_blocks, num_err[j], 3, i + 1, NumOfExperiments, &results);
//             AES_3_encryption_mean[i][j] = results.err_mean;
//             AES_3_encryption_std[i][j] = results.err_std;
// #endif

#ifdef DES
            DES_test_error(num_blocks, num_err[j], i + 1, NumOfExperiments, &results);
            DES_encryption_mean[i][j] = results.err_mean;
            DES_encryption_std[i][j] = results.err_std;
#endif

// #ifdef Blowfish
//             Blowfish_test_error(num_blocks, num_err[j], i + 1, NumOfExperiments, &results);
//             Blowfish_encryption_mean[i][j] = results.err_mean;
//             Blowfish_encryption_std[i][j] = results.err_std;
// #endif
        }
    }

    // file_print("AES/logs/AES_1_encryption.txt", AES_1_encryption_mean, AES_1_encryption_std);
    // file_print("AES/logs/AES_2_encryption.txt", AES_2_encryption_mean, AES_2_encryption_std);
    // file_print("AES/logs/AES_3_encryption.txt", AES_3_encryption_mean, AES_3_encryption_std);
    file_print("DES/logs/DES_encryption.txt", DES_encryption_mean, DES_encryption_std);

    return 0;
} 