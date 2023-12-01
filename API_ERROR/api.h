#ifndef _API_H_
#define _API_H_

#include "AES/aes.h"
#include "DES/des.h"

/****************************** MACROS ******************************/
// api colors
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

typedef struct ERROR {
    double err_mean, err_std;
} ERROR;

int AES_test_error(unsigned long int number_of_blocks, int num_err, int option_key, int user_choice, int NumOfExperiments, ERROR* AES_results);
int DES_test_error(unsigned long int number_of_blocks, int num_err, int user_choice, int NumOfExperiments, ERROR* DES_results);

void print_hex(BYTE str[], int len);
void print_hex_color(BYTE str[], int len, int* arr, int cnt_error);
void print_debug(BYTE* message, BYTE* cyphertext, unsigned long int length_of_message);


#endif //_API_H_