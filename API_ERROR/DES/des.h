#ifndef DES_H
#define DES_H

// #include "../AES/aes.h"
#include <stddef.h>

#define DES_BLOCK_SIZE 8
#define BUFF_SIZE 1024

//colors
// #define KNRM  "\x1B[0m"
// #define KRED  "\x1B[31m"
// #define KGRN  "\x1B[32m"
// #define KYEL  "\x1B[33m"
// #define KBLU  "\x1B[34m"
// #define KMAG  "\x1B[35m"
// #define KCYN  "\x1B[36m"
// #define KWHT  "\x1B[37m"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

// typedef struct ERROR {
//     double err_mean, err_std;
// } ERROR;

size_t DES(uint8_t * to, uint8_t mode, uint64_t * keys48b, uint8_t * from, size_t length);

void DES_time_performance(unsigned long int number_of_blocks, int user_choice,
                          int NumOfExperiments, ERROR* DES_results);

// int DES_test_error(unsigned long int number_of_blocks, int num_err, int user_choice, int NumOfExperiments, ERROR* DES_results);

void key_expansion(uint64_t key64b, uint64_t * keys48b);
void key_permutation_56bits_to_28bits(uint64_t block56b, uint32_t * block32b_1, uint32_t * block32b_2);
void key_expansion_to_48bits(uint32_t block28b_1, uint32_t block28b_2, uint64_t * keys48b);
uint64_t key_contraction_permutation(uint64_t block56b);

void feistel_cipher(uint8_t mode, uint32_t * N1, uint32_t * N2, uint64_t * keys48b);
void round_feistel_cipher(uint32_t * N1, uint32_t * N2, uint64_t key48b);
uint32_t func_F(uint32_t block32b, uint64_t key48b);
uint64_t expansion_permutation(uint32_t block32b);
uint32_t substitutions(uint64_t block48b);
void substitution_6bits_to_4bits(uint8_t * blocks6b, uint8_t * blocks4b);
uint32_t permutation(uint32_t block32b);

uint8_t extreme_bits(uint8_t block6b);
uint8_t middle_bits(uint8_t block6b);

uint64_t initial_permutation(uint64_t block64b);
uint64_t final_permutation(uint64_t block64b);

void split_64bits_to_32bits(uint64_t block64b, uint32_t * block32b_1, uint32_t * block32b_2);
void split_64bits_to_8bits(uint64_t block64b, uint8_t * blocks8b);
void split_48bits_to_6bits(uint64_t block48b, uint8_t * blocks6b);

uint64_t join_32bits_to_64bits(uint32_t block32b_1, uint32_t block32b_2);
uint64_t join_28bits_to_56bits(uint32_t block28b_1, uint32_t block28b_2);
uint64_t join_8bits_to_64bits(uint8_t * blocks8b);
uint32_t join_4bits_to_32bits(uint8_t * blocks8b);

static inline size_t input_string(uint8_t * buffer);
static inline void swap(uint32_t * N1, uint32_t * N2);
static inline void print_array(uint8_t * array, size_t length);
static inline void print_bits(uint64_t x, register uint64_t Nbit);

void xor_of_two_blocks_DES(uint8_t* block_1, uint8_t* block_2);

#endif   // DES_H