## How to launch

To get results for AES_error distributon:
```
cd ./API_ERROR
gcc api_error.c AES/aes_test_error.c AES/aes.c -o api_aes -lm
./api_aes
```

To get results for DES_error distributon:
```
cd ./API_ERROR
gcc api_error.c DES/des_test_error.c DES/des.c -o des_aes -lm
./des_aes
```

After that, you get graphics fot AES-1, AES-2, AES-3 or DES