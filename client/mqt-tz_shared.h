#ifndef MQT-TZ_SHARED_H
#define MQT-TZ_SHARED_H

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#define MAX_SIZE        120
#define RSA_PADDING     RSA_PKCS1_PADDING

void test_method(char *tmp);
char* format_payload(char *ret_val, char *cli_id, void *payload);
int private_decrypt(unsigned char *enc_data, int data_len, 
        unsigned char *decrypted);
int public_encrypt(unsigned char *data, int data_len, 
        unsigned char *encrypted);

#endif
