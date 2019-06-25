#ifndef MQTTZ_SHARED_H
#define MQTTZ_SHARED_H

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MQTTZ_CLI_ID_FILE       "cli_id.txt"
#define MQTTZ_CLI_IV_FILE       "cli_aes_iv.txt"
#define MQTTZ_CLI_KEY_FILE      "cli_aes_key.txt"
#define MQTTZ_BRK_PKEY_FILE     "sPubKey.pem"
#define MQTTZ_MAX_MSG_SIZE      120
#define MQTTZ_RSA_PADDING       RSA_PKCS1_PADDING

#define MQTTZ_FILE_NOT_FOUND_ERROR      1
#define MQTTZ_FILE_READING_ERROR        2
#define MQTTZ_OPENSSL_ERROR             3

typedef struct mqttz_config {
    char *cli_id;
    char *cli_aes_key;
    char *cli_aes_iv;
} mqttz_config;

void test_method(char *tmp);
char* format_payload(char *ret_val, char *cli_id, void *payload);
int key_exchange(mqttz_config *mqttz);
int private_decrypt(unsigned char *enc_data, int data_len, 
        unsigned char *decrypted);
int public_encrypt(unsigned char *data, int data_len, 
        unsigned char *encrypted);

#endif
