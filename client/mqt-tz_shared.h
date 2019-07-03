#ifndef MQTTZ_SHARED_H
#define MQTTZ_SHARED_H

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MQTTZ_CLI_ID_FILE       "mqt-tz/cli_id.txt"
#define MQTTZ_CLI_IV_FILE       "mqt-tz/cli_aes_iv.txt"
#define MQTTZ_CLI_KEY_FILE      "mqt-tz/cli_aes_key.txt"
#define MQTTZ_BRK_PKEY_FILE     "mqt-tz/sPubKey.pem"
#define MQTTZ_MAX_MSG_SIZE      4096
#define MQTTZ_CLI_ID_SIZE       12
#define MQTTZ_RSA_PADDING       RSA_PKCS1_PADDING
#define MQTTZ_REQUEST_TOPIC     "id_query"
#define MQTTZ_RESPONSE_TOPIC    "id_response"
#define MQTTZ_AES               0
#define MQTTZ_RSA               1

#define MQTTZ_SUCCESS                   0
#define MQTTZ_FILE_NOT_FOUND_ERROR      1
#define MQTTZ_FILE_READING_ERROR        2
#define MQTTZ_OPENSSL_ERROR             3
#define MQTTZ_MALFORMED_PAYLOAD_ERROR   4
#define MQTTZ_BAD_PARAMETERS_ERROR      5

typedef struct mqttz_config {
    char *cli_id;
    char *cli_aes_key;
    char *cli_aes_iv;
} mqttz_config;

void test_method(char *tmp);
int key_exchange(mqttz_config *mqttz);
int mqttz_clean(mqttz_config *mqttz);
int mqttz_init(mqttz_config *mqttz);
int private_decrypt(unsigned char *enc_data, int data_len, 
        unsigned char *decrypted);
int public_encrypt(unsigned char *data, int data_len, 
        unsigned char *encrypted);
int symmetric_encrypt(unsigned char *plain_text, int plain_text_len,
        unsigned char *key, unsigned char *iv, unsigned char *cipher_text);
int symmetric_decrypt(unsigned char *cipher_text, int cipher_text_len,
        unsigned char *key, unsigned char *iv, unsigned char *plain_text);
int unwrap_payload(char *msg, char *cli_id, char *payload);
int wrap_payload(mqttz_config *mqttz, char *ret_val, char *payload, int mode);

#endif
