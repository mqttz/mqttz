#include "mqt-tz_shared.h"

void test_method(char *tmp)
{
    printf("%s", tmp);
}

int mqttz_init(mqttz_config *mqttz)
{
    mqttz->cli_id = malloc((MQTTZ_CLI_ID_SIZE + 1) * sizeof(char));
    mqttz->cli_aes_key = malloc((MQTTZ_AES_KEY_SIZE + 1) * sizeof(char));
    mqttz->cli_aes_iv = malloc((MQTTZ_AES_IV_SIZE + 1) * sizeof(char));
    memset(mqttz->cli_id, '\0',
            sizeof *(mqttz->cli_id) * (MQTTZ_CLI_ID_SIZE + 1));
    memset(mqttz->cli_aes_key, '\0',
            sizeof *(mqttz->cli_aes_key) * (MQTTZ_AES_KEY_SIZE + 1));
    memset(mqttz->cli_aes_iv, '\0',
            sizeof *(mqttz->cli_aes_iv) * (MQTTZ_AES_IV_SIZE + 1));
    return MQTTZ_SUCCESS;
}

int mqttz_clean(mqttz_config *mqttz)
{
    memset(mqttz->cli_id, '\0', 
            sizeof *(mqttz->cli_id) * (MQTTZ_CLI_ID_SIZE + 1));
    memset(mqttz->cli_aes_key, '\0',
            sizeof *(mqttz->cli_aes_key) * (MQTTZ_AES_KEY_SIZE + 1));
    memset(mqttz->cli_aes_iv, '\0',
            sizeof *(mqttz->cli_aes_iv) * (MQTTZ_AES_IV_SIZE + 1));
    free(mqttz->cli_id);
    free(mqttz->cli_aes_key);
    free(mqttz->cli_aes_iv);
    return MQTTZ_SUCCESS;
}

int symmetric_encrypt(unsigned char *plain_text, int plain_text_len,
        unsigned char *key, unsigned char *iv, unsigned char *cipher_text)
{
    int cipher_text_len;
    EVP_CIPHER_CTX *ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error in symmetric_encrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        printf("Error initializing the cipher in symmetric_encrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text,
                plain_text_len))
    {
        printf("Error encrypting plain text in symmetric_encrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    cipher_text_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len))
    {
        printf("Error finalizing encrypt in symmetric_encrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    cipher_text_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return MQTTZ_SUCCESS;
}

int symmetric_decrypt(unsigned char *cipher_text, int cipher_text_len,
        unsigned char *key, unsigned char *iv, unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plain_text_len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error initializing EVP Context in symmetric_decrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        printf("Error initializing the cipher in symmetric_decrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text,
                cipher_text_len))
    {
        printf("Error decrypting cipher text in symmetric_decrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    plain_text_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len))
    {
        printf("Error finalizing decrypt in symmetric_decrypt!\n");
        return MQTTZ_OPENSSL_ERROR;
    }
    plain_text_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plain_text[plain_text_len] = '\0'; // FIXME why am I doing this?
    return MQTTZ_SUCCESS;
}

int wrap_payload(mqttz_config *mqttz, char *ret_val, char *load, int mode)
{
    strcpy(ret_val, "{client_id: ");
    strcat(ret_val, mqttz->cli_id);
    // Encrypt Payload According to the mode
    unsigned char enc_text[MQTTZ_MAX_MSG_SIZE];
    unsigned char dec_text[MQTTZ_MAX_MSG_SIZE];
    int dec_len, enc_len;
    switch(mode)
    {
        case MQTTZ_RSA:
            return MQTTZ_SUCCESS;
        case MQTTZ_AES:
            mqttz->cli_aes_iv = (char *) malloc((MQTTZ_AES_IV_SIZE + 1)
                    * sizeof(char));
            if (!RAND_bytes((unsigned char *) mqttz->cli_aes_iv,
                        MQTTZ_AES_IV_SIZE))
            {
                printf("MQT-TZ: OpenSSL Error when generating IV!\n");
                return MQTTZ_OPENSSL_ERROR;
            }
            mqttz->cli_aes_iv[MQTTZ_AES_IV_SIZE] = '\0'; 
            printf("MQT-TZ: Generated client's Initial Vector!\n");
            if (symmetric_encrypt((unsigned char *) load, strlen(load), 
                    (unsigned char *) mqttz->cli_aes_key, 
                    (unsigned char *) mqttz->cli_aes_iv, enc_text) != MQTTZ_SUCCESS)
            {
                printf("MQT-TZ: Error with AES Encrypt!\n");
                return MQTTZ_OPENSSL_ERROR;
            }
            break;
        default:
            printf("ERROR: Incorrect mode in wrap_payload. Mode: %i\n", mode);
            return MQTTZ_BAD_PARAMETERS_ERROR;
    }
    strcat(ret_val, ", iv: ");
    strcat(ret_val, mqttz->cli_aes_iv);
    strcat(ret_val, ", payload: ");
    strcat(ret_val, enc_text);
    strcat(ret_val, "}");
    return MQTTZ_SUCCESS;
}

int unwrap_payload(mqttz_config *mqttz, char *msg, char *payload, int mode)
{   
    char tmp[] = "{client_id: ";
    char tmp2[] = ", iv: ";
    char tmp3[] = ", payload: ";
    char *pch = strstr(msg, tmp);
    char *pch2 = strstr(msg, tmp2);
    char *pch3 = strstr(msg, tmp3);
    if (pch == NULL)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD_ERROR;
    }
    if (pch2 == NULL)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD_ERROR;
    }
    if (pch3 == NULL)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD_ERROR;
    }
    if ((pch2 - (pch + strlen(tmp))) != MQTTZ_CLI_ID_SIZE)
    {
        printf("MQT-TZ: Badly formatted Client ID in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD_ERROR;
    }
    if (strcmp(mqttz->cli_id, "?") == 0)
    {
        // Will this happen here? TODO
        // mqttz->cli_id = (char *)malloc((MQTTZ_CLI_ID_SIZE + 1) * sizeof(char));
        // strncpy(cli_id, pch + strlen(tmp), MQTTZ_CLI_ID_SIZE);
        // mqttz->cli_id[MQTTZ_CLI_ID_SIZE] = '\0';
        return MQTTZ_SUCCESS;
    }
    if ((pch3 - (pch2 + strlen(tmp2))) != MQTTZ_AES_IV_SIZE)
    {
        printf("MQT-TZ: Badly formatted IV in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD_ERROR;
    }
    mqttz->cli_aes_iv = (char *)malloc((MQTTZ_AES_IV_SIZE + 1) * sizeof(char));
    strncpy(mqttz->cli_aes_iv, pch2 + strlen(tmp2), MQTTZ_AES_IV_SIZE);
    // BIO_dump_fp(stdout, (const char *)mqttz->cli_id, strlen(mqttz->cli_id));
    mqttz->cli_aes_iv[MQTTZ_AES_IV_SIZE] = '\0';
    int enc_payload_size = strlen(msg) - ((pch3 + strlen(tmp3)) - msg) - 1;
    char enc_payload[enc_payload_size];
    // memset(enc_payload, '\0', enc_payload_size); Don't need it
    strncpy(enc_payload, pch3 + strlen(tmp3), enc_payload_size);
    switch (mode)
    {
        case MQTTZ_AES:
            if(symmetric_decrypt((unsigned char *) enc_payload,
                    enc_payload_size,
                    (unsigned char *) mqttz->cli_aes_key,
                    (unsigned char *) mqttz->cli_aes_iv,
                    (unsigned char *) payload) != MQTTZ_SUCCESS)
            {
                printf("MQT-TZ: Error in AES Decrypt!\n");
                return MQTTZ_OPENSSL_ERROR;
            }
            break;
        default:
            printf("ERROR: Incorrect mode in unwrap_payload. Mode: %i\n", mode);
            return MQTTZ_BAD_PARAMETERS_ERROR;
    }
    return MQTTZ_SUCCESS;
}

int client_init(mqttz_config *mqttz)
{
    FILE *fp;
    size_t len = 0;
    // If there is a client ID file, we can assume the Key Exchange has
    // successfully finished.
    if (access(MQTTZ_CLI_ID_FILE, R_OK) != -1)
    {
        // Load values if they are not loaded and files are available
        fp = fopen(MQTTZ_CLI_ID_FILE, "r");
        // TODO Define Cli_ID len
        if (getline(&(mqttz->cli_id), &len, fp) == -1)
        {
            printf("Error reading %s file!\n", MQTTZ_CLI_ID_FILE);
            return MQTTZ_FILE_READING_ERROR;
        }
        else
            printf("MQT-TZ: Loaded Client Id -> %s", mqttz->cli_id);
        if (strlen(mqttz->cli_id) != MQTTZ_CLI_ID_SIZE)
        {
            // FIXME Should we do this?
            // BIO_dump_fp(stdout, (const char *)mqttz->cli_id, strlen(mqttz->cli_id));
            printf("MQT-TZ: We are where we should not\n");
            mqttz->cli_id[MQTTZ_CLI_ID_SIZE] = '\0';
        }
        fclose(fp);
        if (access(MQTTZ_CLI_KEY_FILE, R_OK) != -1)
        {
            fp = fopen(MQTTZ_CLI_KEY_FILE, "r");
            if ((getline(&(mqttz->cli_aes_key), &len, fp) == -1) | (len == 0))
            {
                printf("Error reading %s file!\n", MQTTZ_CLI_KEY_FILE);
                return MQTTZ_FILE_READING_ERROR;
            }
            else
                printf("MQT-TZ: Loaded Client Key -> %s", mqttz->cli_aes_key);
            if (strlen(mqttz->cli_aes_key) != MQTTZ_AES_KEY_SIZE)
            {
                // FIXME Should we do this?
                mqttz->cli_aes_key[MQTTZ_AES_KEY_SIZE] = '\0';
            }
            fclose(fp);
        }
        else
        {
            printf("MQT-TZ: Key file not available!\n");
            return MQTTZ_FILE_NOT_FOUND_ERROR;
        }
    }
    else // TODO Define Expiration for the Key? (From Server Side!)
    {
        // If files are not available, we must trigger the Key Exchange
        printf("MQT-TZ: File not found: %s!\n", MQTTZ_CLI_ID_FILE);
        printf("MQT-TZ: Starting the key exchange protocol...\n");
        // Initially, client id is set to '?'
        mqttz->cli_id = "?";
        // 1st: Generate a symetric key and store it.
        mqttz->cli_aes_key = (char *)malloc((MQTTZ_AES_KEY_SIZE + 1) * sizeof(char));
        if (!RAND_bytes((unsigned char *) mqttz->cli_aes_key, MQTTZ_AES_KEY_SIZE))
        {
            printf("MQT-TZ: OpenSSL Error when generating Key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        mqttz->cli_aes_key[MQTTZ_AES_KEY_SIZE] = '\0'; 
        fp = fopen(MQTTZ_CLI_KEY_FILE, "w");
        fputs(mqttz->cli_aes_key, fp);
        fclose(fp);
        printf("MQT-TZ: Generated client's Symmetric Key!\n");
        // 2nd: Send to broker a RR to the `key_query` topic
        // Ugly Version: spawn a ./mosquitto_rr bash process
        // Send the following message: TODO
        // {cli_id: '?', payload: ENC(mqttz->cli_aes_key + mqttz->cli_aes_iv,
        //  sPubKey)}
        //  TODO enc my stuff with his stuff
        char ret_val[MQTTZ_MAX_MSG_SIZE];
        memset(ret_val, '\0', sizeof(ret_val));
        // Example for encrypting with AES
        wrap_payload(mqttz, ret_val, "Hello World!", MQTTZ_AES);
        char cmd[MQTTZ_MAX_MSG_SIZE];
        sprintf(cmd, "mosquitto_rr -p 1887 -t '%s' -m '%s' -e '%s'",
                MQTTZ_REQUEST_TOPIC, ret_val, MQTTZ_RESPONSE_TOPIC);
        BIO_dump_fp(stdout, (const char *)cmd, strlen(cmd));
        fp = popen(cmd, "r");
        char *tmp_response = NULL;
        len = 0;
        if ((fp == NULL) || (getline(&tmp_response, &len, fp) == -1))
        {
            printf("MQT-TZ: Error running command!\n");
        }
        pclose(fp);
        // Decrypt message which should have the following format:
        // {cli_id: <my_cli_id>, payload: ENC(OK, mqttz->cli_aes_key)}
        printf("We receive this response: %s\n", tmp_response);
        char enc_payload[MQTTZ_MAX_MSG_SIZE];
        // mqttz->cli_id = (char *)malloc((MQTTZ_CLI_ID_SIZE + 1) * sizeof(char));
        // memset(mqttz->cli_id, '\0', sizeof(MQTTZ_CLI_ID_SIZE + 1));
        memset(enc_payload, '\0', sizeof(enc_payload));
        if (unwrap_payload(mqttz, tmp_response, enc_payload,
                    MQTTZ_AES) != MQTTZ_SUCCESS)
        {
            printf("MQT-TZ: Error Decrypting the OK message in KE!\n");
            return MQTTZ_MALFORMED_PAYLOAD_ERROR;
        }
        printf("We received this: %s\n- Client ID: %s\n- Payload: %s\n",
                tmp_response, mqttz->cli_id, enc_payload);
        // TODO: decrypt payload
        if (1) // || dec_payload == "OK")
        {
            // Write client id to file
            fp = fopen(MQTTZ_CLI_ID_FILE, "w");
            fputs(mqttz->cli_id, fp);
            fclose(fp);
        }
        // Nice Version: creare a rr client and use it TODO
        return MQTTZ_SUCCESS;
    }
    return MQTTZ_SUCCESS; 
}

/*
int subscriber_init(mqttz_config *mqttz)
{
    FILE *fp;
    size_t len = 0;

    // If there is a client ID file, we can assume the Key Exchange has
    // successfully finished.
    if (access(MQTTZ_CLI_ID_FILE, R_OK) != -1)
    {
        // Load values if they are not loaded and files are available
        fp = fopen(MQTTZ_CLI_ID_FILE, "r");
        // TODO Define Cli_ID len
        if ((getline(&(mqttz->cli_id), &len, fp) == -1) | (len == MQTTZ_CLI_ID_SIZE))
        {
            printf("Error reading %s file!\n", MQTTZ_CLI_ID_FILE);
            return MQTTZ_FILE_READING_ERROR;
        }
        fclose(fp);
        if (access(MQTTZ_CLI_KEY_FILE, R_OK) != -1)
        {
            fp = fopen(MQTTZ_CLI_KEY_FILE, "r");
            if ((getline(&(mqttz->cli_aes_key), &len, fp) == -1) | (len == 0))
            {
                printf("Error reading %s file!\n", MQTTZ_CLI_KEY_FILE);
                return MQTTZ_FILE_READING_ERROR;
            }
            if (strlen(mqttz->cli_aes_key) != MQTTZ_AES_KEY_SIZE)
            {
                // FIXME Should we do this?
                printf("Current length: %li\n", strlen(mqttz->cli_aes_key));
                mqttz->cli_aes_key[MQTTZ_AES_KEY_SIZE] = '\0';
            }
            fclose(fp);
        }
        else
        {
            printf("MQT-TZ: Key file not available!\n");
            return MQTTZ_FILE_NOT_FOUND_ERROR;
        }
        if (access(MQTTZ_CLI_IV_FILE, R_OK) != -1)
        {
            fp = fopen(MQTTZ_CLI_IV_FILE, "r");
            if ((getline(&(mqttz->cli_aes_iv), &len, fp) == -1) || (len == 0))
            {
                printf("MQT-TZ: Error reading %s file!\n", MQTTZ_CLI_KEY_FILE);
                return MQTTZ_FILE_READING_ERROR;
            }
            if (strlen(mqttz->cli_aes_iv) != MQTTZ_AES_IV_SIZE)
            {
                // FIXME Should we do this?
                mqttz->cli_aes_iv[MQTTZ_AES_IV_SIZE] = '\0';
            }
            fclose(fp);
        }
        else
        {
            printf("MQT-TZ: Key file not available!\n");
            return MQTTZ_FILE_NOT_FOUND_ERROR;
        }
    }
    else // TODO Define Expiration for the Key? (From Server Side!)
    {
        // If files are not available, we must trigger the Key Exchange
        printf("MQT-TZ: File not found: %s!\n", MQTTZ_CLI_ID_FILE);
        printf("MQT-TZ: Starting the key exchange protocol...\n");
        // 1st: Generate a symetric key and iv and store it.
        unsigned char key[MQTTZ_AES_KEY_SIZE], iv[MQTTZ_AES_IV_SIZE];
        memset(key, '\0', MQTTZ_AES_KEY_SIZE);
        memset(iv, '\0', MQTTZ_AES_IV_SIZE);
        if (!RAND_bytes(key, MQTTZ_AES_KEY_SIZE))
        {
            printf("MQT-TZ: OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        // Initially, client id is set to '?'
        mqttz->cli_id = "?";
        //strcpy(mqttz->cli_id, "?");
        mqttz->cli_aes_key = (char *) key;
        printf("Size of the generated key: %li", strlen(mqttz->cli_aes_key));
        //strcpy(mqttz->cli_aes_key, (char *) key);
        fp = fopen(MQTTZ_CLI_KEY_FILE, "w");
        fputs(mqttz->cli_aes_key, fp);
        fclose(fp);
        printf("MQT-TZ: Generated client's Symmetric Key!\n");
        if (!RAND_bytes(iv, MQTTZ_AES_IV_SIZE))
        {
            printf("MQT-TZ: OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        //strcpy(mqttz->cli_aes_iv, (char *) iv);
        mqttz->cli_aes_iv = (char *) iv;
        fp = fopen(MQTTZ_CLI_IV_FILE, "w");
        fputs(mqttz->cli_aes_iv, fp);
        fclose(fp);
        printf("MQT-TZ: Generated client's Initial Vector!\n");
        // 2nd: Send to broker a RR to the `key_query` topic
        // Ugly Version: spawn a ./mosquitto_rr bash process
        // Send the following message: TODO
        // {cli_id: '?', payload: ENC(mqttz->cli_aes_key + mqttz->cli_aes_iv,
        //  sPubKey)}
        //  TODO enc my stuff with his stuff
        char ret_val[MQTTZ_MAX_MSG_SIZE];
        memset(ret_val, '\0', sizeof(ret_val));
        // Example for encrypting with AES
        wrap_payload(mqttz, ret_val, "Hello World!", MQTTZ_AES);
        // BIO_dump_fp(stdout, (const char *)ret_val, strlen(ret_val));
        // char *msg = format_payload('?', enc_key)
        // char *cmd = (char*)malloc(4098 * sizeof(char)); //FIXME
        char cmd[MQTTZ_MAX_MSG_SIZE];
        sprintf(cmd, "mosquitto_rr -p 1887 -t '%s' -m '%s' -e '%s'",
                MQTTZ_REQUEST_TOPIC, ret_val, MQTTZ_RESPONSE_TOPIC);
        BIO_dump_fp(stdout, (const char *)cmd, strlen(cmd));
        fp = popen(cmd, "r");
        char *tmp_response = NULL;
        len = 0;
        if ((fp == NULL) || (getline(&tmp_response, &len, fp) == -1))
        {
            printf("MQT-TZ: Error running command!\n");
        }
        pclose(fp);
        // Decrypt message which should have the following format:
        // {cli_id: <my_cli_id>, payload: ENC(OK, mqttz->cli_aes_key)}
        printf("We receive this response: %s\n", tmp_response);
        char enc_payload[MQTTZ_MAX_MSG_SIZE];
        mqttz->cli_id = (char *)malloc((MQTTZ_CLI_ID_SIZE + 1) * sizeof(char));
        memset(mqttz->cli_id, '\0', sizeof(MQTTZ_CLI_ID_SIZE + 1));
        memset(enc_payload, '\0', sizeof(enc_payload));
        if (unwrap_payload(mqttz, tmp_response, enc_payload,
                    MQTTZ_AES) != MQTTZ_SUCCESS)
        {
            printf("MQT-TZ: Error Decrypting the OK message in KE!\n");
            return MQTTZ_MALFORMED_PAYLOAD_ERROR;
        }
        printf("We received this: %s\n- Client ID: %s\n- Payload: %s\n",
                tmp_response, mqttz->cli_id, enc_payload);
        // TODO: decrypt payload
        // if (dec_payload == "OK")
        // {
            // Write client id to file
            // fp = fopen(MQTTZ_CLI_ID_FILE, "w");
            // fputs(mqttz->cli_id, fp);
            // fclose(fp);
        // }
        // Nice Version: creare a rr client and use it TODO
        return MQTTZ_SUCCESS;
    }
    return MQTTZ_SUCCESS; //wahapen with this FIXME
}
*/

RSA *createRSA(char *filename, int public)
{
    FILE *fp = fopen(filename, "rb");

    if (fp == NULL)
    {
        printf("Unable to open file %s \n", filename);
        return NULL;
    }
    RSA *rsa = RSA_new();

    if (public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }
    return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *encrypted)
{
    RSA *rsa = createRSA(MQTTZ_BRK_PKEY_FILE, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa,
            MQTTZ_RSA_PADDING);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, 
        unsigned char *decrypted)
{
    RSA *rsa = createRSA("mqt-tz/privkey.pem", 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa,
            MQTTZ_RSA_PADDING);
    if (result == -1)
    {
        char *err;
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        printf("Error decrypting message: %s\n", err);
    }
    return result;
}
