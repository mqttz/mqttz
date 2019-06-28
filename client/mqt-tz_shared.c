#include "mqt-tz_shared.h"

void test_method(char *tmp)
{
    printf("%s", tmp);
}

char *format_payload(char *ret_val, char *cli_id, void *load)
{
    char *payload;
    payload = (char *) load;
    strcpy(ret_val, "{client_id: ");
    strcat(ret_val, cli_id);
    strcat(ret_val, ", payload: ");
    strcat(ret_val, payload);
    strcat(ret_val, "}");
    unsigned char tmp[4096];
    unsigned char tmp2[4096];
    int res = public_encrypt((unsigned char *) ret_val, sizeof(ret_val), tmp);
    if (res == -1)
    {
        printf("Public encrypt failed!\n");
    }
    else
    {
        printf("Public encrypt succeded!\n");
        //printf("%s\n", tmp);
    }
    int res2 = private_decrypt(tmp, sizeof(tmp), tmp2); 
    if (res2 == -1)
    {
        printf("Private decrypt failed!\n");
    }
    else
    {
        printf("%s\n", tmp2);
    }
    return ret_val;
}

int unwrap_payload(char *msg, char *cli_id, char *payload)
{   
    char tmp[] = "{client_id: ";
    char tmp2[] = ", payload: ";
    char *pch = strstr(msg, tmp);
    char *pch2 = strstr(msg, tmp2);
    if (pch == NULL)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD;
    }
    if (pch2 == NULL)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD;
    }
    if ((pch2 - (pch + strlen(tmp))) != MQTTZ_CLI_ID_SIZE)
    {
        printf("MQT-TZ: Badly formatted Payload in KE!\n");
        return MQTTZ_MALFORMED_PAYLOAD;
    }
    strncpy(cli_id, pch + strlen(tmp), MQTTZ_CLI_ID_SIZE);
    int payload_size = strlen(msg) - ((pch2 + strlen(tmp2)) - msg) - 2;
    printf("Payload size: %i\n", payload_size);
    strncpy(payload, pch2 + strlen(tmp2), payload_size);
    return MQTTZ_SUCCESS;
}

int key_exchange(mqttz_config *mqttz)
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
        if ((getline(&(mqttz->cli_id), &len, fp) == -1) | (len == 0))
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
        unsigned char key[32], iv[16];
        memset(key, '\0', sizeof(key));
        memset(iv, '\0', sizeof(iv));
        if (!RAND_bytes(key, sizeof(key)))
        {
            printf("MQT-TZ: OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        mqttz->cli_aes_key = (char *) key;
        fp = fopen(MQTTZ_CLI_KEY_FILE, "w");
        fputs(mqttz->cli_aes_key, fp);
        fclose(fp);
        printf("MQT-TZ: Generated client's Symmetric Key!\n");
        if (!RAND_bytes(iv, sizeof(iv)))
        {
            printf("MQT-TZ: OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
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
        // char *msg = format_payload('?', enc_key)
        char *cmd = (char*)malloc(4098 * sizeof(char)); //FIXME
        sprintf(cmd, "mosquitto_rr -p 1887 -t '%s' -m '%s' -e '%s'",
                MQTTZ_REQUEST_TOPIC, "hello", MQTTZ_RESPONSE_TOPIC);
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
        char enc_payload[MQTTZ_MAX_MSG_SIZE];
        mqttz->cli_id = malloc(MQTTZ_CLI_ID_SIZE * sizeof(char));
        memset(mqttz->cli_id, '\0', MQTTZ_CLI_ID_SIZE);
        memset(enc_payload, '\0', sizeof(enc_payload));
        if (unwrap_payload(tmp_response, mqttz->cli_id, 
            enc_payload) != MQTTZ_SUCCESS)
        {
            return MQTTZ_MALFORMED_PAYLOAD;
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
    return 0; //wahapen with this FIXME
}

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
