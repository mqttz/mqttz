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
    strcat(ret_val, ", payload: '");
    strcat(ret_val, payload);
    strcat(ret_val, "'}");
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
            printf("Key file not available!\n");
            return MQTTZ_FILE_NOT_FOUND_ERROR;
        }
        if (access(MQTTZ_CLI_IV_FILE, R_OK) != -1)
        {
            fp = fopen(MQTTZ_CLI_IV_FILE, "r");
            if ((getline(&(mqttz->cli_aes_iv), &len, fp) == -1) | (len == 0))
            {
                printf("Error reading %s file!\n", MQTTZ_CLI_KEY_FILE);
                return MQTTZ_FILE_READING_ERROR;
            }
            fclose(fp);
        }
        else
        {
            printf("Key file not available!\n");
            return MQTTZ_FILE_NOT_FOUND_ERROR;
        }
    }
    else // TODO Define Expiration for the Key? (From Server Side!)
    {
        // If files are not available, we must trigger the Key Exchange
        printf("File not found: %s!\n", MQTTZ_CLI_ID_FILE);
        // 1st: Generate a symetric key and store it.
        unsigned char key[32], iv[16];
        if (!RAND_bytes(key, sizeof(key)))
        {
            printf("OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        mqttz->cli_aes_key = (char *) key;
        fp = fopen(MQTTZ_CLI_KEY_FILE, "w");
        fputs(mqttz->cli_aes_key, fp);
        fclose(fp);
        if (!RAND_bytes(iv, sizeof(iv)))
        {
            printf("OpenSSL Error when generating key!\n");
            return MQTTZ_OPENSSL_ERROR;
        }
        mqttz->cli_aes_iv = (char *) iv;
        fp = fopen(MQTTZ_CLI_IV_FILE, "w");
        fputs(mqttz->cli_aes_iv, fp);
        fclose(fp);
        return 0;
    }
    return 0;
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
    RSA *rsa = createRSA("mqt-tz/sPubKey.pem", 1);
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
