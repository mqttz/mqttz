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
        printf("%s\n", tmp);
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
            RSA_PADDING);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, 
        unsigned char *decrypted)
{
    RSA *rsa = createRSA("mqt-tz/privkey.pem", 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa,
            RSA_PADDING);
    if (result == -1)
    {
        char *err;
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        printf("\nError encrypting message: %s\n", err);
    }
    return result;
}
