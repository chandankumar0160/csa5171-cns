#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void encrypt_des(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *ciphertext) {
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key((DES_cblock *)key, &ks1);
    DES_set_key((DES_cblock *)(key + 8), &ks2);
    DES_set_key((DES_cblock *)(key + 16), &ks3);

    DES_cblock iv_block;
    memcpy(iv_block, iv, 8);

    unsigned char block[8];
    DES_ncbc_encrypt(plaintext, block, 8, &ks1, &iv_block, DES_ENCRYPT);
    DES_ncbc_encrypt(block, block, 8, &ks2, &iv_block, DES_DECRYPT);
    DES_ncbc_encrypt(block, ciphertext, 8, &ks3, &iv_block, DES_ENCRYPT);

    for (int i = 8; i < plaintext_len; i += 8) {
        memcpy(block, plaintext + i, 8);
        DES_ncbc_encrypt(block, block, 8, &ks1, &iv_block, DES_ENCRYPT);
        DES_ncbc_encrypt(block, block, 8, &ks2, &iv_block, DES_DECRYPT);
        DES_ncbc_encrypt(block, ciphertext + i, 8, &ks3, &iv_block, DES_ENCRYPT);
    }
}

int main() {
    unsigned char key[] = "123456781234567812345678";
    unsigned char iv[] = "12345678";
    unsigned char plaintext[] = "hello world";
    int plaintext_len = strlen(plaintext);
    unsigned char ciphertext[plaintext_len];

    encrypt_des(plaintext, plaintext_len, key, iv, ciphertext);

    printf("Ciphertext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
