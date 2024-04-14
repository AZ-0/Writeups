#ifndef _WB_AES_
#define _WB_AES_

#include <stdint.h>
#include <stdio.h>

typedef struct {
    FILE* key;
    unsigned char size;
} WB_AES_KEY;

unsigned char wb_aes_encrypt(unsigned char *out, const unsigned char *in, const WB_AES_KEY *_key);

#endif
