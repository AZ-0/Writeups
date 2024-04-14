#include <stdlib.h>
#include <stdio.h>
#include "wb-aes.h"

typedef struct {
    uint8_t state[16];
    WB_AES_KEY *key;
} AES_STATE;

static void
xtime(uint8_t *out, const uint8_t *in)
{
    const unsigned char t[2] = {0, 0x1B};
    *out = ((*in) << 1) ^ t[(*in) >> 7];
}

static void
wb_aes_enc_initiate_key(WB_AES_KEY *key, const WB_AES_KEY *_key)
{
    key->size = _key->size;
    key->key = _key->key;
}

static void
wb_aes_enc_add_round_key(AES_STATE *state, const WB_AES_KEY *key, const unsigned char i)
{
    // empty function
    (void) state;
    (void) key;
    (void) i;
}

static void
wb_aes_enc_sub_bytes(AES_STATE *state)
{
    for (unsigned char i = 0; i < 16 ; i++) {
        uint8_t byte = state->state[i];
        fseek(state->key->key, byte, SEEK_CUR);
        fread(state->state+i, 1, 1, state->key->key);
        fseek(state->key->key, 255-byte, SEEK_CUR);
    }
}

static void
wb_aes_enc_shift_rows(AES_STATE *state)
{
    uint8_t tmp;

    tmp = state->state[1];
    state->state[1]  = state->state[5];
    state->state[5]  = state->state[9];
    state->state[9]  = state->state[13];
    state->state[13] = tmp;

    tmp = state->state[2];
    state->state[ 2] = state->state[10];
    state->state[10] = tmp;
    tmp = state->state[6];
    state->state[ 6] = state->state[14];
    state->state[14] = tmp;

    tmp = state->state[3];
    state->state[ 3] = state->state[15];
    state->state[15] = state->state[11];
    state->state[11] = state->state[7];
    state->state[ 7] = tmp;
}

static void
wb_aes_enc_mix_columns(AES_STATE *state)
{
    uint8_t elt0;
    uint8_t elt1;
    uint8_t elt2;
    uint8_t elt3;

    for (unsigned int i = 0; i < 4; i++) {
        elt0  = state->state[(i << 2) + 0];
        elt1  = state->state[(i << 2) + 1];
        elt2  = state->state[(i << 2) + 2];
        elt3  = state->state[(i << 2) + 3];
        elt0 ^= state->state[(i << 2) + 1];
        elt1 ^= state->state[(i << 2) + 2];
        elt2 ^= state->state[(i << 2) + 3];
        elt3 ^= state->state[(i << 2) + 0];
        state->state[(i << 2) + 2] ^= elt0;
        state->state[(i << 2) + 3] ^= elt1;
        state->state[(i << 2) + 0] ^= elt2;
        state->state[(i << 2) + 1] ^= elt3;
        xtime(&elt0, &elt0);
        xtime(&elt1, &elt1);
        xtime(&elt2, &elt2);
        xtime(&elt3, &elt3);
        elt1 ^= state->state[(i << 2) + 0];
        elt2 ^= state->state[(i << 2) + 1];
        elt3 ^= state->state[(i << 2) + 2];
        elt0 ^= state->state[(i << 2) + 3];
        state->state[(i << 2) + 0] = elt0;
        state->state[(i << 2) + 1] = elt1;
        state->state[(i << 2) + 2] = elt2;
        state->state[(i << 2) + 3] = elt3;
    }
}

static void
wb_aes_initiate_state(AES_STATE *state, const unsigned char *block, WB_AES_KEY *key)
{
    state->key = key;
    for (unsigned int i = 0; i < 16 ; i++) {
        state->state[i] = block[i];
    }
}

static void
wb_aes_deinitiate_state(unsigned char *block, const AES_STATE *state)
{
    for (unsigned int i = 0; i < 16; i++) {
        block[i] = state->state[i];
    }
}

unsigned char
wb_aes_encrypt(unsigned char *out, const unsigned char *in, const WB_AES_KEY *_key)
{
	AES_STATE state[1];
	WB_AES_KEY key[1];
	unsigned int rounds;

	wb_aes_enc_initiate_key(key, _key);

	if     (key->size == 16) rounds = 10;
    else if(key->size == 24) rounds = 12;
	else if(key->size == 32) rounds = 14;
    else {
        fprintf(stderr, "Error: Wrong key size.\n");
        exit(EXIT_FAILURE);
    }

	wb_aes_initiate_state(state, in, key);
	wb_aes_enc_add_round_key(state, key, 0);
	for (unsigned int i = 1; i < rounds; i++) {
		wb_aes_enc_sub_bytes(state);
		wb_aes_enc_shift_rows(state);
		wb_aes_enc_mix_columns(state);
		wb_aes_enc_add_round_key(state, key, i);
	}
	wb_aes_enc_sub_bytes(state);
	wb_aes_enc_shift_rows(state);
	wb_aes_enc_add_round_key(state, key, rounds);

    wb_aes_deinitiate_state(out, state);

	return EXIT_SUCCESS;
}
