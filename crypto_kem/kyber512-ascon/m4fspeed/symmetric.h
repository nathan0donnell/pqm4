#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "ascon.h"
#include "params.h"
#include <stddef.h>

void kyber_ascon_absorb(ascon_state_t *s, const unsigned char *input, unsigned char x, unsigned char y);
void kyber_ascon_squeezeblocks(ascon_state_t *s, unsigned char *output, size_t nblocks);
void kyber_ascon_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

void ascon_prf(unsigned char *output, size_t outlen, const unsigned char *key, unsigned char nonce); 
void ascon_hash_a(unsigned char *out, const unsigned char *in, unsigned long long inlen);
void ascon_hash_b(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen);


#define hash_ascon_a(OUT, IN, INBYTES) ascon_hash_a(OUT, IN, INBYTES) 
#define hash_ascon_b(OUT, OUTLEN,IN, INBYTES) ascon_hash_b(OUT,OUTLEN, IN, INBYTES) 
#define xof_absorb(STATE, IN, X, Y) kyber_ascon_absorb(STATE, IN, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) kyber_ascon_squeezeblocks(STATE,OUT, OUTBLOCKS)
#define prf(OUT, OUTBYTES, KEY, NONCE) ascon_prf(OUT, OUTBYTES, KEY, NONCE) 
#define kdf(OUT, IN, INBYTES) ascon_hash_b(OUT, KYBER_SSBYTES, IN, INBYTES)
#define rkprf(OUT, KEY, INPUT) kyber_ascon_rkprf(OUT, KEY, INPUT)

#define XOF_BLOCKBYTES 168

typedef ascon_state_t xof_state;

#endif /* SYMMETRIC_H */
