#ifndef SYMMETRIC_H
#define SYMMETRIC_H
#include "params.h"
#include "ascon.h"
#include <stddef.h>
#include <stdint.h>

typedef ascon_state_t xof_state;

void kyber_ascon_absorb(xof_state *s,
                                                     const uint8_t seed[KYBER_SYMBYTES],
                                                     uint8_t x,
                                                     uint8_t y);

void kyber_ascon_prf(uint8_t *out,
                                                  size_t outlen,
                                                  const uint8_t key[KYBER_SYMBYTES],
                                                  uint8_t nonce);
void kyber_ascon_rkprf(uint8_t out[KYBER_SSBYTES],
                                                    const uint8_t key[KYBER_SYMBYTES],
                                                    const uint8_t input[KYBER_CIPHERTEXTBYTES]);
void ascon_hash_h(unsigned char *out,
                                               const unsigned char *in,
                                               unsigned long long inlen);
void ascon_hash_g(unsigned char *out,
                                               const unsigned char *in,
                                               unsigned long long inlen);
void ascon_hash_b(unsigned char *out,
                                               size_t outlen,
                                               const unsigned char *in,
                                               unsigned long long inlen);

#define XOF_BLOCKBYTES 8
#define hash_ascon_h(OUT, IN, INBYTES) ascon_hash_h(OUT, IN, INBYTES)
#define hash_ascon_g(OUT, IN, INBYTES) ascon_hash_g(OUT, IN, INBYTES)
#define hash_ascon_b(OUT, OUTLEN, IN, INBYTES) ascon_hash_b(OUT, OUTLEN, IN, INBYTES)
#define xof_absorb(STATE, IN, X, Y) kyber_ascon_absorb(STATE, IN, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) ascon_squeeze(STATE, OUT, OUTBLOCKS)
#define xof_ctx_release(STATE) (void)STATE
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_ascon_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_ascon_rkprf(OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */
