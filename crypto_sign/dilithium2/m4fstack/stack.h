#ifndef STACK_H
#define STACK_H

#include "poly.h"
#include "smallpoly.h"
#include <stdint.h>
#include <stddef.h>

void poly_challenge_compress(uint8_t c[68], const poly *cp);
void poly_challenge_decompress(poly *cp, const uint8_t c[68]);


void poly_schoolbook(poly *c, const uint8_t ccomp[68], const uint8_t *t0);

// TODO: replace this with individual functions later
void unpack_sk_stack(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

void polyw_pack(uint8_t buf[3*256], poly *w);
void polyw_unpack(poly *w, const uint8_t buf[3*256]);

void polyw_add(uint8_t buf[3*256], poly *p);

void poly_decompose_w1(poly *a1, const poly *a);


void unpack_sk_s1(smallpoly *a, uint8_t *sk, size_t idx);
void unpack_sk_s2(smallpoly *a, uint8_t *sk, size_t idx);


void poly_uniform_pointwise_montgomery_polywadd_stack(uint8_t wcomp[3*N], poly *b, uint8_t  seed[SEEDBYTES], uint16_t nonce);
#endif