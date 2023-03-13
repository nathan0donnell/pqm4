#ifndef STACK_H
#define STACK_H

#include "poly.h"
#include "smallpoly.h"
#include <stdint.h>

void poly_challenge_compress(uint8_t c[68], poly *cp);
void poly_challenge_decompress(poly *cp, uint8_t c[68]);


void poly_schoolbook(poly *c, uint8_t ccomp[68], const uint8_t *t0);

// TODO: replace this with individual functions later
void unpack_sk_stack(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               smallpoly s1[L],
               smallpoly s2[K],
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);
#endif