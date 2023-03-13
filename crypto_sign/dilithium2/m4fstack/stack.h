#ifndef STACK_H
#define STACK_H

#include "poly.h"
#include <stdint.h>

void poly_challenge_compress(uint8_t c[68], poly *cp);
void poly_challenge_decompress(poly *cp, uint8_t c[68]);
#endif