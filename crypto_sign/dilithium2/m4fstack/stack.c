#include "stack.h"

void poly_challenge_compress(uint8_t c[68], poly *cp){
  unsigned int i, pos;
  uint64_t signs;
  uint64_t mask;
  /* Encode c */
  for(i=0;i<68;i++) c[i] = 0;
  signs = 0;
  mask = 1;
  pos = 0;
  for(i = 0; i < N; ++i){
    if(cp->coeffs[i] != 0){
      c[pos++] = i;
      if(cp->coeffs[i] == -1){
        signs |= mask;
      }
      mask <<= 1;
    }
  }

  for (i = 0; i < 8; ++i) {
    c[64+i] = (unsigned char) (signs >> 8 * i);
  }
}

void poly_challenge_decompress(poly *cp, uint8_t c[68]){
  unsigned int i;
  unsigned pos;
  uint64_t signs = 0;
  for(i = 0; i < N; i++) cp->coeffs[i] = 0;
  for(i = 0; i < 8; i++) {
    signs |= ((uint64_t)c[64+i]) << (8*i);
  }

  for(i = 0; i < TAU; i++){
    pos = c[i];
    if(signs & 1){
      cp->coeffs[pos] = -1;
    } else {
      cp->coeffs[pos] = 1;
    }
    signs >>= 1;
  }
}