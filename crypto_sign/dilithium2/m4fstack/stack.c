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


static inline int32_t polyt0_unpack_idx(const uint8_t *t0, unsigned idx){
    int32_t coeff;
    // 8 coefficients are packed in 13 bytes
    t0 += 13*(idx >> 3);

    if(idx % 8 == 0){
        coeff  = t0[0];
        coeff |= (uint32_t)t0[1] << 8;
    } else if(idx % 8 == 1){
        coeff  = t0[1] >> 5;
        coeff |= (uint32_t)t0[2] << 3;
        coeff |= (uint32_t)t0[3] << 11;
    } else if(idx % 8 == 2){
        coeff  = t0[3] >> 2;
        coeff |= (uint32_t)t0[4] << 6;
    } else if(idx % 8 == 3){
        coeff  = t0[4] >> 7;
        coeff |= (uint32_t)t0[5] << 1;
        coeff |= (uint32_t)t0[6] << 9;
    } else if(idx % 8 == 4){
        coeff  = t0[6] >> 4;
        coeff |= (uint32_t)t0[7] << 4;
        coeff |= (uint32_t)t0[8] << 12;
    } else if(idx % 8 == 5){
        coeff  = t0[8] >> 1;
        coeff |= (uint32_t)t0[9] << 7;
    } else if(idx % 8 == 6){
        coeff  = t0[9] >> 6;
        coeff |= (uint32_t)t0[10] << 2;
        coeff |= (uint32_t)t0[11] << 10;
    } else if(idx % 8 == 7){
        coeff  = t0[11] >> 3;
        coeff |= (uint32_t)t0[12] << 5;
    }
    coeff &= 0x1FFF;
    return (1 << (D-1)) - coeff;
}

void poly_schoolbook(poly *c, uint8_t ccomp[68], const uint8_t *t0){
  unsigned i,j,idx;
  uint64_t signs = 0;
  for(i = 0; i < N; i++) c->coeffs[i] = 0;
  for(i = 0; i < 8; i++) {
    signs |= ((uint64_t)ccomp[64+i]) << (8*i);
  }

  for(idx = 0; idx < TAU; idx++){
    i = ccomp[idx];
    if(!(signs & 1)){
        for(j = 0; i+j < N; j++){
            c->coeffs[i+j] += polyt0_unpack_idx(t0, j);
            c->coeffs[i+j] %= Q;
        }
        for(j = N-i; j<N; j++){
            c->coeffs[i+j-N] -= polyt0_unpack_idx(t0, j);
            c->coeffs[i+j-N]  %= Q;
        }
    } else {
        for(j = 0; i+j < N; j++){
            c->coeffs[i+j] -= polyt0_unpack_idx(t0, j);
            c->coeffs[i+j] %= Q;
        }
        for(j = N-i; j<N; j++){
            c->coeffs[i+j-N] += polyt0_unpack_idx(t0, j);
            c->coeffs[i+j-N]  %= Q;
        }
    }

    signs >>= 1;
  }
}


// TODO: remove this later
void unpack_sk_stack(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               smallpoly s1[L],
               smallpoly s2[K],
               const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += SEEDBYTES;

  for(i = 0; i < SEEDBYTES; ++i)
    tr[i] = sk[i];
  sk += SEEDBYTES;

  for(i=0; i < L; ++i)
    small_polyeta_unpack(&s1[i], sk + i*POLYETA_PACKEDBYTES);
  sk += L*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    small_polyeta_unpack(&s2[i], sk + i*POLYETA_PACKEDBYTES);
  sk += K*POLYETA_PACKEDBYTES;
}