#include "stack.h"

void poly_challenge_compress(uint8_t c[68], const poly *cp){
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

void poly_challenge_decompress(poly *cp, const uint8_t c[68]){
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


// TODO: buffer at most 8 coeffs at once
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

void poly_schoolbook(poly *c, const uint8_t ccomp[68], const uint8_t *t0){
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
        }
        for(j = N-i; j<N; j++){
            c->coeffs[i+j-N] -= polyt0_unpack_idx(t0, j);
        }
    } else {
        for(j = 0; i+j < N; j++){
            c->coeffs[i+j] -= polyt0_unpack_idx(t0, j);
        }
        for(j = N-i; j<N; j++){
            c->coeffs[i+j-N] += polyt0_unpack_idx(t0, j);
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

void polyw_pack(uint8_t buf[3*256], poly *w){
  poly_reduce(w);
  poly_caddq(w);
  unsigned int i;
  for(i = 0; i < N; i++){
    buf[i*3 + 0] = w->coeffs[i];
    buf[i*3 + 1] = w->coeffs[i] >> 8;
    buf[i*3 + 2] = w->coeffs[i] >> 16;
  }
}

void polyw_unpack(poly *w, const uint8_t buf[3*256]) {
  unsigned int i;
  for(i = 0; i < N; i++){
    w->coeffs[i] =  buf[i*3 + 0];
    w->coeffs[i] |= (int32_t)buf[i*3 + 1] << 8;
    w->coeffs[i] |= (int32_t)buf[i*3 + 2] << 16;
  }
}

void polyw_add(uint8_t buf[3*256], poly *p){
  unsigned int i;
  int32_t coeff;
  for(i = 0; i < N; i++){
    coeff =  buf[i*3 + 0];
    coeff |= (int32_t)buf[i*3 + 1] << 8;
    coeff |= (int32_t)buf[i*3 + 2] << 16;

    coeff += p->coeffs[i];


    // // TODO: constant-time reduction here
    coeff %= Q;
    if(coeff < 0){
        coeff += Q;
    }

    buf[i*3 + 0] = coeff;
    buf[i*3 + 1] = coeff >> 8;
    buf[i*3 + 2] = coeff >> 16;
  }
}

static int32_t decompose_w1(int32_t a){
  int32_t a1;

  a1  = (a + 127) >> 7;
#if GAMMA2 == (Q-1)/32
  a1  = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif GAMMA2 == (Q-1)/88
  a1  = (a1*11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif

  return a1;
}

void poly_decompose_w1(poly *a1, const poly *a) {
  unsigned int i;

  for(i = 0; i < N; ++i)
    a1->coeffs[i] = decompose_w1(a->coeffs[i]);
}
