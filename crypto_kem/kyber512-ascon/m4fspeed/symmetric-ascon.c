#include "symmetric.h"

#include <stdlib.h>

/*************************************************
 * Name:        kyber_ascon_absorb
 *
 * Description: Absorb step of ASCON specialized for the Kyber context.
 *
 * Arguments:   - ascon_state_t *s:                     pointer to (uninitialized) output ASCON state
 *              - const uint64_t *input:      pointer to KYBER_SYMBYTES input to be absorbed into s
 *              - unsigned char x                  additional byte of input
 *              - unsigned char y                  additional byte of input
 **************************************************/
void kyber_ascon_absorb(ascon_state_t *s, const unsigned char *input, unsigned char x, unsigned char y)
{
    unsigned char extseed[KYBER_SYMBYTES + 2];
    int i;

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extseed[i] = input[i];
    }
    extseed[i++] = x;
    extseed[i]   = y;
    ascon_absorb(s, extseed, KYBER_SYMBYTES + 2);
}

/*************************************************
 * Name:        kyber_ascon_squeezeblocks
 *
 * Description: Squeeze step of ascon XOF. Squeezes full blocks of ascon_RATE bytes each.
 *              Modifies the state. Can be called multiple times to keep squeezing,
 *              i.e., is incremental.
 *
 * Arguments:   - ascon_state_t *output:      pointer to output blocks
 *              - size_t nblocks:             number of blocks to be squeezed (written to output)
 *              - asconctx *s:                pointer to in/output ASCON state
 **************************************************/
void kyber_ascon_squeezeblocks(ascon_state_t *s, unsigned char *output, size_t nblocks)
{
    ascon_squeeze(s, output, nblocks);
}


/*************************************************
 * Name:        ascon_prf
 *
 * Description: Usage of ASCON as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of ASCON output
 *
 * Arguments:   - unsigned char *output:      pointer to output
 *              - size_t outlen:              number of requested output bytes
 *              - const unsigned char * key:  pointer to the key (of length KYBER_SYMBYTES)
 *              - const unsigned char nonce:  single-byte nonce (public PRF input)
 **************************************************/

void ascon_prf(unsigned char *output, size_t outlen, const unsigned char *key, unsigned char nonce) {
    unsigned char extkey[KYBER_SYMBYTES + 1];
    size_t i;

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extkey[i] = key[i];
    }
    extkey[i] = nonce;

    ascon_hash_b(output, outlen, extkey, KYBER_SYMBYTES + 1);
}

/*************************************************
 * Name:        ascon_hash_a
 *
 * Description: Usage of ASCON to hash an input
 *
 *
 * Arguments:   - unsigned char *out:           pointer to output
 *              - const unsigned char *in:      pointer to input
 *              - unsigned long long inlen:     length of input
 **************************************************/

void ascon_hash_a(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    ascon_state_t s;
    ascon_inithash(&s);
    ascon_absorb(&s, in, inlen);
    ascon_squeeze(&s, out, ASCON_CRYPTO_BYTES);
}

/*************************************************
 * Name:        ascon_hash_b
 *
 * Description: Usage of ASCON to hash an input
 *
 *
 * Arguments:   - unsigned char *out:           pointer to output
 *              - const unsigned char *in:      pointer to input
 *              - size_t outlen:                number of requested output bytes
 *              - unsigned long long inlen:     length of input
 **************************************************/
void ascon_hash_b(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen)
{
    ascon_state_t s;
    ascon_inithash(&s);
    ascon_absorb(&s, in, inlen);
    ascon_squeeze(&s, out, outlen);
}

/*************************************************
 * Name:        kyber_ascon_rkprf
 *
 * Description: Usage of ascon as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of ascon output, used for computing
 *              rejection key
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
 *              - uint8_t input: single-byte nonce (public PRF input)
 **************************************************/
void kyber_ascon_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES])
{
    ascon_state_t s;
    ascon_inithash(&s);
    ascon_absorb(&s, key, KYBER_SYMBYTES);
    ascon_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
    ascon_squeeze(&s, out, KYBER_SSBYTES);
}
