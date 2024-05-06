#include "params.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*************************************************
 * Name:        kyber_ascon_absorb
 *
 * Description: Absorb step of ASCON specialized for the Kyber context.
 *
 * Arguments:   - xof_state *state: pointer to (uninitialized) output state
 *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
 *              - uint8_t i: additional byte of input
 *              - uint8_t j: additional byte of input
 **************************************************/
void kyber_ascon_absorb(xof_state *state,
                                                     const uint8_t seed[KYBER_SYMBYTES],
                                                     uint8_t x,
                                                     uint8_t y)
{
    uint8_t extseed[KYBER_SYMBYTES + 2];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    ascon_absorb(state, extseed, sizeof(extseed));
}

/*************************************************
 * Name:        kyber_ascon_prf
 *
 * Description: Usage of ASCON as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of ASCON output
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
 *              - uint8_t nonce: single-byte nonce (public PRF input)
 **************************************************/
void kyber_ascon_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t extkey[KYBER_SYMBYTES + 1];

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    ascon_hash_b(out, outlen, extkey, KYBER_SYMBYTES + 1);
}

/*************************************************
 * Name:        ascon_hash_h
 *
 * Description: Usage of ASCON to hash an input with fixed ascon CRYPTO_BYTES
 *
 *
 * Arguments:   - unsigned char *out:           pointer to output
 *              - const unsigned char *in:      pointer to input
 *              - unsigned long long inlen:     length of input
 **************************************************/

void ascon_hash_h(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    ascon_state_t s;
    ascon_inithash(&s);
    ascon_absorb(&s, in, inlen);
    ascon_squeeze(&s, out, ASCON_CRYPTO_BYTES);
    xof_ctx_release(&s);
}

/*************************************************
 * Name:         _ascon_hash_g
 *
 * Description: Usage of ASCON to hash an input with fixed ascon CRYPTO_BYTES
 *
 *
 * Arguments:   - unsigned char *out:           pointer to output
 *              - const unsigned char *in:      pointer to input
 *              - unsigned long long inlen:     length of input
 **************************************************/

void ascon_hash_g(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    ascon_state_t s;
    ascon_inithash(&s);
    ascon_absorb(&s, in, inlen);
    ascon_squeeze(&s, out, ASCON_CRYPTO_BYTES);
    xof_ctx_release(&s);
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
    xof_ctx_release(&s);
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
    xof_ctx_release(&s);
}
