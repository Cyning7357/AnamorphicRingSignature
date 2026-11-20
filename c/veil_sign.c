/* c/veil_sign.c -- self-contained VEIL v3 ring signing and verification.
 *
 * Implements the signing and verification path of prototype/veil_core.py for
 * the REGULAR mode (veil_core.sign(embed=None)) and the ATTRIBUTABLE FPE mode
 * (veil_core.sign(embed="fpe")) at the paper's mechanics parameters:
 *
 *     d = 256, k = 3, l = 4, t = 19, tau = 39, q = 8380417,
 *     payload = 32 B + 16 B MAC (mu = 384 bits), q_rounds = 16,
 *     domain = "VEIL/v3", response = t*l*d/8 = 2432 B per ring member.
 *
 * The AOS ring, the sparse binary challenge, h_chain, int_to_box/box_to_int
 * and the balanced 16-round Feistel FPE follow the Python code.  Only the key
 * material and the per-signature randomness are derived from SHAKE-256
 * instead of NumPy's RNG: a signature produced here verifies here, and its
 * serialized size matches Python's, but it is not byte-identical to a Python
 * signature (explicitly allowed by the task).
 *
 * Hash primitives (all OpenSSL EVP, matching hashlib):
 *   * SHAKE-256 -- sparse_challenge (digest || ctr_be16 -> 64 B),
 *                  FPE round function _f (dk || round_be16 || half -> 1216 B),
 *                  deterministic randomness expansion.
 *   * SHA-256   -- h_chain, exactly as hashlib.sha256 in Python.
 *
 * The NTT and sparse multiplication kernels are the ones from
 * c/veil_kernels.c; the roots / bit-reversal tables come from c/constants.h.
 *
 * Build (Windows, mingw-w64 + OpenSSL 3):
 *   gcc -O3 -shared -static-libgcc -o "%TEMP%\veil_sign.dll" c\veil_sign.c ^
 *       -I c -L <mingw-prefix>/lib -lcrypto
 *
 * Exported C API (driven by prototype/c_sign.py through ctypes):
 *   void  *veil_ctx_new(const uint8_t *seed, size_t seed_len, int n);
 *   void   veil_ctx_free(void *ctx);
 *   size_t veil_sig_size(const void *ctx);          // 32 + n * 2432
 *   int    veil_n(const void *ctx);
 *   int    veil_sign(ctx, pi, msg, msg_len, extra, extra_len,
 *                    dk, dk_len, mu, mode, nonce, out, out_cap, out_len);
 *   int    veil_verify(ctx, msg, msg_len, extra, extra_len, sig, sig_len);
 *
 * mode: 0 = REGULAR (uniform box decoys), 1 = FPE (embed="fpe").
 * mu  : 48 bytes = 32-byte payload || 16-byte MAC, big-endian, the integer
 *       (payload << 128) | mac that Python's encode_mu() produces.
 * nonce: caller-chosen 64-bit value; every (seed, nonce) pair gives a
 *       different, deterministic signature.
 */

#if defined(_WIN32)
#  define VEIL_API __declspec(dllexport)
#else
#  define VEIL_API __attribute__((visibility("default")))
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "constants.h"   /* Q, D, PSI, BITREV, ROOTS, INV_ROOTS, INV_D, PSI_INV */

/* paper mechanics parameters (veil_core.Params defaults) */
#define K 3
#define L 4
#define TAU 39
#define TBITS 19
#define ND (L * D)                 /* 1024 box coefficients  */
#define L_BITS (TBITS * ND)        /* 19456                  */
#define RESP_BYTES (L_BITS / 8)    /* 2432                   */
#define HALF_BYTES (L_BITS / 16)   /* 1216 = L1/8 = L2/8     */
#define MU_BYTES 48                /* 32 B payload + 16 B MAC */
#define MU_BITS (MU_BYTES * 8)     /* 384                    */
#define Q_ROUNDS 16
#define BOX_H (1 << 18)            /* 2^(t-1)                */
#define BOX_M 39                   /* tau * eta              */
#define Y_LIMIT (BOX_H + BOX_M)    /* H + M: mask box superset */
#define Y_RANGE (2 * Y_LIMIT)      /* 524366 < 2^19          */
#define MAX_N 32
#define DK_MAX 64
#define C1_BYTES 32
#define DOMAIN_LEN 8
#define VEIL_DOMAIN "VEIL/v3"

/* ------------------------------------------------------------------------- */
/* SHAKE-256 / SHA-256 through OpenSSL EVP                                   */
/* ------------------------------------------------------------------------- */

static int shake256(const void *in, size_t inlen, void *out, size_t outlen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (ctx != NULL) {
        ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1;
        if (ok && inlen != 0)
            ok = EVP_DigestUpdate(ctx, in, inlen) == 1;
        if (ok)
            ok = EVP_DigestFinalXOF(ctx, (unsigned char *)out, outlen) == 1;
        EVP_MD_CTX_free(ctx);
    }
    return ok;
}

static int sha256_digest(const void *in, size_t inlen, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    int ok = 0;

    if (ctx != NULL) {
        ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
        if (ok && inlen != 0)
            ok = EVP_DigestUpdate(ctx, in, inlen) == 1;
        if (ok)
            ok = EVP_DigestFinal_ex(ctx, out, &len) == 1 && len == 32;
        EVP_MD_CTX_free(ctx);
    }
    return ok;
}

/* HMAC-SHA256 built from EVP only; the HMAC() symbol is blocked here.        */
static int sha256_two(const uint8_t *a, size_t alen,
                      const uint8_t *b, size_t blen, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    int ok = 0;

    if (ctx != NULL) {
        ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
        if (ok && alen != 0)
            ok = EVP_DigestUpdate(ctx, a, alen) == 1;
        if (ok && blen != 0)
            ok = EVP_DigestUpdate(ctx, b, blen) == 1;
        if (ok)
            ok = EVP_DigestFinal_ex(ctx, out, &len) == 1 && len == 32;
        EVP_MD_CTX_free(ctx);
    }
    return ok;
}

static int hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[32];

    memset(k, 0, sizeof(k));
    if (keylen > sizeof(k)) {
        if (!sha256_digest(key, keylen, k))
            return 0;
    } else {
        memcpy(k, key, keylen);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    if (!sha256_two(ipad, sizeof(ipad), msg, msglen, inner))
        return 0;
    return sha256_two(opad, sizeof(opad), inner, sizeof(inner), out);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_le64(uint8_t *p, uint64_t v){
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* h_chain(m, j, w, extra) = SHA256(domain || |m|_be32 || m || j_be32 ||
 *                                  w_0..w_{k-1} as little-endian int64 || extra)
 * with w values in [0, q), exactly as in prototype/veil_core.py.            */
static void h_chain(uint8_t out[32], const uint8_t *m, size_t mlen, uint32_t j,
                    const int64_t *w, const uint8_t *extra, size_t elen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t buf[4];
    uint8_t polybuf[D * 8];
    unsigned int outlen = 0;

    if (ctx == NULL) {              /* cannot happen with a working libcrypto */
        memset(out, 0, 32);
        return;
    }
    (void)EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    (void)EVP_DigestUpdate(ctx, VEIL_DOMAIN, DOMAIN_LEN);
    put_be32(buf, (uint32_t)mlen);
    (void)EVP_DigestUpdate(ctx, buf, sizeof(buf));
    if (mlen != 0)
        (void)EVP_DigestUpdate(ctx, m, mlen);
    put_be32(buf, j);
    (void)EVP_DigestUpdate(ctx, buf, sizeof(buf));
    for (int i = 0; i < K; i++) {
        for (int t = 0; t < D; t++)
            put_le64(polybuf + (size_t)8 * t, (uint64_t)w[(size_t)i * D + t]);
        (void)EVP_DigestUpdate(ctx, polybuf, sizeof(polybuf));
    }
    if (elen != 0)
        (void)EVP_DigestUpdate(ctx, extra, elen);
    (void)EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

/* ------------------------------------------------------------------------- */
/* NTT and sparse multiplication (c/veil_kernels.c)                           */
/* ------------------------------------------------------------------------- */

static int64_t modq(int64_t x)
{
    x %= Q;
    return x < 0 ? x + Q : x;
}

static void fwd_stages(int64_t *b)
{
    size_t ro = 0;
    for (int len = 2; len <= D; len <<= 1) {
        int half = len >> 1;
        for (int blk = 0; blk < D; blk += len) {
            for (int j = 0; j < half; ++j) {
                int64_t u = b[blk + j];
                int64_t t = (b[blk + j + half] * ROOTS[ro + j]) % Q;
                int64_t hi = u + t;
                if (hi >= Q) hi -= Q;
                int64_t lo = u - t;
                if (lo < 0) lo += Q;
                b[blk + j] = hi;
                b[blk + j + half] = lo;
            }
        }
        ro += (size_t)half;
    }
}

static void ntt_fwd(int64_t *out, const int64_t *in)
{
    for (int i = 0; i < D; ++i) {
        int j = BITREV[i];
        int64_t v = in[j] % Q;
        if (v < 0) v += Q;
        out[i] = (v * PSI[j]) % Q;
    }
    fwd_stages(out);
}

static void ntt_inv(int64_t *out, const int64_t *in)
{
    int64_t b[D];
    size_t ro = 0;

    for (int i = 0; i < D; ++i) b[i] = in[i];
    for (int len = D; len >= 2; len >>= 1) {
        int half = len >> 1;
        for (int blk = 0; blk < D; blk += len) {
            for (int j = 0; j < half; ++j) {
                int64_t u = b[blk + j];
                int64_t v = b[blk + j + half];
                int64_t hi = u + v;
                if (hi >= Q) hi -= Q;
                int64_t lo = modq(u - v);
                b[blk + j] = hi;
                b[blk + j + half] = (lo * INV_ROOTS[ro + j]) % Q;
            }
        }
        ro += (size_t)half;
    }
    for (int i = 0; i < D; ++i) {
        int j = BITREV[i];
        out[i] = (((b[j] * INV_D) % Q) * PSI_INV[i]) % Q;
    }
}

/* out = (sum_{i in idx} x^i) * a  mod (x^D + 1) */
static void sparse_mul(int64_t *out, const int64_t *a, const int32_t *idx, int nidx)
{
    for (int i = 0; i < D; ++i) out[i] = 0;
    for (int k = 0; k < nidx; ++k) {
        int i = idx[k];
        if (i == 0) {
            for (int j = 0; j < D; ++j) out[j] += a[j];
        } else {
            for (int j = i; j < D; ++j) out[j] += a[j - i];
            for (int j = 0; j < i; ++j) out[j] -= a[D - i + j];
        }
    }
    for (int j = 0; j < D; ++j) out[j] = modq(out[j]);
}

/* w = A * z, with A_hat already in the NTT domain (k x l polynomials).      */
static void mat_vec(const int64_t *Ahat, const int64_t *z, int64_t *out)
{
    int64_t zh[L][D];
    int64_t acc[D];

    for (int j = 0; j < L; j++)
        ntt_fwd(zh[j], z + (size_t)j * D);
    for (int i = 0; i < K; i++) {
        for (int t = 0; t < D; t++) acc[t] = 0;
        for (int j = 0; j < L; j++) {
            const int64_t *a = Ahat + ((size_t)i * L + j) * D;
            const int64_t *b = zh[j];
            for (int t = 0; t < D; t++) acc[t] += a[t] * b[t];
        }
        for (int t = 0; t < D; t++) acc[t] %= Q;
        ntt_inv(out + (size_t)i * D, acc);
    }
}

/* ------------------------------------------------------------------------- */
/* box <-> integer (prototype/veil_core.py: int_to_box / box_to_int)          */
/* ------------------------------------------------------------------------- */

/* Little-endian bit unpacking, 19-bit digits, subtract H.                    */
static void int_to_box(const uint8_t *x, int64_t *z)
{
    for (int i = 0; i < ND; i++) {
        uint32_t p = (uint32_t)i * TBITS;
        uint32_t byte = p >> 3;
        uint32_t sh = p & 7u;
        uint32_t v = (uint32_t)x[byte]
                   | ((uint32_t)x[byte + 1] << 8)
                   | ((uint32_t)x[byte + 2] << 16);
        /* 19 bits starting at bit 6 or 7 of the byte spill into a 4th byte. */
        if (sh >= 6 && byte + 3 < (uint32_t)RESP_BYTES)
            v |= (uint32_t)x[byte + 3] << 24;
        z[i] = (int64_t)((v >> sh) & ((1u << TBITS) - 1u)) - BOX_H;
    }
}

/* Inverse of int_to_box: pack the box into a big-endian integer, exactly as
 * Python's box_to_int(z).to_bytes(RESP_BYTES, "big") serialization does.     */
static void box_to_int(const int64_t *z, uint8_t *out)
{
    uint8_t le[RESP_BYTES];
    uint64_t acc = 0;
    int nbits = 0;
    size_t pos = 0;

    for (int i = 0; i < ND; i++) {
        acc |= ((uint64_t)(z[i] + BOX_H)) << nbits;
        nbits += TBITS;
        while (nbits >= 8) {
            le[pos++] = (uint8_t)(acc & 0xffu);
            acc >>= 8;
            nbits -= 8;
        }
    }
    for (int i = 0; i < RESP_BYTES; i++)
        out[i] = le[RESP_BYTES - 1 - i];
}

/* int_to_box from a big-endian encoding (Feistel output / signature response). */
static void int_to_box_be(const uint8_t *be, int64_t *z)
{
    uint8_t le[RESP_BYTES];
    for (int i = 0; i < RESP_BYTES; i++)
        le[i] = be[RESP_BYTES - 1 - i];
    int_to_box(le, z);
}

static int in_box(const int64_t *z)
{
    for (int i = 0; i < ND; i++)
        if (z[i] < -((int64_t)BOX_H) || z[i] >= (int64_t)BOX_H)
            return 0;
    return 1;
}

/* ------------------------------------------------------------------------- */
/* deterministic randomness from SHAKE-256                                    */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t key[40];        /* 32-byte seed || 8-byte nonce */
    uint64_t ctr;
    uint8_t buf[4096];
    size_t pos;
    size_t len;
} Prng;

static void prng_init(Prng *p, const uint8_t seed[32], uint64_t nonce)
{
    memcpy(p->key, seed, 32);
    for (int i = 0; i < 8; i++)
        p->key[32 + i] = (uint8_t)(nonce >> (8 * (7 - i)));
    p->ctr = 0;
    p->pos = 0;
    p->len = 0;
}

static void prng_refill(Prng *p)
{
    uint8_t in[48];
    memcpy(in, p->key, 40);
    for (int i = 0; i < 8; i++)
        in[40 + i] = (uint8_t)(p->ctr >> (8 * (7 - i)));
    (void)shake256(in, sizeof(in), p->buf, sizeof(p->buf));
    p->pos = 0;
    p->len = sizeof(p->buf);
    p->ctr++;
}

static void prng_bytes(Prng *p, uint8_t *out, size_t n)
{
    while (n > 0) {
        size_t take;
        if (p->pos == p->len)
            prng_refill(p);
        take = p->len - p->pos;
        if (take > n)
            take = n;
        memcpy(out, p->buf + p->pos, take);
        p->pos += take;
        out += take;
        n -= take;
    }
}

typedef struct {
    uint64_t acc;
    int nbits;
} BitReader;

static uint32_t br_read(BitReader *br, Prng *prng, int nbits)
{
    uint32_t v;

    while (br->nbits < nbits) {
        uint8_t byte;
        prng_bytes(prng, &byte, 1);
        br->acc = (br->acc << 8) | (uint64_t)byte;
        br->nbits += 8;
    }
    br->nbits -= nbits;
    v = (uint32_t)((br->acc >> br->nbits) & (((uint64_t)1 << nbits) - 1u));
    br->acc &= ((uint64_t)1 << br->nbits) - 1u;
    return v;
}

/* y uniform in [-H+M, H-M) with H = 2^18, M = 39.                            */
static void sample_y(Prng *prng, BitReader *br, int64_t *y)
{
    for (int i = 0; i < ND; i++) {
        uint32_t v;
        do {
            v = br_read(br, prng, 19);
        } while (v >= (uint32_t)Y_RANGE);
        y[i] = (int64_t)v - Y_LIMIT;
    }
}

/* ------------------------------------------------------------------------- */
/* Feistel FPE over the 19456-bit box (veil_core._f / feistel_perm)           */
/* ------------------------------------------------------------------------- */

static void feistel_f(const uint8_t *dk, size_t dklen, uint16_t rnd,
                      const uint8_t *half, uint8_t *out)
{
    uint8_t in[DK_MAX + 2 + HALF_BYTES];

    memcpy(in, dk, dklen);
    in[dklen] = (uint8_t)(rnd >> 8);
    in[dklen + 1] = (uint8_t)(rnd & 0xffu);
    memcpy(in + dklen + 2, half, HALF_BYTES);
    (void)shake256(in, dklen + 2 + HALF_BYTES, out, HALF_BYTES);
}

/* 16-round balanced Feistel; x and out are 2432-byte big-endian integers.    */
static void feistel_perm(const uint8_t *dk, size_t dklen,
                         const uint8_t *x, uint8_t *out)
{
    uint8_t l[HALF_BYTES], r[HALF_BYTES], f[HALF_BYTES], t[HALF_BYTES];

    memcpy(l, x, HALF_BYTES);
    memcpy(r, x + HALF_BYTES, HALF_BYTES);
    for (int round = 0; round < Q_ROUNDS; round++) {
        feistel_f(dk, dklen, (uint16_t)round, r, f);
        for (int i = 0; i < HALF_BYTES; i++)
            t[i] = (uint8_t)(l[i] ^ f[i]);
        memcpy(l, r, HALF_BYTES);
        memcpy(r, t, HALF_BYTES);
    }
    memcpy(out, l, HALF_BYTES);
    memcpy(out + HALF_BYTES, r, HALF_BYTES);
}

/* Inverse permutation: rounds in reverse (veil_core.feistel_inv).           */
static void feistel_inv(const uint8_t *dk, size_t dklen,
                        const uint8_t *y, uint8_t *out)
{
    uint8_t l[HALF_BYTES], r[HALF_BYTES], f[HALF_BYTES], t[HALF_BYTES];

    memcpy(l, y, HALF_BYTES);
    memcpy(r, y + HALF_BYTES, HALF_BYTES);
    for (int round = Q_ROUNDS - 1; round >= 0; round--) {
        feistel_f(dk, dklen, (uint16_t)round, l, f);
        for (int i = 0; i < HALF_BYTES; i++)
            t[i] = (uint8_t)(r[i] ^ f[i]);
        memcpy(r, l, HALF_BYTES);
        memcpy(l, t, HALF_BYTES);
    }
    memcpy(out, l, HALF_BYTES);
    memcpy(out + HALF_BYTES, r, HALF_BYTES);
}

/* ------------------------------------------------------------------------- */
/* sparse challenge (veil_core.sparse_challenge)                              */
/* ------------------------------------------------------------------------- */

static int cmp_i32(const void *a, const void *b)
{
    int32_t x = *(const int32_t *)a;
    int32_t y = *(const int32_t *)b;
    return (x > y) - (x < y);
}

/* SHAKE-256(digest || ctr_be16) -> 64 B -> 16-bit big-endian values mod d,
 * keeping the first TAU distinct positions.                                  */
static void sparse_challenge(const uint8_t digest[32], int32_t idx[TAU])
{
    uint8_t seen[D / 8];
    uint8_t in[34];
    int count = 0;
    unsigned ctr = 0;

    memset(seen, 0, sizeof(seen));
    memcpy(in, digest, 32);
    while (count < TAU) {
        uint8_t blk[64];
        in[32] = (uint8_t)(ctr >> 8);
        in[33] = (uint8_t)ctr;
        (void)shake256(in, sizeof(in), blk, sizeof(blk));
        for (int i = 0; i < 64 && count < TAU; i += 2) {
            uint32_t v = (((uint32_t)blk[i] << 8) | (uint32_t)blk[i + 1])
                         % (uint32_t)D;
            if (!(seen[v >> 3] & (uint8_t)(1u << (v & 7)))) {
                seen[v >> 3] |= (uint8_t)(1u << (v & 7));
                idx[count++] = (int32_t)v;
            }
        }
        ctr++;
    }
    qsort(idx, TAU, sizeof(int32_t), cmp_i32);
}

/* ------------------------------------------------------------------------- */
/* context: matrix A (NTT domain), secret keys, public keys                  */
/* ------------------------------------------------------------------------- */

typedef struct {
    int n;
    uint8_t seed[32];
    int64_t Ahat[K][L][D];
    int64_t sk[MAX_N][L][D];
    int64_t pk[MAX_N][K][D];   /* t_j in the normal domain, as in Python */
} VeilCtx;

static void derive_bytes(uint8_t *out, size_t outlen,
                         const uint8_t seed[32], const char *tag)
{
    uint8_t in[32 + 16];
    size_t tlen = strlen(tag);

    if (tlen > 16)
        tlen = 16;
    memcpy(in, seed, 32);
    memcpy(in + 32, tag, tlen);
    (void)shake256(in, 32 + tlen, out, outlen);
}

VEIL_API void *veil_ctx_new(const uint8_t *seed, size_t seed_len, int n)
{
    VeilCtx *c;
    uint8_t *raw;
    uint8_t *sraw;
    size_t abytes;
    size_t sbytes;
    int64_t poly[D];
    int64_t acc[D];
    int64_t shat[L][D];

    if (seed == NULL || seed_len == 0 || n < 1 || n > MAX_N)
        return NULL;
    c = (VeilCtx *)calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    c->n = n;
    (void)shake256(seed, seed_len, c->seed, sizeof(c->seed));

    /* A: k*l polynomials, 3 bytes per coefficient reduced mod q, then NTT. */
    abytes = (size_t)K * L * D * 3;
    raw = (uint8_t *)malloc(abytes);
    if (raw == NULL) { free(c); return NULL; }
    derive_bytes(raw, abytes, c->seed, "A");
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < L; j++) {
            const uint8_t *p = raw + ((size_t)i * L + j) * D * 3;
            for (int t = 0; t < D; t++) {
                poly[t] = ((int64_t)p[3 * t] << 16)
                        | ((int64_t)p[3 * t + 1] << 8)
                        | (int64_t)p[3 * t + 2];
                poly[t] %= Q;
            }
            ntt_fwd(c->Ahat[i][j], poly);
        }
    }
    free(raw);

    /* Secret keys: coefficients in {-1, 0, 1}. */
    sbytes = (size_t)n * L * D;
    sraw = (uint8_t *)malloc(sbytes);
    if (sraw == NULL) { free(c); return NULL; }
    derive_bytes(sraw, sbytes, c->seed, "sk");
    for (int m = 0; m < n; m++)
        for (int i = 0; i < L; i++)
            for (int t = 0; t < D; t++)
                c->sk[m][i][t] =
                    (int64_t)(sraw[((size_t)m * L + i) * D + t] % 3u) - 1;
    free(sraw);

    /* t_j = A * s_j in the normal domain. */
    for (int m = 0; m < n; m++) {
        for (int i = 0; i < L; i++)
            ntt_fwd(shat[i], c->sk[m][i]);
        for (int i = 0; i < K; i++) {
            for (int t = 0; t < D; t++) acc[t] = 0;
            for (int j = 0; j < L; j++) {
                const int64_t *a = c->Ahat[i][j];
                const int64_t *b = shat[j];
                for (int t = 0; t < D; t++)
                    acc[t] += a[t] * b[t];
            }
            for (int t = 0; t < D; t++) acc[t] %= Q;
            ntt_inv(c->pk[m][i], acc);
        }
    }
    return c;
}

VEIL_API void veil_ctx_free(void *vctx)
{
    free(vctx);
}

VEIL_API size_t veil_sig_size(const void *vctx)
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    return c == NULL ? 0 : (size_t)C1_BYTES + (size_t)c->n * RESP_BYTES;
}

VEIL_API int veil_n(const void *vctx)
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    return c == NULL ? 0 : c->n;
}

/* ------------------------------------------------------------------------- */
/* signing                                                                    */
/* ------------------------------------------------------------------------- */

static int sign_once(const VeilCtx *c, int pi,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *extra, size_t elen,
                     const uint8_t *dk, size_t dklen, const uint8_t *mu,
                     int mode, uint64_t nonce, uint8_t *sig)
{
    Prng prng;
    BitReader br;
    int64_t y[ND], z[ND], w[K * D], az[K * D], ct[D];
    uint8_t c_init[32], c_next[32], c_after[32], c1[32];
    int32_t cvec[TAU];
    int have_c1 = 0;

    memset(c1, 0, sizeof(c1));
    prng_init(&prng, c->seed, nonce);
    br.acc = 0;
    br.nbits = 0;

    /* 1. the signer commits: w_pi = A*y, then starts the hash chain there. */
    sample_y(&prng, &br, y);
    mat_vec(&c->Ahat[0][0][0], y, w);
    h_chain(c_init, m, mlen, (uint32_t)pi, w, extra, elen);
    memcpy(c_next, c_init, sizeof(c_next));

    /* 2. decoys j != pi: z_j from the FPE (or the box), w_j = A z_j - c_j t_j. */
    for (int step = 1; step < c->n; step++) {
        int j = (pi + step) % c->n;

        if (mode == 1) {
            uint8_t x[RESP_BYTES];
            uint8_t perm[RESP_BYTES];
            prng_bytes(&prng, x, RESP_BYTES - MU_BYTES);
            memcpy(x + (RESP_BYTES - MU_BYTES), mu, MU_BYTES);
            feistel_perm(dk, dklen, x, perm);
            int_to_box_be(perm, z);
        } else {
            uint8_t x[RESP_BYTES];
            prng_bytes(&prng, x, RESP_BYTES);
            int_to_box(x, z);
        }

        sparse_challenge(c_next, cvec);
        mat_vec(&c->Ahat[0][0][0], z, az);
        for (int i = 0; i < K; i++) {
            sparse_mul(ct, c->pk[j][i], cvec, TAU);
            for (int t = 0; t < D; t++)
                w[(size_t)i * D + t] = modq(az[(size_t)i * D + t] - ct[t]);
        }
        h_chain(c_after, m, mlen, (uint32_t)j, w, extra, elen);
        if (j == c->n - 1) {
            memcpy(c1, c_after, sizeof(c1));
            have_c1 = 1;
        }
        memcpy(c_next, c_after, sizeof(c_next));
        box_to_int(z, sig + C1_BYTES + (size_t)j * RESP_BYTES);
    }

    /* 3. close on the signer's branch: z_pi = y + c_pi * s_pi (integers). */
    sparse_challenge(c_next, cvec);
    for (int i = 0; i < L; i++) {
        sparse_mul(ct, c->sk[pi][i], cvec, TAU);
        for (int t = 0; t < D; t++) {
            int64_t cs = ct[t] > Q / 2 ? ct[t] - Q : ct[t];
            z[(size_t)i * D + t] = y[(size_t)i * D + t] + cs;
        }
    }
    /* y is uniform over [-H-M, H+M) and z must land in [-H, H); every
     * accepted z then has a unique preimage and is uniform over the box,
     * independent of s.  veil_sign() retries on rejection.                  */
    if (!in_box(z))
        return 0;
    box_to_int(z, sig + C1_BYTES + (size_t)pi * RESP_BYTES);

    if (!have_c1)                 /* pi == n-1: c1 is the digest at pi       */
        memcpy(c1, c_init, sizeof(c1));
    memcpy(sig, c1, C1_BYTES);
    return 1;
}

VEIL_API int veil_sign(void *vctx, int pi,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *extra, size_t extra_len,
                       const uint8_t *dk, size_t dk_len,
                       const uint8_t *mu, int mode, uint64_t nonce,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    size_t need;

    if (c == NULL || out == NULL || mu == NULL || dk == NULL)
        return 0;
    if (mode != 0 && mode != 1)
        return 0;
    if (dk_len > DK_MAX)
        return 0;
    if (msg_len > (size_t)0xFFFFFFFFu)
        return 0;
    if (pi < 0 || pi >= c->n)
        return 0;
    need = (size_t)C1_BYTES + (size_t)c->n * RESP_BYTES;
    if (out_cap < need)
        return 0;

    for (int attempt = 0; attempt < 16; attempt++) {
        if (sign_once(c, pi, msg, msg_len, extra, extra_len, dk, dk_len,
                      mu, mode, nonce + (uint64_t)attempt, out)) {
            if (out_len != NULL)
                *out_len = need;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* verification                                                               */
/* ------------------------------------------------------------------------- */

VEIL_API int veil_verify(void *vctx,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *extra, size_t extra_len,
                         const uint8_t *sig, size_t sig_len)
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    int64_t z[ND], w[K * D], az[K * D], ct[D];
    uint8_t c_digest[32];
    int32_t cvec[TAU];
    size_t need;

    if (c == NULL || sig == NULL)
        return 0;
    if (msg_len > (size_t)0xFFFFFFFFu)
        return 0;
    need = (size_t)C1_BYTES + (size_t)c->n * RESP_BYTES;
    if (sig_len != need)
        return 0;

    memcpy(c_digest, sig, sizeof(c_digest));
    for (int j = 0; j < c->n; j++) {
        int_to_box_be(sig + C1_BYTES + (size_t)j * RESP_BYTES, z);
        if (!in_box(z))
            return 0;
        sparse_challenge(c_digest, cvec);
        mat_vec(&c->Ahat[0][0][0], z, az);
        for (int i = 0; i < K; i++) {
            sparse_mul(ct, c->pk[j][i], cvec, TAU);
            for (int t = 0; t < D; t++)
                w[(size_t)i * D + t] = modq(az[(size_t)i * D + t] - ct[t]);
        }
        h_chain(c_digest, msg, msg_len, (uint32_t)j, w, extra, extra_len);
    }
    return memcmp(c_digest, sig, C1_BYTES) == 0;
}

/* ------------------------------------------------------------------------- */
/* extraction and linking                                                     */
/* ------------------------------------------------------------------------- */

/* Same tag as veil_core.link_tag: SHA256("VEIL/link" || sk_i || epoch_be64). */
VEIL_API int veil_link_tag(void *vctx, int member, uint64_t epoch,
                           uint8_t out[32])
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    uint8_t *buf;
    size_t off = 9;
    int ok;

    if (c == NULL || out == NULL || member < 0 || member >= c->n)
        return 0;
    buf = (uint8_t *)malloc(9 + (size_t)L * D * 8 + 8);
    if (buf == NULL)
        return 0;
    memcpy(buf, "VEIL/link", 9);
    for (int i = 0; i < L; i++)
        for (int t = 0; t < D; t++) {
            put_le64(buf + off, (uint64_t)c->sk[member][i][t]);
            off += 8;
        }
    put_be64(buf + off, epoch);
    off += 8;
    ok = sha256_digest(buf, off, out);
    free(buf);
    return ok;
}

/* Recover (payload, signer index) from an attributable signature.           */
VEIL_API int veil_extract_fpe(void *vctx,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t *dk, size_t dk_len,
                              const uint8_t *dk_mac, size_t dk_mac_len,
                              uint8_t payload_out[32], int *pi_out)
{
    const VeilCtx *c = (const VeilCtx *)vctx;
    uint8_t x[RESP_BYTES], h[32];
    size_t need;
    int decoys = 0, signer = -1;
    uint8_t payload[32];

    if (c == NULL || sig == NULL || dk == NULL || dk_mac == NULL ||
        payload_out == NULL || pi_out == NULL)
        return 0;
    if (dk_len > DK_MAX)
        return 0;
    need = (size_t)C1_BYTES + (size_t)c->n * RESP_BYTES;
    if (sig_len != need)
        return 0;

    for (int j = 0; j < c->n; j++) {
        const uint8_t *mu;
        feistel_inv(dk, dk_len, sig + C1_BYTES + (size_t)j * RESP_BYTES, x);
        mu = x + RESP_BYTES - MU_BYTES;
        if (hmac_sha256(dk_mac, dk_mac_len, mu, 32, h) &&
            memcmp(h, mu + 32, 16) == 0) {
            decoys++;
            memcpy(payload, mu, 32);
        } else {
            signer = j;
        }
    }
    if (decoys != c->n - 1 || signer < 0)
        return 0;
    memcpy(payload_out, payload, 32);
    *pi_out = signer;
    return 1;
}

/* ------------------------------------------------------------------------- */
/* diagnostic: NTT / sparse-multiplication self-check                        */
/* ------------------------------------------------------------------------- */

/* Schoolbook negacyclic product mod (x^D + 1), q.                            */
static void schoolbook_mul(int64_t *out, const int64_t *a, const int64_t *b)
{
    int64_t tmp[2 * D];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < D; i++)
        for (int j = 0; j < D; j++)
            tmp[i + j] += a[i] * b[j];
    for (int i = 0; i < D; i++) {
        int64_t v = tmp[i];
        if (i < D - 1)          /* res[:d-1] -= c[d:], as in veil_core */
            v -= tmp[D + i];
        out[i] = modq(v);
    }
}

/* Returns 1 when the ported kernels agree with schoolbook arithmetic.        */
VEIL_API int veil_kernel_selftest(void)
{
    uint8_t seed[32];
    uint8_t raw[2 * D * 3];
    int64_t a[D], b[D], ah[D], bh[D], ch[D], prod[D], ref[D], sparse[D];
    int64_t dense[D];
    int32_t idx[TAU];

    (void)shake256("VEIL/v3/kernel-selftest", 23, seed, sizeof(seed));
    derive_bytes(raw, sizeof(raw), seed, "k");
    for (int i = 0; i < D; i++) {
        a[i] = ((int64_t)raw[3 * i] << 16)
             | ((int64_t)raw[3 * i + 1] << 8)
             | (int64_t)raw[3 * i + 2];
        a[i] %= Q;
        b[i] = ((int64_t)raw[D * 3 + 3 * i] << 16)
             | ((int64_t)raw[D * 3 + 3 * i + 1] << 8)
             | (int64_t)raw[D * 3 + 3 * i + 2];
        b[i] %= Q;
    }

    /* NTT round trip */
    ntt_fwd(ah, a);
    ntt_inv(prod, ah);
    if (memcmp(prod, a, sizeof(a)) != 0)
        return 0;

    /* cyclic-negacyclic multiplication through the NTT */
    ntt_fwd(bh, b);
    for (int i = 0; i < D; i++)
        ch[i] = (ah[i] * bh[i]) % Q;
    ntt_inv(prod, ch);
    schoolbook_mul(ref, a, b);
    if (memcmp(prod, ref, sizeof(prod)) != 0)
        return 0;

    /* sparse multiplication (the challenge polynomial has TAU ones) */
    memset(dense, 0, sizeof(dense));
    idx[0] = 0;
    dense[0] = 1;
    for (int i = 1; i < TAU; i++) {
        idx[i] = i * 6 + 1;
        dense[idx[i]] = 1;
    }
    sparse_mul(sparse, a, idx, TAU);
    schoolbook_mul(ref, dense, a);
    if (memcmp(sparse, ref, sizeof(sparse)) != 0)
        return 0;
    return 1;
}

/* Merkle commitment to the epoch's member set.                               *
 * coeffs holds n leaves, each leaf being l*d int64 coefficients in the same  *
 * little-endian layout as the NumPy array in veil_core.merkle_root, so the   *
 * roots of the two implementations are directly comparable.                  */
VEIL_API int veil_merkle_root(const int64_t *coeffs, size_t n, size_t l, size_t d,
                              uint8_t out[32])
{
    if (!coeffs || !out || n == 0 || l == 0 || d == 0)
        return 0;

    size_t leaf_bytes = l * d * 8;
    size_t cap = n + 1;                    /* room for one duplicated node */
    uint8_t *buf = malloc(9 + leaf_bytes);
    uint8_t *level = malloc(cap * 32);
    uint8_t *next = malloc(cap * 32);
    if (!buf || !level || !next) {
        free(buf); free(level); free(next);
        return 0;
    }
    memcpy(buf, "VEIL/leaf", 9);
    for (size_t i = 0; i < n; i++) {
        const int64_t *leaf = coeffs + i * l * d;
        for (size_t j = 0; j < l * d; j++) {
            uint64_t v = (uint64_t)leaf[j];
            for (int k = 0; k < 8; k++)
                buf[9 + 8 * j + k] = (uint8_t)(v >> (8 * k));
        }
        if (!sha256_digest(buf, 9 + leaf_bytes, level + 32 * i)) {
            free(buf); free(level); free(next);
            return 0;
        }
    }

    size_t count = n;
    while (count > 1) {
        if (count % 2) {                    /* odd node is carried up */
            memcpy(level + 32 * count, level + 32 * (count - 1), 32);
            count++;
        }
        size_t pairs = count / 2;
        for (size_t i = 0; i < pairs; i++) {
            uint8_t in[9 + 64];
            memcpy(in, "VEIL/node", 9);
            memcpy(in + 9, level + 64 * i, 32);
            memcpy(in + 41, level + 64 * i + 32, 32);
            if (!sha256_digest(in, sizeof(in), next + 32 * i)) {
                free(buf); free(level); free(next);
                return 0;
            }
        }
        uint8_t *tmp = level; level = next; next = tmp;
        count = pairs;
    }
    memcpy(out, level, 32);
    free(buf); free(level); free(next);
    return 1;
}
