/* NTT and sparse multiplication over Z_q[x]/(x^256+1), q = 8380417.
 * Constants (roots, bit reversal) are emitted by gen_constants.py.
 * Build: gcc -O3 -shared -o veil_kernels.dll veil_kernels.c
 */
#include <stdint.h>
#include <stddef.h>

#include "constants.h"

static int64_t modq(int64_t x) {
    x %= Q;
    return x < 0 ? x + Q : x;
}

static void fwd_stages(int64_t *b) {
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

void ntt_fwd(int64_t *out, const int64_t *in) {
    for (int i = 0; i < D; ++i) {
        int j = BITREV[i];
        out[i] = (in[j] * PSI[j]) % Q;
    }
    fwd_stages(out);
}

void ntt_inv(int64_t *out, const int64_t *in) {
    int64_t b[D];
    for (int i = 0; i < D; ++i) b[i] = in[i];
    size_t ro = 0;
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
void sparse_mul(int64_t *out, const int64_t *a, const int32_t *idx, int nidx) {
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
