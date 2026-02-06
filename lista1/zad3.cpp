#include "md5.h"
#include "zad3.hpp"

#include <vector>
#include <bits/stdc++.h>
#include <random>
#include <chrono>
#include <cstring>

#define FF(a, b, c, d, M, s, t) { a = b + rol(a + F(b, c, d) + M + t, s); }
#define GG(a, b, c, d, M, s, t) { a = b + rol(a + G(b, c, d) + M + t, s); }
#define HH(a, b, c, d, M, s, t) { a = b + rol(a + H(b, c, d) + M + t, s); }
#define II(a, b, c, d, M, s, t) { a = b + rol(a + I(b, c, d) + M + t, s); }

uint32_t M0[16] = {
    0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98,
    0x87b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8,
    0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125,
    0xe8255108,0x9fc9cdf7, 0xf2bd1dd9, 0x5b3c3780
};

uint32_t M0p[16] = {
    0x02dd31d1, 0xc4eee6c5, 0x069a3d69, 0x5cf9af98,
    0x07b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8,
    0x0634ad55, 0x02b3f409, 0x8388e483, 0x5a41f125,
    0xe8255108, 0x9fc9cdf7, 0x72bd1dd9, 0x5b3c3780
};

uint32_t M1[16] = {
    0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 
    0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1,
    0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 
    0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
};

uint32_t M1p[16] = {
    0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a,
    0x479a7335, 0x0cfdebf0, 0x66f12930, 0x8fb109d1,
    0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79,
    0xddcb74ed, 0x6dd3c55f, 0x580a9bb1, 0xe3a7cc35
};

uint32_t M1_found[16] = {
    0xae9d07bb, 0x0d8b36c8, 0x6d9773b6, 0x12d79762,
    0x495cd64e, 0x4d81eebc, 0x07b68d2a, 0xe04d1d4e,
    0x5dbb1f1d, 0x8abb97b8, 0x692978e2, 0x9e75c081,
    0xa9b0f0f9, 0x3b939d6c, 0xac21fd08, 0x5b91284d
};
uint32_t M1_foundp[16] = {
    0xae9d07bb, 0x0d8b36c8, 0x6d9773b6, 0x12d79762,
    0xc95cd64e, 0x4d81eebc, 0x07b68d2a, 0xe04d1d4e,
    0x5dbb1f1d, 0x8abb97b8, 0x692978e2, 0x9e754081,
    0xa9b0f0f9, 0x3b939d6c, 0x2c21fd08, 0x5b91284d
};

static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};


static uint32_t MASK_A1_ZERO = 0x0a000820;
static uint32_t MASK_A1_ONE = 0x84200000;
static uint32_t MASK_D1_ZERO = 0x02208026;
static uint32_t MASK_D1_ONE = 0x8c000800;
static uint32_t MASK_D1_COPY = 0x701f10c0;
static uint32_t MASK_C1_ZERO = 0x40201080;
static uint32_t MASK_C1_ONE = 0xbe1f0966;
static uint32_t MASK_C1_COPY = 0x00000018;
static uint32_t MASK_B1_ZERO = 0x443b19ee;
static uint32_t MASK_B1_ONE = 0xba040010;
static uint32_t MASK_B1_COPY = 0x00000601;
static uint32_t MASK_A2_ZERO = 0xb41011af;
static uint32_t MASK_A2_ONE = 0x482f0e50;
static uint32_t MASK_D2_ZERO = 0x9a1113a9;
static uint32_t MASK_D2_ONE = 0x04220c56;
static uint32_t MASK_C2_ZERO = 0x083201c0;
static uint32_t MASK_C2_ONE = 0x96011e01;
static uint32_t MASK_C2_COPY = 0x01808000;
static uint32_t MASK_B2_ZERO = 0x1b810001;
static uint32_t MASK_B2_ONE = 0x843283c0;
static uint32_t MASK_B2_COPY = 0x00000002;
static uint32_t MASK_A3_ZERO = 0x03828202;
static uint32_t MASK_A3_ONE = 0x9c0101c1;
static uint32_t MASK_A3_COPY = 0x00001000;
static uint32_t MASK_D3_ZERO = 0x00041003;
static uint32_t MASK_D3_ONE = 0x878383c0;
static uint32_t MASK_C3_ZERO = 0x00021000;
static uint32_t MASK_C3_ONE = 0x800583c3;
static uint32_t MASK_C3_COPY = 0x00086000;
static uint32_t MASK_B3_ZERO = 0x0007e000;
static uint32_t MASK_B3_ONE = 0x80081080;
static uint32_t MASK_B3_COPY = 0x7f000000;
static uint32_t MASK_A4_ZERO = 0xc0000080;
static uint32_t MASK_A4_ONE = 0x3f0fe008;
static uint32_t MASK_D4_ZERO = 0xbf040000;
static uint32_t MASK_D4_ONE = 0x400be088;
static uint32_t MASK_C4_ZERO = 0x82008008;
static uint32_t MASK_C4_ONE = 0x7d000000;
static uint32_t MASK_B4_ZERO = 0x80000000;
static uint32_t MASK_B4_ONE = 0x20000000;
static uint32_t MASK_A5_ZERO = 0x80020000;
static uint32_t MASK_A5_COPY = 0x00008008;
static uint32_t MASK_D5_ZERO = 0x80000000;
static uint32_t MASK_D5_ONE = 0x00020000;
static uint32_t MASK_D5_COPY = 0x20000000;
static uint32_t MASK_C5_ZERO = 0x80020000;
static uint32_t MASK_B5_ZERO = 0x80000000;
static uint32_t MASK_A6_ZERO = 0x80000000;
static uint32_t MASK_A6_COPY = 0x00020000;
static uint32_t MASK_D6_ZERO = 0x80000000;
static uint32_t MASK_C6_ZERO = 0x80000000;
static uint32_t MASK_B6_DIFF = 0x80000000;
static uint32_t MASK_B12_COPY = 0x80000000;
static uint32_t MASK_A13_COPY = 0x80000000;
static uint32_t MASK_D13_DIFF = 0x80000000;
static uint32_t MASK_C13_COPY = 0x80000000;
static uint32_t MASK_B13_COPY = 0x80000000;
static uint32_t MASK_A14_COPY = 0x80000000;
static uint32_t MASK_D14_COPY = 0x80000000;
static uint32_t MASK_C14_COPY = 0x80000000;
static uint32_t MASK_B14_COPY = 0x80000000;
static uint32_t MASK_A15_COPY = 0x80000000;
static uint32_t MASK_D15_COPY = 0x80000000;
static uint32_t MASK_C15_COPY = 0x80000000;
static uint32_t MASK_B15_DIFF = 0x80000000;
static uint32_t MASK_A16_ONE = 0x02000000;
static uint32_t MASK_A16_COPY = 0x80000000;
static uint32_t MASK_D16_ONE = 0x02000000;
static uint32_t MASK_D16_COPY = 0x80000000;


static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }


static void inline modify_message(uint32_t a_modified, uint32_t a_prev, uint32_t b, uint32_t c, uint32_t d, uint32_t* M1, uint32_t K, uint32_t S)
{
    uint32_t x = a_modified - b;
    x = ror(x, S);
    x = x - (F(b, c, d) + K + a_prev);
    *M1 = x;
}

static inline void set_one(uint32_t *ptr, uint32_t mask)  { *ptr |= mask; }
static inline void set_zero(uint32_t *ptr, uint32_t mask) { *ptr &= ~mask; }
static inline void copy_bits(uint32_t *dst, uint32_t mask, uint32_t src) { *dst = (*dst & ~mask) | (src & mask); }

static inline bool verify_one(uint32_t v, uint32_t mask) { return (v & mask) == mask; }
static inline bool verify_zero(uint32_t v, uint32_t mask) { return (v & mask) == 0x00000000;}
static inline bool verify_copy(uint32_t v, uint32_t u, uint32_t mask) { return (v & mask) == (u & mask); }
static inline bool verify_diff(uint32_t v, uint32_t u, uint32_t mask) { return (v & mask) != (u & mask); }

void apply_message_modifications(const uint32_t *states, uint32_t *buffer, uint32_t M1[16], std::mt19937_64 &rng)
{
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;   

    bool message_found = false;
    while(!message_found)
    {

        // uint32_t M1_init[16] = {
        //     0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 
        //     0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1,
        //     0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 
        //     0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
        // };

        for (int j = 0; j < 16; ++j)
        {
            //M1[j] = dist(rng);
            M1[j] = M1_found[j];
            //M1[j] = M1_init[j];

        }

        a = states[0];
        b = states[1];
        c = states[2];
        d = states[3];    

        uint32_t a_prev = states[0];
        uint32_t b_prev = states[1];
        uint32_t c_prev = states[2];
        uint32_t d_prev = states[3];
    
        
        FF(a, b, c, d, M1[0], S[0], K[0]); 
        set_zero(&a, MASK_A1_ZERO);
        set_one(&a, MASK_A1_ONE);
        modify_message(a, a_prev, b, c, d, &M1[0], K[0], S[0]);
        a_prev = a;
    
    
        FF(d, a, b, c, M1[1], S[1], K[1]); 
        set_one(&d, MASK_D1_ONE);
        set_zero(&d, MASK_D1_ZERO);
        copy_bits(&d, MASK_D1_COPY, a);
        modify_message(d, d_prev, a, b, c, &M1[1], K[1], S[1]);
        d_prev = d;
    
    
        FF(c, d, a, b, M1[2], S[2], K[2]);
        copy_bits(&c, MASK_C1_COPY, d);
        set_one(&c, MASK_C1_ONE);
        set_zero(&c, MASK_C1_ZERO);
        modify_message(c, c_prev, d, a, b, &M1[2], K[2], S[2]);
        c_prev = c;
    
        FF(b, c, d, a, M1[3], S[3], K[3]);
        copy_bits(&b, MASK_B1_COPY, c);
        set_zero(&b, MASK_B1_ZERO);
        set_one(&b, MASK_B1_ONE);
        modify_message(b, b_prev, c, d, a, &M1[3], K[3], S[3]);
        b_prev = b;
        
        FF(a, b, c, d, M1[4], S[4], K[4]);
        set_zero(&a, MASK_A2_ZERO);
        set_one(&a, MASK_A2_ONE);
        modify_message(a, a_prev, b, c, d, &M1[4], K[4], S[4]);
        a_prev = a;
    
        FF(d, a, b, c, M1[5], S[5], K[5]);
        set_one(&d, MASK_D2_ONE);
        set_zero(&d, MASK_D2_ZERO);
        modify_message(d, d_prev, a, b, c, &M1[5], K[5], S[5]);
        d_prev = d;
    
        FF(c, d, a, b, M1[6], S[6], K[6]);
        copy_bits(&c, MASK_C2_COPY, d);
        set_one(&c, MASK_C2_ONE);
        set_zero(&c, MASK_C2_ZERO);
        modify_message(c, c_prev, d, a, b, &M1[6], K[6], S[6]);
        c_prev = c;
    
        FF(b, c, d, a, M1[7], S[7], K[7]);
        copy_bits(&b, MASK_B2_COPY, c);
        set_one(&b, MASK_B2_ONE);
        set_zero(&b, MASK_B2_ZERO);
        modify_message(b, b_prev, c, d, a, &M1[7], K[7], S[7]);
        b_prev = b;
        
        FF(a, b, c, d, M1[8], S[8], K[8]);
        copy_bits(&a, MASK_A3_COPY, b);
        set_one(&a, MASK_A3_ONE);
        set_zero(&a, MASK_A3_ZERO);
        modify_message(a, a_prev, b, c, d, &M1[8], K[8], S[8]);
        a_prev = a;
    
        FF(d, a, b, c, M1[9], S[9], K[9]);
        set_zero(&d, MASK_D3_ZERO);
        set_one(&d, MASK_D3_ONE);
        modify_message(d, d_prev, a, b, c, &M1[9], K[9], S[9]);
        d_prev = d;
    
        FF(c, d, a, b, M1[10], S[10], K[10]);
        copy_bits(&c, MASK_C3_COPY, d);
        set_one(&c, MASK_C3_ONE);
        set_zero(&c, MASK_C3_ZERO);
        modify_message(c, c_prev, d, a, b, &M1[10], K[10], S[10]);
        c_prev = c;
    
        FF(b, c, d, a, M1[11], S[11], K[11]);
        copy_bits(&b, MASK_B3_COPY, c);
        set_one(&b, MASK_B3_ONE);
        set_zero(&b, MASK_B3_ZERO);
        modify_message(b, b_prev, c, d, a, &M1[11], K[11], S[11]);
        b_prev = b;
    
        FF(a, b, c, d, M1[12], S[12], K[12]);
        set_one(&a, MASK_A4_ONE);
        set_zero(&a, MASK_A4_ZERO);
        modify_message(a, a_prev, b, c, d, &M1[12], K[12], S[12]);
        a_prev = a;
        
        FF(d, a, b, c, M1[13], S[13], K[13]);
        set_one(&d, MASK_D4_ONE);
        set_zero(&d, MASK_D4_ZERO);
        modify_message(d, d_prev, a, b, c, &M1[13], K[13], S[13]);
        d_prev = d;
        
        FF(c, d, a, b, M1[14], S[14], K[14]);
        set_zero(&c, MASK_C4_ZERO);
        set_one(&c, MASK_C4_ONE);
        modify_message(c, c_prev, d, a, b, &M1[14], K[14], S[14]);
        c_prev = c;
    
        FF(b, c, d, a, M1[15], S[15], K[15]);
        set_one(&b, MASK_B4_ONE);
        set_zero(&b, MASK_B4_ZERO);
        modify_message(b, b_prev, c, d, a, &M1[15], K[15], S[15]);
        b_prev = b;
    
        GG(a, b, c, d, M1[1], S[16], K[16]);
        if (!verify_zero(a, MASK_A5_ZERO))continue;
        if (!verify_copy(a, b, MASK_A5_COPY)) continue;
    
        GG(d, a, b, c, M1[6], S[17], K[17]);
        if (!verify_zero(d, MASK_D5_ZERO)) continue;
        if (!verify_one(d, MASK_D5_ONE)) continue;
        if (!verify_copy(d, a, MASK_D5_COPY)) continue;
    
        GG(c, d, a, b, M1[11], S[18], K[18]);
        if (!verify_zero(c, MASK_C5_ZERO)) continue;
    
        GG(b, c, d, a, M1[0], S[19], K[19]);
        if (!verify_zero(b, MASK_B5_ZERO)) continue;

        GG(a, b, c, d, M1[5], S[20], K[20]);
        if (!verify_zero(a, MASK_A6_ZERO)) continue;
        if (!verify_copy(a, b, MASK_A6_COPY)) continue;
        GG(d, a, b, c, M1[10], S[21], K[21]);
        if (!verify_zero(d, MASK_D6_ZERO)) continue;

        GG(c, d, a, b, M1[15], S[22], K[22]);
        if (!verify_zero(c, MASK_C6_ZERO)) continue;
        GG(b, c, d, a, M1[4], S[23], K[23]);
        if (!verify_diff(b, c, MASK_B6_DIFF)) continue;
        
        GG(a, b, c, d, M1[9], S[24], K[24]);
        GG(d, a, b, c, M1[14], S[25], K[25]);
        GG(c, d, a, b, M1[3], S[26], K[26]);
        GG(b, c, d, a, M1[8], S[27], K[27]);
        
        GG(a, b, c, d, M1[13], S[28], K[28]);
        GG(d, a, b, c, M1[2], S[29], K[29]);
        GG(c, d, a, b, M1[7], S[30], K[30]);
        GG(b, c, d, a, M1[12], S[31], K[31]);
    
        HH(a, b, c, d, M1[5], S[32], K[32]);
        HH(d, a, b, c, M1[8], S[33], K[33]);
        HH(c, d, a, b, M1[11], S[34], K[34]);
        HH(b, c, d, a, M1[14], S[35], K[35]);
        
        HH(a, b, c, d, M1[1], S[36], K[36]);
        HH(d, a, b, c, M1[4], S[37], K[37]);
        HH(c, d, a, b, M1[7], S[38], K[38]);
        HH(b, c, d, a, M1[10], S[39], K[39]);
        
        HH(a, b, c, d, M1[13], S[40], K[40]);
        HH(d, a, b, c, M1[0], S[41], K[41]);
        HH(c, d, a, b, M1[3], S[42], K[42]);
        HH(b, c, d, a, M1[6], S[43], K[43]);
        
        HH(a, b, c, d, M1[9], S[44], K[44]);
        HH(d, a, b, c, M1[12], S[45], K[45]);
        HH(c, d, a, b, M1[15], S[46], K[46]);
        HH(b, c, d, a, M1[2], S[47], K[47]);
        if (!verify_copy(b, d, MASK_B12_COPY)) continue;

    
        II(a, b, c, d, M1[0], S[48], K[48]);
        if (!verify_copy(a, c, MASK_A13_COPY)) continue;
        II(d, a, b, c, M1[7], S[49], K[49]);
        if (!verify_diff(d, b, MASK_D13_DIFF)) continue;
        II(c, d, a, b, M1[14], S[50], K[50]);
        if (!verify_copy(c, a, MASK_C13_COPY)) continue;
        II(b, c, d, a, M1[5], S[51], K[51]);
        if (!verify_copy(b, d, MASK_B13_COPY)) continue;
        
        II(a, b, c, d, M1[12], S[52], K[52]);
        if (!verify_copy(a, c, MASK_A14_COPY)) continue;
        II(d, a, b, c, M1[3], S[53], K[53]);
        if (!verify_copy(d, b, MASK_D14_COPY)) continue;
        II(c, d, a, b, M1[10], S[54], K[54]);
        if (!verify_copy(c, a, MASK_C14_COPY)) continue;
        II(b, c, d, a, M1[1], S[55], K[55]);
        if (!verify_copy(b, d, MASK_B14_COPY)) continue;
        
        II(a, b, c, d, M1[8], S[56], K[56]);
        if (!verify_copy(a, c, MASK_A15_COPY)) continue;
        II(d, a, b, c, M1[15], S[57], K[57]);
        if (!verify_copy(d, b, MASK_D15_COPY)) continue;
        II(c, d, a, b, M1[6], S[58], K[58]);
        if (!verify_copy(c, a, MASK_C15_COPY)) continue;
        II(b, c, d, a, M1[13], S[59], K[59]);
        if (!verify_diff(b, d, MASK_B15_DIFF)) continue;
        
        II(a, b, c, d, M1[4], S[60], K[60]);
        if (!verify_one(a, MASK_A16_ONE)) continue;
        if (!verify_copy(a, c, MASK_A16_COPY)) continue;
        II(d, a, b, c, M1[11], S[61], K[61]);
        if (!verify_one(d, MASK_D16_ONE)) continue;
        if (!verify_copy(d, b, MASK_D16_COPY)) continue;
        II(c, d, a, b, M1[2], S[62], K[62]);
        II(b, c, d, a, M1[9], S[63], K[63]);

        message_found = true;
    }

    buffer[0] = states[0] + a;
    buffer[1] = states[1] + b;
    buffer[2] = states[2] + c;
    buffer[3] = states[3] + d;
}


void find_collision() {

    std::random_device rd;
    std::mt19937_64 rng(rd());
    
    MD5Context ctx1;
    MD5Context ctx2;

    uint32_t buffer1[4] = {0x52589324, 0x3093d7ca, 0x2a06dc54, 0x20c5be06};
    uint32_t buffer2[4] = {0xd2589324, 0xb293d7ca, 0xac06dc54, 0xa2c5be06};
    
    uint32_t M1[16];
    uint32_t M1p[16];

    bool collision_found = false;

    while (!collision_found) {
        memcpy(ctx1.buffer, buffer1, sizeof(uint32_t) * 4);
        memcpy(ctx2.buffer, buffer2, sizeof(uint32_t) * 4);

        apply_message_modifications(buffer1, ctx1.buffer, M1, rng);

        memcpy(M1p, M1, sizeof(uint32_t) * 16);
        
        M1p[4]  = static_cast<uint32_t>(M1p[4]  + 0x80000000);
        M1p[11] = static_cast<uint32_t>(M1p[11] - 0x8000);
        M1p[14] = static_cast<uint32_t>(M1p[14] + 0x80000000);

        md5Step(ctx2.buffer, M1p);

        if (memcmp(ctx1.buffer, ctx2.buffer, sizeof(uint32_t) * 4) == 0) {

            collision_found = true;
            std::cout << "M1:  ";
            for (size_t i = 0; i < 16; ++i) std::cout << std::hex << M1[i] << " ";
            std::cout << "\nM1': ";
            for (size_t i = 0; i < 16; ++i) std::cout << std::hex << M1p[i] << " ";
            std::cout << std::endl;
        }
    }
}

// bool find_collision_test() {
//     MD5Context ctx1;
//     md5Init(&ctx1);
//     ctx1.buffer[0] = 0x52589324;
//     ctx1.buffer[1] = 0x3093d7ca;
//     ctx1.buffer[2] = 0x2a06dc54;
//     ctx1.buffer[3] = 0x20c5be06;

//     MD5Context ctx2;
//     md5Init(&ctx2);
//     ctx2.buffer[0] = 0xd2589324;
//     ctx2.buffer[1] = 0xb293d7ca;
//     ctx2.buffer[2] = 0xac06dc54;
//     ctx2.buffer[3] = 0xa2c5be06;

//     uint32_t M1_init[16] = 
//     {
//         0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 
//         0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1,
//         0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 
//         0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
//     };

//     uint32_t M1p_init[16] =
//     {
//         0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a,
//         0x479a7335, 0x0cfdebf0, 0x66f12930, 0x8fb109d1,
//         0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79,
//         0xddcb74ed, 0x6dd3c55f, 0x580a9bb1, 0xe3a7cc35
//     };

//     uint32_t M1[16];
//     memcpy(M1, M1_init, sizeof(uint32_t) * 16);

//     uint32_t M1p[16];
//     memcpy(M1p, M1p_init, sizeof(uint32_t) * 16);

//     apply_message_modifications(ctx1.buffer, M1);

//     md5Step(ctx2.buffer, M1p);

//     if (memcmp(ctx1.buffer, ctx2.buffer, 16) == 0) 
//     {
//         return true;    
//     }
//     else
//     {
//         return false;
//     }
// }

// bool find_collision1_test() {
    
//     MD5Context ctx1;
//     MD5Context ctx2;

//     uint32_t buffer1[4] = {0x52589324, 0x3093d7ca, 0x2a06dc54, 0x20c5be06};
//     uint32_t buffer2[4] = {0xd2589324, 0xb293d7ca, 0xac06dc54, 0xa2c5be06};

//     uint32_t M1_init[16] = 
//     {
//         0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 
//         0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1,
//         0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 
//         0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
//     };

//     uint32_t M1[16];
//     uint32_t M1p[16];
    
//     memcpy(ctx1.buffer, buffer1, sizeof(uint32_t) * 4);
//     memcpy(ctx2.buffer, buffer2, sizeof(uint32_t) * 4);

//     memcpy(M1, M1_init, sizeof(uint32_t) * 16);

//     apply_message_modifications(ctx1.buffer, M1);

//     memcpy(M1p, M1, sizeof(uint32_t) * 16);
        
//     M1p[4]  = static_cast<uint32_t>(M1p[4]  + 0x80000000);
//     M1p[11] = static_cast<uint32_t>(M1p[11] - 0x8000);
//     M1p[14] = static_cast<uint32_t>(M1p[14] + 0x80000000);

//     md5Step(ctx2.buffer, M1p);

//     if (memcmp(ctx1.buffer, ctx2.buffer, sizeof(uint32_t)*4) == 0) {
//         std::cout << "M1:  ";
//         for (size_t i = 0; i < 16; ++i) std::cout << std::hex << M1[i] << " ";
//         std::cout << "\nM1': ";
//         for (size_t i = 0; i < 16; ++i) std::cout << std::hex << M1p[i] << " ";
//         std::cout << std::endl;

//         return true;
        
//     }

//     return false;
    
// }