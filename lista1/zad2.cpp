#include "md5.h"

#include <iostream>


void convert_to_big_endian(uint8_t digest1[16])
{
    for (int i = 0; i < 16; i += 4)
    {
        uint8_t tmp0 = digest1[i];
        uint8_t tmp1 = digest1[i+1];
        uint8_t tmp2 = digest1[i+2];
        uint8_t tmp3 = digest1[i+3];

        digest1[i] = tmp3;
        digest1[i+1] = tmp2;
        digest1[i+2] = tmp1;
        digest1[i+3] = tmp0;
    }
}


int main() {

    uint32_t M0[16] = {
        0x2dd31d1, 0xc4eee6c5, 0x69a3d69, 0x5cf9af98,
        0x87b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8,
        0x634ad55, 0x2b3f409, 0x8388e483, 0x5a417125,
        0xe8255108,0x9fc9cdf7, 0xf2bd1dd9, 0x5b3c3780
    };

    uint32_t M1[16] = {
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a, 
        0xc79a7335, 0xcfdebf0, 0x66f12930, 0x8fb109d1,
        0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c15cc79, 
        0xddcb74ed, 0x6dd3c55f, 0xd80a9bb1, 0xe3a7cc35
    };

    uint32_t M0p[16] = {
        0x02dd31d1, 0xc4eee6c5, 0x069a3d69, 0x5cf9af98,
        0x07b5ca2f, 0xab7e4612, 0x3e580440, 0x897ffbb8,
        0x0634ad55, 0x02b3f409, 0x8388e483, 0x5a41f125,
        0xe8255108, 0x9fc9cdf7, 0x72bd1dd9, 0x5b3c3780
    };

    uint32_t M1p[16] = {
        0xd11d0b96, 0x9c7b41dc, 0xf497d8e4, 0xd555655a,
        0x479a7335, 0x0cfdebf0, 0x66f12930, 0x8fb109d1,
        0x797f2775, 0xeb5cd530, 0xbaade822, 0x5c154c79,
        0xddcb74ed, 0x6dd3c55f, 0x580a9bb1, 0xe3a7cc35
    };

    uint8_t digest1[16], digest2[16];
    MD5Context ctx1;
    MD5Context ctx2;

    md5Init(&ctx1);
    md5Step(ctx1.buffer, M0);
    md5Step(ctx1.buffer, M1);

    memcpy(digest1, ctx1.buffer, 4 * sizeof(uint32_t));

    md5Init(&ctx2);
    md5Step(ctx2.buffer, M0p);
    md5Step(ctx2.buffer, M1p);

    memcpy(digest2, ctx2.buffer, 4 * sizeof(uint32_t));

    convert_to_big_endian(digest1);
    convert_to_big_endian(digest2);

    if (memcmp(digest1, digest2, 16) == 0) 
    {
        printf("Collision found: \n");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x", digest1[i]);
        }
        printf("\n");

    } 
    else 
    {
        printf("No collision found\n");
    }
    return 0;
}