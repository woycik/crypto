#pragma once
#include "types.hpp"

namespace crypto {

    inline bInt extended_gcd(bInt a, bInt b, bInt &x, bInt &y) {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        bInt x1, y1;
        bInt gcd = extended_gcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return gcd;
    }

    inline bInt modular_inverse(bInt a, bInt m) {
        bInt x, y;
        bInt g = extended_gcd(a, m, x, y);
        
        if (g != 1) {
            throw std::runtime_error("Modular inverse does not exist (gcd != 1)");
        }
        
        bInt res = (x % m + m) % m;
        return res;
    }
}