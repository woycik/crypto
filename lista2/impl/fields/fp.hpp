#pragma once

#include <iostream>
#include <stdexcept>
#include "../types.hpp"
#include "../utils.hpp"

namespace crypto::fields
{
    class Fp {
    private:
        bInt value;
        bInt p;

    public:
        Fp(const bInt& v, const bInt& modulus);
        Fp(long long v, const bInt& modulus);
        Fp();

        const bInt& get_value() const;
        const bInt& get_modulus() const;

        void check_field_compatibility(const Fp& other) const;

        Fp operator+(const Fp& other) const;
        Fp operator-() const;
        Fp operator-(const Fp& other) const;
        Fp operator*(const Fp& other) const;
        Fp operator/(const Fp& other) const;

        Fp inv() const;
        Fp pow(bInt exp) const;

        bool operator==(const Fp& other) const;
        bool operator!=(const Fp& other) const;

        friend std::ostream& operator<<(std::ostream& os, const Fp& e);
    };
}