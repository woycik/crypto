#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include "../types.hpp"

namespace crypto::fields {

    class F2k {
    private:
        bInt value;
        bInt modulus_poly;

        int deg(const bInt& n) const;
        bInt reduce(bInt n) const;
        void check_field_compatibility(const F2k& other) const;

    public:
        F2k(const bInt& v, const bInt& mod_poly);
        F2k(long long v, const bInt& mod_poly);
        F2k(const std::string& hex_val, const bInt& m);
        F2k();

        const bInt& get_value() const;
        const bInt& get_modulus() const;
        bInt poly_mul(bInt a, bInt b) const;
        std::pair<bInt, bInt> poly_div_mod(bInt a, bInt b) const;

        F2k operator+(const F2k& other) const;
        F2k operator-(const F2k& other) const;
        F2k operator*(const F2k& other) const;
        F2k operator/(const F2k& other) const;

        F2k inv() const;
        F2k pow(bInt exponent) const;

        bool operator==(const F2k& other) const;
        bool operator!=(const F2k& other) const;

        friend std::ostream& operator<<(std::ostream& os, const F2k& e);
    };

}