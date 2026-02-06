#include "f2k.hpp"

namespace crypto::fields {

    int F2k::deg(const bInt& n) const {
        if (n == 0) return -1;
        return static_cast<int>(boost::multiprecision::msb(n));
    }

    bInt F2k::reduce(bInt n) const {
        int deg_p = deg(modulus_poly);
        while (deg(n) >= deg_p) {
            int shift = deg(n) - deg_p;
            n ^= (modulus_poly << shift);
        }
        return n;
    }

    void F2k::check_field_compatibility(const F2k& other) const {
        if (modulus_poly != other.modulus_poly) {
            throw std::runtime_error("F2k: Incompatible fields for operation");
        }
    }

    F2k::F2k(const bInt& v, const bInt& mod_poly) : modulus_poly(mod_poly) {
        value = reduce(v);
    }

    F2k::F2k(long long v, const bInt& mod_poly) : F2k(bInt(v), mod_poly) {}

    F2k::F2k() : value(0), modulus_poly(0) {}

    const bInt& F2k::get_value() const { 
        return value; 
    }

    const bInt& F2k::get_modulus() const { 
        return modulus_poly; 
    }

    F2k F2k::operator+(const F2k& other) const {
        check_field_compatibility(other);
        return F2k(value ^ other.value, modulus_poly);
    }

    F2k F2k::operator-(const F2k& other) const {
        return *this + other;
    }

    F2k F2k::operator*(const F2k& other) const {
        check_field_compatibility(other);
        bInt a = value;
        bInt b = other.value;
        bInt res = 0;
        int max_bit = deg(b);
        for (int i = 0; i <= max_bit; ++i) {
            if (boost::multiprecision::bit_test(b, i)) {
                res ^= (a << i);
            }
        }
        return F2k(res, modulus_poly);
    }

    F2k F2k::inv() const {
        if (value == 0)
        {
            throw std::runtime_error("Inverse of zero in F2k");
        }

        bInt A = modulus_poly;
        bInt B = value;

        bInt y = 0;
        bInt s = 1;

        while (B != 0) {
            auto [Q, C] = poly_div_mod(A, B);  // A = Q*B + C

            bInt s_new = y ^ poly_mul(Q, s);

            A = B;
            B = C;

            y = s;
            s = s_new;
        }

        if (A != 1)
            throw std::runtime_error("Element has no inverse");

        return F2k(y % modulus_poly, modulus_poly);
}


    F2k F2k::pow(long long exponent) const {
        F2k result(1, modulus_poly);
        F2k base = *this;
        if (exponent == 0) return result;
        if (exponent < 0) {
            base = base.inv();
            exponent = -exponent;
        }
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = result * base;
            }
            base = base * base;
            exponent /= 2;
        }
        return result;
    }

    F2k F2k::operator/(const F2k& other) const {
        return *this * other.inv();
    }

    bool F2k::operator==(const F2k& other) const { 
        return value == other.value; 
    }

    bool F2k::operator!=(const F2k& other) const { 
        return value != other.value; 
    }

    std::ostream& operator<<(std::ostream& os, const F2k& e) {
        return os << std::hex << "0x" << e.value << std::dec;
    }

    std::pair<bInt, bInt> F2k::poly_div_mod(bInt a, bInt b) const {
        if (b == 0) throw std::runtime_error("Division by zero in poly_div_mod");
        
        bInt quotient = 0;
        int deg_a = deg(a);
        int deg_b = deg(b);

        while (deg_a >= deg_b) {
            int shift = deg_a - deg_b;
            quotient |= (bInt(1) << shift);
            a ^= (b << shift);
            deg_a = deg(a);
        }
        return {quotient, a};
    }

    bInt F2k::poly_mul(bInt a, bInt b) const {
        bInt res = 0;
        for (int i = 0; i <= deg(b); ++i) {
            if (boost::multiprecision::bit_test(b, i)) {
                res ^= (a << i);
            }
        }
        return res;
    }

}