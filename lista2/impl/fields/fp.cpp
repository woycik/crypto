#include "fp.hpp"

namespace crypto::fields
{
    Fp::Fp(const bInt& v, const bInt& modulus) : p(modulus) {
        value = v % p;
        if (value < 0)
        {
            value += p;
        } 
    }

    Fp::Fp(long long v, const bInt& modulus) : Fp(bInt(v), modulus) {}

    Fp::Fp() : value(bInt(0)), p(bInt(1)) {}

    const bInt& Fp::get_value() const { 
        return value; 
    }

    const bInt& Fp::get_modulus() const { 
        return p; 
    }

    void Fp::check_field_compatibility(const Fp& other) const {
        if (p != other.p) {
            throw std::runtime_error("Fp: Incompatible fields for operation");
        }
    }

    Fp Fp::operator+(const Fp& other) const {
        check_field_compatibility(other);
        bInt res = value + other.value;
        if (res >= p)
        {
            res -= p;
        }
        return Fp(res, p);
    }

    Fp Fp::operator-() const {
        if (value == 0)
        {
            return Fp(bInt(0), p);
        }
        return Fp(p - value, p);
    }

    Fp Fp::operator-(const Fp& other) const {
        check_field_compatibility(other);
        bInt res = value - other.value;
        if (res < 0)
        {
            res += p;
        }    
        return Fp(res, p);
    }

    Fp Fp::operator*(const Fp& other) const {
        check_field_compatibility(other);
        bInt res = (value * other.value) % p;
        return Fp(res, p);
    }

    Fp Fp::inv() const {
        if (value == 0) throw std::runtime_error("Division by zero in Fp");
        return Fp(crypto::modular_inverse(value, p), p);
    }

    Fp Fp::operator/(const Fp& other) const {
        check_field_compatibility(other);
        return *this * other.inv();
    }

    Fp Fp::pow(bInt exp) const {
        Fp res(bInt(1), p);
        Fp base = *this;

        if (exp < 0) {
            base = base.inv();
            exp = -exp;
        }

        while (exp > 0) {
            if (boost::multiprecision::bit_test(exp, 0)) 
            {
                res = res * base;
            }
            base = base * base;
            exp >>= 1;
        }
        return res;
    }

    bool Fp::operator==(const Fp& other) const { 
        check_field_compatibility(other);
        return value == other.value; 
    }
    
    bool Fp::operator!=(const Fp& other) const { 
        check_field_compatibility(other);
        return value != other.value; 
    }

    std::ostream& operator<<(std::ostream& os, const Fp& e) {
        return os << e.value;
    }
}