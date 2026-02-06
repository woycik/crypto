#pragma once

#include <vector>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <memory>
#include <string>
#include <utility>
#include "../types.hpp"
#include "fp.hpp"

namespace crypto::fields {

    class Fpk {
    public:
        std::vector<Fp> coeffs;
        std::shared_ptr<std::vector<Fp>> irreducible_poly;
        bInt p;

        Fpk(const std::vector<Fp>& c, const std::vector<Fp>& mod_poly_in);
        Fpk(const std::vector<Fp>& c, std::shared_ptr<std::vector<Fp>> mod_ptr);
        Fpk(const std::vector<bInt>& c, std::shared_ptr<std::vector<Fp>> mod_ptr);
        Fpk();
        Fpk(const std::string& hex_val, std::shared_ptr<std::vector<Fp>> mod_ptr);

        bInt get_p() const;
        int deg() const;

        Fpk operator+(const Fpk& other) const;
        Fpk operator-() const;
        Fpk operator-(const Fpk& other) const;
        Fpk operator*(const Fpk& other) const;
        Fpk operator/(const Fpk& other) const;

        Fpk inv() const;
        Fpk pow(bInt exp) const;

        static std::pair<Fpk, Fpk> div_mod(Fpk A, Fpk B);

        bool operator==(const Fpk& other) const;
        bool operator!=(const Fpk& other) const;

        friend std::ostream& operator<<(std::ostream& os, const Fpk& p);

    private:
        const std::vector<Fp>& modulus_poly() const;
        void check_field_compatibility(const Fpk& other) const;
        void trim();
        void reduce();
    };

}