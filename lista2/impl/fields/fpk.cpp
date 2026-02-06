#include "fpk.hpp"

namespace crypto::fields {

    Fpk::Fpk(const std::vector<Fp>& c, const std::vector<Fp>& mod_poly_in) 
        : coeffs(c) 
    {
        irreducible_poly = std::make_shared<std::vector<Fp>>(mod_poly_in);
        trim();
        if (!coeffs.empty() && deg() >= static_cast<int>(modulus_poly().size()) - 1) {
            reduce();
        }
    }

    Fpk::Fpk(const std::vector<Fp>& c, std::shared_ptr<std::vector<Fp>> mod_ptr)
        : coeffs(c), irreducible_poly(mod_ptr)
    {
        trim();
        if (mod_ptr && !coeffs.empty() && deg() >= static_cast<int>(mod_ptr->size()) - 1) {
            reduce();
        }
    }

    Fpk::Fpk(const std::vector<bInt>& c, std::shared_ptr<std::vector<Fp>> mod_ptr)
        : irreducible_poly(mod_ptr)
    {
        p = get_p();
        coeffs.reserve(c.size());
        for (const auto& val : c) {
            coeffs.emplace_back(Fp(val, p));
        }
    }

    Fpk::Fpk() : coeffs({}), irreducible_poly(nullptr) {}

    bInt Fpk::get_p() const {
        return modulus_poly()[0].get_modulus();
    }

    int Fpk::deg() const {
        return static_cast<int>(coeffs.size()) - 1;
    }

    const std::vector<Fp>& Fpk::modulus_poly() const {
        if (!irreducible_poly || irreducible_poly->empty()) {
            throw std::runtime_error("Fpk: Uninitialized modulus polynomial");
        }
        return *irreducible_poly;
    }

    void Fpk::check_field_compatibility(const Fpk& other) const {
        if (irreducible_poly != other.irreducible_poly) {
            throw std::runtime_error("Fpk: Incompatible fields for operation");
        }
    }

    void Fpk::trim() {
        while (coeffs.size() > 1 && coeffs.back().get_value() == 0) {
            coeffs.pop_back();
        }
    }

    void Fpk::reduce() {
        if (!irreducible_poly) return;
        const auto& P = modulus_poly();
        int p_deg = static_cast<int>(P.size()) - 1;

        while (deg() >= p_deg) {
            int diff = deg() - p_deg;
            Fp factor = coeffs.back() / P.back();
            for (int i = 0; i <= p_deg; ++i) {
                coeffs[i + diff] = coeffs[i + diff] - (P[i] * factor);
            }
            trim();
        }
    }

    Fpk Fpk::operator+(const Fpk& other) const {
        check_field_compatibility(other);
        std::vector<Fp> res = coeffs;
        const auto& b_coeffs = other.coeffs;
        bInt current_p = get_p();

        if (b_coeffs.size() > res.size()) {
            res.resize(b_coeffs.size(), Fp(bInt(0), current_p));
        }
        
        for (size_t i = 0; i < b_coeffs.size(); ++i) {
            res[i] = res[i] + b_coeffs[i];
        }
        return Fpk(res, irreducible_poly);
    }

    Fpk Fpk::operator-() const {
        std::vector<Fp> res;
        res.reserve(coeffs.size());
        for (const auto& c : coeffs) {
            res.push_back(-c);
        }
        return Fpk(res, irreducible_poly);
    }

    Fpk Fpk::operator-(const Fpk& other) const {
        return *this + (-other); 
    }

    Fpk Fpk::operator*(const Fpk& other) const {
        check_field_compatibility(other);
        bInt current_p = get_p();

        if (coeffs.empty() || other.coeffs.empty()) {
            return Fpk({Fp(bInt(0), current_p)}, irreducible_poly);
        }

        std::vector<Fp> prod(coeffs.size() + other.coeffs.size() - 1, Fp(bInt(0), current_p));
        for (size_t i = 0; i < coeffs.size(); ++i) {
            for (size_t j = 0; j < other.coeffs.size(); ++j) {
                prod[i + j] = prod[i + j] + (coeffs[i] * other.coeffs[j]);
            }
        }
        return Fpk(prod, irreducible_poly);
    }

    std::pair<Fpk, Fpk> Fpk::div_mod(Fpk A, Fpk B) {
        if (B.coeffs.size() == 1 && B.coeffs[0].get_value() == 0) 
            throw std::runtime_error("Div by zero");

        bInt current_p = A.get_p();
        auto poly_ptr = A.irreducible_poly;

        Fpk Q({Fp(bInt(0), current_p)}, poly_ptr); 
        Fpk R = A;

        int b_deg = B.deg();
        Fp b_lead_coeff_inv = B.coeffs.back().inv();

        while (R.deg() >= b_deg && !(R.deg() == 0 && R.coeffs[0].get_value() == 0)) {
            int diff = R.deg() - b_deg;
            Fp factor = R.coeffs.back() * b_lead_coeff_inv;

            std::vector<Fp> temp(diff + 1, Fp(bInt(0), current_p));
            temp.back() = factor;
            
            Fpk temp_poly(temp, poly_ptr);
            Q = Q + temp_poly;
            R = R - (temp_poly * B);
        }
        return {Q, R};
    }

    Fpk Fpk::inv() const {
        if (deg() == 0 && coeffs[0].get_value() == 0) throw std::runtime_error("Inverse of zero");
        bInt current_p = get_p();

        Fpk A({Fp(0, current_p)}, irreducible_poly); 
        A.coeffs = *irreducible_poly; 
        Fpk B = *this;

        Fpk y({Fp(0, current_p)}, irreducible_poly);
        Fpk s({Fp(1, current_p)}, irreducible_poly);

        while (!(B.deg() == 0 && B.coeffs[0].get_value() == 0)) {
            auto [Q, C] = div_mod(A, B);
            Fpk s_new = y - Q * s;
            A = B; 
            B = C;
            y = s; 
            s = s_new;
        }

        if (A.deg() > 0) throw std::runtime_error("GCD not constant");
        return y * Fpk({A.coeffs[0].inv()}, irreducible_poly);
    }

    Fpk Fpk::operator/(const Fpk& other) const {
        return *this * other.inv();
    }

    Fpk Fpk::pow(bInt exp) const {
        bInt current_p = get_p();
        Fpk res({Fp(bInt(1), current_p)}, irreducible_poly);
        Fpk base = *this;

        if (exp < 0) {
            base = base.inv();
            exp = -exp;
        }

        while (exp > 0) {
            if (boost::multiprecision::bit_test(exp, 0)) res = res * base;
            base = base * base;
            exp >>= 1;
        }
        return res;
    }

    bool Fpk::operator==(const Fpk& other) const { 
        return coeffs == other.coeffs; 
    }

    bool Fpk::operator!=(const Fpk& other) const { 
        return !(*this == other); 
    }

    std::ostream& operator<<(std::ostream& os, const Fpk& p) {
        if (p.coeffs.empty()) return os << "0";
        bool first = true;
        for (int i = p.deg(); i >= 0; --i) {
            if (p.coeffs[i].get_value() == 0) continue;
            if (!first) os << " + ";
            os << p.coeffs[i];
            if (i > 0) os << "x";
            if (i > 1) os << "^" << i;
            first = false;
        }
        if (first) os << "0";
        return os;
    }
}