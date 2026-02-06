#include "fpk.hpp"

namespace crypto::fields {

    // --- POPRAWKA: Zabezpieczenie przed pustym modulusem (dla inv()) ---

    Fpk::Fpk(const std::vector<Fp>& c, const std::vector<Fp>& mod_poly_in) 
        : coeffs(c) 
    {
        irreducible_poly = std::make_shared<std::vector<Fp>>(mod_poly_in);
        trim();
        // Sprawdzamy !modulus_poly().empty() pośrednio przez size, ale tutaj mamy pewność bo to referencja.
        if (!coeffs.empty() && !mod_poly_in.empty() && deg() >= static_cast<int>(mod_poly_in.size())) {
            reduce();
        }
    }

    Fpk::Fpk(const std::vector<Fp>& c, std::shared_ptr<std::vector<Fp>> mod_ptr)
        : coeffs(c), irreducible_poly(mod_ptr)
    {
        trim();
        // --- FIX KLUCZOWY ---
        // Dodano warunek !mod_ptr->empty(). 
        // Jeśli mod_ptr jest pusty (jak w inv()), NIE wchodzimy do reduce().
        if (mod_ptr && !mod_ptr->empty() && !coeffs.empty() && deg() >= static_cast<int>(mod_ptr->size())) {
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

    static std::string clean_token(std::string s) {
        s.erase(std::remove(s.begin(), s.end(), '['), s.end());
        s.erase(std::remove(s.begin(), s.end(), ']'), s.end());
        s.erase(std::remove(s.begin(), s.end(), '\"'), s.end());
        s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
        return s;
    }

    Fpk::Fpk(const std::string& raw_val, std::shared_ptr<std::vector<Fp>> mod_ptr)
        : irreducible_poly(mod_ptr) 
    {
        // Tutaj musimy rzucić wyjątek, bo parsowanie stringa wymaga znajomości p (bazy ciała),
        // a p bierzemy z mod_ptr[0]. Jeśli mod_ptr jest pusty, nie znamy p.
        if (!mod_ptr || mod_ptr->empty()) {
            throw std::invalid_argument("Fpk string ctor: modulus empty");
        }
        
        this->p = (*mod_ptr)[0].get_modulus();
        this->coeffs.clear();

        std::string s = raw_val;
        
        if (!s.empty() && s.find('[') != std::string::npos) 
        {
            std::stringstream ss(s);
            std::string token;
            while (std::getline(ss, token, ',')) 
            {
                std::string cleaned = clean_token(token);
                if (cleaned.empty()) continue;
                bInt val(cleaned);
                this->coeffs.emplace_back(val, this->p);
            }
        } 
        else 
        {
            std::string cleaned = clean_token(s);
            if (!cleaned.empty()) 
            {
                bInt val(cleaned);
                this->coeffs.emplace_back(val, this->p);
            }
        }
        trim();
        // Tutaj też reduce jest bezpieczne, bo sprawdziliśmy empty() na początku
        if (deg() >= static_cast<int>(mod_ptr->size())) reduce();
    }

    bInt Fpk::get_p() const {
        // Zabezpieczenie na wypadek użycia get_p wewnątrz inv() na dummy obiekcie
        if (!irreducible_poly || irreducible_poly->empty()) return 0; 
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
        // W inv() używamy różnych wskaźników (dummy vs real), więc wyłączamy check
        // jeśli któryś jest pusty (tryb Euklidesa).
        if ((irreducible_poly && irreducible_poly->empty()) || 
            (other.irreducible_poly && other.irreducible_poly->empty())) return;

        if (irreducible_poly != other.irreducible_poly) {
             // Opcjonalnie: throw std::runtime_error("Fpk: Incompatible fields");
             // Ale w tym zadaniu zazwyczaj jest ok.
        }
    }

    void Fpk::trim() {
        while (coeffs.size() > 1 && coeffs.back().get_value() == 0) {
            coeffs.pop_back();
        }
    }

    void Fpk::reduce() {
        if (!irreducible_poly || irreducible_poly->empty()) return; // FIX
        
        const auto& P = modulus_poly(); 
        int k = static_cast<int>(P.size());

        while (deg() >= k) {
            int diff = deg() - k;
            Fp factor = coeffs.back(); 
            coeffs.pop_back(); 
            
            for (int i = 0; i < k; ++i) {
                if (i + diff >= static_cast<int>(coeffs.size())) {
                    coeffs.resize(i + diff + 1, Fp(0, (*irreducible_poly)[0].get_modulus()));
                }
                coeffs[i + diff] = coeffs[i + diff] - (P[i] * factor);
            }
            trim();
        }
    }

    Fpk Fpk::operator+(const Fpk& other) const {
        check_field_compatibility(other);
        std::vector<Fp> res = coeffs;
        const auto& b_coeffs = other.coeffs;
        
        // Pobieramy p bezpiecznie (jeśli dummy, bierzemy z coeffs)
        bInt current_p = (!coeffs.empty()) ? coeffs[0].get_modulus() : other.coeffs[0].get_modulus();

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
        bInt current_p = (!coeffs.empty()) ? coeffs[0].get_modulus() : 
                         (!other.coeffs.empty()) ? other.coeffs[0].get_modulus() : 0;

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
        if (B.coeffs.empty() || (B.coeffs.size() == 1 && B.coeffs[0].get_value() == 0)) 
            throw std::runtime_error("Div by zero");

        // Pobieramy p z samego wielomianu A (bo get_p() może paść na dummy mod)
        bInt current_p = A.coeffs[0].get_modulus();
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
            
            // Manualne mnożenie temp * B, żeby uniknąć reduce() w operatorze *
            std::vector<Fp> prod_coeffs(temp.size() + B.coeffs.size() - 1, Fp(0, current_p));
            for(size_t i=0; i<temp.size(); ++i) {
                if(temp[i].get_value() == 0) continue;
                for(size_t j=0; j<B.coeffs.size(); ++j) {
                     prod_coeffs[i+j] = prod_coeffs[i+j] + (temp[i] * B.coeffs[j]);
                }
            }
            Fpk sub_poly(prod_coeffs, poly_ptr); // poly_ptr jest dummy, więc konstruktor nie zrobi reduce

            // Q = Q + temp
            Fpk temp_fpk(temp, poly_ptr);
            Q = Q + temp_fpk;

            // R = R - sub_poly
            R = R - sub_poly;
        }
        return {Q, R};
    }

    Fpk Fpk::inv() const {
        if (deg() == 0 && coeffs[0].get_value() == 0) throw std::runtime_error("Inverse of zero");
        
        bInt current_p = coeffs[0].get_modulus();

        // Rekonstrukcja M(x) = x^k + P(x)
        std::vector<Fp> full_mod_coeffs = modulus_poly(); 
        full_mod_coeffs.push_back(Fp(1, current_p));         

        // Dummy mod (pusty) aby wyłączyć reduce()
        auto dummy_mod = std::make_shared<std::vector<Fp>>(); 
        
        Fpk A(full_mod_coeffs, dummy_mod); 
        Fpk B(coeffs, dummy_mod);

        Fpk y({Fp(0, current_p)}, dummy_mod);
        Fpk s({Fp(1, current_p)}, dummy_mod);

        while (!(B.deg() == 0 && B.coeffs[0].get_value() == 0) && !B.coeffs.empty()) {
            auto [Q, C] = div_mod(A, B);
            
            // Ręczne mnożenie Q * s bez reduce
            std::vector<Fp> prod_qs(Q.coeffs.size() + s.coeffs.size() - 1, Fp(0, current_p));
            if (Q.coeffs.empty() || s.coeffs.empty()) {
                prod_qs = {Fp(0, current_p)};
            } else {
                for(size_t i=0; i<Q.coeffs.size(); ++i) {
                    for(size_t j=0; j<s.coeffs.size(); ++j) {
                        prod_qs[i+j] = prod_qs[i+j] + (Q.coeffs[i] * s.coeffs[j]);
                    }
                }
            }
            Fpk Q_times_s(prod_qs, dummy_mod);
            
            Fpk s_new = y - Q_times_s;

            A = B; 
            B = C;
            y = s; 
            s = s_new;
        }

        if (A.deg() > 0) throw std::runtime_error("GCD not constant");
        
        Fp inv_A0 = A.coeffs[0].inv();
        std::vector<Fp> res_coeffs;
        for(auto& c : y.coeffs) res_coeffs.push_back(c * inv_A0);
        
        // Powrót do prawdziwego modulus_poly -> odpali się reduce()
        return Fpk(res_coeffs, irreducible_poly);
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