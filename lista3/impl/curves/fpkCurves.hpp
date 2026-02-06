#pragma once
#include "../types.hpp"
#include "../fields/fpk.hpp"
#include "../fields/fp.hpp"
#include <stdexcept>

namespace crypto::curves {

    using namespace crypto::fields;
    
    // -----------------------------------------------------------
    // 1. KLASA KRZYWEJ (Kontener danych)
    // -----------------------------------------------------------
    class EllipticCurveFpk {
    public:
        Fpk a;
        Fpk b;
        
        EllipticCurveFpk(Fpk a, Fpk b) : a{a}, b{b} {};
    };

    // -----------------------------------------------------------
    // 2. STRUKTURA PUNKTU (Logika inline)
    // -----------------------------------------------------------
    struct PointFpk {
        Fpk x;
        Fpk y;
        bool is_infinity;
        const EllipticCurveFpk* curve_params;

        // --- Konstruktory ---

        // Domyślny (Infinity)
        PointFpk() : is_infinity(true), curve_params(nullptr) {}

        // Zwykły
        PointFpk(Fpk x, Fpk y, const EllipticCurveFpk* curve = nullptr) 
            : x(x), y(y), is_infinity(false), curve_params(curve) {}
        
        // Pomocniczy (tworzenie infinity z kontekstem ciała)
        PointFpk(bool is_inf, const Fpk& ctx, const EllipticCurveFpk* curve = nullptr) 
            : x(std::vector<Fp>{Fp(0, ctx.get_p())}, ctx.irreducible_poly),
              y(std::vector<Fp>{Fp(0, ctx.get_p())}, ctx.irreducible_poly),
              is_infinity(is_inf),
              curve_params(curve)
        {}

        // --- Operatory Porównania ---

        bool operator==(const PointFpk& other) const {
            if (is_infinity != other.is_infinity) return false;
            if (is_infinity) return true;
            return (x == other.x) && (y == other.y);
        }

        bool operator!=(const PointFpk& other) const {
            return !(*this == other);
        }

        // --- Metody Logiczne ---

        // Helper statyczny do tworzenia elementu neutralnego
        static PointFpk make_infinity(const EllipticCurveFpk* curve) {
            if (!curve) return PointFpk();
            // Przekazujemy 'a' z krzywej, by wyciągnąć kontekst (p i wielomian)
            return PointFpk(true, curve->a, curve);
        }

        // Walidacja: y^2 = x^3 + ax + b
        bool is_valid() const {
            if (is_infinity) return true;
            if (!curve_params) return false;

            Fpk left = y.pow(2);
            Fpk right = x.pow(3) + (curve_params->a * x) + curve_params->b;
            return left == right;
        }

        // Odwrotność (-P) = (x, -y)
        PointFpk invert() const {
            if (is_infinity) return *this;
            if (!curve_params) throw std::runtime_error("PointFpk: Missing curve context");
            return PointFpk(x, -y, curve_params);
        }

        // Dodawanie (P + Q)
        PointFpk operator+(const PointFpk& other) const {
            if (!curve_params) throw std::runtime_error("PointFpk: Missing curve context");

            if (is_infinity) return other;
            if (other.is_infinity) return *this;

            // P + (-P) = 0
            if (x == other.x && y == (-other.y)) {
                return make_infinity(curve_params);
            }

            // Pobieramy kontekst z parametru 'a' krzywej, żeby tworzyć stałe (2, 3)
            bInt p = curve_params->a.get_p();
            auto poly_ctx = curve_params->a.irreducible_poly;

            // Różne punkty (P != Q)
            if (*this != other) {
                // Jeśli x są równe, to pionowa linia (ale y nie są przeciwne -> dziwne, ale infinity)
                if (x == other.x) return make_infinity(curve_params);

                Fpk num = other.y - y;
                Fpk den = other.x - x;
                Fpk lambda = num / den;

                Fpk x3 = lambda.pow(2) - x - other.x;                
                Fpk y3 = lambda * (x - x3) - y;

                return PointFpk(x3, y3, curve_params);
            } 
            else // Podwajanie (P == Q)
            {
                // Sprawdzenie czy y == 0 (w Fpk sprawdzamy czy współczynniki są zerowe/puste)
                if (y.coeffs.empty() || (y.deg() == 0 && y.coeffs[0].get_value() == 0)) {
                    return make_infinity(curve_params);
                }

                // Tworzymy stałe w ciele Fpk
                Fpk three({Fp(3, p)}, poly_ctx);
                Fpk two({Fp(2, p)}, poly_ctx);

                // lambda = (3x^2 + a) / (2y)
                Fpk num = three * x.pow(2) + curve_params->a;
                Fpk den = two * y;
                Fpk lambda = num / den;

                Fpk x3 = lambda.pow(2) - (two * x);                
                Fpk y3 = lambda * (x - x3) - y;

                return PointFpk(x3, y3, curve_params);
            }
        }

        // Mnożenie skalarne (P * k)
        PointFpk operator*(const bInt& k_in) const {
            if (!curve_params) throw std::runtime_error("PointFpk: Missing curve context");

            PointFpk R = make_infinity(curve_params);
            PointFpk Q = *this;
            bInt k = k_in;

            if (k < 0) {
                Q = Q.invert();
                k = -k;
            }

            while (k > 0) {
                if ((k & 1)) {
                    R = R + Q;
                }
                Q = Q + Q;
                k >>= 1;
            }
            return R;
        }

        // Alias dla Schnorra (Operacja grupowa)
        PointFpk operator*(const PointFpk& other) const {
            return *this + other;
        }

        // Alias dla pow
        PointFpk pow(const bInt& k) const {
            return (*this) * k;
        }
    };

} // namespace crypto::curves