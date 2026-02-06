#pragma once
#include "../types.hpp"
#include "../fields/f2k.hpp"
#include <stdexcept>

namespace crypto::curves {
    
    using namespace crypto::fields;

    // -----------------------------------------------------------
    // 1. KLASA KRZYWEJ (Musi być pierwsza!)
    // -----------------------------------------------------------
    // Zawiera tylko dane, żadnej logiki zależnej od Punktu.
    class EllipticCurveBinary {
    public:
        F2k a;
        F2k b;

        EllipticCurveBinary(F2k a, F2k b) : a(a), b(b) {}
    };

    // -----------------------------------------------------------
    // 2. STRUKTURA PUNKTU (Logika inline wewnątrz)
    // -----------------------------------------------------------
    struct PointF2k {
        F2k x;
        F2k y;
        bool is_infinity;
        const EllipticCurveBinary* curve_params;

        // --- Konstruktory ---
        
        // Domyślny
        PointF2k() : is_infinity(true), curve_params(nullptr) {}    

        // Zwykły
        PointF2k(F2k x, F2k y, const EllipticCurveBinary* curve) 
            : x(x), y(y), is_infinity(false), curve_params(curve) {}

        // Pomocniczy (np. do tworzenia infinity z kontekstem)
        PointF2k(bool is_inf, const F2k& ctx, const EllipticCurveBinary* curve) 
            : x(0, ctx.get_modulus()), 
              y(0, ctx.get_modulus()), 
              is_infinity(is_inf),
              curve_params(curve)
        {}

        // --- Operatory Porównania ---

        bool operator==(const PointF2k& other) const {
            if (is_infinity != other.is_infinity) return false;
            if (is_infinity) return true;
            return (x == other.x) && (y == other.y);
        }

        bool operator!=(const PointF2k& other) const {
            return !(*this == other);
        }

        // --- Metody Logiczne (Wszystko w środku!) ---

        // Helper statyczny do tworzenia elementu neutralnego
        static PointF2k make_infinity(const EllipticCurveBinary* curve) {
            if (!curve) return PointF2k();
            // Przekazujemy 'a' tylko po to, by konstruktor wyciągnął modulus
            return PointF2k(true, curve->a, curve);
        }

        // Sprawdzenie poprawności punktu
        bool is_valid() const {
            if (is_infinity) return true;
            if (!curve_params) return false; 

            // Kompilator zna już 'EllipticCurveBinary', więc widzi pola 'a' i 'b'
            F2k left = y.pow(2) + (x * y);
            F2k right = x.pow(3) + (curve_params->a * x.pow(2)) + curve_params->b;
            
            return left == right;
        }

        // Odwrotność (-P)
        PointF2k invert() const {
            if (is_infinity) return *this;
            if (!curve_params) throw std::runtime_error("PointF2k: Missing curve context");
            
            // -P = (x, x+y)
            return PointF2k(x, x + y, curve_params);
        }

        // Dodawanie (P + Q)
        PointF2k operator+(const PointF2k& other) const {
            if (!curve_params) throw std::runtime_error("PointF2k: Missing curve context");
            
            if (is_infinity) return other;
            if (other.is_infinity) return *this;

            if (x == other.x && y != other.y) {
                return make_infinity(curve_params);
            }

            if (*this != other) {
                // Różne punkty
                F2k m = (y + other.y) / (x + other.x);
                F2k x3 = m.pow(2) + m + x + other.x + curve_params->a;
                F2k y3 = m * (x + x3) + x3 + y;
                return PointF2k(x3, y3, curve_params);
            } 
            else {
                // Podwajanie (P == Q)
                if (x.get_value() == 0) return make_infinity(curve_params);

                F2k m = x + (y / x);
                F2k x3 = m.pow(2) + m + curve_params->a;
                F2k one(1, curve_params->a.get_modulus());
                F2k y3 = x.pow(2) + (m + one) * x3;
                
                return PointF2k(x3, y3, curve_params);
            }
        }

        // Mnożenie skalarne (P * k)
        PointF2k operator*(const bInt& k_in) const {
            if (!curve_params) throw std::runtime_error("PointF2k: Missing curve context");

            PointF2k R = make_infinity(curve_params);
            PointF2k Q = *this;
            bInt k = k_in;

            if (k < 0) {
                Q = Q.invert();
                k = -k;
            }

            while (k > 0) {
                if ((k & 1)) R = R + Q;
                Q = Q + Q;
                k >>= 1;
            }
            return R;
        }

        PointF2k operator*(const PointF2k& other) const {
            return *this + other;
        }

        // Alias pow (dla kompatybilności)
        PointF2k pow(const bInt& k) const { 
            return (*this) * k; 
        }
    };

} // namespace crypto::curves