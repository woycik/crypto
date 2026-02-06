#pragma once
#include "../types.hpp"
#include "../fields/fpk.hpp"
#include "../fields/fp.hpp"
#include <stdexcept>

namespace crypto::curves {

    using namespace crypto::fields;
    

    class EllipticCurve {
    public:
        Fp a;
        Fp b;
        
        EllipticCurve(Fp a, Fp b) : a(a), b(b) {};
    };

    struct PointFp {
        Fp x;
        Fp y;
        bool is_infinity;
        const EllipticCurve* curve_params;


        PointFp() : is_infinity(true), curve_params(nullptr) {}

        PointFp(Fp x, Fp y, const EllipticCurve* curve = nullptr) 
            : x(x), y(y), is_infinity(false), curve_params(curve) {}

        PointFp(bool is_inf, const Fp& ctx, const EllipticCurve* curve = nullptr) 
            : x(Fp(0, ctx.get_modulus())),
              y(Fp(0, ctx.get_modulus())),
              is_infinity(is_inf),
              curve_params(curve)
        {}

        bool operator==(const PointFp& other) const {
            if (is_infinity != other.is_infinity) return false;
            if (is_infinity) return true;
            return (x == other.x) && (y == other.y);
        }

        bool operator!=(const PointFp& other) const {
            return !(*this == other);
        }


        static PointFp make_infinity(const EllipticCurve* curve) {
            if (!curve) return PointFp();
            return PointFp(true, curve->a, curve);
        }

        bool is_valid() const {
            if (is_infinity) return true;
            if (!curve_params) return false;
            
            Fp left = y.pow(2);
            Fp right = x.pow(3) + (curve_params->a * x) + curve_params->b;
            
            return left == right;
        }

        PointFp invert() const {
            if (is_infinity) return *this;
            if (!curve_params) throw std::runtime_error("PointFp: Missing curve context");
            return PointFp(x, -y, curve_params);
        }

        PointFp operator+(const PointFp& other) const {
            if (!curve_params) throw std::runtime_error("PointFp: Missing curve context");

            if (is_infinity) return other;
            if (other.is_infinity) return *this;

            if (x == other.x && y == (-other.y)) {
                return make_infinity(curve_params);
            }

            bInt p = curve_params->a.get_modulus();

            // Różne punkty (P != Q i nie są odwrotnością)
            if (*this != other) {
                // Jeśli x są równe, ale y nie są przeciwne (i nie są równe, bo weszliśmy w if P!=Q),
                // to w ciele Fp jest to sytuacja niemożliwa dla poprawnych punktów na krzywej,
                // chyba że y=0, ale wtedy P==Q. Dla bezpieczeństwa zwracamy infinity.
                if (x == other.x) return make_infinity(curve_params);

                // lambda = (y2 - y1) / (x2 - x1)
                Fp num = other.y - y;
                Fp den = other.x - x;
                Fp lambda = num / den;

                // x3 = lambda^2 - x1 - x2
                Fp x3 = lambda.pow(2) - x - other.x;                
                // y3 = lambda * (x1 - x3) - y1
                Fp y3 = lambda * (x - x3) - y;

                return PointFp(x3, y3, curve_params);
            } 
            else // Podwajanie (P == Q)
            {
                // Jeśli y = 0, styczna jest pionowa -> punkt w nieskończoności
                if (y.get_value() == 0) {
                    return make_infinity(curve_params);
                }

                Fp three(3, p);
                Fp two(2, p);

                // lambda = (3x^2 + a) / (2y)
                Fp num = three * x.pow(2) + curve_params->a;
                Fp den = two * y;
                Fp lambda = num / den;

                // x3 = lambda^2 - 2x
                Fp x3 = lambda.pow(2) - (two * x);                
                // y3 = lambda * (x - x3) - y
                Fp y3 = lambda * (x - x3) - y;

                return PointFp(x3, y3, curve_params);
            }
        }

        // Mnożenie skalarne (P * k)
        PointFp operator*(const bInt& k_in) const {
            if (!curve_params) throw std::runtime_error("PointFp: Missing curve context");

            PointFp R = make_infinity(curve_params);
            PointFp Q = *this;
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

        PointFp operator*(const PointFp& other) const {
            return *this + other;
        }

        PointFp pow(const bInt& k) const {
            return (*this) * k;
        }
    };

} // namespace crypto::curves