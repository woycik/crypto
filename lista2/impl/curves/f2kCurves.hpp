#pragma once
#include "../types.hpp"
#include "../fields/f2k.hpp"

namespace crypto::curves {
    
    using namespace crypto::fields;

    struct PointF2k {
        F2k x;
        F2k y;
        bool is_infinity;

        PointF2k(F2k x, F2k y) : x(x), y(y), is_infinity(false) {}
        
        PointF2k(bool is_inf, const F2k& ctx) 
            : x(0, ctx.get_modulus()), 
              y(0, ctx.get_modulus()), 
              is_infinity(is_inf) 
        {}

        bool operator==(const PointF2k& other) const {
            if (is_infinity != other.is_infinity) return false;
            if (is_infinity) return true;
            return (x == other.x) && (y == other.y);
        }

        bool operator!=(const PointF2k& other) const {
            return !(*this == other);
        }
    };

    class EllipticCurveBinary {
    public:
        F2k a;
        F2k b;

        EllipticCurveBinary(F2k a, F2k b) : a(a), b(b) {}

        PointF2k infinity() const {
            return PointF2k(true, a);
        }

        bool is_on_curve(const PointF2k& P) const {
            if (P.is_infinity) 
            {
                return true;
            }
            
            F2k left = P.y.pow(2) + (P.x * P.y);
            F2k right = P.x.pow(3) + (a * P.x.pow(2)) + b;
            
            return left == right;
        }

        PointF2k add(const PointF2k& P, const PointF2k& Q) const {
            if (P.is_infinity) return Q;
            if (Q.is_infinity) return P;

            if (P.x == Q.x && P.y != Q.y) {
                return infinity();
            }

            if (P != Q) {
                F2k m = (Q.y + P.y) / (Q.x + P.x);
                F2k x3 = m.pow(2) + m + P.x + Q.x + a;
                F2k y3 = m * (P.x + x3) + x3 + P.y;
                return PointF2k(x3, y3);
            } 
            else 
            {
                if (P.x.get_value() == 0) return infinity();

                F2k m = P.x + (P.y / P.x);
                F2k x3 = m.pow(2) + m + a;
                
                F2k one(1, a.get_modulus());
                
                F2k y3 = P.x.pow(2) + (m + one) * x3;
                return PointF2k(x3, y3);
            }
        }

        PointF2k inv(const PointF2k& P) const {
            if (P.is_infinity) return P;
            return PointF2k(P.x, P.x + P.y);
        }
    };
}