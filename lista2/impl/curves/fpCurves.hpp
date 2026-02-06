#pragma once
#include "../types.hpp"
#include "../fields/fpk.hpp"
#include "../fields/fp.hpp"

namespace crypto::curves {

    using namespace crypto::fields;
    
    struct Point {
        Fp x;
        Fp y;
        bool is_infinity;

        Point(Fpk x, Fpk y) : x(x), y(y), is_infinity(false) {}
        
        Point(bool is_inf, const Fp& ctx) 
            : x(Fp(0, ctx.get_p())),
              y(Fp(0, ctx.get_p())),
              is_infinity(is_inf) 
        {}

        bool operator==(const Point& other) const {
            if (is_infinity != other.is_infinity) return false;
            if (is_infinity) return true;
            return (x == other.x) && (y == other.y);
        }

        bool operator!=(const Point& other) const {
            return !(*this == other);
        }
    };

    class EllipticCurve{
        
        public:
            Fp a;
            Fp b;
            EllipticCurve(Fp a, Fp b) : a{a}, b{b} {};

            Point infinity() const {
                return Point(true, a);
            }

            bool is_on_curve(const Point& P) const {
                if (P.is_infinity) return true;
                
                Fp left = P.y.pow(2);
                Fp right = P.x.pow(3) + a * P.x + b;
                
                return left == right;
            }

            
        Point add(const Point& P, const Point& Q) const {
            if (P.is_infinity) return Q;
            if (Q.is_infinity) return P;

            if (P.x == Q.x && P.y == (-Q.y)) {
                return infinity();
            }

            bInt p = a.get_p();
            auto poly_ctx = a.irreducible_poly;

            if (P != Q) {

                if (P.x == Q.x) return infinity();

                Fp num = Q.y - P.y;
                Fp den = Q.x - P.x;
                
                Fp lambda = num / den;

                Fp x3 = lambda.pow(2) - P.x - Q.x;                
                Fp y3 = lambda * (P.x - x3) - P.y;

                return Point(x3, y3);
            } 
            else 
            {

                if (P.y.coeffs.empty() || (P.y.deg() == 0 && P.y.coeffs[0].get_value() == 0)) {
                    return infinity();
                }

                Fp three({Fp(3, p)}, poly_ctx);
                Fp two({Fp(2, p)}, poly_ctx);

                Fp num = three * P.x.pow(2) + a;
                Fp den = two * P.y;

                Fp lambda = num / den;

                Fp x3 = lambda.pow(2) - (two * P.x);                
                Fp y3 = lambda * (P.x - x3) - P.y;

                return Point(x3, y3);
            }
        }

        Point inv(const Point& P) const {
            if (P.is_infinity) return P;
            return Point(P.x, -P.y);
        }
        
    };
}