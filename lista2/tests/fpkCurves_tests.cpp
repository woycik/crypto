#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "../impl/fields/fp.hpp"
#include "../impl/fields/fpk.hpp"
#include "../impl/curves/fpkCurves.hpp"

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

TEST_CASE("GF(7^2)") {
    bInt p(7);
    auto poly = std::make_shared<std::vector<Fp>>(std::vector<Fp>{Fp(1, p), Fp(0, p), Fp(1, p)});
    
    Fpk a({0}, poly);
    Fpk b({1}, poly);
    EllipticCurve curve(a, b);

    Fpk x({0}, poly);
    Fpk y({1}, poly);
    Point G(x, y);
    Point O = curve.infinity();

    REQUIRE(curve.is_on_curve(G) == true);

    Point res1 = curve.add(G, O);
    CHECK((res1 == G));

    Point res2 = curve.add(O, G);
    CHECK((res2 == G));

    Point res3 = curve.add(O, O);
    CHECK((res3 == O));

    Point negG = curve.inv(G);
    CHECK(curve.is_on_curve(negG) == true);
    CHECK((negG.x == G.x));
    CHECK((negG.y == -G.y));

    Point sum_zero = curve.add(G, negG);
    CHECK((sum_zero == O));

    Point G2 = curve.add(G, G);
    CHECK(curve.is_on_curve(G2) == true);
    CHECK((G2 != O));

    Point G3_a = curve.add(G, G2);
    Point G3_b = curve.add(G2, G);
    CHECK((G3_a == G3_b));
    CHECK(curve.is_on_curve(G3_a) == true);
}