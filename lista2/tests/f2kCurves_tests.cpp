#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "../impl/curves/f2kCurves.hpp" 

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

TEST_CASE("GF(2^3)") {
    bInt poly(11); 
    F2k a(1, poly);
    F2k b(4, poly);
    EllipticCurveBinary curve(a, b);

    F2k x(2, poly);
    F2k y(3, poly);
    PointF2k G(x, y);
    PointF2k O = curve.infinity();

    REQUIRE(curve.is_on_curve(G) == true);

    PointF2k res1 = curve.add(G, O);
    CHECK((res1 == G));

    PointF2k negG = curve.inv(G);
    CHECK(curve.is_on_curve(negG) == true);
    CHECK((negG.x == G.x));
    CHECK((negG.y == (G.x + G.y)));

    PointF2k sum_zero = curve.add(G, negG);
    CHECK((sum_zero == O));

    PointF2k G2 = curve.add(G, G);
    CHECK(curve.is_on_curve(G2) == true);
}