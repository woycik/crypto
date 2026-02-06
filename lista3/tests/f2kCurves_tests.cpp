#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "../impl/curves/f2kCurves.hpp" 

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

TEST_CASE("F(2^3)") {
    bInt poly(11); 
    F2k a(1, poly);
    F2k b(4, poly);
    EllipticCurveBinary curve(a, b);

    F2k x(2, poly);
    F2k y(3, poly);
    PointF2k G(x, y, &curve);
    PointF2k O = PointF2k::make_infinity(&curve);

    REQUIRE(G.is_valid() == true);

    PointF2k res1 = G + O;
    CHECK((res1 == G));

    PointF2k negG = G.invert();
    CHECK(negG.is_infinity == true);
    CHECK((negG.x == G.x));
    CHECK((negG.y == (G.x + G.y)));

    PointF2k sum_zero = G + negG;
    CHECK((sum_zero == O));

    PointF2k G2 = G + G;
    CHECK(G2.is_valid() == true);
}