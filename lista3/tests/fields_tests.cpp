#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "./../impl/fields/fp.hpp"
#include "./../impl/fields/fpk.hpp"
#include "./../impl/fields/f2k.hpp"

using namespace crypto;
using namespace crypto::fields;

TEST_CASE("1") {
    bInt p(13);
    Fp a(10, p), b(5, p), c(2, p);

    CHECK((a + b).get_value() == 2);
    CHECK((c + c).get_value() == 4);
    CHECK((b - a).get_value() == 8);
    CHECK((c - b).get_value() == 10);
    CHECK((a * b).get_value() == 11);
    CHECK((a * c).get_value() == 7);

    Fp inv_b = b.inv();
    CHECK(inv_b.get_value() == 8);
    CHECK((b * inv_b).get_value() == 1);

    Fp inv_c = c.inv();
    CHECK(inv_c.get_value() == 7);
    CHECK((c * inv_c).get_value() == 1);

    Fp zero(0, p);
    CHECK_THROWS(zero.inv());
}

TEST_CASE("2") {
    bInt p(7);
    auto poly_ptr = std::make_shared<std::vector<Fp>>(std::vector<Fp>{Fp(1, p), Fp(0, p), Fp(1, p)});

    Fpk a(std::vector<Fp>{Fp(2, p), Fp(3, p)}, poly_ptr);
    Fpk b(std::vector<Fp>{Fp(1, p), Fp(4, p)}, poly_ptr);

    Fpk sum = a + b;
    CHECK(sum.coeffs.size() >= 1);
    CHECK(sum.coeffs[0].get_value() == 3);
    if (sum.coeffs.size() > 1) CHECK(sum.coeffs[1].get_value() == 0);

    Fpk prod = a * b;
    CHECK(prod.coeffs.size() >= 2);
    CHECK(prod.coeffs[0].get_value() == 4);
    CHECK(prod.coeffs[1].get_value() == 4);

    Fpk inv_a = a.inv();
    Fpk check_inv = a * inv_a;
    CHECK(check_inv.coeffs[0].get_value() == 1);
    if (check_inv.coeffs.size() > 1) CHECK(check_inv.coeffs[1].get_value() == 0);

    Fpk check_div = (a / b) * b;
    CHECK(check_div == a);
}

TEST_CASE("3") {
    bInt poly(11); // 1011 = x^3 + x + 1

    CHECK(F2k(8, poly).get_value() == 3);

    F2k a(5, poly), b(3, poly);
    CHECK((a + b).get_value() == 6);

    F2k c(2, poly);
    CHECK((c * c).get_value() == 4);

    F2k d(4, poly);
    CHECK((d * c).get_value() == 3);

    F2k inv_c = c.inv();
    CHECK(inv_c.get_value() == 5);
    CHECK((c * inv_c).get_value() == 1);

    CHECK((d / c).get_value() == 2);
}