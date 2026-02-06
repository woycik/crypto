#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include <openssl/sha.h>
#include "../impl/algorithms/SchnorrSignature.hpp"
#include "../impl/fields/fp.hpp"
#include "../impl/fields/f2k.hpp"
#include "../impl/curves/f2kCurves.hpp"
#include "../impl/curves/fpCurves.hpp"
#include "../impl/curves/fpkCurves.hpp"

using namespace crypto::fields;
using namespace crypto::algorithms;
using namespace crypto::curves;
using namespace crypto;

TEST_CASE("Fp") {
    
    bInt p("23");
    bInt group_order("11");
    bInt g_val("2");
    
    Fp generator(g_val, p);
    
    SchnorrSignature<Fp> signer(generator, group_order);
    
    auto pubKey = signer.public_key;;

    std::string msg_str = "message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto signature = signer.sign_message(message);
    bInt s = signature.first;
    bInt e = signature.second;

    CHECK(signer.verify_message(message, s, e) == true);

    std::string fake_msg_str = "message2";
    std::vector<uint8_t> fake_message(fake_msg_str.begin(), fake_msg_str.end());
    CHECK(signer.verify_message(fake_message, s, e) == false);

    bInt fake_s = (s + 1) % group_order;
    CHECK(signer.verify_message(message, fake_s, e) == false);
}

TEST_CASE("F2k") {
    
    bInt mod_poly("0x201B"); 
    
    bInt group_order("8191");
    
    bInt g_val("2");

    F2k generator(g_val, mod_poly);
    
    SchnorrSignature<F2k> signer(generator, group_order);
    
    auto pubKey = signer.public_key;
    
    CHECK(signer.private_key > 0);
    CHECK(pubKey.get_value() != 0); 

    std::string msg_str = "message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto signature = signer.sign_message(message);
    bInt s = signature.first;
    bInt e = signature.second;

    CHECK(signer.verify_message(message, s, e) == true);

    std::string fake_msg_str = "message2";
    std::vector<uint8_t> fake_message(fake_msg_str.begin(), fake_msg_str.end());
    CHECK(signer.verify_message(fake_message, s, e) == false);

    bInt fake_s = (s + 1) % group_order;
    CHECK(signer.verify_message(message, fake_s, e) == false);
}

TEST_CASE("F2kCurve") {

    bInt mod_poly("0x800000000000000000000000000000000000000C9");
    
    F2k a(1, mod_poly);
    F2k b(1, mod_poly);

    EllipticCurveBinary curve(a, b);
    
    F2k Gx("0x2FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8", mod_poly);
    F2k Gy("0x289070FB05D38FF58321F2E800536D538CCDAA3D9", mod_poly);

    bInt group_order("0x4000000000000000000020108A2E0CC0D99F8A5EF");

    PointF2k G(Gx, Gy, &curve);

    REQUIRE(G.is_valid() == true);

    SchnorrSignature<PointF2k> signer(G, group_order);
    
    signer.generatePrivateKey();
    auto pubKey = signer.generatePublicKey();
    
    CHECK(pubKey.is_valid() == true);
    
    std::string msg_str = "message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto signature = signer.sign_message(message);
    bInt s = signature.first;
    bInt e = signature.second;

    CHECK(signer.verify_message(message, s, e) == true);
    
    bInt fake_s = (s + 1) % group_order;
    CHECK(signer.verify_message(message, fake_s, e) == false);
}

TEST_CASE("FpCurve") {

    bInt mod("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    
    Fp a(0, mod);
    Fp b(7, mod);

    EllipticCurve curve(a, b);
    
    bInt Gx_hex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    bInt Gy_hex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    bInt group_order("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    PointFp G(Fp(Gx_hex, mod), Fp(Gy_hex, mod), &curve);

    REQUIRE(G.is_valid() == true);

    SchnorrSignature<PointFp> signer(G, group_order);
    
    signer.generatePrivateKey();
    auto pubKey = signer.generatePublicKey();
    
    CHECK(pubKey.is_valid() == true);
    
    std::string msg_str = "message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto signature = signer.sign_message(message);
    bInt s = signature.first;
    bInt e = signature.second;

    CHECK(signer.verify_message(message, s, e) == true);
    
    bInt fake_s = (s + 1) % group_order;
    CHECK(signer.verify_message(message, fake_s, e) == false);
}

TEST_CASE("FpkCurve") {

    bInt p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    auto mod_poly = std::make_shared<std::vector<Fp>>();
    mod_poly->emplace_back(0, p);
    mod_poly->emplace_back(1, p);

    std::vector<Fp> a_coeffs = { Fp(0, p) };
    Fpk a(a_coeffs, mod_poly);

    std::vector<Fp> b_coeffs = { Fp(7, p) };
    Fpk b(b_coeffs, mod_poly);

    EllipticCurveFpk curve(a, b);
    
    Fpk Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", mod_poly);
    Fpk Gy("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", mod_poly);

    bInt group_order("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    PointFpk G(Gx, Gy, &curve);

    REQUIRE(G.is_valid() == true);

    SchnorrSignature<PointFpk> signer(G, group_order);
    
    signer.generatePrivateKey();
    auto pubKey = signer.generatePublicKey();
    
    CHECK(pubKey.is_valid() == true);
    
    std::string msg_str = "message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto signature = signer.sign_message(message);
    bInt s = signature.first;
    bInt e = signature.second;

    CHECK(signer.verify_message(message, s, e) == true);
    
    bInt fake_s = (s + 1) % group_order;
    CHECK(signer.verify_message(message, fake_s, e) == false);
}

TEST_CASE("FpCurve GitHub (secp256k1)") {
    
    bInt p_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    bInt n_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    Fp a(0, p_hex);
    Fp b(7, p_hex);

    EllipticCurve curve(a, b);

    bInt Gx_hex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    bInt Gy_hex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    PointFp G(Fp(Gx_hex, p_hex), Fp(Gy_hex, p_hex), &curve);

    bInt x_vec("0xbed123a21c0e50b003d302e83e755a444cbd436dfc4ea6635696c49499e47da6");
    
    bInt k_vec("0x6dfb9c259dc3b79f03470418af01cb1e064692dacc353f0f656cad0bfec583a7");

    bInt e_vec("0x64821fe9a06c9daa280f7ac4182e82e18b6e0fba1eefb8620a434289aaee9560");

    bInt s_expected("0x154f020e7841eab3507bf3bb1b0b2cdc4e0ee413c380098096128171c26c2ee0");

    PointFp X_calc = G.pow(x_vec);

    bInt expected_Xx("0x7f032a1e20deb84dc51d44cd11657c4a4d3c6bccb19c05cfd5b4b007e8a478d3");
    bInt expected_Xy("0x56e3dcb493aa83b590954d6c33cdfd20ef4b083d33b051efda091486035a4a69");

    CHECK(X_calc.x.get_value() == expected_Xx);
    CHECK(X_calc.y.get_value() == expected_Xy);
    PointFp R_calc = G.pow(k_vec);

    bInt expected_Rx("0x83b62cb5324d37f5ad971ce99fda0d8e2a922407df6fa9b73dea4835b7fdb1dc");
    bInt expected_Ry("0xef1f1211e51938e79f9c0b6929f1da6feba68f2dd48db68adc4539f39d9fa52e");

    CHECK(R_calc.x.get_value() == expected_Rx);
    CHECK(R_calc.y.get_value() == expected_Ry);
    
    bInt s_calc = (k_vec + (e_vec * x_vec)) % n_hex;
    
    CHECK(s_calc == s_expected);

    PointFp LHS = G.pow(s_expected);

    PointFp eX = X_calc.pow(e_vec);
    
    PointFp RHS = R_calc * eX; 

    CHECK(LHS.x.get_value() == RHS.x.get_value());
    CHECK(LHS.y.get_value() == RHS.y.get_value());
    
    bInt expected_sG_x("0xcc83cf2ae222fb66ece196534d6608fba8ee0faef867e0f94ab7ecb225b44e4f");
    CHECK(LHS.x.get_value() == expected_sG_x);
}


TEST_CASE("FpCurve GitHub (secp256k1)") {
    
    bInt p_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    bInt n_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    Fp a(0, p_hex);
    Fp b(7, p_hex);

    EllipticCurve curve(a, b);

    bInt Gx_hex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    bInt Gy_hex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    PointFp G(Fp(Gx_hex, p_hex), Fp(Gy_hex, p_hex), &curve);

    bInt x_vec("0xbed123a21c0e50b003d302e83e755a444cbd436dfc4ea6635696c49499e47da6");
    
    bInt k_vec("0x6dfb9c259dc3b79f03470418af01cb1e064692dacc353f0f656cad0bfec583a7");

    bInt e_vec("0x64821fe9a06c9daa280f7ac4182e82e18b6e0fba1eefb8620a434289aaee9560");

    bInt s_expected("0x154f020e7841eab3507bf3bb1b0b2cdc4e0ee413c380098096128171c26c2ee0");

    PointFp X_calc = G.pow(x_vec);

    bInt expected_Xx("0x7f032a1e20deb84dc51d44cd11657c4a4d3c6bccb19c05cfd5b4b007e8a478d3");
    bInt expected_Xy("0x56e3dcb493aa83b590954d6c33cdfd20ef4b083d33b051efda091486035a4a69");

    CHECK(X_calc.x.get_value() == expected_Xx);
    CHECK(X_calc.y.get_value() == expected_Xy);
    PointFp R_calc = G.pow(k_vec);

    bInt expected_Rx("0x83b62cb5324d37f5ad971ce99fda0d8e2a922407df6fa9b73dea4835b7fdb1dc");
    bInt expected_Ry("0xef1f1211e51938e79f9c0b6929f1da6feba68f2dd48db68adc4539f39d9fa52e");

    CHECK(R_calc.x.get_value() == expected_Rx);
    CHECK(R_calc.y.get_value() == expected_Ry);
    
    bInt s_calc = (k_vec + (e_vec * x_vec)) % n_hex;
    
    CHECK(s_calc == s_expected);

    PointFp LHS = G.pow(s_expected);

    PointFp eX = X_calc.pow(e_vec);
    
    PointFp RHS = R_calc * eX; 

    CHECK(LHS.x.get_value() == RHS.x.get_value());
    CHECK(LHS.y.get_value() == RHS.y.get_value());
    
    bInt expected_sG_x("0xcc83cf2ae222fb66ece196534d6608fba8ee0faef867e0f94ab7ecb225b44e4f");
    CHECK(LHS.x.get_value() == expected_sG_x);
}



TEST_CASE("translate_r formatting") {

    bInt mod_poly("19");
    
    F2k val(5, mod_poly);
    
    bInt dummy_order("15");
    SchnorrSignature<F2k> signer(val, dummy_order);

    std::string json = signer.translate_r(val);
    
    CHECK(json == "\"05\""); 
}

TEST_CASE("translate_r formatting for Fp") {

    bInt p("17"); 
    bInt dummy_n("10");

    Fp val_small(5, p);
    Fp val_max(16, p);
    Fp val_zero(0, p); 

    SchnorrSignature<Fp> signer(val_zero, dummy_n);

    CHECK(signer.translate_r(val_small) == "\"05\"");
    CHECK(signer.translate_r(val_max)   == "\"10\"");
    CHECK(signer.translate_r(val_zero)  == "\"00\"");

    bInt p_large("257");
    Fp val_L(10, p_large);

    SchnorrSignature<Fp> signer_L(val_L, dummy_n);
    
    CHECK(signer_L.translate_r(val_L) == "\"000A\"");
}

TEST_CASE("translate_r formatting for F2k") {
    bInt poly8("0x11B"); 
    bInt dummy_n("10");

    F2k val(5, poly8);
    SchnorrSignature<F2k> signer8(val, dummy_n);
    CHECK(signer8.translate_r(val) == "\"05\"");

    bInt poly9("0x203");
    F2k val9(5, poly9);
    
    SchnorrSignature<F2k> signer9(val9, dummy_n);
    CHECK(signer9.translate_r(val9) == "\"0005\"");
}

TEST_CASE("Schnorr - translate_r formatting for Fpk") {
    bInt p("17");
    bInt dummy_n("10");

    auto mod_poly = std::make_shared<std::vector<Fp>>();
    mod_poly->emplace_back(1, p);
    mod_poly->emplace_back(0, p);
    mod_poly->emplace_back(1, p);

    std::vector<Fp> c1 = { Fp(5, p), Fp(3, p) };
    Fpk val1(c1, mod_poly);

    SchnorrSignature<Fpk> signer(val1, dummy_n);

    CHECK(signer.translate_r(val1) == "[\"05\",\"03\"]");

    std::vector<Fp> c2 = { Fp(10, p) };
    Fpk val2(c2, mod_poly);

    CHECK(signer.translate_r(val2) == "[\"0A\",\"00\"]");
}

TEST_CASE("Schnorr - translate_r formatting for Points (Curve)") {
    bInt p("17");
    Fp a(0, p); 
    Fp b(7, p);
    EllipticCurve curve(a, b);
    bInt dummy_n("10");

    Fp x(3, p);
    Fp y(5, p);
    PointFp P(x, y, &curve);

    SchnorrSignature<PointFp> signer(P, dummy_n);

    CHECK(signer.translate_r(P) == "{\"x\":\"03\",\"y\":\"05\"}");

    PointFp Inf = PointFp::make_infinity(&curve);
    CHECK(signer.translate_r(Inf) == "{\"x\":\"00\",\"y\":\"00\"}");
}

TEST_CASE("Schnorr - translate_r formatting for PointFpk (Nested)") {
    
    bInt p("17");
    auto mod_poly = std::make_shared<std::vector<Fp>>();
    mod_poly->emplace_back(1, p); 
    mod_poly->emplace_back(0, p);
    mod_poly->emplace_back(1, p);

    Fpk X({Fp(3,p)}, mod_poly); 
    std::vector<Fp> cy = {Fp(2, p), Fp(5, p)};
    Fpk Y(cy, mod_poly);

    EllipticCurveFpk curve(X, Y);
    PointFpk P(X, Y, &curve);

    bInt dummy_n("10");
    SchnorrSignature<PointFpk> signer(P, dummy_n);

    std::string expected = "{\"x\":[\"03\",\"00\"],\"y\":[\"02\",\"05\"]}";
    
    CHECK(signer.translate_r(P) == expected);
}