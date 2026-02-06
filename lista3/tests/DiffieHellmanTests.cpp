#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "./../impl/fields/fp.hpp"
#include "./../impl/fields/fpk.hpp"
#include "./../impl/fields/f2k.hpp"
#include "./../impl/curves/f2kCurves.hpp"
#include "./../impl/curves/fpCurves.hpp"
#include "./../impl/curves/fpkCurves.hpp"
#include "./../impl/algorithms/DiffieHellamnFp.hpp"

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

using namespace crypto::fields;
using namespace crypto::algorithms;


TEST_CASE("Alice-Bob test with Jakub Musiał") {
    bInt p("65063");
    
    Fp g(2, p);
    
    bInt order(32531);

    DiffieHellman<Fp> alice(g, order);

    alice.setPrivateKey(bInt(24243));
    
    Fp alice_pub = alice.generatePublicKey();

    Fp pk_kuba_musial(25421, p);
    
    Fp secret_alice = alice.computeSharedSecret(pk_kuba_musial);

    CHECK(secret_alice.get_value() == bInt(48008));
}

TEST_CASE("Alice-Bob test with Jakub Musiał input in real time") {
    bInt p("65063");
    Fp g(2, p);
    bInt order(32531);

    DiffieHellman<Fp> alice(g, order);

    alice.generatePrivateKey();
    Fp alice_pub = alice.generatePublicKey();
    std::cout << alice_pub << std::endl;

    std::string input_str;
    std::cout << "Enter pub key: ";

    if (!(std::cin >> input_str)) {
        FAIL("No pub key");
    }

    bInt kuba_val(input_str);
    Fp pk_kuba_musial(kuba_val, p);
    
    Fp secret_alice = alice.computeSharedSecret(pk_kuba_musial);
    std::cout <<secret_alice << std::endl;

}

TEST_CASE("F(2^4)") {

    bInt modulus("19");
    
    F2k g(2, modulus);
    bInt order("15");

    DiffieHellman<F2k> alice(g, order);
    DiffieHellman<F2k> bob(g, order);

    bInt sk_alice = alice.generatePrivateKey();
    bInt sk_bob = bob.generatePrivateKey();

    CHECK(sk_alice > 0);
    CHECK(sk_alice < order);

    F2k pk_alice = alice.generatePublicKey();
    F2k pk_bob = bob.generatePublicKey();

    CHECK(pk_alice.get_modulus() == modulus);

    F2k secret_alice = alice.computeSharedSecret(pk_bob);
    F2k secret_bob = bob.computeSharedSecret(pk_alice);

    CHECK(secret_alice == secret_bob);
}

TEST_CASE("basic") {
    bInt modulus("19");
    bInt order("15");
    F2k g(2, modulus);

    DiffieHellman<F2k> dh(g, order);
    
    bInt alice_priv = 3; 
    bInt bob_priv = 5;

    F2k alice_pub = g.pow(3);
    CHECK(alice_pub.get_value() == 8);

    F2k bob_pub = g.pow(5);
    CHECK(bob_pub.get_value() == 6);

    F2k shared_a = bob_pub.pow(3);
    F2k shared_b = alice_pub.pow(5);

    CHECK(shared_a.get_value() == 1);
    CHECK(shared_b.get_value() == 1);
    CHECK(shared_a == shared_b);
}


TEST_CASE("Fp") {

    bInt p("23");
    
    Fp g(5, p);
    bInt order("22");

    DiffieHellman<Fp> alice(g, order);
    DiffieHellman<Fp> bob(g, order);

    bInt sk_alice = alice.generatePrivateKey();
    bInt sk_bob = bob.generatePrivateKey();

    Fp pk_alice = alice.generatePublicKey();
    Fp pk_bob = bob.generatePublicKey();

    CHECK(pk_alice.get_modulus() == p);

    Fp secret_alice = alice.computeSharedSecret(pk_bob);
    Fp secret_bob = bob.computeSharedSecret(pk_alice);

    CHECK(secret_alice == secret_bob);
}

TEST_CASE("F(3^2)") {

    bInt p("3");

    std::vector<Fp> poly_coeffs;
    poly_coeffs.emplace_back(1, p);
    poly_coeffs.emplace_back(0, p);
    poly_coeffs.emplace_back(1, p);
    
    auto modulus_poly = std::make_shared<std::vector<Fp>>(poly_coeffs);

    std::vector<bInt> g_coeffs = {1, 1}; 
    
    Fpk g(g_coeffs, modulus_poly);

    bInt order("8");

    DiffieHellman<Fpk> alice(g, order);
    DiffieHellman<Fpk> bob(g, order);

    alice.generatePrivateKey();
    bob.generatePrivateKey();

    Fpk pk_alice = alice.generatePublicKey();
    Fpk pk_bob = bob.generatePublicKey();

    Fpk secret_alice = alice.computeSharedSecret(pk_bob);
    Fpk secret_bob = bob.computeSharedSecret(pk_alice);

    CHECK(secret_alice == secret_bob);

}

TEST_CASE("E(F2^4)") {
    bInt mod_poly("19");
    F2k a(0, mod_poly);
    F2k b(1, mod_poly);
    crypto::curves::EllipticCurveBinary curve(a, b);

    F2k px(0, mod_poly);
    F2k py(1, mod_poly);
    
    crypto::curves::PointF2k P(px, py, &curve);

    CHECK(P.is_valid() == true);

    SUBCASE("Diffie-Hellman Integration") {
        bInt order("20");

        DiffieHellman<crypto::curves::PointF2k> alice(P, order);
        DiffieHellman<crypto::curves::PointF2k> bob(P, order);

        alice.generatePrivateKey();
        bob.generatePrivateKey();

        auto ss_a = alice.computeSharedSecret(bob.generatePublicKey());
        auto ss_b = bob.computeSharedSecret(alice.generatePublicKey());

        CHECK(ss_a == ss_b);
        CHECK(ss_a.is_valid() == true);
    }
}