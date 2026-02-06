#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include <vector>
#include <string>
#include <boost/multiprecision/cpp_int.hpp>

#include "./../impl/fields/f2k.hpp"
#include "./../impl/algorithms/GHash.hpp"

using namespace crypto::algorithms;
using namespace crypto::fields;


bInt hexToBigInt(const std::string& hex) {
    if (hex.empty()) return 0;
    return bInt("0x" + hex);
}

TEST_CASE("Basic") {
    bInt gcm_modulus("0x100000000000000000000000000000087");

    std::string H_hex = "66e94bd4ef8a2c3b884cfa59ca342b2e";
    bInt H_val = hexToBigInt(H_hex);
    
    F2k H_elem(H_val, gcm_modulus);
    GHash ghash(H_elem);

    SUBCASE("Test Case 1 (Empty)") {
        std::string A_hex = "";
        std::string C_hex = "";
        
        bInt A = hexToBigInt(A_hex);
        bInt C = hexToBigInt(C_hex);
        
        F2k result = ghash.calculate(A, A_hex.length() * 4, C, C_hex.length() * 4);
        
        std::string expected_hex = "00000000000000000000000000000000";
        bInt expected_val = hexToBigInt(expected_hex);
        F2k expected(expected_val, gcm_modulus);

        CHECK(result == expected);
    }

    SUBCASE("Test Case 2") {
        std::string A_hex = "";
        std::string C_hex = "0388dace60b6a392f328c2b971b2fe78";
        
        bInt A = hexToBigInt(A_hex);
        bInt C = hexToBigInt(C_hex);
        
        F2k result = ghash.calculate(A, A_hex.length() * 4, C, C_hex.length() * 4);
        
        std::string expected_hex = "f38cbb1ad69223dcc3457ae5b6b0f885";
        bInt expected_val = hexToBigInt(expected_hex);
        F2k expected(expected_val, gcm_modulus);

        CHECK(result == expected);
    }
}

TEST_CASE("Test case 4") {
    bInt gcm_modulus("0x100000000000000000000000000000087");

    std::string H_hex = "b83b533708bf535d0aa6e52980d53b78";
    bInt H_val = hexToBigInt(H_hex);
    
    F2k H_elem(H_val, gcm_modulus);
    GHash ghash(H_elem);

    std::string A_hex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    std::string C_hex = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";

    bInt A = hexToBigInt(A_hex);
    bInt C = hexToBigInt(C_hex);

    F2k result = ghash.calculate(A, A_hex.length() * 4, C, C_hex.length() * 4);

    std::string expected_hex = "698e57f70e6ecc7fd9463b7260a9ae5f";
    bInt expected_val = hexToBigInt(expected_hex);
    F2k expected(expected_val, gcm_modulus);

    CHECK(result == expected);
}

TEST_CASE("Test case 5") {
    bInt gcm_modulus("0x100000000000000000000000000000087");

    std::string H_hex = "b83b533708bf535d0aa6e52980d53b78";
    bInt H_val = hexToBigInt(H_hex);
    
    F2k H_elem(H_val, gcm_modulus);
    GHash ghash(H_elem);

    std::string A_hex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    std::string C_hex = "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598";

    bInt A = hexToBigInt(A_hex);
    bInt C = hexToBigInt(C_hex);

    F2k result = ghash.calculate(A, A_hex.length() * 4, C, C_hex.length() * 4);

    std::string expected_hex = "df586bb4c249b92cb6922877e444d37b";
    bInt expected_val = hexToBigInt(expected_hex);
    F2k expected(expected_val, gcm_modulus);

    CHECK(result == expected);
}