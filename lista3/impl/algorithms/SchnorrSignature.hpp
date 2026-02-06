#pragma once

#include <vector>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <type_traits>
#include <openssl/sha.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <random>

#include "../types.hpp"
#include "../fields/f2k.hpp"
#include "../fields/fp.hpp"
#include "../fields/fpk.hpp" 

using namespace crypto::fields;

namespace crypto::algorithms {

template <typename AlgebraicStructure>    
class SchnorrSignature {
public:
    SchnorrSignature(const AlgebraicStructure& generator, const bInt& group_order)
        : g(generator), n(group_order) 
        {
            private_key = generate_random_value_in_range(1, n - 1);
            public_key = generatePublicKey();
        }

    ~SchnorrSignature() = default;

    bInt private_key;
    AlgebraicStructure public_key;
    AlgebraicStructure g;
    bInt n;

    // 1. Klucz publiczny y = g^x (ZGODNE Z KOLEGĄ)
    AlgebraicStructure generatePublicKey()
    {
        public_key = g.pow(private_key);
        return public_key;
    }

    bInt generatePrivateKey() {
        private_key = generate_random_value_in_range(1, n - 1);
        return private_key;
    }

    std::pair<bInt, bInt> sign_message(const std::vector<uint8_t>& M)
    {
        bInt k = generate_random_value_in_range(1, n - 1);
        
        AlgebraicStructure r(g.pow(k));

        std::string encoded_r = translate_r(r);
        
        std::vector<uint8_t> full_input(encoded_r.begin(), encoded_r.end());
        full_input.insert(full_input.end(), M.begin(), M.end());

        unsigned char hash[32];
        SHA256(full_input.data(), full_input.size(), hash);

        // e pobieramy BEZ modulo (patrz niżej)
        bInt e = get_hash_value_from_bytes(hash);

        // 2. Podpis z ODEJMOWANIEM (s = k - xe) (ZGODNE Z KOLEGĄ)
        bInt x_e = (private_key * e) % n;
        bInt s;

        // 3. Bezpieczne odejmowanie (ZGODNE Z KOLEGĄ)
        // Dzięki temu nie ma znaczenia, czy bInt jest signed czy unsigned.
        if (k >= x_e) {
            s = k - x_e;
        } else {
            s = n - (x_e - k);
        }

        return std::make_pair(s, e);
    }

    bool verify_message(const std::vector<uint8_t>& M, const bInt& s, const bInt& e)
    {
        // Weryfikacja: R' = g^s * y^e = g^(k-xe) * g^(xe) = g^k
        AlgebraicStructure rv(g.pow(s) * public_key.pow(e));        
        std::string encoded_rv = translate_r(rv);
        
        std::vector<uint8_t> full_input(encoded_rv.begin(), encoded_rv.end());
        full_input.insert(full_input.end(), M.begin(), M.end());

        unsigned char hash[32];
        SHA256(full_input.data(), full_input.size(), hash);

        bInt e_new = get_hash_value_from_bytes(hash);

        return e_new == e;
    }

    // Helper (Publiczny dla main.cpp)
    std::string to_padded_hex(const bInt& val, size_t target_hex_chars) {
        std::stringstream ss;
        ss << std::hex << val; // Lowercase
        std::string hex = ss.str();
        
        if (hex.size() >= 2 && hex.substr(0, 2) == "0x") hex = hex.substr(2);
        else if (hex.size() >= 2 && hex.substr(0, 2) == "0X") hex = hex.substr(2);

        if (hex.length() < target_hex_chars) {
            hex.insert(0, target_hex_chars - hex.length(), '0');
        } 
        
        return hex;
    }

private:
    bInt generate_random_value_in_range(const bInt& min, const bInt& max) {
        boost::random::mt19937 gen(std::random_device{}());        
        boost::random::uniform_int_distribution<bInt> dist(min, max);
        return dist(gen);
    }

public:
    template <typename T>
    std::string translate_r(const T& structure)
    {
        if constexpr (std::is_same_v<T, Fp>) {
            bInt p = structure.get_modulus();
            size_t bit_len = static_cast<size_t>(boost::multiprecision::msb(p)) + 1;
            size_t byte_len = (bit_len + 7) / 8;
            return "\"" + to_padded_hex(structure.get_value(), byte_len * 2) + "\"";
        }
        else if constexpr (std::is_same_v<T, F2k>) {
            bInt poly = structure.get_modulus();
            size_t m = static_cast<size_t>(boost::multiprecision::msb(poly)); 
            size_t byte_len = (m + 7) / 8;
            return "\"" + to_padded_hex(structure.get_value(), byte_len * 2) + "\"";
        }
        else if constexpr (std::is_same_v<T, Fpk>) {
            std::stringstream ss;
            ss << "[";
            
            // WAŻNE: W Twoim JSON 'modulus' ma rozmiar k (dla extension=8 ma 8 el.).
            // Więc k = size(), a nie size()-1.
            size_t k = 0;
            if (structure.irreducible_poly) {
                k = structure.irreducible_poly->size(); 
            } else {
                // Fallback, jeśli z jakiegoś powodu brak pointera (nie powinno się zdarzyć)
                k = structure.coeffs.size();
            }

            // Padding liczymy względem BAZY ciała (p_base), a nie rzędu grupy!
            bInt p = structure.get_p();
            size_t bit_len = static_cast<size_t>(boost::multiprecision::msb(p)) + 1;
            size_t byte_len = (bit_len + 7) / 8;
            size_t target_len = byte_len * 2;

            for(size_t i = 0; i < k; ++i) {
                bInt val = 0;
                // Jeśli współczynnik istnieje, bierzemy go. Jeśli nie (wielomian niższego stopnia), zostaje 0.
                if(i < structure.coeffs.size()) {
                    val = structure.coeffs[i].get_value();
                }
                
                ss << "\"" << to_padded_hex(val, target_len) << "\"";
                
                if(i < k - 1) ss << ",";
            }
            ss << "]";
            return ss.str();
        }
        else {
            if (structure.is_infinity) {
                return "{\"x\":\"00\",\"y\":\"00\"}"; 
            }
            std::string x_json = translate_r(structure.x);
            std::string y_json = translate_r(structure.y);
            std::stringstream ss;
            ss << "{\"x\":" << x_json << ",\"y\":" << y_json << "}";
            return ss.str();
        }
    }

    bInt get_hash_value_from_bytes(const unsigned char* hash)
    {
        bInt res = 0;
        for (int i = 0; i < 32; ++i) {
            res = (res << 8) | hash[i];
        }
        // 4. USUNIĘTO MODULO (ZGODNE Z KOLEGĄ)
        // Kolega używa import_bits i zwraca surową liczbę.
        // My też musimy zwrócić pełny hash, bo jest on częścią podpisu {s, e}.
        return res; 
    }

    bInt get_hash_value_from_bytes(const std::vector<uint8_t>& hash_vec) {
        return get_hash_value_from_bytes(hash_vec.data());
    }
};

} // namespace crypto::algorithms