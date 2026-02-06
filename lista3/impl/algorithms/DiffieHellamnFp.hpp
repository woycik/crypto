#pragma once

#include <iostream>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include "../types.hpp"

namespace crypto::algorithms {

template <typename AlgebraicObject>
class DiffieHellman {
public:

    DiffieHellman(const AlgebraicObject& generator, const bInt& group_order) 
        : g(generator), n(group_order) {}

    ~DiffieHellman() = default;

    bInt generatePrivateKey() {
        private_key = generate_random_value_in_range(1, n - 1);
        return private_key;
    }

    AlgebraicObject generatePublicKey() {
        public_key = g.pow(private_key);
        return public_key;
    }

    AlgebraicObject computeSharedSecret(const AlgebraicObject& other_public_key) {
        shared_secret = other_public_key.pow((private_key));
        return shared_secret;
    }

    AlgebraicObject getPublicKey() const { return public_key; }
    AlgebraicObject getSharedSecret() const { return shared_secret; }
    bInt getPrivateKey() const { return private_key; }
    void setPrivateKey(bInt value) { private_key = value; }

    AlgebraicObject public_key;
    AlgebraicObject shared_secret;
    
private:
    AlgebraicObject g;
    bInt n;
    bInt private_key;

    bInt generate_random_value_in_range(const bInt& min, const bInt& max) {
        boost::random::mt19937 gen(std::random_device{}());        
        boost::random::uniform_int_distribution<bInt> dist(min, max);
        return dist(gen);
    }
};

} // namespace crypto::algorithms