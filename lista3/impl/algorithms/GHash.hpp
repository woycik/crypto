#pragma once

#include <vector>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include "../types.hpp"
#include "../fields/f2k.hpp"

using namespace crypto::fields;

namespace crypto::algorithms {
    
    using bInt = boost::multiprecision::cpp_int;

    class GHash {
    private:
        F2k H; 
        bInt R;
        
        bInt multiply(bInt X, bInt Y) {
            bInt Z = 0;
            bInt V = Y; 
            for (int i = 0; i < 128; ++i) {
                if (boost::multiprecision::bit_test(X, 127 - i)) {
                    Z ^= V;
                }
                bool lsb_is_set = boost::multiprecision::bit_test(V, 0);
                V >>= 1;
                if (lsb_is_set) {
                    V ^= R;
                }
            }
            return Z;
        }

        void process_stream(bInt& Y, bInt stream, uint64_t bit_len, bInt H_val) {
            uint64_t remaining_bits = bit_len;

            while (remaining_bits > 0) 
            {
                uint64_t chunk_size = (remaining_bits >= 128) ? 128 : remaining_bits;
                
                uint64_t shift = remaining_bits - chunk_size;
                bInt block = (stream >> shift);

                if (chunk_size < 128) 
                { 
                    bInt mask = (bInt(1) << chunk_size) - 1;
                    block &= mask;
                } 
                else
                {
                    block &= ((bInt(1) << 128) - 1);
                }

                if (chunk_size < 128) {
                    block <<= (128 - chunk_size);
                }

                Y ^= block;
                Y = multiply(Y, H_val);

                remaining_bits -= chunk_size;
            }
        }

    public:
        GHash(const F2k& h_key) : H(h_key), R("0xE1000000000000000000000000000000") {}

        F2k calculate(bInt A_full, uint64_t A_bit_len, bInt C_full, uint64_t C_bit_len) 
        {
            bInt H_val = H.get_value();
            bInt mod_poly = H.get_modulus();
            
            bInt Y_val = 0; 

            process_stream(Y_val, A_full, A_bit_len, H_val);
            process_stream(Y_val, C_full, C_bit_len, H_val);

            bInt len_block = (bInt(A_bit_len) << 64) | bInt(C_bit_len);
            
            Y_val ^= len_block;
            Y_val = multiply(Y_val, H_val);

            return F2k(Y_val, mod_poly);
        }
    };
}