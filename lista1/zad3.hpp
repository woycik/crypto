#ifndef ZAD31_HPP
#define ZAD31_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <stdexcept>
#include <atomic>

extern uint32_t M0p[16];
extern uint32_t M0[16];
extern uint32_t M1[16];
extern uint32_t M1p[16];

inline uint32_t rol(uint32_t x, unsigned s) { return (x << s) | (x >> (32 - s)); }
inline uint32_t ror(uint32_t x, unsigned s) { return (x >> s) | (x << (32 - s)); }

void find_collision();

#endif