/******************************************************************************

Copyright 2019 Lopit Ivan, lopit.i.i@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

******************************************************************************/

#pragma once

#include <stdint.h>

namespace incr4k
{
inline uint32_t
F_tansform(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((~x) & z);
}

inline uint32_t
G_tansform(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & z) | (y & ~z);
}

inline uint32_t
H_tansform(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

inline uint32_t
I_tansform(uint32_t x, uint32_t y, uint32_t z)
{
    return y ^ (x | (~z));
}

inline uint32_t
rl32_tansform(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

inline uint32_t
FF_transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += F_tansform(b, c, d) + x + ac;
    a = rl32_tansform(a, s);
    return a + b;
}

inline uint32_t
GG_transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += G_tansform(b, c, d) + x + ac;
    a = rl32_tansform(a, s);
    return a + b;
}
inline uint32_t
HH_transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += H_tansform(b, c, d) + x + ac;
    a = rl32_tansform(a, s);
    return a + b;
}

inline uint32_t
II_transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += I_tansform(b, c, d) + x + ac;
    a = rl32_tansform(a, s);
    return a + b;
}

}  // namespace incr4k
