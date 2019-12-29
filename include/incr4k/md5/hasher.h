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

#include <array>
#include <stdint.h>

namespace incr4k
{
class md5_hasher
{
public:
    inline md5_hasher() = default;

    md5_hasher(md5_hasher&) = delete;
    md5_hasher(md5_hasher&&) = delete;

    md5_hasher& operator=(md5_hasher&) = delete;
    md5_hasher& operator=(md5_hasher&&) = delete;

    void update(const uint8_t* input, size_t size);
    void update(const char* input, size_t size);

    void finalize(std::string& str_hash);
    void finalize(std::array<uint8_t, 16>& raw_hash);

    static std::string calculate(const uint8_t* input, size_t size);

private:
    void transform(const uint8_t* block);
    void merge_bytes(const uint8_t* i, std::array<uint32_t, 64>& o);
    void split_bytes(const uint32_t* input, uint8_t* output, size_t size);

    std::array<uint32_t, 2> c = {};
    std::array<uint32_t, 4> s = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    std::array<uint8_t, 64> buffer = {};
};

}  // namespace incr4k
