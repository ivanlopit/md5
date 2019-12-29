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

#include <gtest/gtest.h>
#include <incr4k/md5/hasher.h>

#include <string>
#include <utility>

class md5_hasher_rfc1321_vectors
    : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
};

TEST_P(md5_hasher_rfc1321_vectors, test)
{
    auto value = std::get<0>(GetParam());
    auto expected = std::get<1>(GetParam());

    auto result = incr4k::md5_hasher::calculate((uint8_t*)value.data(), value.size());

    ASSERT_EQ(result, expected);
}

INSTANTIATE_TEST_CASE_P(
    md5_hasher_rfc1321,
    md5_hasher_rfc1321_vectors,
    ::testing::Values(
        // clang-format off
        std::make_tuple<std::string, std::string>("", "d41d8cd98f00b204e9800998ecf8427e"),
        std::make_tuple<std::string, std::string>("a", "0cc175b9c0f1b6a831c399e269772661"),
        std::make_tuple<std::string, std::string>("abc", "900150983cd24fb0d6963f7d28e17f72"),
        std::make_tuple<std::string, std::string>("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        std::make_tuple<std::string, std::string>("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        std::make_tuple<std::string, std::string>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789","d174ab98d277d9f5a5611c2c9f419d9f"),
        std::make_tuple<std::string, std::string>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"))
    // clang-format on
);

class md5_hasher_huge_vectors : public ::testing::TestWithParam<std::tuple<size_t, std::string>>
{
};

TEST_P(md5_hasher_huge_vectors, test)
{
    auto size = std::get<0>(GetParam());
    auto expected = std::get<1>(GetParam());

    std::vector<uint8_t> data(size, 0u);
    for (size_t i = 0; i < size; ++i)
    {
        data[i] = i % 256;
    }

    auto result = incr4k::md5_hasher::calculate(data.data(), size);

    ASSERT_EQ(result, expected);
}

INSTANTIATE_TEST_CASE_P(
    md5_hasher_huge,
    md5_hasher_huge_vectors,
    ::testing::Values(
        // clang-format off
        std::make_tuple<size_t, std::string>(1024,               "b2ea9f7fcea831a4a63b213f41a8855b"),
        std::make_tuple<size_t, std::string>(1024 * 1024,        "c35cc7d8d91728a0cb052831bc4ef372"),
        std::make_tuple<size_t, std::string>(1024 * 1024 * 1024, "cb17f4ab872d64db60b980a67cf04a8a"))
    // clang-format on
);
