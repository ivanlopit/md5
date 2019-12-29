#include "incr4k/md5/hasher.h"
#include <sstream>
#include <iomanip>

#include "transforms.hxx"

namespace incr4k
{
void
md5_hasher::update(const uint8_t* input, size_t size)
{
    uint32_t index = (uint32_t)((c[0] >> 3) & 0x3F);
    c[0] += (uint32_t)size << 3;

    if (c[0] < ((uint32_t)size << 3))
    {
        c[1]++;
    }

    c[1] += ((uint32_t)size >> 29);

    const uint32_t leftover = 64 - index;

    size_t i = 0;
    if (size >= leftover)
    {
        memcpy(buffer.data() + index, input, leftover);
        transform(buffer.data());

        for (i = leftover; i + 63 < size; i += 64)
        {
            transform(input + i);
        }
        index = 0;
    }
    else
    {
        i = 0;
    }

    memcpy(buffer.data() + index, input + i, size - i);
}

void
md5_hasher::finalize(std::string& str_hash)
{
    std::array<uint8_t, 16> digest;
    finalize(digest);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 16; ++i)
    {
        ss << std::setw(2) << std::setfill('0') << (int)digest[i];
    }

    str_hash = ss.str();
}

std::string
md5_hasher::calculate(const uint8_t* input, size_t size)
{
    md5_hasher hasher;
    hasher.update(input, size);

    std::string result;
    hasher.finalize(result);
    return result;
}

void
md5_hasher::transform(const uint8_t* block)
{
    uint32_t a = s[0];
    uint32_t b = s[1];
    uint32_t c = s[2];
    uint32_t d = s[3];

    std::array<uint32_t, 64> x;
    merge_bytes(block, x);
    // clang-format off
    a = FF_transform(a, b, c, d, x[ 0],  7, 0xd76aa478);
    d = FF_transform(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    c = FF_transform(c, d, a, b, x[ 2], 17, 0x242070db);
    b = FF_transform(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    a = FF_transform(a, b, c, d, x[ 4],  7, 0xf57c0faf);
    d = FF_transform(d, a, b, c, x[ 5], 12, 0x4787c62a);
    c = FF_transform(c, d, a, b, x[ 6], 17, 0xa8304613);
    b = FF_transform(b, c, d, a, x[ 7], 22, 0xfd469501);
    a = FF_transform(a, b, c, d, x[ 8],  7, 0x698098d8);
    d = FF_transform(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    c = FF_transform(c, d, a, b, x[10], 17, 0xffff5bb1);
    b = FF_transform(b, c, d, a, x[11], 22, 0x895cd7be);
    a = FF_transform(a, b, c, d, x[12],  7, 0x6b901122);
    d = FF_transform(d, a, b, c, x[13], 12, 0xfd987193);
    c = FF_transform(c, d, a, b, x[14], 17, 0xa679438e);
    b = FF_transform(b, c, d, a, x[15], 22, 0x49b40821);

    a = GG_transform(a, b, c, d, x[ 1],  5, 0xf61e2562);
    d = GG_transform(d, a, b, c, x[ 6],  9, 0xc040b340);
    c = GG_transform(c, d, a, b, x[11], 14, 0x265e5a51);
    b = GG_transform(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    a = GG_transform(a, b, c, d, x[ 5],  5, 0xd62f105d);
    d = GG_transform(d, a, b, c, x[10],  9, 0x02441453);
    c = GG_transform(c, d, a, b, x[15], 14, 0xd8a1e681);
    b = GG_transform(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    a = GG_transform(a, b, c, d, x[ 9],  5, 0x21e1cde6);
    d = GG_transform(d, a, b, c, x[14],  9, 0xc33707d6);
    c = GG_transform(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    b = GG_transform(b, c, d, a, x[ 8], 20, 0x455a14ed);
    a = GG_transform(a, b, c, d, x[13],  5, 0xa9e3e905);
    d = GG_transform(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    c = GG_transform(c, d, a, b, x[ 7], 14, 0x676f02d9);
    b = GG_transform(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    a = HH_transform(a, b, c, d, x[ 5],  4, 0xfffa3942);
    d = HH_transform(d, a, b, c, x[ 8], 11, 0x8771f681);
    c = HH_transform(c, d, a, b, x[11], 16, 0x6d9d6122);
    b = HH_transform(b, c, d, a, x[14], 23, 0xfde5380c);
    a = HH_transform(a, b, c, d, x[ 1],  4, 0xa4beea44);
    d = HH_transform(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    c = HH_transform(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    b = HH_transform(b, c, d, a, x[10], 23, 0xbebfbc70);
    a = HH_transform(a, b, c, d, x[13],  4, 0x289b7ec6);
    d = HH_transform(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    c = HH_transform(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    b = HH_transform(b, c, d, a, x[ 6], 23, 0x04881d05);
    a = HH_transform(a, b, c, d, x[ 9],  4, 0xd9d4d039);
    d = HH_transform(d, a, b, c, x[12], 11, 0xe6db99e5);
    c = HH_transform(c, d, a, b, x[15], 16, 0x1fa27cf8);
    b = HH_transform(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    a = II_transform(a, b, c, d, x[ 0],  6, 0xf4292244);
    d = II_transform(d, a, b, c, x[ 7], 10, 0x432aff97);
    c = II_transform(c, d, a, b, x[14], 15, 0xab9423a7);
    b = II_transform(b, c, d, a, x[ 5], 21, 0xfc93a039);
    a = II_transform(a, b, c, d, x[12],  6, 0x655b59c3);
    d = II_transform(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    c = II_transform(c, d, a, b, x[10], 15, 0xffeff47d);
    b = II_transform(b, c, d, a, x[ 1], 21, 0x85845dd1);
    a = II_transform(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
    d = II_transform(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    c = II_transform(c, d, a, b, x[ 6], 15, 0xa3014314);
    b = II_transform(b, c, d, a, x[13], 21, 0x4e0811a1);
    a = II_transform(a, b, c, d, x[ 4],  6, 0xf7537e82);
    d = II_transform(d, a, b, c, x[11], 10, 0xbd3af235);
    c = II_transform(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    b = II_transform(b, c, d, a, x[ 9], 21, 0xeb86d391);
    // clang-format on

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
}

void
md5_hasher::merge_bytes(const uint8_t* input, std::array<uint32_t, 64>& output)
{
    for (size_t i = 0, j = 0; j < 64; j += 4, ++i)
    {
        output[i] = *((const uint32_t*)(input + j));
    }
}

void
md5_hasher::split_bytes(const uint32_t* input, uint8_t* output, size_t size)
{
    for (size_t i = 0, j = 0; j < size; j += 4, ++i)
    {
        *((uint32_t*)(output + j)) = input[i];
    }
}

void
md5_hasher::finalize(std::array<uint8_t, 16>& raw_hash)
{
    const uint32_t index = (c[0] >> 3) & 0x3F;

    uint8_t bits[8];
    split_bytes(c.data(), bits, 8);

    const uint32_t length_to_pad = (index < 56) ? (56 - index) : (120 - index);
    uint8_t padding[] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    update(padding, length_to_pad);
    update(bits, 8);

    split_bytes(s.data(), raw_hash.data(), 16);
}

void
md5_hasher::update(const char* input, size_t size)
{
    return update(reinterpret_cast<const uint8_t*>(input), size);
}

}  // namespace incr4k
