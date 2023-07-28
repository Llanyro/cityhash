// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
//
// http://code.google.com/p/cityhash/
//
// This file provides a few functions for hashing strings.  All of them are
// high-quality functions in the sense that they pass standard tests such
// as Austin Appleby's SMHasher.  They are also fast.
//
// For 64-bit x86 code, on short strings, we don't know of anything faster than
// CityHash64 that is of comparable quality.  We believe our nearest competitor
// is Murmur3.  For 64-bit x86 code, CityHash64 is an excellent choice for hash
// tables and most other hashing (excluding cryptography).
//
// For 64-bit x86 code, on long strings, the picture is more complicated.
// On many recent Intel CPUs, such as Nehalem, Westmere, Sandy Bridge, etc.,
// CityHashCrc128 appears to be faster than all competitors of comparable
// quality.  CityHash128 is also good but not quite as fast.  We believe our
// nearest competitor is Bob Jenkins' Spooky.  We don't have great data for
// other 64-bit CPUs, but for long strings we know that Spooky is slightly
// faster than CityHash on some relatively recent AMD x86-64 CPUs, for example.
// Note that CityHashCrc128 is declared in citycrc.h.
//
// For 32-bit x86 code, we don't know of anything faster than CityHash32 that
// is of comparable quality.  We believe our nearest competitor is Murmur3A.
// (On 64-bit CPUs, it is typically faster to use the other CityHash variants.)
//
// Functions in the CityHash family are not suitable for cryptography.
//
// Please see CityHash's README file for more details on our performance
// measurements and so on.
//
// WARNING: This code has been only lightly tested on big-endian platforms!
// It is known to work well on little-endian platforms that have a small penalty
// for unaligned reads, such as current Intel and AMD moderate-to-high-end CPUs.
// It should work on all 32-bit and 64-bit platforms that allow unaligned reads;
// bug reports are welcome.
//
// By the way, for some hash functions, given strings a and b, the hash
// of a+b is easily derived from the hashes of a and b.  This property
// doesn't hold for any hash functions in this file.

#ifndef LLCPP_HASH_CITY_HASH_HPP_
#define LLCPP_HASH_CITY_HASH_HPP_

#include "llcppheaders/llanytypeslib.h"

namespace city {

extern "C" {  // Extern C

inline ui64 Uint128Low64(const ui128& x) { return x.first; }
inline ui64 Uint128High64(const ui128& x) { return x.second; }

// Hash function for a byte array.
ui64 CityHash64(ll_string_t buf, len_t len);
/*
*	Allocates an array to store ALL content of file
*	Then uses CityHash64 to hash the file
*	Obviously is slower than giving the array and the size...
*/
ui64 CityHash64(ll_string_t filename);

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
ui64 CityHash64WithSeed(ll_string_t buf, len_t len, ui64 seed);

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
ui64 CityHash64WithSeeds(ll_string_t buf, len_t len, ui64 seed0, ui64 seed1);

// Hash function for a byte array.
ui128 CityHash128(ll_string_t s, len_t len);

// Hash function for a byte array.  For convenience, a 128-bit seed is also
// hashed into the result.
ui128 CityHash128WithSeed(ll_string_t s, len_t len, ui128 seed);

// Hash function for a byte array.  Most useful in 32-bit binaries.
ui32 CityHash32(ll_string_t buf, len_t len);

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
inline ui64 Hash128to64(const ui128& x) {
  // Murmur-inspired hashing.
  const ui64 kMul = 0x9ddfea08eb382d69ULL;
  ui64 a = (Uint128Low64(x) ^ Uint128High64(x)) * kMul;
  a ^= (a >> 47);
  ui64 b = (Uint128High64(x) ^ a) * kMul;
  b ^= (b >> 47);
  b *= kMul;
  return b;
}

} /* Extern C */

} /* namespace city */

#endif  // LLCPP_HASH_CITY_HASH_HPP_